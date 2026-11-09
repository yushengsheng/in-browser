"""New windows use temporary encrypted catalogs; no account data or real network."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from creation_fingerprint import creation_defaults,random_fingerprint,validate_profile,build_native
from installation import initialize_installation
from local_signer import LocalSigner
from local_state import LocalBrowserError
from manager_service import ManagerService
from window_create import WindowCreator


class CreationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='window-creation-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        initialize_installation(self.root)
        self.service=ManagerService(self.root)
        self.creator=self.service.creator()
        self.creator._launch=Mock()
        self.executable=self.root/'synthetic.exe';self.executable.write_bytes(b'never executed')
        self.service.configuration.local_core=Mock(return_value=self.executable)
        self.service._runtime=lambda p,previous:copy.deepcopy(previous)
        signer=LocalSigner(self.root)
        def compile_native(configuration,profile):
            native={'Resource':{'synthetic':True},'userAgent':profile['fingerprint']['userAgent'],'DataProtect':{'CipherKey':'1'*64}}
            return native,signer.sign_native(native,configuration._key,core_major=profile['core_version'])
        for target,replacement in [('window_create.build_native',compile_native),
                ('fingerprint_continuity.create_baseline',lambda *_:{'synthetic':True}),
                ('fingerprint_continuity.verify_continuity',lambda *_: {'passed':True})]:
            patched=patch(target,replacement);patched.start();self.addCleanup(patched.stop)
        self.addCleanup(self.creator.lease.release)

    def request(self,count=1,**changes):
        return {'request_id':'a'*32,'profile':creation_defaults(),'count':count,'random_each':False,**changes}

    def test_single_creation_and_identical_request_are_durable_and_idempotent(self):
        request=self.request()
        self.creator.start(request);self.creator._run(request['request_id'])
        status=self.creator.status(request['request_id'])
        self.assertEqual((status['state'],status['completed']),('completed',1))
        records=self.service.store.all();self.assertEqual(len(records),1)
        record=records[0]
        self.assertTrue(record['created_locally'])
        self.assertEqual(record['_runtime']['signature_provider'],'local-v1')
        self.assertTrue(record['_portable_crypt'])
        self.assertTrue(Path(record['_runtime']['profile_path']).is_dir())
        before=self.service._manifest(self.root/'profiles')
        self.assertEqual(self.creator.start(request)['completed'],1)
        self.assertEqual(before,self.service._manifest(self.root/'profiles'))
        self.assertEqual(len(self.service.store.all()),1)

    def test_batch_mapping_proxy_order_and_independent_noise(self):
        request=self.request(3,random_each=True,proxy_lines=['fixture.invalid:1001','fixture.invalid:1002','fixture.invalid:1003'])
        self.creator.start(request);self.creator._run(request['request_id'])
        records=self.service.store.all()
        self.assertEqual([row['seq'] for row in records],[1,2,3])
        self.assertEqual([row['proxy']['port'] for row in records],[1001,1002,1003])
        self.assertEqual([row['name'] for row in records],['新窗口 1','新窗口 2','新窗口 3'])
        self.assertEqual(len({tuple(row['fingerprint'][k] for k in ('canvasValue','webGLValue','clientRectNoiseValue')) for row in records}),3)
        self.assertEqual(len({row['_portable_crypt']['key_id'] for row in records}),3)

    def test_custom_noise_is_preserved_when_batch_randomization_is_disabled(self):
        request=self.request(2)
        request['profile']['fingerprint']['canvasValue']=123456
        self.creator.start(request);self.creator._run(request['request_id'])
        self.assertEqual([r['fingerprint']['canvasValue'] for r in self.service.store.all()],[123456,123456])

    def test_cancel_preserves_completed_and_drops_unneeded_private_specs(self):
        request=self.request(3)
        self.creator.start(request)
        self.creator.cancel(request['request_id']);self.creator._run(request['request_id'])
        self.assertEqual(self.creator.status(request['request_id'])['state'],'cancelled')
        self.assertEqual(self.service.store.all(),[])
        with self.service.store.connect() as con:
            self.assertEqual(con.execute('SELECT count(*) FROM creation_items WHERE data IS NOT NULL').fetchone()[0],0)

    def test_interrupted_job_can_resume_without_duplicating_committed_windows(self):
        request=self.request(2);self.creator.start(request)
        helper=self.service.synchronizer()
        with self.service.store.connect() as con:
            data,key=con.execute('SELECT data,source_key FROM creation_items ORDER BY ordinal LIMIT 1').fetchone()
        self.creator._create(helper,self.service.store.unpack(data),key,self.executable)
        self.creator.lease.release()
        restarted=WindowCreator(self.service);restarted._launch=Mock()
        self.assertEqual(restarted.latest()['state'],'interrupted')
        restarted.resume(request['request_id']);restarted._run(request['request_id'])
        self.assertEqual(len(self.service.store.all()),2)
        self.assertEqual(restarted.latest()['completed'],2)

    def test_missing_core_fails_batch_once_and_retains_retry_specs(self):
        request=self.request(1000);self.creator.start(request)
        self.service.configuration.local_core.side_effect=LocalBrowserError('合成缺失内核')
        self.creator._run(request['request_id'])
        status=self.creator.status(request['request_id'])
        self.assertEqual((status['state'],status['failed']),('failed',1000))
        self.service.configuration.local_core.assert_called_once()
        self.assertEqual(self.service.store.all(),[])
        self.assertLessEqual(len(status['items']),100)

    def test_validation_rejects_bad_count_or_proxy_mapping_before_job_write(self):
        for request in (self.request(0),self.request(1001),self.request(True),self.request(2,proxy_lines=['x:1','x:2','x:3'])):
            with self.subTest(count=request['count']),self.assertRaises(LocalBrowserError):self.creator.start(request)
        self.assertIsNone(self.creator.latest())

    def test_request_id_cannot_be_reused_for_a_different_profile(self):
        request=self.request();self.creator.start(request)
        changed=copy.deepcopy(request);changed['profile']['name']='different'
        with self.assertRaises(LocalBrowserError):self.creator.start(changed)

    def test_completed_creation_history_is_removed_with_its_window(self):
        request=self.request();self.creator.start(request);self.creator._run(request['request_id'])
        identity=self.service.store.all()[0]['id']
        deleted=self.service.delete(identity)
        self.assertTrue(deleted['deleted']);self.assertTrue(deleted['cleanup_complete'])
        self.assertIsNone(self.creator.latest())
        self.assertEqual(self.service.store.source_bindings(),{})

    def test_cancel_interrupted_job_drops_private_request_specs(self):
        request=self.request();self.creator.start(request);self.creator.lease.release()
        restarted=WindowCreator(self.service)
        self.assertEqual(restarted.latest()['state'],'interrupted')
        self.assertEqual(restarted.cancel(request['request_id'])['state'],'cancelled')
        with self.service.store.connect() as con:
            self.assertEqual(con.execute('SELECT count(*) FROM creation_items WHERE data IS NOT NULL').fetchone()[0],0)

    def test_cancel_after_commit_keeps_accurate_mapping_and_missing_status_can_clear(self):
        request=self.request(2);self.creator.start(request)
        helper=self.service.synchronizer()
        with self.service.store.connect() as con:
            data,key=con.execute('SELECT data,source_key FROM creation_items ORDER BY ordinal LIMIT 1').fetchone()
        self.creator._create(helper,self.service.store.unpack(data),key,self.executable)
        self.creator.lease.release();restarted=WindowCreator(self.service)
        status=restarted.cancel(request['request_id'])
        self.assertEqual((status['state'],status['completed']),('cancelled',1))
        self.assertTrue(status['items'][0]['id'])
        self.assertIsNone(restarted.status('missing',missing_ok=True))
        with self.assertRaises(LocalBrowserError):restarted.status('missing')

    def test_failed_batch_requires_explicit_retry_or_cancel_before_another_batch(self):
        request=self.request(2);self.creator.start(request)
        self.service.configuration.local_core.side_effect=LocalBrowserError('合成缺失内核')
        self.creator._run(request['request_id'])
        new_request=self.request(request_id='b'*32)
        with self.assertRaises(LocalBrowserError):self.creator.start(new_request)
        self.assertEqual(self.creator.cancel(request['request_id'])['state'],'cancelled')
        with self.service.store.connect() as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM creation_items WHERE data IS NOT NULL').fetchone()[0],0)
        self.assertEqual(self.creator.start(new_request)['state'],'running')


class FingerprintTests(unittest.TestCase):
    def test_cookie_import_supports_netscape_http_only_and_session_cookies(self):
        from profile_model import parse_cookies
        text='\ufeff# Netscape HTTP Cookie File\n#HttpOnly_.example.invalid\tTRUE\t/\tTRUE\t2000000000\tsession\tsynthetic\nexample.invalid\tFALSE\t/\tFALSE\t0\tpreference\tsynthetic'
        cookies=parse_cookies(text,{})
        self.assertTrue(cookies[0]['httpOnly']);self.assertTrue(cookies[0]['secure'])
        self.assertEqual(cookies[0]['domain'],'.example.invalid')
        self.assertNotIn('expires',cookies[1])
        with self.assertRaises(LocalBrowserError):parse_cookies('example.invalid\tINVALID\t/\tFALSE\t0\tname\tvalue',{})
    def test_original_native_compiler_maps_every_supported_core_and_reuses_protection(self):
        from configuration import Configuration
        from core_specs import majors
        from local_state import LocalBrowserError
        with tempfile.TemporaryDirectory(prefix='native-creation-') as directory,\
                patch('creation_fingerprint.creation_variations',return_value={'Seed':'synthetic','Sign':'synthetic'}):
            root=Path(directory);initialize_installation(root);configuration=Configuration(root)
            configuration._display=lambda:{'size':{'width':1920,'height':1080},'workAreaSize':{'width':1920,'height':1040},'scaleFactor':1}
            for core in majors():
                with self.subTest(core=core):
                    profile=creation_defaults(core);profile['fingerprint']=random_fingerprint(profile['fingerprint'])
                    profile.update(id='synthetic',seq=1)
                    native,binary=build_native(configuration,profile)
                    self.assertEqual(native['navigator']['hardwareConcurrency'],profile['fingerprint']['hardwareConcurrency'])
                    self.assertTrue(native['userAgent'].find('Chrome/'+core+'.')>=0)
                    self.assertEqual(native['canvasContext']['canvasContextNoiseValue'],profile['fingerprint']['canvasValue'])
                    self.assertEqual(native['screen']['width'],1920)
                    self.assertEqual(native['allowLocalPorts'],[])
                    self.assertEqual(native['AllowLocalWebSocketPorts'],[])
                    self.assertEqual(len(native['canvasContext'].get('bypassDomains',[])),33)
                    self.assertEqual(len(native['WebGL'].get('bypassDomains',[])),33)
                    self.assertTrue(LocalSigner(root).verify(binary))
                    self.assertEqual(native.get('DataProtect') is None,int(core)<130)
                    if core=='148':
                        changed=copy.deepcopy(profile);changed['fingerprint']['canvasValue']+=1
                        second,_=build_native(configuration,changed,native)
                        self.assertEqual(native['DataProtect'],second['DataProtect'])
                        self.assertNotEqual(native['canvasContext'],second['canvasContext'])

    def test_randomization_never_mutates_original_and_keeps_ranges(self):
        original=creation_defaults()['fingerprint'];before=copy.deepcopy(original)
        result=random_fingerprint(original)
        self.assertEqual(original,before)
        for field,low,high in [('canvasValue',10000,1000000),('webGLValue',10000,1000000),('audioContextValue',1,100),('clientRectNoiseValue',1,999999)]:
            self.assertLessEqual(low,result[field]);self.assertLessEqual(result[field],high)

    def test_invalid_custom_fingerprint_is_never_silently_downgraded(self):
        for changes in ({'webGLMeta':'0','webGLRender':''},
                        {'mediaDevice':'0','mediaDeviceValue':None},{'webglparameterscode':'missing'},
                        {'webRTC':'4'},{'position':'1','lat':None,'lng':None},
                        {'ostype':'IOS','os':'Win32'},{'precisionData':-1}):
            profile=creation_defaults();profile['fingerprint'].update(changes)
            with self.subTest(fields=list(changes)),self.assertRaises(LocalBrowserError):validate_profile(profile)

    def test_geo_requires_complete_real_values_and_valid_timezone(self):
        from creation_fingerprint import geo_result
        data={'ip':'192.0.2.1','timezone':'Asia/Shanghai','languages':'zh-CN,zh','latitude':30,'longitude':120,'country_code':'CN'}
        self.assertEqual(geo_result(data)['timeZone'],'Asia/Shanghai')
        for changes in ({'timezone':'invalid'},{'latitude':float('nan')},{'languages':''},{'country_code':''}):
            with self.subTest(fields=list(changes)),self.assertRaises(Exception):geo_result({**data,**changes})


class CreatedLaunchTests(unittest.TestCase):
    def test_background_mode_does_not_close_an_observed_ready_process(self):
        from browser_core import BrowserController
        controller=BrowserController.__new__(BrowserController)
        controller.state={'synthetic':{'pid':1,'window_observed':True,'ready':True,'created':0}}
        controller.profiles={'synthetic':{'enable_background_mode':True}}
        controller._ensure_record=Mock(return_value=True);controller._queue_windowless_close=Mock()
        with patch('browser_core._visible_windows',return_value=[]):
            self.assertEqual(controller._status('synthetic'),'已打开')
            controller._queue_windowless_close.assert_not_called()
            controller.profiles['synthetic']['enable_background_mode']=False
            self.assertEqual(controller._status('synthetic'),'正在关闭')
            controller._queue_windowless_close.assert_called_once_with('synthetic')

    def test_imported_profiles_never_use_new_cleanup_or_randomization(self):
        from created_window import prepare_launch,apply_launch_cleanup
        profile={'created_options':{'clear_cookies':True,'random_each_open':True}}
        self.assertIs(prepare_launch(None,profile),profile)
        apply_launch_cleanup(None,profile)

    def test_opt_in_cleanup_preserves_preferences_bookmarks_and_other_profiles(self):
        from types import SimpleNamespace
        from created_window import apply_launch_cleanup
        with tempfile.TemporaryDirectory(prefix='created-cleanup-') as directory:
            root=Path(directory);profile=root/'profiles/synthetic'
            for name in ('Default/Cache/data','Default/History','Default/Network/Cookies','Default/Bookmarks','Default/Preferences','Default/Storage/ext/data'):
                target=profile/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b'synthetic')
            other=root/'profiles/other/Default/Cache/data';other.parent.mkdir(parents=True);other.write_bytes(b'other')
            p={'id':'synthetic','created_locally':True,'_runtime':{'profile_path':str(profile)},
               'created_options':{'clear_cache':True,'clear_cache_without_extensions':True,'clear_history':True,'clear_cookies':True}}
            apply_launch_cleanup(SimpleNamespace(root=root),p)
            for name in ('Default/Cache','Default/History','Default/Network/Cookies'):self.assertFalse((profile/name).exists())
            for name in ('Default/Bookmarks','Default/Preferences','Default/Storage/ext/data'):self.assertTrue((profile/name).is_file())
            self.assertEqual(other.read_bytes(),b'other')

    def test_egress_mismatch_blocks_without_replacing_previous_success(self):
        from created_window import check_egress
        p={'created_locally':True,'created_options':{'stop_ip_change':True},'_last_creation_egress':{'ip':'192.0.2.1'}}
        before=copy.deepcopy(p)
        with self.assertRaises(LocalBrowserError):check_egress(p,{'egress_ip':'192.0.2.2'})
        self.assertEqual(p,before)
        check_egress(p,{'egress_ip':'192.0.2.1'})
        self.assertEqual(p['_pending_creation_egress']['ip'],'192.0.2.1')


if __name__=='__main__':unittest.main(verbosity=2)
