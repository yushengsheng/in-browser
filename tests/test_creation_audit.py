"""Creation audit regressions: synthetic queues and compiler, no browser/network."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from configuration import Configuration
from creation_fingerprint import creation_defaults,validate_profile,build_native,freeze_creation_battery,preset
from local_state import LocalBrowserError
from window_create import WindowCreator


def mobile_profile():
    profile=creation_defaults()
    fp=profile['fingerprint'];fp.update(ostype='Android',os='Linux armv81',platformVersion='14')
    fp.update(preset(fp))
    return profile


class CreationCompilerAuditTests(unittest.TestCase):
    def setUp(self):
        self.configuration=SimpleNamespace(resources=ROOT/'app/resources',_config_command=Configuration._config_command,
            _display=lambda:{'size':{'width':1920,'height':1080},'workAreaSize':{'width':1920,'height':1040},'scaleFactor':1},
            sign=lambda *a,**k:b'synthetic')
        self.seed=patch('creation_fingerprint.creation_variations',return_value={'Seed':'synthetic','Sign':'synthetic'})
        self.seed.start();self.addCleanup(self.seed.stop)

    def compile(self,profile,previous=None):
        profile.setdefault('id','synthetic');profile.setdefault('seq',1)
        return build_native(self.configuration,profile,previous)[0]

    def test_real_gpu_mode_clears_only_compiler_copy(self):
        profile=creation_defaults()
        profile['fingerprint'].update(webGLMeta='1',webGLManufacturer='Synthetic Vendor',webGLRender='Synthetic Renderer',webgpu={'synthetic':True})
        before=copy.deepcopy(profile['fingerprint'])
        native=self.compile(profile)
        self.assertIsNone(native['WebGL']['webglVendor'])
        self.assertIsNone(native['WebGL']['webglRenderer'])
        self.assertIsNone(native['WebGPU'])
        self.assertEqual(profile['fingerprint'],before)

    def test_custom_gpu_mode_preserves_explicit_values(self):
        profile=creation_defaults()
        profile['fingerprint'].update(webGLMeta='0',webglparameterscode='',webGLManufacturer='Synthetic Vendor',webGLRender='Synthetic Renderer',webgpu={'synthetic':True})
        native=self.compile(profile)
        self.assertEqual(native['WebGL']['webglVendor'],'Synthetic Vendor')
        self.assertEqual(native['WebGL']['webglRenderer'],'Synthetic Renderer')
        self.assertEqual(native['WebGPU'],{'synthetic':True})

    def test_custom_media_and_voices_reject_scalar_null_and_nonfinite_json(self):
        for mode,field in (('mediaDevice','mediaDeviceValue'),('speechVoices','speechVoicesValue')):
            for value in ('null','7','true','"synthetic"','[NaN]',None,7,True):
                with self.subTest(field=field,type=type(value).__name__):
                    profile=creation_defaults();profile['fingerprint'].update({mode:'0',field:value})
                    with self.assertRaises(LocalBrowserError):validate_profile(profile)
                    with self.assertRaises(LocalBrowserError):self.compile(profile)

    def test_media_and_voices_keep_object_or_array_templates_without_guessed_schema(self):
        for mode,field,target in (('mediaDevice','mediaDeviceValue','mediaDevicesInfo'),('speechVoices','speechVoicesValue','voices')):
            for value in ([],{},[{'synthetic':True}],{'synthetic':{'items':[]}}):
                for as_text in (False,True):
                    with self.subTest(field=field,container=type(value).__name__,text=as_text):
                        profile=creation_defaults();profile['fingerprint'].update({mode:'0',field:json.dumps(value) if as_text else value})
                        native=self.compile(validate_profile(profile))
                        self.assertEqual(native[target],value)

    def test_plugins_reject_invalid_records_before_vendor_can_drop_them(self):
        complete={key:'synthetic' for key in ('name','filename','description','mimeType','mimeDescription','suffixes')}
        for value in ([None],[7],[{}],[{**complete,'mimeType':7}]):
            profile=creation_defaults();profile['fingerprint'].update(enablePlugins=True,plugins=json.dumps(value))
            with self.assertRaises(LocalBrowserError):validate_profile(profile)
            with self.assertRaises(LocalBrowserError):self.compile(profile)
        for value in ([],[complete]):
            profile=creation_defaults();profile['fingerprint'].update(enablePlugins=True,plugins=value)
            native=self.compile(validate_profile(profile))
            self.assertEqual(len(native['plugins']),len(value))
            if value:self.assertEqual(native['plugins'][0]['name'],complete['name'])

    def test_inactive_templates_and_existing_native_recompile_are_not_new_validation(self):
        profile=creation_defaults();profile['fingerprint'].update(mediaDevice='1',mediaDeviceValue='null',speechVoices='1',speechVoicesValue='7',enablePlugins=False,plugins='[null]')
        previous=self.compile(validate_profile(profile))
        profile['fingerprint'].update(mediaDevice='0',mediaDeviceValue='null')
        native=self.compile(profile,previous)
        self.assertIsNone(native['mediaDevicesInfo'])
        self.assertEqual(native['DataProtect'],previous['DataProtect'])

    def test_mobile_battery_is_fixed_for_first_compile_and_previous_native_wins(self):
        profile=mobile_profile();profile['_creation_battery']=47
        first=self.compile(profile);second=self.compile(profile)
        self.assertEqual(first['battery'],47);self.assertEqual(second['battery'],47)
        profile['_creation_battery']=81
        previous=copy.deepcopy(first);previous['battery']=63
        with patch('creation_fingerprint.freeze_creation_battery') as freeze:
            native=self.compile(profile,previous)
        freeze.assert_not_called();self.assertEqual(native['battery'],63)
        self.assertEqual(native['DataProtect'],previous['DataProtect'])

    def test_desktop_avoids_battery_draw_and_corrupt_frozen_value_is_not_redrawn(self):
        profile=creation_defaults()
        with patch('creation_fingerprint.secrets.randbelow') as draw:
            self.assertFalse(freeze_creation_battery(profile))
        draw.assert_not_called();self.assertNotIn('_creation_battery',profile)
        profile['_creation_battery']=47
        self.assertEqual(self.compile(profile)['battery'],100)
        for value in (True,19,101,'45',None):
            profile=mobile_profile();profile['_creation_battery']=value
            with patch('creation_fingerprint.secrets.randbelow') as draw,self.assertRaises(LocalBrowserError):
                freeze_creation_battery(profile)
            draw.assert_not_called();self.assertEqual(profile['_creation_battery'],value)


class CreationBatteryQueueTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('creation_battery_fixture',ROOT/'tests/test_window_creation.py')
        fixture_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture_module)
        self.fixture=fixture_module.CreationTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.creator=self.fixture.creator

    def request(self,count=1,**changes):
        request=self.fixture.request(count,**changes);request['profile']=mobile_profile()
        return request

    def queued(self):
        with self.creator.store.connect() as con:
            return [self.creator.store.unpack(row[0]) for row in con.execute('SELECT data FROM creation_items WHERE data IS NOT NULL ORDER BY ordinal')]

    def test_same_fingerprint_batch_freezes_battery_once_before_attempt(self):
        request=self.request(3)
        with patch('creation_fingerprint.secrets.randbelow',side_effect=lambda upper:17 if upper==81 else 0) as draw:
            self.creator.start(request)
            self.assertEqual([p['_creation_battery'] for p in self.queued()],[37]*3)
            self.creator._run(request['request_id'])
        self.assertEqual(sum(call.args==(81,) for call in draw.call_args_list),1)
        self.assertEqual([p['_creation_battery'] for p in self.fixture.service.store.all()],[37]*3)

    def test_independent_batch_freezes_each_battery_before_attempt(self):
        values=iter((1,2,3));request=self.request(3,random_each=True)
        with patch('creation_fingerprint.secrets.randbelow',side_effect=lambda upper:next(values) if upper==81 else 0) as draw:
            self.creator.start(request)
            self.assertEqual([p['_creation_battery'] for p in self.queued()],[21,22,23])
            self.creator._run(request['request_id'])
        self.assertEqual(sum(call.args==(81,) for call in draw.call_args_list),3)

    def test_failed_creation_retry_keeps_registered_battery(self):
        request=self.request();self.creator.start(request);before=self.queued()[0]['_creation_battery']
        with patch('creation_fingerprint.secrets.randbelow') as draw:
            with patch.object(self.creator,'_create',side_effect=LocalBrowserError('合成创建失败')):
                self.creator._run(request['request_id'])
            self.assertEqual(self.queued()[0]['_creation_battery'],before)
            self.creator.resume(request['request_id']);self.creator._run(request['request_id'])
        draw.assert_not_called();self.assertEqual(self.fixture.service.store.all()[0]['_creation_battery'],before)

    def test_old_queue_persists_battery_before_failed_attempt_and_retry(self):
        request=self.request();self.creator.start(request)
        legacy=self.queued()[0];legacy.pop('_creation_battery')
        with self.creator.store.connect() as con:con.execute('UPDATE creation_items SET data=?',(self.creator.store.pack(legacy),))
        observed=[]
        def fail(*_):
            observed.append(self.queued()[0]['_creation_battery'])
            raise LocalBrowserError('合成创建失败')
        with patch('creation_fingerprint.secrets.randbelow',return_value=12) as draw:
            with patch.object(self.creator,'_create',side_effect=fail):self.creator._run(request['request_id'])
            self.creator.resume(request['request_id']);self.creator._run(request['request_id'])
        draw.assert_called_once_with(81)
        self.assertEqual(observed,[32]);self.assertEqual(self.fixture.service.store.all()[0]['_creation_battery'],32)

    def test_old_queue_persistence_failure_never_attempts_create(self):
        request=self.request();self.creator.start(request)
        legacy=self.queued()[0];legacy.pop('_creation_battery')
        with self.creator.store.connect() as con:con.execute('UPDATE creation_items SET data=?',(self.creator.store.pack(legacy),))
        original_pack=self.creator.store.pack
        def fail(profile):
            if '_creation_battery' in profile:raise OSError('synthetic persistence failure')
            return original_pack(profile)
        with patch.object(self.creator.store,'pack',side_effect=fail),patch.object(self.creator,'_create') as create:
            self.creator._run(request['request_id'])
        create.assert_not_called();self.assertNotIn('_creation_battery',self.queued()[0])
        self.assertEqual(self.creator.status(request['request_id'])['state'],'failed')
        self.creator.resume(request['request_id']);self.creator._run(request['request_id'])
        self.assertEqual(self.creator.status(request['request_id'])['state'],'completed')

    def test_interrupted_job_recovers_persisted_battery_without_redrawing(self):
        request=self.request(2);self.creator.start(request)
        expected=[p['_creation_battery'] for p in self.queued()];self.creator.lease.release()
        restarted=WindowCreator(self.fixture.service);restarted._launch=Mock();self.addCleanup(restarted.lease.release)
        self.assertEqual(restarted.latest()['state'],'interrupted')
        with patch('creation_fingerprint.secrets.randbelow') as draw:
            restarted.resume(request['request_id']);restarted._run(request['request_id'])
        draw.assert_not_called()
        self.assertEqual([p['_creation_battery'] for p in self.fixture.service.store.all()],expected)


if __name__=='__main__':unittest.main()
