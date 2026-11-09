"""Creation parity contracts use synthetic data and never contact the network."""
import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from creation_fingerprint import creation_defaults,build_native,creation_variations,needs_geo,catalog
from installation import initialize_installation
from local_state import LocalBrowserError


class CreationVariationsTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from configuration import Configuration
        self.temp=tempfile.TemporaryDirectory(prefix='creation-public-seed-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);initialize_installation(self.root)
        self.configuration=Configuration(self.root)
        self.configuration._display=lambda:{'size':{'width':1920,'height':1080},'workAreaSize':{'width':1920,'height':1040},'scaleFactor':1}
        key=ec.generate_private_key(ec.SECP256R1())
        replacement=patch('local_source._variations_key',return_value=key.public_key());replacement.start();self.addCleanup(replacement.stop)
        seed=b'synthetic verified creation seed'
        self.variations={'Seed':base64.b64encode(gzip.compress(seed,mtime=0)).decode(),
            'Sign':base64.b64encode(key.sign(seed,ec.ECDSA(hashes.SHA256()))).decode()}
        self.native={'userAgentVersion':'148.0.7778.289'}
        self.path=self.root/'creation-variations.bin'

    def test_new_compilation_caches_verified_seed_and_same_core_ua_works_offline(self):
        p=creation_defaults();p.update(id='synthetic',seq=1)
        with patch('local_source.public_variations',return_value=self.variations) as public:
            first,_=build_native(self.configuration,p)
        self.assertEqual(first['Variations'],self.variations);public.assert_called_once()
        self.assertTrue(self.path.is_file())
        with patch('local_source.public_variations',side_effect=OSError('synthetic offline')) as network:
            second,_=build_native(self.configuration,p)
        self.assertEqual(second['Variations'],self.variations);network.assert_not_called()

    def test_other_ua_or_core_never_reuses_cached_seed_when_offline(self):
        with patch('local_source.public_variations',return_value=self.variations):
            creation_variations(self.configuration,self.native,'148')
        before=self.path.read_bytes()
        with patch('local_source.public_variations',side_effect=OSError('synthetic offline')) as network:
            for core,version in [('148','148.0.7778.290'),('130','130.0.6723.193')]:
                with self.subTest(core=core),self.assertRaises(LocalBrowserError):
                    creation_variations(self.configuration,{'userAgentVersion':version},core)
        self.assertEqual(network.call_count,2);self.assertEqual(self.path.read_bytes(),before)
        with patch('local_source.public_variations') as network,self.assertRaises(LocalBrowserError):
            creation_variations(self.configuration,self.native,'130')
        network.assert_not_called()

    def test_bad_download_or_bad_encrypted_cache_is_rejected_without_overwrite(self):
        from local_state import write_encrypted
        with patch('local_source.public_variations',return_value={**self.variations,'Sign':'invalid'}),self.assertRaises(LocalBrowserError):
            creation_variations(self.configuration,self.native,'148')
        self.assertFalse(self.path.exists())
        for content in (b'corrupt encrypted fixture',None):
            if content is None:write_encrypted(self.path,{'format':1,'entries':{'148:148.0.7778.289':{**self.variations,'Sign':'invalid'}}},root=self.root)
            else:self.path.write_bytes(content)
            before=self.path.read_bytes()
            with patch('local_source.public_variations') as network,self.assertRaises(LocalBrowserError):
                creation_variations(self.configuration,self.native,'148')
            network.assert_not_called();self.assertEqual(self.path.read_bytes(),before)

    def test_cache_commit_failure_stops_compilation_before_signing(self):
        p=creation_defaults();p.update(id='synthetic',seq=1)
        with patch('local_source.public_variations',return_value=self.variations),\
                patch('creation_fingerprint.write_encrypted',side_effect=OSError('synthetic disk error')),\
                patch.object(self.configuration,'sign') as sign,self.assertRaises(LocalBrowserError):
            build_native(self.configuration,p)
        sign.assert_not_called();self.assertFalse(self.path.exists())

    def test_existing_native_preserves_present_or_absent_seed_without_cache_or_network(self):
        p=creation_defaults();p.update(id='synthetic',seq=1)
        with patch('creation_fingerprint.creation_variations',return_value=self.variations):
            original,_=build_native(self.configuration,p)
        for has_seed in (True,False):
            previous=copy.deepcopy(original)
            if not has_seed:previous.pop('Variations')
            with patch('creation_fingerprint.creation_variations') as cache,patch('local_source.public_variations') as network:
                result,_=build_native(self.configuration,p,previous)
            cache.assert_not_called();network.assert_not_called()
            self.assertEqual('Variations' in result,has_seed)
            if has_seed:self.assertEqual(result['Variations'],previous['Variations'])
            self.assertEqual(result['DataProtect'],previous['DataProtect'])


class CreationNoiseTests(unittest.TestCase):
    def test_new_native_uses_verified_noise_template_and_existing_native_keeps_its_rules(self):
        from configuration import Configuration
        configuration=SimpleNamespace(resources=ROOT/'app/resources',_config_command=Configuration._config_command,
            _display=lambda:{'size':{'width':1920,'height':1080},'workAreaSize':{'width':1920,'height':1040},'scaleFactor':1},
            sign=lambda *a,**k:b'synthetic')
        profile=creation_defaults();profile.update(id='synthetic',seq=1)
        expected=catalog()['NoiseBypassEvidence']['ordered_domains_sha256']
        with patch('creation_fingerprint.creation_variations',return_value={'Seed':'synthetic','Sign':'synthetic'}):
            native,_=build_native(configuration,profile)
        for component in ('canvasContext','WebGL'):
            domains=native[component].get('bypassDomains',[])
            self.assertEqual(len(domains),33)
            self.assertEqual(hashlib.sha256(json.dumps(domains,separators=(',',':')).encode()).hexdigest(),expected)
        for has_rules in (True,False):
            previous=copy.deepcopy(native)
            for component in ('canvasContext','WebGL'):
                if has_rules:previous[component]['bypassDomains']=['synthetic.example.invalid']
                else:previous[component].pop('bypassDomains')
            changed=copy.deepcopy(profile);changed['fingerprint']['canvasValue']=12345
            result,_=build_native(configuration,changed,previous)
            self.assertEqual(result['canvasContext']['canvasContextNoiseValue'],12345)
            for component in ('canvasContext','WebGL'):
                self.assertEqual('bypassDomains' in result[component],has_rules)
                if has_rules:self.assertTrue(result[component]['bypassDomains']==previous[component]['bypassDomains'])

    def test_partial_or_changed_template_cannot_silently_pass_catalog_validation(self):
        bad=copy.deepcopy(catalog());bad['NoiseBypassDefaults']['canvasContext']['bypassDomains'].pop()
        catalog.cache_clear()
        try:
            with patch('creation_fingerprint.json.loads',return_value=bad),self.assertRaises(LocalBrowserError):catalog()
        finally:catalog.cache_clear()


class CreationResolutionTests(unittest.TestCase):
    def test_first_creation_runtime_preserves_pc_and_mobile_open_size(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('creation_queue_fixture',ROOT/'tests/test_window_creation.py')
        fixture_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture_module)
        for kind,system,size in (('PC','Win32',(1100,780)),('Android','Linux armv81',(500,950)),('IOS','iPhone',(500,950))):
            with self.subTest(device=kind):
                fixture=fixture_module.CreationTests();fixture.setUp()
                try:
                    request=fixture.request()
                    request['profile']['fingerprint'].update(ostype=kind,os=system,openWidth=size[0],openHeight=size[1])
                    fixture.creator.start(request);fixture.creator._run(request['request_id'])
                    record=fixture.service.store.all()[0]
                    self.assertEqual(record['_runtime']['window_size_once'],list(size))
                    self.assertFalse(record['_runtime']['has_launched'])
                finally:fixture.doCleanups()

    def test_random_fixed_mobile_screen_uses_its_stock_device_dictionary(self):
        from manager_service import ManagerService
        for kind,system in (('Android','Linux armv81'),('IOS','iPhone')):
            with self.subTest(device=kind),tempfile.TemporaryDirectory(prefix='creation-mobile-screen-') as directory:
                root=Path(directory);initialize_installation(root)
                creator=ManagerService(root).creator();creator._launch=Mock()
                try:
                    profile=creation_defaults();profile['fingerprint'].update(ostype=kind,os=system,resolutionType='2')
                    with patch('window_create.secrets.choice',side_effect=lambda values:values[0]) as choose:
                        creator.start({'request_id':'c'*32,'profile':profile,'count':3,'random_each':False})
                    with creator.store.connect() as con:rows=con.execute('SELECT data FROM creation_items ORDER BY ordinal').fetchall()
                    self.assertEqual(len(rows),3)
                    resolutions=[]
                    for row in rows:
                        fp=creator.store.unpack(row[0])['fingerprint']
                        self.assertEqual(fp['resolutionType'],'1')
                        self.assertIn(fp['resolution'],catalog()['MobileResolutions'][kind])
                        resolutions.append(fp['resolution'])
                    self.assertEqual(len(set(resolutions)),1)
                    self.assertEqual(sum(call.args[0]==catalog()['MobileResolutions'][kind] for call in choose.call_args_list),1)
                finally:creator.lease.release()


class CreationWebRtcTests(unittest.TestCase):
    def record(self):
        return {'id':'synthetic','created_locally':True,'fingerprint':{**creation_defaults()['fingerprint'],'webRTC':'0'},
            'created_options':{},'_native':{'WebRTC':{'PublicIP':'192.0.2.1'}},
            '_runtime':{},'_creation_geo':{'ip':'192.0.2.1'}}

    def test_replace_mode_requires_egress_even_when_other_automatic_fields_are_disabled(self):
        fp=creation_defaults()['fingerprint']
        self.assertFalse(needs_geo(fp))
        self.assertTrue(needs_geo({**fp,'webRTC':'0'}))
        for key in ('isIpCreateLanguage','isIpCreateTimeZone','isIpCreateDisplayLanguage','isIpCreatePosition'):
            with self.subTest(field=key):self.assertTrue(needs_geo({**fp,key:True}))

    def test_real_compiler_uses_geo_public_ip_for_replace_mode(self):
        from configuration import Configuration
        configuration=SimpleNamespace(resources=ROOT/'app/resources',_config_command=Configuration._config_command,
            _display=lambda:{'size':{'width':1920,'height':1080},'workAreaSize':{'width':1920,'height':1040},'scaleFactor':1},
            sign=lambda *a,**k:b'synthetic')
        p=creation_defaults();p.update(id='synthetic',seq=1,_creation_geo={'ip':'192.0.2.9'})
        p['fingerprint']['webRTC']='0'
        with patch('creation_fingerprint.creation_variations',return_value={'Seed':'synthetic','Sign':'synthetic'}):
            native,_=build_native(configuration,p)
        self.assertEqual(native['WebRTC']['PublicIP'],'192.0.2.9')

    def test_empty_manual_location_is_null_and_valid_zero_or_ip_position_is_preserved(self):
        from configuration import Configuration
        configuration=SimpleNamespace(resources=ROOT/'app/resources',_config_command=Configuration._config_command,
            _display=lambda:{'size':{'width':1920,'height':1080},'workAreaSize':{'width':1920,'height':1040},'scaleFactor':1},
            sign=lambda *a,**k:b'synthetic')
        p=creation_defaults();p.update(id='synthetic',seq=1)
        with patch('creation_fingerprint.creation_variations',return_value={'Seed':'synthetic','Sign':'synthetic'}):
            p['fingerprint'].update(lat='',lng=None,precisionData='')
            before=copy.deepcopy(p)
            native,_=build_native(configuration,p)
            self.assertEqual(native['geoPosition'],{'latitude':None,'longitude':None})
            self.assertEqual(p,before)
            for values in ((0,0,0),(12.5,-42.25,30)):
                p['fingerprint'].update(zip(('lat','lng','precisionData'),values))
                native,_=build_native(configuration,p)
                self.assertEqual(native['geoPosition'],dict(zip(('latitude','longitude','accuracy'),values)))
            p['fingerprint'].update(isIpCreatePosition=True,lat='',lng='',precisionData='')
            p['_creation_geo']={'latitude':12.5,'longitude':-42.25}
            native,_=build_native(configuration,p)
            self.assertEqual(native['geoPosition'],{'latitude':12.5,'longitude':-42.25,'accuracy':10})

    def test_prepare_launch_rechecks_replace_ip_using_current_worker_route(self):
        from created_window import prepare_launch
        p=self.record();before=copy.deepcopy(p)
        route={'port':32123}
        proxy_runtime=SimpleNamespace(ensure=Mock(return_value=route),owned=Mock(return_value=True),
            control=Mock(return_value=True),stop_if_unused=Mock())
        geo={'ip':'192.0.2.2'}
        def compile_native(configuration,updated,previous):
            return {'WebRTC':{'PublicIP':updated['_creation_geo']['ip']}},b'synthetic native fixture'
        with tempfile.TemporaryDirectory(prefix='creation-webrtc-') as directory:
            root=Path(directory);(root/'fingerprints').mkdir()
            service=SimpleNamespace(root=root,proxy_runtime=proxy_runtime,configuration=None,store=SimpleNamespace(put=Mock()),_sync=Mock())
            with patch('fingerprint_continuity.verify_continuity',return_value={'passed':True}),\
                    patch('fingerprint_continuity.create_baseline',return_value={'synthetic':True}),\
                    patch('created_window.resolve_geo',return_value=geo) as resolve,\
                    patch('created_window.build_native',side_effect=compile_native):
                result=prepare_launch(service,p)
            self.assertEqual(result['_native']['WebRTC']['PublicIP'],'192.0.2.2')
            resolve.assert_called_once_with({'type':'http','host':'127.0.0.1','port':route['port']})
            service.store.put.assert_called_once();proxy_runtime.stop_if_unused.assert_called_once_with(p['id'])
        self.assertEqual(p,before)

    def test_missing_or_changed_actual_egress_is_rejected_before_remembering_success(self):
        from created_window import check_egress
        p=self.record();before=copy.deepcopy(p)
        for result in ({},{'egress_ip':None},{'egress_ip':'192.0.2.2'}):
            with self.subTest(result=result),self.assertRaises(LocalBrowserError):check_egress(p,result)
            self.assertEqual(p,before)
        check_egress(p,{'egress_ip':'192.0.2.1'})
        self.assertEqual(p['_pending_creation_egress']['ip'],'192.0.2.1')
        p=self.record();p['_native']['WebRTC']['PublicIP']=None
        with self.assertRaises(LocalBrowserError):check_egress(p,{'egress_ip':'192.0.2.1'})

    def test_imported_profiles_never_recalculate_or_enforce_new_replace_policy(self):
        from created_window import prepare_launch,check_egress
        p=self.record();p.pop('created_locally');before=copy.deepcopy(p)
        with patch('created_window.resolve_geo') as resolve:
            self.assertIs(prepare_launch(None,p),p)
            check_egress(p,{'egress_ip':'192.0.2.2'})
        resolve.assert_not_called();self.assertEqual(p,before)


if __name__=='__main__':unittest.main(verbosity=2)
