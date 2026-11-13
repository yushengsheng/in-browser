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

    def test_download_diagnostics_preserve_only_fixed_public_failure_codes(self):
        for code in ('source_seed_input','source_seed_download','source_seed_verification',
                     'source_seed_budget','synthetic-private-diagnostic'):
            with self.subTest(code=code):
                error=LocalBrowserError('synthetic source failure');error.code=code
                with patch('local_source.public_variations',side_effect=error),self.assertRaises(LocalBrowserError) as caught:
                    creation_variations(self.configuration,self.native,'148')
                expected=code if code.startswith('source_seed_') else None
                self.assertEqual(getattr(caught.exception,'code',None),expected)
                self.assertNotIn('synthetic',str(caught.exception))
                self.assertFalse(self.path.exists())

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


class CreationRandomFontTests(unittest.TestCase):
    def setUp(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('creation_font_queue_fixture',ROOT/'tests/test_window_creation.py')
        fixture_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture_module)
        self.fixture=fixture_module.CreationTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.creator=self.fixture.creator;self.configuration=self.fixture.service.configuration
        self.names=['Synthetic Font '+str(index) for index in range(40)]
        self.configuration._font_config=Mock(side_effect=lambda fp:{'BasePath':'synthetic',
            'Names':str(fp.get('font') or '').split(',') if fp.get('font') else list(self.names),
            'BlockFallbackList':[],'Files':[]})

    def queued(self):
        with self.creator.store.connect() as con:
            return [self.creator.store.unpack(row[0]) for row in con.execute(
                'SELECT data FROM creation_items WHERE data IS NOT NULL ORDER BY ordinal')]

    def request(self,count=1,**changes):
        request=self.fixture.request(count,**changes)
        request['profile']['fingerprint'].update(fontType='2',font='')
        return request

    def test_default_single_window_keeps_system_fonts_without_font_lookup(self):
        request=self.fixture.request()
        self.creator.start(request);self.creator._run(request['request_id'])
        self.configuration._font_config.assert_not_called()
        record=self.fixture.service.store.all()[0]
        self.assertEqual(record['fingerprint']['fontType'],'0')
        self.assertEqual(record['fingerprint']['font'],'')

    def test_same_fingerprint_batch_freezes_one_selection_before_launch(self):
        request=self.request(3)
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            rng.return_value.sample.return_value=self.names[:30]
            self.creator.start(request)
            queued=self.queued()
            self.assertEqual(len({p['fingerprint']['font'] for p in queued}),1)
            self.assertTrue(queued[0]['fingerprint']['font'])
            self.creator._run(request['request_id'])
        rng.return_value.sample.assert_called_once_with(self.names,30)
        self.assertEqual([p['fingerprint']['font'] for p in self.fixture.service.store.all()],
            [p['fingerprint']['font'] for p in queued])

    def test_independent_batch_freezes_each_selection_before_launch(self):
        request=self.request(3,random_each=True)
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            rng.return_value.sample.side_effect=[self.names[index:index+30] for index in range(3)]
            self.creator.start(request)
            queued=self.queued()
            self.assertEqual(len({p['fingerprint']['font'] for p in queued}),3)
            self.creator._run(request['request_id'])
        self.assertEqual(rng.return_value.sample.call_count,3)
        self.assertEqual([p['fingerprint']['font'] for p in self.fixture.service.store.all()],
            [p['fingerprint']['font'] for p in queued])

    def test_failed_creation_retry_preserves_registered_selection(self):
        request=self.request()
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            rng.return_value.sample.return_value=self.names[:30]
            self.creator.start(request);before=self.queued()[0]['fingerprint']['font']
            with patch.object(self.creator,'_create',side_effect=LocalBrowserError('合成创建失败')):
                self.creator._run(request['request_id'])
            self.assertEqual(self.creator.status(request['request_id'])['state'],'failed')
            self.assertEqual(self.queued()[0]['fingerprint']['font'],before)
            self.creator.resume(request['request_id']);self.creator._run(request['request_id'])
        self.assertEqual(rng.return_value.sample.call_count,1)
        self.assertEqual(self.fixture.service.store.all()[0]['fingerprint']['font'],before)

    def test_random_candidates_exclude_names_that_cannot_round_trip_the_comma_field(self):
        good=['Synthetic Normal A','Synthetic Normal B','Synthetic Normal C']
        self.names=['Synthetic,Comma Font',' Synthetic Leading Font','Synthetic Trailing Font ','']+good
        request=self.request(2)
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            rng.return_value.sample.return_value=good
            self.creator.start(request)
            self.assertTrue(all(p['fingerprint']['font']==','.join(good) for p in self.queued()))
            self.creator._run(request['request_id'])
        rng.return_value.sample.assert_called_once_with(good,len(good))
        self.assertEqual(self.creator.status(request['request_id'])['state'],'completed')

    def test_no_round_trip_random_candidates_fail_before_drawing_or_mutating_selection(self):
        from creation_fingerprint import freeze_random_font
        self.names=['Synthetic,Comma Font',' Synthetic Leading Font','Synthetic Trailing Font ','']
        fp={'fontType':'2','font':''}
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            for _ in range(2):
                with self.assertRaises(LocalBrowserError):freeze_random_font(self.configuration,fp)
        rng.assert_not_called()
        self.assertEqual(fp,{'fontType':'2','font':''})

    def test_large_random_selection_fits_probe_and_stays_fixed_across_creation_retry(self):
        from fingerprint_continuity import _font_names
        self.names=['Synthetic Font '+str(index).zfill(3) for index in range(220)]
        request=self.request(2)
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            rng.return_value.sample.return_value=self.names[:165]
            self.creator.start(request)
            selections=[p['fingerprint']['font'] for p in self.queued()]
            self.assertEqual(len(set(selections)),1)
            selected=selections[0].split(',');self.assertTrue(selected)
            probed=_font_names({'_native':{'FontConfig':{'Names':selected}}})
            self.assertLessEqual(len(probed),128)
            self.assertTrue(set(selected)<=set(probed))
            with patch.object(self.creator,'_create',side_effect=LocalBrowserError('synthetic creation failure')):
                self.creator._run(request['request_id'])
            self.assertEqual([p['fingerprint']['font'] for p in self.queued()],selections)
            self.creator.resume(request['request_id']);self.creator._run(request['request_id'])
        rng.return_value.sample.assert_called_once_with(self.names,165)
        self.assertEqual([p['fingerprint']['font'] for p in self.fixture.service.store.all()],selections)

    def test_random_probe_budget_counts_semicolon_alias_families(self):
        from creation_fingerprint import freeze_random_font
        from fingerprint_continuity import _font_names
        self.names=['Synthetic Family '+str(index).zfill(3)+';Synthetic Alias '+str(index).zfill(3) for index in range(220)]
        fp={'fontType':'2','font':''}
        draw=self.names[:165][::-1]
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            rng.return_value.sample.return_value=draw
            self.assertTrue(freeze_random_font(self.configuration,fp))
        rng.return_value.sample.assert_called_once_with(self.names,165)
        selected=fp['font'].split(',');self.assertTrue(selected)
        probed=_font_names({'_native':{'FontConfig':{'Names':selected}}})
        self.assertLessEqual(len(probed),128)
        self.assertLess(len(selected),128-len(_font_names({})))
        self.assertEqual(selected,sorted(draw[:(128-len(_font_names({})))//2]))
        self.assertTrue(all(alias.strip() in probed for name in selected for alias in name.split(';')))

    def test_random_probe_budget_deduplicates_overlap_with_fixed_probe_families(self):
        from creation_fingerprint import freeze_random_font
        from fingerprint_continuity import _font_names
        self.names=['Arial','Times New Roman']+['Arial;Synthetic Alias '+str(index).zfill(3) for index in range(220)]
        fp={'fontType':'2','font':''}
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            rng.return_value.sample.return_value=self.names[:166]
            self.assertTrue(freeze_random_font(self.configuration,fp))
        rng.return_value.sample.assert_called_once_with(self.names,166)
        selected=fp['font'].split(',');probed=_font_names({'_native':{'FontConfig':{'Names':selected}}})
        self.assertEqual(len(probed),128)
        self.assertEqual(len(selected),128-len(_font_names({}))+2)
        self.assertTrue(all(alias.strip() in probed for name in selected for alias in name.split(';')))

    def test_unprobeable_name_lengths_do_not_trigger_replacement_draws_or_mutate_on_failure(self):
        from creation_fingerprint import freeze_random_font
        from fingerprint_continuity import _font_names
        long_name='Synthetic '+('x'*201)
        for names in ([long_name,'Synthetic Valid'],[long_name,long_name+'y']):
            with self.subTest(has_valid='Synthetic Valid' in names):
                self.names=names;fp={'fontType':'2','font':''}
                with patch('creation_fingerprint.secrets.SystemRandom') as rng:
                    rng.return_value.sample.return_value=names
                    if 'Synthetic Valid' in names:
                        self.assertTrue(freeze_random_font(self.configuration,fp))
                        self.assertEqual(fp['font'],'Synthetic Valid')
                        self.assertLessEqual(len(_font_names({'_native':{'FontConfig':{'Names':[fp['font']]}}})),128)
                    else:
                        with self.assertRaises(LocalBrowserError):freeze_random_font(self.configuration,fp)
                        self.assertEqual(fp,{'fontType':'2','font':''})
                rng.return_value.sample.assert_called_once_with(names,len(names))

    def test_legacy_queue_persists_missing_selection_before_attempt_and_retry(self):
        request=self.fixture.request();self.creator.start(request)
        legacy=self.queued()[0];legacy['fingerprint'].update(fontType='2',font='')
        with self.creator.store.connect() as con:
            con.execute('UPDATE creation_items SET data=?',(self.creator.store.pack(legacy),))
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            rng.return_value.sample.return_value=self.names[:30]
            with patch.object(self.creator,'_create',side_effect=LocalBrowserError('合成创建失败')):
                self.creator._run(request['request_id'])
            frozen=self.queued()[0]['fingerprint']['font'];self.assertTrue(frozen)
            self.creator.resume(request['request_id']);self.creator._run(request['request_id'])
        self.assertEqual(rng.return_value.sample.call_count,1)
        self.assertEqual(self.fixture.service.store.all()[0]['fingerprint']['font'],frozen)

    def test_explicit_fonts_stay_unchanged_for_both_batch_modes(self):
        selected=','.join(self.names[:2])
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            for random_each in (False,True):
                request=self.request(2,random_each=random_each,request_id=('e' if random_each else 'f')*32)
                request['profile']['fingerprint']['font']=selected
                self.creator.start(request)
                self.assertTrue(all(p['fingerprint']['font']==selected for p in self.queued()))
                self.creator._run(request['request_id'])
        rng.assert_not_called();self.configuration._font_config.assert_not_called()
        self.assertTrue(all(p['fingerprint']['font']==selected for p in self.fixture.service.store.all()))

    def test_native_compiler_uses_registered_fonts_without_drawing_again(self):
        from configuration import Configuration
        request=self.request()
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            rng.return_value.sample.return_value=self.names[:30]
            self.creator.start(request);profile=self.queued()[0];profile.update(id='synthetic',seq=1)
            configuration=SimpleNamespace(resources=ROOT/'app/resources',_config_command=Configuration._config_command,
                _display=lambda:{'size':{'width':1920,'height':1080},'workAreaSize':{'width':1920,'height':1040},'scaleFactor':1},
                _font_config=self.configuration._font_config,sign=lambda *a,**k:b'synthetic')
            with patch('creation_fingerprint.creation_variations',return_value={'Seed':'synthetic','Sign':'synthetic'}):
                native,_=build_native(configuration,profile)
        self.assertEqual(rng.return_value.sample.call_count,1)
        self.assertEqual(native['FontConfig']['Names'],profile['fingerprint']['font'].split(','))


class CreationPortableFontTests(unittest.TestCase):
    def setUp(self):
        from configuration import Configuration
        self.names=['Synthetic Frozen Font','Synthetic Fallback Font']
        self.fonts=Mock(side_effect=lambda fp:{'BasePath':'synthetic-portable-filter',
            'Names':[name.strip() for name in fp['font'].split(',')] if fp.get('font') else list(self.names),
            'BlockFallbackList':[],'Files':[]})
        self.configuration=SimpleNamespace(resources=ROOT/'app/resources',_config_command=Configuration._config_command,
            _display=lambda:{'size':{'width':1920,'height':1080},'workAreaSize':{'width':1920,'height':1040},'scaleFactor':1},
            _font_config=self.fonts,sign=lambda *a,**k:b'synthetic')

    def original(self,kind='1',selected=True):
        profile=creation_defaults();profile.update(id='synthetic',seq=1)
        profile['fingerprint'].update(fontType=kind,font=','.join(self.names) if selected else '')
        with patch('creation_fingerprint.creation_variations',return_value={'Seed':'synthetic','Sign':'synthetic'}):
            native,_=build_native(self.configuration,profile)
        self.fonts.reset_mock()
        return profile,native

    def test_ip_and_noise_recompile_keeps_frozen_fonts_when_target_fonts_are_missing(self):
        for kind in ('1','2'):
            with self.subTest(kind=kind):
                profile,previous=self.original(kind)
                profile['fingerprint'].update(webRTC='0',canvasValue=54321)
                profile['_creation_geo']={'ip':'192.0.2.17'}
                self.fonts.side_effect=LocalBrowserError('synthetic target font missing')
                with patch('creation_fingerprint.secrets.SystemRandom') as rng:
                    native,_=build_native(self.configuration,profile,previous)
                self.fonts.assert_not_called();rng.assert_not_called()
                self.assertEqual(native['FontConfig'],previous['FontConfig'])
                self.assertEqual(native['DataProtect'],previous['DataProtect'])
                self.assertEqual(native['WebRTC']['PublicIP'],'192.0.2.17')
                self.assertEqual(native['canvasContext']['canvasContextNoiseValue'],54321)
                self.fonts.side_effect=lambda fp:{'BasePath':'synthetic-portable-filter',
                    'Names':self.names,'BlockFallbackList':[],'Files':[]}

    def test_legacy_random_empty_field_recovers_the_signed_selection_without_redrawing(self):
        profile,previous=self.original('2')
        profile['fingerprint']['font']=''
        self.fonts.side_effect=LocalBrowserError('synthetic target font missing')
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            first,_=build_native(self.configuration,profile,previous)
            second,_=build_native(self.configuration,profile,first)
        self.fonts.assert_not_called();rng.assert_not_called()
        self.assertEqual(profile['fingerprint']['font'],','.join(self.names))
        self.assertEqual(first['FontConfig'],previous['FontConfig'])
        self.assertEqual(second['FontConfig'],previous['FontConfig'])

    def test_custom_empty_field_keeps_original_installed_font_filter(self):
        profile,previous=self.original(selected=False)
        self.fonts.side_effect=LocalBrowserError('synthetic target font missing')
        native,_=build_native(self.configuration,profile,previous)
        self.fonts.assert_not_called()
        self.assertEqual(profile['fingerprint']['font'],'')
        self.assertEqual(native['FontConfig'],previous['FontConfig'])

    def test_legacy_random_comma_names_reuse_twice_without_ambiguous_field_serialization(self):
        profile,previous=self.original('2')
        profile['fingerprint']['font']=''
        previous['FontConfig']['Names']=['Synthetic,Comma Font']
        self.fonts.side_effect=LocalBrowserError('synthetic target font missing')
        with patch('creation_fingerprint.secrets.SystemRandom') as rng:
            first,_=build_native(self.configuration,profile,previous)
            second,_=build_native(self.configuration,profile,first)
        self.fonts.assert_not_called();rng.assert_not_called()
        self.assertEqual(profile['fingerprint']['font'],'')
        self.assertEqual(first['FontConfig'],previous['FontConfig'])
        self.assertEqual(second['FontConfig'],previous['FontConfig'])

    def test_signed_font_selection_does_not_gain_new_count_or_name_length_limits(self):
        self.names=['Synthetic Font '+str(index) for index in range(513)]+['Synthetic '+('x'*300)]
        profile,previous=self.original()
        self.fonts.side_effect=LocalBrowserError('synthetic target font missing')
        native,_=build_native(self.configuration,profile,previous)
        self.fonts.assert_not_called()
        self.assertEqual(native['FontConfig'],previous['FontConfig'])

    def test_explicit_changed_fonts_and_new_windows_still_use_current_font_validation(self):
        profile,previous=self.original()
        profile['fingerprint']['font']='Synthetic New Font'
        native,_=build_native(self.configuration,profile,previous)
        self.fonts.assert_called_once()
        self.assertEqual(native['FontConfig']['Names'],['Synthetic New Font'])
        self.fonts.reset_mock();self.fonts.side_effect=LocalBrowserError('synthetic target font missing')
        with self.assertRaises(LocalBrowserError):build_native(self.configuration,profile)
        self.fonts.assert_called_once()

    def test_external_font_files_or_invalid_names_cannot_bypass_current_font_validation(self):
        profile,previous=self.original()
        for changes in ({'Files':['synthetic-font-file']},{'Names':[]},{'Names':[None]}):
            with self.subTest(fields=list(changes)):
                altered=copy.deepcopy(previous);altered['FontConfig'].update(changes)
                self.fonts.reset_mock()
                native,_=build_native(self.configuration,profile,altered)
                self.fonts.assert_called_once()
                self.assertEqual(native['FontConfig']['Names'],self.names)
                self.assertEqual(native['FontConfig']['Files'],[])


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
