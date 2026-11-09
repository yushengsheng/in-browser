"""Synthetic protection-mode compatibility and immutable engine mapping checks."""
import copy
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from bit_source import BitSource
from configuration import Configuration
from core_specs import majors
import local_source
from local_source import PreparedSources,source_protection,freeze_source_native
from local_signer import LocalSigner
from local_state import LocalBrowserError,read_encrypted,write_encrypted
from portable_paths import encode_archive
from portable_vault import PortableVault

IDENTITY='3'*32


def full(major='124',protection=None):
    return {'id':IDENTITY,'browserFingerPrint':{'browserId':IDENTITY,'coreProduct':'chrome',
        'coreVersion':major,'extendOptions':{'DataProtect':protection}}}


class LegacySourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='legacy-source-test-');self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.root=self.base/'data';self.root.mkdir()
        PortableVault(self.root).initialize()
        self.signer=LocalSigner(self.root)
        self.configuration=Configuration.__new__(Configuration)
        self.configuration.root=self.root;self.configuration._key=hashlib.sha256(b'synthetic aes key').digest()
        self.configuration.vendor_data=self.base/'vendor';self.configuration.vendor_data.mkdir()
        self.configuration.independent=True
        self.cache=PreparedSources(self.root)
        self.configuration.prepared_sources=lambda:self.cache

    def test_legacy_absent_and_null_modes_remain_absent_and_null(self):
        for major in (value for value in majors() if int(value)<130):
            for extension in (None,{}, {'DataProtect':None},'{}','{"DataProtect":null}'):
                with self.subTest(major=major,extension=extension):
                    fp={'coreVersion':major,'extendOptions':extension};before=copy.deepcopy(fp)
                    self.assertIsNone(source_protection(fp));self.assertEqual(fp,before)

    def test_modern_missing_and_malformed_modes_are_rejected(self):
        for major in ('130','148','999',''):
            with self.subTest(major=major),self.assertRaises(LocalBrowserError):
                source_protection({'coreVersion':major,'extendOptions':{'DataProtect':None}})
        for mode in ({}, {'CipherKey':''}, {'CipherKey':True}, {'CipherKey':123},'unexpected',[]):
            with self.subTest(mode=mode),self.assertRaises(LocalBrowserError):
                source_protection({'coreVersion':'124','extendOptions':{'DataProtect':mode}})

    def test_protected_modes_preserve_every_option_on_old_and_new_cores(self):
        protected={'CipherKey':'synthetic only','Opaque':{'Enabled':False,'Values':[1,None,3]}}
        for major in ('124','148'):
            fp=full(major,protected)['browserFingerPrint']
            self.assertIs(source_protection(fp),protected)

    def test_cache_preserves_legacy_mode_and_rejects_invented_protection(self):
        for missing in (False,True):
            value=full();native={'Resource':{'fixture':True}}
            if missing:value['browserFingerPrint']['extendOptions'].pop('DataProtect')
            else:native['DataProtect']=None
            item={'format':1,'id':IDENTITY,'full':value,'detail':copy.deepcopy(value),'native':native}
            self.cache.put(item);self.assertEqual(self.cache.get(IDENTITY)['native'],native)
            self.assertEqual(self.cache.get(IDENTITY)['full'],value)
            item['native']['DataProtect']={'CipherKey':'invented fixture'}
            with self.assertRaises(LocalBrowserError):self.cache.put(item)

    def test_source_prepare_keeps_legacy_identity_and_protection_binding(self):
        profiles=self.base/'profiles';folder=profiles/IDENTITY;(folder/'Default').mkdir(parents=True)
        for name in ('Local State','Default/Preferences'):(folder/name).write_text('{}')
        (folder/'Last Version').write_text('124.0.0.0')
        database=self.configuration.vendor_data/'db.sqlite'
        with sqlite3.connect(database) as con:
            con.execute('CREATE TABLE global_configs (config_name TEXT,config_value TEXT)')
            con.execute('INSERT INTO global_configs VALUES (?,?)',('browser_cache_dir',str(profiles)))
        con.close()
        reader=Mock();reader.source_settings.return_value=full()
        reader.build_source.return_value=({'Resource':{'fixture':True},'DataProtect':None},None)
        cache=self.configuration.vendor_data/'LocalCache';cache.mkdir()
        (cache/IDENTITY).write_bytes(b'synthetic cache bytes consumed only by mocked adapter')
        with patch.object(local_source,'_reader',return_value=reader):
            result=local_source.prepare(self.configuration,IDENTITY,'124')
        self.assertIsNone(result['native']['DataProtect'])
        self.assertEqual(self.cache.get(IDENTITY)['full'],full())
        reader.source_settings.assert_called_once_with(IDENTITY)

    def test_every_known_major_is_discoverable_but_unknown_is_rejected(self):
        for major in majors():
            self.assertEqual(BitSource._core_major(full(major),major+'.0.0.0'),major)
        for major in ('99','999'):
            with self.assertRaises(ValueError):BitSource._core_major(full(major),major+'.0.0.0')

    def test_native_decode_accepts_legacy_null_without_changing_bytes(self):
        native={'Resource':{'fixture':True},'DataProtect':None,'userAgentVersion':'148.0.0.0'}
        signed=self.signer.sign_native(native,self.configuration._key,core_major='124')
        path=self.base/'native.bin';path.write_bytes(signed)
        self.assertTrue(self.signer.verify(path))
        self.assertEqual(self.configuration.decode(path),native)
        self.assertEqual(path.read_bytes(),signed)
        corrupted=bytearray(signed);corrupted[16]^=1
        path.write_bytes(corrupted)
        self.assertFalse(self.signer.verify(path))

    def test_build_local_passes_real_core_instead_of_spoofed_user_agent(self):
        native={'Resource':{'fixture':True},'DataProtect':None,'userAgentVersion':'148.0.0.0'}
        profile={'fingerprint':{'coreVersion':'124'},'preferences':{},'_runtime':{'core_major':'124'}}
        made,signed=self.configuration.build_local(profile,native,previous_preferences={})
        path=self.base/'local.bin';path.write_bytes(signed)
        self.assertEqual(made,native);self.assertTrue(self.signer.verify(path))

    def converter(self,native,major,protection,*,allow=False):
        node=ROOT/'runtime/node/node.exe'
        if not node.is_file():self.skipTest('Bundled Node unavailable')
        source=self.base/'adapter.js'
        source.write_text('us={6.3:0};async function ps(info,geo){await hs("",JSON.stringify('+json.dumps(native)+'));}\n'+
            '\n'.join('function '+name+'(){}' for name in ('gs','_s','ca','os','ss','cs')),encoding='utf-8')
        payload={'sourceFile':str(source),'info':full(major,protection),'geo':None,'allowLegacyProtection':allow}
        return subprocess.run([str(node),str(ROOT/'app/config_factory.js')],input=json.dumps(payload).encode(),
            capture_output=True,timeout=5,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))

    def test_converter_requires_explicit_legacy_permission_and_never_invents_keys(self):
        native={'Resource':{'fixture':True},'DataProtect':None}
        self.assertEqual(self.converter(native,'124',None,allow=True).returncode,0)
        self.assertNotEqual(self.converter(native,'124',None).returncode,0)
        self.assertNotEqual(self.converter(native,'148',None,allow=True).returncode,0)
        native['DataProtect']={'CipherKey':'invented fixture'}
        self.assertNotEqual(self.converter(native,'124',None,allow=True).returncode,0)

    def test_converter_preserves_protected_values_on_legacy_and_modern_cores(self):
        protected={'CipherKey':'synthetic only','Opaque':False}
        for major in ('124','148'):
            native={'Resource':{'fixture':True},'DataProtect':dict(reversed(list(protected.items())))}
            result=self.converter(native,major,protected)
            self.assertEqual(result.returncode,0)
            self.assertEqual(json.loads(result.stdout),native)

    def archive(self):
        archive={'format':1,'key_id':self.signer.key_id,'items':{},'engines':{'148':str(self.root/'old-engine.exe')},'fixture':{'keep':True}}
        path=self.root/'local-source-archive.bin';write_encrypted(path,encode_archive(archive,self.root),root=self.root)
        return path

    def test_existing_engine_mapping_is_validated_and_never_replaced(self):
        self.archive();store=Mock();store.validate.return_value=self.root/'old-engine.exe'
        with patch('local_engine.LocalEngineStore',return_value=store),patch.object(BitSource,'_core_path') as source:
            self.assertEqual(self.configuration.local_core('148'),self.root/'old-engine.exe')
        source.assert_not_called();store.ensure.assert_not_called()

    def test_new_engine_mapping_is_atomic_encrypted_and_keeps_existing_values(self):
        path=self.archive();source=self.base/'stock.exe';deployed=self.root/'new-engine.exe'
        store=Mock();store.ensure.return_value=deployed;store.validate.return_value=deployed
        with patch('local_engine.LocalEngineStore',return_value=store),patch.object(BitSource,'_core_path',return_value=source):
            self.assertEqual(self.configuration.local_core('124'),deployed)
        store.ensure.assert_called_once_with('124',source,self.signer.public_der)
        value=self.configuration.source_archive()
        self.assertEqual(value['engines'],{'148':str(self.root/'old-engine.exe'),'124':str(deployed)})
        self.assertEqual(value['fixture'],{'keep':True})
        self.assertNotIn(b'new-engine.exe',path.read_bytes())

    def test_engine_deploy_or_archive_publish_failure_preserves_old_archive(self):
        path=self.archive();before=path.read_bytes();store=Mock()
        with patch('local_engine.LocalEngineStore',return_value=store),patch.object(BitSource,'_core_path',return_value=self.base/'stock.exe'):
            store.ensure.side_effect=LocalBrowserError('fixture')
            with self.assertRaises(LocalBrowserError):self.configuration.local_core('124')
            self.assertEqual(path.read_bytes(),before)
            store.ensure.side_effect=None;store.ensure.return_value=self.root/'new-engine.exe';store.validate.return_value=store.ensure.return_value
            with patch('local_state.os.replace',side_effect=OSError('fixture')),self.assertRaises(LocalBrowserError):
                self.configuration.local_core('124')
            self.assertEqual(path.read_bytes(),before)
        self.assertEqual(read_encrypted(path,root=self.root)['fixture'],{'keep':True})


class FrozenSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='frozen-source-test-');self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.root=self.base/'data';self.root.mkdir()
        PortableVault(self.root).initialize();self.signer=LocalSigner(self.root)
        self.configuration=Configuration.__new__(Configuration)
        self.configuration._key=hashlib.sha256(b'synthetic frozen-source aes key').digest()
        self.configuration.vendor_data=self.base/'vendor'
        self.cache=self.configuration.vendor_data/'LocalCache';self.cache.mkdir(parents=True)
        self.path=self.cache/IDENTITY
        self.public=patch('signature_lifetime._verification_key',return_value=self.signer._public_key)
        self.public.start();self.addCleanup(self.public.stop)
        self.info=full('130',{'CipherKey':'synthetic protection only'})
        self.info['browserFingerPrint']['isIpCreatePosition']=True
        self.native={'Resource':{'fixture':True},'DataProtect':copy.deepcopy(source_protection(self.info['browserFingerPrint'])),
            'userAgentVersion':'130.0.0.0',
            'Variations':{'Seed':'synthetic source seed','Sign':'synthetic source signature'},
            'geoPosition':{'latitude':20.5,'longitude':30.25,'accuracy':500},'geoPositionMode':'prompt',
            'navigator':{'hardwareConcurrency':4},'screen':{'width':1200},'timeZone':'synthetic zone'}

    def write(self,native=None):
        self.path.write_bytes(self.signer.sign_native(native or self.native,self.configuration._key,core_major='130'))

    def rebuilt(self):
        result=copy.deepcopy(self.native);result['Variations']=None
        result['geoPosition']={'latitude':21.5,'longitude':32.25,'accuracy':1000}
        return result

    def test_only_actual_variations_and_ip_position_are_frozen_without_mutating_source(self):
        self.write();before=self.path.read_bytes();rebuilt=self.rebuilt();original=copy.deepcopy(rebuilt)
        frozen,evidence=freeze_source_native(self.configuration,self.info,rebuilt)
        self.assertEqual(frozen,self.native);self.assertEqual(rebuilt,original)
        self.assertEqual(self.path.read_bytes(),before)
        self.assertEqual(evidence,local_source.source_signature_identity(self.configuration,IDENTITY))

    def test_stale_or_multiple_static_field_differences_are_rejected(self):
        self.write()
        for keys in (('timeZone',),('navigator','screen'),('geoPositionMode',)):
            with self.subTest(keys=keys):
                rebuilt=self.rebuilt()
                for key in keys:rebuilt[key]='changed synthetic static value'
                with self.assertRaises(LocalBrowserError):freeze_source_native(self.configuration,self.info,rebuilt)

    def test_manual_position_and_unknown_position_fields_are_not_recalculated(self):
        self.write();self.info['browserFingerPrint']['isIpCreatePosition']=False
        with self.assertRaises(LocalBrowserError):freeze_source_native(self.configuration,self.info,self.rebuilt())
        self.info['browserFingerPrint']['isIpCreatePosition']=True
        self.info['browserFingerPrint']['position']='2'
        with self.assertRaises(LocalBrowserError):freeze_source_native(self.configuration,self.info,self.rebuilt())
        self.info['browserFingerPrint'].pop('position')
        rebuilt=self.rebuilt();rebuilt['geoPosition']['unsupportedField']=1
        with self.assertRaises(LocalBrowserError):freeze_source_native(self.configuration,self.info,rebuilt)

    def test_wrong_source_id_or_missing_matching_file_never_uses_other_cache(self):
        self.write();wrong=copy.deepcopy(self.info);wrong['browserFingerPrint']['browserId']='4'*32
        with self.assertRaises(LocalBrowserError):freeze_source_native(self.configuration,wrong,self.rebuilt())
        self.path.rename(self.cache/('4'*32))
        with patch.object(local_source,'public_variations',side_effect=LocalBrowserError('synthetic unavailable')) as public,\
                self.assertRaises(LocalBrowserError):freeze_source_native(self.configuration,self.info,self.rebuilt())
        public.assert_called_once()

    def test_normal_closed_source_recovers_public_seed_and_keeps_existing_geo_conversion(self):
        rebuilt=self.rebuilt();variations={'Seed':'synthetic public seed','Sign':'synthetic public signature'}
        with patch.object(local_source,'public_variations',return_value=variations):
            frozen,evidence=freeze_source_native(self.configuration,self.info,rebuilt)
        self.assertEqual(frozen['Variations'],variations)
        self.assertEqual(frozen['geoPosition'],rebuilt['geoPosition'])
        self.assertEqual(frozen['DataProtect'],rebuilt['DataProtect'])
        self.assertFalse(evidence['present'])

    def test_wrong_protection_or_rebuilt_protection_is_rejected(self):
        self.write()
        rebuilt=self.rebuilt();rebuilt['DataProtect']={'CipherKey':'wrong synthetic protection'}
        with self.assertRaises(LocalBrowserError):freeze_source_native(self.configuration,self.info,rebuilt)
        wrong=copy.deepcopy(self.native);wrong['DataProtect']={'CipherKey':'wrong synthetic protection'};self.write(wrong)
        with self.assertRaises(LocalBrowserError):freeze_source_native(self.configuration,self.info,self.rebuilt())

    def test_bad_signature_ciphertext_and_unknown_envelope_are_rejected(self):
        for offset in (0,8,30,-1):
            with self.subTest(offset=offset):
                self.write();raw=bytearray(self.path.read_bytes());raw[offset]^=1;self.path.write_bytes(raw)
                with self.assertRaises(LocalBrowserError):freeze_source_native(self.configuration,self.info,self.rebuilt())

    def test_signature_replacement_during_freeze_is_rejected(self):
        self.write();read=local_source._source_signature;calls=[]
        def replaced(configuration,identity):
            result=read(configuration,identity)
            if not calls:
                changed=copy.deepcopy(self.native);changed['Variations']['Seed']='replacement synthetic seed'
                self.write(changed)
            calls.append(True)
            return result
        with patch.object(local_source,'_source_signature',side_effect=replaced),self.assertRaises(LocalBrowserError):
            freeze_source_native(self.configuration,self.info,self.rebuilt())

    def test_special_parent_link_is_rejected_before_reading_payload(self):
        self.write();original=Path.lstat
        def linked(path,*args,**kwargs):
            info=original(path,*args,**kwargs)
            if path==self.cache:
                return SimpleNamespace(st_mode=info.st_mode,st_file_attributes=getattr(info,'st_file_attributes',0)|0x400)
            return info
        with patch.object(Path,'lstat',linked),self.assertRaises(LocalBrowserError):
            freeze_source_native(self.configuration,self.info,self.rebuilt())

    def test_stable_handle_and_path_may_have_different_windows_ctime_semantics(self):
        self.write();original=os.fstat
        def different_ctime(fd):
            info=original(fd)
            return SimpleNamespace(st_dev=info.st_dev,st_ino=info.st_ino,st_size=info.st_size,
                st_mtime_ns=info.st_mtime_ns,st_ctime_ns=info.st_ctime_ns+12345)
        with patch.object(local_source.os,'fstat',side_effect=different_ctime):
            frozen,_=freeze_source_native(self.configuration,self.info,self.rebuilt())
        self.assertEqual(frozen,self.native)

    def test_replaced_opened_file_or_changed_handle_metadata_is_rejected(self):
        self.write();original=os.fstat
        for mode in ('opened_identity','handle_changed'):
            with self.subTest(mode=mode):
                calls=[]
                def changed(fd):
                    info=original(fd);calls.append(True)
                    return SimpleNamespace(st_dev=info.st_dev,
                        st_ino=info.st_ino+(1 if mode=='opened_identity' else 0),
                        st_size=info.st_size+(1 if mode=='handle_changed' and len(calls)>1 else 0),
                        st_mtime_ns=info.st_mtime_ns,st_ctime_ns=info.st_ctime_ns)
                with patch.object(local_source.os,'fstat',side_effect=changed),self.assertRaises(LocalBrowserError):
                    freeze_source_native(self.configuration,self.info,self.rebuilt())


class PublicVariationsTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key=ec.generate_private_key(ec.SECP256R1())
        self.public=patch.object(local_source,'_variations_key',return_value=self.key.public_key())
        self.public.start();self.addCleanup(self.public.stop)
        self.seed=b'synthetic signed variation proto';self.compressed=gzip.compress(self.seed,mtime=0)
        self.signature=base64.b64encode(self.key.sign(self.seed,ec.ECDSA(hashes.SHA256()))).decode()
        local_source._VARIATIONS_CACHE.clear();self.addCleanup(local_source._VARIATIONS_CACHE.clear)

    def response(self,body=None,signature=None,**headers):
        reply=Mock();reply.status=200;reply.headers={'x-seed-signature':signature or self.signature,**headers}
        stream=io.BytesIO(self.compressed if body is None else body)
        reply.read1=stream.read1
        reply.__enter__=Mock(return_value=reply);reply.__exit__=Mock(return_value=False)
        return reply

    def test_public_seed_matches_exact_ua_milestone_and_is_verified_before_freezing(self):
        reply=self.response();opener=Mock();opener.open.return_value=reply
        with patch.object(local_source,'build_opener',return_value=opener):
            value=local_source.public_variations({'userAgentVersion':'118.0.0.0'})
            again=local_source.public_variations({'userAgentVersion':'118.0.0.0'})
        request=opener.open.call_args.args[0]
        self.assertTrue(request.full_url.endswith('milestone=118'))
        self.assertEqual(opener.open.call_args.kwargs,{'timeout':5})
        self.assertEqual(request.get_header('A-im'),'gzip')
        self.assertIsNone(request.get_header('Authorization'));self.assertIsNone(request.get_header('Cookie'))
        self.assertEqual(value,{'Seed':base64.b64encode(self.compressed).decode(),'Sign':self.signature})
        self.assertEqual(again,value);self.assertEqual(opener.open.call_count,1)
        reply.__exit__.assert_called_once()

    def test_public_seed_bad_signature_bad_compression_and_oversized_body_are_rejected(self):
        for reply in (self.response(signature=base64.b64encode(b'bad signature').decode()),
                self.response(body=b'invalid gzip payload'),self.response(**{'Content-Length':str(local_source._VARIATIONS_LIMIT+1)})):
            with self.subTest(reply=reply):
                opener=Mock();opener.open.return_value=reply
                with patch.object(local_source,'build_opener',return_value=opener),self.assertRaises(LocalBrowserError):
                    local_source.public_variations({'userAgentVersion':'130.0.0.0'})
                self.assertEqual(local_source._VARIATIONS_CACHE,{})
                reply.__exit__.assert_called_once()

    def test_public_seed_timeout_offline_and_invalid_version_never_use_other_milestone(self):
        opener=Mock();reply=self.response();opener.open.return_value=reply
        with patch.object(local_source,'build_opener',return_value=opener),\
                patch.object(local_source.time,'monotonic',side_effect=[0,6]),self.assertRaises(LocalBrowserError):
            local_source.public_variations({'userAgentVersion':'130.0.0.0'})
        reply.__exit__.assert_called_once()
        opener.open.side_effect=OSError('synthetic offline')
        with patch.object(local_source,'build_opener',return_value=opener),self.assertRaises(LocalBrowserError):
            local_source.public_variations({'userAgentVersion':'130.0.0.0'})
        with patch.object(local_source,'build_opener') as network,self.assertRaises(LocalBrowserError):
            local_source.public_variations({'userAgentVersion':'synthetic invalid version'})
        network.assert_not_called();self.assertEqual(local_source._VARIATIONS_CACHE,{})


if __name__=='__main__':unittest.main(verbosity=2)
