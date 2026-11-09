"""Synthetic new-source preparation and publication gates; no private installation."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
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
import import_preparation
import local_source
from local_source import PreparedSources
from local_state import LocalBrowserError
from portable_vault import PortableVault
from source_database import snapshot

A='1'*32;B='2'*32


def full(identity=A):
    return {'id':identity,'name':'same fixture name','seq':7,'browserFingerPrint':{
        'browserId':identity,'coreProduct':'chrome','coreVersion':'148',
        'extendOptions':{'DataProtect':{'CipherKey':'synthetic-protection-only'}}}}


class SourcePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='source-prepare-test-');self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.root=self.base/'data';self.root.mkdir()
        PortableVault(self.root).initialize()
        self.vendor=self.base/'vendor';self.vendor.mkdir()
        cache=self.vendor/'LocalCache';cache.mkdir()
        for identity in (A,B):(cache/identity).write_bytes(b'synthetic cache bytes consumed only by mocked adapter')
        self.profiles=self.base/'source-profiles';self.profiles.mkdir()
        for identity in (A,B):
            folder=self.profiles/identity;(folder/'Default').mkdir(parents=True)
            (folder/'Local State').write_text('{}');(folder/'Default/Preferences').write_text('{}')
            (folder/'Last Version').write_text('148.0.7778.289')
        self.database=self.vendor/'db.sqlite'
        con=sqlite3.connect(self.database)
        con.execute('CREATE TABLE global_configs (config_name TEXT,config_value TEXT)')
        con.execute('INSERT INTO global_configs VALUES (?,?)',('browser_cache_dir',str(self.profiles)))
        con.commit();con.close()
        self.cache=PreparedSources(self.root)
        self.configuration=SimpleNamespace(root=self.root,vendor_data=self.vendor,prepared_sources=lambda:self.cache)

    def reader(self,value=None):
        value=copy.deepcopy(value or full())
        reader=Mock();reader.source_settings.return_value=value
        reader.build_source.return_value=({'DataProtect':copy.deepcopy(value['browserFingerPrint']['extendOptions']['DataProtect'])},None)
        return reader

    def test_prepare_fetches_one_exact_source_and_encrypts_cache(self):
        reader=self.reader()
        with patch.object(local_source,'_reader',return_value=reader):
            value=local_source.prepare(self.configuration,A,'148')
        reader.source_settings.assert_called_once_with(A)
        reader.build_source.assert_called_once_with(value['full'],sign=False,frozen_geo=None)
        self.assertEqual(self.cache.get(A)['full'],value['full'])
        self.assertNotIn(b'synthetic-protection-only',self.cache.database.read_bytes())
        self.assertEqual(self.cache.ids(),{A})

    def test_wrong_source_core_or_protection_never_populates_cache(self):
        for mode in ('identity','core','protection'):
            with self.subTest(mode=mode):
                value=full(B if mode=='identity' else A)
                if mode=='core':value['browserFingerPrint']['coreVersion']='124'
                reader=self.reader(value)
                if mode=='protection':reader.build_source.return_value=({'DataProtect':{'CipherKey':'wrong'}},None)
                with patch.object(local_source,'_reader',return_value=reader),self.assertRaises(LocalBrowserError):
                    local_source.prepare(self.configuration,A,'148')
                self.assertEqual(self.cache.ids(),set())

    def test_same_name_and_sequence_keep_two_separate_sources(self):
        for identity in (A,B):
            with patch.object(local_source,'_reader',return_value=self.reader(full(identity))):
                local_source.prepare(self.configuration,identity,'148')
        self.assertEqual(self.cache.ids(),{A,B})
        self.assertEqual(self.cache.get(A)['full']['id'],A)
        self.assertEqual(self.cache.get(B)['full']['id'],B)

    def test_cache_row_swap_and_mismatched_native_never_apply_to_another_source(self):
        for identity in (A,B):
            with patch.object(local_source,'_reader',return_value=self.reader(full(identity))):
                local_source.prepare(self.configuration,identity,'148')
        value=self.cache.get(A);value['native']['DataProtect']={'CipherKey':'wrong fixture'}
        with self.assertRaises(LocalBrowserError):self.cache.put(value)
        self.assertEqual(self.cache.get(A)['full']['id'],A)
        with self.cache.connect() as con:
            con.execute('UPDATE sources SET payload=(SELECT payload FROM sources WHERE source_id=?) WHERE source_id=?',(B,A))
        with self.assertRaises(LocalBrowserError):self.cache.get(A)
        self.assertEqual(self.cache.get(B)['full']['id'],B)

    def test_source_converter_rejects_random_fingerprint_regeneration(self):
        node=ROOT/'runtime/node/node.exe'
        if not node.is_file():self.skipTest('Bundled Node unavailable')
        source=self.base/'synthetic-adapter.js'
        source.write_text('us={6.3:0};async function ps(info,geo){await hs("",JSON.stringify({DataProtect:{CipherKey:"fixture"},seed:zt(1,9)}));}\n'+
            '\n'.join('function '+name+'(){}' for name in ('gs','_s','ca','os','ss','cs')),encoding='utf-8')
        payload={'sourceFile':str(source),'info':{'browserFingerPrint':{'coreVersion':'148','extendOptions':{'DataProtect':{'CipherKey':'fixture'}}}},'geo':None,'rejectRandomization':True}
        rejected=subprocess.run([str(node),str(ROOT/'app/config_factory.js')],input=json.dumps(payload).encode(),capture_output=True,timeout=5,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        self.assertNotEqual(rejected.returncode,0)
        payload['rejectRandomization']=False
        accepted=subprocess.run([str(node),str(ROOT/'app/config_factory.js')],input=json.dumps(payload).encode(),capture_output=True,timeout=5,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        self.assertEqual(accepted.returncode,0)

    def test_prepared_cache_rebases_only_managed_font_path_on_folder_copy(self):
        value={'format':1,'id':A,'full':full(),'detail':full(),'native':{'DataProtect':full()['browserFingerPrint']['extendOptions']['DataProtect'],'FontConfig':{'BasePath':str(self.root/'fonts')}}}
        self.cache.put(value)
        copied=self.base/'copied';shutil.copytree(self.root,copied)
        self.assertEqual(PreparedSources(copied).get(A)['native']['FontConfig']['BasePath'],str(copied/'fonts'))

    def provider(self):
        prepared={}
        for identity in (A,B):
            folder=self.profiles/identity;(folder/'Default').mkdir(parents=True,exist_ok=True)
            (folder/'Local State').write_text('{}');(folder/'Default/Preferences').write_text('{}')
            (folder/'Last Version').write_text('148.0.7778.289')
        config=self.configuration
        config.independent=True;config.source_archive=lambda:{'profile_root':str(self.profiles),'items':{}}
        config.source_detail=lambda identity:copy.deepcopy(prepared.get(identity))
        config.source_settings=lambda identity:copy.deepcopy(prepared[identity])
        config.local_core=lambda major:self.base/'synthetic-engine.exe'
        config.prepare_source=lambda identity,core:prepared.setdefault(identity,full(identity))
        return BitSource(config)

    def test_source_change_after_preparation_forces_refresh_before_copy(self):
        from configuration import Configuration
        reader=self.reader()
        with patch.object(local_source,'_reader',return_value=reader):local_source.prepare(self.configuration,A,'148')
        config=self.configuration;config.independent=True
        config.source_prepared_for_profile=lambda identity:Configuration.source_prepared_for_profile(config,identity)
        config.source_detail=lambda identity:(self.cache.get(identity) or {}).get('detail')
        config.source_settings=lambda identity:self.cache.get(identity)['full']
        config.local_core=lambda major:self.base/'synthetic-engine.exe'
        provider=BitSource(config)
        self.assertTrue(config.source_prepared_for_profile(A))
        (self.profiles/A/'Default/Preferences').write_text('{"new source state":true}')
        self.assertFalse(config.source_prepared_for_profile(A))
        updated=full();updated['browserFingerPrint']['userAgent']='new fixture UA'
        config.prepare_source=lambda identity,core:local_source.prepare(config,identity,core)
        with patch('bit_source.ProfileProcessSnapshot',return_value=SimpleNamespace(uncertain=lambda _:False,occupied=lambda _:False)),\
                patch('bit_source.profile_processes',return_value=[]),patch.object(local_source,'_reader',return_value=self.reader(updated)):
            item=next(item for item in provider.discover() if item['source_id']==A)
            self.assertTrue(item['_needs_preparation'])
            result=provider.startup(item)
        self.assertEqual(result['info']['browserFingerPrint']['userAgent'],'new fixture UA')
        self.assertTrue(config.source_prepared_for_profile(A))

    def test_source_change_during_network_preparation_never_persists_old_configuration(self):
        reader=self.reader()
        def changed(*args,**kwargs):
            (self.profiles/A/'Default/Preferences').write_text('{"changed during prepare":true}')
            return {'DataProtect':full()['browserFingerPrint']['extendOptions']['DataProtect']},None
        reader.build_source.side_effect=changed
        with patch.object(local_source,'_reader',return_value=reader),self.assertRaises(LocalBrowserError):
            local_source.prepare(self.configuration,A,'148')
        self.assertEqual(self.cache.ids(),set())

    def test_source_signature_change_during_preparation_never_persists_mixed_configuration(self):
        reader=self.reader()
        def changed(*args,**kwargs):
            (self.vendor/'LocalCache'/A).write_bytes(b'changed synthetic cache bytes consumed only by mocked adapter')
            return {'DataProtect':full()['browserFingerPrint']['extendOptions']['DataProtect']},None
        reader.build_source.side_effect=changed
        with patch.object(local_source,'_reader',return_value=reader),self.assertRaises(LocalBrowserError):
            local_source.prepare(self.configuration,A,'148')
        self.assertEqual(self.cache.ids(),set())

    def test_prepared_source_becomes_stale_when_only_actual_launch_signature_changes(self):
        from configuration import Configuration
        with patch.object(local_source,'_reader',return_value=self.reader()):local_source.prepare(self.configuration,A,'148')
        config=self.configuration
        self.assertTrue(Configuration.source_prepared_for_profile(config,A))
        (self.vendor/'LocalCache'/A).write_bytes(b'changed synthetic cache bytes consumed only by mocked adapter')
        self.assertFalse(Configuration.source_prepared_for_profile(config,A))

    def test_normal_closed_source_without_vendor_cache_keeps_first_seed_registration_note(self):
        (self.vendor/'LocalCache'/A).unlink()
        with patch.object(local_source,'_reader',return_value=self.reader()):
            value=local_source.prepare(self.configuration,A,'148')
        self.assertFalse(value['native_source']['present'])
        self.assertEqual(value['import_note'],local_source.PUBLIC_SEED_IMPORT_NOTE)
        self.assertEqual(self.cache.get(A)['import_note'],value['import_note'])

    def test_new_local_profile_is_discovered_then_prepared_without_cloud_list(self):
        provider=self.provider()
        snapshot=SimpleNamespace(uncertain=lambda _:False,occupied=lambda _:False)
        with patch('bit_source.ProfileProcessSnapshot',return_value=snapshot) as scan,patch('bit_source.profile_processes',return_value=[]):
            candidates=provider.discover()
            self.assertEqual(scan.call_count,1)
            self.assertEqual(len(candidates),2)
            self.assertTrue(all(item['status']=='ready' and item['_needs_preparation'] for item in candidates))
            startup=provider.startup(candidates[0])
            self.assertEqual(startup['info']['id'],A)
            self.assertEqual(candidates[0]['info']['name'],'same fixture name')
            self.assertNotIn('_needs_preparation',candidates[0])
            (self.profiles/A/'Default/Preferences').write_text('{"changed":true}')
            with self.assertRaises(LocalBrowserError):provider.revalidate(candidates[0])

    def test_unreadable_browser_state_blocks_source_preview(self):
        provider=self.provider();unknown=SimpleNamespace(uncertain=lambda _:True,occupied=lambda _:False)
        with patch('bit_source.ProfileProcessSnapshot',return_value=unknown):
            self.assertTrue(all(item['status']=='unsupported' for item in provider.discover()))

    def test_sqlite_source_read_connects_only_to_copy_and_preserves_wal(self):
        con=sqlite3.connect(self.database);self.addCleanup(con.close)
        con.execute('PRAGMA journal_mode=WAL');con.execute('INSERT INTO global_configs VALUES (?,?)',('fixture','value'));con.commit()
        paths=[self.database,Path(str(self.database)+'-wal'),Path(str(self.database)+'-shm')]
        before={p.name:hashlib.sha256(p.read_bytes()).digest() for p in paths if p.exists()}
        original=sqlite3.connect
        def connect(path,*args,**kwargs):
            self.assertFalse(str(path).startswith(self.database.as_uri()))
            return original(path,*args,**kwargs)
        with patch('source_database.sqlite3.connect',side_effect=connect),snapshot(self.database) as copied:
            self.assertEqual(copied.execute('SELECT count(*) FROM global_configs').fetchone()[0],2)
        self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).digest() for p in paths if p.exists()})

    def import_record(self):
        (self.root/'portable-mode.bin').write_bytes(b'synthetic marker')
        (self.root/'continuity-mode.bin').write_bytes(b'synthetic marker')
        staged=self.base/'staged';staged.mkdir();work=self.base/'work';work.mkdir()
        (work/'fingerprint.bin').write_bytes(b'synthetic signature')
        record={'id':'local-fixture','_native':{},'_runtime':{'signature_provider':'local-v1',
            'profile_path':str(self.root/'profiles/final'),'fingerprint_path':str(self.root/'fingerprints/final.bin')}}
        return record,staged,work

    def test_import_prepares_key_and_cold_start_baseline_before_publish(self):
        record,staged,work=self.import_record();calls=[]
        def baseline(probe,root):
            calls.append('baseline')
            self.assertEqual(probe['_runtime']['profile_path'],str(staged))
            self.assertEqual(probe['_runtime']['fingerprint_path'],str(work/'fingerprint.bin'))
            return {'binding':{'fixture':True}}
        with patch.object(import_preparation,'capture_profile',side_effect=lambda p:calls.append('key') or {'format':1}),\
                patch.object(import_preparation,'create_baseline',side_effect=baseline),\
                patch.object(import_preparation,'verify_continuity',side_effect=lambda *args:calls.append('verify')),\
                patch.object(import_preparation,'binding_for',return_value={'fixture':True}):
            result=import_preparation.prepare_import(SimpleNamespace(root=self.root),record,{},staged,work)
        self.assertEqual(calls,['key','baseline','verify'])
        self.assertIn('_portable_crypt',result);self.assertIn('_continuity',result)
        self.assertFalse((self.root/'profiles').exists())

    def test_bad_profile_key_or_mismatched_baseline_aborts_preparation(self):
        record,staged,work=self.import_record()
        with patch.object(import_preparation,'capture_profile',side_effect=LocalBrowserError('fixture')),\
                patch.object(import_preparation,'create_baseline') as baseline,self.assertRaises(LocalBrowserError):
            import_preparation.prepare_import(SimpleNamespace(root=self.root),record,{},staged,work)
        baseline.assert_not_called()
        with patch.object(import_preparation,'capture_profile',return_value={'format':1}),\
                patch.object(import_preparation,'create_baseline',return_value={'binding':{'wrong':True}}),\
                patch.object(import_preparation,'verify_continuity'),\
                patch.object(import_preparation,'binding_for',return_value={'correct':True}),self.assertRaises(LocalBrowserError):
            import_preparation.prepare_import(SimpleNamespace(root=self.root),record,{},staged,work)


if __name__=='__main__':unittest.main(verbosity=2)
