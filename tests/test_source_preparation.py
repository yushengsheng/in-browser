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
        self.base=Path(self.temp.name).resolve();self.root=self.base/'data';self.root.mkdir()
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

    def test_sibling_portable_packages_both_discover_shared_vendor_without_writing_it(self):
        before={p.relative_to(self.base).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                for folder in (self.vendor,self.profiles) for p in folder.rglob('*') if p.is_file()}
        providers=[]
        for package in ('A','B'):
            root=self.base/package/'app/data';root.mkdir(parents=True)
            (root/'portable-mode.bin').write_bytes(b'synthetic portable marker')
            config=SimpleNamespace(root=root,vendor_data=self.vendor,independent=True,
                source_detail=lambda identity:full(identity),source_archive=lambda:{'items':{}})
            providers.append(BitSource(config))
        processes=SimpleNamespace(uncertain=lambda _:False,occupied=lambda _:False)
        with patch('bit_source.ProfileProcessSnapshot',return_value=processes):
            found=[provider.discover() for provider in providers]
        self.assertEqual([[row['source_id'] for row in rows] for rows in found],[[A,B],[A,B]])
        self.assertTrue(all(row['status']=='ready' for rows in found for row in rows))
        self.assertEqual(providers[0].vendor_data,providers[1].vendor_data)
        self.assertNotEqual(providers[0].configuration.root,providers[1].configuration.root)
        after={p.relative_to(self.base).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
               for folder in (self.vendor,self.profiles) for p in folder.rglob('*') if p.is_file()}
        self.assertEqual(before,after)
        for provider in providers:
            self.assertEqual([p.name for p in provider.configuration.root.iterdir()],['portable-mode.bin'])

    def test_preview_reads_only_display_fields_without_preparing_or_changing_candidates(self):
        provider=self.provider()
        processes=SimpleNamespace(uncertain=lambda _:False,occupied=lambda _:False)
        with patch('bit_source.ProfileProcessSnapshot',return_value=processes):
            candidates=provider.discover()
        before=copy.deepcopy(candidates)
        files={p.relative_to(self.base).as_posix():hashlib.sha256(p.read_bytes()).digest()
               for p in self.base.rglob('*') if p.is_file()}
        reader=Mock()
        reader.source_detail.side_effect=lambda identity,**_:dict(full(identity),
            name='来源 '+identity[0],remark='测试备注 <b>原样显示</b>',password='synthetic-private-only')
        with patch.object(local_source,'_reader',return_value=reader), \
                patch.object(provider.configuration,'prepare_source',side_effect=AssertionError('Unexpected preparation')):
            metadata=provider.preview_metadata(candidates)
        self.assertEqual(candidates,before)
        self.assertEqual(reader.source_detail.call_count,2)
        reader.source_settings.assert_not_called();reader.build_source.assert_not_called()
        for item in candidates:
            value=metadata[item['source_key']]
            self.assertEqual(set(value),{'name','remark','seq'})
            self.assertEqual(value['name'],'来源 '+item['source_id'][0])
            self.assertEqual(value['remark'],'测试备注 <b>原样显示</b>')
            self.assertEqual(value['seq'],7)
        self.assertEqual(files,{p.relative_to(self.base).as_posix():hashlib.sha256(p.read_bytes()).digest()
                               for p in self.base.rglob('*') if p.is_file()})

    def test_prepared_preview_reuses_saved_labels_without_network(self):
        provider=self.provider()
        candidate={'source_id':A,'source_key':'synthetic','status':'ready',
                   'info':dict(full(),remark='已准备的备注')}
        with patch.object(local_source,'_reader',side_effect=AssertionError('Unexpected session')):
            metadata=provider.preview_metadata([candidate])
        self.assertEqual(metadata['synthetic'],{'name':'same fixture name','remark':'已准备的备注','seq':7})

    def test_preview_session_failure_is_bounded_and_does_not_block_import_candidates(self):
        provider=self.provider()
        processes=SimpleNamespace(uncertain=lambda _:False,occupied=lambda _:False)
        with patch('bit_source.ProfileProcessSnapshot',return_value=processes):candidates=provider.discover()
        before=copy.deepcopy(candidates)
        with patch.object(local_source,'_reader',side_effect=RuntimeError('synthetic-private-only')) as reader:
            metadata=provider.preview_metadata(candidates)
        reader.assert_called_once()
        self.assertEqual(candidates,before)
        self.assertTrue(all(value['metadata_note'] for value in metadata.values()))
        self.assertNotIn('synthetic-private-only',json.dumps(metadata))

    def test_preview_wrong_identity_is_not_displayed_and_unsupported_source_is_not_requested(self):
        provider=self.provider();reader=Mock();reader.source_detail.return_value=dict(full(B),remark='wrong source')
        candidate={'source_id':A,'source_key':'synthetic','status':'ready','info':None,'_needs_preparation':True}
        with patch.object(local_source,'_reader',return_value=reader):
            metadata=provider.preview_metadata([candidate])
        self.assertTrue(metadata['synthetic']['metadata_note'])
        self.assertNotIn('wrong source',json.dumps(metadata))
        reader.reset_mock();candidate['status']='unsupported'
        with patch.object(local_source,'_reader',return_value=reader):provider.preview_metadata([candidate])
        reader.source_detail.assert_not_called()

    def test_preview_metadata_stops_new_requests_when_detection_budget_is_spent(self):
        provider=self.provider();reader=Mock();reader.source_detail.return_value=full()
        candidates=[{'source_id':identity,'source_key':identity,'status':'ready','info':None,'_needs_preparation':True}
                    for identity in (A,B)]
        with patch.object(local_source,'_reader',return_value=reader), \
                patch('bit_source.time.monotonic',side_effect=[0,0,0,11]):
            metadata=provider.preview_metadata(candidates)
        reader.source_detail.assert_called_once_with(A,timeout=3)
        self.assertEqual(metadata[A]['name'],'same fixture name')
        self.assertTrue(metadata[B]['metadata_note'])

    def test_one_unreadable_source_does_not_hide_later_window_labels(self):
        candidates=[{'source_id':identity,'source_key':identity,'status':'ready','info':None,'_needs_preparation':True}
                    for identity in (A,B)]
        before=copy.deepcopy(candidates)
        for invalid in (LocalBrowserError('synthetic-private-only'),full(B)):
            provider=self.provider()
            reader=Mock();reader.source_detail.side_effect=[invalid,dict(full(B),remark='第二个窗口')]
            with patch.object(local_source,'_reader',return_value=reader):
                metadata=provider.preview_metadata(candidates)
            self.assertEqual(reader.source_detail.call_count,2)
            self.assertTrue(metadata[A]['metadata_note'])
            self.assertEqual(metadata[B]['remark'],'第二个窗口')
            self.assertNotIn('synthetic-private-only',json.dumps(metadata))
            self.assertEqual(candidates,before)

    def test_preview_retry_completes_remaining_labels_and_expires_memory_cache(self):
        provider=self.provider();reader=Mock()
        reader.source_detail.side_effect=lambda identity,**_:full(identity)
        candidates=[{'source_id':identity,'source_key':identity,'status':'ready','info':None,'_needs_preparation':True}
                    for identity in (A,B)]
        with patch.object(local_source,'_reader',return_value=reader):
            with patch('bit_source.time.monotonic',side_effect=[0,0,0,11]):
                first=provider.preview_metadata(candidates)
            self.assertTrue(first[B]['metadata_note'])
            with patch('bit_source.time.monotonic',return_value=12):
                second=provider.preview_metadata(candidates)
            self.assertTrue(all(not value.get('metadata_note') for value in second.values()))
            self.assertEqual([call.args[0] for call in reader.source_detail.call_args_list],[A,B])
            with patch('bit_source.time.monotonic',return_value=13):
                provider.preview_metadata(candidates)
            self.assertEqual(reader.source_detail.call_count,2)
            with patch('bit_source.time.monotonic',return_value=700):
                provider.preview_metadata(candidates)
            self.assertEqual(reader.source_detail.call_count,4)
            provider.preview_metadata([])
            self.assertEqual(provider._preview_labels,{})

    def test_same_provider_discovers_vendor_installed_after_first_preview(self):
        provider=self.provider()
        (self.root/'portable-mode.bin').write_bytes(b'synthetic portable marker')
        saved=self.vendor/'database-not-installed'
        self.database.rename(saved)
        processes=SimpleNamespace(uncertain=lambda _:False,occupied=lambda _:False)
        with patch('bit_source.ProfileProcessSnapshot',return_value=processes):
            self.assertEqual(provider.discover(),[])
            saved.rename(self.database)
            found=provider.discover()
            self.assertEqual([row['source_id'] for row in found],[A,B])
            self.assertTrue(all(row['status']=='ready' for row in found))
            self.database.rename(saved)
            self.assertEqual(provider.discover(),[])
        self.assertFalse((self.root/'windows.sqlite').exists())

    def test_same_provider_refreshes_vendor_cache_directory_from_wal(self):
        provider=self.provider()
        processes=SimpleNamespace(uncertain=lambda _:False,occupied=lambda _:False)
        moved=self.base/'new vendor cache';shutil.copytree(self.profiles,moved)
        con=sqlite3.connect(self.database)
        try:
            con.execute('PRAGMA journal_mode=WAL')
            with patch('bit_source.ProfileProcessSnapshot',return_value=processes):
                first=provider.discover()
                con.execute('UPDATE global_configs SET config_value=? WHERE config_name=?',
                    (str(moved),'browser_cache_dir'));con.commit()
                second=provider.discover()
        finally:con.close()
        self.assertEqual([row['source_key'] for row in first],[row['source_key'] for row in second])
        self.assertTrue(all(row['profile_path'].parent==moved for row in second))
        with self.assertRaises(LocalBrowserError):provider.revalidate(first[0])

    def test_missing_vendor_returns_only_unavailable_archived_sources(self):
        provider=self.provider()
        (self.root/'portable-mode.bin').write_bytes(b'synthetic portable marker')
        provider.configuration.source_archive=lambda:{'items':{A:{'detail':full(A)}}}
        self.database.rename(self.vendor/'database-not-installed')
        with patch('bit_source.ProfileProcessSnapshot') as processes:
            rows=provider.discover()
        processes.assert_not_called()
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['status'],'missing_data')
        self.assertEqual(rows[0]['source_id'],A)
        self.assertFalse((self.root/'windows.sqlite').exists())

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
        def baseline(probe,root,*,progress=None):
            calls.append('baseline')
            if progress:
                progress('first');progress('second')
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
