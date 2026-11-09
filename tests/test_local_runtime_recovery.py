"""Synthetic catalog commit recovery for renewal and preference saves."""
import copy
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))

from browser_core import sha256
from local_runtime import LocalRuntime
from local_signer import LocalSigner,MAX_VALIDITY_HOURS
from manager_service import ManagerService
from portable_vault import PortableVault
import profile_model
from profile_preferences import apply_preferences
from local_state import LocalBrowserError
from window_store import WindowStore,fingerprint_unreferenced


class RuntimeRecoveryTests(unittest.TestCase):
    @contextmanager
    def fixture(self,operation):
        with tempfile.TemporaryDirectory(prefix='runtime-recovery-') as directory:
            root=Path(directory)
            resources=root/'app/resources';resources.mkdir(parents=True)
            (resources/'defaults.json').write_text(json.dumps({
                'browserFingerPrint':{'isIpCreateTimeZone':True}}),encoding='utf-8')
            with patch.object(profile_model,'APP_ROOT',root/'app'):
                PortableVault(root).initialize()
                signer=LocalSigner(root,validity_hours=MAX_VALIDITY_HOURS)
                native={'DataProtect':{'CipherKey':'synthetic-only'}}
                source=root/'original.bin';source.write_bytes(signer.sign_native(native,b'x'*32))
                executable=root/'BitBrowser.exe';executable.write_bytes(b'synthetic, never run')
                profile=root/'profile';profile.mkdir()
                configuration=SimpleNamespace(decode=lambda _:copy.deepcopy(native),
                    build_local=Mock(return_value=(copy.deepcopy(native),signer.sign_native(native,b'x'*32))))
                store=WindowStore(configuration,root)
                record=profile_model.defaults()
                record.update(id='synthetic',seq=1,created_at='synthetic',archived=False,
                    _native=copy.deepcopy(native),_prefs_dirty=False,_cookie_pending=False,
                    _runtime={'profile_path':str(profile),'fingerprint_path':str(source),
                        'fingerprint_sha256':sha256(source),'core_path':str(executable),
                        'core_major':'148','signature_provider':'local-v1','signature_key_id':signer.key_id})
                store.put(record)
                service=ManagerService.__new__(ManagerService)
                service.root=root;service.store=store;service.configuration=configuration
                service.operations=threading.RLock();service._closed=Mock();service._sync=Mock()
                service._status=Mock(return_value='closed')
                service._runtime=lambda _record,previous:copy.deepcopy(previous)
                runtime=LocalRuntime.__new__(LocalRuntime)
                runtime.root=root;runtime.service=service;runtime.signer=signer
                runtime.engines=SimpleNamespace(validate=lambda *_:executable,ensure_current=lambda *_:executable)
                def execute():
                    if operation=='renew':return runtime.prepare(store.get(record['id']),force=True)
                    return service.save({'id':record['id'],'preferences':{'mute_audio':True}})
                yield service,record,execute,signer

    def test_success_preserves_old_file_and_native_payload(self):
        for operation in ('renew','save'):
            with self.subTest(operation=operation),self.fixture(operation) as (service,old,execute,signer):
                original=Path(old['_runtime']['fingerprint_path']).read_bytes()
                execute()
                current=service.store.get(old['id'])
                target=Path(current['_runtime']['fingerprint_path'])
                self.assertTrue(signer.verify(target))
                self.assertEqual(current['_native'],old['_native'])
                self.assertEqual(current['fingerprint'],old['fingerprint'])
                self.assertEqual(Path(old['_runtime']['fingerprint_path']).read_bytes(),original)
                if operation=='renew':self.assertEqual(target.read_bytes()[284:],original[284:])

    def test_precommit_failure_removes_only_unreferenced_signature(self):
        for operation in ('renew','save'):
            with self.subTest(operation=operation),self.fixture(operation) as (service,old,execute,_):
                failure=OSError('synthetic precommit failure')
                with patch.object(service.store,'put',side_effect=failure):
                    with self.assertRaises(OSError) as raised:execute()
                self.assertIs(raised.exception,failure)
                self.assertEqual(service.store.get(old['id']),old)
                self.assertTrue(Path(old['_runtime']['fingerprint_path']).is_file())
                self.assertEqual(list((service.root/'fingerprints').iterdir()),[])
                service._sync.assert_not_called()

    def test_engine_repair_preserves_signature_native_and_saved_baseline(self):
        with self.fixture('renew') as (service,old,_execute,signer):
            old['_continuity']={'synthetic':'must stay unchanged'}
            service.store.put(old)
            before=Path(old['_runtime']['fingerprint_path']).read_bytes()
            repaired=service.root/'repaired.exe';repaired.write_bytes(b'synthetic repaired executable')
            runtime=LocalRuntime.__new__(LocalRuntime)
            runtime.root=service.root;runtime.service=service;runtime.signer=signer
            runtime.engines=SimpleNamespace(ensure_current=lambda *_:repaired)
            with patch.object(signer,'resign',side_effect=AssertionError('repair must not resign')):
                result=runtime.prepare(service.store.get(old['id']))
            self.assertEqual(result['_runtime']['core_path'],str(repaired))
            self.assertEqual(result['_native'],old['_native'])
            self.assertEqual(result['_continuity'],old['_continuity'])
            self.assertEqual(Path(result['_runtime']['fingerprint_path']).read_bytes(),before)
            self.assertEqual(service.store.get(old['id']),result)

    def test_postcommit_failure_keeps_referenced_signature_and_retry_works(self):
        for operation in ('renew','save'):
            with self.subTest(operation=operation),self.fixture(operation) as (service,old,execute,signer):
                failure=OSError('synthetic postcommit failure');actual_put=service.store.put
                def committed_then_error(record,**options):
                    actual_put(record,**options)
                    raise failure
                with patch.object(service.store,'put',side_effect=committed_then_error):
                    with self.assertRaises(OSError) as raised:execute()
                self.assertIs(raised.exception,failure)
                current=service.store.get(old['id']);target=Path(current['_runtime']['fingerprint_path'])
                self.assertNotEqual(target,Path(old['_runtime']['fingerprint_path']))
                self.assertTrue(signer.verify(target))
                self.assertEqual(sha256(target),current['_runtime']['fingerprint_sha256'])
                self.assertTrue(Path(old['_runtime']['fingerprint_path']).is_file())
                service._sync.assert_not_called()
                execute()
                self.assertTrue(signer.verify(service.store.get(old['id'])['_runtime']['fingerprint_path']))

    def test_unavailable_readback_preserves_file_and_original_commit_error(self):
        for operation in ('renew','save'):
            with self.subTest(operation=operation),self.fixture(operation) as (service,old,execute,_):
                failure=OSError('synthetic commit failure');actual_get=service.store.get
                attempted=False
                def failed_put(*_args,**_options):
                    nonlocal attempted
                    attempted=True
                    raise failure
                def uncertain_get(identity):
                    if attempted:raise OSError('synthetic unavailable readback')
                    return actual_get(identity)
                with patch.object(service.store,'put',side_effect=failed_put), \
                        patch.object(service.store,'get',side_effect=uncertain_get):
                    with self.assertRaises(OSError) as raised:execute()
                self.assertIs(raised.exception,failure)
                self.assertEqual(len(list((service.root/'fingerprints').glob('*.bin'))),1)
                self.assertEqual(list((service.root/'fingerprints').glob('*.tmp')),[])
                self.assertEqual(actual_get(old['id']),old)
                service._sync.assert_not_called()

    def test_ambiguous_catalog_reference_never_authorizes_cleanup(self):
        with self.fixture('renew') as (service,old,_execute,_signer):
            target=Path(old['_runtime']['fingerprint_path'])
            for record in (None,{}, {'id':old['id'],'_runtime':{}},
                           {'id':old['id'],'_runtime':{'fingerprint_path':'relative.bin'}},
                           {'id':'different','_runtime':{'fingerprint_path':str(service.root/'other.bin')}},
                           {**old,'_runtime':{**old['_runtime'],'fingerprint_sha256':'different'}}):
                with self.subTest(record_type=type(record).__name__),patch.object(service.store,'get',return_value=record):
                    self.assertFalse(fingerprint_unreferenced(service.store,old['id'],target))


class PreferenceRecoveryTests(unittest.TestCase):
    def test_new_created_first_launch_keeps_native_prompt_then_uses_stock_reopen_preference(self):
        from profile_preferences import prepare_clipboard
        for disabled in (False,True):
            with self.subTest(disabled=disabled),tempfile.TemporaryDirectory(prefix='clipboard-first-') as directory:
                root=Path(directory);profile=root/'profile';folder=profile/'Default';folder.mkdir(parents=True)
                path=folder/'Preferences';path.write_text('{}',encoding='utf-8')
                record={'id':'synthetic','created_locally':True,'_prefs_dirty':True,
                    '_runtime':{'profile_path':str(profile),'new_profile':True,'has_launched':False},
                    'preferences':{**profile_model.PREFERENCES,'disable_clipboard':disabled}}
                service=SimpleNamespace(root=root,store=Mock(),settings=lambda:{'download_dir':''},_sync=Mock())
                apply_preferences(service,record);prepare_clipboard(record)
                values=json.loads(path.read_text(encoding='utf-8'))['profile']['default_content_setting_values']
                if disabled:self.assertEqual(values['clipboard'],2)
                else:self.assertNotIn('clipboard',values)
                record['_runtime'].update(new_profile=False,has_launched=True)
                prepare_clipboard(record)
                self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['profile']['default_content_setting_values']['clipboard'],2 if disabled else 1)

    def test_clipboard_launch_parity_preserves_unrelated_data_and_is_idempotent(self):
        from profile_preferences import prepare_clipboard
        with tempfile.TemporaryDirectory(prefix='clipboard-launch-') as directory:
            profile=Path(directory);folder=profile/'Default';folder.mkdir()
            path=folder/'Preferences'
            original={'profile':{'content_settings':{'exceptions':{'clipboard':{'synthetic':True}}}},
                      'session':{'restore_on_startup':1},'synthetic':{'preserved':True}}
            path.write_text(json.dumps(original),encoding='utf-8')
            raw=path.read_bytes()
            record={'_runtime':{'profile_path':str(profile)},'preferences':{'disable_clipboard':False}}
            self.assertTrue(prepare_clipboard(record))
            result=json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(result['profile']['default_content_setting_values']['clipboard'],1)
            self.assertEqual(result['profile']['content_settings'],original['profile']['content_settings'])
            self.assertEqual(result['session'],original['session'])
            self.assertEqual(path.with_suffix('.clipboard-backup').read_bytes(),raw)
            before=path.stat().st_mtime_ns
            self.assertFalse(prepare_clipboard(record))
            self.assertEqual(path.stat().st_mtime_ns,before)
            record['preferences']['disable_clipboard']=True
            self.assertTrue(prepare_clipboard(record))
            result=json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(result['profile']['default_content_setting_values']['clipboard'],2)
            self.assertNotIn('clipboard',result['profile']['content_settings']['exceptions'])
            self.assertEqual(result['synthetic'],original['synthetic'])

    def test_clipboard_launch_write_failure_keeps_original_and_backup(self):
        from profile_preferences import prepare_clipboard
        with tempfile.TemporaryDirectory(prefix='clipboard-failure-') as directory:
            profile=Path(directory);folder=profile/'Default';folder.mkdir()
            path=folder/'Preferences';path.write_text('{"synthetic":true}',encoding='utf-8')
            original=path.read_bytes()
            record={'_runtime':{'profile_path':str(profile)},'preferences':{}}
            with patch('profile_preferences.os.replace',side_effect=OSError('synthetic')):
                with self.assertRaises(LocalBrowserError):prepare_clipboard(record)
            self.assertEqual(path.read_bytes(),original)
            self.assertEqual(path.with_suffix('.clipboard-backup').read_bytes(),original)
            self.assertEqual(list(folder.glob('.clipboard-*.tmp')),[])

    def test_clipboard_disable_clears_residual_top_level_data_even_if_default_is_denied(self):
        from profile_preferences import prepare_clipboard
        with tempfile.TemporaryDirectory(prefix='clipboard-denied-') as directory:
            profile=Path(directory);folder=profile/'Default';folder.mkdir()
            path=folder/'Preferences'
            path.write_text(json.dumps({'profile':{'default_content_setting_values':{'clipboard':2}},
                'clipboard':{'synthetic':'old'}}),encoding='utf-8')
            record={'_runtime':{'profile_path':str(profile)},'preferences':{'disable_clipboard':True}}
            self.assertTrue(prepare_clipboard(record))
            self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['clipboard'],{})
            self.assertFalse(prepare_clipboard(record))

    def test_clipboard_launch_rejects_running_profile_without_writes(self):
        from profile_preferences import prepare_clipboard
        with tempfile.TemporaryDirectory(prefix='clipboard-running-') as directory:
            profile=Path(directory);folder=profile/'Default';folder.mkdir()
            path=folder/'Preferences';path.write_text('{}',encoding='utf-8')
            record={'_runtime':{'profile_path':str(profile)},'preferences':{}}
            with patch('browser_processes.profile_processes',return_value=[object()]):
                with self.assertRaises(LocalBrowserError):prepare_clipboard(record)
            self.assertEqual(path.read_text(encoding='utf-8'),'{}')
            self.assertEqual(len(list(folder.iterdir())),1)

    def test_failed_download_clear_retains_ownership_until_replace_and_retries(self):
        with tempfile.TemporaryDirectory(prefix='preferences-recovery-') as directory:
            root=Path(directory);PortableVault(root).initialize()
            profile=root/'profile';folder=profile/'Default';folder.mkdir(parents=True)
            path=folder/'Preferences'
            original={'download':{'default_directory':str(root/'old-download'),
                                  'prompt_for_download':False,'unrelated':True},
                      'synthetic':{'preserved':True}}
            path.write_text(json.dumps(original),encoding='utf-8')
            before=path.read_bytes()
            store=WindowStore(SimpleNamespace(),root)
            record={'id':'synthetic','seq':1,'created_at':'synthetic','archived':False,
                    '_runtime':{'profile_path':str(profile)},
                    'preferences':copy.deepcopy(profile_model.PREFERENCES),
                    '_download_managed':True,'_prefs_dirty':True}
            store.put(record)
            service=SimpleNamespace(root=root,store=store,settings=lambda:{'download_dir':''},_sync=Mock())
            failure=OSError('synthetic replace failure')
            with patch('profile_preferences.os.replace',side_effect=failure):
                with self.assertRaises(OSError) as raised:apply_preferences(service,store.get(record['id']))
            self.assertIs(raised.exception,failure)
            pending=store.get(record['id'])
            self.assertTrue(pending['_download_managed'])
            self.assertTrue(pending['_prefs_dirty'])
            self.assertEqual(path.read_bytes(),before)
            service._sync.assert_not_called()
            apply_preferences(service,pending)
            result=json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(result['download'],{'unrelated':True})
            self.assertEqual(result['synthetic'],original['synthetic'])
            saved=store.get(record['id'])
            self.assertFalse(saved['_download_managed'])
            self.assertFalse(saved['_prefs_dirty'])

    def test_failed_final_enable_save_keeps_ownership_for_later_setting_clear(self):
        with tempfile.TemporaryDirectory(prefix='preferences-enable-recovery-') as directory:
            root=Path(directory);PortableVault(root).initialize()
            profile=root/'profile';folder=profile/'Default';folder.mkdir(parents=True)
            path=folder/'Preferences';path.write_text('{}',encoding='utf-8')
            store=WindowStore(SimpleNamespace(),root)
            record={'id':'synthetic','seq':1,'created_at':'synthetic','archived':False,
                    '_runtime':{'profile_path':str(profile)},
                    'preferences':copy.deepcopy(profile_model.PREFERENCES),
                    '_download_managed':False,'_prefs_dirty':True}
            store.put(record)
            settings={'download_dir':str(root/'managed-download')}
            service=SimpleNamespace(root=root,store=store,settings=lambda:settings,_sync=Mock())
            failure=OSError('synthetic final catalog failure');actual_put=store.put;calls=0
            def fail_final_put(value):
                nonlocal calls
                calls+=1
                if calls==2:raise failure
                actual_put(value)
            with patch.object(store,'put',side_effect=fail_final_put):
                with self.assertRaises(OSError) as raised:apply_preferences(service,store.get(record['id']))
            self.assertIs(raised.exception,failure)
            self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['download']['default_directory'],settings['download_dir'])
            pending=store.get(record['id'])
            self.assertTrue(pending['_download_managed'])
            self.assertTrue(pending['_prefs_dirty'])
            service._sync.assert_not_called()
            settings['download_dir']=''
            apply_preferences(service,pending)
            self.assertNotIn('default_directory',json.loads(path.read_text(encoding='utf-8'))['download'])
            saved=store.get(record['id'])
            self.assertFalse(saved['_download_managed'])
            self.assertFalse(saved['_prefs_dirty'])


if __name__=='__main__':unittest.main(verbosity=2)
