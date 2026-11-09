"""Removed creation paths and retained saves, using synthetic temporary records only."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

from local_state import LocalBrowserError
from manager_service import ManagerService
import profile_model
from window_store import WindowStore
from window_sync import WindowSynchronizer


class RemovedFeatureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='removed-feature-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = self.root / 'app'
        resources = self.app / 'data/resources'
        resources.mkdir(parents=True)
        self.fields = {'resolutionType': '1', 'resolution': '1920x1080', 'canvasValue': 0,
                       'webGLValue': 0, 'audioContextValue': 0, 'hardwareConcurrency': 8,
                       'deviceMemory': 8, 'clientRectNoiseValue': 0, 'userAgent': '',
                       'coreVersion': '148', 'os': 'Win32', 'ostype': 'PC', 'isIpCreateTimeZone': True}
        (resources / 'defaults.json').write_text(json.dumps({'browserFingerPrint': self.fields}), encoding='utf-8')
        model_root = patch.object(profile_model, 'APP_ROOT', self.app)
        model_root.start()
        self.addCleanup(model_root.stop)

    def service(self, *, local=True):
        record = profile_model.defaults()
        record['fingerprint'].update(userAgent='synthetic original agent', canvasValue='13579',
                                     hardwareConcurrency='8', resolution='1280 x 720')
        profile = self.root / 'profiles/existing'
        (profile / 'Default').mkdir(parents=True)
        (profile / 'Default/Preferences').write_text('{}', encoding='utf-8')
        signature = self.root / 'original.bin'
        signature.write_bytes(b'synthetic-original-signature')
        record.update(id='existing', seq=1, name='synthetic', created_at='synthetic',
                      last_opened_at=None, archived=False, _native={'synthetic': True},
                      _runtime={'alias': 'existing', 'profile_path': str(profile),
                                'fingerprint_path': str(signature), 'core_major': '148',
                                'signature_provider': 'local-v1' if local else 'vendor'},
                      _prefs_dirty=False, _cookie_pending=False, _empty=False)
        service = ManagerService.__new__(ManagerService)
        service.root = self.root
        service.operations = threading.RLock()
        service.store = SimpleNamespace(get=Mock(return_value=copy.deepcopy(record)),
                                        put=Mock(), all=Mock(return_value=[copy.deepcopy(record)]),
                                        public=WindowStore.public,
                                        allocate=Mock(side_effect=AssertionError('Must not allocate')),
                                        templates=Mock(side_effect=AssertionError('Must not select a template')))
        service.configuration = SimpleNamespace(build=Mock(return_value=({'synthetic': 'new'}, b'new-signature')),
                                                 build_local=Mock(return_value=({'synthetic': 'new'}, b'new-signature')))
        service.proxy_runtime = SimpleNamespace(stop_if_unused=Mock())
        service._runtime = Mock(return_value=copy.deepcopy(record['_runtime']))
        service._status = Mock(return_value='closed')
        service._closed = Mock()
        service._sync = Mock()
        service._copy_profile = Mock()
        return service, record

    def test_default_fingerprint_is_deterministic_and_independent(self):
        first = profile_model.defaults()
        second = profile_model.defaults()
        self.assertEqual(first, second)
        first['fingerprint']['canvasValue'] = 123
        self.assertEqual(second['fingerprint']['canvasValue'], 0)
        self.assertFalse(hasattr(profile_model, 'randomize'))
        self.assertFalse(hasattr(ManagerService, 'duplicate'))
        self.assertFalse(hasattr(ManagerService, 'import_profiles'))
        self.assertFalse(hasattr(WindowStore, 'allocate'))
        self.assertFalse(hasattr(WindowStore, 'templates'))
        self.assertFalse((ROOT / 'app/legacy_profiles.py').exists())

    def test_save_rejects_missing_or_unknown_id_before_any_write(self):
        service, _ = self.service()
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*'))
        for incoming in ({}, {'id': ''}, {'id': None}, None, []):
            with self.subTest(kind=type(incoming).__name__), self.assertRaises(LocalBrowserError):
                service.save(incoming)
        service.store.get.assert_not_called()
        service.store.get.side_effect = LocalBrowserError('该窗口记录不存在。')
        with self.assertRaises(LocalBrowserError):
            service.save({'id': 'missing'})
        service.store.put.assert_not_called()
        service.store.allocate.assert_not_called()
        service.store.templates.assert_not_called()
        service._runtime.assert_not_called()
        service.configuration.build_local.assert_not_called()
        self.assertEqual(before, sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*')))

    def test_removed_bridge_actions_use_unknown_action_rejection_without_save(self):
        service = ManagerService.__new__(ManagerService)
        service.save = Mock()
        unknown = service.request('synthetic-unknown')
        for action in ('create', 'copy', 'randomize', 'duplicate', 'import_profiles'):
            self.assertEqual(service.request(action, {'profile': {'id': 'existing'}}), unknown)
        service.save.assert_not_called()

    def test_existing_metadata_save_keeps_exact_source_fingerprint(self):
        service, old = self.service()
        incoming = WindowStore.public(old)
        incoming.update(name='renamed', remark='updated', tags=['kept'], urls=['about:blank'])
        reply = service.request('save', {'profile': incoming})
        self.assertTrue(reply['ok'])
        saved = service.store.put.call_args.args[0]
        self.assertEqual(saved['fingerprint'], old['fingerprint'])
        self.assertEqual(saved['_native'], old['_native'])
        self.assertEqual(saved['_runtime']['open_urls_once'], ['about:blank'])
        self.assertEqual((saved['name'], saved['remark']), ('renamed', 'updated'))
        service.configuration.build_local.assert_not_called()
        service._closed.assert_not_called()

    def test_fingerprint_changes_still_fail_closed(self):
        service, old = self.service()
        incoming = {'id': old['id'], 'fingerprint': {'canvasValue': 777}}
        self.assertFalse(service.request('save', {'profile': incoming})['ok'])
        with self.assertRaises(LocalBrowserError):
            service.save(incoming)
        service.store.put.assert_not_called()
        service._runtime.assert_not_called()

    def test_metadata_save_preserves_missing_and_empty_source_fingerprint_fields(self):
        service, old = self.service()
        for ua in (None, ''):
            original = copy.deepcopy(old)
            for field in ('canvasValue', 'webGLValue', 'audioContextValue', 'clientRectNoiseValue', 'userAgent'):
                original['fingerprint'].pop(field, None)
            if ua is not None:
                original['fingerprint']['userAgent'] = ua
            service.store.get.return_value = copy.deepcopy(original)
            with self.subTest(empty_agent=ua == ''):
                reply = service.request('save', {'profile': {'id': original['id'], 'remark': 'metadata only'}})
                self.assertTrue(reply['ok'])
                self.assertEqual(service.store.put.call_args.args[0]['fingerprint'], original['fingerprint'])
        service.configuration.build_local.assert_not_called()

    def test_preferences_keep_old_signature_and_source_fingerprint(self):
        service, old = self.service()
        result = service.request('save', {'profile': {'id': old['id'], 'preferences': {'mute_audio': True}}})
        self.assertTrue(result['ok'])
        saved = service.store.put.call_args.args[0]
        self.assertEqual(saved['fingerprint'], old['fingerprint'])
        self.assertTrue(saved['preferences']['mute_audio'])
        self.assertTrue(saved['_prefs_dirty'])
        self.assertEqual(Path(old['_runtime']['fingerprint_path']).read_bytes(), b'synthetic-original-signature')
        self.assertEqual(Path(saved['_runtime']['fingerprint_path']).read_bytes(), b'new-signature')
        self.assertEqual(service.configuration.build_local.call_args.kwargs['previous_preferences'], old['preferences'])
        service._closed.assert_called_once()

    def test_proxy_and_cookie_saves_keep_fingerprint_and_closed_window_checks(self):
        service, old = self.service()
        proxy = {'type': 'http', 'host': 'fixture.invalid', 'port': 8080}
        cookies = json.dumps([{'name': 'synthetic', 'value': 'synthetic', 'url': 'https://fixture.invalid'}])
        result = service.request('save', {'profile': {'id': old['id'], 'proxy': proxy, 'cookie_text': cookies}})
        self.assertTrue(result['ok'])
        saved = service.store.put.call_args.args[0]
        self.assertEqual(saved['fingerprint'], old['fingerprint'])
        self.assertTrue(saved['_cookie_pending'])
        self.assertEqual(saved['proxy']['type'], 'http')
        service.proxy_runtime.stop_if_unused.assert_called_once_with(old['id'])
        self.assertEqual(service._closed.call_count, 2)
        service.configuration.build_local.assert_not_called()

    def test_failed_catalog_save_removes_only_new_signature(self):
        service, old = self.service()
        service.store.put.side_effect = OSError('synthetic write failure')
        before = (Path(old['_runtime']['profile_path']) / 'Default/Preferences').read_bytes()
        with self.assertRaises(OSError):
            service.save({'id': old['id'], 'preferences': {'mute_audio': True}})
        self.assertEqual(Path(old['_runtime']['fingerprint_path']).read_bytes(), b'synthetic-original-signature')
        self.assertEqual(list((self.root / 'fingerprints').iterdir()), [])
        self.assertEqual((Path(old['_runtime']['profile_path']) / 'Default/Preferences').read_bytes(), before)
        service._sync.assert_not_called()

    def test_core_upgrade_still_backs_up_and_preserves_old_signature_on_failure(self):
        service, old = self.service(local=False)
        service._copy_profile.side_effect = LocalBrowserError('synthetic backup failure')
        with self.assertRaises(LocalBrowserError):
            service.save({'id': old['id'], 'fingerprint': {'coreVersion': '149'}})
        source, target = service._copy_profile.call_args.args
        self.assertEqual(source, Path(old['_runtime']['profile_path']))
        self.assertEqual(target.parent, self.root / 'backups')
        self.assertEqual(Path(old['_runtime']['fingerprint_path']).read_bytes(), b'synthetic-original-signature')
        self.assertEqual(list((self.root / 'fingerprints').iterdir()), [])
        service.store.put.assert_not_called()

    @staticmethod
    def synthetic_catalog():
        return (patch.object(WindowStore, 'pack', lambda self, value: json.dumps(value).encode()),
                patch.object(WindowStore, 'unpack', lambda self, value: json.loads(value)))

    def test_source_record_and_transactional_import_preserve_source_values(self):
        service, old = self.service()
        full = {'browserFingerPrint': copy.deepcopy(old['fingerprint']), 'name': 'source', 'url': ['about:blank']}
        candidate = {'info': {'name': 'source'}, 'source_key': 'synthetic-key', 'source_id': 'synthetic-source'}
        sync = WindowSynchronizer.__new__(WindowSynchronizer)
        sync.service = service
        record = sync._record(candidate, full, old['_native'], old['proxy'], 'imported',
                              self.root / 'profiles/imported', Path(old['_runtime']['fingerprint_path']), {}, [])
        for key in self.fields:
            self.assertEqual(record['fingerprint'][key], full['browserFingerPrint'][key], key)
        pack, unpack = self.synthetic_catalog()
        with pack, unpack:
            store = WindowStore(SimpleNamespace(), self.root / 'catalog')
            store.commit_import(record, candidate['source_key'])
            self.assertEqual(store.source_binding(candidate['source_key']), 'imported')
            self.assertEqual(store.get('imported')['fingerprint'], record['fingerprint'])
            replacement = copy.deepcopy(record)
            replacement['name'] = 'must not replace'
            with self.assertRaises(LocalBrowserError):
                store.commit_import(replacement, candidate['source_key'])
            self.assertEqual(store.get('imported')['name'], 'source')

    def test_legacy_catalog_migration_keeps_available_original_fingerprint(self):
        service, old = self.service()
        root = self.root / 'legacy'
        root.mkdir()
        (root / 'settings.bin').write_bytes(b'synthetic')
        snapshot = self.app.parent / 'analysis/private-bootstrap/selected-settings.bin'
        snapshot.parent.mkdir(parents=True)
        snapshot.write_bytes(b'synthetic')
        native = {'navigator': {'platform': 'Win32', 'hardwareConcurrency': '8', 'deviceMemory': 8},
                  'userAgent': 'synthetic original agent'}
        original = {'browserFingerPrint': copy.deepcopy(old['fingerprint']), 'seq': 1}
        def encrypted(path):
            return [{'alias': old['id'], 'info': original}] if path == snapshot else {'windows': [old['_runtime']]}
        pack, unpack = self.synthetic_catalog()
        with pack, unpack, patch('window_store.APP_ROOT', self.app), patch('window_store.read_encrypted', side_effect=encrypted):
            store = WindowStore(SimpleNamespace(decode=lambda _: native), root)
            migrated = store.get(old['id'])
            self.assertEqual(migrated['fingerprint'], old['fingerprint'])
            self.assertTrue(store.setting('migration_done'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
