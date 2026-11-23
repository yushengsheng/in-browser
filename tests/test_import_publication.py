"""Synthetic publication checks; fixtures are retained for manual removal."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tests')]

from local_state import LocalBrowserError
from test_sync_reliability import fixture
import window_sync


@unittest.skipUnless(os.name == 'nt', 'Requires real Windows sharing semantics')
class ImportPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = ROOT / '测试文件夹'
        base.mkdir(exist_ok=True)
        cls.suite_root = Path(tempfile.mkdtemp(prefix='import-publication-', dir=base))
        (cls.suite_root / 'owner.json').write_text(json.dumps({
            'purpose': 'synthetic-import-publication', 'pid': os.getpid(),
            'retained_for_user_deletion': True}), encoding='utf-8')
        cls.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        cls.kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
            wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        cls.kernel.CreateFileW.restype = wintypes.HANDLE
        cls.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        cls.kernel.CloseHandle.restype = wintypes.BOOL

    def setUp(self):
        self.root = self.suite_root / self._testMethodName
        self.root.mkdir()
        guard = patch.object(window_sync, 'profile_processes', return_value=[])
        guard.start()
        self.addCleanup(guard.stop)

    def hold_without_delete_sharing(self, path):
        # READ/WRITE sharing lets validation finish, but prevents publication.
        # GENERIC_READ is required; attribute-only opens do not deny rename.
        flags = 0x02000000 if path.is_dir() else 0x80
        handle = self.kernel.CreateFileW(str(path), 0x80000000, 0x1 | 0x2, None, 3, flags, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        def release():
            nonlocal handle
            if handle is not None:
                owned, handle = handle, None
                if not self.kernel.CloseHandle(owned):
                    raise ctypes.WinError(ctypes.get_last_error())
        self.addCleanup(release)
        return release

    def prepared(self, label):
        service, sync, items = fixture(self.root / label, count=1)
        with patch.object(sync, '_complete_intent', side_effect=SystemExit(37)):
            with self.assertRaises(SystemExit):
                sync._import(items[0], lambda phase: None)
        intent = next(sync.state.intents(items[0]['source_key']))
        self.assertEqual(intent['state'], 'prepared')
        work, final, config = sync._intent_paths(intent)
        return service, sync, intent, work, final, config

    def trace_rename(self):
        native = window_sync.os.rename
        failures = []
        def rename(source, target):
            try:
                return native(source, target)
            except OSError as error:
                failures.append(error)
                raise
        return patch.object(window_sync.os, 'rename', side_effect=rename), failures

    def assert_prepared(self, service, sync, intent, work):
        remaining = list(sync.state.intents(intent['source_key']))
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]['intent_id'], intent['intent_id'])
        self.assertEqual(remaining[0]['state'], 'prepared')
        self.assertIsNone(service.store.source_binding(intent['source_key']))
        self.assertTrue(work.is_dir())

    def assert_committed(self, service, sync, intent, work, final, config):
        self.assertEqual(service.store.source_binding(intent['source_key']), intent['profile_id'])
        self.assertEqual(len(service.store.all()), 1)
        self.assertEqual(service._manifest(final), intent['data']['manifest'])
        self.assertEqual(window_sync.sha256(config), intent['data']['signature_hash'])
        self.assertEqual(list(sync.state.intents(intent['source_key'])), [])
        self.assertFalse(work.exists())

    def test_transient_profile_and_signature_handles_allow_complete_retry(self):
        for part in ('profile', 'fingerprint.bin'):
            with self.subTest(part=part):
                service, sync, intent, work, final, config = self.prepared(part)
                source_before = service._manifest(self.root / part / 'sources')
                source = work / part
                release = self.hold_without_delete_sharing(source)
                tracing, failures = self.trace_rename()
                with tracing as rename, patch.object(window_sync.time, 'sleep',
                        side_effect=lambda delay: release()) as sleep:
                    result = sync._complete_intent(intent)
                self.assertEqual(result['id'], intent['profile_id'])
                self.assertEqual(len(failures), 1)
                self.assertIn(failures[0].winerror, (5, 32, 33))
                self.assertEqual(sum(c.args[0] == source for c in rename.call_args_list), 2)
                sleep.assert_called_once_with(.05)
                self.assert_committed(service, sync, intent, work, final, config)
                self.assertEqual(service._manifest(self.root / part / 'sources'), source_before)

    def test_persistent_handles_stop_after_three_attempts_and_recover(self):
        for part in ('profile', 'fingerprint.bin'):
            with self.subTest(part=part):
                service, sync, intent, work, final, config = self.prepared(part)
                source = work / part
                release = self.hold_without_delete_sharing(source)
                tracing, failures = self.trace_rename()
                with tracing as rename, patch.object(window_sync.time, 'sleep') as sleep:
                    with self.assertRaises(OSError) as captured:
                        sync._complete_intent(intent)
                self.assertEqual(len(failures), 3)
                self.assertIs(captured.exception, failures[-1])
                self.assertTrue(all(error.winerror in (5, 32, 33) for error in failures))
                self.assertEqual(sum(c.args[0] == source for c in rename.call_args_list), 3)
                self.assertEqual(sleep.call_args_list, [call(.05), call(.1)])
                self.assert_prepared(service, sync, intent, work)
                self.assertTrue(source.exists())
                self.assertEqual(final.exists(), part == 'fingerprint.bin')
                self.assertFalse(config.exists())
                release()
                sync._recover_intents(intent['source_key'])
                self.assert_committed(service, sync, intent, work, final, config)

    def test_changed_publication_content_during_wait_is_rejected(self):
        for part in ('profile', 'fingerprint.bin'):
            with self.subTest(part=part):
                service, sync, intent, work, final, config = self.prepared(part)
                source = work / part
                changed = source / 'proof' if part == 'profile' else source
                release = self.hold_without_delete_sharing(source)
                def change_content(delay):
                    release()
                    changed.write_bytes(b'changed while publication waited')
                tracing, failures = self.trace_rename()
                with tracing as rename, patch.object(window_sync.time, 'sleep',
                        side_effect=change_content) as sleep:
                    with self.assertRaises(LocalBrowserError):
                        sync._complete_intent(intent)
                self.assertEqual(len(failures), 1)
                self.assertEqual(sum(c.args[0] == source for c in rename.call_args_list), 1)
                sleep.assert_called_once_with(.05)
                self.assert_prepared(service, sync, intent, work)
                self.assertEqual(changed.read_bytes(), b'changed while publication waited')
                self.assertEqual(final.exists(), part == 'fingerprint.bin')
                self.assertFalse(config.exists())

    def test_conflicting_target_inserted_during_wait_is_preserved(self):
        for part in ('profile', 'fingerprint.bin'):
            with self.subTest(part=part):
                service, sync, intent, work, final, config = self.prepared(part)
                source = work / part
                release = self.hold_without_delete_sharing(source)
                target_content = final / 'unowned' if part == 'profile' else config
                def insert_target(delay):
                    release()
                    target_content.parent.mkdir(parents=True, exist_ok=True)
                    target_content.write_bytes(b'unrelated synthetic target')
                tracing, failures = self.trace_rename()
                with tracing as rename, patch.object(window_sync.time, 'sleep',
                        side_effect=insert_target) as sleep:
                    with self.assertRaises(LocalBrowserError):
                        sync._complete_intent(intent)
                self.assertEqual(len(failures), 1)
                self.assertEqual(sum(c.args[0] == source for c in rename.call_args_list), 1)
                sleep.assert_called_once_with(.05)
                self.assert_prepared(service, sync, intent, work)
                self.assertEqual(target_content.read_bytes(), b'unrelated synthetic target')
                self.assertTrue(source.exists())

    def test_nonpublication_errors_do_not_retry(self):
        for number, error in enumerate((OSError(13, 'synthetic validation error'),
                                       LocalBrowserError('synthetic validation error'))):
            with self.subTest(kind=type(error).__name__):
                error.winerror = 5
                service, sync, intent, work, final, config = self.prepared(str(number))
                with patch.object(service, '_manifest', side_effect=error) as manifest, \
                        patch.object(window_sync.time, 'sleep') as sleep:
                    with self.assertRaises(type(error)) as captured:
                        sync._complete_intent(intent)
                self.assertIs(captured.exception, error)
                manifest.assert_called_once()
                sleep.assert_not_called()
                self.assert_prepared(service, sync, intent, work)
                self.assertFalse(final.exists())
                self.assertFalse(config.exists())

    def test_other_rename_errors_and_missing_windows_code_do_not_retry(self):
        for code in (2, 80, 112, None):
            with self.subTest(winerror=code):
                service, sync, intent, work, final, config = self.prepared(str(code))
                error = PermissionError(13, 'synthetic rename error')
                if code is not None:
                    error.winerror = code
                with patch.object(window_sync.os, 'rename', side_effect=error) as rename, \
                        patch.object(window_sync.time, 'sleep') as sleep:
                    with self.assertRaises(OSError) as captured:
                        sync._complete_intent(intent)
                self.assertIs(captured.exception, error)
                self.assertFalse(getattr(error, '_sync_publish_retryable', False))
                rename.assert_called_once()
                sleep.assert_not_called()
                self.assert_prepared(service, sync, intent, work)
                self.assertFalse(final.exists())
                self.assertFalse(config.exists())

    def test_extension_publication_lock_does_not_retry(self):
        service, sync, intent, work, final, config = self.prepared('extension')
        extension = self.root / 'external-extension'
        extension.mkdir()
        (extension / 'manifest.json').write_text('{}', encoding='utf-8')
        source = self.root / 'extension' / 'sources' / f'{1:032x}'
        staged = work / 'profile'
        (staged / 'Default' / 'Preferences').write_text(json.dumps({
            'extensions': {'settings': {'synthetic': {'path': str(extension), 'state': 1}}}}),
            encoding='utf-8')
        copy_profile = service._copy_profile
        releases = []
        def copy_then_hold(original, pending):
            result = copy_profile(original, pending)
            releases.append(self.hold_without_delete_sharing(pending))
            return result
        tracing, failures = self.trace_rename()
        with patch.object(service, '_copy_profile', side_effect=copy_then_hold), \
                tracing as rename, patch.object(window_sync.time, 'sleep') as sleep:
            with self.assertRaises(OSError) as captured:
                sync._extensions(source, staged, final)
        self.assertEqual(len(failures), 1)
        self.assertIs(captured.exception, failures[0])
        self.assertIn(failures[0].winerror, (5, 32, 33))
        rename.assert_called_once()
        sleep.assert_not_called()
        for release in releases:
            release()
        self.assert_prepared(service, sync, intent, work)


if __name__ == '__main__':
    unittest.main()
