"""Temporary fixtures only. Never construct the real manager or launch a browser."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
spec = importlib.util.spec_from_file_location('project_check', ROOT / 'tools/check_project.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class RunnerContracts(unittest.TestCase):
    def test_internal_json_failure_overrides_zero_exit(self):
        for report in ({'success': False, 'checks': {'gate': True}},
                       {'success': True, 'checks': {'gate': False}},
                       {'success': True, 'checks': {}}, {'checks': {'gate': True}}):
            with self.subTest(report=report):
                self.assertFalse(check.classify_output('json', 0, json.dumps(report), '')[0])
        self.assertTrue(check.classify_output('json', 0, '{"success":true,"checks":{"gate":true}}', '')[0])

    def test_unittest_requires_real_completion_and_sync_requires_both_groups(self):
        self.assertFalse(check.classify_output('unittest', 0, '', 'OK\n')[0])
        self.assertTrue(check.classify_output('unittest', 0, '', 'Ran 2 tests in 0.1s\n\nOK\n')[0])
        self.assertFalse(check.classify_output('unittest', 1, '', 'Ran 2 tests in 0.1s\n\nOK\n')[0])
        first = '{"fixture_checks_passed":["synthetic"]}'
        self.assertFalse(check.classify_output('sync', 0, first, '')[0])
        self.assertTrue(check.classify_output('sync', 0, first + '\n{"direct_request_and_process_checks_passed":true}', '')[0])

    def test_timeout_is_a_failure_with_no_child_output_on_console(self):
        with tempfile.TemporaryDirectory() as directory:
            env = check.child_environment(directory, sys.executable)
            result = check.run_command('synthetic-timeout', [sys.executable, '-c', 'import time; time.sleep(5)'],
                                       'exit', env, timeout=0.1)
        self.assertEqual((result['status'], result['reason']), ('failed', 'timeout'))
        self.assertLess(result['seconds'], 5)

    def test_static_compilation_never_imports_code_or_writes_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / 'app'
            app.mkdir()
            (app / 'fixture.pyw').write_text('raise RuntimeError("must not execute")\n', encoding='utf-8')
            (app / 'data').mkdir()
            (app / 'data/private.py').write_text('invalid syntax here!', encoding='utf-8')
            results = check.python_checks(root)
            self.assertEqual([result['status'] for result in results], ['passed'])
            self.assertFalse(list(root.rglob('*.pyc')))

    def test_output_limit_is_a_failure_even_when_child_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(check, 'MAX_LOG_BYTES', 128):
            env = check.child_environment(directory, sys.executable)
            result = check.run_command('synthetic-output', [sys.executable, '-c', 'print("x" * 1024)'], 'exit', env)
        self.assertEqual((result['status'], result['reason']), ('failed', 'output_limit'))
        self.assertTrue(result['log_truncated'])

    def test_child_environment_and_failure_logs_remove_sensitive_values(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(check.os.environ, {'PYTHONPATH': 'outside', 'HTTP_PROXY': 'outside'}):
            env = check.child_environment(directory, sys.executable)
            self.assertNotIn('PYTHONPATH', env)
            self.assertNotIn('HTTP_PROXY', env)
            self.assertEqual(env['PYTHONNOUSERSITE'], '1')
            self.assertTrue(Path(env['APPDATA']).is_relative_to(Path(directory)))
        source = 'username=fixture-user\npassword=fixture-password\n198.51.100.42\nhttps://fixture.invalid/private\nC:\\Users\\fixture-user\\private.bin'
        redacted = check.redact(source)
        for value in ('fixture-user', 'fixture-password', '198.51.100.42', 'fixture.invalid'):
            self.assertNotIn(value, redacted)


class ApplicationContracts(unittest.TestCase):
    def test_public_bridge_preserves_disabled_creation_and_restricted_save(self):
        from manager_service import ManagerService
        service = ManagerService.__new__(ManagerService)
        service.save = Mock(return_value={'fixture': True})
        for action in ('create', 'copy', 'randomize', 'duplicate', 'import_profiles'):
            self.assertFalse(service.request(action, {})['ok'], action)
        result = service.request('save', {'profile': {'id': 'synthetic'}})
        self.assertTrue(result['ok'])
        service.save.assert_called_once_with({'id': 'synthetic'}, allow_fingerprint=False)

    def test_public_record_excludes_native_secrets_and_keeps_original_intact(self):
        from window_store import WindowStore
        record = {'id': 'synthetic', 'fingerprint': {'extendOptions': {'CipherKey': 'fixture-secret'}},
                  '_native': {'DataProtect': {'CipherKey': 'fixture-secret'}},
                  '_runtime': {'fingerprint_path': 'synthetic-missing', 'account_password': 'fixture-secret'},
                  '_source': {'private': 'fixture-secret'}, '_continuity': {'private': 'fixture-secret'}}
        original = copy.deepcopy(record)
        public = WindowStore.public(record)
        self.assertNotIn('fixture-secret', json.dumps(public))
        self.assertFalse(any(key.startswith('_') for key in public))
        self.assertEqual(record, original)

    def test_portable_marker_rebases_managed_paths_and_blocks_escape(self):
        from portable_paths import decode_record, decode_path, encode_record
        from local_state import LocalBrowserError
        with tempfile.TemporaryDirectory() as directory:
            old, moved = Path(directory) / 'first', Path(directory) / 'moved'
            old.mkdir()
            moved.mkdir()
            value = {'_runtime': {'profile_path': str(old / 'profiles/synthetic')}}
            self.assertEqual(encode_record(value, old), value)
            (old / 'portable-mode.bin').write_bytes(b'fixture')
            packed = encode_record(value, old)
            self.assertEqual(packed['_runtime']['profile_path'], '@data/profiles/synthetic')
            self.assertEqual(decode_record(packed, moved)['_runtime']['profile_path'], str(moved / 'profiles/synthetic'))
            for value in ('@data/../escape', '@data/folder\\..\\escape', '@app/C:/escape'):
                with self.assertRaises(LocalBrowserError):
                    decode_path(value, moved)

    def test_independent_marker_uses_supplied_root_without_vendor_context(self):
        from app_paths import APP_ROOT, DATA_ROOT
        from configuration import Configuration
        from local_state import LocalBrowserError
        self.assertEqual(APP_ROOT, (ROOT / 'app').resolve())
        self.assertEqual(DATA_ROOT, APP_ROOT / 'data')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'independent-mode.bin').write_bytes(b'fixture')
            with patch.dict(check.os.environ, {'APPDATA': str(root / 'unavailable-vendor')}), \
                    patch.object(Configuration, '_initial_context', side_effect=AssertionError('Vendor context must not be read')):
                configuration = Configuration(root)
            self.assertTrue(configuration.independent)
            self.assertEqual(configuration.root, root)
            self.assertEqual(configuration.context, {})
            with self.assertRaises(LocalBrowserError):
                configuration.authorization()

    def test_entry_import_and_existing_instance_never_initialize_manager(self):
        import ctypes
        with patch('manager_service.ManagerService', side_effect=AssertionError('Manager must not initialize')) as manager:
            with patch.object(ctypes, 'WinDLL', create=True) as load:
                module = runpy.run_path(str(ROOT / 'app/local_browser.pyw'), run_name='contract_fixture')
                load.assert_not_called()
                kernel, user = Mock(), Mock()
                kernel.CreateMutexW.return_value = 123
                user.FindWindowW.return_value = 0
                load.side_effect = lambda name, **kwargs: kernel if name == 'kernel32' else user
                with patch.object(ctypes, 'get_last_error', return_value=183, create=True), patch.object(sys, 'argv', ['fixture.pyw']):
                    module['main']()
                kernel.CloseHandle.assert_called_once_with(123)
            manager.assert_not_called()
        bridge = next(node for node in ast.parse((ROOT / 'app/local_browser.pyw').read_text(encoding='utf-8')).body
                      if isinstance(node, ast.ClassDef) and node.name == 'Bridge')
        exposed = {node.name for node in bridge.body if isinstance(node, ast.FunctionDef) and not node.name.startswith('_')}
        self.assertEqual(exposed, {'request'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
