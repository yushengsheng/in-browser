"""Only synthetic trees are copied; no browser or real installation data is opened."""
from contextlib import contextmanager, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'app')]
import portable_transfer as transfer


class PortableTransfer(unittest.TestCase):
    def setUp(self):
        budget = patch.object(transfer, 'MAX_TARGET_UNITS', 512)
        budget.start()
        self.addCleanup(budget.stop)
        self.temporary = tempfile.TemporaryDirectory(prefix='ib-transfer-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.base, self.source, self.target = (self.root / name for name in ('base', 'old', 'new'))
        self.base.mkdir(); self.source.mkdir()
        for name in ('runtime/python/python.exe', 'app/local_browser.pyw', '启动本地浏览器.cmd',
                     'app/engines/148/bitbrowser.exe'):
            self.write(self.base / name, b'synthetic-public')
        (self.base / 'runtime/empty').mkdir()
        self.manifest()
        for name in transfer.MANAGED:
            (self.source / name).mkdir(parents=True)
        self.write(self.source / 'app/engines/148/bitbrowser.exe', b'synthetic-public')
        self.write(self.source / 'app/data/.hidden/key.bin', b'synthetic-only-key')
        self.write(self.source / 'app/data/profiles/synthetic/storage', b'synthetic-only-storage')
        (self.source / 'app/data/profiles/synthetic/empty').mkdir()

    @staticmethod
    def write(path, data):
        path = transfer.io_path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def manifest(self):
        files = {p.relative_to(self.base).as_posix(): {'bytes': p.stat().st_size,
                    'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                 for p in self.base.rglob('*') if p.is_file() and p.name != 'release-manifest.json'}
        (self.base / 'release-manifest.json').write_text(json.dumps({'algorithm': 'SHA256', 'files': files}), 'utf-8')

    @contextmanager
    def isolated(self):
        with patch.object(transfer, 'closed') as closed, patch.object(transfer, 'validate_data', return_value=1), \
                patch.object(transfer, 'manager_guards') as guards:
            guards.return_value.__enter__.return_value = None
            yield closed

    def run_transfer(self):
        return transfer.transfer(self.base, self.source, self.target)

    def test_complete_copy_keeps_hidden_empty_directories_and_long_names_without_short_aliases(self):
        deep = self.source / 'app/data/profiles/synthetic'
        for _ in range(5):
            deep /= '中文😀' * 10
        self.assertGreater(len(str(deep).encode('utf-16-le')) // 2, 260)
        self.write(deep / 'storage', b'long-path-synthetic')
        before = transfer.inventory(self.source, transfer.MANAGED, time.monotonic() + 30)
        with self.isolated() as closed:
            result = self.run_transfer()
        self.assertTrue(result['verified'])
        self.assertEqual(closed.call_count, 2)
        self.assertEqual(before, transfer.inventory(self.source, transfer.MANAGED, time.monotonic() + 30))
        self.assertTrue((self.target / 'app/data/profiles/synthetic/empty').is_dir())
        self.assertTrue((self.target / 'runtime/empty').is_dir())
        self.assertEqual(transfer.io_path(self.target / deep.relative_to(self.source) / 'storage').read_bytes(), b'long-path-synthetic')
        self.assertEqual((self.target / 'app/data/.hidden/key.bin').read_bytes(), b'synthetic-only-key')

    def test_same_name_stock_engine_conflict_is_rejected_before_creating_target(self):
        self.write(self.source / 'app/engines/148/bitbrowser.exe', b'different')
        with self.isolated(), self.assertRaises(transfer.TransferError):
            self.run_transfer()
        self.assertFalse(self.target.exists())
        self.assertFalse(list(self.root.glob('.transfer-*')))

    def test_incomplete_same_stock_directory_is_never_filled_from_public_base(self):
        (self.source / 'app/engines/148/bitbrowser.exe').unlink()
        with self.isolated(), self.assertRaises(transfer.TransferError):
            self.run_transfer()
        self.assertFalse(list(self.root.glob('.transfer-*')))

    def test_transferred_installation_can_transfer_itself_again_with_extra_old_stock(self):
        for name in transfer.MANAGED:
            (self.base / name).mkdir(parents=True, exist_ok=True)
        self.write(self.base / 'app/data/.hidden/synthetic', b'synthetic')
        self.write(self.base / 'app/engines/112/bitbrowser.exe', b'synthetic-extra-stock')
        with self.isolated():
            result = transfer.transfer(self.base, self.base, self.target)
        self.assertTrue(result['verified'])
        self.assertEqual((self.target / 'app/engines/112/bitbrowser.exe').read_bytes(), b'synthetic-extra-stock')

    def test_manifest_missing_or_wrong_hash_cannot_be_masked_by_old_stock(self):
        (self.base / 'app/engines/148/bitbrowser.exe').unlink()
        with self.isolated(), self.assertRaises(FileNotFoundError):
            self.run_transfer()
        self.assertFalse(list(self.root.glob('.transfer-*')))
        self.write(self.base / 'app/engines/148/bitbrowser.exe', b'tampered')
        with self.isolated(), self.assertRaises(transfer.TransferError):
            self.run_transfer()

    def test_existing_destination_and_source_child_are_refused(self):
        self.target.mkdir()
        (self.target / 'keep').write_bytes(b'keep')
        with self.isolated(), self.assertRaises(transfer.TransferError):
            self.run_transfer()
        self.assertEqual((self.target / 'keep').read_bytes(), b'keep')
        self.target = self.source / 'child'
        with self.isolated(), self.assertRaises(transfer.TransferError):
            self.run_transfer()
        self.assertFalse(self.target.exists())

    def test_default_target_path_budget_refuses_over_80_utf16_units(self):
        self.target = self.root / ('long-target-' * 12)
        self.assertGreater(len(str(self.target).encode('utf-16-le')) // 2, 80)
        with self.isolated(), patch.object(transfer, 'MAX_TARGET_UNITS', 80), self.assertRaises(transfer.TransferError):
            self.run_transfer()
        self.assertFalse(self.target.exists())

    def check_engine_path_gate(self, directory_units, filename):
        try:
            temporary = tempfile.TemporaryDirectory(prefix='LBG-', dir=self.root.anchor)
        except PermissionError:
            self.skipTest('Short drive-root test directory is not writable')
        self.addCleanup(temporary.cleanup)
        workspace = Path(temporary.name).resolve()
        units = lambda path: len(str(path).encode('utf-16-le')) // 2
        self.target = workspace / ('L' * (78 - units(workspace) - 1))
        self.assertEqual(units(self.target), 78)
        relative = Path('app/local-engines') / ('a' * 64) / ('b' * 64)
        relative /= 'c' * (directory_units - units(self.target / relative) - 1)
        self.assertEqual(units(self.target / relative), directory_units)
        self.write(self.source / relative / filename, b'synthetic-engine-resource')
        before = transfer.inventory(self.source, transfer.MANAGED, time.monotonic() + 30)
        with self.isolated(), self.assertRaises(transfer.TargetPathTooDeep):
            self.run_transfer()
        self.assertFalse(self.target.exists())
        self.assertFalse(list(workspace.glob('.transfer-*')))
        self.assertEqual(before, transfer.inventory(self.source, transfer.MANAGED, time.monotonic() + 30))
        self.target = workspace / 'LB'
        self.assertLess(units(self.target / relative), 248)
        self.assertLess(units(self.target / relative / filename), 260)
        with self.isolated():
            self.assertTrue(self.run_transfer()['verified'])
        self.assertEqual(transfer.io_path(self.target / relative / filename).read_bytes(), b'synthetic-engine-resource')

    def test_engine_file_budget_rejects_260_path_before_staging_and_short_root_copies_same_tree(self):
        self.check_engine_path_gate(247, 'synthetic-engine-resource.dll')

    def test_engine_directory_budget_rejects_248_even_when_file_is_below_260(self):
        self.check_engine_path_gate(248, 'f')

    def test_public_runtime_and_stock_directories_use_the_same_real_windows_budget(self):
        target = Path(self.root.anchor) / 'LB'
        for prefix in ('runtime', 'app/engines', 'app/local-engines'):
            relative = prefix + '/' + 'a' * (248 - len(str(target / Path(prefix)).encode('utf-16-le')) // 2 - 1)
            with self.subTest(prefix=prefix), self.assertRaises(transfer.TargetPathTooDeep):
                transfer.check_target_paths(target, {relative: {'directory': True}})

    def test_source_changes_mid_copy_leave_partial_tree_and_never_publish(self):
        original = transfer.copy_file
        changed = False
        def changing(source, target, expected, deadline):
            nonlocal changed
            original(source, target, expected, deadline)
            if not changed:
                changed = True
                self.write(self.source / 'app/data/new-arrival', b'changed')
        with self.isolated(), patch.object(transfer, 'copy_file', side_effect=changing), self.assertRaises(transfer.TransferError):
            self.run_transfer()
        self.assertFalse(self.target.exists())
        self.assertEqual(len(list(self.root.glob('.transfer-*'))), 1)
        self.assertEqual((self.source / 'app/data/.hidden/key.bin').read_bytes(), b'synthetic-only-key')

    def test_cancelled_copy_preserves_partial_and_source(self):
        with self.isolated(), patch.object(transfer, 'copy_file', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.run_transfer()
        self.assertFalse(self.target.exists())
        self.assertEqual(len(list(self.root.glob('.transfer-*'))), 1)

    def test_low_disk_space_refuses_without_partial(self):
        with self.isolated(), patch.object(transfer.shutil, 'disk_usage', return_value=Mock(free=0)), self.assertRaises(transfer.TransferError):
            self.run_transfer()
        self.assertFalse(list(self.root.glob('.transfer-*')))

    def test_linked_source_tree_is_refused(self):
        folder = self.source / 'app/data/link'
        try:
            folder.symlink_to(self.base, target_is_directory=True)
        except OSError:
            self.skipTest('Symlink privilege unavailable')
        with self.isolated(), self.assertRaises(transfer.TransferError):
            self.run_transfer()
        self.assertFalse(self.target.exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows junction boundary')
    def test_junction_is_refused_without_symlink_privilege(self):
        folder = self.source / 'app/data/junction'
        result = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(folder), str(self.base)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        self.assertEqual(result.returncode, 0)
        try:
            with self.isolated(), self.assertRaises(transfer.TransferError):
                self.run_transfer()
            self.assertFalse(self.target.exists())
        finally:
            os.rmdir(folder)

    def test_cli_requires_execute_and_never_prints_input_or_exception(self):
        output = io.StringIO()
        with redirect_stdout(output), patch.object(transfer, 'transfer') as perform:
            self.assertEqual(transfer.main(['--source', 'synthetic-secret-source', '--destination', 'synthetic-secret-target']), 1)
        perform.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), {'success': False, 'source_modified_by_tool': False})

    def test_isolated_embedded_cli_has_tools_imports_and_noargs_prompts(self):
        script = str(ROOT / 'tools/portable_transfer.py')
        code = ('import runpy; runpy.run_path(' + repr(script) + ",run_name='transfer_probe'); "
                'import inspect_installation; print("import_ok")')
        imported = subprocess.run([sys.executable, '-B', '-I', '-c', code], capture_output=True,
            timeout=30, text=True, encoding='utf-8', errors='replace',
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(imported.returncode, 0)
        self.assertEqual(imported.stdout.strip(), 'import_ok')
        self.assertFalse(imported.stderr)
        interactive = subprocess.run([sys.executable, '-B', '-X', 'utf8', script],
            input=str(self.source) + '\n' + str(self.source) + '\n', capture_output=True,
            timeout=30, text=True, encoding='utf-8', errors='replace',
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(interactive.returncode, 1)
        self.assertIn('原来能正常打开的旧程序目录', interactive.stdout)
        self.assertIn('新的短目标目录', interactive.stdout)
        self.assertIn('迁移未完成', interactive.stdout)
        self.assertNotIn(str(self.source), interactive.stdout)
        self.assertFalse(interactive.stderr)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(transfer.main(['--unexpected-secret-path']), 1)
        self.assertEqual(json.loads(output.getvalue()), {'success': False, 'source_modified_by_tool': False})

    def test_real_synthetic_catalog_keys_are_read_only_and_wrong_key_refuses(self):
        from local_signer import LocalSigner
        from local_state import protect, write_encrypted
        from portable_vault import PortableVault
        data = self.source / 'app/data'
        PortableVault(data).initialize()
        for name in ('independent-mode.bin', 'portable-mode.bin', 'continuity-mode.bin'):
            write_encrypted(data / name, {'format': 1, 'state': 'ready'}, root=data)
        LocalSigner(data)
        connection = sqlite3.connect(data / 'windows.sqlite')
        connection.execute('CREATE TABLE profiles(id TEXT, seq INTEGER, created_at TEXT, last_opened_at TEXT, archived INTEGER, data BLOB)')
        connection.execute('CREATE TABLE settings(key TEXT, value BLOB)')
        connection.execute('CREATE TABLE source_bindings(source_key TEXT, profile_id TEXT, imported_at TEXT)')
        connection.execute('INSERT INTO settings VALUES (?,?)', ('synthetic', protect(b'{}', root=data)))
        connection.commit(); connection.close()
        before = transfer.inventory(self.source, transfer.MANAGED, time.monotonic() + 30)
        self.assertEqual(transfer.validate_data(self.source, time.monotonic() + 30), 0)
        self.assertEqual(before, transfer.inventory(self.source, transfer.MANAGED, time.monotonic() + 30))
        key = data / '.portable-vault/.portable-key'
        key.write_bytes(os.urandom(32))
        with self.assertRaises(Exception):
            transfer.validate_data(self.source, time.monotonic() + 30)

    def test_process_check_rejects_relevant_browser_and_unknown_identity(self):
        process = Mock(pid=os.getpid() + 10000)
        process.info = {'exe': str(self.source / 'app/local-engines/synthetic.exe'), 'cmdline': ['synthetic'], 'name': 'synthetic.exe'}
        with patch('psutil.process_iter', return_value=[process]), self.assertRaises(transfer.TransferError):
            transfer.closed((self.base, self.source))
        process.info = {'exe': None, 'cmdline': None, 'name': 'bitbrowser.exe'}
        with patch('psutil.process_iter', return_value=[process]), self.assertRaises(transfer.TransferError):
            transfer.closed((self.base, self.source))

    def test_source_core_context_rebases_app_alias_and_refuses_incomplete_engine(self):
        import inspect_installation
        from local_state import LocalBrowserError
        data = self.source / 'app/data'
        self.write(data / 'portable-mode.bin', b'synthetic-marker')
        fingerprint = data / 'synthetic.bin'
        self.write(fingerprint, b'synthetic-fingerprint')
        record = {'_runtime': {'signature_key_id': 'synthetic-key', 'profile_path': str(data / 'profiles/synthetic'),
            'fingerprint_path': str(fingerprint), 'fingerprint_sha256': hashlib.sha256(fingerprint.read_bytes()).hexdigest(),
            'core_path': str(ROOT / 'app/local-engines/old/synthetic/bitbrowser.exe'), 'core_major': '148'}}
        signer = Mock(key_id='synthetic-key')
        with patch.object(inspect_installation, 'read_catalog', return_value={'quick_check': True, 'records': [record]}), \
                patch('local_state.read_encrypted', return_value={'format': 1, 'state': 'ready'}), \
                patch('local_signer.LocalSigner', return_value=signer), patch('local_signer._envelope', return_value=(None, None, 1)), \
                patch('local_engine.LocalEngineStore') as store:
            store.return_value.validate.side_effect = LocalBrowserError('synthetic-private-detail')
            with self.assertRaises(LocalBrowserError):
                transfer.validate_data(self.source, time.monotonic() + 30)
            actual = store.return_value.validate.call_args.args[0]
            self.assertEqual(transfer.canonical(actual), self.source / 'app/local-engines/old/synthetic/bitbrowser.exe')
            signer._load_private.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
