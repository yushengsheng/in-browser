"""Synthetic program-update transactions; never execute a bundled application."""
from contextlib import chdir, contextmanager
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import py_compile
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TEST_RUNS = ROOT / 'analysis/test-runs'
PACKAGE_ID = '0123456789abcdef0123456789abcdef'
sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tools')]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('synthetic_inplace_update', ROOT / 'tools/inplace_update.py')
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def snapshot(root):
    result = {}
    if root.exists():
        for path in root.rglob('*'):
            if path.is_file():
                info = path.stat()
                result[path.relative_to(root).as_posix()] = (
                    info.st_ino, info.st_size, info.st_mtime_ns, digest(path.read_bytes()))
    return result


@contextmanager
def fixture():
    TEST_RUNS.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix='inplace-update-', dir=TEST_RUNS)
    scope = Path(temporary.name)
    owner = {'pid': os.getpid(), 'scope': str(scope), 'purpose': 'synthetic-inplace-update'}
    marker = scope / '.fixture-owner.json'
    marker.write_text(json.dumps(owner), 'utf-8')
    try:
        yield scope
    finally:
        # Synchronous children only create junctions or import synthetic public
        # modules. All have exited; no browser or application worker is launched.
        import psutil
        safe = not psutil.Process().children(recursive=True)
        safe = safe and scope.resolve().parent == TEST_RUNS.resolve()
        safe = safe and json.loads(marker.read_text('utf-8')) == owner
        for current, directories, files in os.walk(scope, followlinks=False):
            for name in (*directories, *files):
                info = (Path(current) / name).lstat()
                safe = safe and not stat.S_ISLNK(info.st_mode)
                safe = safe and not getattr(info, 'st_file_attributes', 0) & 0x400
        if not safe:
            temporary._finalizer.detach()
            raise AssertionError('synthetic_cleanup_boundary_refused')
        temporary.cleanup()
        if scope.exists():
            raise AssertionError('synthetic_cleanup_incomplete')


def manifest(root):
    files = {}
    for path in root.rglob('*'):
        if path.is_file() and path.name != 'release-manifest.json':
            name = path.relative_to(root).as_posix()
            if name.startswith(('app/data/', 'app/local-engines/', 'app/__pycache__/')):
                continue
            raw = path.read_bytes()
            files[name] = {'bytes': len(raw), 'sha256': digest(raw)}
    write(root / 'release-manifest.json', json.dumps(
        {'algorithm': 'SHA256', 'files': files}, sort_keys=True).encode())
    return files


def release(root, *, version, previous=None):
    root.mkdir(parents=True)
    values = {
        'VERSION': (version + '\n').encode(),
        '启动本地浏览器.cmd': b'@echo off\r\nrem synthetic, never executed\r\n',
        'app/local_browser.pyw': b'# synthetic application entry, never executed\n',
        'app/update_guard.py': b'# synthetic startup guard, never imported\n',
        'app/public.py': ('VERSION = "' + version + '"\n').encode(),
        'app/ui/index.html': ('<p>' + version + '</p>').encode(),
        'runtime/python/python.exe': b'synthetic console, never executed',
        'runtime/python/pythonw.exe': b'synthetic windowless runtime, never executed',
        'runtime/python/site-packages/current.py': ('VALUE = "' + version + '"\n').encode(),
        'runtime/webview2/msedgewebview2.exe': b'synthetic webview runtime, never executed',
        'app/engines/148/manifest.json': b'{"build":"synthetic-148"}',
        'app/engines/148/chrome.exe': b'synthetic immutable inventory core, never executed',
    }
    if previous is None:
        values.update({'app/retired.py': b'# old, listed program module\n',
                       'runtime/python/site-packages/retired.py': b'# old, listed dependency\n'})
    else:
        values['update-policy.json'] = json.dumps({
            'format': 1, 'from_versions': {'0.2.7': digest((previous / 'release-manifest.json').read_bytes())},
            'data_format': 1}, sort_keys=True).encode()
        values['app/new.py'] = b'# new, listed program module\n'
        values['tools/inplace_update.py'] = b'# synthetic update recovery entry, never executed\n'
        values['overlay-package.json'] = json.dumps({'format': 1, 'package_id': PACKAGE_ID}).encode()
    for name, raw in values.items():
        write(root / name, raw)
    runtime_files = {name[len('runtime/'):]: {'bytes': len(raw), 'sha256': digest(raw)}
                     for name, raw in values.items() if name.startswith('runtime/')}
    write(root / 'runtime/manifest.sha256.json', json.dumps(
        {'algorithm': 'SHA256', 'files': runtime_files}, sort_keys=True).encode())
    manifest(root)
    return root


def pair(scope):
    target = release(scope / 'target', version='0.2.7')
    source = release(target / '.program-packages' / PACKAGE_ID, version='0.2.8', previous=target)
    write(target / '启动本地浏览器.cmd', (source / '启动本地浏览器.cmd').read_bytes())
    for name in ('app/data/private-profile/Default/Local Storage/synthetic.bin',
                 'app/data/resources/legacy-adapter.js',
                 'app/local-engines/old-build/chrome.exe',
                 'app/engines/112/chrome.exe'):
        write(target / name, b'synthetic private bytes, must keep identity')
    return source, target


def public_bytes(root):
    result = {}
    for path in root.rglob('*'):
        if path.is_file():
            name = path.relative_to(root).as_posix()
            if name.startswith(('app/data/', 'app/local-engines/', '.program-update', '.program-packages/')):
                continue
            result[name] = path.read_bytes()
    return result


@contextmanager
def synthetic_data_check():
    with patch.object(updater, 'validate_data', return_value={
            'success': True, 'profiles': 0, 'checks': {'synthetic_data': True}}):
        yield


class Interrupted(BaseException):
    pass


class InplaceUpdate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with fixture() as scope:
            probe = scope
            write(scope / 'nested/small.txt', b'cleanup probe')
        if probe.exists():
            raise AssertionError('synthetic_cleanup_probe_failed')

    def assert_protected(self, target, before):
        for name, expected in before.items():
            self.assertEqual(snapshot(target / name), expected, name)

    def protected(self, target):
        return {name: snapshot(target / name) for name in (
            'app/data', 'app/local-engines', 'app/engines')}

    def reject_unchanged(self, source, target):
        before = public_bytes(target)
        protected = self.protected(target)
        with synthetic_data_check(), self.assertRaises(updater.UpdateError) as caught:
            updater.update(source, target)
        self.assertIsInstance(caught.exception.code, str)
        self.assertTrue(caught.exception.code)
        self.assertEqual(public_bytes(target), before)
        self.assert_protected(target, protected)
        self.assertFalse((target / '.program-update').exists())
        return caught.exception

    def test_success_replaces_program_retains_exact_private_identity_and_backup(self):
        with fixture() as scope:
            source, target = pair(scope)
            protected = self.protected(target)
            original = public_bytes(target)
            source_before = snapshot(source)
            with synthetic_data_check():
                result = updater.update(source, target)
            self.assertIsInstance(result, dict)
            self.assertEqual((target / 'VERSION').read_bytes(), b'0.2.8\n')
            self.assertEqual((target / 'app/new.py').read_bytes(), (source / 'app/new.py').read_bytes())
            self.assertFalse((target / 'app/retired.py').exists())
            self.assertFalse((target / 'runtime/python/site-packages/retired.py').exists())
            self.assert_protected(target, protected)
            self.assertEqual(snapshot(source), source_before)
            self.assertFalse((target / '.program-update').exists())
            backups = list(target.glob('.program-update-backup-*'))
            self.assertEqual(len(backups), 1)
            backup_files = [path for path in backups[0].rglob('*') if path.is_file()]
            self.assertTrue(any(path.read_bytes() == original['app/public.py'] for path in backup_files))
            self.assertFalse(any('app/data/' in path.relative_to(backups[0]).as_posix() for path in backup_files))

    def test_missing_new_inventory_build_is_refused_with_existing_inventory_untouched(self):
        with fixture() as scope:
            source, target = pair(scope)
            write(source / 'app/engines/149/chrome.exe', b'new synthetic stock build')
            write(source / 'app/engines/149/manifest.json', b'{"build":"synthetic-149"}')
            manifest(source)
            error = self.reject_unchanged(source, target)
            self.assertEqual(error.code, 'stock_core_missing')
            self.assertFalse((target / 'app/engines/149').exists())

    def test_inventory_path_collision_with_different_bytes_is_rejected_before_writes(self):
        with fixture() as scope:
            source, target = pair(scope)
            write(source / 'app/engines/148/chrome.exe', b'incompatible same-path synthetic build')
            manifest(source)
            self.reject_unchanged(source, target)

    def test_legacy_app_bytecode_does_not_prevent_removing_retired_source(self):
        with fixture() as scope:
            source, target = pair(scope)
            write(target / 'app/__pycache__/retired.cpython-313.pyc', b'synthetic stale cache')
            with synthetic_data_check():
                updater.update(source, target)
            updater.verify_release(target)
            self.assertFalse((target / 'app/retired.py').exists())

    def test_version_downgrade_same_version_and_non_plain_semver_are_rejected(self):
        for version in ('0.2.6', '0.2.7', '0.2.8-rc1', 'v0.2.8', '01.2.8', '0.2.8+meta'):
            with self.subTest(version=version), fixture() as scope:
                source, target = pair(scope)
                write(source / 'VERSION', (version + '\n').encode())
                manifest(source)
                self.reject_unchanged(source, target)

    def test_missing_policy_bad_pin_and_unsupported_source_version_are_rejected(self):
        for mode in ('missing_policy', 'bad_pin', 'unsupported'):
            with self.subTest(mode=mode), fixture() as scope:
                source, target = pair(scope)
                path = source / 'update-policy.json'
                if mode == 'missing_policy':
                    path.unlink()
                else:
                    policy = json.loads(path.read_text('utf-8'))
                    policy['from_versions'] = ({'0.2.7': '0' * 64} if mode == 'bad_pin'
                                               else {'0.2.6': '0' * 64})
                    write(path, json.dumps(policy).encode())
                manifest(source)
                self.reject_unchanged(source, target)

    def test_modified_missing_or_unknown_old_program_files_are_rejected(self):
        for mode in ('modified', 'missing', 'unknown_module', 'unknown_runtime'):
            with self.subTest(mode=mode), fixture() as scope:
                source, target = pair(scope)
                if mode == 'modified':
                    write(target / 'app/public.py', b'# modified old program')
                elif mode == 'missing':
                    (target / 'app/public.py').unlink()
                elif mode == 'unknown_module':
                    write(target / 'app/unknown.py', b'# unknown active module')
                else:
                    write(target / 'runtime/python/site-packages/unknown.py', b'# unknown active dependency')
                self.reject_unchanged(source, target)

    def test_incomplete_new_release_and_runtime_manifest_mismatch_are_rejected(self):
        for mode in ('missing_program', 'modified_program', 'missing_manifest', 'bad_runtime_manifest'):
            with self.subTest(mode=mode), fixture() as scope:
                source, target = pair(scope)
                if mode == 'missing_program':
                    (source / 'app/new.py').unlink()
                elif mode == 'modified_program':
                    write(source / 'app/new.py', b'# modified new program')
                elif mode == 'missing_manifest':
                    (source / 'release-manifest.json').unlink()
                else:
                    write(source / 'runtime/manifest.sha256.json', b'{"algorithm":"SHA256","files":{}}')
                    manifest(source)
                self.reject_unchanged(source, target)

    def test_new_release_requires_startup_and_recovery_components(self):
        for name in ('app/update_guard.py', 'tools/inplace_update.py', 'overlay-package.json'):
            with self.subTest(component=name), fixture() as scope:
                source, target = pair(scope)
                (source / name).unlink()
                manifest(source)
                self.reject_unchanged(source, target)

    def test_source_target_identity_and_ancestor_relationships_are_rejected(self):
        with fixture() as scope:
            source, target = pair(scope)
            (source / 'nested').mkdir()
            (target / 'nested').mkdir()
            for a, b in ((target, target), (source, source / 'nested'), (target / 'nested', target)):
                with self.subTest(direction=str(a == b)), synthetic_data_check(), self.assertRaises(updater.UpdateError):
                    updater.update(a, b)

    def test_busy_or_uninspectable_process_gate_rejects_before_program_writes(self):
        with fixture() as scope:
            source, target = pair(scope)
            before = snapshot(target)
            with patch.object(updater, 'closed', side_effect=RuntimeError('synthetic uninspectable process')):
                with synthetic_data_check(), self.assertRaises(updater.UpdateError):
                    updater.update(source, target)
            self.assertEqual(snapshot(target), before)

    def test_updater_redirects_legacy_bytecode_before_importing_local_helpers(self):
        from check_project import child_environment
        with fixture() as scope:
            package = scope / 'synthetic-package'
            entry = package / 'tools/inplace_update.py'
            write(entry, (ROOT / 'tools/inplace_update.py').read_bytes())
            helpers = {
                package / 'app/update_guard.py': (
                    'UpdateGuardError = ValueError\n'
                    'verify_release = read_update_policy = _manifest = _ordinary = _exists = _root = '
                    '_json_file = _verified_file = _identity = None\n').encode(),
            }
            old = b'raise SystemExit(73)\n'
            stamp = 1700000000
            caches = {}
            for source, fresh in helpers.items():
                size = max(len(old), len(fresh))
                write(source, old.ljust(size, b' '))
                os.utime(source, (stamp, stamp))
                cache = source.parent / '__pycache__' / (
                    source.stem + '.' + sys.implementation.cache_tag + '.pyc')
                cache.parent.mkdir()
                py_compile.compile(str(source), cfile=str(cache), doraise=True,
                                   invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
                write(source, fresh.ljust(size, b' '))
                os.utime(source, (stamp, stamp))
                self.assertEqual(source.stat().st_size, size)
                self.assertEqual(int(source.stat().st_mtime), stamp)
                caches[cache] = cache.read_bytes()
            env = child_environment(scope, sys.executable)
            options = {'env': env, 'cwd': scope, 'stdin': subprocess.DEVNULL,
                       'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE, 'timeout': 20}
            if os.name == 'nt':
                options['creationflags'] = subprocess.CREATE_NO_WINDOW
            for source in helpers:
                # This control proves that -B alone really accepts each stale
                # same-size, same-second timestamp cache on this interpreter.
                control = subprocess.run([sys.executable, '-B', '-c',
                    'import sys;sys.path.insert(0,sys.argv[1]);__import__(sys.argv[2])',
                    str(source.parent), source.stem], **options)
                self.assertEqual(control.returncode, 73, 'synthetic_stale_cache_control_failed')
            completed = subprocess.run([sys.executable, '-B', '-c',
                "import runpy,sys; module=runpy.run_path(sys.argv[1],run_name='synthetic_update_import'); "
                "assert callable(module['update']) and 'main' not in module", str(entry)], **options)
            self.assertEqual(completed.returncode, 0, 'updater_imported_synthetic_stale_bytecode')
            self.assertEqual(completed.stdout, b'')
            self.assertTrue(all(cache.read_bytes() == raw for cache, raw in caches.items()))
            self.assertFalse(list(package.glob('.program-no-cache-*')))

    def test_closed_gate_checks_readable_ownership_before_missing_process_fields(self):
        import psutil
        with fixture() as scope:
            source, target, outside = (scope / name for name in ('source', 'target', 'outside'))
            for directory in (source, target, outside):
                directory.mkdir()
            profile = str(target / 'app/data/profiles/synthetic')
            denied = (
                {'exe': str(target / 'runtime/python/python.exe'), 'cmdline': None, 'name': 'python.exe'},
                {'exe': str(target / 'runtime/custom-renamed.exe'), 'cmdline': None, 'name': 'custom-renamed.exe'},
                {'exe': str(target / 'app/local-engines/old-build/renamed.exe'), 'cmdline': None, 'name': 'renamed.exe'},
                {'exe': None, 'cmdline': [str(target / 'app/local_browser.pyw')], 'name': 'renamed.exe'},
                {'exe': None, 'cmdline': ['renamed.exe', '--user-data-dir=' + profile], 'name': 'renamed.exe'},
                {'exe': None, 'cmdline': ['renamed.exe', '--user-data-dir', profile], 'name': 'renamed.exe'},
                {'exe': None, 'cmdline': None, 'name': 'python.exe'},
            )
            for index, info in enumerate(denied):
                process = SimpleNamespace(pid=os.getpid() + 100000, info=info)
                with self.subTest(case=index), patch.object(psutil, 'process_iter', return_value=[process]), \
                        patch.object(updater.time, 'sleep'):
                    with self.assertRaises(updater.UpdateError):
                        updater.closed((target,))
                    with self.assertRaises(updater.UpdateError):
                        updater.check_closed(source, target)
            allowed = (
                {'exe': str(outside / 'python.exe'), 'cmdline': [str(outside / 'python.exe'), str(outside / 'script.py')], 'name': 'python.exe'},
                {'exe': str(outside / 'renamed.exe'), 'cmdline': ['renamed.exe', '--user-data-dir', str(outside / 'profile')], 'name': 'renamed.exe'},
            )
            for index, info in enumerate(allowed):
                process = SimpleNamespace(pid=os.getpid() + 100000, info=info)
                with self.subTest(unrelated=index), patch.object(psutil, 'process_iter', return_value=[process]):
                    updater.closed((target,))
                    updater.check_closed(source, target)

    def test_closed_gate_relative_system_executable_does_not_belong_to_working_directory(self):
        import psutil
        with fixture() as scope:
            target = scope / 'target'
            target.mkdir()
            process = SimpleNamespace(pid=os.getpid() + 100000,
                info={'exe': 'Registry', 'cmdline': None, 'name': 'Registry'})
            with chdir(target), patch.object(psutil, 'process_iter', return_value=[process]):
                updater.closed((target,))
                updater.check_closed(target / '.program-packages' / PACKAGE_ID, target)

    def test_closed_gate_known_process_without_absolute_executable_remains_unknown(self):
        import psutil
        with fixture() as scope:
            target, outside = scope / 'target', scope / 'outside'
            target.mkdir()
            outside.mkdir()
            executables = [None, '', 'pythonw.exe', 'runtime/python/pythonw.exe']
            if os.name == 'nt':
                executables += [target.drive + 'pythonw.exe', r'\pythonw.exe', '/pythonw.exe',
                                '\\\\?\\' + target.drive + 'pythonw.exe',
                                '\\\\.\\' + target.drive + 'pythonw.exe',
                                '"' + str(outside / 'pythonw.exe') + '"']
            for name in ('pythonw.exe', 'python.exe', 'bitbrowser.exe', 'msedgewebview2.exe'):
                for index, executable in enumerate(executables):
                    process = SimpleNamespace(pid=os.getpid() + 100000, info={
                        'exe': executable, 'cmdline': [str(outside / name), str(outside / 'script.py')],
                        'name': name})
                    with self.subTest(name=name, case=index), chdir(target), \
                            patch.object(psutil, 'process_iter', return_value=[process]):
                        with self.assertRaises(updater.UpdateError) as caught:
                            updater.closed((target,))
                        self.assertEqual(caught.exception.code, 'program_running_or_unknown')

    def test_closed_gate_running_package_is_still_refused_from_target_working_directory(self):
        import psutil
        with fixture() as scope:
            target, outside = scope / 'target', scope / 'outside'
            target.mkdir()
            outside.mkdir()
            executable = str(target / 'runtime/python/pythonw.exe')
            profile = str(target / 'app/data/profiles/synthetic')
            cases = (
                {'exe': executable, 'cmdline': None, 'name': 'renamed.exe'},
                {'exe': executable, 'cmdline': [executable, str(target / 'app/local_browser.pyw')],
                 'name': 'pythonw.exe'},
                {'exe': str(outside / 'python.exe'),
                 'cmdline': ['python.exe', str(target / 'app/local_browser.pyw')], 'name': 'python.exe'},
                {'exe': 'renamed.exe', 'cmdline': ['renamed.exe', '--user-data-dir=' + profile],
                 'name': 'renamed.exe'},
                {'exe': 'renamed.exe', 'cmdline': ['renamed.exe', '--user-data-dir', profile],
                 'name': 'renamed.exe'},
            )
            for index, info in enumerate(cases):
                process = SimpleNamespace(pid=os.getpid() + 100000, info=info)
                with self.subTest(case=index), chdir(target), \
                        patch.object(psutil, 'process_iter', return_value=[process]):
                    with self.assertRaises(updater.UpdateError) as caught:
                        updater.closed((target,))
                    self.assertEqual(caught.exception.code, 'program_running_or_unknown')

    @unittest.skipUnless(os.name == 'nt', 'Windows manager mutex')
    def test_existing_manager_mutex_rejects_before_program_writes(self):
        with fixture() as scope:
            source, target = pair(scope)
            before = snapshot(target)
            with updater.manager_guard(target):
                with synthetic_data_check(), self.assertRaises(updater.UpdateError):
                    updater.update(source, target)
            self.assertEqual(snapshot(target), before)

    def test_program_failure_at_each_transaction_boundary_rolls_back(self):
        for phase in ('after_stage', 'after_bootstrap', 'before_move_old', 'after_move_old',
                      'after_publish', 'before_commit'):
            with self.subTest(phase=phase), fixture() as scope:
                source, target = pair(scope)
                original = public_bytes(target)
                protected = self.protected(target)
                seen = []
                def fail(current, relative):
                    seen.append(current)
                    if current == phase:
                        raise OSError('synthetic transaction failure')
                with synthetic_data_check(), self.assertRaises((updater.UpdateError, OSError)):
                    updater.update(source, target, hook=fail)
                self.assertIn(phase, seen)
                self.assertEqual(public_bytes(target), original)
                self.assert_protected(target, protected)
                self.assertFalse((target / '.program-update').exists())

    def test_interrupted_update_is_recovered_independently_before_commit(self):
        for phase in ('after_stage', 'after_bootstrap', 'before_move_old', 'after_move_old',
                      'after_publish', 'before_commit'):
            with self.subTest(phase=phase), fixture() as scope:
                source, target = pair(scope)
                original = public_bytes(target)
                protected = self.protected(target)
                def stop(current, relative):
                    if current == phase:
                        raise Interrupted()
                with synthetic_data_check(), self.assertRaises(Interrupted):
                    updater.update(source, target, hook=stop)
                self.assertTrue((target / '.program-update').exists())
                with synthetic_data_check():
                    result = updater.recover(source, target)
                self.assertIsInstance(result, dict)
                self.assertEqual(public_bytes(target), original)
                self.assert_protected(target, protected)
                self.assertFalse((target / '.program-update').exists())

    def test_interruption_after_commit_keeps_verified_new_program(self):
        with fixture() as scope:
            source, target = pair(scope)
            protected = self.protected(target)
            def stop(phase, relative):
                if phase == 'after_commit':
                    raise Interrupted()
            with synthetic_data_check(), self.assertRaises(Interrupted):
                updater.update(source, target, hook=stop)
            self.assertFalse((target / '.program-update').exists())
            self.assertEqual(len(list(target.glob('.program-update-backup-*'))), 1)
            self.assertEqual((target / 'VERSION').read_bytes(), b'0.2.8\n')
            updater.verify_release(target)
            self.assert_protected(target, protected)

    def test_real_vault_signer_and_catalog_validation_keeps_original_bytes_and_identities(self):
        from local_signer import LocalSigner
        from local_state import write_encrypted
        from portable_vault import PortableVault
        with fixture() as scope:
            target = scope / 'installation'
            data = target / 'app/data'
            data.mkdir(parents=True)
            vault = PortableVault(data).initialize()
            signer = LocalSigner(data)
            for name, identity in (('portable-mode.bin', vault.key_id),
                                   ('continuity-mode.bin', vault.key_id),
                                   ('independent-mode.bin', signer.key_id)):
                write_encrypted(data / name, {'format': 1, 'state': 'ready', 'key_id': identity}, root=data)
            connection = sqlite3.connect(data / 'windows.sqlite')
            try:
                connection.execute('CREATE TABLE profiles (id TEXT PRIMARY KEY,seq INTEGER UNIQUE,created_at TEXT,last_opened_at TEXT,archived INTEGER,data BLOB)')
                connection.execute('CREATE TABLE settings (key TEXT PRIMARY KEY,value BLOB)')
                connection.execute('CREATE TABLE source_bindings (source_key TEXT PRIMARY KEY,profile_id TEXT UNIQUE,imported_at TEXT)')
                connection.commit()
            finally:
                connection.close()
            work = scope / 'validation-work'
            work.mkdir()
            before = snapshot(data)
            report = updater.validate_data(target, work, time.monotonic() + 10)
            self.assertTrue(report['existing_data'])
            self.assertEqual(report['catalog_rows'], 0)
            self.assertEqual(snapshot(data), before)
            self.assertEqual(PortableVault(data, key_required=True).key_id, vault.key_id)
            self.assertEqual(LocalSigner(data, load_private=False).key_id, signer.key_id)
            self.assertEqual(list(work.iterdir()), [])

    def sync_catalog(self, scope):
        from local_signer import LocalSigner
        from local_state import write_encrypted
        from portable_vault import PortableVault
        from sync_state import SyncState
        from window_store import WindowStore
        target = scope / 'installation'
        data = target / 'app/data'
        data.mkdir(parents=True)
        vault = PortableVault(data).initialize()
        signer = LocalSigner(data)
        for name, identity in (('portable-mode.bin', vault.key_id),
                               ('continuity-mode.bin', vault.key_id),
                               ('independent-mode.bin', signer.key_id)):
            write_encrypted(data / name, {'format': 1, 'state': 'ready', 'key_id': identity}, root=data)
        store = WindowStore(SimpleNamespace(), data)
        state = SyncState(store)
        state.create('synthetic-job', [{'source_key': 'synthetic-source', 'info': {'name': 'synthetic'}}])
        state.finish_item('synthetic-job', 1, 'completed', 'synthetic')
        work = scope / 'validation-work'
        work.mkdir()
        return target, data, work

    @staticmethod
    def remove_result_cursors(connection):
        connection.execute('DROP INDEX sync_items_result_cursor')
        for table in ('sync_jobs', 'sync_items'):
            connection.execute('ALTER TABLE ' + table + ' DROP COLUMN result_cursor')

    def test_catalog_validation_accepts_legacy_and_parallel_sync_schemas_without_writes(self):
        for legacy in (True, False):
            with self.subTest(legacy=legacy), fixture() as scope:
                target, data, work = self.sync_catalog(scope)
                if legacy:
                    with sqlite3.connect(data / 'windows.sqlite') as connection:
                        self.remove_result_cursors(connection)
                    connection.close()
                before = snapshot(data)
                result = updater.validate_data(target, work, time.monotonic() + 10)
                self.assertEqual(result, {'catalog_rows': 0, 'existing_data': True})
                self.assertEqual(snapshot(data), before)
                self.assertEqual(list(work.iterdir()), [])
                with sqlite3.connect(data / 'windows.sqlite') as connection:
                    self.assertEqual(connection.execute('SELECT completed FROM sync_jobs').fetchone(), (1,))
                    self.assertEqual(connection.execute('SELECT state FROM sync_items').fetchone(), ('completed',))
                    if not legacy:
                        for table in ('sync_jobs', 'sync_items'):
                            self.assertEqual(connection.execute('SELECT result_cursor FROM ' + table).fetchone(), (1,))
                connection.close()

    def test_catalog_validation_rejects_extra_missing_and_hidden_columns_without_writes(self):
        statements = (
            'ALTER TABLE sync_jobs ADD COLUMN unexpected INTEGER',
            'ALTER TABLE profiles ADD COLUMN result_cursor INTEGER',
            'ALTER TABLE sync_items DROP COLUMN candidate',
            'ALTER TABLE sync_items ADD COLUMN hidden_value INTEGER GENERATED ALWAYS AS (ordinal + 1) VIRTUAL',
        )
        for index, statement in enumerate(statements):
            with self.subTest(case=index), fixture() as scope:
                target, data, work = self.sync_catalog(scope)
                with sqlite3.connect(data / 'windows.sqlite') as connection:
                    connection.execute(statement)
                connection.close()
                before = snapshot(data)
                with self.assertRaises(updater.UpdateError) as caught:
                    updater.validate_data(target, work, time.monotonic() + 10)
                self.assertEqual(caught.exception.code, 'unsupported_data')
                self.assertEqual(snapshot(data), before)
                self.assertEqual(list(work.iterdir()), [])

    def test_catalog_validation_rejects_noncanonical_result_cursor_columns_without_writes(self):
        variants = (
            ('sync_jobs', 'TEXT NOT NULL DEFAULT 0'),
            ('sync_jobs', 'INTEGER DEFAULT 0'),
            ('sync_jobs', 'INTEGER NOT NULL DEFAULT 1'),
            ('sync_items', 'TEXT'),
            ('sync_items', 'INTEGER NOT NULL DEFAULT 0'),
            ('sync_items', 'INTEGER DEFAULT 0'),
            ('sync_items', 'INTEGER GENERATED ALWAYS AS (ordinal + 1) VIRTUAL'),
        )
        for table, declaration in variants:
            with self.subTest(table=table, declaration=declaration), fixture() as scope:
                target, data, work = self.sync_catalog(scope)
                with sqlite3.connect(data / 'windows.sqlite') as connection:
                    self.remove_result_cursors(connection)
                    connection.execute('ALTER TABLE ' + table + ' ADD COLUMN result_cursor ' + declaration)
                connection.close()
                before = snapshot(data)
                with self.assertRaises(updater.UpdateError) as caught:
                    updater.validate_data(target, work, time.monotonic() + 10)
                self.assertEqual(caught.exception.code, 'unsupported_data')
                self.assertEqual(snapshot(data), before)
                self.assertEqual(list(work.iterdir()), [])

    def test_unknown_or_malicious_pending_transaction_is_retained_and_rejected(self):
        for raw in (b'{}', b'{"format":1,"target":"../../outside","files":["app/data/private"]}',
                    b'{"format":1,"format":1}'):
            with self.subTest(length=len(raw)), fixture() as scope:
                source, target = pair(scope)
                write(target / '.program-update/journal.json', raw)
                before = snapshot(target)
                with synthetic_data_check(), self.assertRaises(updater.UpdateError):
                    updater.recover(source, target)
                self.assertEqual(snapshot(target), before)

    def test_existing_pending_transaction_blocks_a_second_update(self):
        with fixture() as scope:
            source, target = pair(scope)
            write(target / '.program-update/unknown.bin', b'unknown incomplete transaction')
            before = snapshot(target)
            with synthetic_data_check(), self.assertRaises(updater.UpdateError):
                updater.update(source, target)
            self.assertEqual(snapshot(target), before)

    @contextmanager
    def junction(self, link, destination):
        if os.name == 'nt':
            result = subprocess.run([os.environ.get('COMSPEC', 'cmd.exe'), '/d', '/c',
                                     'mklink', '/J', str(link), str(destination)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=10,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 0, 'synthetic_junction_creation_failed')
        else:
            link.symlink_to(destination, target_is_directory=True)
        try:
            yield
        finally:
            os.rmdir(link) if os.name == 'nt' else link.unlink()

    def test_incoming_program_directory_link_is_rejected_without_following_it(self):
        with fixture() as scope:
            source, target = pair(scope)
            ui, moved = source / 'app/ui', scope / 'original-ui'
            ui.rename(moved)
            try:
                with self.junction(ui, moved):
                    self.reject_unchanged(source, target)
            finally:
                moved.rename(ui)

    def test_pending_transaction_link_is_rejected_and_external_sentinel_untouched(self):
        with fixture() as scope:
            source, target = pair(scope)
            outside = scope / 'outside'
            write(outside / 'sentinel.bin', b'synthetic external sentinel')
            def stop(phase, relative):
                if phase == 'after_stage':
                    raise Interrupted()
            with synthetic_data_check(), self.assertRaises(Interrupted):
                updater.update(source, target, hook=stop)
            work = target / '.program-update'
            before = snapshot(outside)
            with self.junction(work / 'hostile-link', outside):
                with synthetic_data_check(), self.assertRaises(updater.UpdateError):
                    updater.recover(source, target)
                self.assertTrue(work.exists())
            self.assertEqual(snapshot(outside), before)
            with synthetic_data_check():
                updater.recover(source, target)

    def test_tampered_recovery_plan_cannot_supply_mutation_paths(self):
        with fixture() as scope:
            source, target = pair(scope)
            def stop(phase, relative):
                if phase == 'after_bootstrap':
                    raise Interrupted()
            with synthetic_data_check(), self.assertRaises(Interrupted):
                updater.update(source, target, hook=stop)
            plan_path = target / '.program-update/plan.json'
            original = plan_path.read_bytes()
            value = json.loads(original)
            value['operations'] = [{'name': 'app/data/private-profile', 'old': None}]
            write(plan_path, json.dumps(value).encode())
            before = snapshot(target)
            with synthetic_data_check(), self.assertRaises(updater.UpdateError):
                updater.recover(source, target)
            self.assertEqual(snapshot(target), before)
            write(plan_path, original)
            with synthetic_data_check():
                updater.recover(source, target)


if __name__ == '__main__':
    # Keep synthetic failure diagnostics bounded and free of private paths.
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(InplaceUpdate)
    names = [test._testMethodName for test in suite]
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    failed = {getattr(test, 'test_case', test)._testMethodName
              for test, _ in result.failures + result.errors}
    print(json.dumps({'success': result.wasSuccessful(), 'tests': result.testsRun,
                      'checks': {name: name not in failed for name in names},
                      'failed': sorted(failed)}))
    print('Ran {} tests in synthetic fixtures'.format(result.testsRun), file=sys.stderr)
    print('OK' if result.wasSuccessful() else 'FAILED (failures={}, errors={})'.format(
        len(result.failures), len(result.errors)), file=sys.stderr)
    sys.exit(0 if result.wasSuccessful() else 1)
