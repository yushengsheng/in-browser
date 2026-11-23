"""Synthetic, read-only startup integrity checks; no real application is opened."""
import argparse
import builtins
from contextlib import contextmanager
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from retained_fixture import new_scope, report_checks, test_name
SPEC = importlib.util.spec_from_file_location('synthetic_update_guard', ROOT / 'app/update_guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


@contextmanager
def fixture():
    yield new_scope(ROOT, prefix='update-guard-', purpose='synthetic-update-guard')


def release(base, *, policy=False):
    root = base / 'install'
    root.mkdir()
    values = {
        'VERSION': b'0.2.7\n',
        'app/local_browser.pyw': b'# synthetic entry, never launched\n',
        'app/ui/index.html': b'<p>Synthetic</p>',
        'app/engines/148/manifest.json': b'{}',
        'runtime/python/pythonw.exe': b'synthetic, never executed',
        'runtime/webview2/empty/.keep': b'',
    }
    if policy:
        values['update-policy.json'] = json.dumps({
            'format': 1, 'from_versions': {'0.2.7': 'a' * 64}, 'data_format': 1}).encode()
    for name, raw in values.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    files = {name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
             for name, raw in values.items()}
    (root / 'release-manifest.json').write_text(json.dumps({'algorithm': 'SHA256', 'files': files}), 'utf-8')
    return root, files


def save_manifest(root, files):
    (root / 'release-manifest.json').write_text(json.dumps({'algorithm': 'SHA256', 'files': files}), 'utf-8')


class StartupGuard(unittest.TestCase):
    def rejected(self, root):
        with self.assertRaises(guard.UpdateGuardError):
            guard.verify_release(root)

    def test_development_without_release_markers_is_allowed(self):
        with fixture() as base:
            self.assertEqual(guard.require_complete_installation(base), {
                'development': True, 'files': {}, 'verified_files': 0, 'verified_bytes': 0})

    def test_complete_release_and_strict_policy_are_verified(self):
        with fixture() as base:
            root, files = release(base, policy=True)
            report = guard.require_complete_installation(root)
            self.assertFalse(report['development'])
            self.assertEqual(report['files'], files)
            self.assertEqual(report['verified_files'], len(files))
            self.assertEqual(report['verified_bytes'], sum(item['bytes'] for item in files.values()))
            self.assertEqual(guard.read_update_policy(root)['from_versions'], {'0.2.7': 'a' * 64})

    def test_old_release_without_policy_is_verified(self):
        with fixture() as base:
            root, files = release(base)
            self.assertIsNone(guard.read_update_policy(root))
            self.assertEqual(guard.verify_release(root)['files'], files)

    def test_policy_requires_manifest_and_manifest_membership(self):
        for missing_manifest in (False, True):
            with self.subTest(missing_manifest=missing_manifest), fixture() as base:
                root, files = release(base, policy=True)
                if missing_manifest:
                    (root / 'release-manifest.json').unlink()
                else:
                    del files['update-policy.json']
                    save_manifest(root, files)
                self.rejected(root)

    def test_incomplete_marker_blocks_before_any_metadata_read(self):
        for directory in (False, True):
            with self.subTest(directory=directory), fixture() as base:
                marker = base / '.program-update'
                marker.mkdir() if directory else marker.write_bytes(b'')
                with patch.object(guard, 'verify_release', side_effect=AssertionError('must_not_read')):
                    with self.assertRaises(guard.UpdateGuardError):
                        guard.require_complete_installation(base)

    def test_update_verifier_can_validate_pending_target(self):
        with fixture() as base:
            root, files = release(base)
            (root / '.program-update').mkdir()
            self.assertEqual(guard.verify_release(root)['files'], files)
            with self.assertRaises(guard.UpdateGuardError):
                guard.require_complete_installation(root)

    def test_duplicate_json_keys_are_rejected_at_every_level(self):
        raw_values = (
            '{"algorithm":"SHA256","algorithm":"SHA256","files":{}}',
            '{"algorithm":"SHA256","files":{"VERSION":{"bytes":1,"bytes":1,"sha256":"' + 'a' * 64 + '"}}}',
            '{"algorithm":"SHA256","files":{"VERSION":{},"VERSION":{}}}',
        )
        for raw in raw_values:
            with self.subTest(raw_length=len(raw)), fixture() as base:
                root, _ = release(base)
                (root / 'release-manifest.json').write_text(raw, 'utf-8')
                self.rejected(root)

    def test_invalid_metadata_shape_and_entry_types_are_rejected(self):
        entries = ({'bytes': True, 'sha256': 'a' * 64}, {'bytes': -1, 'sha256': 'a' * 64},
                   {'bytes': 1, 'sha256': 'A' * 64}, {'bytes': 1, 'sha256': 'x'},
                   {'bytes': 1, 'sha256': 'a' * 64, 'other': 0}, [])
        for entry in entries:
            with self.subTest(entry_type=type(entry).__name__), fixture() as base:
                root, files = release(base)
                files['VERSION'] = entry
                save_manifest(root, files)
                self.rejected(root)
        for value in ([], {}, {'algorithm': 'SHA512', 'files': {}},
                      {'algorithm': 'SHA256', 'files': {}, 'extra': 0}):
            with fixture() as base:
                root, _ = release(base)
                (root / 'release-manifest.json').write_text(json.dumps(value), 'utf-8')
                self.rejected(root)

    def test_dangerous_and_private_manifest_paths_are_rejected(self):
        names = ('../outside', '/absolute', 'C:/drive', 'app\\other.py', 'app//other.py',
                 'app/./other.py', 'app/other.py.', 'app/other.py ', 'app/CON.txt',
                 'app/NUL', 'app/com1.py', 'app/has?mark', 'app/new\nline',
                 'app/data', 'APP/Data/private.bin', 'app/local-engines/core',
                 '.program-update', '.program-update/journal.json', 'release-manifest.json')
        for name in names:
            with self.subTest(path_length=len(name)), fixture() as base:
                root, files = release(base)
                files[name] = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
                save_manifest(root, files)
                self.rejected(root)

    def test_case_aliases_and_file_directory_collisions_are_rejected(self):
        additions = ('version', 'APP/other.py', 'app/UI/other.js', 'app', 'app/ui')
        for name in additions:
            with self.subTest(name=name), fixture() as base:
                root, files = release(base)
                files[name] = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
                save_manifest(root, files)
                self.rejected(root)

    def test_missing_damaged_and_resized_files_are_rejected(self):
        for mode in ('missing', 'same_size_damage', 'truncated', 'extended'):
            with self.subTest(mode=mode), fixture() as base:
                root, _ = release(base)
                path = root / 'VERSION'
                if mode == 'missing':
                    path.unlink()
                else:
                    path.write_bytes({'same_size_damage': b'9.9.9\n', 'truncated': b'0',
                                      'extended': b'0.2.7\nextra'}[mode])
                self.rejected(root)

    def test_file_changes_during_hashing_are_rejected(self):
        with fixture() as base:
            root, _ = release(base)
            original = hashlib.sha256
            path = root / 'VERSION'
            changed = False
            class ChangingDigest:
                def __init__(self):
                    self.digest = original()
                def update(self, block):
                    nonlocal changed
                    self.digest.update(block)
                    if not changed:
                        changed = True
                        before = path.stat()
                        path.write_bytes(b'9.9.9\n')
                        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 10 ** 9))
                def hexdigest(self):
                    return self.digest.hexdigest()
            with patch.object(guard.hashlib, 'sha256', side_effect=ChangingDigest):
                self.rejected(root)
            self.assertTrue(changed)

    def test_extra_active_program_files_are_rejected(self):
        for name in ('app/retired.py', 'app/ui/old.js', 'runtime/python/retired.dll',
                     'runtime/python/__pycache__/site.pyc', 'tools/psutil.py',
                     'tools/nested/retired.py'):
            with self.subTest(name=name), fixture() as base:
                root, _ = release(base)
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'never executed')
                self.rejected(root)

    def test_manifest_tools_and_legacy_tools_cache_are_allowed(self):
        with fixture() as base:
            root, files = release(base)
            tool = root / 'tools/update.py'
            tool.parent.mkdir()
            raw = b'# synthetic public tool, never executed\n'
            tool.write_bytes(raw)
            files['tools/update.py'] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            save_manifest(root, files)
            cache = root / 'tools/__pycache__'
            cache.mkdir()
            (cache / 'synthetic.pyc').write_bytes(b'legacy cache, never read')
            original = os.scandir
            def no_cache_read(path):
                self.assertNotEqual(Path(path), cache)
                return original(path)
            with patch.object(guard.os, 'scandir', side_effect=no_cache_read):
                self.assertEqual(guard.verify_release(root)['files'], files)

    def test_legacy_runtime_cache_only_for_manifest_sources_is_kept_without_reading(self):
        with fixture() as base:
            root,files=release(base)
            source=root/'runtime/python/site-packages/synthetic.py'
            source.parent.mkdir(parents=True,exist_ok=True);raw=b'VALUE=1\n';source.write_bytes(raw)
            files[source.relative_to(root).as_posix()]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
            save_manifest(root,files)
            cache=source.parent/'__pycache__';cache.mkdir()
            paths=[cache/('synthetic.cpython-313'+suffix+'.pyc') for suffix in ('','.opt-1','.opt-2')]
            for path in paths:path.write_bytes(b'legacy bytecode, must never be loaded')
            original=Path.open
            def no_cache_read(path,*args,**kwargs):
                self.assertNotIn(path,paths)
                return original(path,*args,**kwargs)
            with patch.object(Path,'open',no_cache_read):
                self.assertEqual(guard.verify_release(root)['files'],files)
            self.assertTrue(all(path.read_bytes()==b'legacy bytecode, must never be loaded' for path in paths))
            source.write_bytes(b'VALUE=2\n')
            self.rejected(root)

    def test_runtime_cache_rejects_orphans_extra_files_directories_and_links(self):
        for name in ('synthetic.pyc','synthetic.py','synthetic.cpython-313.pyc',
                     'synthetic.cpython-313.opt-3.pyc','nested'):
            with self.subTest(name=name),fixture() as base:
                root,_=release(base);cache=root/'runtime/python/site-packages/__pycache__'
                cache.mkdir(parents=True)
                if name=='nested':(cache/name).mkdir()
                else:(cache/name).write_bytes(b'synthetic unknown extra')
                self.rejected(root)

    def test_runtime_cache_junction_is_rejected_without_following_it(self):
        with fixture() as base:
            root,_=release(base);parent=root/'runtime/python/site-packages'
            parent.mkdir(parents=True,exist_ok=True)
            outside=base/'unrelated-cache';outside.mkdir()
            marker=outside/'preserve.txt';marker.write_bytes(b'not part of program')
            link=parent/'__pycache__'
            self.junction(link,outside)
            self.rejected(root)
            self.assertEqual(marker.read_bytes(),b'not part of program')

    def test_private_trees_inventory_and_legacy_cache_are_never_enumerated(self):
        with fixture() as base:
            root, _ = release(base)
            skip = ('app/data', 'app/local-engines', 'app/__pycache__', 'app/engines')
            for name in skip:
                path = root / name
                path.mkdir(parents=True, exist_ok=True)
                (path / 'synthetic-private.bin').write_bytes(b'must not read')
            (root / 'personal-note.txt').write_text('synthetic note', 'utf-8')
            original = os.scandir
            def public_only(path):
                self.assertNotIn(Path(path), [root / name for name in skip])
                return original(path)
            with patch.object(guard.os, 'scandir', side_effect=public_only):
                self.assertFalse(guard.verify_release(root)['development'])

    def test_empty_runtime_directories_are_preserved(self):
        with fixture() as base:
            root, _ = release(base)
            (root / 'runtime/python/empty').mkdir()
            guard.verify_release(root)

    def test_manifest_and_policy_resource_limits(self):
        with fixture() as base:
            root, _ = release(base, policy=True)
            with patch.object(guard, 'MAX_MANIFEST', 2):
                self.rejected(root)
        with fixture() as base:
            root, _ = release(base)
            with patch.object(guard, 'MAX_FILES', 1):
                self.rejected(root)
            with patch.object(guard, 'MAX_BYTES', 1):
                self.rejected(root)

    def test_invalid_policy_and_duplicate_version_are_rejected(self):
        policies = (
            {'format': True, 'data_format': 1, 'from_versions': {'0.2.7': 'a' * 64}},
            {'format': 1, 'data_format': 2, 'from_versions': {'0.2.7': 'a' * 64}},
            {'format': 1, 'data_format': 1, 'from_versions': ['0.2.7']},
            {'format': 1, 'data_format': 1, 'from_versions': {'bad': 'a' * 64}},
            {'format': 1, 'data_format': 1, 'from_versions': {'0.2.7': 'A' * 64}},
        )
        for value in policies:
            with fixture() as base:
                root, _ = release(base)
                (root / 'update-policy.json').write_text(json.dumps(value), 'utf-8')
                self.rejected(root)
        with fixture() as base:
            root, _ = release(base)
            raw = ('{"format":1,"data_format":1,"from_versions":{"0.2.7":"' +
                   'a' * 64 + '","0.2.7":"' + 'b' * 64 + '"}}')
            (root / 'update-policy.json').write_text(raw, 'utf-8')
            self.rejected(root)

    def test_reparse_files_are_rejected(self):
        with fixture() as base:
            root, _ = release(base)
            original = Path.lstat
            for name in ('release-manifest.json', 'app/ui/index.html'):
                def reparse(path, *, follow_symlinks=False):
                    info = original(path)
                    if path != root / name:
                        return info
                    return types.SimpleNamespace(st_mode=info.st_mode,
                                                 st_file_attributes=0x400)
                with self.subTest(name=name), patch.object(Path, 'lstat', reparse):
                    self.rejected(root)

    def junction(self, link, target):
        result = subprocess.run([os.environ.get('COMSPEC', 'cmd.exe'), '/d', '/c',
                                 'mklink', '/J', str(link), str(target)],
                                cwd=link.parent, env={**os.environ, 'TEMP': str(link.parent), 'TMP': str(link.parent)},
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, 'synthetic_junction_creation_failed')
        self.assertTrue(link.lstat().st_file_attributes & 0x400)

    def test_real_parent_junction_is_rejected(self):
        with fixture() as base:
            root, _ = release(base)
            original = root / 'app/ui'
            moved = base / 'ui-original'
            original.rename(moved)
            self.junction(original, moved)
            self.rejected(root)

    def test_broken_update_marker_junction_still_blocks(self):
        with fixture() as base:
            marker, target = base / '.program-update', base / 'original'
            target.mkdir()
            self.junction(marker, target)
            target.rmdir()
            self.assertFalse(marker.exists())
            with self.assertRaises(guard.UpdateGuardError):
                guard.require_complete_installation(base)

    def test_direct_entry_and_self_check_block_before_business_imports(self):
        original_import = builtins.__import__
        business = {'browser_core', 'manager_service', 'installation'}
        for self_check, failure in ((check, problem) for check in (False, True)
                                    for problem in ('marker', 'missing_manifest', 'damaged_file')):
            with self.subTest(self_check=self_check, failure=failure), fixture() as base:
                root, files = release(base, policy=True)
                app = root / 'app'
                entry = app / 'local_browser.pyw'
                entry.write_bytes((ROOT / 'app/local_browser.pyw').read_bytes())
                (app / 'update_guard.py').write_bytes((ROOT / 'app/update_guard.py').read_bytes())
                for path in (entry, app / 'update_guard.py'):
                    raw = path.read_bytes()
                    files[path.relative_to(root).as_posix()] = {
                        'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                save_manifest(root, files)
                if failure == 'marker':
                    (root / '.program-update').write_bytes(b'')
                elif failure == 'missing_manifest':
                    (root / 'release-manifest.json').unlink()
                else:
                    (root / 'VERSION').write_bytes(b'9.9.9\n')
                before = {path.relative_to(root).as_posix() for path in root.rglob('*')}
                touched = []
                def no_business(name, *args, **kwargs):
                    if name in business:
                        touched.append(name)
                        raise AssertionError('business_import_before_gate')
                    return original_import(name, *args, **kwargs)
                user = types.SimpleNamespace(MessageBoxW=MagicMock())
                previous_path, previous_cache = list(sys.path), (sys.pycache_prefix, sys.dont_write_bytecode)
                try:
                    with patch.dict(sys.modules, update_guard=guard), \
                            patch.object(builtins, '__import__', side_effect=no_business), \
                            patch.object(ctypes, 'windll', types.SimpleNamespace(user32=user)), \
                            patch.object(sys, 'argv', [str(entry)] + (['--self-check'] if self_check else [])), \
                            patch('sys.stdout', new_callable=io.StringIO):
                        with self.assertRaises(SystemExit) as raised:
                            runpy.run_path(str(entry), run_name='__main__')
                        self.assertEqual(raised.exception.code, 1)
                    self.assertEqual(touched, [])
                    self.assertEqual(user.MessageBoxW.call_count, 0 if self_check else 1)
                    self.assertEqual({path.relative_to(root).as_posix() for path in root.rglob('*')}, before)
                finally:
                    sys.path[:] = previous_path
                    sys.pycache_prefix, sys.dont_write_bytecode = previous_cache

    def test_cmd_blocks_incomplete_startup_before_runtime_launch(self):
        raw = (ROOT / '启动本地浏览器.cmd').read_bytes()
        package = re.search(rb'set "IB_PACKAGE=%~dp0\.program-packages\\([0-9a-f]{32})"', raw)
        if b'IB_PACKAGE' in raw:
            self.assertIsNotNone(package, 'synthetic_launcher_layout_unknown')
            layout = runpy.run_path(str(ROOT / 'tools/overlay_layout.py'))
            self.assertEqual(raw, layout['launcher_bytes'](package.group(1).decode('ascii')))
        for marker_type in ('file', 'directory', 'broken_junction'):
            with self.subTest(marker_type=marker_type), fixture() as base:
                launcher = base / 'start.cmd'
                launcher.write_bytes(raw)
                marker = base / '.program-update'
                if marker_type == 'broken_junction':
                    target = base / 'original'
                    target.mkdir()
                    self.junction(marker, target)
                    target.rmdir()
                elif marker_type == 'directory':
                    marker.mkdir()
                else:
                    marker.write_bytes(b'')
                env = {key: value for key, value in os.environ.items()
                       if key in ('SystemRoot', 'WINDIR', 'COMSPEC', 'PATH')}
                env.update(TEMP=str(base), TMP=str(base))
                command = '"{}" /d /v:off /s /c ""{}""'.format(
                    os.environ.get('COMSPEC', 'cmd.exe'), launcher)
                result = subprocess.run(command, cwd=base, env=env,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=10)
                self.assertEqual(result.returncode, 1)
                if package:
                    # Overlay entries need their payload to recover a pending
                    # update; direct entries must reject it before runtime checks.
                    self.assertIn(b'Incomplete package.', result.stdout)
                else:
                    self.assertIn(b'Program update is incomplete', result.stdout)
                self.assertNotIn(b'Portable runtime is incomplete', result.stdout)
                self.assertFalse((base / 'app').exists())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path)
    options = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(StartupGuard)
    names = [test.id().rsplit('.', 1)[-1] for test in suite]
    result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    checks, failed = report_checks(names, result)
    skipped = {test_name(test) for test, _ in result.skipped}
    report = {'success': result.wasSuccessful(), 'checks': checks,
              'passed': max(0, result.testsRun - len(failed) - len(skipped)), 'failed': sorted(failed),
              'skipped': sorted(skipped), 'real_browser_started': False, 'real_user_data_accessed': False}
    if options.report:
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(report, ensure_ascii=False))
    print('Ran {} tests in synthetic fixtures'.format(result.testsRun), file=sys.stderr)
    print('OK' if result.wasSuccessful() else 'FAILED (failures={}, errors={})'.format(
        len(result.failures), len(result.errors)), file=sys.stderr)
    sys.exit(0 if result.wasSuccessful() else 1)
