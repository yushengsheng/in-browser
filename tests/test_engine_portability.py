"""Synthetic engine deployment under Windows' legacy MAX_PATH restrictions."""
from contextlib import ExitStack, contextmanager
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import engine_store
import local_engine
import browser_core
import configuration
import fingerprint_continuity
from engine_validation import digest_file, verification_scope
from local_state import LocalBrowserError
from native_paths import absolute_path, io_path, resolved_path
from core_specs import CORE_SPECS
REAL_EXECUTABLE_MAJOR = engine_store.executable_major


@contextmanager
def legacy_windows_io():
    """Fail unprefixed deep calls even on hosts with LongPathsEnabled."""
    calls = []

    def guarded(function):
        def call(path, *args, **kwargs):
            paths = [path]
            if function.__name__ in ('rename', 'replace') and args:
                paths.append(args[0])
            for candidate in paths:
                if isinstance(candidate, int):
                    continue
                value = os.fsdecode(candidate)
                if len(value.encode('utf-16-le')) // 2 >= 260:
                    if not value.startswith('\\\\?\\'):
                        error = OSError('synthetic MAX_PATH restriction')
                        error.winerror = 206
                        raise error
                    calls.append(function.__name__)
            return function(path, *args, **kwargs)
        return call

    with ExitStack() as stack:
        for module, name in ((io, 'open'), (os, 'stat'), (os, 'lstat'), (os, 'scandir'),
                             (os, 'mkdir'), (os, 'chmod'), (os, 'rename'), (os, 'replace'),
                             (os, 'unlink'), (os, 'rmdir')):
            stack.enter_context(patch.object(module, name, guarded(getattr(module, name))))
        yield calls


def transient_io_error(code=5):
    error = PermissionError(13, 'synthetic Windows I/O failure')
    error.winerror = code
    return error


def fail_transient_io(*_args, **_kwargs):
    raise transient_io_error()


@contextmanager
def windows_file_handle(path, share=0):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = create(str(io_path(path)), 0x80000000, share, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())

    def close():
        nonlocal handle
        if handle is not None:
            kernel.CloseHandle(handle)
            handle = None

    try:
        yield close
    finally:
        close()


@unittest.skipUnless(os.name == 'nt', 'Windows path and handle contracts')
class EnginePortabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.area = ROOT / 'analysis/test-runs'
        cls.area.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='engine-path-preflight-', dir=cls.area) as directory:
            nested = Path(directory) / 'nested'
            nested.mkdir()
            (nested / '.owner').write_text('synthetic engine path preflight')
        if Path(directory).exists():
            raise RuntimeError('Test cleanup preflight failed')
        cls.vendor = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.own = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.key_id = hashlib.sha256(cls.own).hexdigest()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='engine-path-', dir=self.area)
        self.base = Path(self.temporary.name)
        (self.base / '.owner').write_text(uuid.uuid4().hex)
        self.addCleanup(self.clean_owned)
        self.deep = self.base
        for number in range(6):
            self.deep /= '中文-deep-' + str(number) + '-' + 'x' * 24
        io_path(self.deep).mkdir(parents=True)
        self.source = self.deep / 'stock'
        io_path(self.source / 'version').mkdir(parents=True)
        self.executable = self.source / 'BitBrowser.exe'
        io_path(self.executable).write_bytes(b'synthetic executable, never run')
        spec = copy.deepcopy(local_engine._SUPPORTED['140'])
        spec['offset'] = 64
        chrome = b'P' * 64 + local_engine._key_block(self.vendor, spec['seeds']) + b'S' * 127
        io_path(self.source / 'version/chrome.dll').write_bytes(chrome)
        spec['sha256'] = hashlib.sha256(chrome).hexdigest()
        header = bytearray(78)
        header[16:24] = (123456789).to_bytes(8, 'big')
        state = 123456789
        encoded = bytearray()
        for octet in self.vendor:
            state ^= state >> 33
            state = state * 0xff51afd7ed558ccd & ((1 << 64) - 1)
            state ^= state >> 33
            state = state * 0xc4ceb9fe1a85ec53 & ((1 << 64) - 1)
            state ^= state >> 33
            encoded.append(octet ^ (state & 255))
        resource = b'index' + header + encoded + b'other resources'
        io_path(self.source / 'version/resources.pak').write_bytes(resource)
        spec['resource_root'] = {'file': 'version/resources.pak', 'offset': 5,
                                 'length': 372, 'key_offset': 78,
                                 'sha256': hashlib.sha256(resource).hexdigest()}
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.object(local_engine, '_SUPPORTED', {'140': spec}))
        self.patches.enter_context(patch.object(local_engine, '_VENDOR_DER_SHA256', hashlib.sha256(self.vendor).hexdigest()))
        self.patches.enter_context(patch.object(engine_store, 'executable_major', return_value='140'))
        self.store = local_engine.LocalEngineStore(self.deep / 'deployed')

    def clean_owned(self):
        # No browser/process is created by these fixtures. The exact owned root
        # is checked before allowing stdlib's temporary-directory cleanup.
        self.assertEqual(self.base.parent.resolve(), self.area.resolve())
        self.assertTrue((self.base / '.owner').is_file())
        shutil.rmtree(io_path(self.base))
        self.temporary.cleanup()
        self.assertFalse(self.base.exists())

    def test_absolute_unc_prefixed_relative_and_case_identities(self):
        target = self.deep / 'stock/version/../BitBrowser.exe'
        ordinary = absolute_path(target)
        prefixed = io_path(target)
        self.assertFalse(str(ordinary).startswith('\\\\?\\'))
        self.assertEqual(absolute_path(prefixed), ordinary)
        self.assertEqual(absolute_path(str(prefixed).upper()), ordinary)
        self.assertEqual(absolute_path(os.path.relpath(ordinary)), ordinary)
        self.assertEqual(io_path(r'\\server\share\a\..\b'), Path(r'\\?\UNC\server\share\b'))
        self.assertEqual(io_path(r'\\?\unc\server\share\b'), Path(r'\\?\UNC\server\share\b'))
        for invalid in (r'\\.\PhysicalDrive0', r'\\?\GLOBALROOT\Device\HarddiskVolume1'):
            with self.assertRaises(ValueError):
                io_path(invalid)

    def test_fresh_deployment_and_legacy_compaction_under_max_path(self):
        source_before = local_engine._inventory(self.source)
        with legacy_windows_io() as calls:
            with self.assertRaises(OSError):
                self.executable.open('rb')
            deployed = self.store.ensure('140', self.executable, self.own)
            data = json.loads(io_path(deployed.parent / 'manifest.json').read_text())
            legacy = self.store.root / self.key_id / ('140-' + data['local_trust']['source_tree_digest'])
            io_path(legacy.parent).mkdir(parents=True)
            os.rename(io_path(deployed.parent), io_path(legacy))
            before = local_engine._inventory(legacy)
            current = self.store.ensure_current(legacy / 'BitBrowser.exe', self.key_id, '140')
            self.assertEqual(self.store.validate(current, self.key_id, '140'), current)
            self.assertEqual(local_engine._inventory(legacy), before)
            self.assertEqual(local_engine._inventory(self.source), source_before)
            self.assertGreater(len(calls), 20)
            self.assertFalse(str(current).startswith('\\\\?\\'))
            self.assertFalse(str(self.store.root).startswith('\\\\?\\'))
            with verification_scope():
                self.assertEqual(digest_file(current), digest_file(io_path(current)))
                with self.assertRaises(PermissionError):
                    io_path(current).write_bytes(b'cannot replace a pinned file')

    def test_stock_store_install_and_resolve_under_max_path(self):
        store = engine_store.EngineStore(self.deep / 'stock-store')
        with legacy_windows_io() as calls:
            installed = store.install('140', self.executable)
            self.assertEqual(store.resolve('140'), installed)
            self.assertEqual(store.available(), {'140': str(installed)})
            self.assertFalse(str(installed).startswith('\\\\?\\'))
            self.assertGreater(len(calls), 10)

    def test_current_first_deployment_copies_once_and_publishes_only_revision_one(self):
        before = local_engine._inventory(self.source)
        with legacy_windows_io(), patch.object(local_engine.shutil, 'copy2', wraps=shutil.copy2) as copier:
            deployed = self.store.ensure('140', self.executable, self.own, current=True)
            self.assertEqual(copier.call_count, len(before[0]))
            self.assertEqual(self.store.ensure_current(deployed, self.key_id, '140'), deployed)
            self.assertEqual(copier.call_count, len(before[0]))
            data = json.loads(io_path(deployed.parent / 'manifest.json').read_text())
            self.assertEqual(data['local_trust']['resource_root_revision'], 1)
            self.assertTrue(deployed.parent.name.endswith('-r2'))
            siblings = list(io_path(deployed.parent.parent).iterdir())
            self.assertEqual(len(siblings), 1)
            self.assertEqual(local_engine._inventory(self.source), before)
            changed = {name for name, value in data['files'].items() if value != before[0][name]}
            self.assertEqual(changed, {'version/chrome.dll', 'version/resources.pak'})

    def test_current_compact_validation_runs_in_parallel_without_deployment_lock(self):
        current = self.store.ensure('140', self.executable, self.own, current=True)
        inventory = local_engine._inventory
        ready = threading.Barrier(10, timeout=10)

        def concurrent_inventory(folder):
            self.assertEqual(folder, current.parent)
            ready.wait()
            return inventory(folder)

        with patch.object(local_engine, '_inventory', side_effect=concurrent_inventory) as checked, \
                patch.object(local_engine, '_DEPLOY_LOCK') as deployment_lock:
            deployment_lock.__enter__.side_effect = AssertionError('Read-only validation acquired deployment lock')
            with ThreadPoolExecutor(max_workers=10) as workers:
                results = list(workers.map(
                    lambda _: self.store.ensure_current(current, self.key_id, '140'), range(10)))
        self.assertEqual(results, [current] * 10)
        self.assertEqual(checked.call_count, 10)
        deployment_lock.__enter__.assert_not_called()

    def test_concurrent_legacy_upgrades_revalidate_under_lock_and_publish_once(self):
        legacy = self.store.ensure('140', self.executable, self.own)
        before = local_engine._inventory(legacy.parent)
        ready = threading.Barrier(10, timeout=10)
        validate = self.store.validate
        deployment_lock = local_engine._DEPLOY_LOCK
        checked_inside, checked_outside = [], []

        def observed_validate(executable, key_id, major=None):
            result = validate(executable, key_id, major)
            if executable == legacy:
                if deployment_lock._is_owned():
                    checked_inside.append(result)
                else:
                    checked_outside.append(result)
                    ready.wait()
            return result

        with patch.object(self.store, 'validate', side_effect=observed_validate), \
                patch.object(local_engine.shutil, 'copy2', wraps=shutil.copy2) as copied, \
                patch.object(local_engine.os, 'rename', wraps=os.rename) as published:
            with ThreadPoolExecutor(max_workers=10) as workers:
                results = list(workers.map(
                    lambda _: self.store.ensure_current(legacy, self.key_id, '140'), range(10)))
        self.assertEqual(len(checked_inside), 10)
        self.assertEqual(len(checked_outside), 10)
        self.assertEqual(len(set(results)), 1)
        self.assertNotEqual(results[0], legacy)
        self.assertEqual(copied.call_count, len(before[0]))
        self.assertEqual(published.call_count, 1)
        self.assertEqual(local_engine._inventory(legacy.parent), before)
        self.assertFalse(any(path.name.startswith('.install-')
                             for path in io_path(results[0].parent.parent).iterdir()))

    def test_upgrade_rejects_source_changed_while_waiting_for_deployment_lock(self):
        legacy = self.store.ensure('140', self.executable, self.own)
        deployment_lock = local_engine._DEPLOY_LOCK

        class ChangingLock:
            def __enter__(self):
                io_path(legacy).write_bytes(b'changed after the first full validation')
                return deployment_lock.__enter__()

            def __exit__(self, *args):
                return deployment_lock.__exit__(*args)

        with patch.object(local_engine, '_DEPLOY_LOCK', ChangingLock()), \
                patch.object(local_engine.shutil, 'copy2') as copied:
            with self.assertRaises(LocalBrowserError):
                self.store.ensure_current(legacy, self.key_id, '140')
        copied.assert_not_called()
        self.assertEqual(len(list(io_path(legacy.parent.parent).iterdir())), 1)

    def test_current_suffix_and_key_prefix_do_not_bypass_full_validation(self):
        current = self.store.ensure('140', self.executable, self.own, current=True)
        manifest = current.parent / 'manifest.json'
        original_manifest = io_path(manifest).read_bytes()
        original_executable = io_path(current).read_bytes()
        data = json.loads(original_manifest)
        forged = copy.deepcopy(data)
        forged['local_trust']['key_id'] = self.key_id[:-1] + ('0' if self.key_id[-1] != '0' else '1')
        downgraded = copy.deepcopy(data)
        downgraded['local_trust']['resource_root_revision'] = 0

        with patch.object(local_engine, '_DEPLOY_LOCK') as deployment_lock:
            deployment_lock.__enter__.side_effect = AssertionError('Invalid build reached deployment')
            for changed_manifest in (forged, downgraded):
                with self.subTest(revision=changed_manifest['local_trust']['resource_root_revision']):
                    io_path(manifest).write_text(json.dumps(changed_manifest), encoding='utf-8')
                    with self.assertRaises(LocalBrowserError):
                        self.store.ensure_current(current, self.key_id, '140')
            io_path(manifest).write_bytes(original_manifest)
            io_path(current).write_bytes(original_executable + b'tampered')
            with self.assertRaises(LocalBrowserError):
                self.store.ensure_current(current, self.key_id, '140')
            io_path(current).write_bytes(original_executable)
            with patch.object(engine_store, 'executable_major', return_value='148'):
                with self.assertRaises(LocalBrowserError):
                    self.store.ensure_current(current, self.key_id, '140')
            mixed = self.store.root / self.key_id / current.parent.name
            io_path(mixed.parent).mkdir()
            shutil.copytree(io_path(current.parent), io_path(mixed))
            with self.assertRaises(LocalBrowserError):
                self.store.ensure_current(mixed / current.name, self.key_id, '140')
        deployment_lock.__enter__.assert_not_called()

    def test_transient_copy_failure_retries_once_and_preserves_old_staging(self):
        key_folder = self.store.root / self.key_id[:16]
        interrupted = key_folder / '.install-0123456789ab'
        io_path(interrupted).mkdir(parents=True)
        marker = interrupted / 'proof'
        io_path(marker).write_bytes(b'old interrupted deployment')
        copy_file = shutil.copy2
        attempts = []

        def copy_once(source, destination, **kwargs):
            attempts.append(source)
            if len(attempts) == 1:
                raise transient_io_error()
            return copy_file(source, destination, **kwargs)

        files, _ = local_engine._inventory(self.source)
        with patch.object(local_engine.shutil, 'copy2', side_effect=copy_once), \
                patch.object(local_engine.time, 'sleep') as delay:
            current = self.store.ensure('140', self.executable, self.own, current=True)
        delay.assert_called_once_with(0.05)
        self.assertEqual(len(attempts), len(files) + 1)
        self.assertEqual(self.store.validate(current, self.key_id, '140'), current)
        self.assertEqual(io_path(marker).read_bytes(), b'old interrupted deployment')
        self.assertEqual(self.store._staging_names(self.key_id), {interrupted.name})

    def test_real_windows_sharing_error_in_current_validation_recovers_once(self):
        current = self.store.ensure('140', self.executable, self.own, current=True)
        digest = local_engine._sha256
        errors = []

        def observe_digest(path):
            try:
                return digest(path)
            except OSError as error:
                errors.append((error.errno, getattr(error, 'winerror', None)))
                raise

        with windows_file_handle(current.parent / 'version/chrome.dll') as release, \
                patch.object(local_engine, '_sha256', side_effect=observe_digest), \
                patch.object(local_engine.time, 'sleep', side_effect=lambda _: release()) as delay:
            self.assertEqual(self.store.ensure_current(current, self.key_id, '140'), current)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0][1] in (5, 32, 33) or errors[0] == (13, None))
        delay.assert_called_once_with(0.05)

    def test_real_windows_persistent_sharing_error_stops_after_two_attempts(self):
        with windows_file_handle(self.source / 'version/chrome.dll'), \
                patch.object(local_engine, '_inventory', wraps=local_engine._inventory) as checked, \
                patch.object(local_engine.time, 'sleep') as delay, \
                patch.object(local_engine.shutil, 'copy2') as copied:
            with self.assertRaises(LocalBrowserError) as caught:
                self.store.ensure('140', self.executable, self.own, current=True)
        self.assertEqual(checked.call_count, 2)
        self.assertEqual(caught.exception.code, 'engine_access_denied')
        original = caught.exception.__context__
        self.assertTrue(getattr(original, 'winerror', None) in (5, 32, 33)
                        or (original.errno, getattr(original, 'winerror', None)) == (13, None))
        delay.assert_called_once_with(0.05)
        copied.assert_not_called()

    def test_failed_staging_cleanup_prevents_a_second_copy(self):
        with patch.object(local_engine.shutil, 'copy2', side_effect=fail_transient_io) as copied, \
                patch.object(local_engine, '_remove_owned_tree', side_effect=fail_transient_io), \
                patch.object(local_engine.time, 'sleep') as delay:
            with self.assertRaises(LocalBrowserError):
                self.store.ensure('140', self.executable, self.own, current=True)
        self.assertEqual(copied.call_count, 1)
        self.assertEqual(len(self.store._staging_names(self.key_id)), 1)
        delay.assert_not_called()

    def test_unknown_staging_snapshot_prevents_retry(self):
        for snapshots in ((None,), (set(), None)):
            with self.subTest(snapshot_count=len(snapshots)), \
                    patch.object(self.store, '_staging_names', side_effect=snapshots), \
                    patch.object(self.store, '_ensure', side_effect=fail_transient_io) as deployed, \
                    patch.object(local_engine.time, 'sleep') as delay:
                with self.assertRaises(LocalBrowserError):
                    self.store.ensure('140', self.executable, self.own, current=True)
            self.assertEqual(deployed.call_count, 1)
            delay.assert_not_called()

    def test_integrity_signature_links_and_other_io_errors_are_not_retried(self):
        errors = [transient_io_error(2), PermissionError(1, 'not an access-denied errno')]
        for code in ('tree_manifest', 'public_root', 'path_link'):
            try:
                local_engine._fail(code)
            except LocalBrowserError as error:
                errors.append(error)
        for number, error in enumerate(errors):
            with self.subTest(case=number), \
                    patch.object(self.store, '_ensure', side_effect=error) as deployed, \
                    patch.object(local_engine.time, 'sleep') as delay:
                with self.assertRaises(LocalBrowserError):
                    self.store.ensure('140', self.executable, self.own, current=True)
            self.assertEqual(deployed.call_count, 1)
            delay.assert_not_called()

    def test_cleanup_access_error_cannot_hide_an_integrity_failure_for_retry(self):
        def masked_failure(*_args, **_kwargs):
            try:
                local_engine._fail('tree_manifest')
            except LocalBrowserError:
                raise transient_io_error()

        with patch.object(self.store, '_ensure', side_effect=masked_failure) as deployed, \
                patch.object(local_engine.time, 'sleep') as delay:
            with self.assertRaises(LocalBrowserError):
                self.store.ensure('140', self.executable, self.own, current=True)
        self.assertEqual(deployed.call_count, 1)
        delay.assert_not_called()

    def test_nested_deployment_and_current_validation_have_only_two_attempts(self):
        current = self.store.ensure('140', self.executable, self.own, current=True)
        with patch.object(self.store, 'validate', side_effect=fail_transient_io) as checked, \
                patch.object(local_engine.time, 'sleep') as delay:
            with self.assertRaises(LocalBrowserError):
                self.store.ensure('140', current, self.own, current=True)
        self.assertEqual(checked.call_count, 2)
        delay.assert_called_once_with(0.05)

    def test_retry_rechecks_changed_stock_instead_of_reusing_the_first_manifest(self):
        def change_source(_seconds):
            chrome = self.source / 'version/chrome.dll'
            io_path(chrome).write_bytes(io_path(chrome).read_bytes() + b'changed before retry')

        with patch.object(local_engine.shutil, 'copy2', side_effect=fail_transient_io) as copied, \
                patch.object(local_engine.time, 'sleep', side_effect=change_source) as delay:
            with self.assertRaises(LocalBrowserError) as caught:
                self.store.ensure('140', self.executable, self.own, current=True)
        self.assertEqual(caught.exception.code, 'engine_stock_hash')
        self.assertEqual(copied.call_count, 1)
        delay.assert_called_once_with(0.05)

    def test_current_first_deployment_covers_all_twenty_one_core_protocols(self):
        self.assertEqual(len(CORE_SPECS), 21)
        resource_data = io_path(self.source / 'version/resources.pak').read_bytes()
        encoded_key = resource_data[5 + 78:5 + 372]
        for major, original in CORE_SPECS.items():
            with self.subTest(major=major):
                source = self.deep / ('source-' + major)
                shutil.copytree(io_path(self.source), io_path(source))
                spec = copy.deepcopy(original)
                spec['offset'] = 64
                chrome = b'P' * 64 + local_engine._key_block(self.vendor, spec['seeds']) + b'S' * 127
                io_path(source / 'version/chrome.dll').write_bytes(chrome)
                spec['sha256'] = hashlib.sha256(chrome).hexdigest()
                resource = copy.deepcopy(original['resource_root'])
                self.assertEqual(resource['length'] - resource['key_offset'], 294)
                header = bytearray(resource['key_offset'])
                header[16:24] = (123456789).to_bytes(8, 'big')
                header[24] = (resource['key_offset'] - 0x39) ^ 0x15
                raw = b'index' + header + encoded_key + b'other resources'
                path = source / resource['file']
                io_path(path.parent).mkdir(parents=True, exist_ok=True)
                io_path(path).write_bytes(raw)
                resource.update(offset=5, sha256=hashlib.sha256(raw).hexdigest())
                spec['resource_root'] = resource
                with patch.object(local_engine, '_SUPPORTED', {major: spec}), \
                        patch.object(engine_store, 'executable_major', return_value=major), legacy_windows_io():
                    store = local_engine.LocalEngineStore(self.deep / ('deployment-' + major))
                    deployed = store.ensure(major, source / 'BitBrowser.exe', self.own, current=True)
                    self.assertEqual(store.validate(deployed, self.key_id, major), deployed)

    def test_current_first_deployment_rejects_wrong_resource_before_copy(self):
        resource = self.source / 'version/resources.pak'
        io_path(resource).write_bytes(io_path(resource).read_bytes() + b'changed')
        with patch.object(local_engine.shutil, 'copy2') as copier:
            with self.assertRaises(LocalBrowserError) as caught:
                self.store.ensure('140', self.executable, self.own, current=True)
        self.assertEqual(caught.exception.code, 'engine_resource_hash')
        copier.assert_not_called()

    def test_wrong_sha_wrong_key_and_junction_remain_rejected(self):
        deployed = self.store.ensure('140', self.executable, self.own)
        with legacy_windows_io():
            with self.assertRaises(LocalBrowserError) as wrong_key:
                self.store.validate(deployed, '0' * 64, '140')
            self.assertEqual(wrong_key.exception.code, 'engine_layout')
            chrome = self.source / 'version/chrome.dll'
            io_path(chrome).write_bytes(io_path(chrome).read_bytes() + b'tampered')
            with self.assertRaises(LocalBrowserError) as wrong_sha:
                self.store.ensure('140', self.executable, self.own)
            self.assertEqual(wrong_sha.exception.code, 'engine_stock_hash')
        junction = self.base / 'junction'
        target = self.base / 'junction-target'
        target.mkdir()
        result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(target)],
                                capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0)
        try:
            with self.assertRaises(LocalBrowserError) as linked:
                local_engine.LocalEngineStore(junction / 'deployed')
            self.assertEqual(linked.exception.code, 'engine_path_link')
        finally:
            os.rmdir(junction)

    def test_access_failure_has_only_safe_stage_and_code(self):
        private = str(self.deep / 'private-name')
        with patch.object(local_engine, '_inventory', side_effect=PermissionError(private)):
            with self.assertRaises(LocalBrowserError) as caught:
                self.store.ensure('140', self.executable, self.own)
        self.assertEqual(caught.exception.code, 'engine_access_denied')
        self.assertEqual(caught.exception.stage, 'deploy')
        self.assertNotIn(private, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_real_version_api_reads_a_prefixed_deep_path(self):
        # Reuse a public runtime PE only to exercise Windows' version resource API.
        target = self.deep / 'version-check.exe'
        shutil.copyfile(io_path(sys.executable), io_path(target))
        self.assertEqual(REAL_EXECUTABLE_MAJOR(target), str(sys.version_info.major))

    def test_configuration_runtime_and_binding_use_deep_native_io(self):
        from bit_source import BitSource
        from local_signer import LocalSigner
        from local_state import read_encrypted, write_encrypted
        from manager_service import ManagerService
        from portable_paths import encode_archive
        from portable_vault import PortableVault

        app = self.deep / 'formal-app'
        stock = app / 'engines/140'
        shutil.copytree(io_path(self.source), io_path(stock))
        files, directories = local_engine._inventory(stock)
        io_path(stock / 'manifest.json').write_text(json.dumps({
            'format': 1, 'core_major': '140', 'executable': 'BitBrowser.exe',
            'files': files, 'directories': directories}), encoding='utf-8')
        data_root = self.base / 'formal-data'
        data_root.mkdir()
        PortableVault(data_root).initialize()
        signer = LocalSigner(data_root)
        archive = {'format': 1, 'key_id': signer.key_id, 'items': {}, 'engines': {}}
        archive_path = data_root / 'local-source-archive.bin'
        write_encrypted(archive_path, encode_archive(archive, data_root), root=data_root)
        config = configuration.Configuration.__new__(configuration.Configuration)
        config.root = data_root
        config.independent = True
        service = ManagerService.__new__(ManagerService)
        service.root = data_root
        service.configuration = config
        service.settings = lambda: {'start_page': ''}
        profile = {'id': 'synthetic-deep-runtime', 'name': 'Synthetic', 'urls': ['about:blank'],
                   'fingerprint': {'coreVersion': '140', 'launchArgs': '', 'displayLanguages': 'en-US'},
                   'preferences': {'restore_session': True}}
        with patch('app_paths.APP_ROOT', app), patch.object(engine_store, 'APP_ROOT', app), \
                patch.object(BitSource, '_core_path', side_effect=AssertionError('Unexpected vendor fallback')), \
                patch('manager_service.executable_major', return_value='140') as runtime_version, \
                legacy_windows_io() as calls:
            deployed = config.local_core('140')
            runtime = service._runtime(profile)
            runtime_version.assert_called_once_with(deployed)
            self.assertEqual(runtime['core_path'], str(deployed))
            self.assertEqual(runtime['core_sha256'], browser_core.sha256(deployed))
            record = {'id': profile['id'], '_runtime': runtime, '_native': {'Resource': 'synthetic'}}
            binding = fingerprint_continuity.binding_for(record, data_root)
            self.assertEqual(binding['engine']['executable'], runtime['core_sha256'])
            persisted = read_encrypted(archive_path, root=data_root)
            self.assertFalse(persisted['engines']['140'].startswith('\\\\?\\'))
            self.assertGreater(len(calls), 20)
            wrong = copy.deepcopy(runtime)
            wrong['core_sha256'] = '0' * 64
            with self.assertRaises(LocalBrowserError) as mismatch:
                fingerprint_continuity._engine_binding(wrong)
            self.assertEqual(mismatch.exception.changed_fields, ['core'])
            resource = deployed.parent / 'version/resources.pak'
            io_path(resource).write_bytes(io_path(resource).read_bytes() + b'tampered')
            with self.assertRaises(LocalBrowserError) as modified:
                fingerprint_continuity._engine_binding(runtime)
            self.assertEqual(modified.exception.code, 'engine_tree_manifest')

    def test_general_sha256_never_pins_or_reuses_mutable_files(self):
        path = self.deep / 'mutable-input.bin'
        io_path(path).write_bytes(b'first bytes')
        with legacy_windows_io(), verification_scope():
            before = browser_core.sha256(path)
            io_path(path).write_bytes(b'newer bytes')
            after = browser_core.sha256(path)
            self.assertNotEqual(before, after)
            self.assertEqual(after, hashlib.sha256(b'newer bytes').hexdigest())

    def test_controller_core_gate_accepts_deep_io_but_rejects_changed_bytes(self):
        import threading
        controller = browser_core.BrowserController.__new__(browser_core.BrowserController)
        controller._state_lock = threading.RLock()
        controller._checked_cores = {}
        runtime = {'core_path': str(self.executable), 'core_sha256': browser_core.sha256(self.executable)}
        before = copy.deepcopy(runtime)
        with legacy_windows_io():
            self.assertTrue(controller._core_valid(runtime))
            self.assertTrue(controller._core_valid(runtime))
            io_path(self.executable).write_bytes(b'changed synthetic executable bytes')
            self.assertFalse(controller._core_valid(runtime))
        self.assertEqual(runtime, before)

    def test_short_alias_proof_uses_native_io_and_returns_an_ordinary_path(self):
        observed = []

        def convert(source, output, _capacity):
            observed.append(source)
            self.assertTrue(source.startswith('\\\\?\\'))
            self.assertEqual(absolute_path(source), self.executable)
            # A Windows API may return an unchanged spelling when no shorter
            # 8.3 name exists. Identity proof still runs; the length gate below
            # independently refuses an alias whose resources remain too deep.
            output.value = str(io_path(self.executable))
            return len(output.value)

        library = SimpleNamespace(GetShortPathNameW=convert)
        with patch.object(browser_core.ctypes, 'WinDLL', return_value=library), legacy_windows_io():
            alias = browser_core._short_executable_path(self.executable)
        self.assertEqual(alias, self.executable)
        self.assertFalse(str(alias).startswith('\\\\?\\'))
        self.assertEqual(len(observed), 1)
        for returned in ('BitBrowser.exe', str(io_path(self.deep / 'missing.exe'))):
            def invalid(_source, output, _capacity, value=returned):
                output.value = value
                return len(value)
            with patch.object(browser_core.ctypes, 'WinDLL', return_value=SimpleNamespace(GetShortPathNameW=invalid)), legacy_windows_io():
                self.assertIsNone(browser_core._short_executable_path(self.executable))

    def test_deep_launch_gate_reads_manifest_and_keeps_resource_length_checks(self):
        resource = 'assets/' + 'nested/' * 40 + 'resource.dat'
        io_path(self.source / 'manifest.json').write_text(json.dumps({'files': {resource: {}}}), encoding='utf-8')
        short = self.base / 'BitBrowser.exe'
        self.assertLess(len(str(short).encode('utf-16-le')) // 2, 260)
        with legacy_windows_io(), patch.object(browser_core, '_short_executable_path', return_value=short):
            with self.assertRaises(LocalBrowserError) as caught:
                browser_core._check_launch_paths(self.executable)
        self.assertEqual(caught.exception.code, 'engine_path_too_long')
        io_path(self.source / 'manifest.json').write_text(json.dumps({'files': {'version/chrome.dll': {}}}), encoding='utf-8')
        with legacy_windows_io(), patch.object(browser_core, '_short_executable_path', return_value=short):
            selected = browser_core._check_launch_paths(self.executable)
        self.assertEqual(selected, short)
        self.assertFalse(str(selected).startswith('\\\\?\\'))

    def test_formal_controller_open_reaches_process_boundary_with_logical_arguments(self):
        from unittest.mock import Mock

        class LaunchObserved(Exception):
            pass

        profile = self.base / 'empty-profile'
        (profile / 'Default').mkdir(parents=True)
        config = self.base / 'synthetic-fingerprint.bin'
        config.write_bytes(b'synthetic fingerprint checked with a mocked signer')
        files, _ = local_engine._inventory(self.source)
        io_path(self.source / 'manifest.json').write_text(json.dumps({'files': files}), encoding='utf-8')
        runtime = {'alias': 'synthetic', 'profile_path': str(profile), 'core_path': str(self.executable),
                   'core_sha256': browser_core.sha256(self.executable), 'core_major': '140',
                   'fingerprint_path': str(config), 'fingerprint_sha256': browser_core.sha256(config),
                   'new_profile': True, 'restore_session': False, 'launch_args': []}
        controller = browser_core.BrowserController(self.base / 'controller',
            settings={'windows': [runtime], 'persistent': False})
        controller._save = Mock()
        before = copy.deepcopy(runtime)
        selected = self.base / 'short-engine/BitBrowser.exe'
        observed = {}

        def intercept(arguments, **options):
            observed.update(arguments=arguments, cwd=str(options['cwd']))
            raise LaunchObserved()

        with legacy_windows_io(), patch.object(controller, '_ensure_record', return_value=False), \
                patch.object(browser_core, '_profile_browsers', return_value=[]), \
                patch('signature_lifetime.require_current_signature'), \
                patch.object(browser_core, '_short_executable_path', side_effect=lambda path:
                    selected if Path(path).name.casefold()=='bitbrowser.exe' else None), \
                patch.object(browser_core.subprocess, 'Popen', side_effect=intercept):
            with self.assertRaises(LaunchObserved):
                controller.open('synthetic', offline_test=True, extra_urls=['about:blank'], bootstrap_blank=True)
        self.assertEqual(observed['arguments'][0], str(selected))
        self.assertTrue(all('\\\\?\\' not in value for value in observed['arguments']))
        self.assertFalse(observed['cwd'].startswith('\\\\?\\'))
        self.assertEqual(runtime, before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
