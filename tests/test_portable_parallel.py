"""Independent profile authentication and atomic output writes can overlap."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
sys.path.insert(0, str(ROOT / 'tests'))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import local_state
import portable_browser as portable
from test_path_locks import fixture_scope, short_path, wait_for


class Overlap:
    def __init__(self, target):
        self.guard = threading.Lock()
        self.active = self.peak = self.calls = 0
        self.target = target
        self.reached = threading.Event()
        self.release = threading.Event()

    def enter(self, operation, *args):
        with self.guard:
            self.active += 1
            self.calls += 1
            self.peak = max(self.peak, self.active)
            if self.active >= self.target:
                self.reached.set()
        try:
            if not self.release.wait(5):
                raise AssertionError('Synthetic workers did not overlap')
            return operation(*args)
        finally:
            with self.guard:
                self.active -= 1


class PortableParallelTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_scope('portable-parallel-')
        self.key = os.urandom(32)
        self.private = {'format': 1, 'key': base64.b64encode(self.key).decode('ascii'),
                        'key_id': hashlib.sha256(self.key).hexdigest()}
        dpapi_patch = patch.object(portable, '_dpapi_protect', side_effect=self.dpapi)
        process_patch = patch.object(portable, 'profile_processes', return_value=[])
        self.addCleanup(dpapi_patch.stop)
        self.addCleanup(process_patch.stop)
        dpapi_patch.start()
        self.processes = process_patch.start()

    @staticmethod
    def dpapi(value, decrypt=False):
        if decrypt:
            if not value.startswith(b'synthetic-wrapper:'):
                raise ValueError('Synthetic other user')
            return value[len(b'synthetic-wrapper:'):]
        return b'synthetic-wrapper:' + value

    def profile(self, name='long-profile-directory', *, rows=40):
        profile = self.root / name
        profile.mkdir()
        wrapped = base64.b64encode(b'DPAPI' + self.dpapi(self.key)).decode('ascii')
        (profile / 'Local State').write_text(json.dumps({
            'os_crypt': {'encrypted_key': wrapped}, 'preserved': [1, True, '合成']},
            ensure_ascii=False, indent=2), encoding='utf-8')
        database = profile / 'Default/Network/Cookies'
        database.parent.mkdir(parents=True)
        cipher = AESGCM(self.key)
        values = []
        for _ in range(rows):
            nonce = os.urandom(12)
            values.append((b'v10' + nonce + cipher.encrypt(nonce, b'synthetic-cookie', None),))
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute('CREATE TABLE cookies (encrypted_value BLOB)')
            connection.executemany('INSERT INTO cookies VALUES (?)', values)
        return profile

    @staticmethod
    def state_identity(profile):
        path = profile / 'Local State'
        return path.read_bytes(), path.stat().st_mtime_ns

    def test_ten_profiles_authenticate_in_parallel_for_both_operations(self):
        profiles = [self.profile(str(number)) for number in range(10)]
        identities = [self.state_identity(profile) for profile in profiles]
        validate = portable._validate_databases
        for mode in ('capture', 'prepare'):
            overlap = Overlap(10)
            with self.subTest(mode=mode), patch.object(portable, '_validate_databases',
                    side_effect=lambda *args: overlap.enter(validate, *args)), \
                    ThreadPoolExecutor(max_workers=10) as workers:
                pending = [workers.submit(portable.capture_profile, profile) if mode == 'capture' else
                           workers.submit(portable.prepare_profile, profile, self.private) for profile in profiles]
                try:
                    self.assertTrue(overlap.reached.wait(4))
                    self.assertEqual(overlap.peak, 10)
                finally:
                    overlap.release.set()
                for future in pending:
                    result = future.result(8)
                    self.assertTrue(result == self.private if mode == 'capture' else result is False)
            self.assertEqual(overlap.calls, 10)
        self.assertTrue([self.state_identity(profile) for profile in profiles] == identities)
        self.assertEqual(self.processes.call_count, 40)
        self.assertFalse(portable._PROFILE_LOCKS._entries)

    def assert_profile_serial(self, profile, alias):
        overlap = Overlap(1)
        validate = portable._validate_databases
        before = self.state_identity(profile)
        with patch.object(portable, '_validate_databases',
                          side_effect=lambda *args: overlap.enter(validate, *args)), \
                ThreadPoolExecutor(max_workers=3) as workers:
            first = workers.submit(portable.capture_profile, profile)
            try:
                self.assertTrue(overlap.reached.wait(4))
                second = workers.submit(portable.prepare_profile, alias, self.private)
                third = workers.submit(portable.capture_profile, profile / '..' / profile.name)
                self.assertTrue(wait_for(lambda: sum(item[1] for item in
                    portable._PROFILE_LOCKS._entries.values()) == 3))
                self.assertEqual(overlap.calls, 1)
            finally:
                overlap.release.set()
            self.assertTrue(first.result(8) == self.private)
            self.assertFalse(second.result(8))
            self.assertTrue(third.result(8) == self.private)
        self.assertEqual(overlap.peak, 1)
        self.assertEqual(overlap.calls, 3)
        self.assertTrue(self.state_identity(profile) == before)
        self.assertFalse(portable._PROFILE_LOCKS._entries)

    def test_capture_and_prepare_share_same_directory_lock(self):
        profile = self.profile()
        alias = Path(str(profile).upper()) if os.name == 'nt' else Path(os.path.relpath(profile))
        self.assert_profile_serial(profile, alias)

    def test_capture_and_prepare_share_short_name_directory_lock(self):
        profile = self.profile()
        self.assert_profile_serial(profile, short_path(profile))

    def test_same_wrapper_reauthenticates_every_row_and_rejects_late_corruption(self):
        profile = self.profile(rows=65)
        before = self.state_identity(profile)
        real_cipher = AESGCM(self.key)
        with patch.object(portable, 'AESGCM') as factory:
            factory.return_value.decrypt.side_effect = real_cipher.decrypt
            self.assertFalse(portable.prepare_profile(profile, self.private))
            self.assertEqual(factory.return_value.decrypt.call_count, 65)
        database = profile / 'Default/Network/Cookies'
        with closing(sqlite3.connect(database)) as connection, connection:
            value = connection.execute('SELECT encrypted_value FROM cookies WHERE rowid=65').fetchone()[0]
            connection.execute('UPDATE cookies SET encrypted_value=? WHERE rowid=65',
                               (value[:-1] + bytes([value[-1] ^ 1]),))
        for operation in (lambda: portable.capture_profile(profile),
                          lambda: portable.prepare_profile(profile, self.private)):
            with self.assertRaises(local_state.LocalBrowserError) as raised:
                operation()
            self.assertEqual(str(raised.exception), portable._FAILED)
            self.assertTrue(self.state_identity(profile) == before)
        self.assertFalse(portable._PROFILE_LOCKS._entries)

    def test_initial_and_late_occupation_refuse_without_writing(self):
        profile = self.profile()
        before = self.state_identity(profile)
        for operation in (lambda: portable.capture_profile(profile),
                          lambda: portable.prepare_profile(profile, self.private)):
            for states in ([object()],), ([], [object()]):
                with self.subTest(checks=len(states)), patch.object(portable, 'profile_processes', side_effect=states):
                    with self.assertRaises(local_state.LocalBrowserError) as raised:
                        operation()
                    self.assertEqual(str(raised.exception), portable._RUNNING)
                    self.assertTrue(self.state_identity(profile) == before)
        self.assertFalse(portable._PROFILE_LOCKS._entries)

    def test_changed_state_during_validation_refuses_saved_result(self):
        profile = self.profile()
        validate = portable._validate_databases

        def change(*args):
            validate(*args)
            path = profile / 'Local State'
            path.write_bytes(path.read_bytes() + b' ')

        with patch.object(portable, '_validate_databases', side_effect=change):
            for operation in (lambda: portable.capture_profile(profile),
                              lambda: portable.prepare_profile(profile, self.private)):
                with self.assertRaises(local_state.LocalBrowserError):
                    operation()
        self.assertFalse(any(profile.glob('Local State.portable-*.tmp')))
        self.assertFalse(portable._PROFILE_LOCKS._entries)

    def test_rewrap_flushes_then_rechecks_and_keeps_original_key(self):
        profile = self.profile()
        path = profile / 'Local State'
        state = json.loads(path.read_text(encoding='utf-8'))
        state['os_crypt']['encrypted_key'] = base64.b64encode(b'DPAPIother-user').decode('ascii')
        path.write_text(json.dumps(state), encoding='utf-8')
        before_database = (profile / 'Default/Network/Cookies').read_bytes()
        events = []
        replace, fsync = portable.os.replace, portable.os.fsync
        with patch.object(portable, '_closed', side_effect=lambda _profile: events.append('closed')), \
                patch.object(portable.os, 'fsync', side_effect=lambda fd: (events.append('fsync'), fsync(fd))[-1]), \
                patch.object(portable.os, 'replace', side_effect=lambda *args: (events.append('replace'), replace(*args))[-1]):
            self.assertTrue(portable.prepare_profile(profile, self.private))
        self.assertEqual(events, ['closed', 'closed', 'fsync', 'closed', 'replace'])
        self.assertTrue(portable.capture_profile(profile) == self.private)
        self.assertTrue((profile / 'Default/Network/Cookies').read_bytes() == before_database)
        self.assertFalse(portable.prepare_profile(profile, self.private))


class EncryptedWriteParallelTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_scope('encrypted-write-parallel-')
        protect_patch = patch.object(local_state, 'protect', side_effect=lambda data, **_kwargs: data)
        self.addCleanup(protect_patch.stop)
        protect_patch.start()

    def test_ten_independent_atomic_writes_overlap_and_remain_complete(self):
        overlap = Overlap(10)
        fsync = local_state.os.fsync
        paths = [self.root / f'output-{number}.bin' for number in range(10)]
        with patch.object(local_state.os, 'fsync', side_effect=lambda fd: overlap.enter(fsync, fd)), \
                ThreadPoolExecutor(max_workers=10) as workers:
            pending = [workers.submit(local_state.write_encrypted, path, {'number': number}, root=self.root)
                       for number, path in enumerate(paths)]
            try:
                self.assertTrue(overlap.reached.wait(4))
                self.assertEqual(overlap.peak, 10)
            finally:
                overlap.release.set()
            for future in pending:
                future.result(8)
        for number, path in enumerate(paths):
            self.assertEqual(json.loads(path.read_bytes()), {'number': number})
        self.assertFalse(list(self.root.glob('*.tmp')))
        self.assertFalse(local_state._ENCRYPTED_WRITE_LOCKS._entries)

    def test_same_output_alias_waits_through_fsync_and_atomic_replace(self):
        directory = self.root / 'long-output-directory'
        directory.mkdir()
        alias = short_path(directory) if os.name == 'nt' else Path(os.path.relpath(directory))
        path = directory / 'output.bin'
        path.write_text('{}', encoding='utf-8')
        overlap = Overlap(1)
        fsync = local_state.os.fsync
        with patch.object(local_state.os, 'fsync', side_effect=lambda fd: overlap.enter(fsync, fd)), \
                ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(local_state.write_encrypted, path, {'first': True}, root=self.root)
            try:
                self.assertTrue(overlap.reached.wait(4))
                second = workers.submit(local_state.write_encrypted, alias / path.name,
                                        {'second': True}, root=self.root)
                self.assertTrue(wait_for(lambda: sum(item[1] for item in
                    local_state._ENCRYPTED_WRITE_LOCKS._entries.values()) == 2))
                self.assertEqual(overlap.calls, 1)
                self.assertEqual(json.loads(path.read_bytes()), {})
            finally:
                overlap.release.set()
            first.result(8)
            second.result(8)
        self.assertEqual(overlap.peak, 1)
        self.assertEqual(json.loads(path.read_bytes()), {'second': True})
        self.assertFalse(list(directory.glob('*.tmp')))
        self.assertFalse(local_state._ENCRYPTED_WRITE_LOCKS._entries)

    def test_fsync_or_replace_failure_preserves_target_and_releases_lock(self):
        path = self.root / 'output.bin'
        for method in ('fsync', 'replace'):
            path.write_bytes(b'original')
            with self.subTest(method=method), patch.object(local_state.os, method,
                    side_effect=OSError('synthetic write failure')):
                with self.assertRaises(OSError):
                    local_state.write_encrypted(path, {'changed': True}, root=self.root)
            self.assertEqual(path.read_bytes(), b'original')
            self.assertFalse(list(self.root.glob('*.tmp')))
            self.assertFalse(local_state._ENCRYPTED_WRITE_LOCKS._entries)
            local_state.write_encrypted(path, {'retry': True}, root=self.root)
            self.assertEqual(json.loads(path.read_bytes()), {'retry': True})


if __name__ == '__main__':
    unittest.main(verbosity=2)
