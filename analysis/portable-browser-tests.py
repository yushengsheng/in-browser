"""Synthetic OSCrypt portability tests; no real profiles, accounts or browsers."""
import base64
import copy
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import portable_browser as portable
from local_state import LocalBrowserError


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='portable-browser-crypto-tests-', dir=ROOT / 'analysis')
        self.profile = Path(self.temporary.name)
        self.key = os.urandom(32)
        self.user = 'first'
        self.users = {name: AESGCM(os.urandom(32)) for name in ('first', 'second')}
        self.dpapi_patch = patch.object(portable, '_dpapi_protect', side_effect=self.dpapi)
        self.process_patch = patch.object(portable, 'profile_processes', return_value=[])
        self.dpapi_patch.start()
        self.processes = self.process_patch.start()
        self.state = {'os_crypt': {'audit_enabled': True, 'encrypted_key': self.wrap(self.key)},
                      'unrelated': {'nested': [True, 9, '保留']}}
        self.write_state(self.state)
        self.make_database('Default/Network/Cookies', 'cookies', 'encrypted_value',
                           [(self.encrypt(self.key, b'host-hash-is-part-of-authenticated-plaintext' + b'x'),), (None,), (b'',)])
        self.make_database('Default/Login Data', 'logins', 'password_value', [(self.encrypt(self.key, b'example-only'),)])

    def tearDown(self):
        self.dpapi_patch.stop()
        self.process_patch.stop()
        if self.profile.resolve().parent != (ROOT / 'analysis').resolve() or not self.profile.name.startswith('portable-browser-crypto-tests-'):
            raise AssertionError('Unsafe temporary cleanup')
        self.temporary.cleanup()

    def dpapi(self, value, decrypt=False):
        cipher = self.users[self.user]
        if decrypt:
            return cipher.decrypt(value[:12], value[12:], None)
        nonce = os.urandom(12)
        return nonce + cipher.encrypt(nonce, value, None)

    def wrap(self, key):
        return base64.b64encode(b'DPAPI' + self.dpapi(key)).decode()

    @staticmethod
    def encrypt(key, clear):
        nonce = os.urandom(12)
        return b'v10' + nonce + AESGCM(key).encrypt(nonce, clear, None)

    def write_state(self, state):
        (self.profile / 'Local State').write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')

    def make_database(self, relative, table, column, values):
        path = self.profile / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as con, con:
            con.execute(f'CREATE TABLE {table} ({column} BLOB, value TEXT)')
            con.executemany(f'INSERT INTO {table}({column}) VALUES (?)', values)

    def before(self):
        state = self.profile / 'Local State'
        return state.read_bytes(), state.stat().st_mtime_ns

    def assert_fixed_failure(self, operation):
        before = self.before()
        with self.assertRaises(LocalBrowserError) as raised:
            operation()
        self.assertIn(str(raised.exception), (portable._FAILED, portable._RUNNING))
        self.assertTrue(self.before() == before)
        self.assertFalse(any(self.profile.glob('Local State.portable-*.tmp')))

    def test_capture_authenticates_cookie_and_password_without_mutation(self):
        before = self.before()
        private = portable.capture_profile(self.profile)
        self.assertTrue(base64.b64decode(private['key']) == self.key)
        self.assertTrue(private['key_id'] == hashlib.sha256(self.key).hexdigest())
        self.assertTrue(self.before() == before)
        self.processes.assert_called_with(self.profile, require_inspectable=True)

    def test_same_user_keeps_exact_bytes_and_mtime(self):
        private = portable.capture_profile(self.profile)
        before = self.before()
        self.assertFalse(portable.prepare_profile(self.profile, private))
        self.assertTrue(self.before() == before)

    def test_mock_second_user_rewraps_original_key_and_keeps_other_state(self):
        private = portable.capture_profile(self.profile)
        database = self.profile / 'Default/Network/Cookies'
        before_database = database.read_bytes()
        self.user = 'second'
        self.assertTrue(portable.prepare_profile(self.profile, private))
        changed = json.loads((self.profile / 'Local State').read_text(encoding='utf-8'))
        restored = portable._unwrap(changed['os_crypt'].pop('encrypted_key'))
        expected = copy.deepcopy(self.state)
        expected['os_crypt'].pop('encrypted_key')
        self.assertTrue(changed == expected)
        self.assertTrue(restored == self.key)
        self.assertTrue(database.read_bytes() == before_database)
        self.assertFalse(portable.prepare_profile(self.profile, private))

    def test_current_wrapper_for_different_key_is_corrected(self):
        private = portable.capture_profile(self.profile)
        state = copy.deepcopy(self.state)
        state['os_crypt']['encrypted_key'] = self.wrap(os.urandom(32))
        self.write_state(state)
        self.assertTrue(portable.prepare_profile(self.profile, private))
        self.assertFalse(portable.prepare_profile(self.profile, private))

    def test_missing_os_crypt_uses_saved_private_key(self):
        private = portable.capture_profile(self.profile)
        self.write_state({'unrelated': self.state['unrelated']})
        self.assertTrue(portable.prepare_profile(self.profile, private))
        self.assertFalse(portable.prepare_profile(self.profile, private))

    def test_app_bound_provider_is_refused(self):
        state = copy.deepcopy(self.state)
        state['os_crypt']['app_bound_encrypted_key'] = 'unsupported-synthetic-value'
        self.write_state(state)
        self.assert_fixed_failure(lambda: portable.capture_profile(self.profile))

    def test_v20_and_unknown_nonempty_encrypted_data_are_refused(self):
        private = portable.capture_profile(self.profile)
        for value in (b'v20' + os.urandom(64), b'v11' + os.urandom(64), b'unknown-format'):
            with self.subTest(prefix=value[:3]):
                with closing(sqlite3.connect(self.profile / 'Default/Network/Cookies')) as con, con:
                    con.execute('UPDATE cookies SET encrypted_value=? WHERE rowid=1', (value,))
                self.assert_fixed_failure(lambda: portable.capture_profile(self.profile))
                self.assert_fixed_failure(lambda: portable.prepare_profile(self.profile, private))

    def test_invalid_authentication_tag_is_refused(self):
        with closing(sqlite3.connect(self.profile / 'Default/Login Data')) as con, con:
            con.execute('UPDATE logins SET password_value=?', (self.encrypt(os.urandom(32), b'other-key'),))
        self.assert_fixed_failure(lambda: portable.capture_profile(self.profile))

    def test_account_login_database_is_authenticated(self):
        self.make_database('Default/Login Data For Account', 'logins', 'password_value', [(b'v20' + os.urandom(64),)])
        self.assert_fixed_failure(lambda: portable.capture_profile(self.profile))

    def test_empty_ciphertext_with_plaintext_column_is_allowed(self):
        with closing(sqlite3.connect(self.profile / 'Default/Network/Cookies')) as con, con:
            con.execute('UPDATE cookies SET value=? WHERE encrypted_value IS NULL OR length(encrypted_value)=0', ('synthetic-plaintext-only',))
        private = portable.capture_profile(self.profile)
        self.assertFalse(portable.prepare_profile(self.profile, private))

    def test_malformed_or_wrong_private_dictionary_is_refused(self):
        private = portable.capture_profile(self.profile)
        other = os.urandom(32)
        for bad in ({}, {**private, 'key': '?' * 44}, {**private, 'key_id': '0' * 64},
                    {'format': 1, 'key': base64.b64encode(other).decode(), 'key_id': hashlib.sha256(other).hexdigest()}):
            self.assert_fixed_failure(lambda: portable.prepare_profile(self.profile, bad))

    def test_running_or_uninspectable_profile_is_refused(self):
        private = portable.capture_profile(self.profile)
        self.processes.return_value = [object()]
        self.assert_fixed_failure(lambda: portable.capture_profile(self.profile))
        self.assert_fixed_failure(lambda: portable.prepare_profile(self.profile, private))
        self.processes.side_effect = LocalBrowserError('synthetic inspection error')
        self.assert_fixed_failure(lambda: portable.prepare_profile(self.profile, private))

    def test_database_budget_refuses_without_state_write(self):
        private = portable.capture_profile(self.profile)
        with patch.object(portable, '_MAX_ROWS', 0):
            self.assert_fixed_failure(lambda: portable.capture_profile(self.profile))
            self.assert_fixed_failure(lambda: portable.prepare_profile(self.profile, private))

    def test_atomic_replace_failure_retains_original_and_removes_temp(self):
        private = portable.capture_profile(self.profile)
        self.user = 'second'
        with patch.object(portable.os, 'replace', side_effect=OSError('synthetic replace failure')):
            self.assert_fixed_failure(lambda: portable.prepare_profile(self.profile, private))

    def test_concurrent_state_change_is_not_overwritten(self):
        private = portable.capture_profile(self.profile)
        self.user = 'second'
        validation = portable._validate_databases
        newer = copy.deepcopy(self.state)
        newer['unrelated']['newer'] = True

        def concurrent_change(profile, key):
            validation(profile, key)
            self.write_state(newer)

        with patch.object(portable, '_validate_databases', side_effect=concurrent_change):
            with self.assertRaises(LocalBrowserError):
                portable.prepare_profile(self.profile, private)
        self.assertTrue(json.loads((self.profile / 'Local State').read_text(encoding='utf-8')) == newer)
        self.assertFalse(any(self.profile.glob('Local State.portable-*.tmp')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
