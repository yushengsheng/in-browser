"""Synthetic installation/SQLite fixtures; never read the real installation data."""
from contextlib import contextmanager
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
spec = importlib.util.spec_from_file_location('installation_inspector', ROOT / 'tools/inspect_installation.py')
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import fingerprint_continuity as continuity
from local_state import LocalBrowserError, protect
from portable_paths import encode_record
from portable_vault import PortableVault


def valid_baseline():
    return {'format': continuity.FORMAT, 'probe_version': continuity.PROBE_VERSION,
            'binding': 'binding-fixture', 'stable': {key: 'fixture' for key in continuity._REQUIRED},
            'unstable': []}


class InstallationFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='inspector-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        self.root = self.project / 'data'
        self.root.mkdir()
        PortableVault(self.root).initialize()
        (self.root / 'portable-mode.bin').write_bytes(b'fixture-marker')
        self.profile = self.root / 'profiles/synthetic'
        self.profile.mkdir(parents=True)
        self.key = b'x' * 32
        self.private = {'format': 1, 'key': base64.b64encode(self.key).decode(),
                        'key_id': hashlib.sha256(self.key).hexdigest()}
        for index, (relative, table, column) in enumerate(inspector._DATABASES):
            path = self.profile / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            con = sqlite3.connect(path)
            try:
                con.execute(f'CREATE TABLE {table} ({column} BLOB)')
                nonce = bytes([index]) * 12
                value = b'v10' + nonce + AESGCM(self.key).encrypt(nonce, b'synthetic-only', None)
                con.execute(f'INSERT INTO {table} VALUES (?)', (value,))
                con.commit()
            finally:
                con.close()
        self.signature = self.root / 'synthetic.bin'
        self.signature.write_bytes(b'synthetic-signature')
        self.engine = self.root / 'synthetic.exe'
        self.engine.write_bytes(b'synthetic-engine-never-run')
        self.record = {'id': 'synthetic', 'archived': False, '_native': {'fixture': True},
                       '_runtime': {'profile_path': str(self.profile), 'core_path': str(self.engine),
                                    'fingerprint_path': str(self.signature), 'fingerprint_sha256': inspector.digest_file(self.signature),
                                    'core_major': '148', 'signature_provider': 'local-v1', 'signature_key_id': 'fixture-key-id'},
                       '_portable_crypt': self.private, '_continuity': valid_baseline()}
        self.database = self.root / 'windows.sqlite'
        con = sqlite3.connect(self.database)
        try:
            con.execute('CREATE TABLE profiles (id TEXT PRIMARY KEY, seq INTEGER UNIQUE, created_at TEXT, last_opened_at TEXT, archived INTEGER, data BLOB)')
            con.execute('CREATE TABLE settings (key TEXT PRIMARY KEY, value BLOB)')
            con.execute('CREATE TABLE source_bindings (source_key TEXT PRIMARY KEY, profile_id TEXT UNIQUE, imported_at TEXT)')
            payload = protect(json.dumps(encode_record(self.record, self.root)).encode(), root=self.root)
            con.execute('INSERT INTO profiles VALUES (?,?,?,?,?,?)', ('synthetic', 1, 'fixture', None, 0, payload))
            for key, value in (('groups', ['fixture']), ('migration_done', True), ('application', {'download_dir': '@data/downloads'})):
                con.execute('INSERT INTO settings VALUES (?,?)', (key, protect(json.dumps(value).encode(), root=self.root)))
            con.execute('INSERT INTO source_bindings VALUES (?,?,?)', ('synthetic-source', 'synthetic', 'fixture'))
            con.commit()
        finally:
            con.close()
        resources = self.root / 'resources'
        resources.mkdir()
        for name in ('electron-main.js', 'crypto.worker.js', 'defaults.json'):
            (resources / name).write_text('{}', encoding='utf-8')
        (self.project / 'runtime').mkdir()
        (self.project / 'runtime/manifest.sha256.json').write_text('{"files":{}}', encoding='utf-8')

    def deadline(self):
        return time.monotonic() + 15

    @contextmanager
    def mocked_installation(self):
        signer = Mock(key_id='fixture-key-id')
        signer.verify.return_value = True
        configuration = Mock()
        configuration.decode.return_value = self.record['_native']
        configuration.source_archive.return_value = {'key_id': signer.key_id, 'items': {}}
        def read(path, **kwargs):
            return {'key_id': signer.key_id} if path.name == 'private.bin' else {'format': 1, 'state': 'ready'}
        with patch.object(inspector, 'ROOT', self.project), patch.object(inspector, 'LocalSigner', return_value=signer), \
                patch.object(inspector, 'LocalEngineStore'), patch.object(inspector, 'Configuration', return_value=configuration) as construct, \
                patch.object(inspector, 'read_encrypted', side_effect=read), \
                patch.object(inspector, 'binding_for', return_value='binding-fixture'), \
                patch.object(inspector, 'profile_processes', return_value=[]), \
                patch.object(continuity, 'probe_snapshot', side_effect=AssertionError('No probe allowed')):
            yield construct

    def test_mock_installation_checks_all_settings_and_does_not_create_original_sidecars(self):
        before = inspector.profile_digest(self.root)
        with self.mocked_installation():
            result = inspector.inspect(self.root)
        self.assertTrue(result['success'])
        self.assertTrue(result['checks']['settings_decrypted_and_decoded'])
        self.assertEqual((result['settings'], result['source_bindings']), (3, 1))
        self.assertEqual(before, inspector.profile_digest(self.root))
        self.assertFalse(list(self.root.rglob('*-shm')))
        self.assertFalse(list(self.root.rglob('*-wal')))

    def test_empty_retired_journals_are_preserved_and_nonempty_journals_refused(self):
        databases = [self.database] + [self.profile / relative for relative, _, _ in inspector._DATABASES]
        for database in databases:
            database.with_name(database.name + '-journal').write_bytes(b'')
        before = inspector.profile_digest(self.root)
        with self.mocked_installation():
            self.assertTrue(inspector.inspect(self.root)['success'])
        self.assertEqual(before, inspector.profile_digest(self.root))
        journal = self.database.with_name(self.database.name + '-journal')
        journal.write_bytes(b'pending-transaction-fixture')
        with self.assertRaises(ValueError):
            inspector.database_fingerprint(self.database, self.deadline())

    def test_settings_reject_corrupt_ciphertext_json_and_path_traversal(self):
        for value in (b'corrupted-envelope', protect(b'not-json', root=self.root),
                      protect(b'{"download_dir":"@data/../outside"}', root=self.root)):
            with self.subTest(size=len(value)):
                con = sqlite3.connect(self.database)
                con.execute('UPDATE settings SET value=? WHERE key=?', (value, 'application'))
                con.commit()
                con.close()
                with self.assertRaises((LocalBrowserError, ValueError)):
                    inspector.read_catalog(self.root, self.deadline())

    def test_wal_is_included_and_no_original_database_is_connected(self):
        source = sqlite3.connect(self.database)
        self.addCleanup(source.close)
        source.execute('PRAGMA journal_mode=WAL')
        source.execute('PRAGMA wal_autocheckpoint=0')
        source.execute('INSERT INTO settings VALUES (?,?)', ('wal-fixture', protect(b'true', root=self.root)))
        source.commit()
        before = inspector.database_fingerprint(self.database, self.deadline())
        original_connect = sqlite3.connect
        calls = []
        def connect(path, *args, **kwargs):
            calls.append(str(path))
            self.assertFalse(str(path).startswith(self.database.as_uri()))
            self.assertNotIn('immutable', str(path))
            return original_connect(path, *args, **kwargs)
        with patch.object(inspector.sqlite3, 'connect', side_effect=connect):
            result = inspector.read_catalog(self.root, self.deadline())
        self.assertEqual(result['settings'], 4)
        self.assertTrue(calls)
        self.assertEqual(before, inspector.database_fingerprint(self.database, self.deadline()))

    def test_all_browser_databases_connect_only_to_copies(self):
        expected = ('Default/Network/Cookies', 'Default/Cookies',
                    'Default/Login Data', 'Default/Login Data For Account')
        originals = [(self.profile / relative).as_uri() for relative in expected]
        original_connect = sqlite3.connect
        calls = []
        def connect(path, *args, **kwargs):
            calls.append(str(path))
            self.assertFalse(any(str(path).startswith(original) for original in originals))
            return original_connect(path, *args, **kwargs)
        before = inspector.profile_digest(self.profile)
        with patch.object(inspector, 'profile_processes', return_value=[]) as processes, \
                patch.object(inspector.sqlite3, 'connect', side_effect=connect):
            result = inspector.inspect_profile(self.profile, self.private, self.deadline())
        self.assertTrue(result.get('browser_ciphertext_authenticated'))
        self.assertCountEqual([path.split('/Default/', 1)[-1].split('?', 1)[0]
                               for path in calls],
                              [relative.removeprefix('Default/').replace(' ', '%20')
                               for relative in expected])
        self.assertEqual(before, inspector.profile_digest(self.profile))
        self.assertEqual(processes.call_count, 2)
        self.assertTrue(all(call.kwargs.get('require_inspectable') is True for call in processes.call_args_list))

    def test_browser_wal_ciphertext_is_authenticated(self):
        relative, table, column = inspector._DATABASES[0]
        source = sqlite3.connect(self.profile / relative)
        self.addCleanup(source.close)
        source.execute('PRAGMA journal_mode=WAL')
        source.execute(f'INSERT INTO {table} ({column}) VALUES (?)', (b'v20-invalid-fixture',))
        source.commit()
        before = inspector.profile_digest(self.profile)
        with patch.object(inspector, 'profile_processes', return_value=[]):
            result = inspector.inspect_profile(self.profile, self.private, self.deadline())
        self.assertEqual(result['profile_validation'], 'failed')
        self.assertNotIn('browser_ciphertext_authenticated', result)
        self.assertEqual(before, inspector.profile_digest(self.profile))

    def test_unknown_or_changing_process_state_never_reports_closed_verification(self):
        with patch.object(inspector, 'profile_processes', side_effect=LocalBrowserError('fixture')), \
                patch.object(inspector, '_validate_databases') as authenticate:
            result = inspector.inspect_profile(self.profile, self.private, self.deadline())
        self.assertIsNone(result['running'])
        authenticate.assert_not_called()
        with patch.object(inspector, 'profile_processes', side_effect=[[], [object()]]):
            result = inspector.inspect_profile(self.profile, self.private, self.deadline())
        self.assertEqual(result['profile_validation'], 'skipped_state_changed')
        self.assertNotIn('profile_snapshot', result)
        self.assertNotIn('browser_ciphertext_authenticated', result)

    def test_snapshot_detects_source_change_and_enforces_copy_budget_and_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(inspector.SnapshotChanged):
                with inspector.database_snapshot(self.database, Path(directory) / 'copy.sqlite', self.deadline()):
                    with self.database.open('ab') as stream:
                        stream.write(b'fixture-change')
        with patch.object(inspector, 'MAX_DATABASE_COPY_BYTES', 1), self.assertRaises(ValueError):
            inspector.read_catalog(self.root, self.deadline())
        with self.assertRaises(TimeoutError):
            inspector.read_catalog(self.root, time.monotonic() - 1)

    def test_resource_absence_refuses_configuration_without_creating_directory(self):
        (self.root / 'resources/defaults.json').unlink()
        before = inspector.profile_digest(self.root)
        with self.mocked_installation() as construct, self.assertRaises(FileNotFoundError):
            inspector.inspect(self.root)
        construct.assert_not_called()
        self.assertEqual(before, inspector.profile_digest(self.root))

    def test_full_catalog_hash_covers_bindings_and_outer_columns_while_old_hash_stays_compatible(self):
        before = inspector.read_catalog(self.root, self.deadline())
        legacy = hashlib.sha256()
        con = sqlite3.connect(self.database)
        for (payload,) in con.execute('SELECT data FROM profiles ORDER BY seq').fetchall() + con.execute('SELECT value FROM settings ORDER BY key').fetchall():
            legacy.update(hashlib.sha256(payload).digest())
        self.assertEqual(before['catalog_payload_sha256'], legacy.hexdigest())
        con.execute('UPDATE profiles SET last_opened_at=?', ('changed-fixture',))
        con.execute('UPDATE source_bindings SET imported_at=?', ('changed-fixture',))
        con.commit()
        con.close()
        after = inspector.read_catalog(self.root, self.deadline())
        self.assertEqual(before['catalog_payload_sha256'], after['catalog_payload_sha256'])
        self.assertNotEqual(before['catalog_full_tables_sha256'], after['catalog_full_tables_sha256'])

    def test_running_or_uninspectable_installation_is_incomplete(self):
        for state in ([object()], LocalBrowserError('fixture')):
            with self.subTest(known=isinstance(state, list)), self.mocked_installation():
                options = {'return_value': state} if isinstance(state, list) else {'side_effect': state}
                with patch.object(inspector, 'profile_processes', **options):
                    result = inspector.inspect(self.root)
            self.assertFalse(result['success'])
            self.assertFalse(result['checks']['all_profile_checks_complete'])
            self.assertNotIn('profile_snapshot', result['profiles'][0])


class InspectorContracts(unittest.TestCase):
    def test_baseline_preprobe_contract_matches_production_without_probing(self):
        baseline = valid_baseline()
        variants = [dict(baseline, format=0), dict(baseline, stable={}), dict(baseline, unstable='invalid'),
                    dict(baseline, stable={'navigator.userAgent': 'fixture'}),
                    dict(baseline, stable=dict(baseline['stable'], **{'unsafe-field': True})),
                    dict(baseline, stable={f'field{index}': True for index in range(continuity.MAX_BASELINE_FIELDS + 1)}),
                    dict(baseline, stable=dict(baseline['stable'], extra='x' * continuity.MAX_SNAPSHOT_BYTES)),
                    dict(baseline, stable=dict(baseline['stable'], extra=float('nan')))]
        self.assertTrue(inspector.baseline_structure_valid(baseline))
        with patch.object(continuity, 'probe_snapshot', side_effect=AssertionError('Probe must not start')):
            for index, value in enumerate(variants):
                with self.subTest(index=index):
                    self.assertFalse(inspector.baseline_structure_valid(value))
                    with self.assertRaises(LocalBrowserError):
                        continuity.verify_continuity({'_continuity': value}, Path('fixture'))

    def test_legacy_comparison_is_preserved_and_new_coverage_is_explicit(self):
        before = {'catalog_payload_sha256': 'payload-fixture', 'profiles': [{'profile_snapshot': {'sha256': 'profile-fixture'}}]}
        current = dict(copy.deepcopy(before), success=True, catalog_full_tables_sha256='new-full-fixture')
        inspector.compare_reports(before, current)
        self.assertTrue(current['success'])
        self.assertFalse(current['comparison_coverage']['catalog_full_tables_available_in_previous_report'])
        self.assertNotIn('catalog_full_tables', current['unchanged_since_comparison'])
        self.assertNotIn('catalog_full_tables_sha256', before)
        current['success'] = True
        inspector.compare_reports(dict(before, catalog_full_tables_sha256='different-fixture'), current)
        self.assertFalse(current['success'])

    def test_atomic_report_failure_preserves_previous_report_and_cleans_own_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text('previous-complete-report', encoding='utf-8')
            with patch.object(inspector.os, 'replace', side_effect=OSError('fixture')), self.assertRaises(OSError):
                inspector.write_report(path, {'success': True})
            self.assertEqual(path.read_text(encoding='utf-8'), 'previous-complete-report')
            self.assertEqual([item.name for item in path.parent.iterdir()], ['report.json'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
