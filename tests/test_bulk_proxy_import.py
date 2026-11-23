"""Bulk proxy bridge, encrypted catalog persistence and all-or-nothing updates."""
import copy
from contextlib import closing, contextmanager
import hashlib
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent / 'app'))

from api import dispatch
import profile_model
from batch_operations import Operations
from browser_core import BrowserController
from manager_service import ManagerService
from portable_vault import PortableVault, is_portable
from proxy_runtime import ProxyRuntime
from window_store import WindowStore


class MemoryWindowStore(WindowStore):
    """Use the production schema and record codec with independent RAM connections."""

    def __init__(self, uri):
        self.uri = uri
        super().__init__(SimpleNamespace(), TESTS)

    @contextmanager
    def connect(self):
        with closing(sqlite3.connect(self.uri, uri=True)) as connection, connection:
            connection.execute('PRAGMA temp_store=MEMORY')
            yield connection


def proxy_fields(proxy):
    return tuple(proxy[key] for key in ('type', 'host', 'port', 'username', 'password'))


class BulkProxyImportTests(unittest.TestCase):
    def setUp(self):
        # Supply only key material. WindowStore.pack/unpack and the vault's
        # authenticated envelope run unchanged without reading a user key.
        vault = PortableVault.__new__(PortableVault)
        vault._key = bytes(range(32))
        vault._key_id = hashlib.sha256(vault._key).digest()
        vault.enabled = True
        self.enterContext(patch('portable_vault.PortableVault', return_value=vault))
        self.uri = f'file:bulk-proxy-{uuid4().hex}?mode=memory&cache=shared'
        keeper = sqlite3.connect(self.uri, uri=True)
        self.addCleanup(keeper.close)
        self.store = MemoryWindowStore(self.uri)
        self.service = ManagerService.__new__(ManagerService)
        self.service.root = TESTS / 'synthetic-bulk-proxy-memory-only'
        self.service.store = self.store
        self.service.operations = Operations()
        self.service.controller = BrowserController(self.service.root, settings={'windows': []})
        self.service.proxy_runtime = Mock(spec=ProxyRuntime)
        self.processes = self.enterContext(patch('browser_processes.psutil.process_iter', return_value=[]))
        self.pending = self.enterContext(patch('profile_delete.get_pending_ids', return_value=set()))

    def add_profiles(self, count):
        identities = []
        for number in range(1, count + 1):
            identity = f'fixture-{number}'
            runtime = {'alias': identity, 'profile_path': str(self.service.root / identity),
                       'fingerprint_path': str(self.service.root / (identity + '.bin')),
                       'core_path': str(self.service.root / 'fixture-browser.exe'),
                       'local_proxy_port': 16000 + number}
            record = {
                'id': identity, 'seq': number, 'created_at': 'fixture', 'updated_at': 'original',
                'archived': False, 'name': identity, 'group': 'catalog group', 'remark': 'fixture',
                'username': f'account-{number}', 'cookie_text': 'synthetic existing cookie',
                'fingerprint': {'marker': number}, 'preferences': {'restore_session': True},
                '_source': {'source_id': f'source-{number}'}, '_native': {'marker': number},
                '_runtime': runtime, 'proxy': {'type': 'noproxy'},
            }
            self.store.put(record)
            self.service.controller.set_profile(identity, runtime)
            identities.append(identity)
        return identities

    def import_proxies(self, ids, text, protocol='socks5'):
        return dispatch(self.service, 'bulk_import_proxies',
                        {'ids': ids, 'text': text, 'protocol': protocol})

    def ciphertext(self):
        with self.store.connect() as connection:
            return dict(connection.execute('SELECT id,data FROM profiles'))

    def assert_rejected(self, ids, text):
        before = self.ciphertext()
        live = copy.deepcopy(self.service.controller.profiles)
        result = self.import_proxies(ids, text)
        self.assertFalse(result['ok'])
        self.assertTrue(result.get('error'))
        self.assertNotIn('fixture.invalid', result['error'])
        self.assertNotIn('fixture-password', result['error'])
        self.assertEqual(before, self.ciphertext())
        self.assertEqual(live, self.service.controller.profiles)

    def test_four_assignments_follow_window_numbers_and_leave_other_data_intact(self):
        ids = self.add_profiles(5)
        selected = [ids[0], ids[3], ids[1], ids[4]]
        expected_order = [ids[0], ids[1], ids[3], ids[4]]
        unselected = ids[2]
        before = {identity: self.store.get(identity) for identity in ids}
        original_blob = self.ciphertext()[unselected]
        rows = [rf'relay-{n}.invalid|{8000+n}|realm\user{n}|fixture\\word{n}|2030-01-01'
                for n in range(4)]
        text = rows[0] + '\\' + rows[1] + '\\\\' + rows[2] + '\r\n' + rows[3]
        self.assertEqual(dispatch(self.service, 'bulk_proxy_count', {'text': text}),
                         {'ok': True, 'data': {'count': 4}})
        self.assertEqual(self.import_proxies(selected, text, 'https'),
                         {'ok': True, 'data': {'updated': 4}})

        fresh = MemoryWindowStore(self.uri)
        for n, identity in enumerate(expected_order):
            current = fresh.get(identity)
            self.assertEqual(proxy_fields(current['proxy']),
                             ('https', f'relay-{n}.invalid', 8000+n, rf'realm\user{n}', rf'fixture\\word{n}'))
            self.assertFalse(current['proxy']['enable_socks5_udp'])
            expected = copy.deepcopy(before[identity])
            expected['proxy'] = current['proxy']
            expected['updated_at'] = current['updated_at']
            del expected['_runtime']['local_proxy_port']
            self.assertEqual(current, expected)
            self.assertEqual(self.service.controller.profiles[identity], current['_runtime'])
        self.assertEqual(fresh.get(unselected), before[unselected])
        ciphertext = self.ciphertext()
        self.assertTrue(all(is_portable(blob) for blob in ciphertext.values()))
        self.assertEqual(ciphertext[unselected], original_blob)

    def test_101_rows_reach_the_last_selected_window(self):
        numbered = self.add_profiles(101)
        text = '\n'.join(f'node-{n}.invalid|{9000+n}|fixture|pass-{n}' for n in range(len(numbered)))
        self.assertEqual(self.import_proxies(numbered[::-1], text),
                         {'ok': True, 'data': {'updated': 101}})
        records = {record['id']: record for record in MemoryWindowStore(self.uri).all()}
        for n, identity in enumerate(numbered):
            self.assertEqual(proxy_fields(records[identity]['proxy']),
                             ('socks5', f'node-{n}.invalid', 9000+n, 'fixture', f'pass-{n}'))

    def test_four_field_credentials_keep_their_backslashes(self):
        ids = self.add_profiles(2)
        text = '\n'.join([r'first.invalid|3128|domain\demo|secret\part\\tail',
                          r'second.invalid|3129|two\\slashes|tail' + '\\'])
        self.assertEqual(self.import_proxies(ids, text, 'http'), {'ok': True, 'data': {'updated': 2}})
        fresh = MemoryWindowStore(self.uri)
        self.assertEqual(proxy_fields(fresh.get(ids[0])['proxy']),
                         ('http', 'first.invalid', 3128, r'domain\demo', r'secret\part\\tail'))
        self.assertEqual(proxy_fields(fresh.get(ids[1])['proxy']),
                         ('http', 'second.invalid', 3129, r'two\\slashes', 'tail\\'))

    def test_existing_single_proxy_parser_keeps_uri_format_and_default_protocol(self):
        for text, protocol, expected in (
            ('https://demo:one%5Ctwo@fixture.invalid:443', 'socks5',
             ('https', 'fixture.invalid', 443, 'demo', r'one\two')),
            ('fixture.invalid:1080', 'socks5', ('socks5', 'fixture.invalid', 1080, '', '')),
        ):
            result = dispatch(self.service, 'proxy_parse', {'text': text, 'default_type': protocol})
            self.assertTrue(result['ok'])
            self.assertEqual(proxy_fields(result['data']['proxy']), expected)

    def test_bulk_credentials_preserve_fullwidth_colons_on_reload(self):
        ids = self.add_profiles(1)
        row = 'fixture.invalid|1080|fixture：account|pass：word：end'
        self.assertEqual(self.import_proxies(ids, row), {'ok': True, 'data': {'updated': 1}})
        saved = MemoryWindowStore(self.uri).get(ids[0])['proxy']
        self.assertEqual((saved['username'], saved['password']), ('fixture：account', 'pass：word：end'))
        original_parser = dispatch(self.service, 'proxy_parse', {'text': row, 'default_type': 'socks5'})
        self.assertTrue(original_parser['ok'])
        single = original_parser['data']['proxy']
        self.assertEqual((single['username'], single['password']), ('fixture:account', 'pass:word:end'))

    def test_mixed_document_formats_keep_credentials_and_ipv6_by_numeric_window(self):
        examples = (
            ('comma.invalid,8101', ('comma.invalid', 8101, '', '')),
            ('wide-comma.invalid，8102，demo|one，pass:word，2030-01-01，',
             ('wide-comma.invalid', 8102, 'demo|one', 'pass:word')),
            ('[2001:db8::a]:8103:demo，two:pass|three',
             ('2001:db8::a', 8103, 'demo，two', 'pass|three')),
            ('wide-colon.invalid：8104：demo,one：one:two：2030-01-01',
             ('wide-colon.invalid', 8104, 'demo,one', 'one:two')),
            (r'pipe.invalid|8105|realm\demo|word，----：end|',
             ('pipe.invalid', 8105, r'realm\demo', 'word，----：end')),
            ('wide-pipe.invalid｜8106｜', ('wide-pipe.invalid', 8106, '', '')),
            ('dash.invalid----8107----dash:demo----dash,pass----2030-01-01',
             ('dash.invalid', 8107, 'dash:demo', 'dash,pass')),
            ('tab.invalid\t8108\ttab：demo\tword|end\t2030-01-01\t',
             ('tab.invalid', 8108, 'tab：demo', 'word|end')),
            ('semicolon.invalid;8109;semi:demo;word，end;', ('semicolon.invalid', 8109, 'semi:demo', 'word，end')),
            ('wide-semi.invalid；8110', ('wide-semi.invalid', 8110, '', '')),
            ('enumeration.invalid、8111、demo、pass、2030-01-01', ('enumeration.invalid', 8111, 'demo', 'pass')),
            ('first-pair.invalid:|8112:|demo:|pass', ('first-pair.invalid', 8112, 'demo', 'pass')),
            ('second-pair.invalid|:8113|:demo|:pass', ('second-pair.invalid', 8113, 'demo', 'pass')),
            ('[2001:db8::b]:8114|demo|pass', ('2001:db8::b', 8114, 'demo', 'pass')),
            ('space.invalid 8115 user.one pass:two', ('space.invalid', 8115, 'user.one', 'pass:two')),
        )
        ids = self.add_profiles(len(examples))
        document = '\r\n'.join(row for row, _ in examples)
        self.assertEqual(dispatch(self.service, 'bulk_proxy_count', {'text': document}),
                         {'ok': True, 'data': {'count': len(ids)}})
        self.assertEqual(self.import_proxies(ids[::-1], document, 'http'),
                         {'ok': True, 'data': {'updated': len(ids)}})
        fresh = MemoryWindowStore(self.uri)
        for identity, (_, fields) in zip(ids, examples):
            self.assertEqual(proxy_fields(fresh.get(identity)['proxy']), ('http', *fields))

    def test_malformed_row_in_mixed_document_rejects_every_update(self):
        ids = self.add_profiles(3)
        for row in ('invalid.example，70000，fixture，pass', 'missing.invalid----2030----one',
                    'mismatch.invalid,9030|fixture|pass', 'ambiguous.invalid:8000:user:demo:word',
                    'bad-date.invalid|8000|user|demo|2030-02-30'):
            with self.subTest(format=row.split('.')[0]):
                self.assert_rejected(ids, '\n'.join(['first.invalid:8030', row, 'last.invalid\t8032']))

    def test_expiry_formats_and_blank_trailing_fields_preserve_entire_password(self):
        rows = [
            'fixture.invalid|8400|fixture|pass.0|2030-2-3|',
            'fixture.invalid,8401,fixture,pass.1,2030/02/03',
            'fixture.invalid｜8402｜fixture｜pass.2｜2030年2月3日',
            'fixture.invalid:8403:fixture:pass.3:2030-02-03T12:34:56',
            'fixture.invalid：8404：fixture：pass.4：',
        ]
        ids = self.add_profiles(len(rows))
        self.assertEqual(self.import_proxies(ids[::-1], '\n'.join(rows)),
                         {'ok': True, 'data': {'updated': len(ids)}})
        fresh = MemoryWindowStore(self.uri)
        for n, identity in enumerate(ids):
            self.assertEqual(proxy_fields(fresh.get(identity)['proxy']),
                             ('socks5', 'fixture.invalid', 8400+n, 'fixture', f'pass.{n}'))

    def test_invalid_stored_proxy_can_be_replaced_without_modifying_profile_data(self):
        target, other = self.add_profiles(2)
        template = self.store.get(target)
        other_blob = self.ciphertext()[other]
        for missing in (False, True):
            with self.subTest(missing=missing):
                original = copy.deepcopy(template)
                if missing:
                    del original['proxy']
                else:
                    original['proxy'] = {'type': 'http', 'host': 'old.invalid', 'port': 'broken'}
                self.store.put(original)
                response = self.import_proxies([target], 'replacement.invalid|1080|fixture|fixture-password')
                self.assertEqual(response, {'ok': True, 'data': {'updated': 1}})
                restored = MemoryWindowStore(self.uri).get(target)
                self.assertEqual(proxy_fields(restored['proxy']),
                                 ('socks5', 'replacement.invalid', 1080, 'fixture', 'fixture-password'))
                expected = copy.deepcopy(original)
                expected['proxy'] = restored['proxy']
                expected['updated_at'] = restored['updated_at']
                del expected['_runtime']['local_proxy_port']
                self.assertEqual(restored, expected)
                self.assertEqual(self.ciphertext()[other], other_blob)

    def test_single_editor_replaces_invalid_stored_proxy_only_after_validation(self):
        target, other = self.add_profiles(2)
        self.enterContext(patch.object(profile_model, 'APP_ROOT', self.service.root))
        self.enterContext(patch.object(profile_model, 'fingerprint_fields', return_value={'canvasValue'}))
        template = {**self.store.get(target), **profile_model.defaults(), 'name': 'Fixture'}
        self.service._runtime = lambda p, previous: copy.deepcopy(previous)
        self.service._status = lambda p: 'closed'
        replacement = {'type': 'http', 'host': 'replacement.invalid', 'port': 8080}
        other_blob = self.ciphertext()[other]
        for missing in (False, True):
            with self.subTest(missing=missing):
                original = copy.deepcopy(template)
                if missing:
                    del original['proxy']
                else:
                    original['proxy'] = {**replacement, 'port': 'broken'}
                self.store.put(original)
                before = self.ciphertext()[target]
                draft = self.store.public(original)
                draft['proxy'] = replacement
                for invalid in ({'proxy': {**replacement, 'port': 0}}, {'fingerprint': {'canvasValue': 123}}):
                    self.assertFalse(dispatch(self.service, 'save', {'profile': {**draft, **invalid}})['ok'])
                    self.assertEqual(self.ciphertext()[target], before)
                self.processes.return_value = [SimpleNamespace(pid=40, info={'cmdline': None},
                    as_dict=lambda attrs: {'name': 'BitBrowser.exe', 'exe': None})]
                blocked = dispatch(self.service, 'save', {'profile': draft})
                self.assertFalse(blocked['ok'])
                self.assertIn('关闭', blocked['error'])
                self.assertEqual(self.ciphertext()[target], before)
                self.processes.return_value = []
                saved = dispatch(self.service, 'save', {'profile': draft})
                self.assertTrue(saved['ok'], saved.get('error'))
                fresh = MemoryWindowStore(self.uri).get(target)
                self.assertEqual(proxy_fields(fresh['proxy']), ('http', 'replacement.invalid', 8080, '', ''))
                self.assertEqual(fresh['fingerprint'], original['fingerprint'])
                self.assertEqual(fresh['_native'], original['_native'])
                self.assertNotIn('local_proxy_port', fresh['_runtime'])
                self.assertEqual(self.ciphertext()[other], other_blob)

    def test_one_selected_window_can_retry_without_rewriting_an_identical_proxy(self):
        ids = self.add_profiles(1)
        text = 'fixture.invalid|22|fixture|fixture-password|2030-01-01'
        expected = {'ok': True, 'data': {'updated': 1}}
        self.assertEqual(self.import_proxies(ids, text, 'ssh'), expected)
        saved = self.ciphertext()
        self.assertEqual(self.import_proxies(ids, text, 'ssh'), expected)
        self.assertEqual(self.ciphertext(), saved)
        proxy = MemoryWindowStore(self.uri).get(ids[0])['proxy']
        self.assertEqual(proxy_fields(proxy), ('ssh', 'fixture.invalid', 22, 'fixture', 'fixture-password'))

    def test_invalid_input_cannot_change_any_window(self):
        ids = self.add_profiles(2)
        row = 'fixture.invalid|1080|fixture|fixture-password'
        for case, targets, text in (
            ('missing row', ids, row),
            ('excess row', ids, '\n'.join([row] * 3)),
            ('invalid last port', ids, row + '\n' + row.replace('1080', '65536')),
            ('ambiguous extra fields', ids, row + '\n' + row + '|date|extra'),
            ('duplicate target', [ids[0], ids[0]], row + '\n' + row),
            ('missing last target', [ids[0], 'missing-window'], row + '\n' + row),
        ):
            with self.subTest(case=case):
                self.assert_rejected(targets, text)

    def test_error_identifies_numeric_assignment_position_for_unordered_input(self):
        ids = self.add_profiles(10)
        second, tenth = ids[1], ids[9]
        record = self.store.get(tenth)
        record['archived'] = True
        self.store.put(record)
        before = self.ciphertext()
        rows = 'first.invalid|1080|fixture|pass\nsecond.invalid|2080|fixture|pass'
        result = self.import_proxies([tenth, second], rows)
        self.assertFalse(result['ok'])
        self.assertIn('第 2 个窗口', result['error'])
        self.assertEqual(before, self.ciphertext())

    def test_running_dynamic_archived_and_deleting_target_block_the_batch(self):
        ids = self.add_profiles(2)
        original = self.store.get(ids[1])
        text = '\n'.join(['fixture.invalid|1080|fixture|fixture-password'] * 2)
        for case in ('running', 'uninspectable', 'dynamic', 'archived', 'pending deletion'):
            with self.subTest(case=case):
                self.processes.return_value = []
                self.pending.return_value = set()
                record = copy.deepcopy(original)
                if case == 'running':
                    path = record['_runtime']['profile_path']
                    self.processes.return_value = [SimpleNamespace(pid=51, info={'cmdline': [
                        'fixture.exe', '--type=renderer', '--user-data-dir=' + path]})]
                elif case == 'uninspectable':
                    process = Mock(pid=51, info={'cmdline': None})
                    process.as_dict.return_value = {'name': 'BitBrowser.exe', 'exe': None}
                    self.processes.return_value = [process]
                elif case == 'dynamic':
                    record.update(created_locally=True, created_options={
                        'dynamic_proxy_url': 'https://provider.invalid/', 'dynamic_proxy_type': 'http'})
                elif case == 'archived':
                    record['archived'] = True
                else:
                    self.pending.return_value = {ids[1]}
                self.store.put(record)
                self.assert_rejected(ids, text)

    def test_late_sqlite_write_failure_rolls_back_prior_rows_and_allows_retry(self):
        ids = self.add_profiles(3)
        text = '\n'.join(['fixture.invalid|1080|fixture|fixture-password'] * 3)
        with self.store.connect() as connection:
            connection.execute("""CREATE TRIGGER fail_last BEFORE UPDATE ON profiles
                                  WHEN NEW.id='fixture-3' BEGIN
                                  SELECT RAISE(ABORT,'synthetic write failure');
                                  END""")
        self.assert_rejected(ids, text)
        with self.store.connect() as connection:
            connection.execute('DROP TRIGGER fail_last')
        self.assertEqual(self.import_proxies(ids, text), {'ok': True, 'data': {'updated': 3}})

    def test_concurrent_edit_in_another_connection_survives_without_partial_import(self):
        ids = self.add_profiles(2)
        untouched = self.ciphertext()[ids[0]]
        other = MemoryWindowStore(self.uri)
        changed = other.get(ids[1])
        changed['remark'] = 'concurrent edit'

        def edit_once(identity):
            if identity == ids[0]:
                other.put(changed)

        self.service.proxy_runtime.stop_if_unused.side_effect = edit_once
        text = '\n'.join(['fixture.invalid|1080|fixture|fixture-password'] * 2)
        self.assertFalse(self.import_proxies(ids, text)['ok'])
        self.assertEqual(other.get(ids[1]), changed)
        self.assertEqual(self.ciphertext()[ids[0]], untouched)

    def test_pending_deletion_after_initial_validation_rolls_back_all_rows(self):
        ids = self.add_profiles(2)
        text = '\n'.join(['fixture.invalid|1080|fixture|fixture-password'] * 2)

        def begin_deletion(identity):
            if identity == ids[1]:
                self.pending.return_value = {identity}

        self.service.proxy_runtime.stop_if_unused.side_effect = begin_deletion
        self.assert_rejected(ids, text)
        self.assertEqual(self.pending.return_value, {ids[1]})

    def test_failed_cache_refresh_does_not_hide_commit_or_skip_other_windows(self):
        ids = self.add_profiles(3)
        text = '\n'.join(f'node-{n}.invalid|1080|fixture|fixture-password' for n in range(3))
        other = MemoryWindowStore(self.uri)
        controller = self.service.controller
        original_runtime = copy.deepcopy(controller.profiles[ids[0]])
        set_profile = controller.set_profile
        visible_at_failure = []

        def refresh(identity, runtime):
            if identity == ids[0]:
                visible_at_failure.extend(record['proxy']['host'] for record in other.all())
                raise RuntimeError('synthetic cache refresh failure')
            set_profile(identity, runtime)

        with patch.object(controller, 'set_profile', side_effect=refresh):
            self.assertEqual(self.import_proxies(ids, text), {'ok': True, 'data': {'updated': 3}})
        self.assertEqual(visible_at_failure, [f'node-{n}.invalid' for n in range(3)])
        self.assertEqual(controller.profiles[ids[0]], original_runtime)
        for identity in ids:
            runtime = other.get(identity)['_runtime']
            self.assertNotIn('local_proxy_port', runtime)
            if identity != ids[0]:
                self.assertEqual(controller.profiles[identity], runtime)


if __name__ == '__main__':
    unittest.main()
