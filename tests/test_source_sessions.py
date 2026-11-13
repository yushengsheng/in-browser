"""Synthetic source tab/session fixtures; no real profile or browser access."""
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

import source_sessions as tabs
import session_recovery as native
from local_state import LocalBrowserError
from batch_operations import Operations
from manager_service import ManagerService


def command(identity, payload=b''):
    return struct.pack('<H', len(payload) + 1) + bytes([identity]) + payload


def pickle_text(value, encoding='utf-8'):
    raw = value.encode(encoding)
    length = len(raw) // 2 if encoding == 'utf-16-le' else len(raw)
    return struct.pack('<i', length) + raw + b'\0' * (-len(raw) % 4)


def navigation(url='https://synthetic.invalid/path%2Ckeep', *, tab=2, index=0):
    payload = (struct.pack('<ii', tab, index) + pickle_text(url) + pickle_text('合成标题', 'utf-16-le')
               + pickle_text('synthetic-page-state') + struct.pack('<i', 0))
    return command(6, struct.pack('<I', len(payload)) + payload)


def session(*extra, version=3, binding=True, marker=True):
    return (b'SNSS' + struct.pack('<I', version)
            + (command(0, struct.pack('<ii', 1, 2)) if binding else b'')
            + navigation() + (command(255) if marker else b'') + b''.join(extra))


class SourceSessionsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='source-sessions-fixture-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.profile = self.root / 'profile'
        self.default = self.profile / 'Default'
        self.default.mkdir(parents=True)
        self.tabfile = self.default / '~TabGroups'
        self.sessions = self.default / 'Sessions'
        self.sessions.mkdir()
        self.session = self.sessions / 'Session_123'

    def write_tabs(self, roots, version=1):
        self.tabfile.write_text(json.dumps({'roots': roots, 'version': version}), encoding='utf-8')

    @staticmethod
    def url(value):
        return {'type': 'url', 'name': 'synthetic', 'url': value}

    def snapshot(self):
        return {str(path.relative_to(self.profile)): path.read_bytes()
                for path in self.profile.rglob('*') if path.is_file()}

    def test_flat_nested_urls_preserve_encoding_order_and_exact_deduplication(self):
        encoded = 'https://synthetic.invalid/a%2Cb?next=%2Fdashboard%3Fx%3D1#part%2Ftwo'
        self.write_tabs([self.url(encoded), {'type': 'folder', 'name': 'group', 'children': [
            self.url('https://synthetic.invalid/a'), {'type': 'folder', 'children': [self.url(encoded),
            self.url('https://synthetic.invalid/a/')]}]}, self.url('chrome://history/')])
        before = self.snapshot()
        self.assertEqual(tabs.collect_source_tabs(self.profile, ['https://fallback.invalid/']),
                         [encoded, 'https://synthetic.invalid/a', 'https://synthetic.invalid/a/', 'chrome://history/'])
        self.assertEqual(self.snapshot(), before)

    def test_missing_or_empty_tabgroups_use_bounded_safe_fallback(self):
        fallback = ['https://fallback.invalid/path%2Ckeep', 'about:blank', 'https://fallback.invalid/path%2Ckeep']
        self.assertEqual(tabs.collect_source_tabs(self.profile, fallback), fallback[:2])
        self.write_tabs([])
        self.assertEqual(tabs.collect_source_tabs(self.profile, fallback), fallback[:2])
        self.assertEqual(tabs.collect_source_tabs(self.profile), [])

    def test_native_session_has_priority_and_does_not_read_stale_cloud_tabs(self):
        self.session.write_bytes(session())
        self.tabfile.write_bytes(b'not valid JSON')
        before = self.snapshot()
        self.assertEqual(tabs.collect_source_tabs(self.profile, ['javascript:dangerous()']), [])
        self.assertTrue(native.has_saved_session(self.profile))
        self.assertEqual(self.snapshot(), before)

    def test_empty_shell_and_corrupt_native_file_use_tabgroups(self):
        self.write_tabs([self.url('https://restored.invalid/one'), self.url('https://restored.invalid/two')])
        for content in (b'SNSS' + struct.pack('<I', 3), b'SNSS' + struct.pack('<I', 3) + command(255),
                        b'SNSS' + struct.pack('<I', 3) + command(6, b'x') + command(255),
                        session(binding=False), session(marker=False)):
            with self.subTest(size=len(content)):
                self.session.write_bytes(content)
                before = self.snapshot()
                self.assertEqual(tabs.collect_source_tabs(self.profile),
                                 ['https://restored.invalid/one', 'https://restored.invalid/two'])
                self.assertEqual(self.snapshot(), before)

    def test_final_tab_or_window_closed_and_all_navigation_pruned_are_not_restorable(self):
        for ending in (command(16, struct.pack('<i4xq', 2, 0)), command(17, struct.pack('<i4xq', 1, 0)),
                       command(5, struct.pack('<ii', 2, 0)), command(11, struct.pack('<ii', 2, 1)),
                       command(24, struct.pack('<iii', 2, 0, 1))):
            with self.subTest(command=ending[2]):
                self.session.write_bytes(session(ending))
                self.assertFalse(native.has_saved_session(self.profile))

    def test_valid_v1_and_v3_native_and_remaining_tab_navigation_are_retained(self):
        for content in (session(version=1, marker=False), session(),
                        session(navigation(index=1), command(24, struct.pack('<iii', 2, 0, 1))),
                        session(command(0, struct.pack('<ii', 1, 3)), navigation(tab=3), command(16, struct.pack('<i4xq', 2, 0)))):
            self.session.write_bytes(content)
            self.assertTrue(native.has_saved_session(self.profile))
        self.session.rename(self.sessions / 'Tabs_123')
        self.assertFalse(native.has_saved_session(self.profile))

    def test_newest_initialized_file_controls_fallback_even_when_all_tabs_closed(self):
        older=self.sessions/'Session_9';newer=self.sessions/'Session_10'
        older.write_bytes(session())
        expected=['https://current.invalid/one','https://current.invalid/two']
        self.write_tabs([self.url(value) for value in expected])
        closed=session(command(16,struct.pack('<i4xq',2,0)))
        for content in (closed,b'SNSS'+struct.pack('<I',3)+command(255),
                        closed+b'\x10\x00\x06partial',
                        b'SNSS'+struct.pack('<I',3)+command(6,b'x')+command(255),b'bad-header'):
            with self.subTest(size=len(content)):
                newer.write_bytes(content)
                before=self.snapshot()
                self.assertTrue(native._usable(older))
                self.assertFalse(native.has_saved_session(self.profile))
                self.assertEqual(tabs.collect_source_tabs(self.profile),expected)
                self.assertEqual(self.snapshot(),before)

    def test_unfinished_new_initial_state_falls_back_to_older_initialized_file(self):
        older=self.sessions/'Session_9';newer=self.sessions/'Session_10'
        older.write_bytes(session())
        for content in (b'SNSS'+struct.pack('<I',3),session(marker=False),
                        session(marker=False)+b'\x10\x00\x06partial'):
            with self.subTest(size=len(content)):
                newer.write_bytes(content)
                self.assertTrue(native.has_saved_session(self.profile))
                self.assertEqual(tabs.collect_source_tabs(self.profile),[])

    def test_initialized_session_keeps_valid_prefix_after_truncated_or_bad_command(self):
        for ending in (b'\x10',b'\x10\x00\x06partial',b'\x00\x00',command(6,b'x'),
                       command(16,struct.pack('<i',2)),command(200)):
            with self.subTest(size=len(ending)):
                self.session.write_bytes(session()+ending)
                self.assertTrue(native.has_saved_session(self.profile))
                self.assertEqual(tabs.collect_source_tabs(self.profile),[])

    def test_session_timestamp_order_is_numeric_and_independent_of_mtime(self):
        old=self.sessions/'Session_9';new=self.sessions/'Session_10'
        old.write_bytes(session(command(16,struct.pack('<i4xq',2,0))))
        new.write_bytes(session())
        os.utime(old,(2000,2000));os.utime(new,(1000,1000))
        self.assertTrue(native.has_saved_session(self.profile))
        (self.sessions/'Session_9223372036854775808').write_bytes(b'outside-int64')
        self.assertTrue(native.has_saved_session(self.profile))

    def test_malformed_structure_and_unsafe_urls_are_rejected_without_partial_tabs(self):
        bad_nodes = [None, {'type': 'unknown', 'url': 'https://synthetic.invalid/'},
                     {'type': 'folder', 'children': {}}, {'type': 'url', 'url': 1},
                     self.url('javascript:dangerous()'), self.url('data:text/html,synthetic'),
                     self.url('file:///synthetic.html'), self.url('chrome://quit/'),
                     self.url('https://synthetic.invalid\\@other.invalid/'), self.url('https://synthetic.invalid/\nother'),
                     self.url('https:///missing-host'), self.url('https://synthetic.invalid:99999/')]
        for bad in bad_nodes:
            with self.subTest(kind=type(bad).__name__):
                self.write_tabs([self.url('https://good.invalid/'), bad])
                before = self.snapshot()
                with self.assertRaises(LocalBrowserError):
                    tabs.collect_source_tabs(self.profile)
                self.assertEqual(self.snapshot(), before)
        for raw in (b'{}', b'{"roots":[],"version":true}', b'{"roots":[],"version":1,"roots":[]}', b'not JSON'):
            self.tabfile.write_bytes(raw)
            with self.assertRaises(LocalBrowserError):
                tabs.collect_source_tabs(self.profile)

    def test_json_size_depth_node_tab_and_url_limits_fail_explicitly(self):
        with patch.object(tabs, 'MAX_TAB_BYTES', 4):
            self.write_tabs([])
            with self.assertRaises(LocalBrowserError):tabs.collect_source_tabs(self.profile)
        deep = self.url('https://synthetic.invalid/')
        for _ in range(tabs.MAX_DEPTH):
            deep = {'type': 'folder', 'children': [deep]}
        self.write_tabs([deep])
        with self.assertRaises(LocalBrowserError):tabs.collect_source_tabs(self.profile)
        for setting, limit in (('MAX_NODES', 1), ('MAX_TABS', 1), ('MAX_URL_LENGTH', 4)):
            self.write_tabs([self.url('https://one.invalid/'), self.url('https://two.invalid/')])
            with patch.object(tabs, setting, limit), self.assertRaises(LocalBrowserError):
                tabs.collect_source_tabs(self.profile)
        self.tabfile.unlink()
        with patch.object(tabs, 'MAX_TABS', 1), self.assertRaises(LocalBrowserError):
            tabs.collect_source_tabs(self.profile, ['https://one.invalid/', 'https://two.invalid/'])

    def test_native_size_file_and_command_limits_are_bounded(self):
        self.session.write_bytes(session())
        for setting, limit in (('MAX_SESSION_BYTES', 8), ('MAX_SESSION_TOTAL', 8), ('MAX_SESSION_FILES', 0), ('MAX_SESSION_COMMANDS', 1)):
            with patch.object(native, setting, limit), self.assertRaises(LocalBrowserError):
                native.has_saved_session(self.profile)

    def test_controller_only_suppresses_startup_urls_for_real_saved_navigation(self):
        import browser_core as core
        executable = self.root / 'BitBrowser.exe'
        executable.write_bytes(b'synthetic-core')
        fingerprint = self.root / 'fingerprint.bin'
        fingerprint.write_bytes(b'synthetic-signature')
        startup = 'https://startup.invalid/a%2Cb'
        for valid in (True, False):
            with self.subTest(native=valid):
                self.session.write_bytes(session() if valid else b'SNSS' + struct.pack('<I', 3) + command(255))
                runtime = {'alias': 'synthetic', 'profile_path': str(self.profile), 'new_profile': True,
                           'core_path': str(executable), 'core_sha256': core.sha256(executable), 'core_major': '148',
                           'fingerprint_path': str(fingerprint), 'fingerprint_sha256': core.sha256(fingerprint),
                           'launch_args': [], 'restore_session': True, 'initial_urls': [startup]}
                controller = core.BrowserController(self.root, settings={'windows': [runtime], 'persistent': False})
                controller._save = Mock()
                with patch.object(controller, '_ensure_record', return_value=False), \
                        patch.object(controller, 'endpoint', return_value='synthetic-endpoint'), \
                        patch.object(core, '_profile_browsers', return_value=[]), \
                        patch.object(core, '_visible_windows', return_value=[1]), \
                        patch('signature_lifetime.require_current_signature'), \
                        patch.object(core.subprocess, 'Popen', return_value=Mock(pid=12345)) as popen, \
                        patch.object(core.psutil, 'Process', return_value=SimpleNamespace(create_time=lambda: 100)):
                    controller.open('synthetic')
                arguments = popen.call_args.args[0]
                self.assertEqual(startup in arguments, not valid)
                self.assertIn('--restore-last-session', arguments)

    def test_replaced_tab_snapshot_is_rejected_instead_of_using_mixed_contents(self):
        self.write_tabs([self.url('https://synthetic.invalid/')])
        original = Path.open
        class ChangedReader:
            def __enter__(owner):
                owner.stream = original(self.tabfile, 'rb')
                return owner
            def fileno(owner):return owner.stream.fileno()
            def read(owner, size):
                raw = owner.stream.read(size)
                owner.stream.close()
                self.tabfile.write_bytes(raw + b' ')
                return raw
            def __exit__(owner, *_):owner.stream.close()
        def opening(path, *args, **kwargs):
            return ChangedReader() if path == self.tabfile and args == ('rb',) else original(path, *args, **kwargs)
        with patch.object(Path, 'open', opening), self.assertRaises(LocalBrowserError):
            tabs.collect_source_tabs(self.profile)

    def test_real_directory_junction_or_link_is_rejected_and_removed(self):
        external = self.root / 'external'
        external.mkdir()
        (external / '~TabGroups').write_text(json.dumps({'version': 1, 'roots': [self.url('https://external.invalid/')]}))
        self.sessions.rmdir()
        self.default.rmdir()
        try:
            if os.name == 'nt':
                import _winapi
                _winapi.CreateJunction(str(external), str(self.default))
            else:
                self.default.symlink_to(external, target_is_directory=True)
        except (OSError, AttributeError):
            self.skipTest('Synthetic directory links unavailable')
        try:
            with self.assertRaises(LocalBrowserError):tabs.collect_source_tabs(self.profile)
            with self.assertRaises(LocalBrowserError):native.has_saved_session(self.profile)
            self.assertTrue((external / '~TabGroups').is_file())
        finally:
            if os.name == 'nt':self.default.rmdir()
            else:self.default.unlink()


class SourceSessionManagerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='source-session-manager-fixture-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.profile = self.root / 'profile'
        (self.profile / 'Default/Sessions').mkdir(parents=True)
        self.urls = ['https://restored.invalid/a%2Cb?return=%2Fhome', 'https://restored.invalid/second']
        startup = ['https://configured.invalid/start']
        self.current = {'id': 'synthetic', 'proxy': {'type': 'noproxy'}, '_cookie_pending': False, 'urls': startup,
                        '_source_session_restore': {'format': 1, 'pending': True, 'urls': list(self.urls)},
                        '_runtime': {'alias': 'synthetic', 'profile_path': str(self.profile),
                                     'fingerprint_path': 'synthetic-signature', 'core_major': '148',
                                     'new_profile': False, 'has_launched': True, 'initial_urls': startup}}
        service = self.service = ManagerService.__new__(ManagerService)
        service.root = self.root
        service.operations = Operations()
        service._require_available = Mock()
        service._status = Mock(return_value='closed')
        service._runtime = lambda record, previous: copy.deepcopy(previous)
        service._preferences = service._sync = Mock()
        service.configuration = SimpleNamespace(independent=False)
        service.proxy_runtime = SimpleNamespace(ensure=Mock(return_value=None), stop_if_unused=Mock())
        service.controller = Mock()
        service.controller.open.side_effect = lambda *args, **kwargs: kwargs['before_launch']()
        def commit(record):
            self.current = copy.deepcopy(record)
        service.store = SimpleNamespace(get=lambda identity: copy.deepcopy(self.current), put=Mock(side_effect=commit),
                                        public=lambda record, status='closed': {'id': record['id'], 'status': status})
        stack = self.stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch('manager_service.require_current_signature'))
        stack.enter_context(patch('manager_service.profile_processes', return_value=[]))
        stack.enter_context(patch('import_cookies.prepare_existing', side_effect=lambda owner, record: record))
        self.cdp = stack.enter_context(patch('manager_service.CDP'))
        self.show_ip = stack.enter_context(patch('ip_info_page.show_ip_info'))

    def test_first_success_consumes_request_without_overwriting_startup_and_never_replays(self):
        self.service.open('synthetic')
        self.assertEqual(self.service.controller.open.call_args.kwargs['extra_urls'], self.urls)
        self.assertFalse(self.current['_source_session_restore']['pending'])
        self.assertEqual(self.current['_source_session_restore']['urls'], self.urls)
        self.assertEqual(self.current['urls'], ['https://configured.invalid/start'])
        self.assertEqual(self.current['_runtime']['initial_urls'], ['https://configured.invalid/start'])
        self.service.open('synthetic')
        self.assertIsNone(self.service.controller.open.call_args.kwargs['extra_urls'])
        self.assertFalse(self.current['_source_session_restore']['pending'])

    def test_launch_failure_preserves_pending_and_retry_applies_the_same_encoded_urls(self):
        self.service.controller.open.side_effect = LocalBrowserError('synthetic launch refusal')
        with self.assertRaises(LocalBrowserError):self.service.open('synthetic')
        self.assertTrue(self.current['_source_session_restore']['pending'])
        self.service.store.put.assert_not_called()
        self.service.controller.open.side_effect = lambda *args, **kwargs: kwargs['before_launch']()
        self.service.open('synthetic')
        self.assertEqual(self.service.controller.open.call_args.kwargs['extra_urls'], self.urls)
        self.assertFalse(self.current['_source_session_restore']['pending'])

    def test_catalog_commit_failure_keeps_authoritative_pending_and_closes_normally(self):
        self.service.store.put.side_effect = OSError('synthetic commit failure')
        with self.assertRaises(OSError):self.service.open('synthetic')
        self.assertTrue(self.current['_source_session_restore']['pending'])
        self.service.controller.close.assert_called_once_with('synthetic')

    def test_cookie_application_failure_keeps_pending_and_closes_normally(self):
        self.current.update(_cookie_pending=True, cookie_text='[]')
        connection = self.cdp.return_value.__enter__.return_value
        def call(method, *args, **kwargs):
            if method == 'Storage.setCookies':raise LocalBrowserError('synthetic cookie refusal')
            return {'targetInfos': []}
        connection.call.side_effect = call
        with self.assertRaises(LocalBrowserError):self.service.open('synthetic')
        self.assertTrue(self.current['_source_session_restore']['pending'])
        self.service.store.put.assert_not_called()
        self.service.controller.close.assert_called_once_with('synthetic')

    def test_explicit_urls_including_empty_list_do_not_consume_source_request(self):
        for urls in ([], ['https://explicit.invalid/']):
            with self.subTest(empty=not urls):
                self.service.open('synthetic', extra_urls=urls)
                self.assertEqual(self.service.controller.open.call_args.kwargs['extra_urls'], urls)
                self.assertTrue(self.current['_source_session_restore']['pending'])

    def test_already_open_only_activates_and_does_not_consume_or_validate_pending(self):
        self.service._status.return_value = 'open'
        self.service.controller.open.side_effect = None
        self.current['_source_session_restore']['format'] = 0
        self.service.open('synthetic')
        self.assertIsNone(self.service.controller.open.call_args.kwargs['extra_urls'])
        self.assertTrue(self.current['_source_session_restore']['pending'])
        self.assertEqual(self.current['_source_session_restore']['format'], 0)

    def test_already_open_instance_exiting_does_not_relaunch_or_consume_pending(self):
        self.service._status.return_value = 'open'
        with self.assertRaises(LocalBrowserError):self.service.open('synthetic')
        self.assertTrue(self.current['_source_session_restore']['pending'])
        self.service.store.put.assert_not_called()

    def test_native_session_created_after_import_has_priority_over_stale_source_urls(self):
        (self.profile / 'Default/Sessions/Session_123').write_bytes(session())
        self.service.open('synthetic')
        self.assertIsNone(self.service.controller.open.call_args.kwargs['extra_urls'])
        self.assertFalse(self.current['_source_session_restore']['pending'])

    def test_post_commit_ip_page_error_keeps_consumed_marker_and_open_browser(self):
        self.show_ip.side_effect = LocalBrowserError('synthetic information page refusal')
        with self.assertRaises(LocalBrowserError):self.service.open('synthetic')
        self.assertFalse(self.current['_source_session_restore']['pending'])
        self.service.controller.close.assert_not_called()

    def test_invalid_pending_request_refuses_before_launch_or_store_changes(self):
        self.current['_source_session_restore']['urls'] = ['javascript:synthetic()']
        with self.assertRaises(LocalBrowserError):self.service.open('synthetic')
        self.assertTrue(self.current['_source_session_restore']['pending'])
        self.service.controller.open.assert_not_called()
        self.service.store.put.assert_not_called()


class NativeTabGroupRestoreTests(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory(prefix='native-tab-groups-fixture-')
        self.addCleanup(directory.cleanup)
        self.root=Path(directory.name)
        self.profile=self.root/'profile'
        (self.profile/'Default/Sessions').mkdir(parents=True)
        (self.profile/'Local State').write_text('{}')
        self.tabfile=self.profile/'Default/~TabGroups'
        self.urls=['https://synthetic.invalid/one','https://synthetic.invalid/two']
        self.data={'version':1,'roots':[
            {'type':'folder','name':'First','color':'blue','isCollapsed':True,
             'children':[{'type':'url','url':self.urls[0]},{'type':'url','url':self.urls[0]}]},
            {'type':'folder','name':'Second','color':'red','isCollapsed':False,
             'children':[{'type':'url','url':self.urls[1]}]},
            {'type':'url','url':self.urls[0]}]}
        self.write()
        self.runtime={'signature_provider':'local-v1','core_major':'148'}

    def write(self):
        self.tabfile.write_text(json.dumps(self.data),encoding='utf-8')

    def marker(self):
        return tabs.collect_source_restore(self.profile,self.runtime,self.urls,startup_urls=self.urls)

    def test_exact_supported_plan_preserves_groups_duplicates_and_snapshot_bytes(self):
        before=self.tabfile.read_bytes()
        marker=self.marker()
        self.assertEqual(marker['mode'],'tab-group-store')
        self.assertEqual(marker['urls'],self.urls)
        self.assertEqual(len(marker['snapshot_sha256']),64)
        self.assertEqual(self.tabfile.read_bytes(),before)
        tabs.verify_tab_group_restore(self.profile,self.runtime,marker)

    def test_other_cores_and_unsigned_or_changed_spec_keep_legacy_url_path(self):
        for runtime in ({'signature_provider':'local-v1','core_major':'124'},
                        {'signature_provider':'vendor','core_major':'148'}):
            self.assertNotIn('mode',tabs.collect_source_restore(self.profile,runtime,self.urls,startup_urls=self.urls))
        from core_specs import CORE_SPECS
        with patch.dict(CORE_SPECS,{'148':{'sha256':'0'*64}}):
            self.assertNotIn('mode',self.marker())

    def test_grouped_or_duplicate_mismatched_snapshot_refuses_but_plain_urls_keep_compatibility(self):
        with self.assertRaises(LocalBrowserError):
            tabs.collect_source_restore(self.profile,self.runtime,self.urls,startup_urls=[self.urls[0]])
        self.data['roots']=[{'type':'url','url':self.urls[0]}]*2
        self.write()
        with self.assertRaises(LocalBrowserError):
            tabs.collect_source_restore(self.profile,self.runtime,self.urls,startup_urls=[self.urls[1]])
        self.data['roots']=[{'type':'url','url':self.urls[0]}]
        self.write()
        marker=tabs.collect_source_restore(self.profile,self.runtime,self.urls,startup_urls=[self.urls[1]])
        self.assertNotIn('mode',marker)
        self.assertEqual(marker['urls'],[self.urls[1]])

    def test_plain_stale_snapshot_uses_known_current_urls_or_no_source_request(self):
        self.data['roots']=[{'type':'url','url':'https://stale.invalid/one'},
                            {'type':'url','url':'https://stale.invalid/two'}]
        self.write();before=self.tabfile.read_bytes()
        marker=tabs.collect_source_restore(self.profile,self.runtime,startup_urls=[self.urls[0]])
        self.assertEqual(marker['urls'],[self.urls[0]])
        self.assertNotIn('mode',marker)
        self.assertIsNone(tabs.collect_source_restore(self.profile,self.runtime,startup_urls=[]))
        unknown=tabs.collect_source_restore(self.profile,self.runtime,startup_urls=None)
        self.assertEqual(unknown['urls'],['https://stale.invalid/one','https://stale.invalid/two'])
        self.assertEqual(self.tabfile.read_bytes(),before)

    def test_vendor_startup_decoding_slash_preference_and_platform_selection(self):
        record={'_source_info':{'url':'https%3A%2F%2Fsynthetic.invalid%2Fa%2Cb,https%3A%2F%2Fother.invalid,https%3A%2F%2Fother.invalid%2F',
                                'platform':'https://platform.invalid/'}}
        self.assertEqual(tabs.source_startup_urls(record),['https://platform.invalid','https://synthetic.invalid/a,b','https://other.invalid/'])
        record['_source_detail']={'url':'https://platform.invalid/child'}
        self.assertEqual(tabs.source_startup_urls(record),['https://platform.invalid/child'])
        record['_source_detail']['workbench']='localserver'
        self.assertEqual(tabs.source_startup_urls(record),['https://platform.invalid/child'])
        for field,value in (('rpaRun',True),('robotUrls',['https://robot.invalid/'])):
            with self.subTest(field=field):
                record['_source_detail'][field]=value
                self.assertIsNone(tabs.source_startup_urls(record))
                del record['_source_detail'][field]

    def test_default_workbench_preserves_matching_users_but_never_drops_extra_console_node(self):
        record={'_source_info':{'workbench':'localserver','url':','.join(self.urls)}}
        before=self.tabfile.read_bytes()
        marker=tabs.collect_source_restore(self.profile,self.runtime,source_record=record)
        self.assertEqual(marker['mode'],'tab-group-store')
        self.assertEqual(self.tabfile.read_bytes(),before)
        self.data['roots'].append({'type':'url','url':'https://console.bitbrowser.net/?synthetic=1'})
        self.write();before=self.tabfile.read_bytes()
        with self.assertRaises(LocalBrowserError):
            tabs.collect_source_restore(self.profile,self.runtime,source_record=record)
        self.assertEqual(self.tabfile.read_bytes(),before)

    def test_native_session_and_missing_or_empty_snapshot_keep_existing_paths(self):
        self.tabfile.unlink()
        self.assertNotIn('mode',tabs.collect_source_restore(self.profile,self.runtime,self.urls,startup_urls=self.urls))
        self.data['roots']=[];self.write()
        self.assertNotIn('mode',tabs.collect_source_restore(self.profile,self.runtime,self.urls,startup_urls=self.urls))
        (self.profile/'Default/Sessions/Session_123').write_bytes(session())
        self.tabfile.write_bytes(b'invalid')
        self.assertIsNone(self.marker())
        for raw in ({'url':'javascript:synthetic()'},{'url':'javascript:synthetic()','workbench':'localserver'}):
            self.assertIsNone(tabs.collect_source_restore(self.profile,self.runtime,source_record={'_source_info':raw}))

    def test_legacy_and_plain_snapshot_do_not_gain_new_startup_rejections(self):
        record={'_source_info':{'url':'javascript:synthetic()'}}
        old={'signature_provider':'local-v1','core_major':'124'}
        self.assertNotIn('mode',tabs.collect_source_restore(self.profile,old,source_record=record))
        self.data['roots']=[{'type':'url','url':self.urls[0]}];self.write()
        self.assertNotIn('mode',tabs.collect_source_restore(self.profile,self.runtime,source_record=record))

    def test_unknown_native_version_nested_groups_and_unsafe_urls_refuse(self):
        original=copy.deepcopy(self.data)
        for mutation in ('version','nested','url'):
            self.data=copy.deepcopy(original)
            if mutation=='version':self.data['version']=2
            elif mutation=='nested':self.data['roots'][0]['children']=[self.data['roots'][1]]
            else:self.data['roots'][0]['children'][0]['url']='javascript:synthetic()'
            self.write()
            with self.subTest(mutation=mutation),self.assertRaises(LocalBrowserError):self.marker()

    def test_changed_snapshot_and_malformed_pending_refuse_without_rewrite(self):
        marker=self.marker()
        self.data['roots'][0]['name']='Changed'
        self.write();before=self.tabfile.read_bytes()
        with self.assertRaises(LocalBrowserError):tabs.verify_tab_group_restore(self.profile,self.runtime,marker)
        self.assertEqual(self.tabfile.read_bytes(),before)
        for field,value in (('format',2),('mode','unknown'),('snapshot_sha256','invalid')):
            with self.subTest(field=field),self.assertRaises(LocalBrowserError):
                tabs.pending_source_restore({'_source_session_restore':{**marker,field:value}})

    def controller(self,stack):
        import browser_core as core
        executable=self.root/'BitBrowser.exe';executable.write_bytes(b'synthetic-core')
        fingerprint=self.root/'fingerprint.bin';fingerprint.write_bytes(b'synthetic-signature')
        runtime={**self.runtime,'alias':'synthetic','profile_path':str(self.profile),'new_profile':False,
                 'core_path':str(executable),'core_sha256':core.sha256(executable),'signature_key_id':'a'*64,
                 'fingerprint_path':str(fingerprint),'fingerprint_sha256':core.sha256(fingerprint),
                 'restore_session':True,'initial_urls':['https://configured.invalid/'],
                 'open_urls_once':['https://once.invalid/'],'launch_args':[]}
        controller=core.BrowserController(self.root,settings={'windows':[runtime],'persistent':False})
        controller._save=Mock()
        stack.enter_context(patch.object(controller,'_ensure_record',return_value=False))
        stack.enter_context(patch.object(controller,'endpoint',return_value='synthetic-endpoint'))
        stack.enter_context(patch.object(core,'_profile_browsers',return_value=[]))
        stack.enter_context(patch.object(core,'_visible_windows',return_value=[1]))
        stack.enter_context(patch('signature_lifetime.require_current_signature'))
        stack.enter_context(patch.object(core.psutil,'Process',return_value=SimpleNamespace(create_time=lambda:100)))
        self.engine_check=Mock()
        stack.enter_context(patch('local_engine.LocalEngineStore',return_value=SimpleNamespace(validate=self.engine_check)))
        popen=stack.enter_context(patch.object(core.subprocess,'Popen',return_value=Mock(pid=12345)))
        return controller,popen

    def test_controller_uses_only_native_group_switch_and_no_flat_urls(self):
        with ExitStack() as stack:
            controller,popen=self.controller(stack)
            controller.open('synthetic',tab_group_restore=self.marker())
            arguments=popen.call_args.args[0]
            self.assertEqual(arguments.count('--x-enable-tab-group-store'),1)
            self.assertNotIn('--restore-last-session',arguments)
            self.assertFalse(any(argument.startswith('https://') for argument in arguments))
            self.engine_check.assert_called_once()

    def test_conflicting_args_blank_probe_and_explicit_urls_never_start(self):
        for arguments in (['--restore-last-session'],['--x-enable-tab-group-store=1']):
            with self.subTest(arguments=arguments),ExitStack() as stack:
                controller,popen=self.controller(stack)
                controller.profiles['synthetic']['launch_args']=arguments
                with self.assertRaises(LocalBrowserError):controller.open('synthetic',tab_group_restore=self.marker())
                popen.assert_not_called()
        for options in ({'bootstrap_blank':True},{'background_probe':True},{'extra_urls':[]}):
            with self.subTest(options=options),ExitStack() as stack:
                controller,popen=self.controller(stack)
                with self.assertRaises(LocalBrowserError):controller.open('synthetic',tab_group_restore=self.marker(),**options)
                popen.assert_not_called()

    def test_snapshot_or_native_session_changed_by_prelaunch_check_never_starts(self):
        for mutation in ('snapshot','session'):
            self.write()
            saved=self.profile/'Default/Sessions/Session_123'
            saved.unlink(missing_ok=True)
            marker=self.marker()
            def mutate():
                if mutation=='snapshot':self.tabfile.write_bytes(self.tabfile.read_bytes()+b' ')
                else:saved.write_bytes(session())
            with self.subTest(mutation=mutation),ExitStack() as stack:
                controller,popen=self.controller(stack)
                with self.assertRaises(LocalBrowserError):
                    controller.open('synthetic',tab_group_restore=marker,before_launch=mutate)
                popen.assert_not_called()

    def test_full_local_engine_validation_failure_prevents_native_launch(self):
        with ExitStack() as stack:
            controller,popen=self.controller(stack)
            self.engine_check.side_effect=LocalBrowserError('synthetic unverified engine')
            with self.assertRaises(LocalBrowserError):controller.open('synthetic',tab_group_restore=self.marker())
            popen.assert_not_called()


class NativeSourceSessionManagerTests(SourceSessionManagerTests):
    def setUp(self):
        super().setUp()
        self.current['_source_session_restore'].update(mode='tab-group-store',snapshot_sha256='a'*64)

    def test_first_success_consumes_request_without_overwriting_startup_and_never_replays(self):
        self.service.open('synthetic')
        options=self.service.controller.open.call_args.kwargs
        self.assertIsNone(options['extra_urls'])
        self.assertEqual(options['tab_group_restore']['mode'],'tab-group-store')
        self.assertFalse(self.current['_source_session_restore']['pending'])
        self.assertEqual(self.current['urls'],['https://configured.invalid/start'])
        self.service.open('synthetic')
        self.assertNotIn('tab_group_restore',self.service.controller.open.call_args.kwargs)

    def test_launch_failure_preserves_pending_and_retry_applies_the_same_encoded_urls(self):
        self.service.controller.open.side_effect=LocalBrowserError('synthetic launch refusal')
        with self.assertRaises(LocalBrowserError):self.service.open('synthetic')
        self.assertTrue(self.current['_source_session_restore']['pending'])
        self.service.store.put.assert_not_called()
        self.service.controller.open.side_effect=lambda *args,**kwargs:kwargs['before_launch']()
        self.service.open('synthetic')
        self.assertEqual(self.service.controller.open.call_args.kwargs['tab_group_restore']['urls'],self.urls)
        self.assertFalse(self.current['_source_session_restore']['pending'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
