"""Pure temporary-file/controller fixtures; never reads real data or starts a browser."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import fingerprint_continuity as fc
from local_state import LocalBrowserError


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture(root):
    engine = root / 'engine'
    engine.mkdir(parents=True)
    executable = engine / 'BitBrowser.exe'
    executable.write_bytes(b'synthetic executable')
    dll = engine / 'version' / 'chrome.dll'
    dll.parent.mkdir()
    dll.write_bytes(b'synthetic native implementation')
    manifest = {'format': 1, 'core_major': '148', 'executable': executable.name,
                'files': {'BitBrowser.exe': {'size': executable.stat().st_size, 'sha256': digest(executable.read_bytes())},
                          'version/chrome.dll': {'size': dll.stat().st_size, 'sha256': digest(dll.read_bytes())}}}
    (engine / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return {'id': 'synthetic-profile', '_native': {'navigator': {'platform': 'Win32'},
                'DataProtect': {'CipherKey': 'synthetic-value'},
                'FontConfig': {'BasePath': str(root / 'font-assets' / 'filters-only-no-files'), 'Names': ['Arial'], 'Files': []}},
            '_runtime': {'alias': 'synthetic-profile', 'core_path': str(executable),
                'core_sha256': digest(executable.read_bytes()), 'core_major': '148',
                'fingerprint_path': str(root / 'synthetic-config.bin'), 'fingerprint_sha256': 'synthetic',
                'profile_path': str(root / 'account-profile'), 'restore_session': True,
                'initial_urls': ['https://fixture.invalid/'], 'open_urls_once': ['https://fixture.invalid/once'],
                'account_platform': 'https://fixture.invalid/', 'account_username': 'synthetic',
                'account_password': 'synthetic', 'launch_args': [], 'disable_gpu': False}}


def sample():
    values = {key: 'synthetic-stable' for key in fc._REQUIRED}
    values.update({'navigator.userAgent': 'synthetic UA', 'navigator.platform': 'Win32',
                   'navigator.languages': ['en-US', 'en'], 'timezone.name': 'UTC',
                   'context.secure': True, 'uaData.supported': False, 'devices.supported': False,
                   'screen.width': 1280, 'screen.height': 720, 'screen.devicePixelRatio': 1,
                   'webgl1.supported': True, 'webgl2.supported': False, 'audio.supported': True,
                   'fonts.metrics': [['Arial', [1, 2, 3, 4, 5]]],
                   'canvas.geometry': 'sha256:geometry', 'canvas.text': 'sha256:text'})
    return {'values': values, 'unstable': [], 'unavailable': ['uaData']}


def raw_sample():
    result = sample()
    for key in fc._PIXELS & result['values'].keys():
        result['values'][key] = 'base64:' + base64.b64encode(b'synthetic pixels').decode()
    return {'values': result['values'], 'errors': [], 'unavailable': result['unavailable']}


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='continuity-test-')
        self.root = Path(self.temporary.name).resolve()
        self.record = fixture(self.root)
        self.spawn_guard = patch('browser_core.subprocess.Popen', side_effect=AssertionError('Browser spawn forbidden'))
        self.spawn_guard.start()

    def tearDown(self):
        self.spawn_guard.stop()
        self.temporary.cleanup()

    def enroll(self, first=None, second=None):
        with patch.object(fc, 'probe_snapshot', side_effect=[first or sample(), second or sample()]) as probe:
            baseline = fc.create_baseline(self.record, self.root)
        self.assertEqual(probe.call_count, 2)
        self.record['_continuity'] = baseline
        return baseline

    def test_two_fresh_starts_record_stable_fields_only(self):
        first, second = sample(), sample()
        second['values']['canvas.text'] = 'sha256:other'
        first['unstable'] = ['audio.offline']
        baseline = self.enroll(first, second)
        self.assertNotIn('canvas.text', baseline['stable'])
        self.assertEqual(baseline['unstable'], ['audio.offline', 'canvas.text'])
        self.assertEqual(baseline['unavailable'], ['uaData'])
        self.assertNotIn(str(self.root), json.dumps(baseline))
        self.assertNotIn('synthetic-value', json.dumps(baseline))

    def test_matching_environment_does_not_change_baseline_or_record(self):
        self.enroll()
        original = copy.deepcopy(self.record)
        with patch.object(fc, 'probe_snapshot', return_value=sample()) as probe:
            result = fc.verify_continuity(self.record, self.root)
        self.assertTrue(result['passed'])
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(self.record, original)

    def test_difference_is_blocked_and_error_contains_only_field_name(self):
        self.enroll()
        actual = sample()
        actual['values']['navigator.userAgent'] = 'private-actual-value'
        with patch.object(fc, 'probe_snapshot', return_value=actual):
            with self.assertRaises(LocalBrowserError) as failure:
                fc.verify_continuity(self.record, self.root)
        self.assertIn('navigator.userAgent', str(failure.exception))
        self.assertNotIn('private-actual-value', str(failure.exception))
        self.assertNotIn(str(self.root), str(failure.exception))

    def test_previously_stable_now_unstable_is_blocked(self):
        self.enroll()
        actual = sample()
        actual['unstable'] = ['canvas.text']
        with patch.object(fc, 'probe_snapshot', return_value=actual):
            with self.assertRaises(LocalBrowserError):
                fc.verify_continuity(self.record, self.root)

    def test_missing_baseline_never_self_enrolls(self):
        with patch.object(fc, 'probe_snapshot') as probe:
            with self.assertRaises(LocalBrowserError):
                fc.verify_continuity(self.record, self.root)
        probe.assert_not_called()

    def test_binding_difference_blocks_before_probe(self):
        self.enroll()
        self.record['_native']['navigator']['platform'] = 'Other'
        with patch.object(fc, 'probe_snapshot') as probe:
            with self.assertRaises(LocalBrowserError):
                fc.verify_continuity(self.record, self.root)
        probe.assert_not_called()

    def test_resigning_and_proxy_change_do_not_invalidate_semantics(self):
        original = fc.binding_for(self.record, self.root)
        self.record['_runtime']['fingerprint_path'] = str(self.root / 'renewed-synthetic-config.bin')
        self.record['_runtime']['fingerprint_sha256'] = 'renewed-envelope'
        self.record['_runtime']['local_proxy_port'] = 12345
        self.record['proxy'] = {'type': 'noproxy'}
        self.assertEqual(original, fc.binding_for(self.record, self.root))

    def test_unrelated_preferences_do_not_invalidate_but_gpu_does(self):
        original = fc.binding_for(self.record, self.root)
        self.record['_native'].update(MemorySaverModeEnabled=True, maxImageBytes=0, notificationsMode=1)
        self.record['_runtime'].update(mute_audio=True, disable_notifications=True)
        self.assertEqual(original, fc.binding_for(self.record, self.root))
        self.record['_runtime']['disable_gpu'] = True
        self.assertNotEqual(original, fc.binding_for(self.record, self.root))

    def test_move_preserves_managed_font_and_engine_binding(self):
        original = fc.binding_for(self.record, self.root)
        moved = self.root / 'moved'
        moved.mkdir()
        shutil.copytree(self.root / 'engine', moved / 'engine')
        record = copy.deepcopy(self.record)
        record['_runtime']['core_path'] = str(moved / 'engine' / 'BitBrowser.exe')
        record['_native']['FontConfig']['BasePath'] = str(moved / 'font-assets' / 'filters-only-no-files')
        self.assertEqual(original, fc.binding_for(record, moved))

    def test_unmanaged_font_path_and_font_selection_remain_bound(self):
        original = fc.native_digest(self.record['_native'], self.root)
        self.record['_native']['FontConfig']['BasePath'] = str(self.root.parent / 'external-fonts')
        self.assertNotEqual(original, fc.native_digest(self.record['_native'], self.root))
        self.record['_native']['FontConfig']['Files'] = ['not-supported.ttf']
        with self.assertRaises(LocalBrowserError):
            fc.native_digest(self.record['_native'], self.root)

    def test_tampered_dll_is_blocked(self):
        (self.root / 'engine' / 'version' / 'chrome.dll').write_bytes(b'changed')
        with self.assertRaises(LocalBrowserError):
            fc.binding_for(self.record, self.root)

    def test_unknown_arguments_are_rejected_not_silently_removed(self):
        self.record['_runtime']['launch_args'] = ['--app=https://fixture.invalid/']
        with self.assertRaises(LocalBrowserError) as failure:
            fc.binding_for(self.record, self.root)
        self.assertNotIn('fixture.invalid', str(failure.exception))

    def test_sampling_noise_is_excluded_without_rounding(self):
        first, second = sample(), sample()
        second['values']['screen.devicePixelRatio'] = 1.00000000001
        merged = fc._merge_samples(first, second)
        self.assertNotIn('screen.devicePixelRatio', merged['values'])
        self.assertIn('screen.devicePixelRatio', merged['unstable'])

    def test_sample_normalization_hashes_pixels_and_rejects_errors(self):
        result = fc._normalize_sample(raw_sample())
        self.assertTrue(result['values']['canvas.text'].startswith('sha256:'))
        bad = raw_sample()
        bad['errors'] = ['audio.offline']
        with self.assertRaises(LocalBrowserError):
            fc._normalize_sample(bad)

    def test_incomplete_baseline_is_not_accepted(self):
        self.enroll()
        self.record['_continuity']['stable'] = {'screen.width': 1280}
        with patch.object(fc, 'probe_snapshot') as probe:
            with self.assertRaises(LocalBrowserError):
                fc.verify_continuity(self.record, self.root)
        probe.assert_not_called()

    def test_essential_field_noise_cannot_create_partial_success(self):
        first, second = sample(), sample()
        second['values']['screen.width'] += 1
        with patch.object(fc, 'probe_snapshot', side_effect=[first, second]):
            with self.assertRaises(LocalBrowserError):
                fc.create_baseline(self.record, self.root)

    def test_all_raster_noise_cannot_create_partial_success(self):
        first, second = sample(), sample()
        second['values']['canvas.geometry'] = 'other'
        second['values']['canvas.text'] = 'other'
        with patch.object(fc, 'probe_snapshot', side_effect=[first, second]):
            with self.assertRaises(LocalBrowserError):
                fc.create_baseline(self.record, self.root)

    def probe_fakes(self, *, live=False, evaluate_error=False, insecure_sample=False):
        observed = {}
        class Controller:
            def __init__(inner, root, settings):
                observed['temporary_root'] = Path(root)
                observed['settings'] = copy.deepcopy(settings)
                inner.root = Path(root)
                inner.profiles = {item['alias']: item for item in settings['windows']}
            def open(inner, alias, **kwargs):
                observed['signature_root'] = inner.root
                observed['open'] = kwargs
            def endpoint(inner, alias):
                return 'synthetic-endpoint'
            def close(inner, alias):
                observed['closed'] = True
        class Connection:
            def __init__(inner, *args, **kwargs):
                inner.timeout = kwargs.get('timeout', 5)
            def __enter__(inner):
                return inner
            def __exit__(inner, *args):
                pass
            def call(inner, method, params=None, session=None):
                if method == 'Target.getTargets':
                    return {'targetInfos': [{'targetId': 'synthetic', 'type': 'page', 'url': 'about:blank'}]}
                if method == 'Target.attachToTarget':
                    return {'sessionId': 'synthetic-session'}
                if method == 'Runtime.evaluate':
                    if evaluate_error:
                        raise ValueError('private internal error')
                    if params['expression'] == fc._READY_EXPRESSION:
                        return {'result': {'value': {'ready': 'complete', 'secure': True, 'url': observed['navigation']}}}
                    value = raw_sample()
                    if insecure_sample:
                        value['values']['context.secure'] = False
                    return {'result': {'value': value}}
                raise AssertionError(method)
        def navigate(connection, session, url):
            observed['navigation'] = url
            observed['navigation_session'] = session
        return (observed, patch.object(fc, 'BrowserController', Controller), patch.object(fc, 'CDP', Connection),
                patch.object(fc, 'profile_processes', return_value=[object()] if live else []),
                patch.object(fc, '_navigate_local_page', navigate))

    def test_probe_uses_only_blank_empty_profile_and_cleans_owned_directory(self):
        (self.root / 'runtime.bin').write_bytes(b'unchanged synthetic runtime')
        observed, controller, cdp, processes, page = self.probe_fakes()
        before = copy.deepcopy(self.record)
        with controller, cdp, processes, page:
            result = fc.probe_snapshot(self.record, self.root)
        item = observed['settings']['windows'][0]
        self.assertNotEqual(item['profile_path'], self.record['_runtime']['profile_path'])
        self.assertTrue(item['new_profile'])
        self.assertFalse(item['restore_session'])
        self.assertEqual(item['initial_urls'], [])
        self.assertEqual(item['account_platform'], '')
        self.assertFalse(observed['settings']['persistent'])
        self.assertEqual(observed['signature_root'], self.root)
        self.assertEqual(observed['open'], {'offline_test': True, 'extra_urls': ['about:blank'], 'bootstrap_blank': True, 'background_probe': True})
        self.assertTrue(observed['closed'])
        self.assertRegex(observed['navigation'], r'^https://probe\.invalid/[0-9a-f]{32}$')
        self.assertEqual(observed['navigation_session'], 'synthetic-session')
        self.assertFalse(observed['temporary_root'].exists())
        self.assertEqual(self.record, before)
        self.assertEqual((self.root / 'runtime.bin').read_bytes(), b'unchanged synthetic runtime')
        self.assertIn('canvas.text', result['values'])

    def test_probe_exception_closes_and_sanitizes_output(self):
        observed, controller, cdp, processes, page = self.probe_fakes(evaluate_error=True)
        with controller, cdp, processes, page:
            with self.assertRaises(LocalBrowserError) as failure:
                fc.probe_snapshot(self.record, self.root)
        self.assertTrue(observed['closed'])
        self.assertFalse(observed['temporary_root'].exists())
        self.assertNotIn('private internal error', str(failure.exception))

    def test_104_probe_uses_and_releases_private_desktop_on_success_or_error(self):
        self.record['_runtime']['core_major']='104'
        for failed in (False,True):
            observed,controller,cdp,processes,page=self.probe_fakes(evaluate_error=failed)
            desktop=Mock()
            with controller,cdp,processes,page,patch('probe_display.ProbeDesktop',return_value=desktop):
                if failed:
                    with self.assertRaises(LocalBrowserError):fc.probe_snapshot(self.record,self.root)
                else:fc.probe_snapshot(self.record,self.root)
            self.assertIs(observed['open']['background_desktop'],desktop)
            self.assertTrue(observed['open']['background_probe'])
            desktop.close.assert_called_once()

    def test_blank_target_waits_for_initial_tab_without_accepting_another_page(self):
        replies=[{'targetInfos':[]},{'targetInfos':[{'targetId':'owned','type':'page','url':''}]},
                 {'targetInfos':[{'targetId':'owned','type':'page','url':'about:blank'}]}]
        connection=SimpleNamespace(timeout=5,call=Mock(side_effect=replies))
        self.assertEqual(fc._blank_target(connection),'owned')
        self.assertEqual(connection.call.call_count,3);self.assertEqual(connection.timeout,5)
        connection.call=Mock(return_value={'targetInfos':[{'targetId':'other','type':'page','url':'https://synthetic.invalid/'}]})
        with self.assertRaises(LocalBrowserError):fc._blank_target(connection)
        connection.call.assert_called_once();self.assertEqual(connection.timeout,5)

    def test_blank_target_ignores_only_exact_known_chromium_ui_pages(self):
        pages=[{'targetId':'ui-'+str(index),'type':'page','url':url} for index,url in enumerate(fc._INTERNAL_PROBE_TARGETS)]
        pages.append({'targetId':'owned','type':'page','url':'about:blank'})
        connection=SimpleNamespace(timeout=5,call=Mock(return_value={'targetInfos':pages}))
        self.assertEqual(fc._blank_target(connection),'owned')
        for url in ('chrome://omnibox-popup.top-chrome/other','chrome://other.top-chrome/','https://synthetic.invalid/'):
            connection.call=Mock(return_value={'targetInfos':[{'targetId':'unknown','type':'page','url':url}]})
            with self.assertRaises(LocalBrowserError):fc._blank_target(connection)

    def test_live_probe_is_preserved_and_never_reported_successful(self):
        observed, controller, cdp, processes, page = self.probe_fakes(live=True)
        with controller, cdp, processes, page:
            with self.assertRaises(LocalBrowserError) as failure:
                fc.probe_snapshot(self.record, self.root)
        self.assertIn('后台环境验证', str(failure.exception))
        self.assertNotIn('正常关闭检查窗口', str(failure.exception))
        self.assertTrue(observed['closed'])
        self.assertTrue(observed['temporary_root'].exists())

    def test_insecure_sample_is_never_accepted_after_local_navigation(self):
        observed, controller, cdp, processes, page = self.probe_fakes(insecure_sample=True)
        with controller, cdp, processes, page:
            with self.assertRaises(LocalBrowserError):
                fc.probe_snapshot(self.record, self.root)
        self.assertTrue(observed['closed'])


    def test_supported_ua_data_cannot_silently_omit_entropy_results(self):
        result = raw_sample()
        result['values']['uaData.supported'] = True
        with self.assertRaises(LocalBrowserError):
            fc._normalize_sample(result)


    def fetch_connection(self, messages=(), calls=(), *, next_id=0):
        outer = self
        class Socket:
            def __init__(inner):
                inner.messages = list(messages)
                inner.sent = []
                inner.timeouts = []
            def settimeout(inner, timeout):
                inner.timeouts.append(timeout)
            def send(inner, value):
                inner.sent.append(json.loads(value))
            def recv(inner):
                if not inner.messages:
                    raise TimeoutError('synthetic-private-transport-detail')
                value = inner.messages.pop(0)
                if callable(value):
                    value = value()
                if isinstance(value, BaseException):
                    raise value
                return value if isinstance(value, (str, bytes)) else json.dumps(value)
        class Connection:
            timeout = 12
            def __init__(inner):
                inner.next_id = next_id
                inner.connection = Socket()
                inner.calls = []
                inner.replies = list(calls)
            def call(inner, method, params=None, session=None):
                inner.calls.append((method, params, session, inner.timeout))
                expected, result = inner.replies.pop(0)
                outer.assertEqual(method, expected)
                if callable(result):
                    result = result()
                if isinstance(result, BaseException):
                    raise result
                return result
        return Connection()

    def fetch_url(self):
        return 'https://probe.invalid/' + 'a' * 32

    def paused_request(self, **changes):
        event = {'method': 'Fetch.requestPaused', 'sessionId': 'owned-session', 'params': {
            'requestId': 'request-one', 'frameId': 'owned-frame', 'resourceType': 'Document',
            'request': {'url': self.fetch_url(), 'method': 'GET'}}}
        for name, value in changes.items():
            if name == 'sessionId':
                event[name] = value
            elif name == 'url':
                event['params']['request']['url'] = value
            elif name == 'request_method':
                event['params']['request']['method'] = value
            else:
                event['params'][name] = value
        return event

    def navigation_reply(self, identifier=1, **changes):
        result = {'frameId': 'owned-frame', 'loaderId': 'new-loader'}
        result.update(changes)
        return {'id': identifier, 'sessionId': 'owned-session', 'result': result}

    def fetch_ack(self, identifier=2, **changes):
        result = {'id': identifier, 'sessionId': 'owned-session', 'result': {}}
        result.update(changes)
        return result

    def fulfill_document(self, connection, deadline=5):
        return fc._fulfill_probe_document(connection, 'owned-session', 'owned-frame', self.fetch_url(), deadline)

    def navigation_calls(self, *, ready=None, final=None):
        return [('Page.getFrameTree', {'frameTree': {'frame': {'id': 'owned-frame', 'url': 'about:blank'}}}),
                ('Fetch.enable', {}), ('Fetch.disable', {}),
                ('Runtime.evaluate', ready or {'result': {'value': {
                    'url': self.fetch_url(), 'ready': 'complete', 'secure': True}}}),
                ('Page.getFrameTree', {'frameTree': {'frame': final or {
                    'id': 'owned-frame', 'loaderId': 'new-loader', 'url': self.fetch_url()}}})]

    def test_fetch_fixed_document_waits_for_both_ack_orders_without_losing_command_ids(self):
        for base, ack_first in ((0, True), (31, False)):
            with self.subTest(ack_first=ack_first):
                nav, ack = self.navigation_reply(base + 1), self.fetch_ack(base + 2)
                connection = self.fetch_connection([self.paused_request(), *( [ack, nav] if ack_first else [nav, ack])], next_id=base)
                with patch.object(fc.time, 'monotonic', return_value=0):
                    result = self.fulfill_document(connection)
                self.assertEqual(result['loaderId'], 'new-loader')
                sent = connection.connection.sent
                self.assertEqual([item['method'] for item in sent], ['Page.navigate', 'Fetch.fulfillRequest'])
                self.assertEqual([item['id'] for item in sent], [base + 1, base + 2])
                self.assertTrue(all(item['sessionId'] == 'owned-session' for item in sent))
                self.assertEqual(sent[0]['params'], {'url': self.fetch_url()})
                payload = sent[1]['params']
                self.assertEqual(payload['requestId'], 'request-one')
                self.assertEqual(payload['responseCode'], 200)
                body = base64.b64decode(payload['body'], validate=True)
                self.assertEqual(body, fc._STATIC_PAGE)
                self.assertLessEqual(len(body), 1024)
                self.assertNotIn(b'<script', body.lower())
                self.assertNotIn(b'http:', body.lower())
                self.assertNotIn(b'https:', body.lower())
                headers = {item['name'].lower(): item['value'] for item in payload['responseHeaders']}
                self.assertEqual(headers['content-type'], 'text/html; charset=utf-8')
                self.assertEqual(headers['content-length'], str(len(body)))
                self.assertIn("default-src 'none'", headers['content-security-policy'])
                self.assertNotIn('location', headers)
                self.assertEqual(connection.connection.messages, [])

    def test_fetch_unowned_or_non_document_requests_are_failed_without_fulfillment(self):
        cases = ({'url': 'https://synthetic.invalid/private-input'}, {'frameId': 'other-frame'},
                 {'request_method': 'POST'}, {'resourceType': 'Script'}, {'request': []},
                 {'redirectedRequestId': 'previous'}, {'responseStatusCode': 200}, {'responseErrorReason': 'Failed'})
        for number, changes in enumerate(cases):
            with self.subTest(case=number):
                connection = self.fetch_connection([self.paused_request(**changes), self.fetch_ack()])
                with patch.object(fc.time, 'monotonic', return_value=0), self.assertRaises(LocalBrowserError) as caught:
                    self.fulfill_document(connection)
                self.assertEqual(caught.exception.code, 'continuity_fetch_request')
                self.assertEqual([item['method'] for item in connection.connection.sent], ['Page.navigate', 'Fetch.failRequest'])
                self.assertEqual(connection.connection.sent[-1]['params']['errorReason'], 'BlockedByClient')
                self.assertNotIn('private-input', str(caught.exception))

    def test_fetch_rejects_foreign_session_and_duplicate_request_identifiers(self):
        for foreign in (True, False):
            with self.subTest(foreign_session=foreign):
                messages = ([self.paused_request(sessionId='foreign-session')] if foreign else
                            [self.paused_request(), self.paused_request()])
                connection = self.fetch_connection(messages)
                with patch.object(fc.time, 'monotonic', return_value=0), self.assertRaises(LocalBrowserError) as caught:
                    self.fulfill_document(connection)
                self.assertEqual(caught.exception.code, 'continuity_fetch_session' if foreign else 'continuity_fetch_request_id')
                self.assertEqual(sum(item['method'] == 'Fetch.fulfillRequest' for item in connection.connection.sent), 0 if foreign else 1)
                self.assertFalse(any(item['method'] == 'Fetch.continueRequest' for item in connection.connection.sent))

    def test_fetch_internal_restart_is_bounded_and_preserves_the_same_body(self):
        messages = [self.paused_request(), self.paused_request(requestId='request-two'),
                    self.fetch_ack(3), self.navigation_reply(), self.fetch_ack(2)]
        connection = self.fetch_connection(messages)
        with patch.object(fc.time, 'monotonic', return_value=0):
            self.fulfill_document(connection)
        payloads = [item['params']['body'] for item in connection.connection.sent if item['method'] == 'Fetch.fulfillRequest']
        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0], payloads[1])
        connection = self.fetch_connection([self.paused_request(), self.paused_request(requestId='request-two'),
            self.paused_request(requestId='request-three'), self.fetch_ack(4)])
        with patch.object(fc.time, 'monotonic', return_value=0), self.assertRaises(LocalBrowserError) as caught:
            self.fulfill_document(connection)
        self.assertEqual(caught.exception.code, 'continuity_fetch_request')
        self.assertEqual(sum(item['method'] == 'Fetch.fulfillRequest' for item in connection.connection.sent), 2)

    def test_fetch_protocol_errors_and_incomplete_navigation_never_succeed(self):
        failures = [self.navigation_reply(errorText='net::ERR_PRIVATE_SENTINEL'),
                    self.navigation_reply(isDownload=True), self.navigation_reply(frameId='other-frame'),
                    self.navigation_reply(loaderId=''), self.navigation_reply(loaderId=None),
                    self.fetch_ack(1, error={'message': 'synthetic-private-protocol-detail'}),
                    self.fetch_ack(2, error={'message': 'synthetic-private-protocol-detail'}),
                    self.fetch_ack(999), self.fetch_ack(True)]
        for number, reply in enumerate(failures):
            with self.subTest(case=number):
                connection = self.fetch_connection([self.paused_request(), reply])
                with patch.object(fc.time, 'monotonic', return_value=0), self.assertRaises(LocalBrowserError) as caught:
                    self.fulfill_document(connection)
                self.assertTrue(caught.exception.code.startswith('continuity_fetch_'))
                self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
                self.assertNotIn('synthetic-private', str(caught.exception))
        connection = self.fetch_connection([self.paused_request(), self.navigation_reply()])
        with patch.object(fc.time, 'monotonic', return_value=0), self.assertRaises(LocalBrowserError) as caught:
            self.fulfill_document(connection)
        self.assertEqual(caught.exception.code, 'continuity_fetch_transport')
        self.assertNotIn('synthetic-private', str(caught.exception))
        self.assertEqual(len(connection.connection.sent), 2)

    def test_fetch_message_shape_byte_budget_and_event_count_are_bounded(self):
        messages = [[], 'not-json', 'x' * 1_000_001,
                    json.dumps({'method': 'Runtime.executionContextsCleared', 'private': '中' * 400_000}, ensure_ascii=False),
                    {'method': 'Unexpected.private-event', 'sessionId': 'owned-session'}]
        for number, message in enumerate(messages):
            with self.subTest(case=number):
                connection = self.fetch_connection([message])
                with patch.object(fc.time, 'monotonic', return_value=0), self.assertRaises(LocalBrowserError) as caught:
                    self.fulfill_document(connection)
                self.assertTrue(caught.exception.code.startswith('continuity_fetch_'))
                self.assertNotIn('private-event', str(caught.exception))
        connection = self.fetch_connection([{'method': 'Runtime.executionContextsCleared', 'sessionId': 'owned-session'}] * 128)
        with patch.object(fc.time, 'monotonic', return_value=0), self.assertRaises(LocalBrowserError) as caught:
            self.fulfill_document(connection)
        self.assertEqual(caught.exception.code, 'continuity_fetch_event_limit')
        self.assertEqual(len(connection.connection.sent), 1)

    def test_fetch_expired_or_late_ack_does_not_extend_the_shared_deadline(self):
        connection = self.fetch_connection()
        with patch.object(fc.time, 'monotonic', return_value=5), self.assertRaises(LocalBrowserError) as caught:
            self.fulfill_document(connection)
        self.assertEqual(caught.exception.code, 'continuity_fetch_budget')
        self.assertEqual(connection.connection.sent, [])
        clock = [0]
        def late_ack():
            clock[0] = 5
            return self.fetch_ack()
        connection = self.fetch_connection([self.paused_request(), self.navigation_reply(), late_ack])
        with patch.object(fc.time, 'monotonic', side_effect=lambda: clock[0]), self.assertRaises(LocalBrowserError) as caught:
            self.fulfill_document(connection)
        self.assertEqual(caught.exception.code, 'continuity_fetch_budget')
        self.assertTrue(all(0 < timeout <= 5 for timeout in connection.connection.timeouts))

    def test_fetch_navigation_binds_initial_frame_and_final_loader_before_sampling(self):
        connection = self.fetch_connection(calls=self.navigation_calls())
        with patch.object(fc, '_fulfill_probe_document', return_value=self.navigation_reply()['result']) as fulfill, \
                patch.object(fc.time, 'monotonic', return_value=0):
            fc._navigate_local_page(connection, 'owned-session', self.fetch_url())
        fulfill.assert_called_once_with(connection, 'owned-session', 'owned-frame', self.fetch_url(), 5)
        self.assertEqual([item[0] for item in connection.calls], ['Page.getFrameTree', 'Fetch.enable', 'Fetch.disable',
            'Runtime.evaluate', 'Page.getFrameTree'])
        self.assertEqual(connection.calls[1][1], {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]})
        self.assertTrue(all(item[2] == 'owned-session' and 0 < item[3] <= 5 for item in connection.calls))
        self.assertEqual(connection.timeout, 12)

    def test_fetch_navigation_rejects_unknown_origin_before_any_command(self):
        for url in ('http://localhost:12345/owned', 'https://probe.invalid/short',
                    'https://synthetic.invalid/' + 'a' * 32, self.fetch_url() + '?private-input'):
            connection = self.fetch_connection()
            with self.subTest(case=url.startswith('http://')), self.assertRaises(LocalBrowserError) as caught:
                fc._navigate_local_page(connection, 'owned-session', url)
            self.assertTrue(caught.exception.code.startswith('continuity_fetch_'))
            self.assertEqual(connection.calls, [])
            self.assertEqual(connection.timeout, 12)
            self.assertNotIn('private-input', str(caught.exception))

    def test_fetch_navigation_rejects_unknown_initial_or_changed_final_document(self):
        for initial, changes in ((True, {'url': 'https://synthetic.invalid/'}), (True, {'id': ''}),
                (True, {'unreachableUrl': self.fetch_url()}), (False, {'id': 'other-frame'}),
                (False, {'loaderId': 'old-loader'}), (False, {'url': 'chrome-error://chromewebdata/'}),
                (False, {'unreachableUrl': self.fetch_url()})):
            with self.subTest(initial=initial, field=next(iter(changes))):
                calls = self.navigation_calls()
                calls[0 if initial else -1][1]['frameTree']['frame'].update(changes)
                connection = self.fetch_connection(calls=calls)
                with patch.object(fc, '_fulfill_probe_document', return_value=self.navigation_reply()['result']) as fulfill, \
                        patch.object(fc.time, 'monotonic', return_value=0), self.assertRaises(LocalBrowserError):
                    fc._navigate_local_page(connection, 'owned-session', self.fetch_url())
                self.assertEqual(fulfill.call_count, 0 if initial else 1)
                self.assertEqual(connection.timeout, 12)

    def test_fetch_navigation_failure_restores_timeout_without_disabling_fetch(self):
        failure = fc._blocked(['probe.navigation'])
        failure.code = 'continuity_fetch_protocol'
        connection = self.fetch_connection(calls=self.navigation_calls()[:2])
        with patch.object(fc, '_fulfill_probe_document', side_effect=failure), \
                patch.object(fc.time, 'monotonic', return_value=0), self.assertRaises(LocalBrowserError) as caught:
            fc._navigate_local_page(connection, 'owned-session', self.fetch_url())
        self.assertEqual(caught.exception.code, 'continuity_fetch_protocol')
        self.assertEqual([item[0] for item in connection.calls], ['Page.getFrameTree', 'Fetch.enable'])
        self.assertEqual(connection.timeout, 12)

    def test_fetch_navigation_never_accepts_insecure_wrong_or_late_ready_document(self):
        for case in ('insecure', 'wrong_url', 'exception', 'late'):
            clock = [0.0]
            connection = self.fetch_connection(calls=self.navigation_calls())
            call = connection.call
            def ready_call(method, params=None, session=None):
                if method != 'Runtime.evaluate':
                    return call(method, params, session)
                if case == 'late':
                    clock[0] = 5
                if case == 'exception':
                    return {'exceptionDetails': {'text': 'synthetic-private-evaluation-detail'}}
                return {'result': {'value': {'ready': 'complete', 'secure': case != 'insecure',
                    'url': 'https://synthetic.invalid/' if case == 'wrong_url' else self.fetch_url()}}}
            connection.call = ready_call
            def advance(seconds):
                clock[0] += seconds
            with self.subTest(case=case), patch.object(fc, '_fulfill_probe_document', return_value=self.navigation_reply()['result']), \
                    patch.object(fc.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(fc.time, 'sleep', side_effect=advance), \
                    self.assertRaises(LocalBrowserError) as caught:
                fc._navigate_local_page(connection, 'owned-session', self.fetch_url())
            self.assertEqual(connection.timeout, 12)
            self.assertNotIn('synthetic-private', str(caught.exception))
            self.assertLessEqual(clock[0], 5.001)

    def test_probe_creates_no_http_socket_or_worker(self):
        observed, controller, cdp, processes, navigation = self.probe_fakes()
        with controller, cdp, processes, navigation, \
                patch('socket.socket', side_effect=AssertionError('HTTP socket forbidden')) as socket, \
                patch('threading.Thread', side_effect=AssertionError('HTTP worker forbidden')) as thread:
            fc.probe_snapshot(self.record, self.root)
        socket.assert_not_called()
        thread.assert_not_called()
        self.assertTrue(observed['closed'])

    def test_default_strict_comparison_does_not_relax_nine_device_variance_fields(self):
        pairs = {'canvas.geometry': ('sha256:' + '1' * 64, 'sha256:' + '2' * 64),
                 'canvas.text': ('sha256:' + '1' * 64, 'sha256:' + '2' * 64),
                 'fonts.metrics': ([['Arial', [1] * 5, [1] * 5, [1] * 5]], [['Arial', [2] * 5, [2] * 5, [2] * 5]]),
                 'devices.kinds': ({'audioinput': 0, 'audiooutput': 0, 'videoinput': 0}, {'audioinput': 1, 'audiooutput': 0, 'videoinput': 0}),
                 'screen.media': ({'(prefers-reduced-motion: reduce)': False}, {'(prefers-reduced-motion: reduce)': True}),
                 'webgl1.extensions': ([], ['EXT_synthetic']), 'webgl2.extensions': ([], ['EXT_synthetic']),
                 'webgl1.pixels': ('sha256:' + '1' * 64, 'sha256:' + '2' * 64),
                 'webgl2.pixels': ('sha256:' + '1' * 64, 'sha256:' + '2' * 64)}
        for field, (old, changed) in pairs.items():
            with self.subTest(field=field):
                original = sample()
                original['values'][field] = old
                self.enroll(original, original)
                before = copy.deepcopy(self.record)
                actual = copy.deepcopy(original)
                actual['values'][field] = changed
                with patch.object(fc, 'probe_snapshot', return_value=actual), patch.object(fc, 'create_baseline') as enroll:
                    with self.assertRaises(LocalBrowserError):
                        fc.verify_continuity(self.record, self.root)
                enroll.assert_not_called()
                self.assertEqual(self.record, before)

    def test_device_measurement_requests_no_permission_and_keeps_no_identifiers(self):
        for forbidden in ('getUserMedia', 'deviceId', 'groupId', '.label', 'requestAdapter'):
            self.assertNotIn(forbidden, fc._EXPRESSION)
        self.assertIn('const kinds={audioinput:0,audiooutput:0,videoinput:0}', fc._EXPRESSION)

    def test_version_one_baseline_is_not_silently_upgraded(self):
        self.enroll()
        self.record['_continuity']['probe_version'] = 1
        with patch.object(fc, 'probe_snapshot') as probe:
            with self.assertRaises(LocalBrowserError):
                fc.verify_continuity(self.record, self.root)
        probe.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
