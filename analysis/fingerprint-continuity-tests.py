"""Pure temporary-file/controller fixtures; never reads real data or starts a browser."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
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
        self.root = Path(self.temporary.name)
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
                if method == 'Page.navigate':
                    observed['navigation'] = params['url']
                    return {}
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
        class Page:
            def start(inner):
                observed['server_started'] = True
                return 'http://localhost:12345/synthetic-owned-page'
            def close(inner):
                observed['server_closed'] = True
        return (observed, patch.object(fc, 'BrowserController', Controller), patch.object(fc, 'CDP', Connection),
                patch.object(fc, 'profile_processes', return_value=[object()] if live else []),
                patch.object(fc, '_LoopbackPage', Page))

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
        self.assertEqual(observed['navigation'], 'http://localhost:12345/synthetic-owned-page')
        self.assertTrue(observed['server_started'])
        self.assertTrue(observed['server_closed'])
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
        self.assertTrue(observed['server_closed'])
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
        self.assertTrue(observed['server_closed'])
        self.assertTrue(observed['temporary_root'].exists())

    def test_insecure_sample_is_never_accepted_after_local_navigation(self):
        observed, controller, cdp, processes, page = self.probe_fakes(insecure_sample=True)
        with controller, cdp, processes, page:
            with self.assertRaises(LocalBrowserError):
                fc.probe_snapshot(self.record, self.root)
        self.assertTrue(observed['server_closed'])
        self.assertTrue(observed['closed'])

    def test_local_navigation_refuses_insecure_or_wrong_document_within_five_seconds(self):
        for secure, actual_url in [(False, 'http://localhost:12345/token'), (True, 'https://fixture.invalid/')]:
            clock = [0.0]
            class Connection:
                timeout = 5
                calls = 0
                def call(inner, method, params=None, session=None):
                    inner.calls += 1
                    if method == 'Page.navigate':
                        return {}
                    return {'result': {'value': {'ready': 'complete', 'secure': secure, 'url': actual_url}}}
            connection = Connection()
            def advance(duration):
                clock[0] += duration
            with patch.object(fc.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(fc.time, 'sleep', side_effect=advance):
                with self.assertRaises(LocalBrowserError):
                    fc._navigate_local_page(connection, 'session', 'http://localhost:12345/token')
            self.assertLessEqual(clock[0], 5.001)
            self.assertLessEqual(connection.calls, 103)
            self.assertEqual(connection.timeout, 5)

    def test_local_page_server_binds_only_loopback_and_closes_bounded(self):
        observed = {}
        class Server:
            server_port = 12345
            def __init__(inner, address, handler):
                observed['address'] = address
                observed['handler'] = handler
            def serve_forever(inner, **kwargs):
                raise AssertionError('Mock must not open a network service')
            def shutdown(inner):
                observed['shutdown'] = True
            def server_close(inner):
                observed['server_close'] = True
            def close_workers(inner):
                observed['workers_closed'] = True
                return True
        class Thread:
            alive = False
            def __init__(inner, **kwargs):
                observed['thread'] = kwargs
            def start(inner):
                inner.alive = True
            def is_alive(inner):
                return inner.alive
            def join(inner, timeout=None):
                observed['join_timeout'] = timeout
                inner.alive = False
        with patch.object(fc, '_ProbeHTTPServer', Server), patch.object(fc.threading, 'Thread', Thread):
            page = fc._LoopbackPage()
            url = page.start()
            self.assertRegex(url, r'^http://localhost:12345/[0-9a-f]{32}$')
            page.close()
            page.close()
        self.assertEqual(observed['address'], ('127.0.0.1', 0))
        self.assertIs(observed['handler'], fc._ProbePageHandler)
        self.assertTrue(observed['thread']['daemon'])
        self.assertEqual(observed['thread']['kwargs'], {'poll_interval': .05})
        self.assertTrue(observed['shutdown'])
        self.assertTrue(observed['server_close'])
        self.assertTrue(observed['workers_closed'])
        self.assertEqual(observed['join_timeout'], 1)

    def test_server_thread_start_failure_closes_listener_without_waiting_for_unstarted_thread(self):
        observed = {}
        class Server:
            server_port = 12345
            def __init__(inner, *args):
                pass
            def serve_forever(inner, **kwargs):
                pass
            def shutdown(inner):
                raise AssertionError('An unstarted server must not wait in shutdown')
            def server_close(inner):
                observed['closed'] = True
            def close_workers(inner):
                observed['workers_closed'] = True
                return True
        class Thread:
            def __init__(inner, **kwargs):
                pass
            def start(inner):
                raise OSError('private start failure')
        with patch.object(fc, '_ProbeHTTPServer', Server), patch.object(fc.threading, 'Thread', Thread):
            with self.assertRaises(LocalBrowserError) as failure:
                fc._LoopbackPage().start()
        self.assertTrue(observed['closed'])
        self.assertTrue(observed['workers_closed'])
        self.assertNotIn('private start failure', str(failure.exception))

    def test_server_close_failure_never_returns_success(self):
        observed = {}
        page = fc._LoopbackPage()
        page.started = True
        class Server:
            def shutdown(inner):
                observed['shutdown'] = True
            def server_close(inner):
                observed['closed'] = True
            def close_workers(inner):
                observed['workers_closed'] = True
                return True
        class Thread:
            def is_alive(inner):
                return True
            def join(inner, timeout=None):
                observed['timeout'] = timeout
        page.server, page.thread = Server(), Thread()
        with self.assertRaises(LocalBrowserError):
            page.close()
        self.assertTrue(observed['closed'])
        self.assertTrue(observed['workers_closed'])
        self.assertEqual(observed['timeout'], 1)

    def test_worker_cleanup_interrupts_only_owned_sockets_and_joins_bounded(self):
        observed = []
        class Connection:
            def shutdown(inner, mode):
                observed.append(('shutdown', mode))
            def close(inner):
                observed.append(('close',))
        class Worker:
            alive = True
            def join(inner, timeout=None):
                self.assertGreaterEqual(timeout, 0)
                self.assertLessEqual(timeout, 1)
                observed.append(('join',))
                inner.alive = False
            def is_alive(inner):
                return inner.alive
        server = object.__new__(fc._ProbeHTTPServer)
        server._workers_lock = fc.threading.Lock()
        server._workers = {Worker(): Connection()}
        self.assertTrue(server.close_workers())
        self.assertEqual([event[0] for event in observed], ['shutdown', 'close', 'join'])

    def test_supported_ua_data_cannot_silently_omit_entropy_results(self):
        result = raw_sample()
        result['values']['uaData.supported'] = True
        with self.assertRaises(LocalBrowserError):
            fc._normalize_sample(result)

    def handler_response(self, request):
        class Request:
            def __init__(inner):
                inner.output = io.BytesIO()
            def makefile(inner, *_):
                return io.BytesIO(request)
            def sendall(inner, data):
                inner.output.write(data)
        connection = Request()
        server = SimpleNamespace(server_port=12345, probe_path='/owned-token')
        captured = io.StringIO()
        with redirect_stdout(captured), redirect_stderr(captured):
            fc._ProbePageHandler(connection, ('127.0.0.1', 1), server)
        self.assertEqual(captured.getvalue(), '')
        return connection.output.getvalue()

    def test_handler_returns_only_small_static_page_without_script_or_redirect(self):
        response = self.handler_response(b'GET /owned-token HTTP/1.1\r\nHost: localhost:12345\r\n\r\n')
        headers, body = response.split(b'\r\n\r\n', 1)
        self.assertIn(b' 200 ', headers)
        self.assertIn(b"default-src 'none'", headers)
        self.assertNotIn(b'Location:', headers)
        self.assertEqual(body, fc._STATIC_PAGE)
        self.assertLessEqual(len(body), 1024)
        self.assertNotIn(b'<script', body.lower())
        self.assertNotIn(b'http:', body.lower())
        self.assertNotIn(b'https:', body.lower())

    def test_handler_rejects_other_hosts_paths_bodies_and_methods_without_reflection(self):
        requests = [
            b'GET /private-request-input HTTP/1.1\r\nHost: localhost:12345\r\n\r\n',
            b'GET /owned-token HTTP/1.1\r\nHost: private-request-input\r\n\r\n',
            b'GET http://private-request-input/ HTTP/1.1\r\nHost: localhost:12345\r\n\r\n',
            b'GET /owned-token HTTP/1.1\r\nHost: localhost:12345\r\nContent-Length: 5\r\n\r\ninput',
            b'POST /owned-token HTTP/1.1\r\nHost: localhost:12345\r\n\r\n',
            b'UNKNOWN /private-request-input HTTP/1.1\r\nHost: localhost:12345\r\n\r\n',
        ]
        for request in requests:
            with self.subTest(request=request.split(b'\r\n')[0]):
                response = self.handler_response(request)
                headers, body = response.split(b'\r\n\r\n', 1)
                self.assertNotIn(b' 200 ', headers)
                self.assertNotIn(b'Location:', headers)
                self.assertNotIn(b'private-request-input', response)
                self.assertEqual(body, b'')

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
