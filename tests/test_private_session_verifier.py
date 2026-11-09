"""Protocol and authorization fixtures only; never open a real browser/profile."""
import base64
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('private_session_verifier', ROOT / 'tools/verify_private_session.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

TARGET = 'https://page.example.invalid'
API = 'https://api.example.invalid'
URL = API + '/natural-session'


def marker():
    return {'format': 1, 'purpose': 'authorized-private-session', 'reload_safe': True,
            'profile_id': 'profile-synthetic', 'expected_stable_sha256': verifier.digest({'field': 'synthetic'}),
            'target_origin': TARGET, 'auth_rule': {'origin': API, 'url_sha256': verifier.url_digest(URL),
                'method': 'GET', 'status': 200, 'json_matches': [
                    {'path': ['success'], 'sha256': verifier.digest(True)},
                    {'path': ['data', 'userId'], 'sha256': verifier.digest('synthetic-id')}]}}


def event(method, *, identity='request', session='page', **params):
    return {'method': 'Network.' + method, 'sessionId': session,
            'params': {'requestId': identity, **params}}


def response_events(*, cached=False, worker=False, method='GET', session='page', identity='request'):
    result = [event('requestWillBeSent', session=session, identity=identity, request={'method': method, 'url': URL + '?private=query'})]
    if cached:
        result.append(event('requestServedFromCache', session=session, identity=identity))
    result.extend([event('responseReceived', session=session, identity=identity,
        response={'url': URL, 'status': 200, 'mimeType': 'application/json', 'fromServiceWorker': worker}),
        event('loadingFinished', session=session, identity=identity, encodedDataLength=100)])
    return result


class MarkerTests(unittest.TestCase):
    def test_authorization_supports_a_separate_https_api_and_canonical_identity(self):
        value = marker()
        self.assertIs(verifier.validate_marker(value), value)
        self.assertEqual(verifier.url_digest(URL + '?rotating=value#ignored'), verifier.url_digest(URL))
        self.assertNotEqual(verifier.digest(True), verifier.digest(1))
        self.assertEqual(verifier.canonical({'z': '合成', 'a': True}), '{"a":true,"z":"合成"}'.encode())

    def test_missing_reload_authorization_bad_origin_and_malformed_rules_refuse(self):
        for change in (lambda v: v.pop('reload_safe'), lambda v: v.update(format=True),
                       lambda v: v.update(target_origin='http://page.example.invalid'),
                       lambda v: v['auth_rule'].update(origin='https://user:secret@api.example.invalid'),
                       lambda v: v['auth_rule'].update(method='DELETE'),
                       lambda v: v['auth_rule']['json_matches'][0].update(path=[True]),
                       lambda v: v['auth_rule'].update(json_matches=[])):
            value = marker()
            change(value)
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                verifier.validate_marker(value)

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}'):
            with self.assertRaises(ValueError):
                verifier._json(raw)

    def test_record_requires_exact_authorized_profile_and_unchanged_stable_hash(self):
        with tempfile.TemporaryDirectory(prefix='private-session-unit-') as directory:
            data = Path(directory).resolve()
            profile = data / 'profiles/profile-synthetic'
            profile.mkdir(parents=True)
            record = {'id': 'profile-synthetic', '_portable_crypt': {'synthetic': True},
                      '_runtime': {'signature_provider': 'local-v1', 'profile_path': str(profile)},
                      '_continuity': {'stable': {'field': 'synthetic'}}}
            self.assertEqual(verifier.validate_record(marker(), record, data), profile)
            for key, value in (('created_locally', True), ('archived', True), ('id', 'other')):
                changed = copy.deepcopy(record)
                changed[key] = value
                with self.assertRaises(verifier.AcceptanceError):
                    verifier.validate_record(marker(), changed, data)
            record['_continuity']['stable']['field'] = 'changed'
            with self.assertRaises(verifier.AcceptanceError):
                verifier.validate_record(marker(), record, data)

    def test_old_paths_are_authenticated_before_relocation_and_bound_after_it(self):
        with tempfile.TemporaryDirectory(prefix='private-relocation-unit-') as directory:
            data = Path(directory).resolve()
            profile = data / 'profiles/profile-synthetic'
            profile.mkdir(parents=True)
            old = {'id': 'profile-synthetic', '_portable_crypt': {'synthetic': True},
                   '_runtime': {'signature_provider': 'local-v1', 'profile_path': 'Z:/old-copy/profile-synthetic'},
                   '_continuity': {'stable': {'field': 'synthetic'}, 'binding': 'old-path'},
                   '_native': {'path': 'old-path'}}
            migrated = copy.deepcopy(old)
            migrated['_runtime']['profile_path'] = str(profile)
            migrated['_continuity']['binding'] = 'relocated-path'
            migrated['_native']['path'] = 'relocated-path'
            events = []
            service = Mock()
            service.configuration.independent = True
            service.store.all.side_effect = lambda: (events.append('read-relocated') or [migrated])
            def factory(selected):
                self.assertEqual(selected, data)
                events.append('normal-relocate')
                return service
            def processes(selected, **_options):
                self.assertEqual(selected, profile)
                events.append('check-closed')
                return []
            result, selected, original = verifier.prepare_service(data, marker(), old, processes, factory)
            self.assertIs(result, service)
            self.assertEqual(selected, profile)
            self.assertEqual(events, ['check-closed', 'normal-relocate', 'read-relocated', 'check-closed'])
            self.assertEqual(original, verifier.immutable_digest(migrated))
            self.assertNotEqual(original, verifier.immutable_digest(old))
            service.open.assert_not_called()
            bad = marker()
            bad['expected_stable_sha256'] = '0' * 64
            forbidden = Mock(side_effect=AssertionError())
            with self.assertRaises(verifier.AcceptanceError):
                verifier.prepare_service(data, bad, old, processes, forbidden)
            forbidden.assert_not_called()

    def test_private_acceptance_refuses_a_nonindependent_runtime_before_opening(self):
        with tempfile.TemporaryDirectory(prefix='private-independent-unit-') as directory:
            data = Path(directory).resolve()
            (data / 'profiles/profile-synthetic').mkdir(parents=True)
            record = {'id': 'profile-synthetic', '_portable_crypt': {'synthetic': True},
                      '_runtime': {'signature_provider': 'local-v1', 'profile_path': 'Z:/old-copy/profile-synthetic'},
                      '_continuity': {'stable': {'field': 'synthetic'}}, '_native': {}}
            for independent in (False, None, 1, 'true'):
                service = Mock()
                service.configuration.independent = independent
                with self.subTest(independent=independent), self.assertRaises(verifier.AcceptanceError):
                    verifier.prepare_service(data, marker(), record, Mock(return_value=[]), Mock(return_value=service))
                service.store.all.assert_not_called()
                service.open.assert_not_called()


class EvidenceTests(unittest.TestCase):
    def test_cached_worker_wrong_method_and_other_page_cannot_authenticate(self):
        observer = verifier.AuthResponses('page', marker()['auth_rule'])
        for values in (response_events(cached=True), response_events(worker=True),
                       response_events(method='POST'), response_events(session='other')):
            self.assertEqual(observer.consume(values), [])
        self.assertEqual(observer.consume(response_events(identity='natural-network')), ['natural-network'])
        self.assertEqual(observer.requests, {})

    def test_response_is_ready_only_after_loading_finished_and_status_success(self):
        values = response_events()
        observer = verifier.AuthResponses('page', marker()['auth_rule'])
        self.assertEqual(observer.consume(values[:2]), [])
        self.assertEqual(observer.consume(values[2:]), ['request'])
        values[1]['params']['response']['status'] = 401
        self.assertEqual(observer.consume(values), [])

    def test_exact_json_identity_all_fields_and_decoded_body_limit(self):
        rule = marker()['auth_rule']
        body = json.dumps({'success': True, 'data': {'userId': 'synthetic-id'}})
        self.assertTrue(verifier.body_matches({'body': body}, rule))
        self.assertTrue(verifier.body_matches({'body': base64.b64encode(body.encode()).decode(), 'base64Encoded': True}, rule))
        self.assertFalse(verifier.body_matches({'body': body.replace('synthetic-id', 'different-id')}, rule))
        self.assertFalse(verifier.body_matches({'body': body.replace('true', '1')}, rule))
        self.assertFalse(verifier.body_matches({'body': 'x' * (verifier.MAX_BODY + 1)}, rule))
        self.assertFalse(verifier.body_matches({'body': '{"success":NaN}'}, rule))

    def test_reload_observes_only_natural_events_and_skips_worker_response(self):
        class Connection:
            def __init__(self):
                self.pending = []
                self.calls = []
            def events(self):
                values, self.pending = self.pending, []
                return values
            def call(self, method, params=None, session=None):
                self.calls.append(method)
                if method == 'Page.reload':
                    self.pending = response_events(worker=True) + response_events(identity='direct')
                    return {}
                if method == 'Network.getResponseBody':
                    return {'body': json.dumps({'success': True, 'data': {'userId': 'synthetic-id'}})}
                raise AssertionError()
            def poll(self, _timeout):
                raise AssertionError()
        connection = Connection()
        self.assertEqual(verifier.authenticate(connection, 'page', marker()['auth_rule']), 1)
        self.assertEqual(connection.calls, ['Page.reload', 'Network.getResponseBody'])

    def test_existing_same_origin_tabs_are_allowed_without_cache_or_page_mutations(self):
        calls = []
        def call(method, params=None, session=None):
            calls.append(method)
            if method == 'Target.getTargets':
                return {'targetInfos': [{'type': 'page', 'url': TARGET + '/safe', 'targetId': str(i)} for i in range(3)]}
            if method == 'Target.attachToTarget':
                return {'sessionId': 'page'}
            return {}
        self.assertEqual(verifier.attach_existing(Mock(call=call), marker()), ('0', 'page'))
        self.assertFalse(any(name in calls for name in ('Network.setCacheDisabled', 'Network.setBypassServiceWorker', 'Target.createTarget', 'Runtime.evaluate')))

    def test_sampling_detects_login_path_spa_route_or_target_loss(self):
        def route(url):
            connection = Mock()
            connection.call.return_value = {'targetInfo': {'type': 'page', 'url': url}}
            return verifier.target_route(connection, 'synthetic', marker())
        self.assertNotEqual(route(TARGET + '/account'), route(TARGET + '/login'))
        self.assertNotEqual(route(TARGET + '/#account'), route(TARGET + '/#login'))
        self.assertEqual(route(TARGET + '/account?a=1'), route(TARGET + '/account?a=2'))
        with self.assertRaises(verifier.AcceptanceError):
            route('https://login.example.invalid/')
        connection = Mock()
        connection.call.side_effect = verifier.CommandRejected()
        with self.assertRaises(verifier.CommandRejected):
            verifier.target_route(connection, 'gone', marker())


class EventRetentionTests(unittest.TestCase):
    def connection(self, messages):
        socket = Mock()
        socket.recv.side_effect = [json.dumps(message) for message in messages]
        import websocket
        with patch.object(websocket, 'create_connection', return_value=socket):
            return verifier.EventCDP('ws://127.0.0.1:1/synthetic'), socket

    def test_command_keeps_interleaved_response_and_finished_events(self):
        values = response_events()
        connection, _socket = self.connection([*values, {'id': 1, 'result': {'synthetic': True}}])
        self.assertEqual(connection.call('Browser.getVersion'), {'synthetic': True})
        self.assertEqual(connection.events(), values)
        self.assertEqual(connection.events(), [])
        self.assertEqual(connection.pending_bytes, 0)

    def test_event_overflow_refuses_instead_of_dropping_evidence(self):
        connection, _socket = self.connection([*response_events(), {'id': 1, 'result': {}}])
        with patch.object(verifier, 'MAX_EVENTS', 1), self.assertRaises(verifier.AcceptanceError):
            connection.call('Browser.getVersion')

    def test_command_error_does_not_reflect_remote_details(self):
        connection, _socket = self.connection([{'id': 1, 'error': {'message': 'synthetic-private-detail'}}])
        with self.assertRaises(verifier.CommandRejected) as raised:
            connection.call('Browser.getVersion')
        self.assertEqual(str(raised.exception), '')


class OwnershipAndOutputTests(unittest.TestCase):
    def test_unknown_live_process_is_never_closed(self):
        service = Mock()
        service.controller.state = {'profile-synthetic': {'pid': 20, 'created': 30}}
        service.controller._record_valid.return_value = True
        with self.assertRaises(verifier.OwnershipError):
            verifier.close_owned(service, 'profile-synthetic', (10, 15), Path('synthetic'), Mock(return_value=[object()]))
        service.close.assert_not_called()

    def test_owned_close_requires_process_and_worker_release(self):
        service = Mock()
        service.controller.state = {'profile-synthetic': {'pid': 20, 'created': 30}}
        service.controller._record_valid.return_value = True
        service.proxy_runtime.state.return_value = None
        verifier.close_owned(service, 'profile-synthetic', (20, 30), Path('synthetic'), Mock(return_value=[]))
        service.close.assert_called_once_with('profile-synthetic')

    def test_a_disappeared_browser_does_not_allow_adopting_an_unknown_process_for_cleanup(self):
        service = Mock()
        service.controller.state = {}
        service.proxy_runtime.state.return_value = None
        verifier.close_owned(service, 'profile-synthetic', (20, 30), Path('synthetic'), Mock(return_value=[]))
        service.close.assert_not_called()
        service.proxy_runtime.stop_if_unused.assert_called_once_with('profile-synthetic')

    def test_dry_run_reads_no_private_marker_or_app_data(self):
        output = io.StringIO()
        with patch.object(verifier, 'load_marker', side_effect=AssertionError()), redirect_stdout(output):
            self.assertEqual(verifier.main([]), 0)
        self.assertEqual(json.loads(output.getvalue()), {'executed': False})

    def test_short_or_invalid_acceptance_cannot_report_long_success_or_private_error(self):
        with tempfile.TemporaryDirectory(prefix='private-output-unit-') as directory:
            destination = Path(directory) / 'anonymous.json'
            output = io.StringIO()
            with patch.object(verifier, 'ROOT', Path(directory)), redirect_stdout(output):
                self.assertEqual(verifier.main(['--execute', '--duration-seconds', '60', '--report', str(destination)]), 1)
            result = json.loads(output.getvalue())
            self.assertFalse(result['long_acceptance'])
            self.assertFalse(result['success'])
            self.assertEqual(result['error_type'], 'FileNotFoundError')
            self.assertNotIn(directory, output.getvalue())
            self.assertEqual(json.loads(destination.read_text()), result)


if __name__ == '__main__':
    unittest.main()
