"""Bounded public-only network diagnostics; all transports and records synthetic."""
import contextlib
import base64
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tools')]
spec = importlib.util.spec_from_file_location('private_network_diagnostic', ROOT / 'tools/diagnose_private_network.py')
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


class PrivateNetworkDiagnosticTests(unittest.TestCase):
    def test_default_preview_never_reads_private_input_or_starts_a_worker(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['diagnostic']), patch.object(diagnostic, 'run') as run, \
                patch.object(diagnostic.subprocess, 'Popen') as popen, \
                patch.object(Path, 'read_text', side_effect=AssertionError()), contextlib.redirect_stdout(output):
            self.assertEqual(diagnostic.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), {'executed': False})
        run.assert_not_called()
        popen.assert_not_called()

    def test_both_paths_send_only_public_root_get_and_do_not_follow_redirects(self):
        import socks
        secret = 'synthetic-private-proxy-credential'
        for mode in ('upstream_socks5', 'production_relay'):
            connection = Mock()
            incoming = (b'HTTP/1.1 200 Connection Established\r\n\r\n' if mode == 'production_relay' else b'')
            incoming += b'HTTP/1.1 302 Found\r\nLocation: https://redirect.example.invalid/private\r\n\r\n'
            connection.recv.side_effect = [bytes([value]) for value in incoming]
            context = Mock()
            context.wrap_socket.return_value = connection
            payload = {'mode': mode, 'host': 'page.example.invalid', 'port': 443, 'relay_port': 1234,
                       'proxy': {'type': 'socks5', 'host': 'proxy.example.invalid', 'port': 1234,
                                 'username': secret, 'password': secret}}
            output = io.StringIO()
            with patch.object(socks, 'socksocket', return_value=connection), \
                    patch.object(diagnostic.socket, 'create_connection', return_value=connection) as connect, \
                    patch.object(diagnostic.ssl, 'create_default_context', return_value=context), \
                    patch.object(diagnostic.threading, 'Timer'), contextlib.redirect_stdout(output):
                result = diagnostic.attempt(payload)
            self.assertEqual(result['statusclass'], '3xx')
            self.assertEqual(result['stage'], 'complete')
            sent = b''.join(value.args[0] for value in connection.sendall.call_args_list)
            self.assertEqual(sent.count(b'GET / HTTP/1.1\r\n'), 1)
            self.assertNotIn(b'Cookie:', sent)
            self.assertNotIn(b'Authorization:', sent)
            self.assertNotIn(b'/private', sent)
            self.assertNotIn(secret, output.getvalue() + json.dumps(result))
            context.wrap_socket.assert_called_once_with(connection, server_hostname='page.example.invalid')
            connection.close.assert_called_once()
            self.assertLessEqual(connect.call_count, 1)

    def test_parent_deadline_kills_only_its_observed_request_child(self):
        child = Mock()
        child.communicate.side_effect = [subprocess.TimeoutExpired('synthetic', 15),
            (b'{"mode":"production_relay","stage":"relay_connect"}\n', b'')]
        child.poll.return_value = 1
        payload = {'mode': 'production_relay', 'host': 'synthetic-private-host'}
        with patch.object(diagnostic.subprocess, 'Popen', return_value=child) as popen:
            result = diagnostic.bounded_attempt(payload)
        self.assertEqual(result['error_type'], 'TimeoutError')
        self.assertEqual(result['stage'], 'relay_connect')
        self.assertEqual(child.communicate.call_args_list[0].kwargs['timeout'], diagnostic.ATTEMPT_TIMEOUT)
        self.assertEqual(child.communicate.call_args_list[0].args[0], diagnostic.canonical(payload))
        child.kill.assert_called_once()
        self.assertEqual(child.communicate.call_count, 2)
        self.assertNotIn('synthetic-private-host', repr(popen.call_args))
        self.assertNotIn('synthetic-private-host', json.dumps(result))

    def test_http_connect_credentials_exist_only_in_the_proxy_request_before_tls(self):
        connection=Mock();encrypted=[False]
        incoming=b'HTTP/1.1 200 Connection Established\r\n\r\nHTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid/private\r\n\r\n'
        connection.recv.side_effect=[bytes([value]) for value in incoming]
        context=Mock()
        def wrap(selected,server_hostname):
            self.assertIs(selected,connection);self.assertEqual(server_hostname,'page.example.invalid')
            encrypted[0]=True
            return connection
        context.wrap_socket.side_effect=wrap
        requests=[]
        def send(value):
            requests.append((encrypted[0],value))
        connection.sendall.side_effect=send
        secret='synthetic-private-proxy-password'
        proxy={'type':'http','host':'proxy.example.invalid','port':1234,'username':'fixture','password':secret}
        payload={'mode':'upstream_http','host':'page.example.invalid','port':443,'proxy':proxy}
        output=io.StringIO()
        with patch.object(diagnostic.socket,'create_connection',return_value=connection) as connect, \
                patch.object(diagnostic.ssl,'create_default_context',return_value=context), \
                patch.object(diagnostic.threading,'Timer'),contextlib.redirect_stdout(output):
            result=diagnostic.attempt(payload)
        self.assertEqual(result['stage'],'complete');self.assertEqual(result['statusclass'],'3xx')
        self.assertEqual(len(requests),2)
        self.assertFalse(requests[0][0]);self.assertTrue(requests[1][0])
        encoded=base64.b64encode(('fixture:'+secret).encode())
        self.assertIn(b'Proxy-Authorization: Basic '+encoded,requests[0][1])
        self.assertTrue(requests[0][1].startswith(b'CONNECT page.example.invalid:443 HTTP/1.1\r\n'))
        self.assertTrue(requests[1][1].startswith(b'GET / HTTP/1.1\r\n'))
        self.assertNotIn(b'Authorization:',requests[1][1]);self.assertNotIn(b'Cookie:',requests[1][1])
        self.assertNotIn(b'/private',requests[1][1])
        self.assertNotIn(secret,output.getvalue()+json.dumps(result))
        self.assertNotIn(encoded.decode(),output.getvalue()+json.dumps(result))
        connect.assert_called_once();connection.close.assert_called_once()

    def test_http_protocol_uses_only_an_in_memory_record_and_keeps_saved_proxy(self):
        import browser_processes,inspect_installation,manager_service,proxy_runtime,verify_private_session
        with tempfile.TemporaryDirectory(prefix='http-protocol-unit-') as temporary:
            root=Path(temporary).resolve();profile=root/'app/data/profiles/profile-synthetic';profile.mkdir(parents=True)
            stable={'synthetic':True}
            marker={'profile_id':'profile-synthetic','expected_stable_sha256':verify_private_session.digest(stable),
                    'target_origin':'https://page.example.invalid'}
            record={'id':'profile-synthetic','_native':{},'_portable_crypt':{'synthetic':True},
                    '_continuity':{'stable':stable},'_runtime':{'signature_provider':'local-v1','profile_path':str(profile)},
                    'proxy':{'type':'socks5','host':'proxy.example.invalid','port':1234,'username':'fixture','password':'synthetic'}}
            original=copy.deepcopy(record)
            catalog={'quick_check':True,'records':[record],'catalog_full_tables_sha256':'synthetic-fixed'}
            service=SimpleNamespace(configuration=SimpleNamespace(independent=True),store=Mock())
            service.store.all.return_value=[record]
            runtime=Mock();active=[None];payloads=[]
            runtime.state.side_effect=lambda _:active[0]
            runtime.owned.side_effect=lambda value:active[0] is not None and value is active[0]
            def ensure(value):
                self.assertEqual(record,original)
                self.assertEqual(value['proxy']['type'],'http')
                for key in ('host','port','username','password'):self.assertEqual(value['proxy'][key],original['proxy'][key])
                active[0]={'port':1234,'created':diagnostic.time.time()}
                return active[0]
            runtime.ensure.side_effect=ensure
            runtime.control.return_value=True
            runtime.stop_if_unused.side_effect=lambda _:active.__setitem__(0,None)
            def bounded(payload):
                payloads.append(copy.deepcopy(payload))
                return {'mode':payload['mode'],'stage':'complete','seconds':0,'statusclass':'2xx','error_type':None}
            with patch.object(verify_private_session,'load_marker',return_value=marker), \
                    patch.object(inspect_installation,'read_catalog',return_value=catalog), \
                    patch.object(browser_processes,'profile_processes',return_value=[]), \
                    patch.object(manager_service,'ManagerService',return_value=service), \
                    patch.object(proxy_runtime,'ProxyRuntime',return_value=runtime), \
                    patch.object(diagnostic,'bounded_attempt',side_effect=bounded),contextlib.redirect_stdout(io.StringIO()):
                report=diagnostic.run(root,'http')
            self.assertTrue(report['success']);self.assertTrue(report['saved_proxy_unchanged'])
            self.assertTrue(report['record_unchanged']);self.assertTrue(report['workers_closed'])
            self.assertFalse(report['browser_started']);self.assertFalse(report['authentication_test'])
            self.assertEqual(record,original);service.store.put.assert_not_called()
            self.assertEqual([value['mode'] for value in payloads],['upstream_http','production_relay']*3)
            self.assertEqual(runtime.stop_if_unused.call_count,3)

    def test_stage_deadline_exits_only_the_request_child_and_cleans_its_socket(self):
        import socks
        class Stopped(BaseException): pass
        callbacks = []
        def timer(delay, function, args):
            self.assertGreater(delay, 0)
            self.assertLessEqual(delay, diagnostic.HANDSHAKE_TIMEOUT)
            callbacks.append((function, args))
            return Mock()
        connection = Mock()
        connection.connect.side_effect = lambda *_: callbacks[-1][0](*callbacks[-1][1])
        payload = {'mode': 'upstream_socks5', 'host': 'page.example.invalid', 'port': 443,
                   'proxy': {'type': 'socks5', 'host': 'proxy.example.invalid', 'port': 1234}}
        with patch.object(diagnostic.threading, 'Timer', side_effect=timer), \
                patch.object(socks, 'socksocket', return_value=connection), \
                patch.object(diagnostic.os, 'write') as write, \
                patch.object(diagnostic.os, '_exit', side_effect=Stopped()) as exit_child, \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(Stopped): diagnostic.attempt(payload)
        exit_child.assert_called_once_with(0)
        row = json.loads(write.call_args.args[1])
        self.assertEqual(row['stage'], 'socks_handshake')
        self.assertEqual(row['error_type'], 'TimeoutError')
        connection.close.assert_called_once()
        budget = Mock()
        with patch.object(diagnostic.time, 'monotonic', return_value=4):
            diagnostic.socket_budget(budget, 6)
            budget.settimeout.assert_called_once_with(2)
            with self.assertRaises(TimeoutError): diagnostic.socket_budget(budget, 3)

    def test_preexisting_browser_or_live_proxy_is_refused_without_stopping_it(self):
        import browser_processes
        import inspect_installation
        import manager_service
        import proxy_runtime
        import verify_private_session
        with tempfile.TemporaryDirectory(prefix='private-network-guard-unit-') as temporary:
            root = Path(temporary).resolve()
            profile = root / 'app/data/profiles/profile-synthetic'
            profile.mkdir(parents=True)
            stable = {'synthetic': True}
            marker = {'profile_id': 'profile-synthetic', 'expected_stable_sha256': verify_private_session.digest(stable),
                      'target_origin': 'https://page.example.invalid'}
            record = {'id': 'profile-synthetic', '_native': {}, '_portable_crypt': {'synthetic': True},
                      '_continuity': {'stable': stable},
                      '_runtime': {'signature_provider': 'local-v1', 'profile_path': str(profile)},
                      'proxy': {'type': 'socks5', 'host': 'proxy.example.invalid', 'port': 1234}}
            catalog = {'quick_check': True, 'records': [record]}
            service = SimpleNamespace(configuration=SimpleNamespace(independent=True), store=Mock())
            service.store.all.return_value = [record]
            runtime = Mock()
            runtime.state.return_value = {'pid': 1234}
            runtime.owned.return_value = True
            for occupied in (True, False):
                runtime.reset_mock()
                with patch.object(verify_private_session, 'load_marker', return_value=marker), \
                        patch.object(inspect_installation, 'read_catalog', return_value=catalog), \
                        patch.object(browser_processes, 'profile_processes', return_value=[object()] if occupied else []), \
                        patch.object(manager_service, 'ManagerService', return_value=service) as constructor, \
                        patch.object(proxy_runtime, 'ProxyRuntime', return_value=runtime):
                    expected = verify_private_session.OwnershipError if occupied else diagnostic.DiagnosticError
                    with self.subTest(browser_occupied=occupied), self.assertRaises(expected): diagnostic.run(root)
                runtime.ensure.assert_not_called()
                runtime.stop_if_unused.assert_not_called()
                if occupied:
                    constructor.assert_not_called()
                    runtime.state.assert_not_called()
                else:
                    runtime.state.assert_called_once_with(record['id'])
                    runtime.owned.assert_called_once_with(runtime.state.return_value)

    def test_exception_and_report_write_failures_never_emit_private_messages_or_paths(self):
        secret = 'synthetic-private-account-address-or-path'
        with tempfile.TemporaryDirectory(prefix='private-network-output-unit-') as temporary:
            destination = Path(temporary) / 'anonymous.json'
            output = io.StringIO()
            argv = ['diagnostic', '--execute', '--package', temporary, '--report', str(destination)]
            with patch.object(sys, 'argv', argv), \
                    patch.object(diagnostic, 'run', side_effect=RuntimeError(secret)), \
                    patch.object(Path, 'write_text', side_effect=OSError(secret)), contextlib.redirect_stdout(output):
                self.assertEqual(diagnostic.main(), 1)
            result = json.loads(output.getvalue())
            self.assertEqual(result['error_type'], 'RuntimeError')
            self.assertEqual(result['report_error_type'], 'OSError')
            self.assertFalse(result['success'])
            self.assertNotIn(secret, output.getvalue())
            self.assertNotIn(temporary, output.getvalue())


if __name__ == '__main__':
    unittest.main()
