"""Local synthetic proxy probes; no real proxy, account, or public request."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import proxy_check


@contextmanager
def server(handler):
    service=ThreadingHTTPServer(('127.0.0.1',0),handler)
    service.daemon_threads=True
    service.hits=[];service.stop=threading.Event()
    thread=threading.Thread(target=service.serve_forever,daemon=True);thread.start()
    try:yield service
    finally:
        service.stop.set();service.shutdown();service.server_close();thread.join(timeout=2)


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*_):pass

    def reply(self,status=200,body=b'{"ip":"203.0.113.7"}',**headers):
        self.send_response(status)
        for name,value in headers.items():self.send_header(name,value)
        self.send_header('Content-Length',str(len(body)));self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.hits.append(self.path)
        try:
            if self.path.endswith('/redirect'):
                self.reply(302,Location=self.server.redirect)
            elif self.path.endswith('/bad'):
                self.reply(body=b'not-json')
            elif self.path.endswith('/first'):
                self.server.stop.wait(4)
                self.reply(body=b'not-json')
            elif self.path.endswith('/drip'):
                self.send_response(200);self.send_header('Content-Length','65536');self.end_headers()
                while not self.server.stop.wait(.15):
                    self.wfile.write(b' ');self.wfile.flush()
            elif self.path.endswith('/auth'):
                self.reply(407,body=b'')
            else:self.reply()
        except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError,OSError):pass


def proxy(service):
    return {'type':'http','host':'127.0.0.1','port':service.server_port,'username':'','password':''}


def targets(*paths):
    return [{'name':'synthetic','url':'http://never-resolve.invalid/'+path} for path in paths]


class ProxyDeadlineTests(unittest.TestCase):
    def test_success_uses_configured_proxy_and_ignores_environment_proxy(self):
        with server(Handler) as service,patch.dict('os.environ',{'HTTP_PROXY':'http://127.0.0.1:1','HTTPS_PROXY':'http://127.0.0.1:1','NO_PROXY':'*'}):
            result=proxy_check.ProxyChecker(targets=targets('ok')).test(proxy(service))
        self.assertTrue(result['success'])
        self.assertEqual(result['egress_ip'],'203.0.113.7')
        self.assertEqual(service.hits,['http://never-resolve.invalid/ok'])

    def test_redirect_and_invalid_response_fallback_keep_same_proxy(self):
        with server(Handler) as trap,server(Handler) as service:
            service.redirect=f'http://127.0.0.1:{trap.server_port}/unexpected'
            result=proxy_check.ProxyChecker(targets=targets('redirect','bad','ok')).test(proxy(service))
        self.assertTrue(result['success'])
        self.assertEqual(len(service.hits),3)
        self.assertEqual(trap.hits,[])

    def test_authentication_failure_never_falls_back_to_direct(self):
        with server(Handler) as trap,server(Handler) as service:
            candidates=[{'name':'synthetic','url':f'http://127.0.0.1:{trap.server_port}/auth'}]
            result=proxy_check.ProxyChecker(targets=candidates).test(proxy(service))
        self.assertFalse(result['success'])
        self.assertEqual(result['attempts'],1)
        self.assertEqual(trap.hits,[])
        self.assertEqual(len(service.hits),1)

    def test_all_fallbacks_and_slow_drip_share_ten_seconds_and_worker_exits(self):
        children=[]
        original=proxy_check.subprocess.Popen
        def launch(*args,**kwargs):
            child=original(*args,**kwargs);children.append(child);return child
        with server(Handler) as service,patch.object(proxy_check.subprocess,'Popen',side_effect=launch):
            started=time.monotonic()
            result=proxy_check.ProxyChecker(targets=targets('first','drip')).test(proxy(service))
            elapsed=time.monotonic()-started
        self.assertFalse(result['success'])
        self.assertTrue(result.get('timed_out'))
        self.assertIn('10秒',result['message'])
        self.assertGreaterEqual(elapsed,9.5)
        self.assertLess(elapsed,10.8)
        self.assertEqual(len(service.hits),2)
        self.assertTrue(children and all(child.poll() is not None for child in children))

    def test_result_arriving_after_deadline_is_not_success(self):
        class Child:
            returncode=0
            def communicate(self,input=None,timeout=None):
                if input is not None:time.sleep(.04)
                return json.dumps({'success':True,'egress_ip':'203.0.113.7'}).encode(),b''
            def poll(self):return self.returncode
        with patch.object(proxy_check,'CHECK_TIMEOUT',.02),patch.object(proxy_check.subprocess,'Popen',return_value=Child()):
            result=proxy_check.ProxyChecker(targets=targets('ok')).test({'type':'noproxy'})
        self.assertFalse(result['success'])
        self.assertTrue(result.get('timed_out'))


if __name__=='__main__':unittest.main(verbosity=2)
