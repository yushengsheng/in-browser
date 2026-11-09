"""Synthetic provider extraction, deadlines and preserved imported behavior."""
import copy
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from dynamic_proxy import fetch_proxy,parse_result,prepare_dynamic_proxy,validate_url
from local_state import LocalBrowserError


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_GET(self):
        self.server.hits.append(self.path)
        try:
            if self.path=='/redirect':
                self.send_response(302);self.send_header('Location','/ok');self.end_headers();return
            self.send_response(200);self.end_headers()
            if self.path=='/slow':
                while not self.server.stop.wait(.15):self.wfile.write(b' ');self.wfile.flush()
            else:self.wfile.write(b'{"data":[{"ip":"fixture.invalid","port":1080}]}')
        except OSError:pass


class DynamicProxyTests(unittest.TestCase):
    def test_common_provider_formats_and_private_fallback(self):
        for raw in ('fixture.invalid:1080',json.dumps({'data':[{'ip':'fixture.invalid','port':1080}]}),
                    json.dumps({'data':'fixture.invalid:1080\n'})):
            result=parse_result(raw,'socks5',{'username':'fixture','password':'synthetic'})
            self.assertEqual((result['host'],result['port'],result['username'],result['password']),
                ('fixture.invalid',1080,'fixture','synthetic'))
        for raw in ('fixture.invalid:1080\nother.invalid:1080','{}','[]',json.dumps({'success':False,'data':'fixture.invalid:1080'})):
            with self.subTest(raw=raw),self.assertRaises((ValueError,LocalBrowserError)):parse_result(raw,'http')

    def test_url_validation_rejects_files_and_header_injection(self):
        for value in ('file:///test','ftp://fixture.invalid/path','http://fixture.invalid/\r\nHeader: synthetic'):
            with self.assertRaises(LocalBrowserError):validate_url(value)

    def test_process_bounds_stream_and_does_not_follow_redirect(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
        server.hits=[];server.stop=threading.Event()
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            url=f'http://127.0.0.1:{server.server_port}'
            self.assertEqual(fetch_proxy(url+'/ok','http')['type'],'http')
            with self.assertRaises(LocalBrowserError):fetch_proxy(url+'/redirect')
            self.assertEqual(server.hits,['/ok','/redirect'])
            started=time.monotonic()
            with self.assertRaises(LocalBrowserError):fetch_proxy(url+'/slow')
            self.assertLess(time.monotonic()-started,11.5)
        finally:server.stop.set();server.shutdown();server.server_close();thread.join(timeout=2)

    def test_new_proxy_is_persisted_without_fingerprint_or_profile_changes(self):
        record={'id':'synthetic','created_locally':True,'created_options':{'dynamic_proxy_url':'https://fixture.invalid/','dynamic_proxy_type':'http'},
            'fingerprint':{'unchanged':True},'_native':{'unchanged':True},'_portable_crypt':{'unchanged':True},
            '_runtime':{'local_proxy_port':1234},'proxy':{'type':'noproxy'}}
        before=copy.deepcopy(record);service=SimpleNamespace(_closed=Mock(),proxy_runtime=SimpleNamespace(stop_if_unused=Mock()),
            _runtime=lambda p,old:copy.deepcopy(old),store=SimpleNamespace(put=Mock()),_sync=Mock())
        with patch('dynamic_proxy.fetch_proxy',return_value={'type':'http','host':'fixture.invalid','port':1080}):
            updated=prepare_dynamic_proxy(service,record)
        self.assertEqual(record,before)
        for field in ('fingerprint','_native','_portable_crypt'):self.assertEqual(updated[field],record[field])
        self.assertNotIn('local_proxy_port',updated['_runtime'])
        service.store.put.assert_called_once()
        imported=copy.deepcopy(record);imported.pop('created_locally')
        with patch('dynamic_proxy.fetch_proxy',side_effect=AssertionError()):self.assertIs(prepare_dynamic_proxy(None,imported),imported)


if __name__=='__main__':unittest.main(verbosity=2)
