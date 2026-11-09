"""Explicit synthetic login retention and opt-in creation settings acceptance."""
import argparse
import copy
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
import traceback
from urllib.parse import urlsplit
import uuid
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_GET(self):
        route=urlsplit(self.path).path
        self.server.hits.append(route)
        if route=='/extract':body=json.dumps({'data':[{'ip':'127.0.0.1','port':self.server.server_port}]}).encode()
        elif route in ('/geo','/probe'):
            body=json.dumps({'ip':'192.0.2.1','timezone':self.server.timezone,'languages':'en-US,en',
                'country_code':'US','latitude':30,'longitude':-90}).encode()
        else:body=b'<!doctype html><title>Synthetic local session</title><p>Local test only</p>'
        self.send_response(200);self.send_header('Content-Length',str(len(body)))
        self.send_header('Content-Type','application/json' if route in ('/extract','/geo','/probe') else 'text/html')
        self.end_headers()
        try:self.wfile.write(body)
        except OSError:pass


def evaluate(connection,session,expression):
    reply=connection.call('Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True},session=session)
    if reply.get('exceptionDetails'):raise ValueError()
    return reply.get('result',{}).get('value')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    if not args.execute:print(json.dumps({'executed':False}));return 0
    report={'success':False,'synthetic':True,'results':[]};service=None;owned=[];server=None
    try:
        marker=ROOT/'local-creation-test.json'
        if marker.is_symlink() or json.loads(marker.read_text())!={'format':1,'purpose':'isolated-local-creation'}:raise ValueError()
        sys.path.insert(0,str(ROOT/'app'))
        from installation import initialize_installation
        from manager_service import ManagerService
        from creation_fingerprint import creation_defaults
        from browser_core import CDP
        from proxy_check import ProxyChecker
        initialize_installation();service=ManagerService()
        if any(not p.get('created_locally') or p.get('username') or p.get('password') or p.get('cookie_text') for p in service.store.all()):raise ValueError()
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True;server.hits=[];server.timezone='Etc/UTC'
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        origin=f'http://127.0.0.1:{server.server_port}';url=origin+'/account'
        service.configuration._proxy_targets=[{'name':'synthetic','url':'http://fixture.invalid/probe'}]
        def local_geo(proxy):
            result=ProxyChecker(targets=[{'name':'synthetic','url':'http://fixture.invalid/geo'}],require_geo=True).test(proxy)
            if not result.get('success'):raise ValueError()
            return result['geo']
        with patch('window_create.resolve_geo',local_geo),patch('created_window.resolve_geo',local_geo):
            for core in ('104','148'):
                p=creation_defaults(core);p.update(name='Synthetic login retention',urls=[url])
                p['cookie_text']=json.dumps([{'name':'synthetic_session','value':'fixture','url':url,'httpOnly':True,'expires':int(time.time())+86400}])
                p['created_options'].update(random_each_open=True,workbench='disable',
                    dynamic_proxy_url=origin+'/extract',dynamic_proxy_type='http')
                p['fingerprint'].update(isIpCreateLanguage=True,isIpCreateTimeZone=True,isIpCreatePosition=True)
                creator=service.creator();job=creator.start({'request_id':uuid.uuid4().hex,'profile':p,'count':1,'random_each':True})
                deadline=time.monotonic()+300
                while job['state']=='running' and time.monotonic()<deadline:
                    time.sleep(.2);job=creator.status(job['job_id'])
                if job['state']!='completed':raise ValueError()
                identity=job['items'][0]['id'];owned.append(identity)
                before=service.store.get(identity);previous=before['_native'];row={'core':core,'rounds':[]};report['results'].append(row)
                for index in range(2):
                    server.timezone='Etc/UTC' if index==0 else 'America/Chicago'
                    service.open(identity)
                    after=service.store.get(identity)
                    with CDP(service.controller.endpoint(identity)) as connection:
                        deadline=time.monotonic()+15;session=None
                        while time.monotonic()<deadline:
                            pages=connection.call('Target.getTargets')['targetInfos']
                            page=next((t for t in pages if t['type']=='page' and t['url']==url),None)
                            if page:
                                session=connection.call('Target.attachToTarget',{'targetId':page['targetId'],'flatten':True})['sessionId']
                                if evaluate(connection,session,'document.readyState==="complete"'):break
                                connection.call('Target.detachFromTarget',{'sessionId':session});session=None
                            time.sleep(.1)
                        if session is None:raise ValueError()
                        try:
                            if index==0:evaluate(connection,session,'localStorage.setItem("synthetic_session","fixture");true')
                            local_storage=evaluate(connection,session,'localStorage.getItem("synthetic_session")==="fixture"')
                            cookies=connection.call('Storage.getCookies')['cookies']
                            cookie=any(c['name']=='synthetic_session' and c['value']=='fixture' and c['httpOnly'] for c in cookies)
                            timezone=evaluate(connection,session,'Intl.DateTimeFormat().resolvedOptions().timeZone')
                        finally:connection.call('Target.detachFromTarget',{'sessionId':session})
                    service.close(identity)
                    checks={'cookie_preserved':cookie,'local_storage_preserved':local_storage,
                        'protection_key_preserved':after['_native'].get('DataProtect')==before['_native'].get('DataProtect'),
                        'oscrypt_key_preserved':after['_portable_crypt']==before['_portable_crypt'],
                        'fingerprint_randomized':after['_native']['canvasContext']!=previous['canvasContext'],
                        'ip_timezone_applied':timezone in (server.timezone,'UTC' if index==0 else server.timezone),
                        'dynamic_proxy_applied':after['proxy']['type']=='http' and after['proxy']['port']==server.server_port}
                    row['rounds'].append(checks)
                    if not all(checks.values()):raise ValueError()
                    previous=after['_native']
                row['delete_complete']=service.delete(identity).get('cleanup_complete') is True
                if not row['delete_complete']:raise ValueError()
                owned.remove(identity)
            report['provider_requests']=server.hits.count('/extract')
            report['proxy_geo_requests']=server.hits.count('/geo')
            report['success']=True
    except Exception as error:
        report['error_type']=type(error).__name__
        report['frames']=[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)[-6:]]
    finally:
        if service:
            for identity in owned:
                try:service.close(identity)
                except Exception:report['normal_close_failed']=True;report['success']=False
        if server:server.shutdown();server.server_close()
        path=ROOT/'analysis/reports/creation-options-live.json';path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
    return 0 if report['success'] else 1


if __name__=='__main__':raise SystemExit(main())
