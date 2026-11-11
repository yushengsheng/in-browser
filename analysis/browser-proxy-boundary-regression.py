"""Real isolated browsers use only local proxy/origin fixtures; no user sites."""
import base64
import copy
from datetime import datetime,timedelta,timezone
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import select
import shutil
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
import traceback
from urllib.parse import urlsplit
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import psutil

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
from browser_core import DATA_ROOT,CDP,LocalBrowserError,profile_processes
from manager_service import ManagerService
from proxy_runtime import ProxyRuntime

DOMAIN='route.fixture.invalid'
PAGE_FAILURES=[]


def relay(a,b):
    a.settimeout(12);b.settimeout(12)
    end=time.monotonic()+35
    while time.monotonic()<end:
        ready,_,_=select.select([a,b],[],[],1)
        for source in ready:
            data=source.recv(65536)
            if not data:return
            (b if source is a else a).sendall(data)


class Origin(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    hits=[]
    def do_GET(self):
        type(self).hits.append(self.path)
        if self.path.startswith('/ws'):
            accept=base64.b64encode(hashlib.sha1((self.headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade');self.send_header('Sec-WebSocket-Accept',accept);self.end_headers()
            header=self.rfile.read(2);size=header[1]&127;mask=self.rfile.read(4);payload=self.rfile.read(size)
            payload=bytes(c^mask[i%4] for i,c in enumerate(payload))
            self.wfile.write(bytes([0x81,len(payload)])+payload);self.wfile.flush();return
        if self.path.startswith('/ip'):body=b'{"ip":"198.51.100.9"}';kind='application/json'
        elif self.path.startswith('/sw.js'):
            body=b"self.addEventListener('install',e=>e.waitUntil(self.skipWaiting()));self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));self.addEventListener('message',e=>e.waitUntil(fetch('/sw-data').then(r=>r.json()).then(v=>e.source.postMessage(v))));";kind='application/javascript'
        elif self.path.startswith('/data') or self.path.startswith('/sw-data'):body=b'{"ok":true}';kind='application/json'
        else:body=b'<!doctype html><title>Local proxy boundary</title><body>Local fixture</body>';kind='text/html'
        self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)));self.send_header('Access-Control-Allow-Origin','*');self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(body)
    def log_message(self,*_):pass


class Proxy(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    requests=[]
    available=True
    def handle_route(self):
        if not type(self).available:self.send_error(502);return
        expected='Basic '+base64.b64encode(b'fixture:password').decode()
        if self.headers.get('Proxy-Authorization')!=expected:
            self.send_error(407);return
        tunnel=self.command=='CONNECT';parsed=urlsplit('//'+self.path if tunnel else self.path)
        if parsed.hostname not in (DOMAIN,'127.0.0.1','localhost') or not parsed.port:
            self.send_error(502);return
        type(self).requests.append({'tunnel':tunnel,'loopback_target':parsed.hostname in ('127.0.0.1','localhost')})
        remote=None
        try:
            remote=socket.create_connection(('127.0.0.1',parsed.port),timeout=3)
            if tunnel:self.send_response(200);self.end_headers()
            else:
                target=(parsed.path or '/')+('?' + parsed.query if parsed.query else '')
                headers=[(k,v) for k,v in self.headers.items() if k.lower() not in ('proxy-authorization','proxy-connection','connection')]
                upgrade=self.headers.get('Upgrade','').lower()=='websocket'
                request=self.command+' '+target+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers)+('Connection: Upgrade\r\n' if upgrade else 'Connection: close\r\n')+'\r\n'
                remote.sendall(request.encode('latin-1'))
            relay(self.connection,remote)
        except (OSError,ValueError):pass
        finally:
            if remote:remote.close()
            self.close_connection=True
    do_GET=handle_route
    do_CONNECT=handle_route
    def log_message(self,*_):pass


class Socks(socketserver.BaseRequestHandler):
    domains=[]
    available=True
    def handle(self):
        if not type(self).available:return
        c=self.request;remote=None;c.settimeout(8)
        def take(n):
            result=b''
            while len(result)<n:
                value=c.recv(n-len(result))
                if not value:raise OSError()
                result+=value
            return result
        try:
            version,count=take(2);methods=take(count)
            if version!=5 or 2 not in methods:return
            c.sendall(b'\x05\x02');version=take(1);user=take(take(1)[0]);password=take(take(1)[0])
            if user!=b'fixture' or password!=b'password':c.sendall(b'\x01\x01');return
            c.sendall(b'\x01\x00');version,cmd,reserved,kind=take(4)
            if cmd!=1:return
            if kind==3:host=take(take(1)[0]).decode();type(self).domains.append(host)
            elif kind==1:host=socket.inet_ntoa(take(4))
            elif kind==4:host=socket.inet_ntop(socket.AF_INET6,take(16))
            else:return
            port=struct.unpack('>H',take(2))[0]
            if host not in (DOMAIN,'127.0.0.1','localhost','::1'):return
            remote=socket.create_connection(('127.0.0.1',port),timeout=3)
            c.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00');relay(c,remote)
        except (OSError,ValueError):pass
        finally:
            if remote:remote.close()


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True


def start(server):
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();return server


def evaluate(service,identity,url,expression):
    with CDP(service.controller.endpoint(identity),timeout=18) as c:
        target=c.call('Target.createTarget',{'url':'about:blank'})['targetId'];session=c.call('Target.attachToTarget',{'targetId':target,'flatten':True})['sessionId']
        c.call('Security.enable',session=session)
        # The generated fixture certificate is trusted only in this disposable
        # test browser, never in the real profile, runtime or Windows trust store.
        c.call('Security.setIgnoreCertificateErrors',{'ignore':True},session=session)
        c.call('Page.navigate',{'url':url},session=session)
        end=time.monotonic()+10
        while time.monotonic()<end:
            result=c.call('Runtime.evaluate',{'expression':'location.href===EXPECTED && document.readyState==="complete"'.replace('EXPECTED',json.dumps(url)),'returnByValue':True},session=session)
            if result.get('result',{}).get('value'):break
            time.sleep(.1)
        result=c.call('Runtime.evaluate',{'expression':expression,'awaitPromise':True,'returnByValue':True},session=session)
        if result.get('exceptionDetails'):
            details=result['exceptionDetails'];description=str((details.get('exception') or {}).get('description') or '')
            category=next((word for word in ['timeout','Failed to fetch','ws','SecurityError','TypeError'] if word in description),'script')
            text=c.call('Runtime.evaluate',{'expression':'document.body?.innerText||""','returnByValue':True},session=session).get('result',{}).get('value','')
            import re
            PAGE_FAILURES.extend(re.findall(r'ERR_[A-Z_]+',str(text)))
            raise AssertionError('local_browser_script_'+category)
        return result.get('result',{}).get('value')


def main():
    work=DATA_ROOT/('proxy-boundary-'+uuid.uuid4().hex);work.mkdir();service=None;servers=[];report={'checks':{},'success':False}
    source=ManagerService();originals=[];udp=None;udp_thread=None;udp_stop=threading.Event();udp_packets=[]
    def check(name,value):
        report['checks'][name]=bool(value)
        if not value:raise AssertionError(name)
    try:
        for name in ['.portable-vault','local-signing']:shutil.copytree(DATA_ROOT/name,work/name)
        for name in ['.portable-vault.lock','local-signing.lock','portable-mode.bin','independent-mode.bin']:
            if (DATA_ROOT/name).is_file():shutil.copy2(DATA_ROOT/name,work/name)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,DOMAIN)])
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=2)).add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]),False).sign(key,hashes.SHA256())
        certfile=work/'fixture.pem';keyfile=work/'fixture-key.pem';certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM));keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        pin=base64.b64encode(hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
        http=start(ThreadingHTTPServer(('127.0.0.1',0),Origin));servers.append(http)
        secure=ThreadingHTTPServer(('127.0.0.1',0),Origin);tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(certfile,keyfile);secure.socket=tls.wrap_socket(secure.socket,server_side=True);start(secure);servers.append(secure)
        hp=ThreadingHTTPServer(('127.0.0.1',0),Proxy);start(hp);servers.append(hp)
        sp=TCP(('127.0.0.1',0),Socks);start(sp);servers.append(sp)
        udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));udp.settimeout(.2)
        udp_port=udp.getsockname()[1]
        def receive_udp():
            while not udp_stop.is_set():
                try:udp.recvfrom(4096);udp_packets.append(True)
                except socket.timeout:pass
                except OSError:return
        udp_thread=threading.Thread(target=receive_udp,daemon=True);udp_thread.start()
        rows=[];service=ManagerService(work)
        for major in ['124','148']:
            original=next(p for p in source.store.all() if str(p['_runtime']['core_major'])==major and not profile_processes(Path(p['_runtime']['profile_path'])))
            original_path=Path(original['_runtime']['profile_path']);originals.append((original_path,source._manifest(original_path)))
            record=copy.deepcopy(original);profile=work/'profiles'/record['id'];service._copy_profile(original_path,profile)
            record['_runtime'].update(profile_path=str(profile),restore_session=False,initial_urls=[],open_urls_once=[],account_platform='',account_username='',account_password='')
            record['preferences']['restore_session']=False
            record['_runtime']['launch_args']=['--disable-background-networking','--ignore-certificate-errors-spki-list='+pin]
            rows.append(record)
        service.configuration._proxy_targets=[{'name':'local fixture','url':f'http://{DOMAIN}:{http.server_port}/ip'}]
        for kind,upstream in [('http',hp),('socks5',sp)]:
            for template in rows:
                record=copy.deepcopy(template);major=str(record['_runtime']['core_major']);record['proxy']={'type':kind,'host':'127.0.0.1','port':upstream.server_address[1],'username':'fixture','password':'password','enable_socks5_udp':False}
                service.store.put(record);service._sync(record);identity=record['id'];service.open(identity,extra_urls=['about:blank'])
                prefix=major+'_'+kind
                http_url=f'http://{DOMAIN}:{http.server_port}/page';https_url=f'https://{DOMAIN}:{secure.server_port}/page'
                expression='''(async()=>{const data=await fetch('/data?fresh='+Date.now()).then(r=>r.json());const ws=await new Promise((resolve,reject)=>{const s=new WebSocket('ws://'+location.host+'/ws');const t=setTimeout(()=>reject(Error('timeout')),7000);s.onopen=()=>s.send('fixture');s.onmessage=e=>{clearTimeout(t);s.close();resolve(e.data==='fixture')};s.onerror=()=>reject(Error('ws'))});return {fetch:data.ok,websocket:ws}})()'''
                result=evaluate(service,identity,http_url,expression);check(prefix+'_http_and_websocket',result=={'fetch':True,'websocket':True})
                result=evaluate(service,identity,https_url,"fetch('/data?fresh='+Date.now()).then(r=>r.json()).then(v=>v.ok)");check(prefix+'_https',result is True)
                expression='''(async()=>{await navigator.serviceWorker.register('/sw.js');const r=await navigator.serviceWorker.ready;return await new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(Error('timeout')),7000);navigator.serviceWorker.onmessage=e=>{clearTimeout(t);resolve(e.data.ok)};r.active.postMessage('probe')})})()'''
                result=evaluate(service,identity,f'http://localhost:{http.server_port}/page',expression);check(prefix+'_serviceworker_uses_proxy',result is True)
                before_udp=len(udp_packets)
                expression='''(async()=>{if(typeof RTCPeerConnection==='undefined')return {disabled:true,count:0};let pc;try{pc=new RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.1:PORT'}]});const candidates=[];pc.onicecandidate=e=>{if(e.candidate)candidates.push(e.candidate.candidate)};pc.createDataChannel('fixture');await pc.setLocalDescription(await pc.createOffer());await new Promise(r=>setTimeout(r,1600));return{disabled:false,count:candidates.length}}catch(e){return{disabled:true,count:0}}finally{pc?.close()}})()'''.replace('PORT',str(udp_port))
                rtc=evaluate(service,identity,'about:blank',expression)
                check(prefix+'_webrtc_has_no_direct_stun_udp',len(udp_packets)==before_udp and rtc['count']==0)
                fixture=Proxy if kind=='http' else Socks
                try:
                    fixture.available=False;before_upstream=sum(path.startswith('/upstream-must-not-direct') for path in Origin.hits)
                    expression='fetch(URL).then(r=>r.ok).catch(()=>false)'.replace('URL',json.dumps(f'http://127.0.0.1:{http.server_port}/upstream-must-not-direct?'+uuid.uuid4().hex))
                    failed=evaluate(service,identity,'about:blank',expression)
                    check(prefix+'_upstream_failure_never_connects_direct',failed is False and sum(path.startswith('/upstream-must-not-direct') for path in Origin.hits)==before_upstream)
                finally:fixture.available=True
                before=sum(path.startswith('/must-not-direct') for path in Origin.hits);state=service.proxy_runtime.state(identity);pid=state['pid'];check(prefix+'_relay_is_owned',ProxyRuntime.owned(state))
                psutil.Process(pid).terminate();psutil.Process(pid).wait(timeout=8)
                expression='''fetch(URL).then(()=>true).catch(()=>false)'''.replace('URL',json.dumps(f'http://127.0.0.1:{http.server_port}/must-not-direct?'+uuid.uuid4().hex))
                failed=evaluate(service,identity,'about:blank',expression)
                check(prefix+'_relay_failure_never_connects_direct',failed is False and sum(path.startswith('/must-not-direct') for path in Origin.hits)==before)
                service=ManagerService(work);service.configuration._proxy_targets=[{'name':'local fixture','url':f'http://{DOMAIN}:{http.server_port}/ip'}]
                service.open(identity,extra_urls=['about:blank'])
                restored=service.proxy_runtime.state(identity);check(prefix+'_manager_restart_restores_same_proxy_port',restored['port']==state['port'] and restored['pid']!=pid)
                result=evaluate(service,identity,http_url,"fetch('/data?new='+Date.now()).then(r=>r.json()).then(v=>v.ok)")
                check(prefix+'_requests_resume_through_proxy',result is True)
                service.close(identity);print(json.dumps({'completed':prefix}),flush=True)
        check('socks_target_domain_sent_to_upstream',DOMAIN in Socks.domains)
        check('proxy_connect_used_for_secure_pages',any(row['tunnel'] for row in Proxy.requests))
        check('all_original_profile_files_unchanged',all(source._manifest(path)==before for path,before in originals))
        report['success']=all(report['checks'].values())
    except Exception as error:
        report.update(error_type=type(error).__name__,frames=[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)])
        if isinstance(error,LocalBrowserError):report['safe_error']=str(error)
        if isinstance(error,AssertionError):report['check_error']=str(error)
        report['fixture_counts']={'origin':len(Origin.hits),'proxy':len(Proxy.requests),'proxy_tunnels':sum(row['tunnel'] for row in Proxy.requests)}
        report['page_failure_tokens']=PAGE_FAILURES
    finally:
        if service:
            for record in service.store.all():
                try:service.close(record['id'])
                except Exception:pass
        for server in servers:
            try:server.shutdown();server.server_close()
            except Exception:pass
        udp_stop.set()
        if udp:udp.close()
        if udp_thread:udp_thread.join(timeout=2)
        remaining=sum(len(profile_processes(p)) for p in (work/'profiles').glob('*') if p.is_dir());report['remaining_test_processes']=remaining
        if work.exists() and work.resolve().parent==DATA_ROOT.resolve() and not remaining:shutil.rmtree(work)
        report['sandbox_removed']=not work.exists();report['success']=report['success'] and report['sandbox_removed']
        Path(__file__).with_name('browser-proxy-boundary-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(report,ensure_ascii=True))


if __name__=='__main__':main()
