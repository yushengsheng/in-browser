"""Local fixtures cover authentication, HTTP bodies, tunnels and fail-closed routing."""
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import shutil
import socket
import sys
import time
import uuid
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from browser_core import DATA_ROOT
from proxy_runtime import CONTROL, Worker


async def pump(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def tunnel(a, b, c, d):
    tasks=[asyncio.create_task(pump(a,d)),asyncio.create_task(pump(c,b))]
    try:
        await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)


class Fixtures:
    def __init__(self):
        self.requests=[]
        self.socks_domains=[]
        self.connections=set()

    async def target(self,reader,writer):
        self.connections.add(writer)
        try:
            header=await reader.readuntil(b'\r\n\r\n');lines=header.decode().split('\r\n')
            headers={k.lower():v.strip() for k,v in (line.split(':',1) for line in lines[1:] if line)}
            if lines[0].split()[1]=='/socket':
                if headers.get('connection','').lower()!='upgrade' or headers.get('upgrade','').lower()!='websocket':return
                writer.write(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');await writer.drain()
                data=await reader.readexactly(8);writer.write(data);await writer.drain();return
            body=b''
            if headers.get('transfer-encoding')=='chunked':
                while True:
                    size=int((await reader.readline()).strip(),16)
                    if not size:
                        await reader.readexactly(2);break
                    body+=await reader.readexactly(size);await reader.readexactly(2)
            elif headers.get('content-length'):
                body=await reader.readexactly(int(headers['content-length']))
            self.requests.append({'path':lines[0].split()[1],'body_size':len(body),'proxy_auth_leaked':'proxy-authorization' in headers})
            result=json.dumps(self.requests[-1]).encode()
            writer.write(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(result)).encode()+b'\r\n\r\n'+result)
            await writer.drain()
        finally:
            writer.close();self.connections.discard(writer)

    async def http_proxy(self,reader,writer):
        self.connections.add(writer);remote=None
        try:
            header=await reader.readuntil(b'\r\n\r\n');lines=header.decode().split('\r\n')
            auth=base64.b64encode(b'fixture:password').decode()
            if not any(line.lower()=='proxy-authorization: basic '+auth.lower() for line in lines):
                writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');await writer.drain();return
            method,target,version=lines[0].split();parsed=urlsplit('//' + target if method=='CONNECT' else target)
            upstream,remote=await asyncio.open_connection('127.0.0.1',parsed.port)
            if method=='CONNECT':
                writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n');await writer.drain()
            else:
                clean=[line for line in lines[1:] if line and not line.lower().startswith('proxy-authorization:')]
                remote.write((method+' '+(parsed.path or '/')+('?' + parsed.query if parsed.query else '')+' '+version+'\r\n'+'\r\n'.join(clean)+'\r\n\r\n').encode());await remote.drain()
            await tunnel(reader,writer,upstream,remote)
        finally:
            writer.close();self.connections.discard(writer)
            if remote:remote.close()

    async def socks_proxy(self,reader,writer):
        self.connections.add(writer);remote=None
        try:
            version,n=await reader.readexactly(2);await reader.readexactly(n);writer.write(b'\x05\x02');await writer.drain()
            version,n=await reader.readexactly(2);username=await reader.readexactly(n);n=(await reader.readexactly(1))[0];password=await reader.readexactly(n)
            valid=username==b'fixture' and password==b'password';writer.write(b'\x01'+(b'\x00' if valid else b'\x01'));await writer.drain()
            if not valid:return
            version,command,reserved,kind=await reader.readexactly(4)
            if kind==3:
                size=(await reader.readexactly(1))[0];domain=(await reader.readexactly(size)).decode()
            elif kind==1:domain=socket.inet_ntop(socket.AF_INET,await reader.readexactly(4))
            else:domain=socket.inet_ntop(socket.AF_INET6,await reader.readexactly(16))
            port=int.from_bytes(await reader.readexactly(2),'big');self.socks_domains.append(domain)
            upstream,remote=await asyncio.open_connection('127.0.0.1',port)
            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00');await writer.drain()
            await tunnel(reader,writer,upstream,remote)
        finally:
            writer.close();self.connections.discard(writer)
            if remote:remote.close()


async def exchange(port,target_port,mode='get',token=None):
    reader,writer=await asyncio.open_connection('127.0.0.1',port)
    try:
        if mode=='control':
            request='POST '+CONTROL+'ping HTTP/1.1\r\nHost: localhost\r\nX-Local-Token: '+token+'\r\nContent-Length: 0\r\n\r\n'
            writer.write(request.encode())
        else:
            if mode=='connect':
                writer.write(('CONNECT fixture.invalid:'+str(target_port)+' HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n').encode());await writer.drain()
                response=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),5)
                if b' 200 ' not in response:return {'code':int(response.split()[1])}
                target='/tunnel'
            else:target='http://fixture.invalid:'+str(target_port)+('/socket' if mode=='websocket' else '/state?q=1')
            method='POST' if mode=='post' else 'GET'
            extra='Transfer-Encoding: chunked\r\n' if mode=='post' else ''
            if mode=='websocket':extra+='Upgrade: websocket\r\n'
            proxy_header='' if mode=='connect' else 'Proxy-Authorization: Basic must-not-leak\r\n'
            writer.write((method+' '+target+' HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n'+proxy_header+extra+'\r\n').encode())
            if mode=='post':writer.write(b'10000\r\n'+b'x'*65536+b'\r\n10000\r\n'+b'y'*65536+b'\r\n0\r\n\r\n')
        await writer.drain();header=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),8)
        if mode=='websocket' and b' 101 ' in header:
            writer.write(b'ws-proof');await writer.drain()
            return {'code':101,'echo':await reader.readexactly(8)==b'ws-proof'}
        code=int(header.split()[1]);length=int(next(line.split(b':',1)[1] for line in header.split(b'\r\n') if line.lower().startswith(b'content-length:')))
        body=await asyncio.wait_for(reader.readexactly(length),8)
        return {'code':code,'body':json.loads(body) if body else {}}
    finally:
        writer.close();await writer.wait_closed()


async def run():
    report={'checks':{},'success':False};fixture=Fixtures();servers=[];workers=[]
    def check(name,value):
        report['checks'][name]=bool(value)
        if not value:raise AssertionError(name)
    try:
        target=await asyncio.start_server(fixture.target,'127.0.0.1',0);servers.append(target);target_port=target.sockets[0].getsockname()[1]
        for kind,handler in [('socks5',fixture.socks_proxy),('http',fixture.http_proxy)]:
            upstream=await asyncio.start_server(handler,'127.0.0.1',0);servers.append(upstream)
            for authenticated in (True,False):
                label=kind+('_valid' if authenticated else '_bad_auth')
                config={'identity':'fixture','token':'control-fixture-token','instance':uuid.uuid4().hex,'digest':'fixture-digest',
                        'proxy':{'type':kind,'host':'127.0.0.1','port':upstream.sockets[0].getsockname()[1],
                                 'username':'fixture','password':'password' if authenticated else 'incorrect'}}
                worker=Worker(Path('.'),config);worker.state={'instance':config['instance'],'digest':config['digest']};workers.append(worker)
                server=await asyncio.start_server(worker.handle,'127.0.0.1',0,limit=32768);servers.append(server);port=server.sockets[0].getsockname()[1]
                start_count=len(fixture.requests)
                if authenticated:
                    for mode in ('get','post','connect'):
                        result=await exchange(port,target_port,mode)
                        check(label+'_'+mode+'_forwarded',result['code']==200 and not result['body']['proxy_auth_leaked'])
                        if mode=='post':check(label+'_chunked_body_preserved',result['body']['body_size']==131072)
                    result=await exchange(port,target_port,'websocket')
                    check(label+'_websocket_upgrade_and_bidirectional_bytes',result['code']==101 and result.get('echo'))
                    check(label+'_control_token_required',(await exchange(port,target_port,'control','wrong-token'))['code']==403)
                    check(label+'_control_authenticated',(await exchange(port,target_port,'control',config['token']))['code']==200)
                else:
                    result=await exchange(port,target_port,'connect');check(label+'_failure_closed',result['code']==502 and len(fixture.requests)==start_count)
                server.close();await server.wait_closed()
                for writer in list(worker.connections):writer.close()
        check('socks_destination_dns_is_remote',fixture.socks_domains and all(name=='fixture.invalid' for name in fixture.socks_domains))
        await asyncio.sleep(.1)
        report['success']=all(report['checks'].values())
    except Exception as exc:
        report['error_type']=type(exc).__name__
        if isinstance(exc,AssertionError):report['failed_check']=str(exc)
    finally:
        for server in servers:server.close()
        for server in servers:await server.wait_closed()
        for worker in workers:
            for writer in list(worker.connections):writer.close()
        for writer in fixture.connections:writer.close()
        await asyncio.sleep(.1)
    return report


if __name__=='__main__':
    report=asyncio.run(run())
    Path(__file__).with_name('proxy-runtime-protocol-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False))
