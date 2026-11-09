"""Optional asynchronous SSH forwarding with per-window host-key pinning."""
import asyncio
from contextlib import contextmanager
import hashlib
import hmac
from pathlib import Path
import threading

from local_state import read_encrypted,write_encrypted
from delete_paths import checked


class SSHConnector:
    def __init__(self,root,config,*,transient=False):
        self.root=Path(root);self.config=config;self.transient=transient
        self.connection=None;self.lock=asyncio.Lock();self.hosts={}

    def _validate_key(self,key):
        proxy=self.config['proxy']
        endpoint=hashlib.sha256((proxy['host'].casefold()+':'+str(proxy['port'])).encode()).hexdigest()
        public=key.export_public_key('openssh').decode('ascii').strip()
        path=self.root/(self.config['identity']+'.ssh-hosts.bin')
        if self.transient:value={'format':1,'hosts':self.hosts}
        else:
            path=checked(path,self.root)
            if path.exists():
                if path.stat().st_size>262144:return False
                value=read_encrypted(path)
            else:value={'format':1,'hosts':{}}
        if value.get('format')!=1 or not isinstance(value.get('hosts'),dict):return False
        previous=value['hosts'].get(endpoint)
        if previous is not None:return isinstance(previous,str) and hmac.compare_digest(previous,public)
        if len(value['hosts'])>=512:return False
        value['hosts'][endpoint]=public
        if not self.transient:write_encrypted(path,value)
        return True

    async def open(self,host,port):
        import asyncssh
        owner=self
        class Client(asyncssh.SSHClient):
            def validate_host_public_key(self,_host,_addr,_port,key):
                try:return owner._validate_key(key)
                except Exception:return False
        async with self.lock:
            if self.connection is None or self.connection.is_closed():
                proxy=self.config['proxy']
                self.connection=await asyncio.wait_for(asyncssh.connect(proxy['host'],int(proxy['port']),
                    username=proxy.get('username') or '',password=proxy.get('password') or '',
                    client_factory=Client,known_hosts=((),(),(),(),(),(),()),server_host_key_algs='default',
                    config=None,client_keys=[],agent_path=None,agent_forwarding=False,
                    connect_timeout=8,login_timeout=8,keepalive_interval=30,keepalive_count_max=2),8)
            connection=self.connection
        return await asyncio.wait_for(connection.open_connection(host,port,encoding=None),8)

    async def close(self):
        if self.connection is not None:
            self.connection.close()
            await asyncio.wait_for(self.connection.wait_closed(),2)
            self.connection=None


@contextmanager
def probe_route(proxy):
    """One probe-process-local relay; the existing process budget bounds all work."""
    from proxy_runtime import Worker
    ready=threading.Event();result={};loop_ref={}
    def run():
        async def serve():
            loop_ref['loop']=asyncio.get_running_loop();stop=asyncio.Event();loop_ref['stop']=stop
            worker=Worker(Path(),{'proxy':proxy,'identity':'probe','instance':'probe','transient_ssh':True})
            server=None
            try:
                server=await asyncio.start_server(worker.handle,'127.0.0.1',0,limit=32768)
                result['port']=server.sockets[0].getsockname()[1];ready.set()
                await stop.wait()
            finally:
                if server is not None:server.close();await server.wait_closed()
                for writer in list(worker.connections):writer.close()
                tasks=list(worker.handlers)
                for task in tasks:task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
                if worker.ssh_connector is not None:await worker.ssh_connector.close()
                worker.browser_checks.shutdown(wait=True,cancel_futures=True)
        try:asyncio.run(serve())
        except Exception:ready.set()
    thread=threading.Thread(target=run,daemon=True,name='ssh-probe-relay');thread.start()
    try:
        if not ready.wait(1) or 'port' not in result:raise OSError('SSH relay unavailable')
        yield result['port']
    finally:
        if 'stop' in loop_ref:
            try:loop_ref['loop'].call_soon_threadsafe(loop_ref['stop'].set)
            except RuntimeError:pass
        thread.join(timeout=2)
