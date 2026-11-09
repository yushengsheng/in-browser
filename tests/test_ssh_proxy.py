"""Authenticated SSH forwarding against loopback fixtures only."""
import asyncio
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import asyncssh
from portable_vault import PortableVault
from proxy_runtime import Worker
from proxy_config import parse_proxy
from ssh_proxy import SSHConnector

# Match SSH's bounded connect budget: Windows can try IPv6 localhost before
# falling back to the fixture's IPv4 listener. The response must still reach EOF.
FORWARD_TIMEOUT=8


class Server(asyncssh.SSHServer):
    def begin_auth(self,username):return True
    def password_auth_supported(self):return True
    def validate_password(self,username,password):return username=='fixture' and password=='synthetic'
    def connection_requested(self,*_):return True


class SSHProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # AsyncSSH also obtains a local display name even with an explicit remote user.
        self.environment=patch.dict('os.environ',{'USERNAME':'synthetic'});self.environment.start()
        self.addCleanup(self.environment.stop)
        self.temporary=tempfile.TemporaryDirectory(prefix='ssh-proxy-')
        self.root=Path(self.temporary.name);PortableVault(self.root).initialize()
        self.key=asyncssh.generate_private_key('ssh-ed25519')
        self.ssh=await asyncssh.create_server(Server,'127.0.0.1',0,server_host_keys=[self.key])
        self.proxy={'type':'ssh','host':'127.0.0.1','port':self.ssh.get_port(),'username':'fixture','password':'synthetic'}
        self.worker=Worker(self.root,{'proxy':self.proxy,'identity':'fixture','instance':'fixture'})
        self.relay=await asyncio.start_server(self.worker.handle,'127.0.0.1',0)
        self.origin=await asyncio.start_server(self.handle_origin,'127.0.0.1',0)
        self.received=[]

    async def handle_origin(self,reader,writer):
        try:
            data=await reader.readuntil(b'\r\n\r\n');self.received.append(data)
            body=b'{"ip":"192.0.2.1","timezone":"Asia/Shanghai","languages":"zh-CN,zh","latitude":30,"longitude":120,"country_code":"CN"}'
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body);await writer.drain()
        finally:writer.close();await writer.wait_closed()

    async def asyncTearDown(self):
        for server in (self.relay,self.origin):server.close();await server.wait_closed()
        for task in list(self.worker.handlers):task.cancel()
        await asyncio.gather(*list(self.worker.handlers),return_exceptions=True)
        if self.worker.ssh_connector:await self.worker.ssh_connector.close()
        self.worker.browser_checks.shutdown()
        self.ssh.close();await self.ssh.wait_closed();self.temporary.cleanup()

    async def request(self,*,connect=False):
        port=self.origin.sockets[0].getsockname()[1]
        reader,writer=await asyncio.open_connection('127.0.0.1',self.relay.sockets[0].getsockname()[1])
        try:
            if connect:
                writer.write(f'CONNECT localhost:{port} HTTP/1.1\r\nHost: fixture\r\n\r\n'.encode());await writer.drain()
                header=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),FORWARD_TIMEOUT)
                if not header.startswith(b'HTTP/1.1 200'):return header
                writer.write(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
            else:writer.write(f'GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: must-not-forward\r\n\r\n'.encode())
            await writer.drain();return await asyncio.wait_for(reader.read(),FORWARD_TIMEOUT)
        finally:writer.close();await writer.wait_closed()

    async def test_http_and_connect_forward_and_pin_host_key(self):
        self.assertIn(b'200 OK',await self.request())
        self.assertIn(b'200 OK',await self.request(connect=True))
        self.assertEqual(len(self.received),2)
        self.assertNotIn(b'must-not-forward',b''.join(self.received))
        self.assertTrue((self.root/'fixture.ssh-hosts.bin').is_file())

    async def test_bad_authentication_fails_without_forwarding(self):
        self.worker.proxy['password']='invalid'
        self.worker.config['proxy']['password']='invalid'
        self.assertIn(b'502',await self.request())
        self.assertEqual(self.received,[])

    async def test_changed_host_key_is_rejected_and_original_pin_preserved(self):
        connector=SSHConnector(self.root,{'proxy':self.proxy,'identity':'pin'})
        self.assertTrue(connector._validate_key(self.key))
        before=(self.root/'pin.ssh-hosts.bin').read_bytes()
        self.assertFalse(connector._validate_key(asyncssh.generate_private_key('ssh-ed25519')))
        self.assertEqual((self.root/'pin.ssh-hosts.bin').read_bytes(),before)

    async def test_reconnected_server_with_a_different_key_cannot_forward(self):
        self.assertIn(b'200 OK',await self.request())
        pin=(self.root/'fixture.ssh-hosts.bin').read_bytes()
        await self.worker.ssh_connector.close()
        port=self.ssh.get_port();self.ssh.close();await self.ssh.wait_closed()
        self.ssh=await asyncssh.create_server(Server,'127.0.0.1',port,
            server_host_keys=[asyncssh.generate_private_key('ssh-ed25519')])
        self.assertIn(b'502',await self.request())
        self.assertEqual(len(self.received),1)
        self.assertEqual((self.root/'fixture.ssh-hosts.bin').read_bytes(),pin)

    async def test_proxy_checker_process_uses_ssh_and_returns_geo(self):
        from proxy_check import ProxyChecker
        port=self.origin.sockets[0].getsockname()[1]
        checker=ProxyChecker(targets=[{'name':'synthetic','url':f'http://localhost:{port}/'}],require_geo=True)
        result=await asyncio.to_thread(checker.test,self.proxy)
        self.assertTrue(result['success'])
        self.assertEqual(result['geo']['timeZone'],'Asia/Shanghai')
        self.assertEqual(len(self.received),1)
        self.assertFalse((self.root/'fixture.ssh-hosts.bin').exists())


class SSHGrammarTests(unittest.TestCase):
    def test_uri_and_unqualified_text_keep_ssh_type(self):
        self.assertEqual(parse_proxy('ssh://fixture:synthetic@host.invalid:22')['proxy']['type'],'ssh')
        self.assertEqual(parse_proxy('host.invalid:22:fixture:synthetic','ssh')['proxy']['type'],'ssh')


if __name__=='__main__':unittest.main(verbosity=2)
