"""Synthetic loopback relay lifetime checks; no real proxy or browser data."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import proxy_runtime


WORKER_FIXTURE = r'''
import asyncio, json, sys, threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
import proxy_runtime
root=Path(sys.argv[2]);mode=sys.argv[3]
proxy_runtime.read_encrypted=lambda path:json.loads(Path(path).read_text())
proxy_runtime.write_encrypted=lambda path,value:Path(path).write_text(json.dumps(value))
browser=SimpleNamespace(pid=12345,create_time=lambda:100)
proxy_runtime.Worker.matching_browsers=lambda self:[browser] if (root/'browser-live').exists() else []
proxy_runtime.Worker.bound_browser_alive=lambda self:(root/'browser-live').exists()
if mode!='full':proxy_runtime.WORKER_SHUTDOWN_TIMEOUT=.4
original=proxy_runtime.Worker.run
async def run(self):
    asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))
    async def monitor():
        previous=None
        while True:
            if self.active!=previous:
                (root/'active-count').write_text(str(self.active));previous=self.active
            if self.browser:(root/'browser-bound').touch()
            await asyncio.sleep(.01)
    observer=asyncio.create_task(monitor())
    if mode=='executor':
        def blocked():
            (root/'executor-blocked').touch()
            threading.Event().wait()
        asyncio.create_task(asyncio.to_thread(blocked))
    try:await original(self)
    finally:
        observer.cancel();await asyncio.gather(observer,return_exceptions=True)
        (root/'run-completed').touch()
proxy_runtime.Worker.run=run
sys.argv=[str(proxy_runtime.SCRIPT),str(root),'fixture']
proxy_runtime.main()
'''


class ProxyRuntimeStabilityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.workers = []
        self.writers = set()
        self.upstream_tasks = set()
        idle = patch.object(proxy_runtime, 'RELAY_IDLE_TIMEOUT', .3)
        idle.start()
        self.addCleanup(idle.stop)

    async def asyncTearDown(self):
        for server in self.servers:
            server.close()
        for server in self.servers:
            await server.wait_closed()
        for writer in list(self.writers):
            writer.close()
        tasks = set(self.upstream_tasks)
        for worker in self.workers:
            for writer in list(worker.connections):
                writer.close()
            tasks.update(worker.handlers)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(*(writer.wait_closed() for writer in self.writers), return_exceptions=True)
        for worker in self.workers:
            worker.browser_checks.shutdown(wait=True, cancel_futures=True)

    async def proxy(self, action):
        async def upstream(reader, writer):
            task = asyncio.current_task()
            self.upstream_tasks.add(task)
            self.writers.add(writer)
            try:
                await reader.readuntil(b'\r\n\r\n')
                writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                await writer.drain()
                await action(reader, writer)
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                self.writers.discard(writer)
                self.upstream_tasks.discard(task)

        server = await asyncio.start_server(upstream, '127.0.0.1', 0)
        self.servers.append(server)
        config = {'proxy': {'type': 'http', 'host': '127.0.0.1',
                           'port': server.sockets[0].getsockname()[1]}}
        worker = proxy_runtime.Worker(ROOT, config)
        self.workers.append(worker)
        server = await asyncio.start_server(worker.handle, '127.0.0.1', 0)
        self.servers.append(server)
        return worker, server.sockets[0].getsockname()[1]

    async def connect(self, port):
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        self.writers.add(writer)
        writer.write(b'CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n')
        await writer.drain()
        header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2)
        self.assertTrue(header.startswith(b'HTTP/1.1 200 '))
        return reader, writer

    async def assert_released(self, worker):
        deadline = time.monotonic() + 2
        while (worker.active or worker.connections or worker.handlers) and time.monotonic() < deadline:
            await asyncio.sleep(.01)
        self.assertEqual(worker.active, 0)
        self.assertFalse(worker.connections)
        self.assertFalse(worker.handlers)

    async def test_active_download_outlasts_silent_upload(self):
        async def stream(reader, writer):
            for _ in range(20):
                await asyncio.sleep(.04)
                writer.write(b'x')
                await writer.drain()
            await reader.read()

        worker, port = await self.proxy(stream)
        reader, writer = await self.connect(port)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(20), 3), b'x' * 20)
        writer.close()
        await writer.wait_closed()
        await self.assert_released(worker)

    async def test_active_upload_outlasts_silent_download(self):
        received = []

        async def collect(reader, writer):
            received.append(await reader.readexactly(20))
            writer.write(b'ok')
            await writer.drain()
            await reader.read()

        worker, port = await self.proxy(collect)
        reader, writer = await self.connect(port)
        for _ in range(20):
            await asyncio.sleep(.04)
            writer.write(b'y')
            await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2), b'ok')
        self.assertEqual(received, [b'y' * 20])
        writer.close()
        await writer.wait_closed()
        await self.assert_released(worker)

    async def test_fully_idle_tunnel_expires_and_releases(self):
        async def idle(reader, writer):
            await reader.read()

        worker, port = await self.proxy(idle)
        reader, writer = await self.connect(port)
        self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b'')
        writer.close()
        await writer.wait_closed()
        await self.assert_released(worker)

    async def test_cancelling_established_tunnel_releases_connections(self):
        async def idle(reader, writer):
            await reader.read()

        worker, port = await self.proxy(idle)
        reader, writer = await self.connect(port)
        for task in list(worker.handlers):
            task.cancel()
        self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b'')
        writer.close()
        await writer.wait_closed()
        await self.assert_released(worker)

    async def test_upstream_disconnect_allows_next_tunnel(self):
        attempts = []

        async def reconnect(reader, writer):
            attempts.append(True)
            if len(attempts) == 1:
                writer.transport.abort()
                return
            writer.write(await reader.readexactly(4))
            await writer.drain()
            await reader.read()

        worker, port = await self.proxy(reconnect)
        reader, writer = await self.connect(port)
        self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b'')
        writer.close()
        await writer.wait_closed()
        await self.assert_released(worker)
        reader, writer = await self.connect(port)
        writer.write(b'ping')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(4), 2), b'ping')
        self.assertEqual(len(attempts), 2)
        writer.close()
        await writer.wait_closed()
        await self.assert_released(worker)


class WorkerBrowserIdentityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='proxy-identity-synthetic-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.profile = self.root / 'long-profile-directory-for-browser-identity'
        self.profile.mkdir()
        self.core = self.root / 'bitbrowser.exe'
        self.fingerprint = self.root / 'fingerprint.bin'
        self.arguments = [str(self.core), '--user-data-dir=' + str(self.profile),
            '--fingerprint-config=' + str(self.fingerprint),
            '--proxy-server=http://127.0.0.1:12345', '--proxy-bypass-list=<-loopback>',
            '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1']
        self.process = Mock(pid=101, cmdline=lambda: list(self.arguments),
                            exe=Mock(return_value=str(self.core)), create_time=Mock(return_value=100))
        self.worker = proxy_runtime.Worker(self.root, {
            'profile': str(self.profile), 'core': str(self.core), 'fingerprint': str(self.fingerprint),
            'token': 'synthetic-control', 'proxy': {'type': 'noproxy'}})
        self.worker.state = {'port': 12345, 'instance': 'synthetic-instance', 'digest': 'synthetic-digest'}
        self.addCleanup(self.worker.browser_checks.shutdown, wait=True, cancel_futures=True)

    def short_profile(self):
        if os.name != 'nt':
            self.skipTest('Windows directory aliases are required')
        from browser_core import _short_executable_path
        alias = _short_executable_path(self.profile)
        if alias is None or os.path.normcase(str(alias)) == os.path.normcase(str(self.profile)):
            self.skipTest('The test volume does not provide an alternate 8.3 spelling')
        self.assertTrue(alias.samefile(self.profile))
        return alias

    async def test_real_short_profile_alias_matches_and_prevents_live_worker_stop(self):
        alias = self.short_profile()
        self.worker.browser = (self.process.pid, 100)
        with patch.object(proxy_runtime, '_profile_browsers', return_value=[self.process]), \
                patch.object(proxy_runtime.psutil, 'Process', return_value=self.process):
            for spelling in (str(self.profile), str(alias), '"' + str(alias) + '"'):
                with self.subTest(spelling='canonical' if spelling == str(self.profile) else 'alias'):
                    self.arguments[1] = '--user-data-dir=' + spelling
                    self.assertTrue(self.worker.matches_browser(self.process))
                    self.assertEqual(self.worker.matching_browsers(), [self.process])
                    self.assertTrue(self.worker.bound_browser_alive())
            reader = asyncio.StreamReader()
            reader.feed_data(('POST ' + proxy_runtime.CONTROL + 'stop HTTP/1.1\r\n'
                              'X-Local-Token: synthetic-control\r\n\r\n').encode())
            writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
            await self.worker.handle(reader, writer)
        self.assertTrue(writer.write.call_args.args[0].startswith(b'HTTP/1.1 409 '))
        self.assertFalse(self.worker.stop.is_set())
        self.assertEqual(self.worker.active, 0)
        self.assertFalse(self.worker.connections)

    async def test_profile_alias_watch_survives_startup_deadline_and_stops_after_exit(self):
        self.arguments[1] = '--user-data-dir=' + str(self.short_profile())
        clock = [0.0]
        sleeps = [0]
        live = [True]
        async def check(operation):
            return operation()
        async def sleep(_delay):
            sleeps[0] += 1
            if sleeps[0] <= 2:
                self.assertEqual(self.worker.browser, (self.process.pid, 100))
                self.assertFalse(self.worker.stop.is_set())
            if sleeps[0] == 1:
                clock[0] = 61.0
            elif sleeps[0] == 2:
                live[0] = False
                clock[0] = 64.0
            else:
                clock[0] += 3.0
            if sleeps[0] > 5:
                self.fail('Worker did not stop after the confirmed browser exit')
        def current(_pid):
            if not live[0]:
                raise proxy_runtime.psutil.NoSuchProcess(self.process.pid)
            return self.process
        with patch.object(proxy_runtime, '_profile_browsers', return_value=[self.process]), \
                patch.object(proxy_runtime.psutil, 'Process', side_effect=current), \
                patch.object(proxy_runtime, 'time', SimpleNamespace(monotonic=lambda: clock[0])), \
                patch.object(proxy_runtime.asyncio, 'sleep', new=sleep), \
                patch.object(self.worker, 'check_browser', new=check):
            await self.worker.watch()
        self.assertTrue(self.worker.stop.is_set())
        self.assertEqual(sleeps[0], 4)

    async def test_identity_mismatches_remain_rejected(self):
        original = list(self.arguments)
        for index, argument in ((1, '--user-data-dir=' + str(self.root / 'other-profile')),
                                (2, '--fingerprint-config=' + str(self.root / 'other.bin')),
                                (3, '--proxy-server=http://127.0.0.1:12346')):
            with self.subTest(index=index):
                self.arguments = list(original)
                self.arguments[index] = argument
                self.assertFalse(self.worker.matches_browser(self.process))
        self.arguments = [*original, '--type=renderer']
        self.assertFalse(self.worker.matches_browser(self.process))
        self.arguments = original
        self.process.exe.return_value = str(self.root / 'other-core.exe')
        self.assertFalse(self.worker.matches_browser(self.process))
        self.process.exe.return_value = str(self.core)
        self.worker.browser = (self.process.pid, 99)
        with patch.object(proxy_runtime.psutil, 'Process', return_value=self.process):
            self.assertFalse(self.worker.bound_browser_alive())


class WorkerShutdownProcessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='proxy-exit-synthetic-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.child=None;self.server=None;self.writers=set();self.upstream_tasks=set()
        self.handshake=asyncio.Event()

    async def asyncTearDown(self):
        if self.child is not None and self.child.poll() is None:
            self.child.kill();self.child.wait(timeout=5)
        if self.server is not None:
            self.server.close();await self.server.wait_closed()
        for writer in list(self.writers):writer.close()
        for task in list(self.upstream_tasks):task.cancel()
        await asyncio.gather(*self.upstream_tasks,return_exceptions=True)
        await asyncio.gather(*(writer.wait_closed() for writer in self.writers),return_exceptions=True)

    async def slow_socks(self,reader,writer):
        task=asyncio.current_task();self.upstream_tasks.add(task);self.writers.add(writer)
        try:
            _,count=await reader.readexactly(2);await reader.readexactly(count)
            writer.write(b'\x05\x00');await writer.drain()
            await reader.read(4096)
            writer.write(b'\x05\x00\x00\x03\xff');await writer.drain()
            self.handshake.set()
            for _ in range(255):
                writer.write(b'x');await writer.drain();await asyncio.sleep(.1)
        except (OSError,asyncio.IncompleteReadError):pass
        finally:
            writer.close()
            try:await writer.wait_closed()
            except OSError:pass
            self.upstream_tasks.discard(task)

    async def wait_for(self,predicate,timeout=3):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if predicate():return
            await asyncio.sleep(.02)
        self.fail('Synthetic worker did not reach the expected state in time')

    async def start(self,mode,*,live=False):
        self.server=await asyncio.start_server(self.slow_socks,'127.0.0.1',0)
        config={'identity':'fixture','token':'synthetic-control','instance':'synthetic-instance',
                'digest':'synthetic-digest','context':'synthetic-context','port':0,
                'profile':'synthetic-profile','core':'synthetic-core','fingerprint':'synthetic-fingerprint',
                'proxy':{'type':'socks5','host':'127.0.0.1','port':self.server.sockets[0].getsockname()[1]}}
        (self.root/'fixture.request').write_text(json.dumps(config))
        (self.root/'unrelated.state').write_text(json.dumps({'instance':config['instance']}))
        if live:(self.root/'browser-live').touch()
        self.child=subprocess.Popen([sys.executable,'-B','-c',WORKER_FIXTURE,str(ROOT/'app'),str(self.root),mode],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        state=self.root/'fixture.state'
        def ready():
            try:self.state=json.loads(state.read_text());return True
            except (OSError,ValueError):return False
        await self.wait_for(ready)
        if live:await self.wait_for(lambda:(self.root/'browser-bound').exists())

    async def connect(self):
        reader,writer=await asyncio.open_connection('127.0.0.1',self.state['port']);self.writers.add(writer)
        writer.write(b'CONNECT synthetic.invalid:443 HTTP/1.1\r\nHost: synthetic.invalid\r\n\r\n')
        await writer.drain()
        return reader

    async def control(self):
        reader,writer=await asyncio.open_connection('127.0.0.1',self.state['port']);self.writers.add(writer)
        writer.write(('POST '+proxy_runtime.CONTROL+'stop HTTP/1.1\r\nX-Local-Token: synthetic-control\r\n\r\n').encode())
        await writer.drain()
        try:response=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),1)
        except OSError:return 0
        finally:
            writer.close()
            try:await writer.wait_closed()
            except OSError:pass
            self.writers.discard(writer)
        return int(response.split(b' ',2)[1])

    async def assert_exit(self,timeout):
        await self.wait_for(lambda:self.child.poll() is not None,timeout)
        self.assertEqual(self.child.returncode,0)
        self.assertFalse((self.root/'fixture.state').exists())
        self.assertFalse((self.root/'fixture.request').exists())
        self.assertTrue((self.root/'unrelated.state').exists())

    async def test_slow_handshake_cannot_starve_stop_checks_or_expire_a_live_browser(self):
        await self.start('quick',live=True)
        await self.connect();await asyncio.wait_for(self.handshake.wait(),2)
        self.assertEqual(await self.control(),409)
        await asyncio.sleep(.6)
        self.assertIsNone(self.child.poll())
        self.assertTrue((self.root/'fixture.state').exists())
        (self.root/'browser-live').unlink()
        self.assertEqual(await self.control(),200)
        await self.assert_exit(2)

    async def test_full_connection_limit_still_exits_inside_manager_budget_after_browser_closes(self):
        await self.start('full',live=True)
        for _ in range(96):await self.connect()
        await asyncio.wait_for(self.handshake.wait(),2)
        def full():
            try:return (self.root/'active-count').read_text()=='96'
            except OSError:return False
        await self.wait_for(full)
        self.assertIn(await self.control(),(0,503))
        started=time.monotonic();(self.root/'browser-live').unlink()
        await self.assert_exit(10)
        self.assertLess(time.monotonic()-started,10)

    async def test_final_deadline_includes_default_executor_shutdown(self):
        await self.start('executor')
        await self.wait_for(lambda:(self.root/'executor-blocked').exists())
        self.assertEqual(await self.control(),200)
        await self.assert_exit(2)
        self.assertTrue((self.root/'run-completed').exists())


class WorkerShutdownOwnershipTests(unittest.TestCase):
    def test_cleanup_retains_replacement_records_and_unrelated_files(self):
        with tempfile.TemporaryDirectory(prefix='proxy-owner-synthetic-') as folder:
            root=Path(folder)
            state=root/'fixture.state';request=root/'fixture.request';other=root/'other.state'
            state.write_text(json.dumps({'instance':'owned'}))
            request.write_text(json.dumps({'instance':'replacement'}))
            other.write_text(json.dumps({'instance':'owned'}))
            worker=proxy_runtime.Worker(root,{'identity':'fixture','instance':'owned','proxy':{'type':'noproxy'}})
            with patch.object(proxy_runtime,'read_encrypted',side_effect=lambda path:json.loads(path.read_text())):
                worker.cleanup_runtime_files()
            worker.browser_checks.shutdown()
            self.assertFalse(state.exists());self.assertTrue(request.exists());self.assertTrue(other.exists())

    def test_normal_main_completion_cancels_exit_timer(self):
        with tempfile.TemporaryDirectory(prefix='proxy-normal-exit-synthetic-') as folder:
            timer=Mock()
            def worker(root,config,*,on_shutdown):
                async def run():on_shutdown()
                return Mock(run=run)
            with patch.object(proxy_runtime.sys,'argv',['worker',folder,'fixture']), \
                    patch.object(proxy_runtime,'read_encrypted',return_value={}), \
                    patch.object(proxy_runtime,'Worker',side_effect=worker), \
                    patch.object(proxy_runtime.threading,'Timer',return_value=timer), \
                    patch.object(proxy_runtime.os,'_exit') as exit_process:
                proxy_runtime.main()
            timer.start.assert_called_once();timer.cancel.assert_called_once();exit_process.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
