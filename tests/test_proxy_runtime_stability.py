"""Synthetic loopback relay lifetime checks; no real proxy or browser data."""
import asyncio
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import proxy_runtime


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
