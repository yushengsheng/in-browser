"""Per-window loopback proxy workers; upstream credentials never enter argv."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

import psutil
import socks

from local_state import LocalBrowserError, read_encrypted, write_encrypted
from browser_processes import _profile_browsers, _is_browser, _switch_values
from proxy_config import normalize_proxy
from browser_policy import PROXY_SWITCHES,verify_running_proxy_args,verify_proxy_extensions

SCRIPT = Path(__file__).resolve()
CONTROL = '/__local_browser_proxy__/'
RELAY_IDLE_TIMEOUT = 600
WORKER_SHUTDOWN_TIMEOUT = 6


def proxy_digest(proxy):
    return hashlib.sha256(json.dumps(normalize_proxy(proxy), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@contextmanager
def route_lock(root, identity, timeout=10000):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    key = hashlib.sha256((str(Path(root).resolve()) + ':' + identity).encode()).hexdigest()
    handle = kernel.CreateMutexW(None, False, 'Local\\BrowserProxy-' + key)
    acquired = handle and kernel.WaitForSingleObject(handle, timeout) in (0, 0x80)
    if not acquired:
        if handle:
            kernel.CloseHandle(handle)
        raise LocalBrowserError('本地代理正在准备，请稍候再试。')
    try:
        yield
    finally:
        kernel.ReleaseMutex(handle)
        kernel.CloseHandle(handle)


class ProxyRuntime:
    def __init__(self, root):
        self.root = Path(root).resolve() / 'proxy-runtime'
        self.root.mkdir(exist_ok=True)

    def paths(self, identity):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', identity):
            raise LocalBrowserError('窗口标识无效。')
        return self.root / (identity + '.request'), self.root / (identity + '.state')

    @staticmethod
    def owned(state):
        try:
            process = psutil.Process(state['pid'])
            args = process.cmdline()
            return (abs(process.create_time() - state['created']) < .01
                    and Path(process.exe()).resolve() == Path(state['executable']).resolve()
                    and len(args) >= 4 and Path(args[1]).resolve() == SCRIPT
                    and Path(args[2]).resolve() == Path(state['root']).resolve() and args[3] == state['identity'])
        except (psutil.Error, OSError, ValueError, KeyError):
            return False

    @staticmethod
    def control(state, operation='ping'):
        try:
            with socket.create_connection(('127.0.0.1', int(state['port'])), timeout=2) as connection:
                message = ('POST ' + CONTROL + operation + ' HTTP/1.1\r\nHost: localhost\r\nX-Local-Token: '
                           + state['token'] + '\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                connection.sendall(message.encode('ascii'))
                data = bytearray()
                while len(data) < 4096:
                    part = connection.recv(4096 - len(data))
                    if not part:
                        break
                    data.extend(part)
                header, body = bytes(data).split(b'\r\n\r\n', 1)
                result = json.loads(body)
                if header.split(b'\r\n', 1)[0] != b'HTTP/1.1 200 OK':
                    return False
                return (result.get('instance') == state['instance'] and result.get('digest') == state['digest'])
        except (OSError, ValueError, KeyError):
            return False

    def state(self, identity):
        _, path = self.paths(identity)
        try:
            return read_encrypted(path) if path.is_file() else None
        except (OSError, LocalBrowserError, ValueError):
            raise LocalBrowserError('本地代理运行记录无法读取，已有窗口资料已保留。') from None

    def ensure(self, profile):
        identity = profile['id']
        proxy = normalize_proxy(profile['proxy'])
        if proxy['type'] == 'noproxy':
            return None
        if proxy.get('enable_socks5_udp'):
            raise LocalBrowserError('本地独立代理目前支持TCP，不支持SOCKS5 UDP；请关闭UDP选项。')
        request, state_path = self.paths(identity)
        with route_lock(self.root, identity):
            previous = self.state(identity)
            digest = proxy_digest(proxy)
            runtime = profile['_runtime']
            verify_proxy_extensions(runtime['profile_path'],runtime.get('managed_extension'))
            live = _profile_browsers(Path(runtime['profile_path']))
            expected_port=int(runtime.get('local_proxy_port') or 0)
            if live:
                try:
                    valid=expected_port>0 and all(Path(p.exe()).resolve()==Path(runtime['core_path']).resolve()
                        and '--fingerprint-config='+runtime['fingerprint_path'] in p.cmdline()
                        and verify_running_proxy_args(p.cmdline(),expected_port) for p in live)
                except (psutil.Error,OSError,ValueError):valid=False
                if not valid:raise LocalBrowserError('已有浏览器的代理隔离参数不完整或发生变化，请正常关闭该窗口后重新打开。')
            context=hashlib.sha256(json.dumps([runtime['profile_path'],runtime['core_path'],runtime['fingerprint_path']]).encode()).hexdigest()
            if previous and self.owned(previous):
                if live:
                    if previous['digest'] != digest or previous.get('context')!=context or not self.control(previous):
                        raise LocalBrowserError('已有本地代理状态不一致，请正常关闭该窗口后重试。')
                    return previous
                if not self.control(previous,'stop'):
                    raise LocalBrowserError('上次本地代理尚未退出，请稍候重开。')
                deadline=time.monotonic()+10
                while time.monotonic()<deadline and self.owned(previous):time.sleep(.05)
                if self.owned(previous):raise LocalBrowserError('上次本地代理尚未退出，请稍候重开。')
            port = int(runtime.get('local_proxy_port') or 0) if live else 0
            if live and (not previous or previous['digest'] != digest or previous['port'] != port):
                raise LocalBrowserError('无法恢复已有窗口的本地代理，请正常关闭窗口后重开。')
            config = {'identity': identity, 'proxy': proxy, 'digest': digest, 'port': port,
                      'token': secrets.token_urlsafe(32), 'instance': secrets.token_hex(16), 'context':context,
                      'profile': runtime['profile_path'], 'core': runtime['core_path'],
                      'fingerprint': runtime['fingerprint_path']}
            write_encrypted(request, config)
            executable = Path(sys.executable).with_name('pythonw.exe')
            if not executable.is_file():
                raise LocalBrowserError('本地代理所需Python运行环境不存在。')
            child = subprocess.Popen([str(executable), str(SCRIPT), str(self.root), identity],
                                     cwd=SCRIPT.parent, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                state = self.state(identity)
                if state and state.get('instance') == config['instance'] and self.owned(state) and self.control(state):
                    return state
                if child.poll() is not None:
                    break
                time.sleep(.1)
            raise LocalBrowserError('本地代理未能就绪，未启动浏览器，也未改为直连。')

    def stop_if_unused(self, identity):
        with route_lock(self.root, identity):
            state = self.state(identity)
            if state and self.owned(state):
                self.control(state, 'stop')
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and self.owned(state):
                    time.sleep(.05)
                if self.owned(state):raise LocalBrowserError('本地代理仍在释放连接，请稍候再试。')


class Worker:
    def __init__(self, root, config, *, on_shutdown=None):
        self.root = root
        self.config = config
        self.proxy = normalize_proxy(config['proxy'])
        self.stop = asyncio.Event()
        self.connections = set()
        self.active = 0
        self.handlers=set()
        self.state = None
        self.browser = None
        self.tls_context = None
        self.ssh_connector = None
        self.on_shutdown = on_shutdown
        self.browser_checks = ThreadPoolExecutor(max_workers=1, thread_name_prefix='proxy-browser-check')

    def matches_browser(self, process):
        args=process.cmdline()
        expected=os.path.normcase(str(Path(self.config['profile']).resolve()))
        return (_is_browser(args) and Path(process.exe()).resolve()==Path(self.config['core']).resolve()
                and any(os.path.normcase(os.path.abspath(value.strip('"')))==expected
                        for value in _switch_values(args,'--user-data-dir') if value)
                and verify_running_proxy_args(args,self.state['port'])
                and '--fingerprint-config='+self.config['fingerprint'] in args)

    async def reply(self, writer, code, body=b''):
        reason = {200: 'OK', 400: 'Bad Request', 403: 'Forbidden', 409: 'Conflict', 502: 'Bad Gateway', 503: 'Unavailable'}[code]
        writer.write(('HTTP/1.1 ' + str(code) + ' ' + reason + '\r\nConnection: close\r\nContent-Length: '
                      + str(len(body)) + '\r\n\r\n').encode() + body)
        await asyncio.wait_for(writer.drain(), 5)

    def matching_browsers(self):
        result = []
        for process in _profile_browsers(Path(self.config['profile'])):
            try:
                if self.matches_browser(process):
                    result.append(process)
            except (psutil.Error, OSError):
                pass
        return result

    def bound_browser_alive(self):
        try:
            process=psutil.Process(self.browser[0])
            return abs(process.create_time()-self.browser[1])<.01 and self.matches_browser(process)
        except (psutil.Error,OSError,ValueError):
            return False

    async def check_browser(self, operation):
        # Slow SOCKS handshakes must not occupy the worker's lifecycle checks.
        return await asyncio.get_running_loop().run_in_executor(self.browser_checks, operation)

    async def watch(self):
        deadline = time.monotonic() + 60
        missing_since = None
        while not self.stop.is_set():
            alive = False
            if self.browser:
                alive=await self.check_browser(self.bound_browser_alive)
            else:
                matches=await self.check_browser(self.matching_browsers)
                if matches:
                    try:self.browser=(matches[0].pid,matches[0].create_time());alive=True
                    except psutil.Error:pass
            if alive:
                missing_since = None
            elif self.browser:
                missing_since = missing_since or time.monotonic()
                if time.monotonic() - missing_since > 2:
                    self.stop.set()
            elif time.monotonic() > deadline:
                self.stop.set()
            await asyncio.sleep(.5)

    async def upstream(self, host, port, tunnel):
        proxy = self.proxy
        if proxy['type']=='ssh':
            if self.ssh_connector is None:
                from ssh_proxy import SSHConnector
                self.ssh_connector=SSHConnector(self.root,self.config,transient=self.config.get('transient_ssh') is True)
            return await self.ssh_connector.open(host,port)
        if proxy['type'] == 'socks5':
            def connect():
                connection = socks.create_connection((host,port),timeout=8,proxy_type=socks.SOCKS5,
                    proxy_addr=proxy['host'],proxy_port=int(proxy['port']),proxy_rdns=True,
                    proxy_username=proxy['username'] or None,proxy_password=proxy['password'] or None)
                try:
                    connection.setblocking(False)
                    return connection
                except Exception:
                    connection.close()
                    raise
            task=asyncio.create_task(asyncio.to_thread(connect))
            try:
                raw=await asyncio.shield(task)
            except asyncio.CancelledError:
                try:(await asyncio.shield(task)).close()
                except Exception:pass
                raise
            try:
                return await asyncio.open_connection(sock=raw)
            except BaseException:
                raw.close()
                raise
        if proxy['type']=='https' and self.tls_context is None:
            self.tls_context=ssl.create_default_context()
        tls = self.tls_context if proxy['type'] == 'https' else None
        reader, writer = await asyncio.wait_for(asyncio.open_connection(proxy['host'], int(proxy['port']), ssl=tls), 8)
        if tunnel:
            try:
                authority = ('[' + host + ']' if ':' in host else host) + ':' + str(port)
                request = 'CONNECT ' + authority + ' HTTP/1.1\r\nHost: ' + authority + '\r\n' + self.auth_header() + '\r\n'
                writer.write(request.encode('latin-1'))
                await asyncio.wait_for(writer.drain(), 8)
                header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 8)
                if len(header) > 32768 or header.split(b'\r\n', 1)[0].split()[1] != b'200':
                    raise ValueError()
            except BaseException:
                writer.close()
                await writer.wait_closed()
                raise
        return reader, writer

    def auth_header(self):
        if not (self.proxy['username'] or self.proxy['password']):
            return ''
        value = base64.b64encode((self.proxy['username'] + ':' + self.proxy['password']).encode()).decode('ascii')
        return 'Proxy-Authorization: Basic ' + value + '\r\n'

    async def pipe(self, reader, writer, activity):
        while True:
            remaining = RELAY_IDLE_TIMEOUT - (time.monotonic() - activity[0])
            if remaining <= 0:
                raise asyncio.TimeoutError()
            try:
                data = await asyncio.wait_for(reader.read(65536), remaining)
            except asyncio.TimeoutError:
                # The other direction may have kept this tunnel active.
                if time.monotonic() - activity[0] < RELAY_IDLE_TIMEOUT:
                    continue
                raise
            if not data:
                try:
                    writer.write_eof()
                except (OSError, NotImplementedError):
                    raise ConnectionError('Tunnel cannot be half-closed') from None
                return
            activity[0] = time.monotonic()
            writer.write(data)
            await asyncio.wait_for(writer.drain(), 30)

    async def handle(self, reader, writer):
        self.handlers.add(asyncio.current_task())
        remote = None
        ready = False
        self.connections.add(writer)
        self.active += 1
        try:
            if self.active > 96:
                await self.reply(writer, 503)
                return
            header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 10)
            if len(header) > 32768:
                raise ValueError()
            lines = header.decode('latin-1').split('\r\n')
            method, target, version = lines[0].split(' ')
            if version not in ('HTTP/1.0', 'HTTP/1.1'):
                raise ValueError()
            headers = []
            for line in lines[1:]:
                if not line:
                    continue
                key, value = line.split(':', 1)
                if not re.fullmatch(r'[!#$%&\x27*+.^_`|~0-9A-Za-z-]+', key):
                    raise ValueError()
                headers.append((key, value.strip()))
            if target.startswith(CONTROL):
                token = next((v for k, v in headers if k.lower() == 'x-local-token'), '')
                if not hmac.compare_digest(token, self.config['token']):
                    await self.reply(writer, 403)
                    return
                if target == CONTROL + 'stop':
                    if await self.check_browser(self.matching_browsers):
                        await self.reply(writer, 409)
                        return
                    self.stop.set()
                elif target != CONTROL + 'ping':
                    raise ValueError()
                body = json.dumps({k: self.state[k] for k in ('instance', 'digest')}).encode()
                await self.reply(writer, 200, body)
                return
            tunnel = method == 'CONNECT'
            parsed = urlsplit('//' + target if tunnel else target)
            if (not parsed.hostname or parsed.username or parsed.password or parsed.fragment
                    or (not tunnel and parsed.scheme != 'http')):
                raise ValueError()
            host = parsed.hostname
            if any(c.isspace() or c in '\r\n\x00' for c in host):
                raise ValueError()
            port = parsed.port or (443 if tunnel else 80)
            upstream_reader, remote = await self.upstream(host, port, tunnel)
            self.connections.add(remote)
            if tunnel:
                writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                await writer.drain()
            else:
                forward = self.proxy['type'] in ('http', 'https')
                path = target if forward else (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
                clean = [(k, v) for k, v in headers if k.lower() not in ('proxy-authorization', 'proxy-connection', 'connection', 'x-local-token')]
                outgoing = method + ' ' + path + ' ' + version + '\r\n' + ''.join(k + ': ' + v + '\r\n' for k, v in clean)
                upgrading=any(k.lower()=='upgrade' and v.lower()=='websocket' for k,v in headers)
                outgoing += ('Connection: Upgrade\r\n' if upgrading else 'Connection: close\r\n') + (self.auth_header() if forward else '') + '\r\n'
                remote.write(outgoing.encode('latin-1'))
                await remote.drain()
            ready = True
            activity = [time.monotonic()]
            tasks = [asyncio.create_task(self.pipe(reader, remote, activity)), asyncio.create_task(self.pipe(upstream_reader, writer, activity))]
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
                for task in done:
                    task.result()
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (Exception, asyncio.CancelledError):
            if not ready:
                try:
                    await self.reply(writer, 502)
                except Exception:
                    pass
        finally:
            self.handlers.discard(asyncio.current_task())
            self.active -= 1
            for connection in (writer, remote):
                if connection:
                    self.connections.discard(connection)
                    connection.close()
                    try:
                        await asyncio.wait_for(connection.wait_closed(), 2)
                    except Exception:
                        pass

    def cleanup_runtime_files(self):
        for suffix in ('.state', '.request'):
            path = self.root / (self.config['identity'] + suffix)
            try:
                if read_encrypted(path).get('instance') == self.config['instance']:
                    path.unlink()
            except (OSError, LocalBrowserError, ValueError):
                pass

    async def run(self):
        server = await asyncio.start_server(self.handle, '127.0.0.1', self.config['port'], limit=32768)
        process = psutil.Process()
        self.state = {'pid': os.getpid(), 'created': process.create_time(), 'executable': process.exe(),
                      'identity': self.config['identity'], 'root': str(self.root), 'port': server.sockets[0].getsockname()[1],
                      'token': self.config['token'], 'instance': self.config['instance'], 'digest': self.config['digest'],
                      'context':self.config['context']}
        state_path = self.root / (self.config['identity'] + '.state')
        write_encrypted(state_path, self.state)
        watch = asyncio.create_task(self.watch())
        try:
            await self.stop.wait()
        finally:
            if self.stop.is_set() and self.on_shutdown is not None:
                self.on_shutdown()
            server.close()
            self.cleanup_runtime_files()
            await server.wait_closed()
            watch.cancel()
            await asyncio.gather(watch, return_exceptions=True)
            for writer in list(self.connections):
                writer.close()
            handlers=list(self.handlers)
            for task in handlers:task.cancel()
            try:
                await asyncio.gather(*handlers,return_exceptions=True)
            finally:
                try:
                    if self.ssh_connector is not None:await self.ssh_connector.close()
                finally:self.browser_checks.shutdown(wait=True, cancel_futures=True)


def main():
    shutdown_timer = None
    def start_shutdown_timeout():
        nonlocal shutdown_timer
        if shutdown_timer is None:
            # Only this independent relay exits; no browser process is controlled.
            shutdown_timer = threading.Timer(WORKER_SHUTDOWN_TIMEOUT, lambda: os._exit(0))
            shutdown_timer.daemon = True
            shutdown_timer.start()
    try:
        root = Path(sys.argv[1]).resolve()
        identity = sys.argv[2]
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', identity):
            return
        config = read_encrypted(root / (identity + '.request'))
        asyncio.run(Worker(root, config, on_shutdown=start_shutdown_timeout).run())
    except Exception:
        pass
    finally:
        if shutdown_timer is not None:
            shutdown_timer.cancel()


if __name__ == '__main__':
    main()
