"""Local-only control of the user's two imported BitBrowser profiles."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import threading
import time
from urllib.parse import urlparse
from urllib.request import build_opener, ProxyHandler

import psutil
import websocket

from app_paths import APP_ROOT,DATA_ROOT
# Re-export existing names so manager and external callers retain their API.
from local_state import LocalBrowserError, protect, read_encrypted, write_encrypted
from browser_processes import (ProfileProcessSnapshot, profile_processes, _switch_values,
                               _is_browser, _profile_browsers)


def sha256(path: Path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _check_launch_paths(executable):
    if os.name!='nt':return
    # Chromium also loads nested resources in its utility/network processes.
    # A short executable path alone does not ensure those files are accessible.
    manifest=executable.parent/'manifest.json'
    paths=[executable]
    if manifest.is_file():
        with manifest.open('rb') as stream:raw=stream.read(16*1024*1024+1)
        if len(raw)>16*1024*1024:raise LocalBrowserError('内核清单不完整，未启动浏览器。')
        try:paths.extend(executable.parent/name for name in json.loads(raw).get('files',{}))
        except (ValueError,TypeError):raise LocalBrowserError('内核清单不完整，未启动浏览器。') from None
    if any(len(str(path.resolve()).encode('utf-16-le'))//2>=260 for path in paths):
        raise LocalBrowserError('程序目录层级过深，内核资源超过Windows的路径限制；请将整个文件夹移到磁盘根目录附近后重试。')


def _visible_windows(pid):
    user = ctypes.WinDLL('user32', use_last_error=True)
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    windows = []
    def callback(window, _):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == pid and user.IsWindowVisible(window):
            name = ctypes.create_unicode_buffer(256)
            user.GetClassNameW(window, name, len(name))
            # Excludes Chromium's hidden/message windows; minimized windows count.
            if name.value == 'Chrome_WidgetWin_1':
                windows.append(window)
        return True
    callback_ref = callback_type(callback)
    if not user.EnumWindows(callback_ref, 0):
        raise LocalBrowserError('无法确认浏览器窗口状态，已有进程和资料已保留。')
    return windows


def _free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def _endpoint(port: int, timeout=1):
    with build_opener(ProxyHandler({})).open(f'http://127.0.0.1:{int(port)}/json/version', timeout=timeout) as response:
        data = json.loads(response.read(65536))
    parsed = urlparse(data['webSocketDebuggerUrl'])
    if parsed.scheme != 'ws' or parsed.hostname not in ('127.0.0.1', 'localhost') or parsed.port != port:
        raise LocalBrowserError('浏览器调试接口返回了意外地址。')
    return data['webSocketDebuggerUrl']


class CDP:
    def __init__(self, endpoint, *, timeout=12):
        self.timeout = timeout
        self.connection = websocket.create_connection(endpoint, timeout=min(8, timeout), suppress_origin=True)
        self.next_id = 0

    def call(self, method, params=None, session=None):
        self.next_id += 1
        command = {'id': self.next_id, 'method': method, 'params': params or {}}
        if session:
            command['sessionId'] = session
        self.connection.send(json.dumps(command))
        deadline=time.monotonic()+self.timeout
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0: raise LocalBrowserError('浏览器操作超时，窗口和资料已保留。')
            self.connection.settimeout(min(8,remaining))
            reply = json.loads(self.connection.recv())
            if reply.get('id') == self.next_id:
                if 'error' in reply:
                    raise LocalBrowserError('浏览器未接受该操作。')
                return reply.get('result', {})

    def close(self):
        self.connection.close(timeout=min(3, self.timeout))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class BrowserController:
    def __init__(self, data_root=DATA_ROOT, settings=None):
        self.root = Path(data_root).resolve()
        self.lock = threading.RLock()
        self.settings = settings if settings is not None else read_encrypted(self.root / 'settings.bin')
        self.profiles = {item['alias']: item for item in self.settings['windows']}
        if any(not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',identity) for identity in self.profiles):
            raise LocalBrowserError('本地窗口标识不正确。')
        self.state_path = self.root / 'runtime.bin'
        try:
            self.state = read_encrypted(self.state_path) if self.state_path.exists() else {}
        except (OSError, ValueError, LocalBrowserError):
            self.state = {}
        self._checked_cores = {}
        self._status_cache = {}
        self._windowless_since = {}
        self._closing_workers = set()

    def _save(self):
        write_encrypted(self.state_path, self.state)

    def _core_valid(self, item):
        executable = Path(item['core_path']).resolve()
        stamp = (executable.stat().st_size, executable.stat().st_mtime_ns, item['core_sha256'])
        key = os.path.normcase(str(executable))
        if self._checked_cores.get(key) != stamp:
            if sha256(executable) != item['core_sha256']:
                return False
            self._checked_cores[key] = stamp
        return True

    def _record_valid(self, alias):
        record = self.state.get(alias)
        if not record:
            return False
        try:
            item = self.profiles[alias]
            process = psutil.Process(record['pid'])
            with process.oneshot():
                if abs(process.create_time() - record['created']) >= .01:
                    return False
                args = process.cmdline()
                if not _is_browser(args) or os.path.normcase(str(Path(process.exe()).resolve())) != os.path.normcase(str(Path(item['core_path']).resolve())):
                    return False
            profiles = _switch_values(args, '--user-data-dir')
            ports = _switch_values(args, '--remote-debugging-port')
            return (len(profiles) == 1
                    and os.path.normcase(str(Path(profiles[0].strip('"')).resolve())) == os.path.normcase(str(Path(item['profile_path']).resolve()))
                    and ports == [str(record['port'])] and 0 < int(record['port']) < 65536
                    and _switch_values(args, '--remote-debugging-address') == ['127.0.0.1']
                    and self._core_valid(item))
        except (psutil.Error, OSError, ValueError, KeyError, TypeError):
            return False

    def _adopt(self, alias, *, processes=None):
        """Recover only a matching profile/core with a verified loopback listener."""
        item = self.profiles[alias]
        for process in (_profile_browsers(Path(item['profile_path'])) if processes is None else processes):
            try:
                args = process.cmdline()
                if os.path.normcase(str(Path(process.exe()).resolve())) != os.path.normcase(str(Path(item['core_path']).resolve())):
                    continue
                ports = [int(value) for value in _switch_values(args, '--remote-debugging-port')]
                if len(ports) != 1 or not 0 < ports[0] < 65536:
                    continue
                if _switch_values(args, '--remote-debugging-address') != ['127.0.0.1']:
                    continue
                record = {'pid': process.pid, 'created': process.create_time(), 'port': ports[0], 'ready': True,
                          'window_observed': bool(_visible_windows(process.pid))}
                previous = self.state.get(alias)
                self.state[alias] = record
                try:
                    self.endpoint(alias, timeout=.4)
                except (OSError, ValueError, KeyError, LocalBrowserError, psutil.Error):
                    if previous is None:
                        self.state.pop(alias, None)
                    else:
                        self.state[alias] = previous
                    continue
                try:
                    self._save()
                except (OSError, LocalBrowserError):
                    pass  # The exact process command line also permits recovery next time.
                return True
            except (psutil.Error, OSError, ValueError):
                continue
        return False

    def _ensure_record(self, alias):
        return self._record_valid(alias) or self._adopt(alias)

    def _forget(self, alias, *, deferred=None):
        self.state.pop(alias, None)
        self._status_cache.pop(alias, None)
        self._windowless_since.pop(alias, None)
        if deferred is not None:
            deferred.add(alias)
            return
        try:
            self._save()
        except (OSError, LocalBrowserError):
            pass  # A dead PID is never trusted when the manager next starts.

    def _request_close(self, alias, timeout=2):
        connection = CDP(self.endpoint(alias, timeout=min(1, timeout)), timeout=timeout)
        try:
            connection.call('Browser.close')
        except (OSError, websocket.WebSocketException):
            pass  # Browser.close commonly closes the socket before its reply.
        finally:
            connection.close()

    def _finish_windowless(self, alias, identity):
        """Normal shutdown only, after the last real window has disappeared."""
        try:
            time.sleep(1)
            with self.lock:
                current = self.state.get(alias)
                if not current or (current['pid'], current['created']) != identity or not self._record_valid(alias):
                    return
                if _visible_windows(current['pid']):
                    current['window_observed'] = True
                    self._windowless_since.pop(alias, None)
                    self._status_cache.pop(alias, None)
                    return
                if not current.get('window_observed') and time.time() - current['created'] < 25:
                    return
                self._request_close(alias, timeout=.8)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                with self.lock:
                    current = self.state.get(alias)
                    if not current or (current['pid'], current['created']) != identity:
                        return
                    if not self._record_valid(alias):
                        self._forget(alias)
                        return
                time.sleep(.2)
        except (OSError, ValueError, KeyError, LocalBrowserError, psutil.Error, websocket.WebSocketException):
            pass  # Never replace a failed graceful close with process termination.
        finally:
            with self.lock:
                self._closing_workers.discard(alias)

    def _queue_windowless_close(self, alias):
        self._windowless_since.setdefault(alias, time.monotonic())
        if alias not in self._closing_workers:
            self._closing_workers.add(alias)
            record = self.state[alias]
            threading.Thread(target=self._finish_windowless, args=(alias, (record['pid'], record['created'])),
                             name='browser-close', daemon=True).start()

    def status(self, alias):
        # Lifecycle operations can be waiting for Chromium to flush profile data.
        # A UI poll must not wait behind those bounded, but slower operations.
        if not self.lock.acquire(blocking=False):
            cached = self._status_cache.get(alias)
            return cached[1] if cached else '启动未完成'
        try:
            cached = self._status_cache.get(alias)
            if cached and time.monotonic() - cached[0] < .4:
                return cached[1]
            value = self._status(alias)
            self._status_cache[alias] = (time.monotonic(), value)
            return value
        finally:
            self.lock.release()

    def statuses(self, aliases=None):
        """Read many statuses using one process scan, retaining live control checks."""
        aliases = list(dict.fromkeys(self.profiles if aliases is None else aliases))
        if not self.lock.acquire(blocking=False):
            return {alias: self._status_cache.get(alias, (None, '启动未完成'))[1] for alias in aliases}
        deferred_forgets = set()
        try:
            now = time.monotonic()
            result = {}
            pending = []
            for alias in aliases:
                cached = self._status_cache.get(alias)
                if cached and now - cached[0] < .4:
                    result[alias] = cached[1]
                else:
                    pending.append(alias)
            if pending:
                snapshot = ProfileProcessSnapshot(browser_names={
                    Path(self.profiles[alias]['core_path']).name for alias in pending})
                for alias in pending:
                    value = self._status(alias, snapshot=snapshot, deferred_forgets=deferred_forgets)
                    self._status_cache[alias] = (time.monotonic(), value)
                    result[alias] = value
            return result
        finally:
            try:
                if deferred_forgets:
                    self._save()
            except (OSError, LocalBrowserError):
                pass  # A dead PID is never trusted when the manager next starts.
            finally:
                self.lock.release()

    def _status(self, alias, *, snapshot=None, deferred_forgets=None):
        if snapshot is None:
            valid = self._ensure_record(alias)
        else:
            profile = Path(self.profiles[alias]['profile_path'])
            processes = snapshot.browsers(profile)
            record = self.state.get(alias)
            valid = bool(record and snapshot.has_pid(record.get('pid')) and self._record_valid(alias))
            if not valid:
                valid = self._adopt(alias, processes=processes)
            if not valid and snapshot.uncertain(profile, pid=(record or {}).get('pid')):
                return '启动未完成'
        if valid:
            if _visible_windows(self.state[alias]['pid']):
                self._windowless_since.pop(alias, None)
                observed = self.state[alias].get('window_observed', False)
                self.state[alias]['window_observed'] = True
                if not self.state[alias].get('ready', True):
                    try:
                        self.endpoint(alias, timeout=.4)
                        self.state[alias]['ready'] = True
                        self._save()
                    except (OSError, ValueError, KeyError, LocalBrowserError, psutil.Error):
                        return '启动未完成'
                elif not observed:
                    try:
                        self._save()
                    except (OSError, LocalBrowserError):
                        pass
                return '已打开'
            if not self.state[alias].get('window_observed') and time.time() - self.state[alias]['created'] < 25:
                return '启动未完成'
            self._queue_windowless_close(alias)
            return '正在关闭'
        if snapshot is not None:
            processes = snapshot.browsers(profile)
            if snapshot.uncertain(profile, pid=(record or {}).get('pid')):
                return '启动未完成'
            if alias in self.state:
                self._forget(alias, deferred=deferred_forgets)
            return '已在其他进程打开' if processes else '未打开'
        if alias in self.state:
            self._forget(alias)
        return '已在其他进程打开' if _profile_browsers(Path(self.profiles[alias]['profile_path'])) else '未打开'

    def endpoint(self, alias, *, timeout=1):
        with self.lock:
            if not self._record_valid(alias):
                raise LocalBrowserError('该窗口尚未打开。')
            record = self.state[alias]
            # A helper with the same profile is not authority for this listener.
            owners = [psutil.Process(record['pid'])]
            if not any(connection.status == psutil.CONN_LISTEN and connection.laddr.port == record['port']
                       for process in owners for connection in process.net_connections(kind='tcp')):
                raise LocalBrowserError('无法确认窗口的本地控制接口。')
            return _endpoint(record['port'], timeout=timeout)

    def open(self, alias, *, offline_test=False, extra_urls=None, bootstrap_blank=False, before_launch=None, background_probe=False, background_desktop=None):
        with self.lock:
            if background_desktop is not None and not background_probe:
                raise LocalBrowserError('后台验证桌面只用于独立空白环境检查。')
            if background_probe:
                item = self.profiles[alias]
                if (not offline_test or not bootstrap_blank or extra_urls != ['about:blank']
                        or not item.get('new_profile') or item.get('restore_session', True)
                        or item.get('managed_extension') or any(item.get(key) for key in
                            ('account_platform', 'account_username', 'account_password'))):
                    raise LocalBrowserError('后台环境验证只能使用独立空白测试资料，未启动浏览器。')
                if str(item.get('core_major'))=='104' and background_desktop is None:
                    raise LocalBrowserError('此旧版内核需要独立后台验证桌面，未启动检查窗口。')
            self._status_cache.pop(alias, None)
            if self._ensure_record(alias):
                record = self.state[alias]
                current=self.profiles[alias]
                if current.get('local_proxy_mode')=='local':
                    from browser_policy import verify_proxy_extensions,verify_running_proxy_args
                    verify_proxy_extensions(current['profile_path'],current.get('managed_extension'))
                    try:valid=verify_running_proxy_args(psutil.Process(record['pid']).cmdline(),current.get('local_proxy_port'))
                    except (psutil.Error,OSError,ValueError):valid=False
                    if not valid:raise LocalBrowserError('已有窗口的代理隔离规则无法确认，请正常关闭该窗口后重新打开。')
                if not record.get('window_observed'):
                    deadline = time.monotonic() + max(0, 25 - (time.time() - record['created']))
                    while time.monotonic() < deadline and self._record_valid(alias):
                        if _visible_windows(record['pid']):
                            break
                        time.sleep(.1)
                if _visible_windows(self.state[alias]['pid']):
                    self.endpoint(alias)
                    self.activate(alias)
                    self.state[alias]['ready']=True
                    self.state[alias]['window_observed']=True
                    self._save()
                    return self.state[alias]
                # Finish saving the old instance before launching a new window.
                self.close(alias)
            item = self.profiles[alias]
            profile = Path(item['profile_path']).resolve()
            if _profile_browsers(profile):
                raise LocalBrowserError('这份资料已被其他浏览器使用，请先正常关闭该窗口。')
            if not profile.is_dir() or (not item.get('new_profile') and not (profile / 'Local State').is_file()):
                raise LocalBrowserError('窗口资料不完整，已停止打开。')
            executable = Path(item['core_path'])
            config = Path(item['fingerprint_path'])
            for path in (executable, config):
                if not path.is_file():
                    raise LocalBrowserError('所需内核或指纹文件不存在。')
            if not self._core_valid(item):
                raise LocalBrowserError('内核文件已变化，请先重新核对兼容性。')
            if sha256(config) != item['fingerprint_sha256']:
                raise LocalBrowserError('窗口指纹文件已变化，已停止打开。')
            from signature_lifetime import require_current_signature,runtime_signature_options
            require_current_signature(config,core_major=item.get('core_major'),**runtime_signature_options(item,self.root))
            port = _free_port()
            args = [str(executable), f'--user-data-dir={profile}', f'--fingerprint-config={config}',
                    f'--remote-debugging-port={port}', '--remote-debugging-address=127.0.0.1',
                    f'--file-url-path-alias=/gen={executable.parent / "gen"}', '--no-default-browser-check',
                    '--no-first-run', '--disable-background-mode', '--disable-blink-features=AutomationControlled']
            if item.get('restore_session',True) and not bootstrap_blank:
                args.append('--restore-last-session')
            if item.get('window_size_once'):
                width,height=item['window_size_once']
                args.append(f'--window-size={int(width)},{int(height)}')
            if item.get('managed_extension'):
                args.append('--load-extension='+str(item['managed_extension']))
            if item.get('local_proxy_mode')=='local':
                from browser_policy import verify_proxy_extensions
                verify_proxy_extensions(profile,item.get('managed_extension'))
                port_value=int(item['local_proxy_port'])
                if not 1<=port_value<=65535:raise LocalBrowserError('本地代理端口无效。')
                args.extend(['--proxy-server=http://127.0.0.1:'+str(port_value),'--proxy-bypass-list=<-loopback>',
                             '--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
                             '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'])
            elif item.get('local_proxy_mode')=='direct':
                args.append('--no-proxy-server')
            from browser_policy import validate_launch_args
            validate_launch_args(item.get('launch_args') or [],proxy_active=bool(item.get('local_proxy_mode')))
            for argument in item.get('launch_args') or []:
                args.append(argument)
            if item.get('account_platform') and (item.get('account_username') or item.get('account_password')):
                args.extend(['--website-url='+item['account_platform'].rstrip('/')+'/',
                             '--website-username='+item.get('account_username',''),'--website-password='+item.get('account_password','')])
            if item.get('language'):
                args.append('--lang=' + item['language'])
            if item.get('mute_audio'):
                args.append('--mute-audio')
            if item.get('disable_gpu'):
                args.append('--disable-gpu')
            if item.get('no_system_proxy'):
                args.append('--x-dont-nest-system-proxy')
            if offline_test:
                args.extend(['--disable-background-networking', '--disable-component-update', '--disable-sync',
                             '--disable-extensions', '--disable-quic',
                             '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost',
                             '--proxy-server=http://127.0.0.1:1'])
            if background_probe and background_desktop is None:
                # Unified Chromium uses the same browser/renderer without showing
                # a platform window. Continuity checks still compare every field.
                args.append('--headless=new')
            urls = ['about:blank'] if bootstrap_blank else list(extra_urls) if extra_urls is not None else list(item.get('open_urls_once') or [])
            if not urls and not offline_test and not bootstrap_blank:
                sessions = profile / 'Default' / 'Sessions'
                has_saved_session = sessions.is_dir() and any(
                    path.name.startswith('Session_') and path.is_file() and path.stat().st_size > 8
                    for path in sessions.iterdir())
                if not item.get('restore_session',True) or not has_saved_session:
                    urls = item.get('initial_urls') or []
            args.extend(urls)
            try:
                self._save()
            except (OSError, LocalBrowserError):
                raise LocalBrowserError('无法保存运行记录，已停止启动；请检查磁盘空间和文件占用。') from None
            if before_launch is not None:
                before_launch()
            require_current_signature(config,core_major=item.get('core_major'),**runtime_signature_options(item,self.root))
            _check_launch_paths(executable)
            presentation={'startupinfo':background_desktop.startupinfo()} if background_desktop is not None else {}
            # Older Chromium writes debug.log in its working directory even
            # during startup failures; keep that out of the immutable engine.
            working_directory=profile if str(item.get('core_major'))=='104' else executable.parent
            process = subprocess.Popen(args, cwd=working_directory, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,**presentation)
            try:
                created = psutil.Process(process.pid).create_time()
            except psutil.Error:
                if self._adopt(alias):
                    return self.state[alias]
                raise LocalBrowserError('内核未能完成启动，资料已保留。') from None
            self.state[alias] = {'pid': process.pid, 'created': created, 'port': port, 'ready': False, 'window_observed': False}
            self._windowless_since.pop(alias, None)
            record_failed = False
            try:
                self._save()
            except (OSError, LocalBrowserError):
                record_failed = True
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                try:
                    self.endpoint(alias)
                except (OSError, LocalBrowserError, psutil.Error, ValueError, KeyError):
                    if process.poll() is not None and not profile_processes(profile):
                        self.state.pop(alias, None)
                        try:
                            self._save()
                        except (OSError, LocalBrowserError):
                            pass
                        raise LocalBrowserError('内核未能打开窗口，资料已保留。') from None
                    time.sleep(.2)
                    continue
                if record_failed:
                    try:
                        self.close(alias)
                    except (OSError, LocalBrowserError):
                        pass
                    if profile_processes(profile):
                        raise LocalBrowserError('运行记录保存失败，窗口已保留；重开管理器可重新识别，也可直接正常关闭浏览器。')
                    raise LocalBrowserError('运行记录保存失败，已正常关闭本次窗口；请检查磁盘和文件占用。')
                self.state[alias]['ready'] = True
                self.state[alias]['window_observed'] = bool(_visible_windows(process.pid))
                try:
                    self._save()
                    item['has_launched'] = True
                    if self.settings.get('persistent', True):
                        write_encrypted(self.root / 'settings.bin', self.settings)
                except (OSError, LocalBrowserError):
                    raise LocalBrowserError('窗口已打开，但管理记录未能完整保存；资料和窗口已保留，重开管理器可重新识别。') from None
                return self.state[alias]
            # Keep the owned process and its recovery record; never kill a live profile on timeout.
            raise LocalBrowserError('窗口启动超时；请检查已显示的浏览器提示，资料已保留。')

    def close(self, alias):
        with self.lock:
            self._status_cache[alias] = (time.monotonic(), '正在关闭')
            if not self._ensure_record(alias):
                if _profile_browsers(Path(self.profiles[alias]['profile_path'])):
                    raise LocalBrowserError('这份资料由其他进程占用，无法验证控制接口；请在对应浏览器中正常关闭。')
                self._forget(alias)
                return
            try:
                self._request_close(alias)
            except (OSError, LocalBrowserError, websocket.WebSocketException):
                # X may close the debug listener a fraction before process exit.
                # With a real window still present, lack of authority is an error.
                if self._record_valid(alias) and _visible_windows(self.state[alias]['pid']):
                    raise
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                if not self._record_valid(alias) and not _profile_browsers(Path(self.profiles[alias]['profile_path'])):
                    self._forget(alias)
                    return
                time.sleep(.2)
            raise LocalBrowserError('窗口仍在退出，请等待浏览器完成保存；未强制结束进程。')

    def activate(self, alias):
        with CDP(self.endpoint(alias)) as connection:
            targets = connection.call('Target.getTargets').get('targetInfos', [])
            page = next((item for item in targets if item.get('type') == 'page'), None)
            if page:
                connection.call('Target.activateTarget', {'targetId': page['targetId']})
        record = self.state.get(alias)
        if not record:
            return
        user = ctypes.WinDLL('user32')
        user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user.IsWindowVisible.argtypes = [wintypes.HWND]
        user.IsIconic.argtypes = [wintypes.HWND]
        user.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user.SetForegroundWindow.argtypes = [wintypes.HWND]
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def callback(window, _):
            pid = wintypes.DWORD()
            user.GetWindowThreadProcessId(window, ctypes.byref(pid))
            if pid.value == record['pid'] and user.IsWindowVisible(window):
                if user.IsIconic(window):
                    user.ShowWindow(window, 9)
                user.SetForegroundWindow(window)
                return False
            return True
        callback_ref = callback_type(callback)
        user.EnumWindows(callback_ref, 0)
