"""Remove only rebuildable caches from explicitly selected, closed local profiles.

Directory handles pin every literal ancestor on Windows. Files are checked and
unlinked through their own handles, so a path replacement cannot redirect a
delete. Empty directories and all persistent browser state are retained.
"""
from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes
import os
import re
import stat
import time

from delete_paths import absolute, checked
from local_state import LocalBrowserError
from native_paths import io_path


CACHE_PATHS = ('Default/Cache', 'Default/Code Cache', 'Default/GPUCache',
               'GPUCache', 'ShaderCache', 'GrShaderCache', 'DawnGraphiteCache')
MAX_ENTRIES = 100000
MAX_DIRECTORIES = 4096
MAX_DEPTH = 32
PROFILE_SECONDS = 30
BATCH_SECONDS = 120


class _CacheError(LocalBrowserError):
    pass


class _Skipped(_CacheError):
    pass


def _plain(info, directory):
    if (stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or not directory and info.st_nlink != 1):
        raise _CacheError('缓存路径含链接、重解析点或非普通文件，已停止清理。')


def _stamp(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


class _FileInfo(ctypes.Structure):
    _fields_ = [('attributes', wintypes.DWORD), ('created', wintypes.FILETIME),
                ('accessed', wintypes.FILETIME), ('written', wintypes.FILETIME),
                ('volume', wintypes.DWORD), ('size_high', wintypes.DWORD),
                ('size_low', wintypes.DWORD), ('links', wintypes.DWORD),
                ('index_high', wintypes.DWORD), ('index_low', wintypes.DWORD)]


class _Disposition(ctypes.Structure):
    _fields_ = [('delete', wintypes.BYTE)]


class _FileIdentity(ctypes.Structure):
    _fields_ = [('volume', ctypes.c_ulonglong), ('identifier', wintypes.BYTE * 16)]


class _WindowsFiles:
    def __init__(self):
        if os.name != 'nt':
            raise _CacheError('当前系统不支持安全缓存清理，资料已保留。')
        self.api = ctypes.WinDLL('kernel32', use_last_error=True)
        self.api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.api.CreateFileW.restype = wintypes.HANDLE
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        self.api.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_FileInfo)]
        self.api.GetFileInformationByHandle.restype = wintypes.BOOL
        self.api.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.GetFileInformationByHandleEx.restype = wintypes.BOOL
        self.api.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                       ctypes.c_void_p, wintypes.DWORD]
        self.api.SetFileInformationByHandle.restype = wintypes.BOOL

    @contextmanager
    def open(self, path, *, directory):
        # Deny WRITE as well as DELETE: an empty directory must not be changed
        # into a junction in place while its path is pinned.
        # Attribute-only directory opens do not enforce NT sharing; requesting
        # GENERIC_READ is required for the pin to actually reject a rename.
        access = 0x80000000 if directory else 0x10080
        share = 1
        flags = 0x02200000  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        handle = self.api.CreateFileW(str(io_path(path)), access, share, None, 3, flags, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = _FileInfo()
            if not self.api.GetFileInformationByHandle(handle, ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if (info.attributes & 0x400 or bool(info.attributes & 0x10) != directory
                    or not directory and info.links != 1):
                raise _CacheError('缓存路径含链接、重解析点或非普通文件，已停止清理。')
            current = io_path(path).lstat()
            _plain(current, directory)
            identity = _FileIdentity()
            if not self.api.GetFileInformationByHandleEx(handle, 18, ctypes.byref(identity), ctypes.sizeof(identity)):
                raise ctypes.WinError(ctypes.get_last_error())
            if (current.st_dev, current.st_ino) != (identity.volume, int.from_bytes(bytes(identity.identifier), 'little')):
                raise _CacheError('缓存路径在检查期间发生变化，已停止清理。')
            yield handle, current
        finally:
            self.api.CloseHandle(handle)

    def remove_file(self, path, expected):
        with self.open(path, directory=False) as (handle, current):
            if _stamp(current) != expected:
                raise _CacheError('缓存文件在检查期间发生变化，已停止清理。')
            disposition = _Disposition(True)
            if not self.api.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                raise ctypes.WinError(ctypes.get_last_error())
        # Do not claim bytes for a still-open delete-pending file or a new file.
        try:
            io_path(path).lstat()
        except FileNotFoundError:
            return current.st_size
        raise _CacheError('部分缓存仍被占用或发生变化，请稍后重试。')


class _Scan:
    def __init__(self, deadline, stack):
        self.deadline = deadline
        self.stack = stack
        self.api = _WindowsFiles()
        self.pinned = set()
        self.files = []
        self.entries = 0

    def tick(self):
        if time.monotonic() >= self.deadline:
            raise _CacheError('缓存清理达到本次时间上限，请重试剩余缓存。')

    def pin(self, path, *, optional=False):
        for part in reversed((path, *path.parents)):
            self.tick()
            if part in self.pinned:
                continue
            try:
                info = io_path(part).lstat()
            except FileNotFoundError:
                if optional:
                    return False
                raise
            _plain(info, True)
            if len(self.pinned) >= MAX_DIRECTORIES:
                raise _CacheError('缓存目录数量超出安全上限，未继续清理。')
            _handle, current = self.stack.enter_context(self.api.open(part, directory=True))
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise _CacheError('缓存目录在检查期间发生变化，已停止清理。')
            self.pinned.add(part)
        return True

    def scan(self, profile):
        self.pin(profile)
        for relative in CACHE_PATHS:
            folder = profile / relative
            if not self.pin(folder, optional=True):
                continue
            pending = [(folder, 0)]
            while pending:
                self.tick()
                current, depth = pending.pop()
                with os.scandir(io_path(current)) as entries:
                    for entry in entries:
                        self.tick()
                        self.entries += 1
                        if self.entries > MAX_ENTRIES or depth >= MAX_DEPTH:
                            raise _CacheError('缓存文件数量或目录深度超出安全上限，未继续清理。')
                        path = current / entry.name
                        info = io_path(path).lstat()
                        directory = stat.S_ISDIR(info.st_mode)
                        _plain(info, directory)
                        if directory:
                            self.pin(path)
                            pending.append((path, depth + 1))
                        else:
                            self.files.append((path, _stamp(info)))


def _owned(service, identity):
    service._require_available(identity)
    record = service.store.get(identity)
    runtime = record.get('_runtime')
    if record.get('id') != identity or not isinstance(runtime, dict):
        raise _CacheError('窗口资料归属不一致，未清理缓存。')
    if record.get('archived') or record.get('delete_pending') or record.get('config_status') == 'delete_pending':
        raise _Skipped('窗口已归档或正在删除，已跳过缓存清理。')
    root = absolute(service.root)
    profile = root / 'profiles' / identity
    declared = runtime.get('profile_path')
    if (not isinstance(declared, str) or not declared or absolute(declared) != profile
            or runtime.get('alias', identity) != identity):
        raise _CacheError('窗口资料不属于本地受管目录，未清理缓存。')
    checked(profile, root)
    return record, profile


def _closed(service, record):
    controller = getattr(service, 'controller', None)
    if controller is not None:
        if record['id'] in getattr(controller, '_closing_workers', set()):
            raise _Skipped('窗口正在关闭，已跳过；请正常关闭完成后重试。')
        state = getattr(controller, 'state', {}).get(record['id']) or {}
        if state.get('ready') is False:
            raise _Skipped('窗口启动或关闭状态尚未确认，已跳过缓存清理。')
    try:
        service._closed(record)
    except Exception:
        raise _Skipped('窗口仍在运行或无法确认已关闭，已跳过；请正常关闭后重试。') from None


def _one(service, identity, batch_deadline):
    result = {'id': identity, 'status': 'failed', 'removed_files': 0, 'removed_bytes': 0, 'message': ''}
    try:
        with service._window_operation(identity):
            record, profile = _owned(service, identity)
            _closed(service, record)
            with ExitStack() as stack:
                scan = _Scan(min(batch_deadline, time.monotonic() + PROFILE_SECONDS), stack)
                scan.scan(profile)
                # The scan is complete before the first delete; bad links or
                # oversized trees cannot cause a partially authorized cleanup.
                scan.tick()
                _closed(service, record)
                failures = 0
                next_check = time.monotonic() + .5
                for path, expected in scan.files:
                    scan.tick()
                    if time.monotonic() >= next_check:
                        _closed(service, record)
                        next_check = time.monotonic() + .5
                    try:
                        removed = scan.api.remove_file(path, expected)
                    except _CacheError:
                        raise
                    except OSError:
                        failures += 1
                        continue
                    result['removed_files'] += 1
                    result['removed_bytes'] += removed
                if failures:
                    raise _CacheError('部分缓存被占用或无法删除，已保留未完成部分；请稍后重试。')
                _closed(service, record)
                scan.files.clear()
                scan.entries = 0
                scan.scan(profile)
                if scan.files:
                    raise _CacheError('缓存目录在清理期间新增或改变文件，已保留这些文件；请稍后重试。')
                result.update(status='cleaned', message='缓存清理完成。' if result['removed_files'] else '没有可清理的缓存。')
    except _Skipped as exc:
        result.update(status='failed' if result['removed_files'] else 'skipped', message=str(exc))
    except _CacheError as exc:
        result['message'] = str(exc)
    except Exception:
        result['message'] = '无法安全确认资料或完成缓存清理，已停止；请稍后重试。'
    return result


def clear_cache(service, identities):
    """Return per-window results; byte counts are deleted logical file sizes."""
    if (not isinstance(identities, list) or not 1 <= len(identities) <= 100
            or any(not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]{1,80}', value) for value in identities)
            or len({value.casefold() for value in identities}) != len(identities)):
        raise LocalBrowserError('请选择 1 至 100 个有效且不重复的窗口清理缓存。')
    deadline = time.monotonic() + BATCH_SECONDS
    activity = service.operations.shared() if hasattr(service.operations, 'shared') else service.operations
    with activity:
        results = [_one(service, identity, deadline) for identity in identities]
    return {'completed': sum(item['status'] == 'cleaned' for item in results),
            'skipped': sum(item['status'] == 'skipped' for item in results),
            'failed': sum(item['status'] == 'failed' for item in results),
            'removed_files': sum(item['removed_files'] for item in results),
            'removed_bytes': sum(item['removed_bytes'] for item in results), 'results': results}
