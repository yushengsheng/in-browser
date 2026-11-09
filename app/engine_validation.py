"""Reuse hashes only while Windows read handles prevent writes and replacement.

The cache lives for one launch operation. Every validation still enumerates the
complete tree; no trust or file-content result survives closing these handles.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path

from local_state import LocalBrowserError

_active = ContextVar('engine_validation', default=None)


@contextmanager
def verification_scope():
    if _active.get() is not None or os.name != 'nt':
        yield
        return
    files = {}
    token = _active.set(files)
    try:
        yield
    finally:
        _active.reset(token)
        for stream, _stamp, _values in files.values():
            stream.close()


def _stamp(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _pinned(path, files):
    path = Path(path)
    name = os.path.normcase(os.path.abspath(path))
    current = _stamp(path.stat())
    if name in files:
        entry = files[name]
        if current != entry[1] or _stamp(os.fstat(entry[0].fileno()))[:4] != entry[1][:4]:
            raise LocalBrowserError('内核文件在启动检查期间发生变化，已停止打开。')
        return entry
    library = ctypes.WinDLL('kernel32', use_last_error=True)
    create = library.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    handle = create(str(path), 0x80000000, 1, None, 3, 0x08000000, None)
    if handle == ctypes.c_void_p(-1).value:
        return None  # A writer/scanner can be present; perform the normal read.
    import msvcrt
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        library.CloseHandle.argtypes = [wintypes.HANDLE]
        library.CloseHandle(handle)
        raise
    stream = os.fdopen(descriptor, 'rb')
    try:
        # Windows Python's path stat and CRT fstat expose different ctime
        # semantics. Match file identity/size/mtime through the descriptor and
        # still require the complete path stamp, including change time, twice.
        if _stamp(os.fstat(stream.fileno()))[:4] != current[:4] or _stamp(path.stat()) != current:
            raise LocalBrowserError('内核文件在启动检查期间发生变化，已停止打开。')
    except Exception:
        stream.close()
        raise
    entry = stream, current, {}
    files[name] = entry
    return entry


def digest_file(path, *, offset=None, replacement=None):
    """Hash all bytes, optionally restoring one authenticated 294-byte key."""
    def calculate(stream):
        stream.seek(0)
        digest = hashlib.sha256()
        if offset is not None:
            remaining = offset
            while remaining:
                block = stream.read(min(1024 * 1024, remaining))
                if not block:
                    raise ValueError('Truncated native file')
                digest.update(block)
                remaining -= len(block)
            if len(stream.read(len(replacement))) != len(replacement):
                raise ValueError('Truncated native trust root')
            digest.update(replacement)
        while block := stream.read(1024 * 1024):
            digest.update(block)
        return digest.hexdigest()

    files = _active.get()
    # Unpublished deployment files are deliberately writable until validation
    # and atomic publication finish; never pin them during their own creation.
    staging = any(part.startswith('.install-') for part in Path(path).parts)
    entry = _pinned(path, files) if files is not None and not staging else None
    if entry is None:
        with Path(path).open('rb') as stream:
            return calculate(stream)
    stream, _identity, values = entry
    key = offset, replacement
    if key not in values:
        values[key] = calculate(stream)
    return values[key]
