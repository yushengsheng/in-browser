"""Folder-key storage with explicit legacy DPAPI reads for existing installations."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import tempfile
import threading

_ENCRYPTED_WRITE_LOCK = threading.RLock()


class LocalBrowserError(Exception):
    pass


class _Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi_protect(data: bytes, decrypt: bool = False) -> bytes:
    backing = ctypes.create_string_buffer(data)
    incoming = _Blob(len(data), ctypes.cast(backing, ctypes.POINTER(ctypes.c_ubyte)))
    outgoing = _Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if decrypt:
        method = crypt.CryptUnprotectData
        method.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
        ok = method(ctypes.byref(incoming), None, None, None, None, 1, ctypes.byref(outgoing))
    else:
        method = crypt.CryptProtectData
        method.argtypes = [ctypes.POINTER(_Blob), wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
        ok = method(ctypes.byref(incoming), 'Local browser', None, None, None, 1, ctypes.byref(outgoing))
    if not ok:
        raise LocalBrowserError('无法读取本机加密设置，请使用原 Windows 用户运行。')
    try:
        return ctypes.string_at(outgoing.data, outgoing.size)
    finally:
        kernel.LocalFree(outgoing.data)


def _vault_root(path=None,root=None):
    if root is not None:return Path(root).resolve()
    if path is not None:
        for parent in Path(path).resolve().parents:
            if (parent/'.portable-vault').exists() or (parent/'portable-mode.bin').exists():return parent
        return Path(path).resolve().parent
    return Path(__file__).resolve().parent/'data'


def protect(data: bytes, decrypt: bool = False, *, root=None) -> bytes:
    from portable_vault import PortableVault,PortableVaultError,is_portable
    selected=_vault_root(root=root)
    try:
        vault=PortableVault(selected,key_required=(selected/'portable-mode.bin').exists() or (decrypt and is_portable(data)))
        if decrypt:
            return vault.decrypt(data) if is_portable(data) else _dpapi_protect(data,decrypt=True)
        return vault.encrypt(data) if vault.enabled else _dpapi_protect(data)
    except PortableVaultError:
        raise LocalBrowserError('文件夹密钥缺失、损坏或与资料不匹配，未覆盖密钥或资料；请恢复完整文件夹。') from None


def read_encrypted(path: Path, *, root=None):
    path=Path(path)
    return json.loads(protect(path.read_bytes(), decrypt=True,root=_vault_root(path,root)))


def write_encrypted(path: Path, value, *, root=None):
    path=Path(path)
    content = protect(json.dumps(value, ensure_ascii=False, separators=(',', ':'),allow_nan=False).encode(),root=_vault_root(path,root))
    with _ENCRYPTED_WRITE_LOCK:
        descriptor, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
