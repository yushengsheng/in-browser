"""Folder-bound AES-GCM storage, independent of Windows users and DPAPI.

``PortableVault(root)`` only reads existing state. Call ``initialize()`` to
explicitly create a new root. Copy the complete root folder, including hidden
files, to retain automatic unlocking on another machine. Possession of that
folder includes the ability to decrypt it. There is no password or recovery
service: losing ``.portable-vault/.portable-key`` makes its data unrecoverable.
Missing or damaged initialized files are never silently replaced or redirected
to another root. Legacy DPAPI detection and migration belong to the caller.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'LPVAULT\x01'
DIRECTORY_NAME = '.portable-vault'
KEY_FILENAME = '.portable-key'
MARKER_FILENAME = 'identity'
LOCK_FILENAME = '.portable-vault.lock'
MAX_PLAINTEXT_BYTES = 16 * 1024 * 1024
_MARKER_MAGIC = b'LPVROOT\x01'
_KEY_SIZE = 32
_KEY_ID_SIZE = 32
_NONCE_SIZE = 12
_HEADER_SIZE = len(MAGIC) + _KEY_ID_SIZE + _NONCE_SIZE
_ENVELOPE_OVERHEAD = _HEADER_SIZE + 16
_INITIALIZATION_LOCK = threading.RLock()


class PortableVaultError(Exception):
    """A bounded, non-secret explanation of an unavailable or invalid vault."""


def is_portable(data):
    """Recognize this version's byte prefix without reading or loading a key."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return False
    try:
        return bytes(memoryview(data).cast('B')[:len(MAGIC)]) == MAGIC
    except (TypeError, ValueError):
        return False


def _read_exact(path, size):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Missing or linked vault file')
    with path.open('rb') as handle:
        data = handle.read(size + 1)
    if len(data) != size:
        raise ValueError('Invalid vault file size')
    return data


def _fsync_directory(path):
    # Windows does not support opening a directory through os.open for fsync.
    if os.name != 'nt':
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


@contextmanager
def _initialization_lock(root):
    """Serialize explicit creation across threads and operating-system processes."""
    with _INITIALIZATION_LOCK:
        lock_path = root / LOCK_FILENAME
        if lock_path.is_symlink():
            raise ValueError('Linked vault lock')
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_BINARY', 0)
                             | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(descriptor, 'r+b') as handle:
            if os.name == 'nt':
                import msvcrt

                def lock():
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

                def unlock():
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                def lock():
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

                def unlock():
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

            deadline = time.monotonic() + 10
            while True:
                try:
                    lock()
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise PortableVaultError('便携密钥正在初始化，请稍后重试。') from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                unlock()


def _bounded_bytes(data, limit):
    if (not isinstance(data, (bytes, bytearray, memoryview))
            or (data.nbytes if isinstance(data, memoryview) else len(data)) > limit):
        raise PortableVaultError('便携加密数据类型或长度无效。')
    return bytes(data)


class PortableVault:
    def __init__(self, root=None, *, key_required=False):
        self.root = Path(root) if root is not None else Path(__file__).resolve().parent / 'data'
        self.directory = self.root / DIRECTORY_NAME
        self.key_path = self.directory / KEY_FILENAME
        self.marker_path = self.directory / MARKER_FILENAME
        self.enabled = False
        self.key_id = None
        self._key = None
        self._key_id = None
        self._load(key_required=key_required)

    def _load(self, *, key_required):
        try:
            if not self.directory.exists() and not self.directory.is_symlink():
                if key_required:
                    raise ValueError('Required vault is missing')
                return
            if self.directory.is_symlink() or not self.directory.is_dir():
                raise ValueError('Invalid vault directory')
            key = _read_exact(self.key_path, _KEY_SIZE)
            identity = _read_exact(self.marker_path, len(_MARKER_MAGIC) + _KEY_ID_SIZE)
            key_id = hashlib.sha256(key).digest()
            if identity != _MARKER_MAGIC + key_id:
                raise ValueError('Vault identity mismatch')
            self._key = key
            self._key_id = key_id
            self.key_id = key_id.hex()
            self.enabled = True
        except Exception:
            raise PortableVaultError('便携密钥缺失、损坏或无法读取，已停止操作；不会覆盖已有密钥。') from None

    def initialize(self):
        """Explicitly create one root, or validate and reuse its existing key."""
        staging = None
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            with _initialization_lock(self.root):
                if self.enabled or self.directory.exists() or self.directory.is_symlink():
                    self._load(key_required=True)
                    return self
                key = os.urandom(_KEY_SIZE)
                identity = _MARKER_MAGIC + hashlib.sha256(key).digest()
                staging = Path(tempfile.mkdtemp(prefix='.portable-vault-stage-', dir=self.root))
                for filename, content in ((KEY_FILENAME, key), (MARKER_FILENAME, identity)):
                    descriptor = os.open(staging / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                         | getattr(os, 'O_BINARY', 0), 0o600)
                    with os.fdopen(descriptor, 'wb') as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                _fsync_directory(staging)
                # Publish key and independent identity together; readers see a complete pair.
                os.rename(staging, self.directory)
                staging = None
                _fsync_directory(self.root)
                self._load(key_required=True)
                return self
        except PortableVaultError:
            raise
        except Exception:
            raise PortableVaultError('便携密钥无法初始化，已停止操作；不会覆盖已有密钥。') from None
        finally:
            if staging is not None:
                # Only remove the two files this call created, never an arbitrary tree.
                for filename in (KEY_FILENAME, MARKER_FILENAME):
                    try:
                        (staging / filename).unlink(missing_ok=True)
                    except OSError:
                        pass
                try:
                    staging.rmdir()
                except OSError:
                    pass

    def _require_key(self):
        if not self.enabled or self._key is None:
            raise PortableVaultError('便携加密尚未启用，请先初始化文件夹密钥。')

    def encrypt(self, data):
        """Encrypt bounded bytes with a fresh nonce and an authenticated root/version."""
        self._require_key()
        raw = _bounded_bytes(data, MAX_PLAINTEXT_BYTES)
        try:
            nonce = os.urandom(_NONCE_SIZE)
            aad = MAGIC + self._key_id
            return aad + nonce + AESGCM(self._key).encrypt(nonce, raw, aad)
        except Exception:
            raise PortableVaultError('便携数据无法加密，已停止写入。') from None

    def decrypt(self, data):
        """Reject another root, unsupported versions, tampering and oversized input."""
        self._require_key()
        envelope = _bounded_bytes(data, MAX_PLAINTEXT_BYTES + _ENVELOPE_OVERHEAD)
        try:
            aad = MAGIC + self._key_id
            if len(envelope) < _ENVELOPE_OVERHEAD or envelope[:len(aad)] != aad:
                raise ValueError('Invalid portable envelope')
            nonce = envelope[len(aad):_HEADER_SIZE]
            return AESGCM(self._key).decrypt(nonce, envelope[_HEADER_SIZE:], aad)
        except (InvalidTag, ValueError, TypeError, OverflowError):
            raise PortableVaultError('便携数据无法解密，密钥不匹配或数据已损坏。') from None
