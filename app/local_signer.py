"""Local RSA root and bounded #BT@ signing; no vendor or browser imports.

LocalSigner(root) creates one RSA-2048 key below ``root`` using the configured
local-state protection (folder key in portable mode, DPAPI in legacy mode).
``public_der`` is its 294-byte SubjectPublicKeyInfo and ``key_id`` its SHA256.
``resign(bytes_or_path)`` retains the complete AES payload. ``sign_native``
uses the existing JSON / PKCS7 / AES-CBC envelope convention. Both issue a
finite signature (24 hours by default) using the actual clock. ``verify`` checks this root and
the current lifetime; ``load_private=False`` reads only the public key.
Missing or damaged files in an existing key directory are never replaced.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from local_state import LocalBrowserError, read_encrypted, write_encrypted

MAGIC = b'#BT@' + bytes(4)
SIGNATURE_SIZE = 256
VALIDITY_MS = 24 * 60 * 60 * 1000
MAX_VALIDITY_HOURS = 24 * 365 * 10
MAX_VALIDITY_MS = MAX_VALIDITY_HOURS * 60 * 60 * 1000
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
_PREFIX_SIZE = 12 + SIGNATURE_SIZE + 16
_MAX_TIMESTAMP_MS = 253402300799999  # Last millisecond representable in year 9999.
_INITIALIZATION_LOCK = threading.RLock()


def _read_bounded(path, limit):
    with Path(path).open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Oversized local signing input')
    return data


def _envelope(data):
    if isinstance(data, (str, os.PathLike)):
        data = _read_bounded(data, _PREFIX_SIZE + MAX_PAYLOAD_BYTES)
    elif isinstance(data, (bytes, bytearray, memoryview)):
        if (data.nbytes if isinstance(data, memoryview) else len(data)) > _PREFIX_SIZE + MAX_PAYLOAD_BYTES:
            raise ValueError('Oversized envelope')
        data = bytes(data)
    else:
        raise ValueError('Unsupported envelope input')
    if len(data) < _PREFIX_SIZE + 32 or data[:8] != MAGIC:
        raise ValueError('Invalid envelope header')
    if struct.unpack('>I', data[8:12])[0] != SIGNATURE_SIZE:
        raise ValueError('Unsupported signature size')
    signature = data[12:12 + SIGNATURE_SIZE]
    times = data[12 + SIGNATURE_SIZE:_PREFIX_SIZE]
    created, expires = struct.unpack('>QQ', times)
    if not 0 < created < expires <= _MAX_TIMESTAMP_MS:
        raise ValueError('Invalid envelope lifetime')
    ciphertext = data[_PREFIX_SIZE:]
    if len(ciphertext) % 16:
        raise ValueError('Unaligned AES payload')
    return signature, times, created, expires, ciphertext


@contextmanager
def _initialization_lock(root):
    """Serialize initial publication across threads and Windows processes."""
    with _INITIALIZATION_LOCK:
        descriptor = os.open(root / 'local-signing.lock', os.O_RDWR | os.O_CREAT | getattr(os, 'O_BINARY', 0), 0o600)
        with os.fdopen(descriptor, 'r+b') as handle:
            deadline = time.monotonic() + 10
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
            while True:
                try:
                    lock()
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise LocalBrowserError('本地签名密钥正在初始化，请稍后重试。') from None
                    time.sleep(0.05)
            try:
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b'\0')
                    handle.flush()
                yield handle
            finally:
                unlock()


class LocalSigner:
    def __init__(self, root=None, *, load_private=True, validity_hours=24):
        if (isinstance(validity_hours, bool) or not isinstance(validity_hours, (int, float))
                or not 0 < validity_hours <= MAX_VALIDITY_HOURS
                or validity_hours * 3_600_000 < 1):
            raise LocalBrowserError('本地签名期限须为正数且不超过十年。')
        self.validity_ms = int(validity_hours * 3_600_000)
        self.root = Path(root) if root is not None else Path(__file__).resolve().parent / 'data'
        self.directory = self.root / 'local-signing'
        self.public_path = self.directory / 'public.der'
        self._private_path = self.directory / 'private.bin'
        self._private_key = None
        try:
            if load_private:
                self.root.mkdir(parents=True, exist_ok=True)
                with _initialization_lock(self.root) as marker:
                    marker.seek(0)
                    identity = marker.read(67)
                    if identity != b'\0' and (len(identity) != 65 or identity[:1] != b'\1'):
                        raise ValueError('Damaged signing identity marker')
                    if not self.directory.exists() and not self.directory.is_symlink():
                        if identity != b'\0':
                            raise ValueError('Previously initialized signing key is missing')
                        self._create_key()
                    self._load_public()
                    expected = b'\1' + self.key_id.encode('ascii')
                    if identity not in (b'\0', expected):
                        raise ValueError('Local signing identity changed')
                    self._load_private()
                    if identity == b'\0':
                        marker.seek(0)
                        marker.write(expected)
                        marker.truncate()
                        marker.flush()
                        os.fsync(marker.fileno())
            else:
                self._load_public()
                if _read_bounded(self.root / 'local-signing.lock', 65) != b'\1' + self.key_id.encode('ascii'):
                    raise ValueError('Local signing identity mismatch')
        except LocalBrowserError:
            raise
        except Exception:
            raise LocalBrowserError('本地签名密钥缺失、损坏或无法读取，已停止操作；不会覆盖已有密钥。') from None

    def _create_key(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = key.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
        private = key.private_bytes(serialization.Encoding.DER,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        staging = Path(tempfile.mkdtemp(prefix='.local-signing-', dir=self.root))
        try:
            write_encrypted(staging / 'private.bin', {
                'version': 1, 'key_id': hashlib.sha256(public).hexdigest(),
                'private_der': base64.b64encode(private).decode('ascii')})
            with (staging / 'public.der').open('xb') as handle:
                handle.write(public)
                handle.flush()
                os.fsync(handle.fileno())
            # Publish the pair together; an incomplete directory is never visible.
            os.rename(staging, self.directory)
        finally:
            if staging.exists():
                if staging.resolve().parent != self.root.resolve() or not staging.name.startswith('.local-signing-'):
                    raise ValueError('Unexpected signing staging directory')
                shutil.rmtree(staging)

    def _load_public(self):
        if self.directory.is_symlink() or not self.directory.is_dir():
            raise ValueError('Missing signing root')
        public = _read_bounded(self.public_path, 294)
        key = serialization.load_der_public_key(public)
        if (len(public) != 294 or not isinstance(key, rsa.RSAPublicKey)
                or key.key_size != 2048 or key.public_numbers().e != 65537):
            raise ValueError('Unexpected local public key')
        self.public_der = public
        self.key_id = hashlib.sha256(public).hexdigest()
        self._public_key = key

    def _load_private(self):
        if not self._private_path.is_file() or self._private_path.stat().st_size > 65536:
            raise ValueError('Missing or oversized private key')
        try:
            record = read_encrypted(self._private_path)
        except LocalBrowserError:
            raise LocalBrowserError('本地签名私钥无法解密，请检查完整目录、加密密钥或旧版Windows用户环境；不会覆盖已有密钥。') from None
        if not isinstance(record, dict) or record.get('version') != 1 or record.get('key_id') != self.key_id:
            raise ValueError('Local key identity mismatch')
        encoded = record.get('private_der')
        if not isinstance(encoded, str) or len(encoded) > 8192:
            raise ValueError('Invalid private key record')
        key = serialization.load_der_private_key(base64.b64decode(encoded, validate=True), password=None)
        if (not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048
                or key.public_key().public_numbers() != self._public_key.public_numbers()):
            raise ValueError('Local key pair mismatch')
        self._private_key = key

    def _sign_payload(self, ciphertext):
        if self._private_key is None:
            raise LocalBrowserError('当前仅加载本地公钥，不能签发启动配置。')
        if not 32 <= len(ciphertext) <= MAX_PAYLOAD_BYTES or len(ciphertext) % 16:
            raise LocalBrowserError('启动配置载荷长度无效，未签发本地配置。')
        created = time.time_ns() // 1_000_000
        expires = created + self.validity_ms
        if not 0 < created < expires <= _MAX_TIMESTAMP_MS:
            raise LocalBrowserError('系统时间超出本地签名支持范围，未签发配置。')
        times = struct.pack('>QQ', created, expires)
        signature = self._private_key.sign(hashlib.sha256(ciphertext).digest() + times,
                                           padding.PKCS1v15(), hashes.SHA256())
        return MAGIC + struct.pack('>I', len(signature)) + signature + times + ciphertext

    def resign(self, envelope):
        """Replace only RSA signature/times; preserve every byte of AES payload."""
        try:
            ciphertext = _envelope(envelope)[4]
        except (OSError, ValueError, TypeError, struct.error):
            raise LocalBrowserError('原启动配置格式或长度无效，未签发本地配置。') from None
        return self._sign_payload(ciphertext)

    def sign_native(self, native, aes_key, *, core_major=None):
        """Serialize native configuration with the existing AES-CBC convention."""
        from core_specs import CORE_SPECS
        legacy = (str(core_major) in CORE_SPECS and int(core_major) < 130
                  and isinstance(native, dict) and bool(native.get('Resource'))
                  and native.get('DataProtect') is None)
        if not legacy and (not isinstance(native, dict) or not isinstance(native.get('DataProtect'), dict)
                or not native['DataProtect'].get('CipherKey')):
            raise LocalBrowserError('缺少匹配的数据保护配置，未签发本地配置。')
        if not isinstance(aes_key, bytes) or len(aes_key) not in (16, 24, 32):
            raise LocalBrowserError('本地配置加密密钥格式无效。')
        try:
            raw = json.dumps(native, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise LocalBrowserError('启动配置无法完整编码，未签发本地配置。') from None
        pad = 16 - len(raw) % 16
        if len(raw) + pad + 16 > MAX_PAYLOAD_BYTES:
            raise LocalBrowserError('启动配置过大，未签发本地配置。')
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
        return self._sign_payload(iv + cipher.update(raw + bytes([pad]) * pad) + cipher.finalize())

    def verify(self, envelope, *, now_ms=None):
        """Return whether this root signed a current, bounded-lifetime envelope."""
        try:
            signature, times, created, expires, ciphertext = _envelope(envelope)
            if expires - created > MAX_VALIDITY_MS:
                return False
            self._public_key.verify(signature, hashlib.sha256(ciphertext).digest() + times,
                                    padding.PKCS1v15(), hashes.SHA256())
            if now_ms is not None and (isinstance(now_ms, bool) or not isinstance(now_ms, (int, float))):
                return False
            now_ns = time.time_ns() if now_ms is None else now_ms * 1_000_000
            # Native lifetime checks include the exact expiry millisecond.
            return created * 1_000_000 <= now_ns <= expires * 1_000_000
        except (InvalidSignature, OSError, ValueError, TypeError, OverflowError, struct.error):
            return False
