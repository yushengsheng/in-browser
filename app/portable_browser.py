"""Carry an existing Chromium OSCrypt key inside the caller's encrypted store.

The returned private dictionary must be saved only through the portable encrypted
catalog. Local State remains a disposable, current-Windows DPAPI wrapper around
that same key; browser databases are never rewritten by this module.
"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from browser_processes import profile_processes
from local_state import LocalBrowserError, _dpapi_protect

_FAILED = '浏览器资料密钥缺失、不受支持或无法验证，未覆盖资料；请保留完整文件夹和原机备份。'
_RUNNING = '浏览器资料正在使用或无法确认关闭状态，未改动资料；请先正常关闭窗口后重试。'
_MAX_STATE_BYTES = 16 * 1024 * 1024
_MAX_WRAPPER_BYTES = 64 * 1024
_MAX_ROWS = 100000
_MAX_BLOB_BYTES = 1024 * 1024
_MAX_DATABASE_BYTES = 64 * 1024 * 1024
_DATABASE_TIMEOUT = 10
_DATABASES = (
    ('Default/Network/Cookies', 'cookies', 'encrypted_value'),
    ('Default/Login Data', 'logins', 'password_value'),
    ('Default/Login Data For Account', 'logins', 'password_value'),
)
_LOCK = threading.RLock()


def _closed(profile):
    try:
        running = profile_processes(profile, require_inspectable=True)
    except Exception:
        raise LocalBrowserError(_RUNNING) from None
    if running:
        raise LocalBrowserError(_RUNNING)


def _stamp(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read_state(profile):
    path = profile / 'Local State'
    before = path.stat()
    if not path.is_file() or before.st_size > _MAX_STATE_BYTES:
        raise ValueError('Unsupported state')
    with path.open('rb') as handle:
        content = handle.read(_MAX_STATE_BYTES + 1)
    if len(content) > _MAX_STATE_BYTES or _stamp(before) != _stamp(path.stat()):
        raise ValueError('State changed')
    state = json.loads(content)
    if not isinstance(state, dict):
        raise ValueError('Unsupported state')
    crypt = state.get('os_crypt', {})
    if not isinstance(crypt, dict) or crypt.get('app_bound_encrypted_key'):
        raise ValueError('Unsupported key provider')
    return state, (_stamp(before), hashlib.sha256(content).digest())


def _unchanged(profile, identity):
    _state, current = _read_state(profile)
    if current != identity:
        raise ValueError('State changed')


def _unwrap(encoded):
    if not isinstance(encoded, str) or len(encoded) > _MAX_WRAPPER_BYTES * 2:
        raise ValueError('Unsupported wrapper')
    wrapped = base64.b64decode(encoded, validate=True)
    if len(wrapped) > _MAX_WRAPPER_BYTES or not wrapped.startswith(b'DPAPI'):
        raise ValueError('Unsupported wrapper')
    key = _dpapi_protect(wrapped[5:], decrypt=True)
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('Unsupported key')
    return key


def _private_key(private):
    if not isinstance(private, dict) or private.get('format') != 1:
        raise ValueError('Unsupported private record')
    encoded = private.get('key')
    key_id = private.get('key_id')
    if not isinstance(encoded, str) or len(encoded) != 44 or not isinstance(key_id, str) or len(key_id) != 64:
        raise ValueError('Unsupported private record')
    key = base64.b64decode(encoded, validate=True)
    if len(key) != 32 or not hmac.compare_digest(hashlib.sha256(key).hexdigest(), key_id):
        raise ValueError('Private key mismatch')
    return key


def _validate_database(path, table, column, cipher):
    if not path.exists():
        return
    if not path.is_file():
        raise ValueError('Unsupported database')
    deadline = time.monotonic() + _DATABASE_TIMEOUT
    connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        connection.execute('PRAGMA query_only=ON')
        connection.execute('BEGIN')
        # These identifiers come exclusively from the fixed _DATABASES tuple.
        where = f'{column} IS NOT NULL AND length({column}) > 0'
        count, largest, total = connection.execute(
            f'SELECT count(*),coalesce(max(length({column})),0),coalesce(sum(length({column})),0) FROM {table} WHERE {where}'
        ).fetchone()
        if count > _MAX_ROWS or largest > _MAX_BLOB_BYTES or total > _MAX_DATABASE_BYTES:
            raise ValueError('Database budget exceeded')
        cursor = connection.execute(f'SELECT {column} FROM {table} WHERE {where}')
        seen = 0
        while rows := cursor.fetchmany(32):
            for (value,) in rows:
                seen += 1
                if time.monotonic() >= deadline or seen > _MAX_ROWS:
                    raise ValueError('Database budget exceeded')
                if not isinstance(value, bytes) or not value.startswith(b'v10') or len(value) < 31:
                    raise ValueError('Unsupported encrypted value')
                clear = cipher.decrypt(value[3:15], value[15:], None)
                del clear
        if seen != count:
            raise ValueError('Database changed')
    finally:
        connection.close()


def _validate_databases(profile, key):
    cipher = AESGCM(key)
    for relative, table, column in _DATABASES:
        _validate_database(profile / relative, table, column, cipher)


def capture_profile(profile):
    """Return private OSCrypt material after authenticating supported data.

    No account, cookie value or password plaintext is returned. Missing or empty
    database values are allowed; unknown nonempty schemes fail closed.
    """
    with _LOCK:
        try:
            profile = Path(profile).resolve()
            _closed(profile)
            state, identity = _read_state(profile)
            key = _unwrap(state.get('os_crypt', {}).get('encrypted_key'))
            _validate_databases(profile, key)
            _closed(profile)
            _unchanged(profile, identity)
            return {'format': 1, 'key': base64.b64encode(key).decode('ascii'),
                    'key_id': hashlib.sha256(key).hexdigest()}
        except LocalBrowserError as exc:
            if str(exc) == _RUNNING:
                raise LocalBrowserError(_RUNNING) from None
            raise LocalBrowserError(_FAILED) from None
        except Exception:
            raise LocalBrowserError(_FAILED) from None


def prepare_profile(profile, private_dict):
    """Rewrap the saved key for this Windows user; return whether state changed.

    Call after any profile copy and immediately before browser launch. A matching
    current wrapper is left byte-for-byte intact, including its mtime.
    """
    with _LOCK:
        temporary = None
        try:
            profile = Path(profile).resolve()
            _closed(profile)
            key = _private_key(private_dict)
            state, identity = _read_state(profile)
            _validate_databases(profile, key)
            crypt = state.setdefault('os_crypt', {})
            try:
                matches = hmac.compare_digest(_unwrap(crypt.get('encrypted_key')), key)
            except Exception:
                matches = False
            _closed(profile)
            _unchanged(profile, identity)
            if matches:
                return False
            wrapped = _dpapi_protect(key)
            if not isinstance(wrapped, bytes) or not wrapped or len(wrapped) > _MAX_WRAPPER_BYTES - 5:
                raise ValueError('Invalid wrapped key')
            # Check the newly created wrapper before publishing it.
            encoded = base64.b64encode(b'DPAPI' + wrapped).decode('ascii')
            if not hmac.compare_digest(_unwrap(encoded), key):
                raise ValueError('Wrapped key mismatch')
            crypt['encrypted_key'] = encoded
            descriptor, name = tempfile.mkstemp(prefix='Local State.portable-', suffix='.tmp', dir=profile)
            temporary = Path(name)
            with os.fdopen(descriptor, 'w', encoding='utf-8', newline='') as output:
                json.dump(state, output, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
                output.flush()
                os.fsync(output.fileno())
            _closed(profile)
            _unchanged(profile, identity)
            os.replace(temporary, profile / 'Local State')
            return True
        except LocalBrowserError as exc:
            if str(exc) == _RUNNING:
                raise LocalBrowserError(_RUNNING) from None
            raise LocalBrowserError(_FAILED) from None
        except Exception:
            raise LocalBrowserError(_FAILED) from None
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
