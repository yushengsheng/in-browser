"""Bounded lifetime cache for UI status only; launch validation never uses it."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import stat
import threading
import time

from signature_lifetime import signature_lifetime


class SignatureStatusCache:
    def __init__(self, *, limit=2048, max_age=30):
        self.limit = max(0, int(limit))
        self.max_age = max(0, float(max_age))
        self._entries = {}
        self._lock = threading.RLock()

    @staticmethod
    def _identity(path):
        value = path.stat()
        if not stat.S_ISREG(value.st_mode):
            raise ValueError('Not a regular signature file')
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                value.st_ctime_ns, value.st_mode)

    def retain(self, paths):
        active = {str(Path(path)) for path in paths}
        with self._lock:
            for key in list(self._entries):
                if key not in active:
                    del self._entries[key]

    def get(self, path, *, now_ms=None):
        path = Path(path)
        key = str(path)
        with self._lock:
            try:
                identity = self._identity(path)
                current = time.monotonic()
                cached = self._entries.get(key)
                if (cached is not None and cached[0] == identity and
                        0 <= current - cached[1] < self.max_age):
                    _, _, info, expires = cached
                else:
                    self._entries.pop(key, None)
                    info = signature_lifetime(path, now_ms=0)
                    if info['status'] not in ('active', 'expired'):
                        return info
                    if identity != self._identity(path):
                        return {'status': 'unknown'}
                    # Integer arithmetic preserves the millisecond expiry boundary.
                    expires = ((datetime.fromisoformat(info['expires_at']) -
                                datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(milliseconds=1))
                    # Stable admission avoids full-scan LRU thrashing above the limit.
                    if len(self._entries) < self.limit:
                        self._entries[key] = (identity, current, dict(info), expires)
                expired = time.time_ns() > expires * 1000000 if now_ms is None else now_ms > expires
                return {**info, 'status': 'expired' if expired else 'active'}
            except FileNotFoundError:
                self._entries.pop(key, None)
                return {'status': 'missing'}
            except (OSError, ValueError, OverflowError):
                self._entries.pop(key, None)
                return {'status': 'unknown'}
