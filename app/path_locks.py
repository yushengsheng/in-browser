"""Process-local reentrant locks retained only while a path has users."""
from contextlib import contextmanager
import os
import threading


def _path_key(path):
    # realpath expands existing Windows short names and resolves parent aliases
    # even when the output file itself does not exist yet.
    value = os.path.normcase(os.path.realpath(os.path.abspath(path)))
    if os.name == 'nt':
        if value.startswith('\\\\?\\unc\\'):
            value = '\\\\' + value[8:]
        elif value.startswith('\\\\?\\') and len(value) > 5 and value[5] == ':':
            value = value[4:]
    return value


class PathLocks:
    def __init__(self):
        self._guard = threading.Lock()
        self._entries = {}

    @contextmanager
    def hold(self, path):
        key = _path_key(path)
        with self._guard:
            entry = self._entries.get(key)
            if entry is None:
                entry = [threading.RLock(), 0]
                self._entries[key] = entry
            # Count waiters before acquiring so an owner cannot retire their lock.
            entry[1] += 1
        try:
            with entry[0]:
                yield
        finally:
            with self._guard:
                entry[1] -= 1
                if not entry[1]:
                    del self._entries[key]
