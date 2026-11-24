"""Path-lock concurrency and lifetime; only owned synthetic directories."""
from concurrent.futures import ThreadPoolExecutor
import ctypes
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
from path_locks import PathLocks, _path_key


def fixture_scope(prefix):
    area = (ROOT / '测试文件夹').resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    parent = temporary if temporary.is_relative_to(area) else area
    parent.mkdir(parents=True, exist_ok=True)
    scope = Path(tempfile.mkdtemp(prefix=prefix, dir=parent)).resolve()
    (scope / '.fixture-owner.json').write_text(json.dumps({
        'purpose': 'synthetic-path-locks', 'pid': os.getpid(),
        'retained_for_user_deletion': True}), encoding='utf-8')
    return scope


def short_path(path):
    if os.name != 'nt':
        raise unittest.SkipTest('Windows short-name aliases')
    method = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
    method.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
    method.restype = ctypes.c_uint
    output = ctypes.create_unicode_buffer(32768)
    size = method(str(path), output, len(output))
    if not 0 < size < len(output):
        raise AssertionError('Cannot inspect synthetic short-name alias')
    if os.path.normcase(output.value) == os.path.normcase(str(path)):
        raise unittest.SkipTest('Volume does not provide distinct 8.3 aliases')
    return Path(output.value)


def wait_for(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)
    return True


class PathLockTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_scope('path-lock-')
        self.profile = self.root / 'long-profile-directory'
        self.profile.mkdir()
        self.locks = PathLocks()

    def test_reentrant_exception_and_sequential_paths_release_registry(self):
        with self.assertRaisesRegex(ValueError, 'synthetic'):
            with self.locks.hold(self.profile):
                with self.locks.hold(self.profile):
                    self.assertEqual(next(iter(self.locks._entries.values()))[1], 2)
                    raise ValueError('synthetic')
        self.assertFalse(self.locks._entries)
        for number in range(200):
            with self.locks.hold(self.root / str(number)):
                self.assertEqual(len(self.locks._entries), 1)
        self.assertFalse(self.locks._entries)

    def test_ten_independent_paths_enter_together(self):
        barrier = threading.Barrier(10)

        def worker(number):
            with self.locks.hold(self.root / str(number)):
                barrier.wait(5)
                return True

        with ThreadPoolExecutor(max_workers=10) as workers:
            pending = [workers.submit(worker, number) for number in range(10)]
            self.assertTrue(all(item.result(8) for item in pending))
        self.assertFalse(self.locks._entries)

    def assert_serial_aliases(self, paths):
        entered = threading.Event()
        release = threading.Event()
        guard = threading.Lock()
        active = peak = 0

        def worker(path):
            nonlocal active, peak
            with self.locks.hold(path):
                with guard:
                    active += 1
                    peak = max(peak, active)
                    entered.set()
                try:
                    if not release.wait(5):
                        raise AssertionError('Synthetic path worker timed out')
                finally:
                    with guard:
                        active -= 1

        with ThreadPoolExecutor(max_workers=len(paths) + 1) as workers:
            try:
                with self.locks.hold(self.profile):
                    entry = next(iter(self.locks._entries.values()))
                    pending = [workers.submit(worker, path) for path in paths]
                    self.assertTrue(wait_for(lambda: entry[1] == len(paths) + 1))
                self.assertTrue(entered.wait(4))
                late = workers.submit(worker, self.profile)
                self.assertTrue(wait_for(lambda: entry[1] == len(paths) + 1))
                self.assertIs(self.locks._entries[_path_key(self.profile)], entry)
                self.assertEqual(peak, 1)
            finally:
                release.set()
            for future in [*pending, late]:
                future.result(8)
        self.assertEqual(peak, 1)
        self.assertFalse(self.locks._entries)

    def test_waiters_keep_one_lock_for_relative_and_case_aliases(self):
        paths = [self.profile, self.profile / '..' / self.profile.name,
                 Path(os.path.relpath(self.profile))]
        if os.name == 'nt':
            paths.extend([Path(str(self.profile).upper()), Path('\\\\?\\' + str(self.profile))])
        self.assert_serial_aliases(paths)

    def test_short_name_aliases_share_lock_and_missing_child_key(self):
        short = short_path(self.profile)
        self.assertEqual(_path_key(short / 'future.bin'), _path_key(self.profile / 'future.bin'))
        self.assert_serial_aliases([self.profile, short])


if __name__ == '__main__':
    unittest.main(verbosity=2)
