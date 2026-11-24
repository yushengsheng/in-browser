"""Fresh, shared process enumeration without cross-boundary occupancy caching."""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import browser_processes as scans
from local_state import LocalBrowserError


class ProcessScanScopeTests(unittest.TestCase):
    def test_ten_pending_checks_share_one_scan_and_each_owner_is_rechecked(self):
        profile = Path.cwd() / 'synthetic-profile'
        args = ['renamed.exe', '--user-data-dir=' + str(profile)]
        listed = SimpleNamespace(pid=123, info={'pid': 123, 'cmdline': args})
        gate = threading.Event()
        counted = threading.Lock()
        calls = []
        class AdmissionLock:
            def __enter__(self):
                counted.acquire()
                calls.append(True)
                if len(calls) == 10:
                    gate.set()
            def __exit__(self, *unused):
                counted.release()
        def collect(_):
            if not gate.wait(5):
                raise AssertionError('Workers did not reach shared scan')
        fresh = []
        def lookup(pid):
            item = SimpleNamespace(pid=pid)
            item.as_dict = lambda attrs: dict(pid=pid, cmdline=list(args), exe='renamed.exe',
                                             name='renamed.exe', create_time=1)
            fresh.append(item)
            return item
        with scans.process_scan_scope():
            scope = scans._SCAN_SCOPE.get()
            scope.lock = AdmissionLock()
            with patch.object(scans.time, 'sleep', side_effect=collect), \
                    patch.object(scans.psutil, 'process_iter', return_value=iter([listed])) as iterator, \
                    patch.object(scans.psutil, 'Process', side_effect=lookup), ThreadPoolExecutor(10) as pool:
                tasks = [pool.submit(copy_context().run, scans.profile_processes, profile) for _ in range(10)]
                results = [task.result(timeout=8) for task in tasks]
        self.assertEqual(iterator.call_count, 1)
        self.assertEqual(len(fresh), 10)
        self.assertEqual(len({id(result[0]) for result in results}), 10)
        self.assertIsNone(scans._SCAN_SCOPE.get())

    def test_request_after_scan_started_cannot_inherit_old_free_result(self):
        started, release = threading.Event(), threading.Event()
        scope = scans._FreshScans()
        counter = []
        def capture(required):
            counter.append(True)
            if len(counter) == 1:
                started.set()
                self.assertTrue(release.wait(5))
                return ()
            return ((9, ('browser', '--user-data-dir=new'), False),)
        with patch.object(scans, '_scan_candidates', side_effect=capture), ThreadPoolExecutor(2) as pool:
            first = pool.submit(scope.rows, False)
            self.assertTrue(started.wait(5))
            try:
                second = pool.submit(scope.rows, False).result(timeout=5)
                self.assertEqual(second[0][0], 9)
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5), ())
        self.assertEqual(len(counter), 2)

    def test_repeated_closed_checks_and_nested_scope_always_rescan(self):
        with patch.object(scans, '_scan_candidates', return_value=()) as scan:
            with scans.process_scan_scope():
                first = scans._SCAN_SCOPE.get()
                scans.profile_processes(Path.cwd())
                with scans.process_scan_scope():
                    self.assertIs(scans._SCAN_SCOPE.get(), first)
                    scans.profile_processes(Path.cwd())
                scans.profile_processes(Path.cwd())
        self.assertEqual(scan.call_count, 3)

    def test_scan_failure_releases_waiters_and_next_check_can_retry(self):
        scope = scans._FreshScans()
        with patch.object(scans, '_scan_candidates', side_effect=[OSError('synthetic'), ()]):
            with self.assertRaises(OSError):
                scope.rows(True)
            self.assertEqual(scope.rows(True), ())
        self.assertIsNone(scope.pending)

    def test_collection_interruption_does_not_poison_later_checks(self):
        scope = scans._FreshScans()
        with patch.object(scans.time, 'sleep', side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):
                scope.rows(True)
        self.assertIsNone(scope.pending)
        with patch.object(scans, '_scan_candidates', return_value=()) as scan:
            self.assertEqual(scope.rows(True), ())
        scan.assert_called_once_with(True)

    def test_shared_unreadable_metadata_does_not_weaken_strict_checks(self):
        for inspection in (True, OSError('synthetic')):
            with self.subTest(kind=type(inspection).__name__), scans.process_scan_scope():
                scope = scans._SCAN_SCOPE.get()
                with patch.object(scope, 'rows', return_value=((9, (), inspection),)):
                    self.assertEqual(scans.profile_processes(Path.cwd()), [])
                    with self.assertRaises((LocalBrowserError, OSError)):
                        scans.profile_processes(Path.cwd(), require_inspectable=True)


if __name__ == '__main__':
    unittest.main()
