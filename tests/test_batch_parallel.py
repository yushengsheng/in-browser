"""Synthetic batch/lifecycle concurrency; no browser, real profile, or network."""
import copy
import ctypes
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

from api import dispatch
from batch_operations import Operations, parallel_batch, shutdown_batches
import browser_core as core
from manager_service import ManagerService


class Overlap:
    def __init__(self, target):
        self.lock = threading.Lock()
        self.active = self.peak = 0
        self.target = target
        self.reached = threading.Event()
        self.release = threading.Event()

    def enter(self):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            if self.active >= self.target:
                self.reached.set()
        try:
            if not self.release.wait(8):
                raise AssertionError('Synthetic workers did not overlap')
        finally:
            with self.lock:
                self.active -= 1


class ParallelBatchTests(unittest.TestCase):
    def service(self, handler):
        service = SimpleNamespace(operations=Operations())
        service.open = service.close = service.archive = handler
        service.request = lambda action, payload: dispatch(service, action, payload)
        self.addCleanup(shutdown_batches, service)
        return service

    def test_open_and_close_reach_ten_and_share_the_limit_across_batches(self):
        overlap = Overlap(10)
        service = self.service(lambda identity: overlap.enter())
        self.addCleanup(overlap.release.set)
        with ThreadPoolExecutor(max_workers=2) as callers:
            calls = [callers.submit(service.request, 'batch', {'action': action, 'ids': [f'{action}{i}' for i in range(30)]})
                     for action in ('open', 'close')]
            try:
                self.assertTrue(overlap.reached.wait(4))
                self.assertEqual(overlap.peak, 10)
                self.assertFalse(service.operations.acquire(blocking=False))
            finally:
                overlap.release.set()
            self.assertEqual([call.result(8)['data']['completed'] for call in calls], [30, 30])
        self.assertEqual(overlap.peak, 10)
        self.assertTrue(service.operations.acquire(blocking=False))
        service.operations.release()
        shutdown_batches(service)
        self.assertFalse(any(thread.is_alive() for thread in service._batch_executor._threads))

    def test_batch_preserves_unique_hundred_limit_partial_failures_and_order(self):
        calls = []
        lock = threading.Lock()
        def handler(identity):
            with lock:
                calls.append(identity)
            if identity in ('p3', 'p9'):
                raise core.LocalBrowserError('合成拒绝')
            if identity == 'p5':
                raise OSError('private synthetic detail')
        service = self.service(handler)
        reply = service.request('batch', {'action': 'open', 'ids': ['p0', 'p0'] + [f'p{i}' for i in range(120)]})
        self.assertTrue(reply['ok'])
        self.assertEqual(len(calls), 100)
        self.assertEqual(len(set(calls)), 100)
        self.assertEqual(reply['data']['completed'], 97)
        self.assertEqual([item['id'] for item in reply['data']['errors']], ['p3', 'p5', 'p9'])
        self.assertNotIn('private synthetic detail', str(reply))

    def test_archive_remains_serial_and_does_not_create_pool(self):
        caller = threading.get_ident()
        ids = []
        service = self.service(lambda identity: ids.append((identity, threading.get_ident())))
        reply = service.request('batch', {'action': 'archive', 'ids': ['a', 'b', 'a']})
        self.assertEqual(reply['data'], {'completed': 2, 'errors': []})
        self.assertEqual(ids, [('a', caller), ('b', caller)])
        self.assertFalse(hasattr(service, '_batch_executor'))

    def test_unexpected_worker_failure_does_not_abandon_other_items(self):
        service = self.service(lambda identity: None)
        def request(action, payload):
            if payload['id'] == 'bad':
                raise RuntimeError('private synthetic detail')
            return {'ok': True}
        service.request = request
        reply = parallel_batch(service, 'close', ['bad', 'good'])
        self.assertEqual(reply['completed'], 1)
        self.assertEqual(reply['errors'][0]['id'], 'bad')
        self.assertNotIn('private synthetic detail', str(reply))
        self.assertTrue(service.operations.acquire(False))
        service.operations.release()

    def test_public_shutdown_waits_for_batch_and_blocks_late_requests_without_deadlock(self):
        service = ManagerService.__new__(ManagerService)
        service.operations = Operations()
        overlap = Overlap(10)
        self.addCleanup(overlap.release.set)
        self.addCleanup(service.shutdown_batches)
        executed = []
        def opening(identity):
            with service.operations.window(identity):
                executed.append(identity)
                overlap.enter()
        service.open = opening
        with ThreadPoolExecutor(max_workers=3) as callers:
            first = callers.submit(service.request, 'batch', {'action': 'open', 'ids': [f'p{i}' for i in range(30)]})
            try:
                self.assertTrue(overlap.reached.wait(3))
                shutdown = callers.submit(service.shutdown_batches)
                deadline = time.monotonic() + 2
                while not service.operations._waiting and time.monotonic() < deadline:
                    time.sleep(.001)
                self.assertTrue(service.operations._waiting)
                late = callers.submit(service.request, 'batch', {'action': 'open', 'ids': ['late']})
                self.assertFalse(shutdown.done())
            finally:
                overlap.release.set()
            self.assertEqual(first.result(5)['data']['completed'], 30)
            shutdown.result(5)
            self.assertFalse(late.result(5)['ok'])
        self.assertEqual(overlap.peak, 10)
        self.assertNotIn('late', executed)
        self.assertFalse(any(thread.is_alive() for thread in service._batch_executor._threads))
        self.assertFalse(service.request('batch', {'action': 'open', 'ids': ['later']})['ok'])

    def test_interrupted_batch_cancels_queued_items_and_drains_running_work(self):
        class SyntheticInterruption(BaseException):
            pass
        entered = threading.Event()
        release = threading.Event()
        interrupted = threading.Event()
        called = []
        lock = threading.Lock()
        self.addCleanup(release.set)
        service = self.service(lambda identity: None)
        def request(action, payload):
            with lock:
                called.append(payload['id'])
            if payload['id'] == 'interrupt':
                raise SyntheticInterruption()
            entered.set()
            release.wait(5)
            return {'ok': True}
        service.request = request
        def run():
            try:
                parallel_batch(service, 'close', ['interrupt'] + [f'p{i}' for i in range(99)])
            except SyntheticInterruption:
                interrupted.set()
        with ThreadPoolExecutor(max_workers=1) as callers:
            running = callers.submit(run)
            try:
                self.assertTrue(entered.wait(2))
                self.assertFalse(interrupted.wait(.05))
                self.assertFalse(service.operations.acquire(False))
            finally:
                release.set()
            running.result(3)
        self.assertTrue(interrupted.is_set())
        self.assertLess(len(called), 100)
        self.assertTrue(service.operations.acquire(False))
        service.operations.release()


class RuntimeJournalTests(unittest.TestCase):
    def controller(self):
        controller = core.BrowserController.__new__(core.BrowserController)
        controller._save_lock = threading.RLock()
        controller._state_lock = threading.RLock()
        controller.state = {'one': {'pid': 101, 'ready': False}}
        controller.state_path = ROOT / 'analysis/test-runs/not-created-journal.bin'
        return controller

    def sharing_error(self, code):
        error = PermissionError('synthetic sharing conflict')
        error.winerror = code
        return error

    def test_transient_windows_conflicts_retry_the_identical_snapshot(self):
        controller = self.controller()
        def write(path, snapshot):
            self.assertEqual(snapshot, {'one': {'pid': 101, 'ready': False}})
            controller.state['one']['ready'] = True
            if writer.call_count < 3:
                raise self.sharing_error(5 if writer.call_count == 1 else 33)
        with patch.object(core, 'write_encrypted', side_effect=write) as writer, \
                patch.object(core.time, 'sleep') as pause:
            controller._save()
        self.assertEqual(writer.call_count, 3)
        self.assertEqual([call.args[0] for call in pause.call_args_list], [.05, .1])

    def test_conflicts_have_a_finite_retry_limit(self):
        for code in (5, 32, 33):
            with self.subTest(code=code):
                controller = self.controller()
                error = self.sharing_error(code)
                with patch.object(core, 'write_encrypted', side_effect=error) as writer, \
                        patch.object(core.time, 'sleep') as pause:
                    with self.assertRaises(PermissionError) as caught:
                        controller._save()
                self.assertIs(caught.exception, error)
                self.assertEqual((writer.call_count, pause.call_count), (3, 2))

    def test_permanent_and_cryptographic_failures_are_not_retried(self):
        for error in (self.sharing_error(19), OSError('synthetic disk failure'),
                      core.LocalBrowserError('synthetic key failure')):
            with self.subTest(error=type(error).__name__):
                with patch.object(core, 'write_encrypted', side_effect=error) as writer, \
                        patch.object(core.time, 'sleep') as pause:
                    with self.assertRaises(type(error)) as caught:
                        self.controller()._save()
                self.assertIs(caught.exception, error)
                self.assertEqual(writer.call_count, 1)
                pause.assert_not_called()

    @unittest.skipUnless(os.name == 'nt', 'Windows atomic replacement sharing')
    def test_real_windows_reader_conflict_is_retried_after_reader_closes(self):
        from ctypes import wintypes
        base = ROOT / 'analysis/test-runs'
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='journal-probe-', dir=base) as name:
            probe = Path(name)
            (probe / 'nested').mkdir()
            (probe / 'nested/proof').write_bytes(b'synthetic')
        self.assertFalse(probe.exists())
        with tempfile.TemporaryDirectory(prefix='journal-sharing-', dir=base) as name:
            scope = Path(name).resolve()
            (scope / 'owner.json').write_text('{"purpose":"synthetic-journal-sharing"}')
            controller = self.controller()
            controller.state_path = scope / 'runtime.bin'
            controller.state_path.write_bytes(b'old synthetic journal')
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle.restype = wintypes.BOOL
            handle = kernel.CreateFileW(str(controller.state_path), 0x80000000, 3, None, 3, 0, None)
            self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
            attempted = threading.Event()
            errors = []
            write = core.write_encrypted
            def observed_write(*args, **kwargs):
                try:
                    return write(*args, **kwargs)
                except OSError as error:
                    errors.append(getattr(error, 'winerror', None))
                    attempted.set()
                    raise
            def reader():
                try:
                    self.assertTrue(attempted.wait(5))
                finally:
                    self.assertTrue(kernel.CloseHandle(handle))
            with ThreadPoolExecutor(max_workers=1) as pool:
                reading = pool.submit(reader)
                try:
                    with patch.object(core, 'write_encrypted', side_effect=observed_write):
                        controller._save()
                finally:
                    attempted.set()
                    reading.result(5)
            self.assertTrue(errors and all(code in (5, 32, 33) for code in errors))
            self.assertEqual(core.read_encrypted(controller.state_path), controller.state)
            self.assertTrue(scope.is_relative_to(base.resolve()))
            self.assertFalse(any(path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400
                                 for path in (scope, *scope.rglob('*'))))
        self.assertFalse(scope.exists())


class OperationGateTests(unittest.TestCase):
    def test_sync_shared_and_ten_window_workers_overlap_and_block_delete_exit(self):
        operations = Operations()
        overlap = Overlap(15)
        self.addCleanup(overlap.release.set)
        def work(identity):
            with operations.window(identity):
                overlap.enter()
        with ThreadPoolExecutor(max_workers=15) as workers:
            with operations.shared():
                futures = [workers.submit(work, str(i)) for i in range(15)]
                try:
                    self.assertTrue(overlap.reached.wait(4))
                    # The polling/exit thread cannot obtain exclusive ownership.
                    with ThreadPoolExecutor(max_workers=1) as exit_thread:
                        self.assertFalse(exit_thread.submit(operations.acquire, False).result(2))
                finally:
                    overlap.release.set()
                for future in futures:
                    future.result(4)
        self.assertEqual(overlap.peak, 15)
        with operations:
            with operations.shared(), operations.window('nested'):
                pass

    def test_waiting_exclusive_runs_before_new_activity_but_admitted_workers_drain(self):
        operations = Operations()
        writer_started = threading.Event()
        writer_entered = threading.Event()
        reader_entered = threading.Event()
        writer_release = threading.Event()
        self.addCleanup(writer_release.set)
        def writer():
            writer_started.set()
            with operations:
                writer_entered.set()
                writer_release.wait(5)
        def reader():
            with operations.shared():
                reader_entered.set()
        with ThreadPoolExecutor(max_workers=3) as workers:
            with operations.shared() as ticket:
                writing = workers.submit(writer)
                self.assertTrue(writer_started.wait(2))
                deadline = time.monotonic() + 2
                while not operations._waiting and time.monotonic() < deadline:
                    time.sleep(.001)
                self.assertTrue(operations._waiting)
                reading = workers.submit(reader)
                def admitted():
                    with operations.shared(ticket), operations.window('queued'):
                        return True
                self.assertTrue(workers.submit(admitted).result(2))
                self.assertFalse(writer_entered.is_set())
                self.assertFalse(reader_entered.is_set())
            try:
                self.assertTrue(writer_entered.wait(2))
                self.assertFalse(reader_entered.is_set())
            finally:
                writer_release.set()
            writing.result(2)
            reading.result(2)
        self.assertTrue(reader_entered.is_set())

    def test_same_window_serializes_and_exception_releases_all_locks(self):
        operations = Operations()
        entered = threading.Event()
        release = threading.Event()
        second = threading.Event()
        self.addCleanup(release.set)
        def first():
            with operations.window('same'):
                entered.set()
                release.wait(5)
                raise core.LocalBrowserError('synthetic failure')
        def next_operation():
            with operations.window('same'):
                second.set()
        with ThreadPoolExecutor(max_workers=2) as workers:
            initial = workers.submit(first)
            self.assertTrue(entered.wait(2))
            following = workers.submit(next_operation)
            try:
                self.assertFalse(second.wait(.05))
            finally:
                release.set()
            with self.assertRaises(core.LocalBrowserError):
                initial.result(2)
            following.result(2)
        self.assertTrue(operations.acquire(False))
        operations.release()
        self.assertFalse(operations._windows._windows)


class LifecycleParallelTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='batch-parallel-fixture-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def service(self, count):
        service = ManagerService.__new__(ManagerService)
        service.root = self.root
        service.operations = Operations()
        records = {f'p{i}': {'id': f'p{i}', 'proxy': {'type': 'noproxy'}, '_cookie_pending': False,
                            '_runtime': {'alias': f'p{i}', 'profile_path': str(self.root / f'p{i}'),
                                         'fingerprint_path': 'synthetic', 'core_major': '148'}} for i in range(count)}
        service.store = SimpleNamespace(get=lambda identity: copy.deepcopy(records[identity]), put=Mock(),
                                        public=lambda record, status='closed': {'id': record['id'], 'status': status})
        service._require_available = Mock()
        service._status = Mock(return_value='closed')
        service._runtime = lambda record, previous: copy.deepcopy(previous)
        service._preferences = service._sync = Mock()
        service.configuration = SimpleNamespace(independent=False)
        service.proxy_runtime = SimpleNamespace(ensure=Mock(return_value=None), stop_if_unused=Mock())
        service.controller = Mock()
        self.addCleanup(shutdown_batches, service)
        return service

    def test_manager_open_reaches_ten_after_all_existing_preflight_gates(self):
        overlap = Overlap(10)
        self.addCleanup(overlap.release.set)
        service = self.service(20)
        service.controller.open.side_effect = lambda *args, **kwargs: (kwargs['before_launch'](), overlap.enter())
        with patch('manager_service.require_current_signature') as signature, \
                patch('import_cookies.prepare_existing', side_effect=lambda owner, record: record), \
                patch('manager_service.CDP'), patch('ip_info_page.show_ip_info'), \
                ThreadPoolExecutor(max_workers=1) as callers:
            batch = callers.submit(service.request, 'batch', {'action': 'open', 'ids': [f'p{i}' for i in range(20)]})
            try:
                self.assertTrue(overlap.reached.wait(4))
                self.assertEqual(overlap.peak, 10)
                self.assertFalse(service.operations.acquire(False))
            finally:
                overlap.release.set()
            self.assertEqual(batch.result(6)['data']['completed'], 20)
        self.assertEqual(signature.call_count, 20)
        self.assertEqual(service.store.put.call_count, 20)

    def test_manager_open_blocks_same_window_close_and_save_until_finished(self):
        service = self.service(1)
        opened = threading.Event()
        release = threading.Event()
        saved = threading.Event()
        self.addCleanup(release.set)
        service.controller.open.side_effect = lambda *args, **kwargs: (opened.set(), release.wait(5))
        def sanitize(*args, **kwargs):
            saved.set()
            raise core.LocalBrowserError('synthetic save stop')
        with patch('manager_service.require_current_signature'), \
                patch('import_cookies.prepare_existing', side_effect=lambda owner, record: record), \
                patch('manager_service.sanitize', side_effect=sanitize), \
                ThreadPoolExecutor(max_workers=3) as workers:
            opening = workers.submit(service.open, 'p0', offline_test=True)
            self.assertTrue(opened.wait(2))
            closing = workers.submit(service.close, 'p0')
            saving = workers.submit(service.request, 'save', {'profile': {'id': 'p0'}})
            try:
                self.assertFalse(saved.wait(.05))
                service.controller.close.assert_not_called()
            finally:
                release.set()
            opening.result(2)
            closing.result(2)
            self.assertFalse(saving.result(2)['ok'])
        self.assertTrue(saved.is_set())
        service.controller.close.assert_called_once_with('p0')

    def test_concurrent_saves_keep_duplicate_username_check_atomic(self):
        service = self.service(2)
        records = {f'p{i}': {'id': f'p{i}', 'seq': i + 1, 'name': f'profile {i}', 'core_version': '148',
                            'fingerprint': {}, 'preferences': {}, 'proxy': {'type': 'noproxy'}, 'urls': [],
                            'username': '', 'platform': 'synthetic', 'duplicate_check': True, 'cookie_text': '',
                            '_runtime': {}} for i in range(2)}
        lock = threading.RLock()
        service.store = SimpleNamespace(lock=lock, get=lambda identity: copy.deepcopy(records[identity]),
                                        all=lambda: copy.deepcopy(list(records.values())),
                                        public=lambda record, status='closed': copy.deepcopy(record),
                                        put=lambda record, **kwargs: records.__setitem__(record['id'], copy.deepcopy(record)))
        together = threading.Barrier(2)
        def runtime(record, previous):
            together.wait(3)
            return {}
        service._runtime = runtime
        def sanitize(incoming, base=None):
            value = copy.deepcopy(base or incoming)
            value.update(copy.deepcopy(incoming))
            return value
        with patch('manager_service.sanitize', side_effect=sanitize), patch('manager_service.parse_cookies', return_value=[]), \
                ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(service.request, 'save', {'profile': {'id': f'p{i}', 'username': 'same'}})
                       for i in range(2)]
            replies = [future.result(4) for future in futures]
        self.assertEqual(sum(reply['ok'] for reply in replies), 1)
        self.assertEqual(sum(record['username'] == 'same' for record in records.values()), 1)
        self.assertIn('已有相同平台', next(reply['error'] for reply in replies if not reply['ok']))

    def controller(self, count):
        executable = self.root / 'BitBrowser.exe'
        executable.write_bytes(b'synthetic-core')
        fingerprint = self.root / 'fingerprint.bin'
        fingerprint.write_bytes(b'synthetic-signature')
        windows = []
        for i in range(count):
            profile = self.root / f'profile-{i}'
            profile.mkdir()
            windows.append({'alias': f'p{i}', 'profile_path': str(profile), 'new_profile': True,
                            'core_path': str(executable), 'core_sha256': core.sha256(executable), 'core_major': '148',
                            'fingerprint_path': str(fingerprint), 'fingerprint_sha256': core.sha256(fingerprint),
                            'launch_args': [], 'restore_session': False})
        return core.BrowserController(self.root, settings={'windows': windows, 'persistent': False})

    def test_controller_real_open_overlaps_and_journal_keeps_all_records(self):
        controller = self.controller(10)
        overlap = Overlap(10)
        self.addCleanup(overlap.release.set)
        writes = []
        with ExitStack() as stack:
            stack.enter_context(patch.object(controller, '_ensure_record', return_value=False))
            stack.enter_context(patch.object(controller, 'endpoint', return_value='synthetic-endpoint'))
            stack.enter_context(patch.object(core, '_profile_browsers', return_value=[]))
            stack.enter_context(patch.object(core, '_visible_windows', return_value=[1]))
            stack.enter_context(patch('signature_lifetime.require_current_signature'))
            stack.enter_context(patch.object(core.subprocess, 'Popen', return_value=Mock(pid=12345)))
            stack.enter_context(patch.object(core.psutil, 'Process', return_value=SimpleNamespace(create_time=lambda: 100)))
            stack.enter_context(patch.object(core, 'write_encrypted', side_effect=lambda path, state: writes.append(copy.deepcopy(state))))
            with ThreadPoolExecutor(max_workers=10) as workers:
                futures = [workers.submit(controller.open, f'p{i}', offline_test=True,
                                          bootstrap_blank=True, before_launch=overlap.enter) for i in range(10)]
                try:
                    self.assertTrue(overlap.reached.wait(4))
                    self.assertEqual(controller.status('p0'), '启动未完成')
                finally:
                    overlap.release.set()
                for future in futures:
                    self.assertTrue(future.result(5)['ready'])
        self.assertEqual(overlap.peak, 10)
        self.assertEqual(set(writes[-1]), {f'p{i}' for i in range(10)})
        self.assertTrue(all(record['ready'] for record in writes[-1].values()))

    def test_controller_normal_close_overlaps_without_process_termination(self):
        controller = self.controller(10)
        overlap = Overlap(10)
        self.addCleanup(overlap.release.set)
        with patch.object(controller, '_ensure_record', return_value=True), \
                patch.object(controller, '_request_close', side_effect=lambda alias: overlap.enter()), \
                patch.object(controller, '_record_valid', return_value=False), \
                patch.object(core, '_profile_browsers', return_value=[]), \
                patch.object(core, 'write_encrypted'), ThreadPoolExecutor(max_workers=10) as workers:
            futures = [workers.submit(controller.close, f'p{i}') for i in range(10)]
            try:
                self.assertTrue(overlap.reached.wait(4))
                self.assertEqual(controller.status('p0'), '正在关闭')
            finally:
                overlap.release.set()
            for future in futures:
                future.result(4)
        self.assertEqual(overlap.peak, 10)
        self.assertFalse(controller.state)


if __name__ == '__main__':
    unittest.main(verbosity=2)
