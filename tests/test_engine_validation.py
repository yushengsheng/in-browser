"""Batch-scoped Windows engine handles; no browser or user profile data."""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import engine_validation as validation
from batch_operations import Operations, parallel_batch, shutdown_batches
from local_state import LocalBrowserError


@unittest.skipUnless(os.name == 'nt', 'Windows protected read handles')
class SharedValidationTests(unittest.TestCase):
    def setUp(self):
        base = ROOT / 'analysis/test-runs'
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='shared-engine-probe-', dir=base) as name:
            probe = Path(name)
            (probe / 'nested').mkdir()
            (probe / 'nested/proof').write_bytes(b'synthetic')
        self.assertFalse(probe.exists())
        self.temporary = tempfile.TemporaryDirectory(prefix='shared-engine-', dir=base)
        self.root = Path(self.temporary.name).resolve()
        (self.root / 'owner.json').write_text('{"purpose":"synthetic-engine-handles"}')
        self.addCleanup(self.cleanup)
        self.path = self.root / 'engine.bin'
        self.original = bytes(range(256)) * 1024
        self.path.write_bytes(self.original)

    def cleanup(self):
        self.assertTrue(self.root.is_relative_to((ROOT / 'analysis/test-runs').resolve()))
        self.assertFalse(any(path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400
                             for path in (self.root, *self.root.rglob('*'))))
        self.temporary.cleanup()
        self.assertFalse(self.root.exists())

    def service(self, handler):
        service = SimpleNamespace(operations=Operations())
        service.request = lambda action, payload: handler(payload['id'])
        self.addCleanup(shutdown_batches, service)
        return service

    def test_ten_contexts_share_one_handle_and_three_distinct_hashes(self):
        barrier = threading.Barrier(10)
        variants = [(None, None), (15, b'one'), (31, b'different replacement')]
        expected = [hashlib.sha256(self.original if offset is None else
                    self.original[:offset] + replacement + self.original[offset + len(replacement):]).hexdigest()
                    for offset, replacement in variants]
        digest = Mock(wraps=hashlib.sha256)
        def work():
            barrier.wait(5)
            with validation.verification_scope():
                return [validation.digest_file(self.path, offset=offset, replacement=replacement)
                        for offset, replacement in variants]
        with patch.object(validation, 'hashlib', SimpleNamespace(sha256=digest)):
            with validation.verification_scope():
                state = validation._active.get()
                with ThreadPoolExecutor(max_workers=10) as pool:
                    futures = [pool.submit(copy_context().run, work) for _ in range(10)]
                    self.assertEqual([future.result(10) for future in futures], [expected] * 10)
                self.assertEqual(len(state.entries), 1)
                stream = next(iter(state.entries.values()))[0]
                self.assertFalse(stream.closed)
                with self.assertRaises(PermissionError):
                    self.path.write_bytes(b'blocked')
                with self.assertRaises(PermissionError):
                    self.path.unlink()
            self.assertTrue(stream.closed)
        self.assertEqual(digest.call_count, 3)
        self.path.write_bytes(b'released')

    def test_batch_workers_share_scope_and_next_batch_reads_changed_content(self):
        expected = hashlib.sha256(self.original).hexdigest()
        barrier = threading.Barrier(10)
        states = []
        lock = threading.Lock()
        def handler(identity):
            with validation.verification_scope():
                barrier.wait(5)
                value = validation.digest_file(self.path)
                with lock:
                    states.append(validation._active.get())
                self.assertEqual(value, expected)
                with self.assertRaises(PermissionError):
                    self.path.write_bytes(b'blocked')
                return {'ok': True}
        service = self.service(handler)
        digest = Mock(wraps=hashlib.sha256)
        with patch.object(validation, 'hashlib', SimpleNamespace(sha256=digest)):
            self.assertEqual(parallel_batch(service, 'open', list(map(str, range(10))))['completed'], 10)
            self.assertEqual(digest.call_count, 1)
            self.assertTrue(all(state is states[0] and state.closed for state in states))
            self.assertIsNone(validation._active.get())
            self.path.write_bytes(b'next batch')
            expected = hashlib.sha256(b'next batch').hexdigest()
            states.clear()
            self.assertEqual(parallel_batch(service, 'open', list(map(str, range(10))))['completed'], 10)
            self.assertEqual(digest.call_count, 2)
            self.assertTrue(all(state is states[0] and state.closed for state in states))
        # Reused executor threads must not retain the preceding Context.
        self.assertTrue(all(service._batch_executor.submit(lambda: validation._active.get() is None).result(2)
                            for _ in range(10)))

    def test_interruption_keeps_handles_until_running_workers_finish(self):
        class Interrupted(BaseException):
            pass
        entered = threading.Event()
        failed = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        states = []
        def handler(identity):
            validation.digest_file(self.path)
            if identity == 'interrupt':
                self.assertTrue(entered.wait(5))
                failed.set()
                raise Interrupted()
            states.append(validation._active.get())
            entered.set()
            self.assertTrue(release.wait(8))
            self.assertFalse(states[-1].closed)
            validation.digest_file(self.path)
            return {'ok': True}
        service = self.service(handler)
        with ThreadPoolExecutor(max_workers=1) as callers:
            batch = callers.submit(parallel_batch, service, 'open', ['interrupt', 'running'])
            try:
                self.assertTrue(failed.wait(5))
                self.assertFalse(batch.done())
                with self.assertRaises(PermissionError):
                    self.path.write_bytes(b'blocked while draining')
            finally:
                release.set()
            with self.assertRaises(Interrupted):
                batch.result(8)
        self.assertTrue(states[0].closed)
        self.path.write_bytes(b'released after interruption')

    def test_staging_remains_writable_and_never_uses_cached_hashes(self):
        staging = self.root / '.install-0123456789ab'
        staging.mkdir()
        path = staging / 'engine.bin'
        path.write_bytes(b'first')
        with validation.verification_scope():
            first = validation.digest_file(path)
            path.write_bytes(b'second')
            self.assertNotEqual(validation.digest_file(path), first)
            self.assertFalse(validation._active.get().entries)

    def test_submission_failure_drains_started_worker_before_closing_handles(self):
        entered = threading.Event()
        failed = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        states = []
        def handler(identity):
            validation.digest_file(self.path)
            states.append(validation._active.get())
            entered.set()
            self.assertTrue(release.wait(8))
            self.assertFalse(states[0].closed)
            validation.digest_file(self.path)
            return {'ok': True}
        class FailingExecutor(ThreadPoolExecutor):
            def submit(executor, *args, **kwargs):
                if entered.wait(.1):
                    failed.set()
                    raise RuntimeError('synthetic submission failure')
                result = super().submit(*args, **kwargs)
                self.assertTrue(entered.wait(5))
                return result
        service = self.service(handler)
        with ThreadPoolExecutor(max_workers=1) as callers, \
                patch('batch_operations.ThreadPoolExecutor', FailingExecutor):
            batch = callers.submit(parallel_batch, service, 'open', ['running', 'unsubmitted'])
            try:
                self.assertTrue(failed.wait(5))
                self.assertFalse(batch.done())
                with self.assertRaises(PermissionError):
                    self.path.write_bytes(b'blocked while submission drains')
            finally:
                release.set()
            with self.assertRaisesRegex(RuntimeError, 'synthetic submission failure'):
                batch.result(8)
        self.assertTrue(states[0].closed)
        self.path.write_bytes(b'released after submission failure')

    def test_existing_writer_forces_uncached_reads(self):
        with self.path.open('r+b') as writer, validation.verification_scope():
            first = validation.digest_file(self.path)
            writer.seek(0)
            writer.write(b'changed')
            writer.flush()
            os.fsync(writer.fileno())
            self.assertNotEqual(validation.digest_file(self.path), first)
            self.assertFalse(validation._active.get().entries)

    def test_expired_copied_context_cannot_reuse_closed_handle(self):
        with validation.verification_scope():
            validation.digest_file(self.path)
            context = copy_context()
        with self.assertRaises(LocalBrowserError):
            context.run(validation.digest_file, self.path)
        self.path.write_bytes(b'released')


if __name__ == '__main__':
    unittest.main(verbosity=2)
