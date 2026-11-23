"""Synthetic encrypted failure evidence; fixtures are retained for manual removal."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tests')]

import import_diagnostics
from import_diagnostics import SETTING_KEY, failure_record, persist_failure
from import_progress import emit
from local_state import LocalBrowserError
from portable_vault import PortableVault
import profile_copy
from test_sync_reliability import fixture
from window_store import WindowStore
import window_sync

SECRET = 'synthetic-private-path-account-message'
JOB = 'a' * 32


class ImportDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = ROOT / '测试文件夹'
        base.mkdir(exist_ok=True)
        cls.suite_root = Path(tempfile.mkdtemp(prefix='import-diagnostics-', dir=base))
        (cls.suite_root / 'owner.json').write_text(json.dumps({
            'purpose': 'synthetic-import-diagnostics', 'pid': os.getpid(),
            'retained_for_user_deletion': True}), encoding='utf-8')

    def setUp(self):
        self.root = self.suite_root / self._testMethodName
        self.root.mkdir()
        PortableVault(self.root).initialize()
        self.store = WindowStore(SimpleNamespace(), self.root)

    def wrapped_error(self):
        try:
            profile_copy._info(self.root / SECRET)
        except OSError:
            try:
                error = LocalBrowserError(SECRET)
                error.code = 'source_seed_budget'
                error.source_key = SECRET
                error.private_path = str(self.root / SECRET)
                raise error from None
            except LocalBrowserError as captured:
                return captured

    def test_restart_reads_encrypted_evidence_without_private_fields(self):
        record = failure_record(JOB, 1, 'preparing', self.wrapped_error())
        persist_failure(self.store, record)
        restarted = WindowStore(SimpleNamespace(), self.root)
        self.assertEqual(restarted.setting(SETTING_KEY), [record])
        self.assertEqual(record['type'], 'LocalBrowserError')
        self.assertEqual(record['code'], 'source_seed_budget')
        self.assertEqual(record['contexts'][0]['type'], 'FileNotFoundError')
        self.assertTrue(any(frame['file'] == 'profile_copy.py'
                            for frame in record['contexts'][0]['frames']))
        text = json.dumps(record)
        self.assertNotIn(SECRET, text)
        self.assertNotIn(str(self.root), text)
        self.assertNotIn('name', record)
        self.assertNotIn('source_key', record)
        with self.store.connect() as connection:
            encrypted = connection.execute('SELECT value FROM settings WHERE key=?', (SETTING_KEY,)).fetchone()[0]
        self.assertNotIn(JOB.encode(), encrypted)
        self.assertNotIn(SECRET.encode(), encrypted)
        self.assertNotIn(b'preparing', encrypted)
        for path in self.root.glob('windows.sqlite*'):
            self.assertNotIn(SECRET.encode(), path.read_bytes())

    def test_unknown_attributes_and_exception_strings_are_never_exposed(self):
        class PrivateError(Exception):
            def __str__(self):
                raise AssertionError('Exception must never be formatted')
        error = PrivateError(SECRET)
        error.code = error.errno = error.winerror = SECRET
        record = failure_record(JOB, 1, SECRET, error)
        self.assertEqual(record['phase'], 'checking')
        self.assertEqual(record['type'], 'Exception')
        self.assertIsNone(record['code'])
        self.assertIsNone(record['errno'])
        self.assertIsNone(record['winerror'])
        self.assertNotIn(SECRET, json.dumps(record))

    def test_frames_and_suppressed_context_are_bounded_and_deduplicated(self):
        def recurse(depth):
            if depth:
                return profile_copy._retry(lambda: recurse(depth - 1))
            raise ValueError(SECRET)
        try:
            recurse(20)
        except ValueError as captured:
            error = captured
        chain = [error]
        for _ in range(6):
            wrapped = LocalBrowserError(SECRET)
            wrapped.__context__ = chain[-1]
            wrapped.__suppress_context__ = True
            wrapped.__traceback__ = error.__traceback__
            chain.append(wrapped)
        record = failure_record(JOB, 1, 'copying', error)
        self.assertEqual(len(record['frames']), 12)
        self.assertTrue(all(frame['file'] == 'profile_copy.py' and frame['line'] > 0
                            for frame in record['frames']))
        bounded = failure_record(JOB, 1, 'copying', chain[-1])
        self.assertEqual(len(bounded['contexts']), 3)
        self.assertEqual(sum(len(item['frames']) for item in (bounded, *bounded['contexts'])), 12)
        error.__context__ = chain[1]
        cycle = failure_record(JOB, 1, 'copying', chain[1])
        self.assertEqual(len(cycle['contexts']), 1)

    def test_five_writers_keep_every_record(self):
        barrier = threading.Barrier(5)
        def writer(worker):
            barrier.wait(timeout=10)
            for index in range(10):
                ordinal = worker * 10 + index + 1
                persist_failure(self.store, failure_record(JOB, ordinal, 'copying', ValueError(SECRET)))
        with ThreadPoolExecutor(max_workers=5) as executor:
            list(executor.map(writer, range(5)))
        records = self.store.setting(SETTING_KEY)
        self.assertEqual(len(records), 50)
        self.assertEqual({item['ordinal'] for item in records}, set(range(1, 51)))

    def test_history_keeps_only_the_latest_hundred_failures(self):
        self.store.set_setting(SETTING_KEY, [failure_record(JOB, ordinal, 'copying', ValueError())
                                            for ordinal in range(1, 101)])
        persist_failure(self.store, failure_record(JOB, 101, 'copying', ValueError()))
        records = self.store.setting(SETTING_KEY)
        self.assertEqual(len(records), 100)
        self.assertEqual([item['ordinal'] for item in records], list(range(2, 102)))

    def test_failed_diagnostic_write_preserves_both_import_failure_messages(self):
        for index, error in enumerate((LocalBrowserError('合成公开失败。'), OSError(SECRET)), 1):
            with self.subTest(kind=type(error).__name__):
                service, sync, items = fixture(self.root / str(index), count=1, encrypted=True)
                job = str(index) * 32
                sync.state.create(job, items)
                def fail(*args):
                    emit('copying')
                    raise error
                with patch.object(sync, '_import', side_effect=fail), \
                        patch.object(window_sync, 'persist_failure', side_effect=OSError(SECRET)):
                    sync._run_item(job, 1, items[0])
                status = sync.state.status(job)
                self.assertEqual((status['completed'], status['failed']), (0, 1))
                expected = ('合成公开失败。' if index == 1 else
                            '本次同步未完成，来源和已有本地窗口未修改。请检查磁盘、文件占用或授权。')
                self.assertEqual(status['items'][0]['message'], expected)
                failures = [item for item in sync.diagnostics[job] if item.get('kind') == 'failure']
                self.assertEqual(len(failures), 1)
                self.assertEqual(failures[0]['phase'], 'copying')
                self.assertNotIn(SECRET, json.dumps(sync.diagnostics[job]))
                self.assertIsNone(service.store.setting(SETTING_KEY))

    def test_dispatch_failure_is_retained_without_marking_pending_item_failed(self):
        service, sync, items = fixture(self.root / 'dispatch', count=1, encrypted=True)
        sync.state.create(JOB, items)
        with patch.object(sync.state, 'begin_item', side_effect=OSError(SECRET)):
            sync._run(JOB)
        status = sync.state.status(JOB)
        self.assertEqual((status['state'], status['completed'], status['failed']), ('interrupted', 0, 0))
        self.assertEqual(len(list(sync.state.pending(JOB))), 1)
        records = service.store.setting(SETTING_KEY)
        self.assertEqual([(item['ordinal'], item['type']) for item in records], [(0, 'OSError')])
        self.assertNotIn(SECRET, json.dumps(records))

    def test_preflight_original_failure_is_retained_with_per_item_outcome(self):
        service, sync, items = fixture(self.root / 'preflight', count=101, encrypted=True)
        sync.state.create(JOB, items)
        with patch.object(sync, '_prepare_roots', side_effect=LocalBrowserError('合成公开失败。')):
            sync._run(JOB)
        status = sync.state.status(JOB)
        self.assertEqual((status['state'], status['completed'], status['failed']), ('completed', 0, 101))
        records = service.store.setting(SETTING_KEY)
        self.assertEqual([item['ordinal'] for item in records], [0])
        self.assertTrue(all(item['type'] == 'LocalBrowserError' for item in records))


if __name__ == '__main__':
    unittest.main(verbosity=2)
