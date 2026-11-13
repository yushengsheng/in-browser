"""Catalog purge waits for that window's status read, without blocking another."""
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import browser_core
from batch_operations import WindowLocks
from profile_delete import _purge_runtime


class StatusPurgeRaceTests(unittest.TestCase):
    def test_purge_cannot_remove_profile_between_status_admission_and_read(self):
        area = ROOT / 'analysis/test-runs'
        area.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='status-purge-preflight-', dir=area) as check:
            folder = Path(check) / 'nested'
            folder.mkdir()
            (folder / '.owner').write_text('synthetic')
        self.assertFalse(Path(check).exists())
        with tempfile.TemporaryDirectory(prefix='status-purge-', dir=area) as directory:
            root = Path(directory)
            (root / '.owner').write_text('synthetic, no processes created')
            controller = browser_core.BrowserController.__new__(browser_core.BrowserController)
            controller.lock = threading.RLock()
            controller._state_lock = controller.lock
            controller._windows = WindowLocks()
            controller.profiles = {identity: {'alias': identity, 'core_path': str(root / 'synthetic.exe'),
                                               'status': '未打开'} for identity in ('a', 'b')}
            controller.state = {}
            controller._status_cache = {}
            controller._windowless_since = {}
            controller._closing_workers = set()
            controller.settings = {'windows': list(controller.profiles.values())}
            service = SimpleNamespace(root=root, controller=controller, configuration=SimpleNamespace())
            status_entered = threading.Event()
            release_status = threading.Event()
            purge_started = threading.Event()
            purge_done = threading.Event()
            other_done = threading.Event()
            results = {}
            failures = []

            def status(alias, **_):
                status_entered.set()
                if not release_status.wait(5):
                    raise RuntimeError('Synthetic status barrier expired')
                return controller.profiles[alias]['status']

            controller._status = status

            def poll():
                try:
                    results.update(controller.statuses(['a']))
                except Exception as error:
                    failures.append(type(error).__name__)

            def purge():
                purge_started.set()
                try:
                    _purge_runtime(service, {'identities': ['a']})
                except Exception as error:
                    failures.append(type(error).__name__)
                finally:
                    purge_done.set()

            def other_window():
                with controller._windows.hold('b'), controller._state_lock:
                    controller.profiles['b']['marker'] = True
                other_done.set()

            threads = []
            with patch.object(browser_core, 'ProfileProcessSnapshot', return_value=object()):
                try:
                    threads.append(threading.Thread(target=poll))
                    threads[-1].start()
                    self.assertTrue(status_entered.wait(2))
                    threads.append(threading.Thread(target=purge))
                    threads[-1].start()
                    self.assertTrue(purge_started.wait(2))
                    self.assertFalse(purge_done.wait(.2))
                    threads.append(threading.Thread(target=other_window))
                    threads[-1].start()
                    self.assertTrue(other_done.wait(2))
                finally:
                    release_status.set()
                    for thread in threads:
                        thread.join(5)
                self.assertTrue(all(not thread.is_alive() for thread in threads))
                self.assertEqual(failures, [])
                self.assertEqual(results, {'a': '未打开'})
                self.assertTrue(purge_done.is_set())
                self.assertNotIn('a', controller.profiles)
                self.assertTrue(controller.profiles['b']['marker'])
                self.assertEqual([item['alias'] for item in controller.settings['windows']], ['b'])
        self.assertFalse(root.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
