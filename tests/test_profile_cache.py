"""Retained synthetic cache fixtures; never use browser profiles or processes."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

from batch_operations import Operations
from local_state import LocalBrowserError
from manager_service import ManagerService
import profile_cache as cache


PERSISTENT = ('Cookies', 'Network/Cookies', 'Network/Cookies-wal', 'Sessions/Session_123',
              'Sessions/Tabs_123', 'Session Storage/data', 'Local Storage/leveldb/data',
              'IndexedDB/site/data', 'Login Data', 'History', 'Preferences', 'Storage/data',
              'Service Worker/CacheStorage/site/data', 'Service Worker/ScriptCache/data',
              'Extensions/extension/data', 'Extension State/data', 'CacheSomething/data')


@unittest.skipUnless(os.name == 'nt', 'Windows handle safety requires Windows')
class ProfileCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.run_root = ROOT / '测试文件夹' / ('profile-cache-' + uuid.uuid4().hex)
        cls.run_root.mkdir(parents=True)
        (cls.run_root / 'owner.json').write_text(json.dumps({'owner': 'test_profile_cache', 'synthetic': True}), encoding='utf-8')

    def setUp(self):
        self.root = self.run_root / self._testMethodName
        self.root.mkdir()
        self.service = ManagerService.__new__(ManagerService)
        self.service.root = self.root
        self.service.operations = Operations()
        self.service._require_available = Mock()
        self.service.controller = Mock(state={}, _closing_workers=set())
        self.records = {}
        self.service.store = Mock()
        self.service.store.get.side_effect = lambda identity: copy.deepcopy(self.records[identity])
        self.snapshot = Mock()
        self.snapshot.occupied.return_value = False
        self.snapshot.uncertain.return_value = False
        self.scan = patch('manager_service.ProfileProcessSnapshot', return_value=self.snapshot)
        self.scan.start()
        self.addCleanup(self.scan.stop)

    def profile(self, identity='selected'):
        profile = self.root / 'profiles' / identity
        profile.mkdir(parents=True)
        self.records[identity] = {'id': identity, 'archived': False, '_runtime': {
            'alias': identity, 'profile_path': str(profile), 'core_path': 'synthetic.exe'}}
        return profile

    def write(self, profile, relative, data=b'synthetic-cache'):
        target = profile / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def clear(self, identities=None):
        return cache.clear_cache(self.service, identities or ['selected'])

    def assert_zero(self, result, status):
        self.assertEqual(result[status], 1)
        self.assertEqual(result['removed_files'], 0)
        self.assertEqual(result['removed_bytes'], 0)

    def test_only_whitelisted_files_removed_and_all_persistent_bytes_unchanged(self):
        profile = self.profile()
        unselected = self.profile('unselected')
        kept = {self.write(profile, 'Default/' + relative, bytes([index]) * 29): bytes([index]) * 29
                for index, relative in enumerate(PERSISTENT)}
        kept[self.write(profile, 'Local State', b'root state')] = b'root state'
        kept[self.write(profile, 'Profile 1/Cache/cache', b'other profile')] = b'other profile'
        kept[self.write(unselected, 'Default/Cache/data', b'unselected')] = b'unselected'
        targets = [self.write(profile, relative + '/nested/data', b'x' * (index + 1))
                   for index, relative in enumerate(cache.CACHE_PATHS)]
        records = copy.deepcopy(self.records)
        result = self.clear()
        self.assertEqual((result['completed'], result['failed'], result['skipped']), (1, 0, 0))
        self.assertEqual((result['removed_files'], result['removed_bytes']), (len(targets), 28))
        self.assertTrue(all(not path.exists() and path.parent.is_dir() for path in targets))
        self.assertTrue(all(path.read_bytes() == expected for path, expected in kept.items()))
        self.assertEqual(records, self.records)
        self.service.store.put.assert_not_called()
        self.service.controller.close.assert_not_called()

    def test_repeated_and_empty_cache_are_cleaned_zero(self):
        profile = self.profile()
        self.write(profile, 'Default/Cache/data')
        self.assertEqual(self.clear()['completed'], 1)
        self.assert_zero(self.clear(), 'completed')

    def test_ids_reject_traversal_duplicates_case_aliases_and_oversized_batch(self):
        for values in (None, 'selected', [], [1], ['../bad'], ['a/b'], ['C:bad'], ['a', 'a'],
                       ['a', 'A'], ['x' * 81], [str(index) for index in range(101)]):
            with self.subTest(values=values):
                with self.assertRaises(LocalBrowserError):
                    cache.clear_cache(self.service, values)
        self.service.store.get.assert_not_called()

    def test_missing_mismatched_or_external_owner_never_deleted(self):
        profile = self.profile()
        target = self.write(profile, 'Default/Cache/data')
        external = self.root / 'external'
        external.mkdir()
        outside = self.write(external, 'Default/Cache/data')
        original = copy.deepcopy(self.records['selected'])
        variants = [dict(original, id='wrong'), dict(original, _runtime={}),
                    dict(original, _runtime=dict(original['_runtime'], alias='wrong')),
                    dict(original, _runtime=dict(original['_runtime'], profile_path=str(external))),
                    dict(original, _runtime=dict(original['_runtime'], profile_path=str(profile / '..' / 'selected')))]
        for record in variants:
            self.records['selected'] = record
            self.assert_zero(self.clear(), 'failed')
            self.assertTrue(target.exists() and outside.exists())
        self.records.clear()
        self.assert_zero(self.clear(), 'failed')

    def test_archived_pending_and_unconfirmed_processes_do_not_remove(self):
        profile = self.profile()
        target = self.write(profile, 'Default/Cache/data')
        self.records['selected']['archived'] = True
        self.assert_zero(self.clear(), 'skipped')
        self.records['selected']['archived'] = False
        self.service._require_available.side_effect = LocalBrowserError('synthetic pending')
        self.assert_zero(self.clear(), 'failed')
        self.service._require_available.side_effect = None
        for method in ('occupied', 'uncertain'):
            getattr(self.snapshot, method).return_value = True
            self.assert_zero(self.clear(), 'skipped')
            getattr(self.snapshot, method).return_value = False
        self.service.controller._closing_workers.add('selected')
        self.assert_zero(self.clear(), 'skipped')
        self.service.controller._closing_workers.clear()
        self.service.controller.state['selected'] = {'ready': False}
        self.assert_zero(self.clear(), 'skipped')
        self.assertTrue(target.exists())

    def junction(self, target, link):
        # Creating a junction requires no elevation; no removal is performed.
        command = 'New-Item -ItemType Junction -Path $env:PROFILE_CACHE_LINK -Target $env:PROFILE_CACHE_TARGET -ErrorAction Stop | Out-Null'
        env = dict(os.environ, TEMP=str(self.root), TMP=str(self.root),
                   PROFILE_CACHE_LINK=str(link), PROFILE_CACHE_TARGET=str(target))
        powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        completed = subprocess.run([str(powershell), '-NoProfile', '-Command', command], cwd=self.root, env=env,
                                   capture_output=True, timeout=15)
        self.assertEqual(completed.returncode, 0, 'Synthetic junction creation failed')

    def test_cache_junction_refused_before_any_deletion(self):
        profile = self.profile()
        valid = self.write(profile, 'Default/Cache/valid')
        external = self.root / 'outside'
        external.mkdir()
        protected = self.write(external, 'protected')
        self.junction(external, profile / 'Default/GPUCache')
        self.assert_zero(self.clear(), 'failed')
        self.assertTrue(valid.exists() and protected.exists())

    def test_nested_junction_and_ancestor_junction_are_refused(self):
        profile = self.profile()
        valid = self.write(profile, 'Default/Cache/valid')
        outside = self.root / 'outside'
        outside.mkdir()
        protected = self.write(outside, 'protected')
        self.junction(outside, profile / 'Default/Cache/nested')
        self.assert_zero(self.clear(), 'failed')
        self.assertTrue(valid.exists() and protected.exists())
        # A root ancestor is rejected even when the declared spelling agrees.
        alias = self.root / 'alias'
        self.junction(profile.parent, alias)
        self.service.root = self.root / 'aliased-root'
        self.service.root.mkdir()
        self.junction(profile.parent, self.service.root / 'profiles')
        self.records['selected']['_runtime']['profile_path'] = str(self.service.root / 'profiles/selected')
        self.assert_zero(self.clear(), 'failed')

    def test_file_hardlink_is_refused_before_deletion(self):
        profile = self.profile()
        valid = self.write(profile, 'Default/Cache/valid')
        outside = self.write(self.root, 'outside', b'persistent')
        os.link(outside, profile / 'Default/Cache/link')
        self.assert_zero(self.clear(), 'failed')
        self.assertEqual(outside.read_bytes(), b'persistent')
        self.assertTrue(valid.exists())

    def test_actual_file_occupancy_counts_only_success_and_can_retry(self):
        profile = self.profile()
        occupied = self.write(profile, 'Default/Cache/occupied', b'occupied')
        free = self.write(profile, 'Default/Code Cache/free', b'free')
        with occupied.open('rb'):
            result = self.clear()
        self.assertEqual((result['failed'], result['removed_files'], result['removed_bytes']), (1, 1, 4))
        self.assertTrue(occupied.exists())
        self.assertFalse(free.exists())
        result = self.clear()
        self.assertEqual((result['completed'], result['removed_files'], result['removed_bytes']), (1, 1, 8))

    def test_file_replacement_after_scan_is_refused_and_not_counted(self):
        profile = self.profile()
        target = self.write(profile, 'Default/Cache/data', b'original')
        original = cache._WindowsFiles.remove_file
        def changed(api, path, expected):
            path.write_bytes(b'changed-after-scan')
            return original(api, path, expected)
        with patch.object(cache._WindowsFiles, 'remove_file', changed):
            self.assert_zero(self.clear(), 'failed')
        self.assertEqual(target.read_bytes(), b'changed-after-scan')

    def test_new_cache_created_during_cleanup_is_preserved_and_reported_partial(self):
        profile = self.profile()
        self.write(profile, 'Default/Cache/data', b'old')
        original = cache._WindowsFiles.remove_file
        def changed(api, path, expected):
            removed = original(api, path, expected)
            self.write(profile, 'Default/Cache/new', b'new')
            return removed
        with patch.object(cache._WindowsFiles, 'remove_file', changed):
            result = self.clear()
        self.assertEqual((result['failed'], result['removed_files'], result['removed_bytes']), (1, 1, 3))
        self.assertEqual((profile / 'Default/Cache/new').read_bytes(), b'new')

    def test_process_becoming_unknown_after_scan_deletes_nothing_and_releases(self):
        profile = self.profile()
        target = self.write(profile, 'Default/Cache/data')
        self.snapshot.uncertain.side_effect = [False, True]
        self.assert_zero(self.clear(), 'skipped')
        self.assertTrue(target.exists())
        profile.rename(profile.with_name('released-after-refusal'))
        self.assertTrue(self.service.operations.acquire(blocking=False))
        self.service.operations.release()

    def test_process_becoming_unknown_after_delete_reports_partial(self):
        profile = self.profile()
        self.write(profile, 'Default/Cache/data', b'123')
        self.snapshot.uncertain.side_effect = [False, False, True]
        result = self.clear()
        self.assertEqual((result['failed'], result['removed_files'], result['removed_bytes']), (1, 1, 3))

    def test_pinned_directories_cannot_be_renamed_during_delete_and_handles_release(self):
        profile = self.profile()
        target = self.write(profile, 'Default/Cache/data')
        original = cache._WindowsFiles.remove_file
        refused = []
        def attempt(api, path, expected):
            for folder in (path.parent, profile, self.root / 'profiles'):
                try:
                    folder.rename(folder.with_name(folder.name + '-moved'))
                except OSError:
                    refused.append(True)
                else:
                    refused.append(False)
            return original(api, path, expected)
        with patch.object(cache._WindowsFiles, 'remove_file', attempt):
            result = self.clear()
        self.assertEqual(refused, [True, True, True])
        self.assertEqual(result['completed'], 1, result['results'][0]['message'])
        self.assertFalse(target.exists())
        profile.rename(profile.with_name('released'))

    def test_link_swap_between_inspection_and_open_refuses_target(self):
        profile = self.profile()
        target = self.write(profile, 'Default/Cache/data')
        outside = self.write(self.root, 'outside/data', b'protected')
        original = cache._WindowsFiles.open
        swapped = False
        @contextmanager
        def changed(api, path, *, directory):
            nonlocal swapped
            if directory and path == target.parent and not swapped:
                swapped = True
                path.rename(path.with_name('retained-original'))
                self.junction(outside.parent, path)
            with original(api, path, directory=directory) as value:
                yield value
        with patch.object(cache._WindowsFiles, 'open', changed):
            self.assert_zero(self.clear(), 'failed')
        self.assertTrue(swapped)
        self.assertEqual(outside.read_bytes(), b'protected')

    def test_resource_limits_and_timeout_fail_without_false_completion(self):
        profile = self.profile()
        target = self.write(profile, 'Default/Cache/data')
        for field, limit in (('MAX_ENTRIES', 0), ('MAX_DIRECTORIES', 0), ('MAX_DEPTH', 0), ('PROFILE_SECONDS', 0)):
            with self.subTest(field=field), patch.object(cache, field, limit):
                self.assert_zero(self.clear(), 'failed')
                self.assertTrue(target.exists())
        self.assertEqual(self.clear()['completed'], 1)

    def test_batch_mixed_results_preserve_requested_order(self):
        self.write(self.profile(), 'Default/Cache/data', b'123')
        self.profile('archived')
        self.records['archived']['archived'] = True
        result = self.clear(['archived', 'missing', 'selected'])
        self.assertEqual([row['id'] for row in result['results']], ['archived', 'missing', 'selected'])
        self.assertEqual((result['completed'], result['skipped'], result['failed']), (1, 1, 1))
        self.assertEqual((result['removed_files'], result['removed_bytes']), (1, 3))

    def test_window_mutations_import_and_exit_wait_for_cleanup_and_release_on_error(self):
        self.write(self.profile(), 'Default/Cache/data')
        reached, release, same_window = threading.Event(), threading.Event(), threading.Event()
        original = cache._WindowsFiles.remove_file
        def blocked(api, path, expected):
            reached.set()
            if not release.wait(5):
                raise AssertionError('Synthetic release timed out')
            return original(api, path, expected)
        def competing():
            with self.service._window_operation('selected'):
                same_window.set()
        with patch.object(cache._WindowsFiles, 'remove_file', blocked), ThreadPoolExecutor(max_workers=2) as workers:
            result = workers.submit(self.clear)
            try:
                self.assertTrue(reached.wait(3))
                competition = workers.submit(competing)
                self.assertFalse(same_window.wait(.1))
                self.assertFalse(self.service.operations.acquire(blocking=False))
                with self.service._window_operation('unrelated'):
                    pass
            finally:
                release.set()
            self.assertEqual(result.result(4)['completed'], 1)
            competition.result(4)
        self.assertTrue(same_window.is_set())
        self.assertTrue(self.service.operations.acquire(blocking=False))
        self.service.operations.release()
        self.assertFalse(self.service.operations._windows._windows)


if __name__ == '__main__':
    unittest.main(verbosity=2)
