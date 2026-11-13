"""Process scan contracts with synthetic objects; no browser or data access."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
import sys
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

import browser_processes as processes
from local_state import LocalBrowserError


class ProfileProcessScanTests(unittest.TestCase):
    def setUp(self):
        self.profile = ROOT / 'analysis/test-runs/synthetic-uncreated-profile'
        self.other = self.profile.with_name('synthetic-other-profile')

    def candidate(self, pid=101, *, args=None, **metadata):
        if args is None:
            args = ['renamed.exe', '--user-data-dir=' + str(self.profile)]
        info = {'pid': pid, 'cmdline': args, 'exe': 'renamed.exe',
                'create_time': 100, 'name': 'renamed.exe', **metadata}
        process = SimpleNamespace(pid=pid, info=dict(info))
        process.as_dict = Mock(side_effect=lambda attrs: {name: info.get(name) for name in attrs})
        return process

    def scan(self, listed, current, *, require_inspectable=False):
        with patch.object(processes.psutil, 'process_iter', return_value=iter(listed)) as iterator, \
                patch.object(processes.psutil, 'Process', side_effect=current) as lookup:
            result = processes.profile_processes(self.profile, require_inspectable=require_inspectable)
        iterator.assert_called_once_with(['pid', 'cmdline'])
        return result, lookup

    def test_all_command_lines_are_read_without_unrelated_metadata(self):
        listed = [self.candidate(pid, args=['unrelated.exe', '--no-profile']) for pid in range(100, 110)]
        for item in listed:
            item.as_dict.side_effect = AssertionError('Unrelated metadata was read')
        result, lookup = self.scan(listed, lambda pid: self.fail('Unrelated PID was opened'))
        self.assertEqual(result, [])
        lookup.assert_not_called()

    def test_matching_renamed_and_helper_processes_return_independent_complete_info(self):
        for helper in (False, True):
            with self.subTest(helper=helper):
                args = ['renamed.exe', '--user-data-dir', str(self.profile)]
                if helper:
                    args.append('--type=renderer')
                cached = self.candidate(args=args)
                fresh = self.candidate(args=list(args))
                result, lookup = self.scan([cached], lambda pid: fresh)
                self.assertEqual(result, [fresh])
                self.assertIsNot(fresh, cached)
                self.assertEqual(set(fresh.info), {'pid', 'cmdline', 'exe', 'create_time', 'name'})
                cached.as_dict.assert_not_called()
                fresh.as_dict.assert_called_once_with(attrs=['pid', 'cmdline', 'exe', 'create_time', 'name'])
                lookup.assert_called_once_with(cached.pid)

    def test_unknown_metadata_does_not_hide_a_matching_owner(self):
        cached = self.candidate()
        fresh = self.candidate(exe=None, create_time=None, name=None)
        result, _ = self.scan([cached], lambda pid: fresh)
        self.assertEqual(result, [fresh])
        self.assertIsNone(fresh.info['exe'])
        self.assertIsNone(fresh.info['create_time'])
        self.assertIsNone(fresh.info['name'])

    def test_command_line_becoming_unreadable_keeps_occupancy(self):
        for args in (None, []):
            with self.subTest(args=args):
                cached = self.candidate()
                fresh = self.candidate(cmdline=args)
                result, _ = self.scan([cached], lambda pid: fresh)
                self.assertEqual(result, [fresh])
                self.assertEqual(fresh.info['cmdline'], args)

    def test_fresh_readable_command_line_is_rechecked(self):
        for args in (['renamed.exe', '--user-data-dir=' + str(self.other)],
                     ['renamed.exe', '--no-profile']):
            with self.subTest(args=args):
                result, _ = self.scan([self.candidate()], lambda pid: self.candidate(args=args))
                self.assertEqual(result, [])

    def test_unreadable_browser_uses_both_name_and_executable_fallbacks(self):
        for field in ('name', 'exe'):
            for args in (None, []):
                with self.subTest(field=field, args=args):
                    cached = self.candidate(cmdline=args, name=None, exe=None)
                    details = {'name': None, 'exe': None, field: 'BitBrowser.exe'}
                    cached.as_dict.side_effect = lambda attrs: {name: details.get(name) for name in attrs}
                    with patch.object(processes.psutil, 'process_iter', return_value=iter([cached])), \
                            patch.object(processes.psutil, 'Process') as lookup:
                        with self.assertRaises(LocalBrowserError):
                            processes.profile_processes(self.profile, require_inspectable=True)
                    cached.as_dict.assert_called_once_with(attrs=['name', 'exe'])
                    lookup.assert_not_called()

    def test_optional_inspection_does_not_read_unreadable_metadata(self):
        cached = self.candidate(cmdline=None)
        cached.as_dict.side_effect = AssertionError('Optional unreadable metadata was read')
        result, lookup = self.scan([cached], lambda pid: self.fail('Unreadable PID was opened'))
        self.assertEqual(result, [])
        lookup.assert_not_called()

    def test_required_inspection_keeps_unrelated_unreadable_processes_unmatched(self):
        cached = self.candidate(cmdline=None, name=None, exe='unrelated.exe')
        result, lookup = self.scan([cached], lambda pid: self.fail('Unrelated PID was opened'), require_inspectable=True)
        self.assertEqual(result, [])
        cached.as_dict.assert_called_once_with(attrs=['name', 'exe'])
        lookup.assert_not_called()

    def test_disappeared_processes_are_skipped_during_lookup_and_delayed_reads(self):
        for stage in ('lookup', 'metadata', 'unreadable'):
            with self.subTest(stage=stage):
                cached = self.candidate()
                fresh = self.candidate()
                if stage == 'unreadable':
                    cached.info['cmdline'] = None
                    cached.as_dict.side_effect = processes.psutil.NoSuchProcess(cached.pid)
                elif stage == 'metadata':
                    fresh.as_dict.side_effect = processes.psutil.NoSuchProcess(cached.pid)

                def lookup(pid):
                    if stage == 'lookup':
                        raise processes.psutil.NoSuchProcess(pid)
                    return fresh

                result, _ = self.scan([cached], lookup, require_inspectable=True)
                self.assertEqual(result, [])

    def test_unexpected_delayed_metadata_failure_cannot_report_a_free_profile(self):
        cached = self.candidate()
        fresh = self.candidate()
        fresh.as_dict.side_effect = OSError('synthetic metadata failure')
        with patch.object(processes.psutil, 'process_iter', return_value=iter([cached])), \
                patch.object(processes.psutil, 'Process', return_value=fresh):
            with self.assertRaises(OSError):
                processes.profile_processes(self.profile)

    def test_parallel_scans_do_not_share_cached_info_in_returned_owners(self):
        cached = self.candidate()
        first_info = cached.info
        barrier = threading.Barrier(10, timeout=5)

        def iterator(attrs):
            self.assertEqual(attrs, ['pid', 'cmdline'])
            cached.info = dict(first_info)
            yield cached

        def lookup(pid):
            barrier.wait()
            # Another process_iter can overwrite its cached object's metadata.
            cached.info = {'pid': pid, 'cmdline': None}
            return self.candidate(pid)

        with patch.object(processes.psutil, 'process_iter', side_effect=iterator), \
                patch.object(processes.psutil, 'Process', side_effect=lookup):
            with ThreadPoolExecutor(max_workers=10) as workers:
                results = list(workers.map(lambda _: processes.profile_processes(self.profile), range(10)))
        owners = [result[0] for result in results]
        self.assertEqual(len({id(owner) for owner in owners}), 10)
        self.assertTrue(all(owner.info == first_info for owner in owners))
        self.assertEqual(cached.info, {'pid': cached.pid, 'cmdline': None})


if __name__ == '__main__':
    unittest.main(verbosity=2)
