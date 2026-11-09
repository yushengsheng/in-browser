"""Synthetic process fixtures only: no real data, browser or network access."""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

import browser_core as core
import browser_processes as processes


class Process:
    def __init__(self, pid, profile, executable, *, created=100, port=9222, args=None, name=None):
        self.pid = pid
        self.args = (list(args) if args is not None else
                     [str(executable), '--user-data-dir=' + str(profile),
                      '--remote-debugging-port=' + str(port), '--remote-debugging-address=127.0.0.1'])
        self.created = created
        self.executable = str(executable)
        self.info = {'pid': pid, 'cmdline': list(self.args), 'exe': self.executable,
                     'create_time': created, 'name': name or Path(executable).name}
        self.port = port
        self.unreadable = False
        self.gone = False

    def oneshot(self):
        return nullcontext()

    def _read(self):
        if self.gone:
            raise core.psutil.NoSuchProcess(self.pid)
        if self.unreadable:
            raise core.psutil.AccessDenied(self.pid)

    def create_time(self):
        self._read()
        return self.created

    def cmdline(self):
        self._read()
        return list(self.args)

    def exe(self):
        self._read()
        return self.executable

    def net_connections(self, *, kind):
        self._read()
        return [SimpleNamespace(status=core.psutil.CONN_LISTEN, laddr=SimpleNamespace(port=self.port))]


class BatchStatusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.executable = self.root / 'BitBrowser.exe'
        self.executable.write_bytes(b'synthetic-core')
        self.digest = core.sha256(self.executable)

    def controller(self, count):
        windows = [{'alias': 'p' + str(index), 'profile_path': str(self.root / ('profile-' + str(index))),
                    'core_path': str(self.executable), 'core_sha256': self.digest}
                   for index in range(count)]
        controller = core.BrowserController(self.root, settings={'windows': windows, 'persistent': False})
        controller._save = Mock()
        controller._queue_windowless_close = Mock()
        return controller

    def process(self, controller, index, pid, **kwargs):
        return Process(pid, controller.profiles['p' + str(index)]['profile_path'], self.executable, **kwargs)

    def record(self, process, **kwargs):
        return {'pid': process.pid, 'created': process.created, 'port': process.port,
                'ready': True, 'window_observed': True, **kwargs}

    def run_statuses(self, controller, listed, *, visible=(), lookup=None, aliases=None):
        by_pid = {process.pid: process for process in listed}
        lookup = lookup or (lambda pid: by_pid[pid])
        with patch.object(processes.psutil, 'process_iter', return_value=iter(listed)) as scan, \
                patch.object(processes.psutil, 'Process', side_effect=lookup) as process_lookup, \
                patch.object(core, '_visible_windows', side_effect=lambda pid: [1] if pid in visible else []), \
                patch.object(core, '_endpoint', return_value='synthetic-endpoint'), \
                patch.object(core, '_profile_browsers', side_effect=AssertionError('Unexpected per-profile scan')):
            result = controller.statuses(aliases)
        return result, scan.call_count, process_lookup.call_count

    def test_ten_thousand_closed_profiles_scan_once_without_pid_lookups(self):
        controller = self.controller(10000)
        result, scans, lookups = self.run_statuses(controller, [])
        self.assertEqual(len(result), 10000)
        self.assertEqual(set(result.values()), {'未打开'})
        self.assertEqual((scans, lookups), (1, 0))
        controller._save.assert_not_called()
        controller._status_cache = {alias: (time.monotonic(), value) for alias, value in result.items()}
        cached, scans, lookups = self.run_statuses(controller, [])
        self.assertEqual(cached, result)
        self.assertEqual((scans, lookups), (0, 0))

    def test_ten_thousand_with_few_real_candidates_keep_lifecycle_states(self):
        controller = self.controller(10000)
        owned = self.process(controller, 0, 101)
        adopted = self.process(controller, 1, 102)
        external = self.process(controller, 2, 103)
        external.executable = str(self.root / 'other.exe')
        external.info['exe'] = external.executable
        starting = self.process(controller, 3, 104, created=time.time())
        closing = self.process(controller, 4, 105)
        helper = self.process(controller, 5, 106)
        helper.args.append('--type=renderer')
        helper.info['cmdline'] = list(helper.args)
        controller.state = {'p0': self.record(owned), 'p3': self.record(starting, window_observed=False),
                            'p4': self.record(closing)}
        result, scans, lookups = self.run_statuses(
            controller, [owned, adopted, external, starting, closing, helper], visible={101, 102, 103})
        self.assertEqual([result['p' + str(index)] for index in range(6)],
                         ['已打开', '已打开', '已在其他进程打开', '启动未完成', '正在关闭', '未打开'])
        self.assertEqual(sum(value == '未打开' for value in result.values()), 9995)
        self.assertEqual(scans, 1)
        self.assertLess(lookups, 30)
        self.assertEqual(controller.state['p1']['pid'], 102)
        controller._queue_windowless_close.assert_called_once_with('p4')

    def test_inaccessible_browser_keeps_unknown_profiles_conservative(self):
        controller = self.controller(3)
        hidden = self.process(controller, 0, 101)
        hidden.info['cmdline'] = None
        hidden.unreadable = True
        controller.state['p0'] = self.record(hidden)
        original = dict(controller.state)
        result, scans, lookups = self.run_statuses(controller, [hidden])
        self.assertEqual(set(result.values()), {'启动未完成'})
        self.assertEqual((scans, lookups), (1, 1))
        self.assertEqual(controller.state, original)
        controller._save.assert_not_called()

    def test_unreadable_recorded_pid_does_not_hide_unrelated_closed_profiles(self):
        controller = self.controller(2)
        hidden = self.process(controller, 0, 101, name='unrelated.exe')
        hidden.info.update(cmdline=None, exe='unrelated.exe')
        hidden.unreadable = True
        controller.state['p0'] = self.record(hidden)
        result, scans, lookups = self.run_statuses(controller, [hidden])
        self.assertEqual(result, {'p0': '启动未完成', 'p1': '未打开'})
        self.assertEqual(scans, 1)
        controller._save.assert_not_called()

    def test_candidate_becomes_unreadable_or_changes_identity(self):
        for change in ('denied', 'created', 'profile', 'helper'):
            with self.subTest(change=change):
                controller = self.controller(2)
                candidate = self.process(controller, 0, 101)
                if change == 'denied':
                    candidate.unreadable = True
                elif change == 'created':
                    candidate.created += 1
                elif change == 'profile':
                    candidate.args[1] = '--user-data-dir=' + controller.profiles['p1']['profile_path']
                else:
                    candidate.args.append('--type=renderer')
                result, scans, lookups = self.run_statuses(controller, [candidate], visible={101})
                self.assertEqual(result, {'p0': '启动未完成', 'p1': '未打开'})
                self.assertEqual(scans, 1)
                self.assertEqual(controller.state, {})
                controller._save.assert_not_called()

    def test_disappeared_candidate_is_closed_and_stale_record_is_forgotten(self):
        controller = self.controller(2)
        candidate = self.process(controller, 0, 101)
        candidate.gone = True
        controller.state['p0'] = self.record(candidate)
        result, scans, lookups = self.run_statuses(controller, [candidate])
        self.assertEqual(set(result.values()), {'未打开'})
        self.assertEqual(scans, 1)
        self.assertEqual(controller.state, {})
        controller._save.assert_called_once_with()

    def test_missing_saved_pid_does_not_trigger_individual_process_lookup(self):
        controller = self.controller(10000)
        controller.state = {'p' + str(index): {'pid': index + 100, 'created': 100, 'port': 9222}
                            for index in range(10000)}
        controller._save = core.BrowserController._save.__get__(controller)
        saved = []
        with patch.object(core, 'write_encrypted', side_effect=lambda path, state: saved.append(dict(state))) as persist:
            result, scans, lookups = self.run_statuses(controller, [])
        self.assertEqual(set(result.values()), {'未打开'})
        self.assertEqual((scans, lookups), (1, 0))
        self.assertEqual(controller.state, {})
        self.assertEqual(saved, [{}])
        persist.assert_called_once_with(controller.state_path, {})

    def test_mid_batch_error_saves_confirmed_forgets_and_keeps_unchecked_records(self):
        for save_fails in (False, True):
            with self.subTest(save_fails=save_fails):
                controller = self.controller(3)
                controller.state = {'p' + str(index): {'pid': index + 100, 'created': 100, 'port': 9222}
                                    for index in range(3)}
                controller._save = core.BrowserController._save.__get__(controller)
                controller.lock = Mock(wraps=controller.lock)
                saved = []
                original_adopt = controller._adopt

                def adopt(alias, **kwargs):
                    if alias == 'p1':
                        raise core.LocalBrowserError('synthetic-query-failure')
                    return original_adopt(alias, **kwargs)

                def persist(path, state):
                    saved.append(dict(state))
                    if save_fails:
                        raise OSError('synthetic-save-failure')

                with patch.object(controller, '_adopt', side_effect=adopt), \
                        patch.object(core, 'write_encrypted', side_effect=persist) as write:
                    with self.assertRaisesRegex(core.LocalBrowserError, 'synthetic-query-failure'):
                        self.run_statuses(controller, [])
                self.assertEqual(set(controller.state), {'p1', 'p2'})
                self.assertEqual([set(state) for state in saved], [{'p1', 'p2'}])
                write.assert_called_once()
                controller.lock.release.assert_called_once_with()

    def test_batch_save_failure_keeps_unknown_record_and_releases_lock(self):
        controller = self.controller(2)
        hidden = self.process(controller, 1, 101, name='unrelated.exe')
        hidden.info.update(cmdline=None, exe='unrelated.exe')
        hidden.unreadable = True
        controller.state = {'p0': {'pid': 999, 'created': 100, 'port': 9222}, 'p1': self.record(hidden)}
        controller._save = core.BrowserController._save.__get__(controller)
        controller.lock = Mock(wraps=controller.lock)
        with patch.object(core, 'write_encrypted', side_effect=OSError('synthetic-save-failure')) as persist:
            result, scans, lookups = self.run_statuses(controller, [hidden])
        self.assertEqual(result, {'p0': '未打开', 'p1': '启动未完成'})
        self.assertEqual(set(controller.state), {'p1'})
        self.assertEqual(scans, 1)
        persist.assert_called_once_with(controller.state_path, controller.state)
        controller.lock.release.assert_called_once_with()

    def test_late_unreadable_candidate_preserves_record_before_deferred_forget(self):
        controller = self.controller(1)
        candidate = self.process(controller, 0, 101)
        candidate.executable = str(self.root / 'other.exe')
        controller.state['p0'] = self.record(candidate)
        original_browsers = processes.ProfileProcessSnapshot.browsers
        checks = 0

        def browsers(snapshot, profile):
            nonlocal checks
            checks += 1
            if checks == 2:
                candidate.unreadable = True
            return original_browsers(snapshot, profile)

        with patch.object(processes.ProfileProcessSnapshot, 'browsers', new=browsers):
            result, scans, lookups = self.run_statuses(controller, [candidate])
        self.assertEqual(result, {'p0': '启动未完成'})
        self.assertEqual(set(controller.state), {'p0'})
        controller._save.assert_not_called()

    def test_single_status_still_persists_each_forget_immediately(self):
        controller = self.controller(2)
        controller.state = {'p' + str(index): {'pid': index + 100, 'created': 100, 'port': 9222}
                            for index in range(2)}
        controller._save = core.BrowserController._save.__get__(controller)
        saved = []
        with patch.object(controller, '_ensure_record', return_value=False), \
                patch.object(core, '_profile_browsers', return_value=[]), \
                patch.object(core, 'write_encrypted', side_effect=lambda path, state: saved.append(dict(state))):
            self.assertEqual(controller.status('p0'), '未打开')
            self.assertEqual([set(state) for state in saved], [{'p1'}])
            self.assertEqual(controller.status('p1'), '未打开')
        self.assertEqual([set(state) for state in saved], [{'p1'}, set()])

    def test_adoption_keeps_core_port_address_and_listener_checks(self):
        for change in ('core', 'duplicate_port', 'address', 'listener', 'digest'):
            with self.subTest(change=change):
                controller = self.controller(1)
                candidate = self.process(controller, 0, 101)
                if change == 'core':
                    candidate.executable = str(self.root / 'other.exe')
                elif change == 'duplicate_port':
                    candidate.args.append('--remote-debugging-port=9223')
                elif change == 'address':
                    candidate.args[-1] = '--remote-debugging-address=localhost'
                elif change == 'listener':
                    candidate.port = 9223
                else:
                    controller.profiles['p0']['core_sha256'] = '0' * 64
                candidate.info['cmdline'] = list(candidate.args)
                result, scans, lookups = self.run_statuses(controller, [candidate], visible={101})
                self.assertEqual(result, {'p0': '已在其他进程打开'})
                self.assertEqual(scans, 1)
                self.assertEqual(controller.state, {})
                controller._save.assert_not_called()

    def test_partial_enumeration_failure_preserves_saved_record(self):
        controller = self.controller(1)
        controller.state['p0'] = {'pid': 101, 'created': 100, 'port': 9222}

        def fail():
            raise core.psutil.AccessDenied(101)
            yield

        with patch.object(processes.psutil, 'process_iter', return_value=fail()) as scan, \
                patch.object(processes.psutil, 'Process') as lookup:
            result = controller.statuses()
        self.assertEqual(result, {'p0': '启动未完成'})
        self.assertEqual(len(controller.state), 1)
        scan.assert_called_once()
        lookup.assert_not_called()
        controller._save.assert_not_called()

    def test_busy_controller_returns_cached_or_opening_without_scanning(self):
        controller = self.controller(2)
        controller.lock = Mock()
        controller.lock.acquire.return_value = False
        controller._status_cache['p0'] = (0, '正在关闭')
        result, scans, lookups = self.run_statuses(controller, [])
        self.assertEqual(result, {'p0': '正在关闭', 'p1': '启动未完成'})
        self.assertEqual((scans, lookups), (0, 0))
        controller.lock.release.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
