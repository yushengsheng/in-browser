"""Synthetic layout/ownership fixtures; never move the user's desktop windows."""
from contextlib import nullcontext
import copy
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import api
import window_layout as layout
import window_layout_win32 as native
from local_state import LocalBrowserError
from window_store import WindowStore


MONITOR = dict(id='display-a', primary=True, x=-1920, y=40, width=1920, height=1040)


class FakeDesktop:
    def __init__(self):
        self.positions = {}
        self.moves = []
        self.rejected = set()
        self.stale = set()
        self.handles = {101: [11], 102: [12]}
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def monitors(self): return [dict(MONITOR)]
    def windows(self): return self.handles
    def owns(self, handle, pid): return handle not in self.stale and handle in self.handles.get(pid, [])
    def rectangle(self, handle): return self.positions.get(handle, (1, 1, 500, 500))
    def constrained_size(self, handle, requested, timeout_ms): return None
    def move(self, handle, rect):
        self.moves.append((handle, rect))
        if handle in self.rejected: return False
        self.positions[handle] = rect
        return True


class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.service = SimpleNamespace(root=self.root, operations=threading.RLock(), store=Mock())
        self.service.store.setting.return_value = {}
        self.desktop = FakeDesktop()
        self.runtime = dict(profile_path=str(self.root / 'profiles/p1'),
                            fingerprint_path=str(self.root / 'configs/p1.bin'), core_path=str(self.root / 'browser.exe'))
        self.targets = [(11, 101, 123, self.runtime), (12, 102, 124, self.runtime)]

    def settings(self, **changes): return layout.validate_settings(changes)

    def run_arrange(self, *, valid=True):
        with patch.object(native, 'Desktop', return_value=self.desktop), \
                patch.object(layout, '_targets', return_value=(self.targets, False)), \
                patch.object(layout, '_owned_process', return_value=valid):
            return layout.arrange(self.service)

    def test_auto_grid_stays_within_negative_origin_work_area(self):
        for count in (1, 2, 7, 37, 120):
            rects = layout.rectangles(self.settings(), MONITOR, count)
            self.assertEqual(len(rects), count)
            for x, y, w, h in rects:
                self.assertGreaterEqual(x, -1920)
                self.assertGreaterEqual(y, 40)
                self.assertLessEqual(x + w, 0)
                self.assertLessEqual(y + h, 1080)
                self.assertGreaterEqual(w, 120)
                self.assertGreaterEqual(h, 40)
            for i, (x, y, w, h) in enumerate(rects):
                for a, b, c, d in rects[i + 1:]:
                    self.assertTrue(x + w <= a or a + c <= x or y + h <= b or b + d <= y)
        with self.assertRaises(LocalBrowserError):
            layout.rectangles(self.settings(), MONITOR, 10000)

    def test_manual_grid_offsets_gaps_and_all_or_nothing_overflow(self):
        settings = self.settings(mode='grid', width=400, height=300, columns=3, start_x=20, start_y=10, gap_x=8, gap_y=6)
        rects = layout.rectangles(settings, MONITOR, 4)
        self.assertEqual(rects, [(-1900, 50, 400, 300), (-1492, 50, 400, 300), (-1084, 50, 400, 300), (-1900, 356, 400, 300)])
        self.service.store.setting.return_value = dict(settings, width=1500)
        with self.assertRaises(LocalBrowserError): self.run_arrange()
        self.assertEqual(self.desktop.moves, [])

    def test_cascade_wrap_and_zero_offsets_never_leave_screen(self):
        for step_x, step_y in ((30, 30), (0, 0), (0, 30), (5000, 20)):
            settings = self.settings(mode='cascade', width=500, height=400, step_x=step_x, step_y=step_y)
            rects = layout.rectangles(settings, MONITOR, 300)
            self.assertEqual(len(rects), 300)
            self.assertTrue(all(-1920 <= x and x + w <= 0 and 40 <= y and y + h <= 1080 for x, y, w, h in rects))

    def test_validation_rejects_non_integers_and_unknown_settings(self):
        for value in ({'width': True}, {'columns': 0}, {'gap_x': -1}, {'step_x': 1.5}, {'width': '500'},
                      {'height': 39}, {'mode': 'unknown'}, {'order': ''}, {'monitor': ''}, {'secret': 1}, []):
            with self.subTest(value=value), self.assertRaises(LocalBrowserError): layout.validate_settings(value)

    def test_unplugged_monitor_falls_back_without_overwriting_saved_choice(self):
        settings = self.settings(monitor='old-device')
        self.assertEqual(layout.select_monitor(settings, [MONITOR]), (MONITOR, True))
        self.service.store.setting.return_value = settings
        result = self.run_arrange()
        self.assertEqual(result['arranged'], 2)
        self.assertIn('主显示器', result['message'])
        self.service.store.set_setting.assert_not_called()

    def test_empty_and_stale_windows_have_truthful_counts(self):
        self.targets = []
        self.assertEqual(self.run_arrange()['total'], 0)
        self.targets = [(11, 101, 123, self.runtime)]
        result = self.run_arrange(valid=False)
        self.assertEqual((result['arranged'], result['skipped'], result['failed']), (0, 1, 0))
        self.assertEqual(self.desktop.moves, [])

    def test_partial_native_failure_is_not_reported_as_complete_success(self):
        self.desktop.rejected.add(12)
        result = self.run_arrange()
        self.assertEqual((result['arranged'], result['failed'], result['total']), (1, 1, 2))

    def test_posted_move_without_actual_change_is_not_success(self):
        self.targets = self.targets[:1]
        desired = layout.rectangles(self.settings(), MONITOR, 1)[0]
        self.desktop.positions[11] = (*desired[:2], 500, 500)
        self.desktop.move = Mock(return_value=True)
        with patch.object(layout.time, 'monotonic', side_effect=[0, 3]):
            result = self.run_arrange()
        self.assertEqual((result['arranged'], result['failed']), (0, 1))

    def test_actual_browser_size_adjustment_is_reported(self):
        self.targets = self.targets[:1]
        desired = layout.rectangles(self.settings(), MONITOR, 1)[0]
        def resized(handle, rect):
            self.desktop.positions[handle] = (*rect[:2], rect[2] + 10, rect[3])
            return True
        self.desktop.move = resized
        with patch.object(layout.time, 'monotonic', side_effect=[0, 3]): result = self.run_arrange()
        self.assertEqual((result['arranged'], result['adjusted']), (1, 1))

    def test_dpi_one_pixel_rounding_is_already_arranged_on_repeat(self):
        self.targets = self.targets[:1]
        desired = layout.rectangles(self.settings(), MONITOR, 1)[0]
        self.desktop.positions[11] = (*desired[:3], desired[3] + 1)
        self.desktop.move = Mock(return_value=True)
        result = self.run_arrange()
        self.assertEqual((result['arranged'], result['failed'], result['adjusted']), (1, 0, 0))

    def test_repeated_native_size_constraint_requires_exact_current_evidence(self):
        self.targets = self.targets[:1]
        desired = layout.rectangles(self.settings(), MONITOR, 1)[0]
        for size in ((desired[2], desired[3] - 100), (desired[2] + 100, desired[3])):
            with self.subTest(size=size):
                self.desktop.positions[11] = (*desired[:2], *size)
                self.desktop.move = Mock(return_value=True)
                self.desktop.constrained_size = Mock(return_value=size)
                with patch.object(layout.time, 'monotonic', side_effect=[0, 3]):
                    result = self.run_arrange()
                self.assertEqual((result['arranged'], result['failed'], result['adjusted']), (1, 0, 1))

    def test_repeat_rejects_missing_or_nonmatching_limits(self):
        self.targets = self.targets[:1]
        desired = layout.rectangles(self.settings(), MONITOR, 1)[0]
        self.desktop.positions[11] = (*desired[:2], 500, 500)
        self.desktop.move = Mock(return_value=True)
        for size in (None, desired[2:], (501, 503)):
            with self.subTest(size=size):
                self.desktop.constrained_size = Mock(return_value=size)
                with patch.object(layout.time, 'monotonic', side_effect=[0, 3]):
                    result = self.run_arrange()
                self.assertEqual((result['arranged'], result['failed']), (0, 1))

    def test_constraint_query_rechecks_ownership_and_geometry(self):
        self.targets = self.targets[:1]
        desired = layout.rectangles(self.settings(), MONITOR, 1)[0]
        for stale in (False, True):
            self.desktop.stale.clear()
            self.desktop.positions[11] = (*desired[:2], 500, 500)
            self.desktop.move = Mock(return_value=True)
            def changed(*_):
                if stale: self.desktop.stale.add(11)
                else: self.desktop.positions[11] = (100, 100, 500, 500)
                return (500, 500)
            self.desktop.constrained_size = changed
            with patch.object(layout.time, 'monotonic', side_effect=[0, 3]):
                result = self.run_arrange()
            self.assertEqual(result['arranged'], 0)
            self.assertEqual(result['skipped' if stale else 'failed'], 1)

    def test_constraint_queries_share_a_bounded_budget(self):
        for target, desired in zip(self.targets, layout.rectangles(self.settings(), MONITOR, 2)):
            self.desktop.positions[target[0]] = (*desired[:2], 500, 500)
        self.desktop.move = Mock(return_value=True)
        self.desktop.constrained_size = Mock(return_value=None)
        with patch.object(layout.time, 'monotonic', side_effect=[0, 3, 3.21]):
            result = self.run_arrange()
        self.assertEqual(result['failed'], 2)
        self.desktop.constrained_size.assert_called_once()
        self.assertLessEqual(self.desktop.constrained_size.call_args.args[-1], 100)

    def process(self, *, created=123, args=None, exe=None):
        args = args if args is not None else ['browser.exe', '--user-data-dir=' + self.runtime['profile_path'],
                                             '--fingerprint-config=' + self.runtime['fingerprint_path']]
        return SimpleNamespace(pid=101, create_time=lambda: created, cmdline=lambda: args,
                               exe=lambda: exe or self.runtime['core_path'], oneshot=nullcontext)

    def test_process_ownership_requires_exact_package_paths_and_live_identity(self):
        args = self.process().cmdline()
        cases = [(self.process(), self.runtime, True), (self.process(created=124), self.runtime, False),
                 (self.process(exe=str(self.root / 'other.exe')), self.runtime, False),
                 (self.process(args=args + ['--type=renderer']), self.runtime, False),
                 (self.process(args=args + ['--fingerprint-config=other']), self.runtime, False),
                 (self.process(args=[args[0], '--user-data-dir=' + str(self.root.parent / 'other/profile'), args[2]]), self.runtime, False),
                 (self.process(), dict(self.runtime, profile_path=str(self.root.parent / 'other/profile')), False)]
        for process, runtime, expected in cases:
            with patch.object(layout.psutil, 'Process', return_value=process):
                self.assertEqual(layout._owned_process(101, 123, runtime, self.root), expected)

    def test_target_collection_scans_once_orders_by_sequence_and_excludes_other_package(self):
        self.service.store.all.return_value = [
            dict(id='a', seq=11, _runtime=self.runtime), dict(id='b', seq=2, _runtime=dict(self.runtime, profile_path=str(self.root / 'profiles/p2'))),
            dict(id='archived', seq=3, archived=True, _runtime=self.runtime)]
        process_a, process_b = self.process(), self.process(created=124)
        process_b.pid = 102
        snapshot = Mock()
        snapshot.uncertain.return_value = False
        snapshot.browsers.side_effect = lambda path: [process_a if path == self.runtime['profile_path'] else process_b]
        self.desktop.handles[999] = [99]
        with patch.object(layout, 'ProfileProcessSnapshot', return_value=snapshot) as scan, \
                patch.object(layout, '_owned_process', return_value=True):
            result, uncertain = layout._targets(self.service, self.desktop, self.settings())
            self.assertFalse(uncertain)
            self.assertEqual([v[0] for v in result], [12, 11])
            scan.assert_called_once()
            result, uncertain = layout._targets(self.service, self.desktop, self.settings(order='desc'))
            self.assertEqual([v[0] for v in result], [11, 12])
        with patch.object(layout, 'ProfileProcessSnapshot', return_value=snapshot), \
                patch.object(layout, '_owned_process', return_value=False):
            result, uncertain = layout._targets(self.service, self.desktop, self.settings())
            self.assertEqual(result, [])
            self.assertTrue(uncertain)

    def test_unknown_process_access_is_not_presented_as_no_open_windows(self):
        self.service.store.all.return_value = [dict(id='a', seq=1, _runtime=self.runtime)]
        snapshot = Mock()
        snapshot.browsers.return_value = []
        snapshot.uncertain.return_value = True
        with patch.object(layout, 'ProfileProcessSnapshot', return_value=snapshot), \
                patch.object(native, 'Desktop', return_value=self.desktop):
            result = layout.arrange(self.service)
        self.assertIn('无法读取', result['message'])
        self.assertNotIn('当前没有', result['message'])
        self.assertEqual(self.desktop.moves, [])

    def test_layout_settings_do_not_rewrite_profile_or_existing_preferences(self):
        with patch('window_store.protect', side_effect=lambda value, **kwargs: value):
            store = self.service.store = WindowStore(None, self.root)
            store.put(dict(id='fixture', seq=1, created_at='fixture', _native={'fixed': True}, _prefs_dirty=False))
            store.set_setting('app', {'confirm_close': False})
            before = copy.deepcopy(store.all())
            layout.save_settings(self.service, {'mode': 'cascade'})
            self.assertEqual(store.all(), before)
            self.assertEqual(store.setting('app'), {'confirm_close': False})
            self.assertEqual(store.setting(layout.SETTING_KEY)['mode'], 'cascade')

    def test_busy_rejected_and_bridge_validation_errors_are_wrapped(self):
        self.service.operations = Mock()
        self.service.operations.acquire.return_value = False
        self.assertFalse(api.dispatch(self.service, 'window_layout_save', {'settings': {}})['ok'])
        self.service.store.set_setting.assert_not_called()
        self.assertFalse(api.dispatch(self.service, 'window_layout_save', {'settings': {'height': 0}})['ok'])
        with patch.object(layout, 'get_settings', return_value={'settings': {}, 'monitors': []}):
            self.assertTrue(api.dispatch(self.service, 'window_layout_get')['ok'])
        with patch.object(layout, 'arrange', return_value={'arranged': 0}):
            self.assertEqual(api.dispatch(self.service, 'arrange_windows')['data'], {'arranged': 0})

    def test_win32_move_restores_without_activation_and_preserves_z_order(self):
        desktop = native.Desktop.__new__(native.Desktop)
        desktop.user = Mock()
        desktop.user.IsIconic.return_value = True
        desktop.user.ShowWindowAsync.return_value = True
        desktop.user.SetWindowPos.return_value = True
        self.assertTrue(desktop.move(123, (0, 0, 500, 400)))
        desktop.user.ShowWindowAsync.assert_called_once_with(123, 4)
        flags = desktop.user.SetWindowPos.call_args.args[-1]
        self.assertEqual(flags & (0x0004 | 0x0010 | 0x4000), 0x0004 | 0x0010 | 0x4000)
        desktop.user.SetForegroundWindow.assert_not_called()

    def test_win32_size_constraints_are_bounded_and_fail_closed(self):
        desktop = native.Desktop.__new__(native.Desktop)
        desktop.user = Mock()
        def reply(handle, message, wparam, address, flags, timeout, result):
            self.assertEqual((handle, message, wparam, flags, timeout), (123, 0x24, 0, 3, 80))
            info = native.MinMaxInfo.from_address(address)
            info.min_track.x, info.min_track.y = 234, 46
            info.max_track.x, info.max_track.y = 2902, 1631
            return 1
        desktop.user.SendMessageTimeoutW.side_effect = reply
        self.assertEqual(desktop.constrained_size(123, (1920, 2088), 80), (1920, 1631))
        self.assertEqual(desktop.constrained_size(123, (120, 40), 80), (234, 46))
        self.assertEqual(desktop.constrained_size(123, (640, 600), 80), (640, 600))
        desktop.user.SendMessageTimeoutW.side_effect = None
        desktop.user.SendMessageTimeoutW.return_value = 0
        self.assertIsNone(desktop.constrained_size(123, (640, 600), 80))
        desktop.user.SendMessageTimeoutW.return_value = 1
        self.assertIsNone(desktop.constrained_size(123, (640, 600), 80))


if __name__ == '__main__': unittest.main()
