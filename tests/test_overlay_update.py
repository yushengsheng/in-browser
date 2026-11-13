"""Overlay updates and hard process exits in disposable synthetic releases."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_inplace_update import (InplaceUpdate, Interrupted, PACKAGE_ID, fixture,
                                manifest, pair, public_bytes, snapshot,
                                synthetic_data_check, updater, write)


EXIT_INTERRUPTED = 83


def overlay_pair(scope):
    source, target = pair(scope)
    write(source / updater.LAUNCHER, b'@echo off\r\nrem synthetic overlay launcher\r\n')
    write(source / updater.OVERLAY_MARKER, json.dumps(
        {'format': 1, 'package_id': PACKAGE_ID}, sort_keys=True).encode())
    manifest(source)
    write(target / updater.LAUNCHER, (source / updater.LAUNCHER).read_bytes())
    return source, target


def root_public_bytes(target):
    return {name: value for name, value in public_bytes(target).items()
            if not name.startswith(updater.PACKAGES + '/')}


def interrupt_at(phase, name=None):
    def stop(current, relative):
        if current == phase and (name is None or relative == name):
            raise Interrupted()
    return stop


class OverlayUpdate(unittest.TestCase):
    setUpClass = classmethod(InplaceUpdate.setUpClass.__func__)
    protected = InplaceUpdate.protected
    assert_protected = InplaceUpdate.assert_protected
    junction = InplaceUpdate.junction

    def reject_unchanged(self, source, target, **options):
        before = snapshot(target)
        with synthetic_data_check(), self.assertRaises(updater.UpdateError):
            updater.update(source, target, **options)
        self.assertEqual(snapshot(target), before)

    def assert_restored(self, source, target, original, protected):
        self.assertEqual(root_public_bytes(target), original)
        self.assert_protected(target, protected)
        self.assertFalse((target / updater.PENDING).exists())
        old_files = updater._manifest(target)
        new_files, _ = updater.compatible_source(source)
        effective = updater.effective_old_files(target, old_files, new_files)
        updater.verify_old_release(target, effective)

    def test_overlay_success_preserves_private_engine_and_payload_identities(self):
        with fixture() as scope:
            source, target = overlay_pair(scope)
            old_manifest = (target / 'release-manifest.json').read_bytes()
            source_before = snapshot(source)
            protected = self.protected(target)
            launcher_before = snapshot(target)[updater.LAUNCHER]
            with synthetic_data_check():
                result = updater.update(source, target)
            self.assertTrue(result['success'])
            self.assertEqual((target / 'VERSION').read_bytes(), b'0.2.8\n')
            self.assertEqual(snapshot(source), source_before)
            self.assertEqual(snapshot(target)[updater.LAUNCHER], launcher_before)
            self.assert_protected(target, protected)
            updater.verify_release(target)
            backup = target / result['backup']
            self.assertEqual((backup / 'old/release-manifest.json').read_bytes(), old_manifest)
            self.assertFalse((backup / 'backup' / updater.LAUNCHER).exists())
            self.assertEqual(json.loads((backup / 'plan.json').read_bytes())['overlay_package'], PACKAGE_ID)

    def test_overlay_source_does_not_require_legacy_manual_command(self):
        with fixture() as scope:
            source, target = overlay_pair(scope)
            self.assertFalse((source / '原地更新旧版本.cmd').exists())
            with synthetic_data_check():
                result = updater.update(source, target)
            self.assertTrue(result['success'])
            updater.verify_release(target)
            self.assertFalse((target / '原地更新旧版本.cmd').exists())

    def test_only_verified_new_launcher_is_an_allowed_old_release_difference(self):
        for relative in (updater.LAUNCHER, 'app/public.py', 'app/unknown.py',
                         'runtime/python/site-packages/current.py', 'tools/unknown.py'):
            with self.subTest(relative=relative), fixture() as scope:
                source, target = overlay_pair(scope)
                write(target / relative, b'synthetic unexpected root program change')
                self.reject_unchanged(source, target)

    def test_missing_unlisted_or_noncanonical_overlay_marker_is_rejected(self):
        variants = (None, {'format': True, 'package_id': PACKAGE_ID},
                    {'format': 1, 'package_id': 'f' * 32},
                    {'format': 1, 'package_id': PACKAGE_ID, 'target': '../elsewhere'})
        for marker in variants:
            with self.subTest(marker=marker), fixture() as scope:
                source, target = overlay_pair(scope)
                if marker is None:
                    (source / updater.OVERLAY_MARKER).unlink()
                else:
                    write(source / updater.OVERLAY_MARKER, json.dumps(marker).encode())
                manifest(source)
                self.reject_unchanged(source, target)
        with fixture() as scope:
            source, target = overlay_pair(scope)
            value = json.loads((source / 'release-manifest.json').read_bytes())
            del value['files'][updater.OVERLAY_MARKER]
            write(source / 'release-manifest.json', json.dumps(value).encode())
            self.reject_unchanged(source, target)

    def test_manifest_cannot_name_private_data_or_nested_packages(self):
        for relative in ('app/data/private.bin', 'app/local-engines/private.bin',
                         '.program-packages/nested/public.bin',
                         '.program-update-backup-synthetic/public.bin'):
            with self.subTest(relative=relative), fixture() as scope:
                source, target = overlay_pair(scope)
                write(source / relative, b'synthetic forbidden public path')
                value = json.loads((source / 'release-manifest.json').read_bytes())
                value['files'][relative] = updater.file_item(source / relative)
                write(source / 'release-manifest.json', json.dumps(value).encode())
                self.reject_unchanged(source, target)

    def test_policy_hash_and_version_increase_remain_required(self):
        for change in ('old_manifest', 'same_version', 'downgrade'):
            with self.subTest(change=change), fixture() as scope:
                source, target = overlay_pair(scope)
                if change == 'old_manifest':
                    with (target / 'release-manifest.json').open('ab') as stream:
                        stream.write(b'\n')
                else:
                    write(source / 'VERSION', b'0.2.7\n' if change == 'same_version' else b'0.2.6\n')
                    manifest(source)
                self.reject_unchanged(source, target)

    def test_overlay_accepts_only_the_exact_isolated_payload_path(self):
        for relative in ('other/' + PACKAGE_ID, '.program-packages/not-an-id',
                         '.program-packages/outer/' + PACKAGE_ID):
            with self.subTest(relative=relative), fixture() as scope:
                source, target = overlay_pair(scope)
                moved = target / relative
                moved.parent.mkdir(parents=True, exist_ok=True)
                source.rename(moved)
                self.reject_unchanged(moved, target)
        with fixture() as scope:
            source, target = overlay_pair(scope)
            moved = scope / PACKAGE_ID
            source.rename(moved)
            self.reject_unchanged(moved, target)

    def test_interpreter_may_be_in_payload_or_outside_target_but_not_replaced_runtime(self):
        with fixture() as scope:
            source, target = overlay_pair(scope)
            for executable in (source / 'runtime/python/python.exe', scope / 'external/python.exe'):
                with self.subTest(allowed=executable.name), patch.object(sys, 'executable', str(executable)):
                    self.assertEqual(updater.paths(source, target), (source, target))
            for executable in (target / 'runtime/python/python.exe', target / 'other/python.exe',
                               target / updater.PACKAGES / ('f' * 32) / 'runtime/python/python.exe'):
                with patch.object(sys, 'executable', str(executable)), self.assertRaises(updater.UpdateError):
                    updater.paths(source, target)

    def test_overlay_keeps_process_scan_for_other_payload_processes(self):
        import psutil
        with fixture() as scope:
            source, target = overlay_pair(scope)
            process = SimpleNamespace(pid=os.getpid() + 100000, info={
                'exe': str(source / 'runtime/python/python.exe'), 'cmdline': None, 'name': 'python.exe'})
            with patch.object(psutil, 'process_iter', return_value=[process]):
                self.reject_unchanged(source, target)

    def test_overlay_process_check_retries_only_until_transient_process_exits(self):
        source, target = Path('synthetic-payload'), Path('synthetic-target')
        with patch.object(updater, 'closed', side_effect=[RuntimeError('synthetic busy'), None]) as check:
            with patch.object(updater.time, 'sleep') as sleep:
                updater.check_closed(source, target)
        self.assertEqual(check.call_count, 2)
        self.assertTrue(all(call.args == ((source, target),) for call in check.call_args_list))
        sleep.assert_called_once_with(0.2)

    def test_overlay_process_check_rejects_after_five_busy_checks(self):
        source, target = Path('synthetic-payload'), Path('synthetic-target')
        with patch.object(updater, 'closed', side_effect=RuntimeError('synthetic busy')) as check:
            with patch.object(updater.time, 'sleep') as sleep:
                with self.assertRaises(updater.UpdateError) as caught:
                    updater.check_closed(source, target)
        self.assertEqual(caught.exception.code, 'program_running_or_unknown')
        self.assertEqual(check.call_count, 5)
        self.assertTrue(all(call.args == ((source, target),) for call in check.call_args_list))
        self.assertEqual([call.args for call in sleep.call_args_list], [(0.2,)] * 4)

    def test_process_check_returns_without_sleep_when_already_closed(self):
        source, target = Path('synthetic-payload'), Path('synthetic-target')
        with patch.object(updater, 'closed') as check:
            with patch.object(updater.time, 'sleep') as sleep:
                updater.check_closed(source, target)
        check.assert_called_once_with((source, target))
        sleep.assert_not_called()

    def test_packages_boundary_and_inner_program_links_are_rejected(self):
        for relative in (updater.PACKAGES, updater.PACKAGES + '/' + PACKAGE_ID + '/app/ui'):
            with self.subTest(relative=relative), fixture() as scope:
                source, target = overlay_pair(scope)
                path, moved = target / relative, scope / 'moved-directory'
                path.rename(moved)
                try:
                    with self.junction(path, moved):
                        with synthetic_data_check(), self.assertRaises(updater.UpdateError):
                            updater.update(source, target)
                        self.assertFalse((target / updater.PENDING).exists())
                finally:
                    moved.rename(path)

    def test_separate_release_source_is_rejected_without_modifying_old_program(self):
        with fixture() as scope:
            source, target = overlay_pair(scope)
            moved = scope / 'separate-release'
            source.rename(moved)
            before = snapshot(target)
            with synthetic_data_check(), self.assertRaises(updater.UpdateError) as caught:
                updater.update(moved, target)
            self.assertEqual(caught.exception.code, 'invalid_overlay_location')
            self.assertEqual(snapshot(target), before)
            (moved / updater.OVERLAY_MARKER).unlink()
            manifest(moved)
            with synthetic_data_check(), self.assertRaises(updater.UpdateError):
                updater.update(moved, target)
            self.assertEqual(snapshot(target), before)

    def test_preplan_crash_restores_without_modifying_original_manifest(self):
        with fixture() as scope:
            source, target = overlay_pair(scope)
            original, protected = root_public_bytes(target), self.protected(target)
            with synthetic_data_check(), patch.object(updater, 'stage', side_effect=Interrupted()):
                with self.assertRaises(Interrupted):
                    updater.update(source, target)
            self.assertFalse((target / updater.PENDING / 'plan.json').exists())
            updater.recover(source, target)
            self.assert_restored(source, target, original, protected)

    def test_exception_at_each_phase_rolls_back_to_effective_old_program(self):
        for phase in ('after_stage', 'after_bootstrap', 'before_move_old', 'after_move_old',
                      'after_publish', 'before_commit'):
            with self.subTest(phase=phase), fixture() as scope:
                source, target = overlay_pair(scope)
                original, protected = root_public_bytes(target), self.protected(target)
                def fail(current, relative):
                    if current == phase:
                        raise OSError('synthetic overlay failure')
                with synthetic_data_check(), self.assertRaises(updater.UpdateError):
                    updater.update(source, target, hook=fail)
                self.assert_restored(source, target, original, protected)

    def test_changed_or_missing_source_after_stage_or_before_commit_retains_transaction(self):
        for phase in ('after_stage', 'before_commit'):
            for missing in (False, True):
                with self.subTest(phase=phase, missing=missing), fixture() as scope:
                    source, target = overlay_pair(scope)
                    protected = self.protected(target)
                    def change(current, relative):
                        if current == phase:
                            if missing:
                                (source / 'app/new.py').unlink()
                            else:
                                write(source / 'app/new.py', b'synthetic source changed after stage')
                    with synthetic_data_check(), self.assertRaises(updater.UpdateError) as caught:
                        updater.update(source, target, hook=change)
                    self.assertEqual(caught.exception.code, 'recovery_required')
                    self.assertTrue((target / updater.PENDING).exists())
                    before = snapshot(target)
                    with self.assertRaises(updater.UpdateError):
                        updater.recover(source, target)
                    self.assertEqual(snapshot(target), before)
                    self.assert_protected(target, protected)

    def test_recovery_mode_source_and_plan_cannot_be_overridden(self):
        for metadata, mutation in (('owner.json', 'missing'), ('plan.json', 'missing'),
                                   ('owner.json', 'other'), ('plan.json', 'other'),
                                   ('plan.json', 'override')):
            with self.subTest(metadata=metadata, mutation=mutation), fixture() as scope:
                source, target = overlay_pair(scope)
                with synthetic_data_check(), self.assertRaises(Interrupted):
                    updater.update(source, target, hook=interrupt_at('after_bootstrap'))
                path = target / updater.PENDING / metadata
                original = path.read_bytes()
                value = json.loads(original)
                if mutation == 'missing':
                    del value['overlay_package']
                elif mutation == 'other':
                    value['overlay_package'] = 'f' * 32
                else:
                    value['overrides'] = {'app/data/private.bin': None}
                write(path, json.dumps(value).encode())
                before = snapshot(target)
                with self.assertRaises(updater.UpdateError):
                    updater.recover(source, target)
                self.assertEqual(snapshot(target), before)
                write(path, original)
                updater.recover(source, target)

    def worker(self, source, target, action, phase, name):
        env = {**os.environ, 'TEMP': str(target.parent), 'TMP': str(target.parent),
               'PYTHONDONTWRITEBYTECODE': '1'}
        completed = subprocess.run(
            [sys.executable, '-B', str(Path(__file__).resolve()), '--worker', action,
             str(source), str(target), phase, name], env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=45, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        self.assertEqual(completed.returncode, EXIT_INTERRUPTED, 'synthetic_hard_exit_not_reached')

    def test_hard_exit_at_every_update_boundary_can_recover(self):
        events = []
        with fixture() as scope:
            source, target = overlay_pair(scope)
            with synthetic_data_check():
                updater.update(source, target, hook=lambda phase, name: events.append((phase, name)))
        self.assertGreater(len(events), 20)
        for phase, name in events:
            with self.subTest(phase=phase, name=name), fixture() as scope:
                source, target = overlay_pair(scope)
                original, protected = root_public_bytes(target), self.protected(target)
                self.worker(source, target, 'update', phase, name)
                if phase == 'after_commit':
                    updater.verify_release(target)
                    self.assertFalse((target / updater.PENDING).exists())
                    self.assert_protected(target, protected)
                else:
                    updater.recover(source, target)
                    self.assert_restored(source, target, original, protected)

    def test_hard_exit_at_every_recovery_boundary_can_resume(self):
        events = []
        with fixture() as scope:
            source, target = overlay_pair(scope)
            with synthetic_data_check(), self.assertRaises(Interrupted):
                updater.update(source, target, hook=interrupt_at('before_commit'))
            updater.recover(source, target, hook=lambda phase, name: events.append((phase, name)))
        self.assertGreater(len(events), 20)
        for phase, name in events:
            with self.subTest(phase=phase, name=name), fixture() as scope:
                source, target = overlay_pair(scope)
                original, protected = root_public_bytes(target), self.protected(target)
                with synthetic_data_check(), self.assertRaises(Interrupted):
                    updater.update(source, target, hook=interrupt_at('before_commit'))
                self.worker(source, target, 'recover', phase, name)
                if phase != 'after_recovery_commit':
                    updater.recover(source, target)
                self.assert_restored(source, target, original, protected)


def worker_main(arguments):
    action, source, target, phase, name = arguments
    def stop(current, relative):
        if (current, relative) == (phase, name):
            os._exit(EXIT_INTERRUPTED)
    try:
        with synthetic_data_check():
            function = updater.update if action == 'update' else updater.recover
            function(Path(source), Path(target), hook=stop)
        return 2
    except BaseException:
        return 3


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--worker':
        sys.exit(worker_main(sys.argv[2:]))
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(OverlayUpdate)
    names = [test._testMethodName for test in suite]
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    failed = {getattr(test, 'test_case', test)._testMethodName
              for test, _ in result.failures + result.errors}
    print(json.dumps({'success': result.wasSuccessful(), 'tests': result.testsRun,
                      'checks': {name: name not in failed for name in names},
                      'failed': sorted(failed)}))
    print('Ran {} tests in synthetic fixtures'.format(result.testsRun), file=sys.stderr)
    print('OK' if result.wasSuccessful() else 'FAILED (failures={}, errors={})'.format(
        len(result.failures), len(result.errors)), file=sys.stderr)
    sys.exit(0 if result.wasSuccessful() else 1)
