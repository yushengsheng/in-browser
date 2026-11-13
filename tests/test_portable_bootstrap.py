"""Normal-launch preparation with disposable releases and synthetic data only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_inplace_update import (Interrupted, fixture, manifest, release, snapshot,
                                synthetic_data_check, updater, write)
from test_overlay_update import overlay_pair, PACKAGE_ID, interrupt_at
import overlay_layout as layout
import portable_bootstrap as bootstrap


def complete_payload(source, target):
    for name in (layout.BOOTSTRAP, 'tools/overlay_layout.py'):
        write(source / name, b'# synthetic public fixture, never executed\n')
    write(source / layout.LAUNCHER, layout.launcher_bytes(PACKAGE_ID))
    write(target / layout.LAUNCHER, layout.launcher_bytes(PACKAGE_ID))
    manifest(source)
    return source, target


def fresh_pair(scope):
    old = release(scope / 'reference', version='0.2.7')
    target = scope / 'empty'
    source = release(target / layout.PACKAGE_DIRECTORY / PACKAGE_ID,
                     version='0.2.8', previous=old)
    write(source / layout.MARKER, json.dumps({'format': 1, 'package_id': PACKAGE_ID}).encode())
    (source / 'runtime/empty/nested').mkdir(parents=True)
    (source / 'app/engines/148/Dictionaries').mkdir(parents=True)
    return complete_payload(source, target)


class PortableBootstrap(unittest.TestCase):
    def setUp(self):
        self.tools = patch.object(bootstrap, 'load_tools', return_value=(updater, layout))
        self.tools.start()
        self.addCleanup(self.tools.stop)

    def test_first_install_keeps_original_application_root_and_is_idempotent(self):
        with fixture() as scope:
            source, target = fresh_pair(scope)
            source_before = snapshot(source)
            first = bootstrap.prepare(source, target)
            self.assertEqual(first['mode'], 'installed')
            self.assertEqual((target / 'VERSION').read_text().strip(), '0.2.8')
            self.assertFalse((target / 'app/data').exists())
            self.assertFalse((source / 'app/data').exists())
            self.assertTrue((target / 'runtime/empty/nested').is_dir())
            self.assertTrue((target / 'app/engines/148/Dictionaries').is_dir())
            updater.verify_release(target)
            before = snapshot(target)
            self.assertEqual(bootstrap.prepare(source, target)['mode'], 'current')
            self.assertEqual(snapshot(target), before)
            self.assertEqual(snapshot(source), source_before)
            with patch.object(bootstrap.subprocess, 'Popen') as launch:
                bootstrap.launch(target)
            args, options = launch.call_args
            self.assertEqual(args[0], [str(target / 'runtime/python/pythonw.exe'), '-B',
                                      str(target / 'app/local_browser.pyw')])
            self.assertEqual(options['cwd'], target / 'app')

    def test_normal_launch_upgrades_then_reopens_without_replaying_update(self):
        with fixture() as scope:
            source, target = complete_payload(*overlay_pair(scope))
            protected = {name: snapshot(target / name) for name in (
                'app/data', 'app/local-engines', 'app/engines')}
            with synthetic_data_check():
                self.assertEqual(bootstrap.prepare(source, target)['mode'], 'updated')
            with patch.object(updater, 'update', side_effect=AssertionError('must not replay')):
                self.assertEqual(bootstrap.prepare(source, target)['mode'], 'current')
            for name, before in protected.items():
                self.assertEqual(snapshot(target / name), before)

    def test_incomplete_payload_never_changes_existing_target(self):
        for missing in ('release-manifest.json', 'update-policy.json',
                        'runtime/python/pythonw.exe', layout.BOOTSTRAP, layout.MARKER):
            with self.subTest(missing=missing), fixture() as scope:
                source, target = complete_payload(*overlay_pair(scope))
                (source / missing).unlink()
                before = snapshot(target)
                with self.assertRaises(Exception):
                    bootstrap.prepare(source, target)
                self.assertEqual(snapshot(target), before)
                self.assertFalse((target / updater.PENDING).exists())

    def test_missing_manifest_and_policy_never_turn_payload_into_development_mode(self):
        with fixture() as scope:
            source, target = fresh_pair(scope)
            (source / 'release-manifest.json').unlink()
            (source / 'update-policy.json').unlink()
            before = snapshot(target)
            with self.assertRaises(updater.UpdateError):
                bootstrap.prepare(source, target)
            self.assertEqual(snapshot(target), before)

    def test_first_install_refuses_existing_data_or_unmanaged_program(self):
        for name in ('app/data/synthetic.bin', 'app/local-engines/synthetic.bin',
                     'app/unknown.py', 'runtime/unknown.bin', 'VERSION'):
            with self.subTest(name=name), fixture() as scope:
                source, target = fresh_pair(scope)
                write(target / name, b'preexisting synthetic bytes')
                before = snapshot(target)
                with self.assertRaises(updater.UpdateError):
                    bootstrap.prepare(source, target)
                self.assertEqual(snapshot(target), before)

    def test_first_install_continues_after_interruption_and_partial_staged_copy(self):
        with fixture() as scope:
            source, target = fresh_pair(scope)
            with self.assertRaises(Interrupted):
                bootstrap.prepare(source, target, hook=interrupt_at('after_install_marker'))
            write(target / updater.PENDING / 'stage/app/public.py', b'partial')
            self.assertEqual(bootstrap.prepare(source, target)['mode'], 'installed')
            updater.verify_release(target)
            self.assertFalse((target / updater.PENDING).exists())

    def test_resume_rejects_corrupt_marker_changed_target_and_added_data(self):
        for kind in ('owner', 'program', 'data'):
            with self.subTest(kind=kind), fixture() as scope:
                source, target = fresh_pair(scope)
                with self.assertRaises(Interrupted):
                    bootstrap.prepare(source, target, hook=interrupt_at('after_install_marker'))
                if kind == 'owner':
                    write(target / updater.PENDING / 'owner.json', b'{broken')
                else:
                    write(target / ('app/data/private.bin' if kind == 'data' else 'app/public.py'),
                          b'changed synthetic bytes')
                before = snapshot(target)
                owner_before = (target / updater.PENDING / 'owner.json').read_bytes()
                with self.assertRaises(Exception):
                    bootstrap.prepare(source, target)
                self.assertEqual(snapshot(target), before)
                self.assertEqual((target / updater.PENDING / 'owner.json').read_bytes(), owner_before)
                self.assertTrue((target / updater.PENDING).exists())

    def test_normal_launch_recovers_interrupted_upgrade_then_updates(self):
        with fixture() as scope:
            source, target = complete_payload(*overlay_pair(scope))
            protected = snapshot(target / 'app/data')
            with synthetic_data_check(), self.assertRaises(Interrupted):
                updater.update(source, target, hook=interrupt_at('after_bootstrap'))
            with synthetic_data_check():
                result = bootstrap.prepare(source, target)
            self.assertEqual(result, {'success': True, 'mode': 'updated', 'recovered': True})
            self.assertEqual(snapshot(target / 'app/data'), protected)
            updater.verify_release(target)

    def test_running_manager_and_parallel_preparation_are_refused(self):
        if os.name != 'nt':
            self.skipTest('Windows named mutex')
        with fixture() as scope:
            source, target = fresh_pair(scope)
            before = snapshot(target)
            with updater.manager_guard(target), self.assertRaises(updater.UpdateError):
                bootstrap.prepare(source, target)
            with bootstrap.preparation_guard(target, updater), self.assertRaises(updater.UpdateError):
                bootstrap.prepare(source, target)
            self.assertEqual(snapshot(target), before)

    def test_synthetic_data_compatibility_failure_prevents_update(self):
        with fixture() as scope:
            source, target = complete_payload(*overlay_pair(scope))
            protected = snapshot(target / 'app/data')
            with patch.object(updater, 'validate_data', side_effect=updater.UpdateError('unsupported_data')):
                with self.assertRaises(updater.UpdateError):
                    bootstrap.prepare(source, target)
            self.assertEqual(snapshot(target / 'app/data'), protected)
            self.assertEqual((target / 'VERSION').read_text().strip(), '0.2.7')

    def test_competing_normal_launch_exits_without_a_blocking_dialog(self):
        with fixture() as scope:
            source, target = fresh_pair(scope)
            with bootstrap.preparation_guard(target, updater), \
                    patch.object(bootstrap, 'ROOT', source), \
                    patch.object(bootstrap, 'launch') as launch, \
                    patch.object(bootstrap.ctypes.windll.user32, 'MessageBoxW') as message:
                self.assertEqual(bootstrap.main(['--target', str(target)]), 0)
                launch.assert_not_called()
                message.assert_not_called()

    def test_hard_exit_at_each_first_install_publication_resumes_on_normal_launch(self):
        with fixture() as scope:
            source, target = fresh_pair(scope)
            points = []
            bootstrap.prepare(source, target, hook=lambda phase, name: points.append((phase, name)))
        child = r'''
import os,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[2]]
from test_portable_bootstrap import bootstrap,updater,layout
bootstrap.load_tools=lambda:(updater,layout)
index=[0]
def hook(phase,name):
    current=index[0];index[0]+=1
    if current==int(sys.argv[5]):os._exit(84)
bootstrap.prepare(Path(sys.argv[3]),Path(sys.argv[4]),hook=hook)
raise SystemExit(85)
'''
        tests = Path(__file__).resolve().parent
        for stop, point in enumerate(points):
            with self.subTest(point=point), fixture() as scope:
                source, target = fresh_pair(scope)
                payload_before = snapshot(source)
                result = subprocess.run([sys.executable, '-B', '-c', child, str(tests),
                                         str(tests.parent / 'tools'), str(source), str(target), str(stop)],
                                        capture_output=True, timeout=30,
                                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                self.assertEqual(result.returncode, 84)
                self.assertEqual(bootstrap.prepare(source, target)['mode'], 'installed')
                updater.verify_release(target)
                self.assertTrue((target / 'runtime/empty/nested').is_dir())
                self.assertTrue((target / 'app/engines/148/Dictionaries').is_dir())
                self.assertFalse((target / 'app/data').exists())
                self.assertEqual(snapshot(source), payload_before)

    def test_launch_failure_does_not_start_a_second_or_payload_application(self):
        with fixture() as scope:
            source, target = fresh_pair(scope)
            with patch.object(bootstrap, 'ROOT', source), \
                    patch.object(bootstrap, 'launch', side_effect=OSError('synthetic')) as launch, \
                    patch.object(bootstrap.ctypes.windll.user32, 'MessageBoxW'):
                self.assertEqual(bootstrap.main(['--target', str(target)]), 1)
            launch.assert_called_once_with(target)
            updater.verify_release(target)


if __name__ == '__main__':
    unittest.main()
