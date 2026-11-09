"""Synthetic process identity through Windows aliases; no browser is started."""
from contextlib import nullcontext
import ctypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

import browser_processes as processes
import browser_core as core
from local_state import LocalBrowserError


def process(profile, *, helper=False):
    args = ['BitBrowser.exe', '--user-data-dir="' + str(profile) + '"']
    if helper:
        args.append('--type=renderer')
    return SimpleNamespace(pid=101, info={'cmdline': args, 'create_time': 100},
                           oneshot=nullcontext, create_time=lambda: 100,
                           cmdline=lambda: list(args))


class ProcessPathAliases(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='process-path-alias-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.profile = self.root / 'long-profile-directory'
        self.profile.mkdir()
        self.alias = self.root / 'profile-alias'
        if os.name == 'nt':
            reply = subprocess.run(['cmd', '/c', 'mklink', '/J', str(self.alias), str(self.profile)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            self.assertEqual(reply.returncode, 0)
            self.addCleanup(self.alias.rmdir)
        else:
            self.alias.symlink_to(self.profile, target_is_directory=True)
            self.addCleanup(self.alias.unlink)

    def test_literal_alias_cannot_hide_an_occupied_profile(self):
        candidate = process(self.alias)
        self.assertNotEqual(os.path.normcase(os.path.abspath(self.alias)),
                            os.path.normcase(str(self.profile)))
        with patch.object(processes.psutil, 'process_iter', return_value=iter([candidate])) as scan:
            self.assertEqual(processes.profile_processes(self.profile, require_inspectable=True), [candidate])
        scan.assert_called_once()

    def test_snapshot_resolves_alias_once_and_keeps_main_process_identity(self):
        candidate = process(self.alias)
        with patch.object(processes.psutil, 'process_iter', return_value=iter([candidate])) as scan, \
                patch.object(processes.psutil, 'Process', return_value=candidate) as lookup:
            snapshot = processes.ProfileProcessSnapshot()
            self.assertTrue(snapshot.occupied(self.profile))
            self.assertTrue(snapshot.occupied(self.alias))
            self.assertEqual(snapshot.browsers(self.profile), [candidate])
            self.assertFalse(snapshot.uncertain(self.profile))
        scan.assert_called_once()
        lookup.assert_called_once_with(101)

    def test_changed_process_profile_is_uncertain_after_alias_match(self):
        candidate = process(self.alias)
        with patch.object(processes.psutil, 'process_iter', return_value=iter([candidate])) as scan, \
                patch.object(processes.psutil, 'Process', return_value=candidate):
            snapshot = processes.ProfileProcessSnapshot()
            candidate.cmdline = lambda: ['BitBrowser.exe', '--user-data-dir=' + str(self.root / 'other')]
            self.assertEqual(snapshot.browsers(self.profile), [])
            self.assertTrue(snapshot.uncertain(self.profile))
        scan.assert_called_once()

    def test_helper_remains_occupied_without_becoming_a_main_browser(self):
        candidate = process(self.alias, helper=True)
        with patch.object(processes.psutil, 'process_iter', return_value=iter([candidate])):
            snapshot = processes.ProfileProcessSnapshot()
        self.assertTrue(snapshot.occupied(self.profile))
        self.assertEqual(snapshot.browsers(self.profile), [])

    def test_unreadable_browser_stays_uncertain_and_blocks_required_inspection(self):
        candidate = process(self.alias)
        candidate.info.update(cmdline=None, name='BitBrowser.exe')
        with patch.object(processes.psutil, 'process_iter', return_value=iter([candidate])):
            self.assertTrue(processes.ProfileProcessSnapshot().uncertain(self.profile))
        with patch.object(processes.psutil, 'process_iter', return_value=iter([candidate])):
            with self.assertRaises(LocalBrowserError):
                processes.profile_processes(self.profile, require_inspectable=True)

    def test_short_path_spelling_uses_the_same_resolved_identity(self):
        if os.name == 'nt':
            api = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
            api.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
            api.restype = ctypes.c_uint
            output = ctypes.create_unicode_buffer(32768)
            size = api(str(self.profile), output, len(output))
            self.assertTrue(0 < size < len(output))
            short = Path(output.value)
        else:
            short = self.alias
        # Volumes can disable 8.3 names. The junction test still exercises a
        # distinct literal spelling there, without silently skipping the check.
        candidate = process(short)
        with patch.object(processes.psutil, 'process_iter', return_value=iter([candidate])):
            self.assertEqual(processes.profile_processes(self.profile), [candidate])
        self.assert_fingerprint_identity(short)

    def assert_fingerprint_identity(self, folder):
        fingerprint=self.profile/'synthetic-fingerprint.bin'
        fingerprint.write_bytes(b'synthetic-signature')
        executable=self.root/'BitBrowser.exe'
        args=[str(executable),'--user-data-dir='+str(self.profile),
              '--fingerprint-config="'+str(folder/'synthetic-fingerprint.bin')+'"',
              '--remote-debugging-port=9222','--remote-debugging-address=127.0.0.1']
        candidate=SimpleNamespace(oneshot=nullcontext,create_time=lambda:100,cmdline=lambda:args,exe=lambda:str(executable))
        controller=core.BrowserController.__new__(core.BrowserController)
        controller.state={'fixture':{'pid':101,'created':100,'port':9222}}
        controller.profiles={'fixture':{'core_path':str(executable),'profile_path':str(self.profile),
                                        'fingerprint_path':str(fingerprint)}}
        with patch.object(core.psutil,'Process',return_value=candidate),patch.object(controller,'_core_valid',return_value=True):
            self.assertTrue(controller._record_valid('fixture'))

    def test_fingerprint_path_alias_and_windows_case_keep_the_same_identity(self):
        self.assert_fingerprint_identity(self.alias)
        if os.name=='nt':self.assert_fingerprint_identity(Path(str(self.alias).upper()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
