"""Reject deep Chromium resources before creating an unusable process."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import browser_core
from local_state import LocalBrowserError


class LaunchPaths(unittest.TestCase):
    def test_short_executable_with_long_resource_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            executable=Path(directory)/'BitBrowser.exe'
            long_name='assets/'+'nested/'*32+'resource.dat'
            self.assertLess(len(str(executable)),260)
            (executable.parent/'manifest.json').write_text(json.dumps({'files':{long_name:{}}}),'utf-8')
            with patch.object(browser_core.os,'name','nt'):
                with self.assertRaises(LocalBrowserError):browser_core._check_launch_paths(executable)

    def test_short_engine_and_legacy_executable_are_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            executable=Path(directory)/'BitBrowser.exe'
            with patch.object(browser_core.os,'name','nt'):
                browser_core._check_launch_paths(executable)
                (executable.parent/'manifest.json').write_text(json.dumps({'files':{'148/chrome.dll':{}}}),'utf-8')
                browser_core._check_launch_paths(executable)

    def test_non_bmp_characters_count_as_two_windows_path_units(self):
        with tempfile.TemporaryDirectory() as directory:
            executable=Path(directory)/'BitBrowser.exe'
            resource='assets/'+'\U0001f642'*100+'/'+'x'*40+'.dat'
            self.assertLess(len(str(executable.parent/resource)),260)
            self.assertGreaterEqual(len(str(executable.parent/resource).encode('utf-16-le'))//2,260)
            (executable.parent/'manifest.json').write_text(json.dumps({'files':{resource:{}}}),'utf-8')
            with patch.object(browser_core.os,'name','nt'):
                with self.assertRaises(LocalBrowserError):browser_core._check_launch_paths(executable)


if __name__=='__main__':unittest.main(verbosity=2)
