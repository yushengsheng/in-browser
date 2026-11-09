"""Use verified Windows aliases for deep resources, or refuse before launch."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import browser_core
from local_state import LocalBrowserError


class LaunchPaths(unittest.TestCase):
    def test_deep_existing_engine_uses_the_same_file_through_a_short_path(self):
        with tempfile.TemporaryDirectory(prefix='native-launch-path-') as directory:
            folder=Path(directory).resolve()/('long-key-directory-'+'a'*48)/('long-build-directory-'+'b'*48)
            folder.mkdir(parents=True)
            executable=folder/'BitBrowser.exe';executable.write_bytes(b'synthetic')
            name='gen/'+'component-resource-'*3+'test.dat'
            (folder/'manifest.json').write_text(json.dumps({'files':{name:{}}}),encoding='utf-8')
            self.assertGreaterEqual(len(str(folder/name).encode('utf-16-le'))//2,260)
            alias=browser_core._short_executable_path(executable)
            if alias is not None and len(str(alias.parent/name).encode('utf-16-le'))//2<260:
                selected=browser_core._check_launch_paths(executable)
                self.assertNotEqual(str(selected),str(executable))
                self.assertTrue(selected.samefile(executable))
                self.assertTrue(selected.parent.samefile(folder))
                self.assertLess(len(str(selected.parent/name).encode('utf-16-le'))//2,260)
            else:
                with self.assertRaises(LocalBrowserError) as caught:browser_core._check_launch_paths(executable)
                self.assertEqual(caught.exception.code,'engine_path_too_long')

    def test_unavailable_or_still_deep_alias_has_an_actionable_error(self):
        with tempfile.TemporaryDirectory() as directory:
            executable=Path(directory)/'BitBrowser.exe'
            (executable.parent/'manifest.json').write_text(json.dumps({'files':{'nested/'*45+'asset.dat':{}}}),encoding='utf-8')
            for alias in (None,executable):
                with self.subTest(alias=alias is None),patch.object(browser_core,'_short_executable_path',return_value=alias):
                    with self.assertRaises(LocalBrowserError) as caught:browser_core._check_launch_paths(executable)
                    self.assertEqual(caught.exception.code,'engine_path_too_long')

    def test_system_alias_must_identify_the_same_executable_and_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);executable=root/'BitBrowser.exe';executable.write_bytes(b'synthetic')
            other=root/'other';other.mkdir();wrong=other/'BitBrowser.exe';wrong.write_bytes(b'synthetic')
            def convert(_source,output,_length):output.value=str(wrong);return len(output.value)
            library=type('Library',(),{})()
            library.GetShortPathNameW=Mock(side_effect=convert)
            with patch.object(browser_core.ctypes,'WinDLL',return_value=library):
                self.assertIsNone(browser_core._short_executable_path(executable))

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
