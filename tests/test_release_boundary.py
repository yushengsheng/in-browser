"""The public source export never includes diagnostic screenshots or data."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import build_release


class ReleaseBoundary(unittest.TestCase):
    @staticmethod
    def source_tree(root):
        names=list(build_release.TOP)+['app/main.py','app/ui/app.js','app/ui/index.html',
                'app/ui/style.css','app/ui/README.md','app/resources/electron-main.js',
                'app/resources/crypto.worker.js','app/resources/defaults.json','app/resources/signature-verification-public.der','app/resources/creation-catalog.json','app/resources/pythonnet.config']
        names+=['analysis/'+name for name in build_release.FIXTURES]
        for name in names:
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('synthetic','utf-8')
        (root/'app/resources/pythonnet.config').write_bytes((ROOT/'app/resources/pythonnet.config').read_bytes())
        return names

    def test_only_named_ui_and_resources_are_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            names=self.source_tree(root)
            excluded=['app/data/profile.bin','app/ui/output/playwright/private.png',
                'app/ui/.playwright-cli/session.json','app/resources/unexpected.json','analysis/private/credentials.py']
            for name in excluded:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('synthetic','utf-8')
            files={path.relative_to(root).as_posix() for path in build_release.source_files(root)}
            self.assertTrue(set(names)<=files)
            self.assertFalse(files.intersection(excluded))

    def test_runtime_and_engine_empty_directories_survive_zip_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.source_tree(root)
            runtime=root/'runtime-source'
            (runtime/'python/empty-runtime').mkdir(parents=True)
            for name in build_release.RUNTIME_EXECUTABLES:
                path=runtime/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'synthetic')
            (runtime/'python/python.exe.config').write_text('<configuration />','utf-8')
            (root/'app/engines/148/Dictionaries').mkdir(parents=True)
            (root/'app/engines/148/chrome.exe').write_bytes(b'synthetic')
            (root/'app/data').mkdir()
            (root/'app/data/private.bin').write_bytes(b'private synthetic')
            sources=build_release.source_files(root)
            output=root/'distribution'
            with patch.object(build_release,'ROOT',root),patch.object(build_release,'source_files',return_value=sources),\
                    patch.object(sys,'argv',['build_release.py','--output',str(output),'--runtime-from',str(runtime),'--zip']),\
                    redirect_stdout(io.StringIO()):
                self.assertEqual(build_release.main(),0)
            expected={path.relative_to(output).as_posix()+'/' for path in output.rglob('*') if path.is_dir()}
            with zipfile.ZipFile(output.with_suffix('.zip')) as archive:
                self.assertEqual({item.filename for item in archive.infolist() if item.is_dir()},expected)
                self.assertFalse(any(name.startswith('app/data/') for name in archive.namelist()))
                extracted=root/'extracted';archive.extractall(extracted)
            actual={path.relative_to(extracted).as_posix()+'/' for path in extracted.rglob('*') if path.is_dir()}
            self.assertEqual(actual,expected)
            for name in ('runtime/python/empty-runtime','app/engines/148/Dictionaries'):
                self.assertTrue((extracted/name).is_dir())
                self.assertEqual(list((extracted/name).iterdir()),[])
            for name in ('python.exe.config','pythonw.exe.config'):
                path=extracted/'runtime/python'/name
                self.assertEqual(path.read_bytes(),(root/'app/resources/pythonnet.config').read_bytes())
                setting=ET.parse(path).find('runtime/loadFromRemoteSources')
                self.assertIsNotNone(setting)
                self.assertEqual(setting.get('enabled'),'true')


if __name__=='__main__':unittest.main(verbosity=2)
