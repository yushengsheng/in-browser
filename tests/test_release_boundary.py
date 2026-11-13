"""The public source export never includes diagnostic screenshots or data."""
from contextlib import redirect_stdout
import ast
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import build_release
import check_project
import overlay_layout


class ReleaseBoundary(unittest.TestCase):
    def test_release_clis_find_sibling_modules_in_isolated_python(self):
        for name,option in (('build_release.py','--output'),('release_archive.py','--archive')):
            with self.subTest(tool=name):
                result=subprocess.run([sys.executable,'-I','-B',str(ROOT/'tools'/name),'--help'],
                    cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                self.assertEqual(result.returncode,0,name+' --help failed in isolated Python')
                self.assertIn(option.encode('ascii'),result.stdout)

    def test_default_check_dependencies_are_exported(self):
        files={path.relative_to(ROOT).as_posix() for path in build_release.source_files(ROOT)}
        required={'tools/check_project.py',*(f'analysis/{name}' for name,_style in check_project.FIXTURES)}
        required.update(path.relative_to(ROOT).as_posix() for path in
                        check_project.source_files(ROOT,{'.py','.pyw','.js'}))
        # Inspect the actual default runner without executing its checks.
        tree=ast.parse((ROOT/'tools/check_project.py').read_text('utf-8'))
        main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        for node in ast.walk(main):
            if isinstance(node,ast.Constant) and isinstance(node.value,str):
                name=node.value
                if (name.startswith(('tests/','test_')) and Path(name).suffix in ('.py','.js','.cjs')):
                    required.add(name if name.startswith('tests/') else 'tests/'+name)
        self.assertIn('tests/test_probe_budget.cjs',required)
        self.assertFalse(required-files,sorted(required-files))

    def test_loopback_verifier_dependency_is_exported(self):
        files={path.relative_to(ROOT).as_posix() for path in build_release.source_files(ROOT)}
        self.assertIn('tools/verify_proxy_loopback.py',files)
        self.assertIn('analysis/browser-proxy-boundary-regression.py',files)

    @staticmethod
    def source_tree(root):
        names=list(build_release.TOP)+['app/main.py','tests/test_probe_budget.cjs','app/ui/app.js','app/ui/index.html',
                'app/ui/style.css','app/ui/README.md','app/resources/electron-main.js',
                'app/resources/crypto.worker.js','app/resources/defaults.json','app/resources/signature-verification-public.der','app/resources/creation-catalog.json','app/resources/pythonnet.config']
        names+=['analysis/'+name for name in build_release.FIXTURES]
        for name in names:
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('synthetic','utf-8')
        (root/'VERSION').write_text('0.2.7\n','utf-8')
        (root/'app/resources/pythonnet.config').write_bytes((ROOT/'app/resources/pythonnet.config').read_bytes())
        return names

    def test_only_named_ui_and_resources_are_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            names=self.source_tree(root)
            excluded=['app/data/profile.bin','app/ui/output/playwright/private.png',
                'app/ui/.playwright-cli/session.json','app/resources/unexpected.json','analysis/private/credentials.py',
                'analysis/private/diagnostic.cjs','app/data/private.cjs','tests/__pycache__/private.cjs',
                *overlay_layout.RETIRED_LAUNCHERS]
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
                self.assertFalse(any('/app/data/' in '/' + name for name in archive.namelist()))
                extracted=root/'extracted';archive.extractall(extracted)
            actual={path.relative_to(extracted).as_posix()+'/' for path in extracted.rglob('*') if path.is_dir()}
            self.assertEqual(actual,expected)
            payloads=list((extracted/overlay_layout.PACKAGE_DIRECTORY).iterdir())
            self.assertEqual(len(payloads),1)
            program=payloads[0]
            self.assertEqual((program/'tests/test_probe_budget.cjs').read_text('utf-8'),'synthetic')
            for name in ('runtime/python/empty-runtime','app/engines/148/Dictionaries'):
                self.assertTrue((program/name).is_dir())
                self.assertEqual(list((program/name).iterdir()),[])
            for name in ('python.exe.config','pythonw.exe.config'):
                path=program/'runtime/python'/name
                self.assertEqual(path.read_bytes(),(root/'app/resources/pythonnet.config').read_bytes())
                setting=ET.parse(path).find('runtime/loadFromRemoteSources')
                self.assertIsNotNone(setting)
                self.assertEqual(setting.get('enabled'),'true')


if __name__=='__main__':unittest.main(verbosity=2)
