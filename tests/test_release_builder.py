"""Distribution preflight uses synthetic source and runtime trees only."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_release


class ReleaseBuilderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='release-builder-fixture-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        self.source = self.root / 'README.md'
        self.source.write_text('Synthetic source', encoding='utf-8')
        resources = self.root / 'app/resources'
        resources.mkdir(parents=True)
        (resources / 'pythonnet.config').write_text('<configuration/>', encoding='utf-8')
        engine = self.root / 'app/engines/148'
        engine.mkdir(parents=True)
        (engine / 'synthetic.bin').write_bytes(b'synthetic engine')
        self.runtime = self.base / 'runtime'
        for name in build_release.RUNTIME_EXECUTABLES:
            path = self.runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic executable')
        self.target = self.base / 'InBrowser-v0.2.3-windows-x64'

    def build(self, *arguments):
        output = io.StringIO()
        with patch.object(build_release, 'ROOT', self.root), \
                patch.object(build_release, 'source_files', return_value=[self.source]), \
                patch.object(sys, 'argv', ['build_release.py', '--output', str(self.target), *arguments]), \
                redirect_stdout(output):
            status = build_release.main()
        return status, json.loads(output.getvalue())

    def test_each_missing_runtime_executable_refuses_before_output_creation(self):
        for name in build_release.RUNTIME_EXECUTABLES:
            with self.subTest(executable=name):
                path = self.runtime / name
                path.unlink()
                try:
                    status, report = self.build('--runtime-from', str(self.runtime), '--zip')
                    self.assertEqual(status, 1)
                    self.assertEqual(report, {'success': False, 'error_type': 'ValueError'})
                    self.assertFalse(self.target.exists())
                    self.assertFalse(self.target.with_name(self.target.name + '.zip').exists())
                finally:
                    path.write_bytes(b'synthetic executable')

    def test_complete_runtime_and_versioned_zip_name_are_preserved(self):
        status, report = self.build('--runtime-from', str(self.runtime), '--zip')
        self.assertEqual(status, 0)
        self.assertTrue(report['runtime_included'])
        self.assertFalse(report['contains_user_data'])
        archive_path = self.target.with_name(self.target.name + '.zip')
        self.assertTrue(archive_path.is_file())
        self.assertFalse(self.target.with_suffix('.zip').exists())
        with zipfile.ZipFile(archive_path) as archive:
            names = set(archive.namelist())
        for name in build_release.RUNTIME_EXECUTABLES:
            self.assertIn('runtime/' + name, names)
        self.assertIn('runtime/python/pythonw.exe.config', names)
        self.assertFalse(any(name.startswith('app/data/') for name in names))

    def test_existing_zip_refuses_before_build_and_keeps_original(self):
        archive = self.target.with_name(self.target.name + '.zip')
        archive.write_bytes(b'existing archive')
        status, report = self.build('--runtime-from', str(self.runtime), '--zip')
        self.assertEqual(status, 1)
        self.assertEqual(report, {'success': False, 'error_type': 'ValueError'})
        self.assertFalse(self.target.exists())
        self.assertEqual(archive.read_bytes(), b'existing archive')


if __name__ == '__main__':
    unittest.main()
