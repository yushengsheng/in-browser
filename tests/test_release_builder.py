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
import overlay_layout


class ReleaseBuilderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='release-builder-fixture-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        self.source = self.root / 'README.md'
        self.source.write_text('Synthetic source', encoding='utf-8')
        (self.root / 'VERSION').write_text('0.2.7\n', encoding='utf-8')
        (self.root / overlay_layout.LAUNCHER).write_bytes(b'legacy launcher')
        bootstrap = self.root / overlay_layout.BOOTSTRAP
        bootstrap.parent.mkdir(parents=True)
        bootstrap.write_bytes(b'# synthetic bootstrap')
        self.sources = [self.source, self.root / 'VERSION', self.root / overlay_layout.LAUNCHER, bootstrap]
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
                patch.object(build_release, 'source_files', return_value=self.sources), \
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
        self.assertEqual(report['layout'], 'overlay')
        self.assertEqual(report['version'], '0.2.7')
        prefix = overlay_layout.PACKAGE_DIRECTORY + '/' + report['package_id'] + '/'
        for name in build_release.RUNTIME_EXECUTABLES:
            self.assertIn(prefix + 'runtime/' + name, names)
        self.assertIn(prefix + 'runtime/python/pythonw.exe.config', names)
        self.assertEqual({path.name for path in self.target.iterdir()},
                         {overlay_layout.PACKAGE_DIRECTORY, overlay_layout.LAUNCHER})
        program = self.target / prefix
        launcher = overlay_layout.launcher_bytes(report['package_id'])
        self.assertEqual((self.target / overlay_layout.LAUNCHER).read_bytes(), launcher)
        self.assertEqual((program / overlay_layout.LAUNCHER).read_bytes(), launcher)
        marker = json.loads((program / overlay_layout.MARKER).read_text('utf-8'))
        self.assertEqual(marker, {'format': 1, 'package_id': report['package_id']})
        manifest = json.loads((program / 'release-manifest.json').read_text('utf-8'))['files']
        self.assertIn(overlay_layout.MARKER, manifest)
        self.assertIn(overlay_layout.LAUNCHER, manifest)
        for name in overlay_layout.RETIRED_LAUNCHERS:
            self.assertFalse((program / name).exists())
            self.assertNotIn(name, manifest)
        self.assertFalse(any('/app/data/' in name for name in names))
        self.assertFalse((self.target / 'app').exists())
        self.assertFalse((self.target / 'runtime').exists())

    def test_source_only_build_keeps_flat_layout(self):
        status, report = self.build()
        self.assertEqual(status, 0)
        self.assertEqual(report['layout'], 'flat')
        self.assertNotIn('package_id', report)
        self.assertTrue((self.target / 'release-manifest.json').is_file())
        self.assertFalse((self.target / overlay_layout.PACKAGE_DIRECTORY).exists())
        self.assertEqual((self.target / overlay_layout.LAUNCHER).read_bytes(), b'legacy launcher')
        for name in overlay_layout.RETIRED_LAUNCHERS:
            self.assertNotIn(name, build_release.TOP)
            self.assertFalse((self.target / name).exists())

    def test_repeated_same_version_builds_have_distinct_payload_identities(self):
        status, first = self.build('--runtime-from', str(self.runtime))
        self.assertEqual(status, 0)
        self.target = self.base / 'another-build'
        status, second = self.build('--runtime-from', str(self.runtime))
        self.assertEqual(status, 0)
        self.assertEqual(first['version'], second['version'])
        self.assertNotEqual(first['package_id'], second['package_id'])

    def test_invalid_source_version_is_rejected_before_output_creation(self):
        for value in ('', '../escape', 'v0.2.7', '00.2.7', '0.2', '0.2.7-preview', '0.2.7\nextra'):
            with self.subTest(version=value):
                (self.root / 'VERSION').write_text(value, encoding='utf-8')
                status, report = self.build('--runtime-from', str(self.runtime))
                self.assertEqual(status, 1)
                self.assertEqual(report['error_type'], 'ValueError')
                self.assertFalse(self.target.exists())

    def test_generated_launcher_is_exact_ascii_crlf_and_quoted(self):
        raw = overlay_layout.launcher_bytes('1' * 32)
        text = raw.decode('ascii')
        self.assertNotIn('\n', text.replace('\r\n', ''))
        self.assertIn('setlocal DisableDelayedExpansion\r\n', text)
        self.assertIn('start "" /b "%IB_PACKAGE%\\runtime\\python\\pythonw.exe" -B ', text)
        self.assertIn('"%IB_PACKAGE%\\tools\\portable_bootstrap.py" --target "%~dp0."', text)
        for name in ('runtime\\python\\pythonw.exe', 'tools\\portable_bootstrap.py',
                     'release-manifest.json', overlay_layout.MARKER):
            self.assertIn('if not exist "%IB_PACKAGE%\\' + name + '" goto incomplete', text)
        for bad_id in ('', 'A' * 32, 'a' * 31, 'a' * 33, '../bad', None):
            with self.subTest(identifier=bad_id), self.assertRaises(ValueError):
                overlay_layout.launcher_bytes(bad_id)

    def test_manifest_rejects_package_and_backup_namespaces(self):
        for index, name in enumerate((overlay_layout.PACKAGE_DIRECTORY, '.program-update-backup-synthetic')):
            with self.subTest(name=name):
                directory = self.base / ('manifest-' + str(index))
                reserved = directory / name
                reserved.mkdir(parents=True)
                (reserved / 'file').write_bytes(b'not public')
                with self.assertRaises(ValueError):
                    build_release.write_manifest(directory, 'release-manifest.json')
                self.assertFalse((directory / 'release-manifest.json').exists())

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
