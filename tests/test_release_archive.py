"""Only synthetic ZIP files; no runtime execution or user profile reads."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import release_archive as archive_tool
import unpack_core_fixture as fixture_tool


def item(value):
    return {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}


class ReleaseArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='release-archive-fixture-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / 'synthetic.zip'
        self.output = self.root / 'extracted'
        self.files = {name: b'synthetic' for name in archive_tool.REQUIRED
                      if name not in ('release-manifest.json', 'runtime/manifest.sha256.json')}

    def write(self, *, wrapper='', extras=(), changed=None, missing=()):
        files = dict(self.files)
        runtime = {name[len('runtime/'):]: item(value) for name, value in files.items()
                   if name.startswith('runtime/')}
        files['runtime/manifest.sha256.json'] = json.dumps({'algorithm': 'SHA256', 'files': runtime}).encode()
        manifest = {name: item(value) for name, value in files.items()}
        files['release-manifest.json'] = json.dumps({'algorithm': 'SHA256', 'files': manifest}).encode()
        if changed:
            files.update(changed)
        for name in missing:
            del files[name]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.archive, 'w', compression=zipfile.ZIP_DEFLATED) as zipped:
                if wrapper:
                    zipped.writestr(wrapper + '/', b'')
                for name, value in files.items():
                    zipped.writestr((wrapper + '/' if wrapper else '') + name, value)
                for name, value in extras:
                    zipped.writestr(name, value)
        return archive_tool.digest(self.archive)

    def extract(self, expected=None):
        return archive_tool.extract(self.archive, expected or archive_tool.digest(self.archive), self.output)

    def test_valid_flat_zip_and_empty_directories(self):
        self.write(extras=[('runtime/python/empty/', b'')])
        report = self.extract()
        self.assertTrue(report['success'])
        self.assertTrue(report['runtime_manifest_verified'])
        self.assertFalse(report['contains_user_data'])
        self.assertTrue((self.output / 'runtime/python/empty').is_dir())

    def test_single_wrapper_folder_is_normalized(self):
        self.write(wrapper='InBrowser-v0.2.6')
        self.assertTrue(self.extract()['success'])
        self.assertTrue((self.output / 'VERSION').is_file())

    def test_bad_digest_and_existing_destination_are_not_modified(self):
        self.write()
        with self.assertRaises(ValueError):
            self.extract('0' * 64)
        self.assertFalse(self.output.exists())
        self.output.mkdir()
        keep = self.output / 'keep'
        keep.write_bytes(b'keep')
        with self.assertRaises(ValueError):
            self.extract()
        self.assertEqual(keep.read_bytes(), b'keep')

    def test_windows_path_escapes_and_aliases_rejected(self):
        for name in ('../escape', '/absolute', 'C:/escape', 'app\\escape', 'app/NUL.txt',
                     'app/name.', 'app/name ', 'app/./same', 'app//same', 'app/stream:secret'):
            with self.subTest(name=name):
                self.write(extras=[(name, b'synthetic')])
                with self.assertRaises(ValueError):
                    self.extract()
                self.assertFalse(self.output.exists())

    def test_user_data_local_deployments_and_git_are_rejected_even_empty(self):
        for name in ('app/data/', 'app/data/window.bin', 'app/local-engines/', '.git/config', 'APP/DATA/'):
            with self.subTest(name=name):
                self.write(extras=[(name, b'')])
                with self.assertRaises(ValueError):
                    self.extract()
                self.assertFalse(self.output.exists())

    def test_duplicates_and_case_aliases_rejected(self):
        for name in ('VERSION', 'version', 'runtime/PYTHON/PYTHON.EXE'):
            with self.subTest(name=name):
                self.write(extras=[(name, b'synthetic')])
                with self.assertRaises(ValueError):
                    self.extract()
                self.assertFalse(self.output.exists())

    def test_file_directory_conflict_is_rejected_before_extraction(self):
        self.write(extras=[('VERSION/child', b'synthetic')])
        with self.assertRaises(ValueError):
            self.extract()
        self.assertFalse(self.output.exists())

    def test_unlisted_or_missing_file_is_rejected_before_extraction(self):
        for options in ({'extras': [('extra.bin', b'synthetic')]}, {'missing': ['VERSION']}):
            with self.subTest(options=list(options)):
                self.write(**options)
                with self.assertRaises(ValueError):
                    self.extract()
                self.assertFalse(self.output.exists())

    def test_changed_file_fails_digest_validation(self):
        self.write(changed={'VERSION': b'changed'})
        with self.assertRaises(ValueError):
            self.extract()

    def test_runtime_manifest_must_agree_with_release_manifest(self):
        self.write(changed={'runtime/manifest.sha256.json': b'{"algorithm":"SHA256","files":{}}'})
        with self.assertRaises(ValueError):
            self.extract()
        self.assertFalse(self.output.exists())

    def test_symlink_entry_rejected(self):
        linked = zipfile.ZipInfo('linked')
        linked.create_system = 3
        linked.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.write(extras=[(linked, b'target')])
        with self.assertRaises(ValueError):
            self.extract()
        self.assertFalse(self.output.exists())

    def test_manifest_and_expanded_archive_have_finite_budgets(self):
        self.write()
        for name, limit in (('MAX_MANIFEST', 1), ('MAX_BYTES', 1), ('MAX_FILES', 1)):
            with self.subTest(name=name), patch.object(archive_tool, name, limit):
                with self.assertRaises(ValueError):
                    self.extract()
                self.assertFalse(self.output.exists())

    def test_duplicate_manifest_keys_rejected(self):
        self.write(changed={'release-manifest.json': b'{"algorithm":"SHA256","files":{},"files":{}}'})
        with self.assertRaises(ValueError):
            self.extract()
        self.assertFalse(self.output.exists())

    def test_source_comparison_rejects_unpublished_files_and_changes(self):
        import build_release
        source_root = self.root / 'source'
        source_root.mkdir()
        source = source_root / 'VERSION'
        source.write_bytes(b'synthetic')
        self.output.mkdir()
        target = self.output / 'VERSION'
        target.write_bytes(b'synthetic')
        with patch.object(build_release, 'source_files', return_value=[source]):
            self.assertEqual(archive_tool.verify_source(source_root, self.output), 1)
            extra = self.output / 'unpublished.txt'
            extra.write_bytes(b'synthetic')
            with self.assertRaises(ValueError):
                archive_tool.verify_source(source_root, self.output)
            extra.unlink()
            target.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                archive_tool.verify_source(source_root, self.output)


class CoreFixtureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='core-archive-fixture-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / 'fixture.zip'
        self.package = self.root / 'package'
        (self.package / 'app').mkdir(parents=True)
        (self.package / 'release-manifest.json').write_text('{}', encoding='utf-8')
        self.index = self.root / 'index.json'
        self.entries = [{'core': core, 'asset': 'core-' + core + '.zip', 'sha256': 'a' * 64, 'bytes': 128}
                        for core in fixture_tool.CORE_SPECS]

    def write_index(self, entries=None):
        self.index.write_text(json.dumps({'format': 1, 'release_tag': 'validation-v0.2.6-cores',
                                         'fixtures': self.entries if entries is None else entries}), encoding='utf-8')

    def write_archive(self, *, core='148', extra=None, missing=None):
        files = {'portable-test.json': b'{}', 'vendor-signature.bin': b'synthetic',
                 'all-core-fixture.json': json.dumps({'format': 1, 'core': core, 'synthetic': True}).encode(),
                 'app/data/synthetic.bin': b'synthetic data',
                 'app/local-engines/synthetic/BitBrowser.exe': b'synthetic executable'}
        if extra:
            files.update(extra)
        if missing:
            files.pop(missing)
        with zipfile.ZipFile(self.archive, 'w') as zipped:
            for name, data in files.items():
                zipped.writestr(name, data)
        return {'bytes': self.archive.stat().st_size, 'sha256': archive_tool.digest(self.archive)}

    def test_index_requires_every_supported_core_once(self):
        self.write_index()
        _, entries = fixture_tool.fixture_index(self.index)
        self.assertEqual(set(entries), set(fixture_tool.CORE_SPECS))
        for values in (self.entries[:-1], [self.entries[0]] * len(self.entries)):
            self.write_index(values)
            with self.assertRaises(ValueError):
                fixture_tool.fixture_index(self.index)

    def test_index_rejects_unsafe_asset_and_oversize(self):
        for key, value in (('asset', '../escape.zip'), ('asset', '--option.zip'),
                           ('bytes', 2 * 1024 ** 3), ('sha256', 'no-digest')):
            values = [dict(entry) for entry in self.entries]
            values[0][key] = value
            self.write_index(values)
            with self.assertRaises(ValueError):
                fixture_tool.fixture_index(self.index)

    def test_complete_synthetic_archive_loads_into_only_empty_package(self):
        entry = self.write_archive()
        report = fixture_tool.unpack(self.archive, self.package, '148', entry)
        self.assertTrue(report['success'])
        self.assertTrue(report['source_device_fixture'])
        with self.assertRaises(ValueError):
            fixture_tool.unpack(self.archive, self.package, '148', entry)
        self.assertEqual((self.package / 'app/data/synthetic.bin').read_bytes(), b'synthetic data')

    def test_wrong_core_and_missing_source_marker_are_rejected(self):
        for kwargs in ({'core': '104'}, {'missing': 'vendor-signature.bin'}):
            entry = self.write_archive(**kwargs)
            with self.assertRaises(ValueError):
                fixture_tool.unpack(self.archive, self.package, '148', entry)
            self.assertFalse((self.package / 'app/data').exists())

    def test_fixture_cannot_override_source_runtime_or_escape(self):
        for name in ('app/manager_service.py', 'runtime/python/python.exe', '../escape',
                     'APP/DATA/synthetic.bin', 'app/data/NUL.txt'):
            entry = self.write_archive(extra={name: b'synthetic'})
            with self.assertRaises(ValueError):
                fixture_tool.unpack(self.archive, self.package, '148', entry)
            self.assertFalse((self.package / 'app/data').exists())

    def test_failed_digest_does_not_create_private_tree(self):
        entry = self.write_archive()
        entry['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            fixture_tool.unpack(self.archive, self.package, '148', entry)
        self.assertFalse((self.package / 'app/data').exists())

    def test_package_directory_link_is_rejected_before_resolution(self):
        linked = self.root / 'linked-package'
        if os.name == 'nt':
            result = subprocess.run(['cmd', '/d', '/c', 'mklink', '/J', str(linked), str(self.package)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            self.assertEqual(result.returncode, 0)
        else:
            linked.symlink_to(self.package, target_is_directory=True)
        entry = self.write_archive()
        with self.assertRaises(ValueError):
            fixture_tool.unpack(self.archive, linked, '148', entry)
        self.assertFalse((self.package / 'app/data').exists())


if __name__ == '__main__':
    unittest.main()
