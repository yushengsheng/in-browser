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
import overlay_layout


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

    def write(self, *, wrapper='', extras=(), changed=None, missing=(), overlay=False,
              marker=None, root_launcher=None, payload_launcher=None):
        files = dict(self.files)
        package_id = '1' * 32
        if overlay:
            for name in archive_tool.OVERLAY_REQUIRED:
                if name not in ('release-manifest.json', 'runtime/manifest.sha256.json'):
                    files.setdefault(name, b'synthetic')
            files['VERSION'] = b'0.2.7\n'
            files[overlay_layout.BOOTSTRAP] = b'# synthetic bootstrap'
            files[overlay_layout.MARKER] = (json.dumps({'format': 1, 'package_id': package_id}).encode()
                                          if marker is None else marker)
            files[overlay_layout.LAUNCHER] = (overlay_layout.launcher_bytes(package_id)
                                            if payload_launcher is None else payload_launcher)
        runtime = {name[len('runtime/'):]: item(value) for name, value in files.items()
                   if name.startswith('runtime/')}
        files['runtime/manifest.sha256.json'] = json.dumps({'algorithm': 'SHA256', 'files': runtime}).encode()
        manifest = {name: item(value) for name, value in files.items()}
        files['release-manifest.json'] = json.dumps({'algorithm': 'SHA256', 'files': manifest}).encode()
        if changed:
            files.update(changed)
        for name in missing:
            del files[name]
        if overlay:
            prefix = overlay_layout.PACKAGE_DIRECTORY + '/' + package_id + '/'
            files = {prefix + name: value for name, value in files.items()}
            files[overlay_layout.LAUNCHER] = (overlay_layout.launcher_bytes(package_id)
                                            if root_launcher is None else root_launcher)
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

    def test_overlay_and_wrapped_overlay_report_verified_program_root(self):
        for wrapper in ('', 'InBrowser-v0.2.7'):
            with self.subTest(wrapper=wrapper):
                self.output = self.root / ('wrapped' if wrapper else 'overlay')
                self.write(overlay=True, wrapper=wrapper)
                report = self.extract()
                program = self.output / overlay_layout.PACKAGE_DIRECTORY / ('1' * 32)
                self.assertEqual(report['layout'], 'overlay')
                self.assertEqual(report['package_id'], '1' * 32)
                self.assertEqual(Path(report['program_root']), program)
                self.assertTrue((program / 'runtime/python/python.exe').is_file())
                self.assertEqual((program / overlay_layout.LAUNCHER).read_bytes(),
                                 (self.output / overlay_layout.LAUNCHER).read_bytes())
                self.assertFalse((self.output / 'app').exists())

    def test_overlay_rejects_incomplete_mismatched_or_extra_payload(self):
        prefix = overlay_layout.PACKAGE_DIRECTORY + '/' + '1' * 32 + '/'
        cases = [
            {'missing': [overlay_layout.MARKER]},
            {'missing': [overlay_layout.BOOTSTRAP]},
            {'missing': ['runtime/python/pythonw.exe']},
            {'missing': ['app/local_browser.pyw']},
            {'missing': ['tools/inplace_update.py']},
            {'changed': {'VERSION': b'0.2.7-preview'}},
            {'root_launcher': b'old launcher'},
            {'payload_launcher': b'different launcher'},
            {'extras': [('app/data/', b'')]},
            {'extras': [('app/stray.py', b'not allowed')]},
            {'extras': [(overlay_layout.PACKAGE_DIRECTORY + '/' + '2' * 32 + '/extra', b'other')]},
            {'extras': [(overlay_layout.PACKAGE_DIRECTORY + '/' + '2' * 32 + '/', b'')]},
            {'extras': [(prefix + 'app/data/', b'')]},
            {'extras': [(prefix + 'app/local-engines/', b'')]},
            {'extras': [(prefix + 'unlisted', b'extra')]},
        ]
        for index, options in enumerate(cases):
            with self.subTest(case=index):
                self.write(overlay=True, **options)
                with self.assertRaises(ValueError):
                    self.extract()
                self.assertFalse(self.output.exists())

    def test_overlay_marker_has_only_exact_format_and_identity(self):
        values = [
            {'format': True, 'package_id': '1' * 32},
            {'format': 2, 'package_id': '1' * 32},
            {'format': 1, 'package_id': '2' * 32},
            {'format': 1, 'package_id': '1' * 32, 'extra': 1},
            {'format': 1}, [],
        ]
        for value in values:
            with self.subTest(marker=value):
                self.write(overlay=True, marker=json.dumps(value).encode())
                with self.assertRaises(ValueError):
                    self.extract()
                self.assertFalse(self.output.exists())
        self.write(overlay=True, marker=b'{"format":1,"format":1,"package_id":"' + b'1' * 32 + b'"}')
        with self.assertRaises(ValueError):
            self.extract()
        self.assertFalse(self.output.exists())

    def test_overlay_metadata_is_in_its_complete_release_manifest(self):
        self.write(overlay=True)
        prefix = overlay_layout.PACKAGE_DIRECTORY + '/' + '1' * 32 + '/'
        with zipfile.ZipFile(self.archive) as zipped:
            release = json.loads(zipped.read(prefix + 'release-manifest.json'))
        del release['files'][overlay_layout.MARKER]
        self.write(overlay=True, changed={'release-manifest.json': json.dumps(release).encode()})
        with self.assertRaises(ValueError):
            self.extract()
        self.assertFalse(self.output.exists())

    def test_payload_cannot_publish_other_packages_or_update_backups(self):
        for name in ('.program-packages/' + '2' * 32 + '/payload',
                     '.program-update-backup-synthetic/saved.bin',
                     '.PROGRAM-UPDATE-BACKUP-other/saved.bin'):
            with self.subTest(name=name):
                self.files[name] = b'not public program content'
                self.write(overlay=True)
                with self.assertRaises(ValueError):
                    self.extract()
                self.assertFalse(self.output.exists())
                del self.files[name]
                raw = json.dumps({'algorithm': 'SHA256', 'files': {name: item(b'content')}}).encode()
                with self.assertRaises(ValueError):
                    archive_tool.manifest(raw)

    def test_overlay_excludes_retired_manual_launchers(self):
        for name in (*overlay_layout.RETIRED_LAUNCHERS, *(name.upper() for name in overlay_layout.RETIRED_LAUNCHERS)):
            with self.subTest(launcher=name):
                self.files[name] = b'legacy launcher'
                self.write(overlay=True)
                with self.assertRaises(ValueError):
                    self.extract()
                self.assertFalse(self.output.exists())
                del self.files[name]

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

    def test_overlay_source_comparison_only_allows_exact_generated_launcher_and_marker(self):
        import build_release
        source_root = self.root / 'source'
        source_root.mkdir()
        sources = []
        for name, raw in (('VERSION', b'0.2.7\n'), (overlay_layout.LAUNCHER, b'legacy launcher'),
                          (overlay_layout.BOOTSTRAP, b'# synthetic bootstrap')):
            path = source_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            sources.append(path)
        package_id = '1' * 32
        program = self.output / overlay_layout.PACKAGE_DIRECTORY / package_id
        program.mkdir(parents=True)
        for source in sources:
            target = program / source.relative_to(source_root)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        launcher = overlay_layout.launcher_bytes(package_id)
        (self.output / overlay_layout.LAUNCHER).write_bytes(launcher)
        (program / overlay_layout.LAUNCHER).write_bytes(launcher)
        (program / overlay_layout.MARKER).write_text(json.dumps({'format': 1, 'package_id': package_id}), 'utf-8')
        with patch.object(build_release, 'source_files', return_value=sources):
            self.assertEqual(archive_tool.verify_source(source_root, self.output), len(sources))
            for relative in ('VERSION', overlay_layout.BOOTSTRAP, overlay_layout.LAUNCHER):
                target = program / relative
                saved = target.read_bytes()
                target.write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    archive_tool.verify_source(source_root, self.output)
                target.write_bytes(saved)
            (program / 'extra.py').write_bytes(b'changed')
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
