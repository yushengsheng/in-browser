"""Temporary synthetic-file tests only; this does not deploy or run a real engine."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'app'))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import engine_store
import local_engine
from local_state import LocalBrowserError


def public_der(key):
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)


class LocalEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vendor = public_der(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        cls.own = public_der(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        cls.own_id = hashlib.sha256(cls.own).hexdigest()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='local-engine-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.executable = self.source / 'BitBrowser.exe'
        self.executable.write_bytes(b'synthetic executable, never run')
        self.chrome = self.source / 'version' / 'chrome.dll'
        self.chrome.parent.mkdir()
        (self.source / 'empty-directory').mkdir()
        self.resource = self.source / 'version' / 'resource.dat'
        self.resource.write_bytes(b'synthetic resources')
        (self.source / 'version' / 'manifest.json').write_text('{"nested":true}', encoding='utf-8')
        (self.source / 'manifest.json').write_text('{"source_only":true}', encoding='utf-8')
        self.specs = copy.deepcopy(local_engine._SUPPORTED)
        for spec in self.specs.values():
            spec['offset'] = 64
        self.major = '124'
        self.write_chrome()
        self.addCleanup(patch.stopall)
        patch.object(local_engine, '_SUPPORTED', self.specs).start()
        patch.object(local_engine, '_VENDOR_DER_SHA256', hashlib.sha256(self.vendor).hexdigest()).start()
        patch.object(engine_store, 'executable_major', side_effect=lambda _path: self.major).start()
        self.store = local_engine.LocalEngineStore(self.root / 'deployed')

    def write_chrome(self, der=None):
        spec = self.specs[self.major]
        data = b'P' * spec['offset'] + local_engine._key_block(der or self.vendor, spec['seeds']) + b'S' * 127
        self.chrome.write_bytes(data)
        spec['sha256'] = hashlib.sha256(data).hexdigest()

    def deploy(self):
        return self.store.ensure(self.major, self.executable, self.own)

    def assert_no_staging(self):
        self.assertFalse(list(self.store.root.glob('*/.install-*')))

    def test_all_decoder_variants_copy_only_public_block(self):
        for major in self.specs:
            with self.subTest(major=major):
                self.major = major
                self.write_chrome()
                source_files, source_dirs = local_engine._inventory(self.source)
                original = self.chrome.read_bytes()
                deployed = self.deploy()
                self.assertEqual(self.store.validate(deployed, self.own_id, major), deployed)
                self.assertEqual(local_engine._inventory(self.source), (source_files, source_dirs))
                self.assertEqual(self.chrome.read_bytes(), original)
                patched = deployed.parent / 'version' / 'chrome.dll'
                result = patched.read_bytes()
                offset = self.specs[major]['offset']
                self.assertEqual(result[:offset], original[:offset])
                self.assertEqual(result[offset + 294:], original[offset + 294:])
                self.assertEqual(local_engine._key_block(result[offset:offset + 294],
                                                        self.specs[major]['seeds']), self.own)
                manifest = json.loads((deployed.parent / 'manifest.json').read_text(encoding='utf-8'))
                self.assertNotIn('manifest.json', manifest['files'])
                self.assertIn('version/manifest.json', manifest['files'])
                self.assertIn('empty-directory', manifest['directories'])
                self.assertEqual(manifest['local_trust']['key_id'], self.own_id)
                self.assertEqual((self.source / 'manifest.json').read_text(encoding='utf-8'), '{"source_only":true}')
                self.assert_no_staging()

    def test_reuse_revalidates_without_copying(self):
        deployed = self.deploy()
        with patch.object(local_engine.shutil, 'copy2', side_effect=AssertionError('Unexpected copy')):
            self.assertEqual(self.deploy(), deployed)
            self.assertEqual(self.store.ensure(self.major, deployed, self.own), deployed)
        self.assert_no_staging()

    def test_unknown_source_hash_refused_before_copy(self):
        self.chrome.write_bytes(self.chrome.read_bytes() + b'unknown build')
        with patch.object(local_engine.shutil, 'copy2') as copier:
            with self.assertRaises(LocalBrowserError):
                self.deploy()
            copier.assert_not_called()
        self.assertFalse(self.store.root.exists())

    def test_wrong_vendor_public_key_refused_before_copy(self):
        self.write_chrome(self.own)
        with patch.object(local_engine.shutil, 'copy2') as copier:
            with self.assertRaises(LocalBrowserError):
                self.deploy()
            copier.assert_not_called()

    def test_unsupported_major_and_bad_public_keys(self):
        wrong_exponent = public_der(rsa.generate_private_key(public_exponent=3, key_size=2048))
        short_rsa = public_der(rsa.generate_private_key(public_exponent=65537, key_size=1024))
        for der in (b'', self.own[:-1], b'?' * 294, short_rsa, wrong_exponent, bytearray(self.own)):
            with self.subTest(length=len(der)):
                with self.assertRaises(LocalBrowserError):
                    self.store.ensure(self.major, self.executable, der)
        with self.assertRaises(LocalBrowserError):
            self.store.ensure('999', self.executable, self.own)
        self.assertFalse(self.store.root.exists())

    def test_disk_limit_refuses_before_copy(self):
        usage = shutil._ntuple_diskusage(1, 1, 0)
        with patch.object(local_engine.shutil, 'disk_usage', return_value=usage), patch.object(local_engine.shutil, 'copy2') as copier:
            with self.assertRaises(LocalBrowserError):
                self.deploy()
            copier.assert_not_called()
        self.assert_no_staging()

    def test_missing_manifest_and_key_or_path_mismatch_refused(self):
        deployed = self.deploy()
        for candidate, key_id, major in ((self.executable, self.own_id, '124'),
                                        (deployed, '0' * 64, '124'),
                                        (deployed, self.own_id, '148')):
            with self.subTest(candidate=candidate.name, major=major):
                with self.assertRaises(LocalBrowserError):
                    self.store.validate(candidate, key_id, major)
        (deployed.parent / 'manifest.json').unlink()
        with self.assertRaises(LocalBrowserError):
            self.deploy()

    def test_corrupt_deployment_refused_and_not_overwritten(self):
        deployed = self.deploy()
        resource = deployed.parent / 'version' / 'resource.dat'
        resource.write_bytes(b'corrupt deployment')
        with patch.object(local_engine.shutil, 'copy2') as copier:
            with self.assertRaises(LocalBrowserError):
                self.deploy()
            copier.assert_not_called()
        self.assertEqual(resource.read_bytes(), b'corrupt deployment')
        self.assert_no_staging()

    def test_forged_manifest_cannot_hide_code_change(self):
        deployed = self.deploy()
        chrome = deployed.parent / 'version' / 'chrome.dll'
        chrome.write_bytes(b'X' + chrome.read_bytes()[1:])
        manifest = deployed.parent / 'manifest.json'
        data = json.loads(manifest.read_text(encoding='utf-8'))
        data['files']['version/chrome.dll']['sha256'] = local_engine._sha256(chrome)
        manifest.write_text(json.dumps(data), encoding='utf-8')
        with self.assertRaises(LocalBrowserError):
            self.store.validate(deployed, self.own_id)

    def test_omitted_or_extra_file_refused(self):
        deployed = self.deploy()
        resource = deployed.parent / 'unlisted.dat'
        resource.write_bytes(b'unlisted resource')
        with self.assertRaises(LocalBrowserError):
            self.store.validate(deployed, self.own_id)
        resource.unlink()
        manifest = deployed.parent / 'manifest.json'
        data = json.loads(manifest.read_text(encoding='utf-8'))
        del data['files']['version/resource.dat']
        manifest.write_text(json.dumps(data), encoding='utf-8')
        with self.assertRaises(LocalBrowserError):
            self.store.validate(deployed, self.own_id)

    def test_copy_failure_cleans_staging(self):
        real_copy = shutil.copy2
        copied = 0

        def fail_after_copy(source, destination, **kwargs):
            nonlocal copied
            result = real_copy(source, destination, **kwargs)
            copied += 1
            if copied == 2:
                raise OSError('Synthetic copy failure')
            return result

        with patch.object(local_engine.shutil, 'copy2', side_effect=fail_after_copy):
            with self.assertRaises(LocalBrowserError):
                self.deploy()
        self.assert_no_staging()
        self.assertFalse(list(self.store.root.glob('*/*/manifest.json')))

    def test_post_publish_failure_removes_only_new_deployment(self):
        with patch.object(self.store, 'validate', side_effect=LocalBrowserError('Synthetic validation failure')):
            with self.assertRaises(LocalBrowserError):
                self.deploy()
        self.assert_no_staging()
        self.assertFalse(list(self.store.root.glob('*/*/manifest.json')))
        self.assertTrue(self.executable.exists())
        self.assertTrue(self.chrome.exists())

    def test_source_change_during_copy_is_refused(self):
        real_copy = shutil.copy2
        changed = False

        def change_source(source, destination, **kwargs):
            nonlocal changed
            result = real_copy(source, destination, **kwargs)
            if not changed:
                changed = True
                self.resource.write_bytes(b'changed while copying')
            return result

        with patch.object(local_engine.shutil, 'copy2', side_effect=change_source):
            with self.assertRaises(LocalBrowserError):
                self.deploy()
        self.assert_no_staging()
        self.assertFalse(list(self.store.root.glob('*/*/manifest.json')))

    def test_source_tree_cannot_contain_destination_root(self):
        store = local_engine.LocalEngineStore(self.source / 'nested-deployment')
        with self.assertRaises(LocalBrowserError):
            store.ensure(self.major, self.executable, self.own)
        self.assertFalse(store.root.exists())

    def test_reparse_attribute_is_refused_without_link_privilege(self):
        original_lstat = Path.lstat

        def source_is_reparse(path):
            result = original_lstat(path)
            if path == self.source:
                return SimpleNamespace(st_mode=result.st_mode, st_file_attributes=0x400)
            return result

        with patch.object(Path, 'lstat', autospec=True, side_effect=source_is_reparse), patch.object(local_engine.shutil, 'copy2') as copier:
            with self.assertRaises(LocalBrowserError):
                self.deploy()
            copier.assert_not_called()
        self.assertFalse(self.store.root.exists())

    def test_symlink_source_is_refused_when_host_allows_symlinks(self):
        link = self.source / 'linked-resource'
        try:
            link.symlink_to(self.resource)
        except OSError:
            self.skipTest('Host does not permit creating synthetic symlinks')
        try:
            with self.assertRaises(LocalBrowserError):
                self.deploy()
        finally:
            link.unlink()
        self.assertFalse(self.store.root.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
