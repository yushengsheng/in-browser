"""Synthetic native trees exercise real deployment/authentication and restoration."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
sys.path.insert(0, str(ROOT / 'tools'))
import verify_portable_fixture
import core_specs
import local_engine as engine
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from local_state import LocalBrowserError

specification = importlib.util.spec_from_file_location('vendor_runtime_restore', ROOT / 'tools/compare_vendor_runtime.py')
comparison = importlib.util.module_from_spec(specification)
specification.loader.exec_module(comparison)


class Fixture:
    _launch_core = staticmethod(verify_portable_fixture._launch_core)

    @staticmethod
    def _inside(path, root, *, exists=True):
        path = Path(path).resolve()
        if not path.is_relative_to(root.resolve()) or path == root.resolve():
            raise ValueError()
        engine._plain_ancestors(path)
        if exists and not path.exists():
            raise ValueError()
        return path

    @staticmethod
    def _json_file(path, root, *, limit):
        path = Fixture._inside(path, root)
        if path.stat().st_size > limit:
            raise ValueError()
        return json.loads(path.read_text(encoding='utf-8'))


def public_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class VendorRestoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='vendor-restore-unit-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.vendor = public_key()
        self.local = public_key()
        source = self.root / 'vendor-source'
        source.mkdir()
        (source / 'BitBrowser.exe').write_bytes(b'synthetic native version fixture; never executable')
        offset, seeds = 31, (12345, 67890)
        chrome = b'c' * offset + engine._key_block(self.vendor, seeds) + b'synthetic untouched suffix'
        (source / 'chrome.dll').write_bytes(chrome)
        resource_folder = source / '148.synthetic'
        resource_folder.mkdir()
        resource = {'file': '148.synthetic/resources.pak', 'id': 1, 'offset': 17, 'length': 373, 'key_offset': 79}
        block = bytearray(resource['length'])
        block[16:24] = struct.pack('>Q', 123456789)
        block[24] = (resource['key_offset'] - 0x39) ^ 0x15
        resource_path = resource_folder / 'resources.pak'
        resource_path.write_bytes(b'r' * resource['offset'] + block + b'synthetic resource suffix')
        self.spec = {'offset': offset, 'seeds': seeds, 'sha256': hashlib.sha256(chrome).hexdigest(), 'resource_root': resource}
        engine._resource_key(source, self.spec, self.vendor)
        resource['sha256'] = engine._sha256(resource_path)
        self.vendor_inventory = engine._inventory(source)
        patches = [patch.dict(core_specs.CORE_SPECS, {'148': self.spec}),
                   patch.object(engine, '_VENDOR_DER_SHA256', hashlib.sha256(self.vendor).hexdigest()),
                   patch('engine_store.executable_major', return_value='148')]
        for replacement in patches:
            replacement.start()
            self.addCleanup(replacement.stop)
        self.store = engine.LocalEngineStore(self.root / 'app/local-engines')
        self.r1 = self.store.ensure('148', source / 'BitBrowser.exe', self.local)
        self.key_id = hashlib.sha256(self.local).hexdigest()

    def record(self, executable):
        return {'_runtime': {'core_path': str(executable), 'signature_key_id': self.key_id}}

    def snapshot(self, folder):
        return {path.relative_to(folder).as_posix(): path.read_bytes() for path in folder.rglob('*') if path.is_file()}

    def test_r1_restores_exact_vendor_tree_and_leaves_deployment_unchanged(self):
        before = self.snapshot(self.r1.parent)
        result, files, directories = comparison._stock_engine(self.record(self.r1), Fixture, self.root)
        self.assertEqual(engine._inventory(result.parent), self.vendor_inventory)
        self.assertEqual((files, directories), self.vendor_inventory)
        self.assertEqual(engine._resource_key(result.parent, self.spec), self.vendor)
        self.assertEqual(self.snapshot(self.r1.parent), before)
        self.assertEqual(self.store.validate(self.r1, self.key_id, '148'), self.r1)

    def test_r2_restores_both_exact_roots_and_all_bytes_without_changing_source(self):
        r2 = self.store.ensure_current(self.r1, self.key_id, '148')
        self.assertTrue(r2.parent.name.endswith('-r2'))
        self.assertEqual(engine._resource_key(r2.parent, self.spec), self.local)
        before = self.snapshot(r2.parent)
        result, files, directories = comparison._stock_engine(self.record(r2), Fixture, self.root)
        self.assertEqual(engine._inventory(result.parent), self.vendor_inventory)
        self.assertEqual((files, directories), self.vendor_inventory)
        self.assertEqual(engine._resource_key(result.parent, self.spec), self.vendor)
        self.assertEqual(self.snapshot(r2.parent), before)
        self.assertEqual(self.store.validate(r2, self.key_id, '148'), r2)

    def test_selected_non148_core_uses_its_exact_spec_and_binding(self):
        with patch.dict(core_specs.CORE_SPECS, {'112': self.spec}), \
                patch('engine_store.executable_major', return_value='112'):
            original = self.store.ensure('112', self.root / 'vendor-source/BitBrowser.exe', self.local)
            current = self.store.ensure_current(original, self.key_id, '112')
            record = self.record(current)
            record['_runtime']['core_major'] = '112'
            before = self.snapshot(current.parent)
            result, files, directories = comparison._stock_engine(record, Fixture, self.root)
            self.assertEqual(engine._inventory(result.parent), self.vendor_inventory)
            self.assertEqual((files, directories), self.vendor_inventory)
            self.assertEqual(self.snapshot(current.parent), before)

    def test_104_empty_runtime_dictionary_matches_production_rule_only(self):
        with patch.dict(core_specs.CORE_SPECS, {'104': self.spec}), \
                patch('engine_store.executable_major', return_value='104'):
            original = self.store.ensure('104', self.root / 'vendor-source/BitBrowser.exe', self.local)
            current = self.store.ensure_current(original, self.key_id, '104')
            (current.parent / 'Dictionaries').mkdir()
            self.assertEqual(self.store.validate(current, self.key_id, '104'), current)
            record = self.record(current)
            record['_runtime']['core_major'] = '104'
            result, files, directories = comparison._stock_engine(record, Fixture, self.root)
            dictionary = result.parent / 'Dictionaries'
            dictionary.mkdir()
            self.assertEqual(comparison._runtime_inventory(result.parent, '104', directories),
                             (files, directories))
            (dictionary / 'unexpected-file').write_bytes(b'synthetic mutation')
            self.assertNotEqual(comparison._runtime_inventory(result.parent, '104', directories),
                                (files, directories))
            (dictionary / 'unexpected-file').unlink()
            (dictionary / 'unexpected-directory').mkdir()
            self.assertNotEqual(comparison._runtime_inventory(result.parent, '104', directories),
                                (files, directories))

    def test_unknown_resource_revision_is_refused_by_real_authentication_before_copy(self):
        manifest_path = self.r1.parent / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['local_trust']['resource_root_revision'] = 2
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        before = self.snapshot(self.r1.parent)
        with self.assertRaises(LocalBrowserError):
            comparison._stock_engine(self.record(self.r1), Fixture, self.root)
        self.assertFalse((self.root / 'analysis/vendor-runtime').exists())
        self.assertEqual(self.snapshot(self.r1.parent), before)

    def test_changed_resource_bytes_and_hash_cannot_excuse_a_nonvendor_resource(self):
        r2 = self.store.ensure_current(self.r1, self.key_id, '148')
        resource_path = r2.parent / self.spec['resource_root']['file']
        current = bytearray(resource_path.read_bytes())
        current[-1] ^= 1
        resource_path.write_bytes(current)
        manifest_path = r2.parent / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['files'][self.spec['resource_root']['file']]['sha256'] = engine._sha256(resource_path)
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        before = self.snapshot(r2.parent)
        with self.assertRaises(LocalBrowserError):
            comparison._stock_engine(self.record(r2), Fixture, self.root)
        self.assertFalse((self.root / 'analysis/vendor-runtime').exists())
        self.assertEqual(self.snapshot(r2.parent), before)

    def test_launch_accepts_canonical_core_and_rejects_same_parent_different_file(self):
        self.assertEqual(comparison._launch_core(str(self.r1), self.r1, Fixture, self.root), self.r1)
        other = self.r1.parent / 'Different.exe'
        other.write_bytes(self.r1.read_bytes())
        with self.assertRaises(ValueError):
            comparison._launch_core(str(other), self.r1, Fixture, self.root)
        with self.assertRaises(ValueError):
            comparison._launch_core(self.r1.name, self.r1, Fixture, self.root)

    def test_launch_rejects_same_file_hardlink_in_different_parent(self):
        other = self.root / 'other-parent'
        other.mkdir()
        alias = other / self.r1.name
        os.link(self.r1, alias)
        self.assertTrue(alias.samefile(self.r1))
        self.assertFalse(alias.parent.samefile(self.r1.parent))
        with self.assertRaises(ValueError):
            comparison._launch_core(str(alias), self.r1, Fixture, self.root)

    @unittest.skipUnless(os.name == 'nt', 'Windows short paths only')
    def test_launch_accepts_a_real_windows_short_path_for_the_authenticated_core(self):
        from browser_core import _short_executable_path
        alias = _short_executable_path(self.r1)
        if alias is None or str(alias).casefold() == str(self.r1).casefold():
            self.skipTest('Filesystem has no distinct short spelling')
        self.assertTrue(alias.samefile(self.r1))
        self.assertTrue(alias.parent.samefile(self.r1.parent))
        self.assertEqual(comparison._launch_core(str(alias), self.r1, Fixture, self.root), self.r1)
        self.assertEqual(self.store.validate(self.r1, self.key_id, '148'), self.r1)


if __name__ == '__main__':
    unittest.main()
