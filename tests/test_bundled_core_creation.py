"""Bundled engine selection with fresh synthetic roots and no browser processes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import configuration
import engine_store
import installation
import local_state
import source_database
from bit_source import BitSource
from local_signer import LocalSigner
from local_state import LocalBrowserError, write_encrypted
from portable_paths import encode_archive


class BundledCoreCreationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='bundled-core-fixture-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.app = self.base / 'app'
        self.root = self.app / 'data'
        resources = self.app / 'resources'
        resources.mkdir(parents=True)
        (resources / 'electron-main.js').write_text('/* synthetic public adapter */', encoding='utf-8')
        (resources / 'crypto.worker.js').write_text('function Tn(){return[65,66,67]}', encoding='utf-8')
        (resources / 'defaults.json').write_text(json.dumps({'browserFingerPrint': {}}), encoding='utf-8')
        for target in (configuration, engine_store, installation):
            mocked = patch.object(target, 'APP_ROOT', self.app)
            mocked.start()
            self.addCleanup(mocked.stop)
        environment = patch.dict(os.environ, {'APPDATA': str(self.base / 'roaming')})
        environment.start()
        self.addCleanup(environment.stop)
        dpapi = patch.object(local_state, '_dpapi_protect', side_effect=AssertionError('Unexpected user-bound encryption'))
        dpapi.start()
        self.addCleanup(dpapi.stop)
        installation.initialize_installation(self.root)
        self.configuration = configuration.Configuration(self.root)
        self.signer = LocalSigner(self.root, load_private=False)
        self.deployed = self.app / 'local-engines' / 'synthetic' / 'BitBrowser.exe'
        self.store = Mock()
        self.store.ensure.return_value = self.deployed
        self.store.ensure_current.return_value = self.deployed
        self.store.validate.return_value = self.deployed
        for target, replacement in (
                ('local_engine.LocalEngineStore', self.store),
                ('engine_store.executable_major', '148'),
                ('bit_source.executable_major', '148')):
            mocked = patch(target, return_value=replacement)
            mocked.start()
            self.addCleanup(mocked.stop)
        snapshot = patch.object(source_database, 'snapshot', wraps=source_database.snapshot)
        self.snapshot = snapshot.start()
        self.addCleanup(snapshot.stop)

    def bundled_engine(self):
        folder = self.app / 'engines' / '148'
        folder.mkdir(parents=True)
        executable = folder / 'BitBrowser.exe'
        executable.write_bytes(b'synthetic executable never launched')
        (folder / 'resource.pak').write_bytes(b'synthetic complete resource')
        files = {path.name: {'size': path.stat().st_size,
                            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                 for path in folder.iterdir()}
        (folder / 'manifest.json').write_text(json.dumps({
            'format': 1, 'core_major': '148', 'executable': executable.name, 'files': files}), encoding='utf-8')
        return executable

    def vendor_engine(self):
        vendor = self.configuration.vendor_data
        executable = vendor / 'Chrome-bin' / '148' / 'synthetic-build' / 'BitBrowser.exe'
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b'synthetic vendor executable never launched')
        with sqlite3.connect(vendor / 'db.sqlite') as con:
            con.execute('CREATE TABLE chrome_versions (chrome TEXT, version TEXT)')
            con.execute('INSERT INTO chrome_versions VALUES (?, ?)', ('148', 'synthetic-build'))
        con.close()
        return executable

    def archive_bytes(self):
        return (self.root / 'local-source-archive.bin').read_bytes()

    def test_fresh_install_uses_verified_bundle_without_vendor_database(self):
        source = self.bundled_engine()
        self.assertFalse((self.configuration.vendor_data / 'db.sqlite').exists())
        self.assertEqual(self.configuration.local_core('148'), self.deployed)
        self.snapshot.assert_not_called()
        self.store.ensure.assert_called_once_with('148', source.resolve(), self.signer.public_der)
        self.store.ensure_current.assert_called_once_with(self.deployed, self.signer.key_id, '148')
        self.store.validate.assert_called_once_with(self.deployed, self.signer.key_id, '148')
        self.assertEqual(self.configuration.source_archive()['engines'], {'148': str(self.deployed)})
        self.assertFalse((self.app / 'local-engines').exists())

    def test_present_corrupt_bundle_refuses_vendor_fallback_and_preserves_archive(self):
        source = self.bundled_engine()
        self.vendor_engine()
        resource = source.parent / 'resource.pak'
        resource.write_bytes(b'x' * resource.stat().st_size)
        before = self.archive_bytes()
        with self.assertRaises(LocalBrowserError):
            self.configuration.local_core('148')
        self.snapshot.assert_not_called()
        self.store.ensure.assert_not_called()
        self.assertEqual(self.archive_bytes(), before)

    def test_present_incomplete_bundle_refuses_vendor_fallback(self):
        source = self.bundled_engine()
        self.vendor_engine()
        (source.parent / 'manifest.json').unlink()
        before = self.archive_bytes()
        with self.assertRaises(LocalBrowserError):
            self.configuration.local_core('148')
        self.snapshot.assert_not_called()
        self.store.ensure.assert_not_called()
        self.assertEqual(self.archive_bytes(), before)

    def test_absent_bundle_retains_verified_vendor_inventory_fallback(self):
        source = self.vendor_engine()
        self.assertEqual(self.configuration.local_core('148'), self.deployed)
        self.assertEqual(self.snapshot.call_count, 1)
        self.store.ensure.assert_called_once_with('148', source, self.signer.public_der)
        self.assertEqual(self.configuration.source_archive()['engines'], {'148': str(self.deployed)})

    def test_existing_mapping_keeps_priority_and_does_not_read_broken_bundle(self):
        source = self.bundled_engine()
        (source.parent / 'manifest.json').unlink()
        archive = self.configuration.source_archive()
        archive['engines']['148'] = str(self.deployed)
        write_encrypted(self.root / 'local-source-archive.bin', encode_archive(archive, self.root), root=self.root)
        before = self.archive_bytes()
        self.assertEqual(self.configuration.local_core('148'), self.deployed)
        self.store.ensure_current.assert_called_once_with(str(self.deployed), self.signer.key_id, '148')
        self.store.ensure.assert_not_called()
        self.snapshot.assert_not_called()
        self.assertEqual(self.archive_bytes(), before)

    def test_mismatched_archive_signer_refuses_any_new_deployment(self):
        self.bundled_engine()
        archive = copy.deepcopy(self.configuration.source_archive())
        archive['key_id'] = '0' * 64
        with patch.object(self.configuration, '_archive_data', return_value=archive), self.assertRaises(LocalBrowserError):
            self.configuration.local_core('148')
        self.snapshot.assert_not_called()
        self.store.ensure.assert_not_called()

    def test_bundle_deployment_failure_preserves_archive(self):
        self.bundled_engine()
        before = self.archive_bytes()
        self.store.ensure.side_effect = LocalBrowserError('Synthetic deployment failure')
        with self.assertRaises(LocalBrowserError):
            self.configuration.local_core('148')
        self.snapshot.assert_not_called()
        self.assertEqual(self.archive_bytes(), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
