"""First-install and public-resource boundaries, using only synthetic folders."""
import copy
import hashlib
import io
import json
from pathlib import Path
import runpy
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import configuration
import installation
import local_state
import profile_model
from bit_source import BitSource
from local_signer import LocalSigner
from local_state import LocalBrowserError, read_encrypted
from portable_vault import PortableVault, is_portable


def tree_digest(root):
    if not root.exists():
        return None
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob('*') if path.is_file()}


class CleanInstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='clean-install-fixture-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.app = self.base / 'app'
        self.root = self.app / 'data'
        resources = self.app / 'resources'
        resources.mkdir(parents=True)
        (resources / 'electron-main.js').write_text('/* synthetic public adapter */', encoding='utf-8')
        (resources / 'crypto.worker.js').write_text('function Tn(){return[65,66,67]}', encoding='utf-8')
        (resources / 'defaults.json').write_text(json.dumps({'browserFingerPrint': {'fixtureField': True}}), encoding='utf-8')
        for target in (installation, configuration, profile_model):
            mocked = patch.object(target, 'APP_ROOT', self.app)
            mocked.start()
            self.addCleanup(mocked.stop)
        environment = patch.dict(configuration.os.environ, {'APPDATA': str(self.base / 'roaming')})
        environment.start()
        self.addCleanup(environment.stop)
        dpapi = patch.object(local_state, '_dpapi_protect', side_effect=AssertionError('No Windows-user encryption allowed'))
        dpapi.start()
        self.addCleanup(dpapi.stop)

    def initialize(self):
        return installation.initialize_installation(self.root)

    def test_missing_and_existing_empty_roots_initialize_without_vendor_access(self):
        for exists in (False, True):
            with self.subTest(empty_root_exists=exists):
                self.root = self.app / ('empty-data' if exists else 'missing-data')
                if exists:
                    self.root.mkdir()
                with patch.object(configuration.Configuration, '_initial_context', side_effect=AssertionError('No vendor context')):
                    self.assertTrue(self.initialize())
                    config = configuration.Configuration(self.root)
                self.assertTrue(config.independent)
                self.assertNotIn('dictionaries', config.context)
                self.assertEqual(config.source_archive()['items'], {})
                self.assertEqual(config.source_archive()['engines'], {})
                self.assertNotIn('profile_root', config.source_archive())
                self.assertEqual(BitSource(config).discover(), [])
                self.assertFalse((self.root / 'resources').exists())
                self.assertFalse((self.root / installation.PENDING).exists())
                self.assertFalse((config.vendor_data / 'db.sqlite').exists())
                vault = PortableVault(self.root, key_required=True)
                signer = LocalSigner(self.root)
                self.assertEqual(config.source_archive()['key_id'], signer.key_id)
                for name in ('portable-mode.bin', 'continuity-mode.bin'):
                    state = read_encrypted(self.root / name, root=self.root)
                    self.assertEqual((state['format'], state['state'], state['key_id']), (1, 'ready', vault.key_id))
                for path in self.root.rglob('*.bin'):
                    self.assertTrue(is_portable(path.read_bytes()))

    def test_new_roots_have_independent_keys_and_never_copy_private_context(self):
        private = self.app / 'data'
        private.mkdir()
        (private / 'configuration-context.bin').write_bytes(b'private-synthetic-do-not-read')
        self.root = self.app / 'fresh'
        self.assertTrue(self.initialize())
        first = PortableVault(self.root, key_required=True).key_id
        first_signer = LocalSigner(self.root, load_private=False).key_id
        self.root = self.app / 'another'
        self.assertTrue(self.initialize())
        self.assertNotEqual(PortableVault(self.root, key_required=True).key_id, first)
        self.assertNotEqual(LocalSigner(self.root, load_private=False).key_id, first_signer)
        self.assertEqual((private / 'configuration-context.bin').read_bytes(), b'private-synthetic-do-not-read')

    def test_second_call_verifies_without_rewriting_any_file(self):
        self.assertTrue(self.initialize())
        before = tree_digest(self.root)
        self.assertFalse(self.initialize())
        self.assertEqual(tree_digest(self.root), before)

    def test_existing_catalog_or_legacy_settings_are_untouched(self):
        for name in ('windows.sqlite', 'settings.bin'):
            with self.subTest(existing=name):
                self.root = self.app / name.replace('.', '-')
                self.root.mkdir()
                (self.root / name).write_bytes(b'existing synthetic state')
                before = tree_digest(self.root)
                with patch.object(PortableVault, 'initialize', side_effect=AssertionError('Must not create a key')):
                    self.assertFalse(self.initialize())
                self.assertEqual(tree_digest(self.root), before)

    def test_unknown_nonempty_or_partial_roots_are_refused_without_changes(self):
        for name in ('resources', '.portable-vault', 'local-signing', 'user-state.bin'):
            with self.subTest(existing=name):
                self.root = self.app / ('partial-' + name.replace('.', '_'))
                self.root.mkdir()
                (self.root / name).write_bytes(b'synthetic')
                before = tree_digest(self.root)
                with self.assertRaises(LocalBrowserError):
                    self.initialize()
                self.assertEqual(tree_digest(self.root), before)

    def test_each_missing_key_or_ready_file_is_refused_without_recreation(self):
        names = ('.portable-vault/.portable-key', '.portable-vault/identity',
                 'local-signing/private.bin', 'local-signing/public.der', 'local-signing.lock',
                 'configuration-context.bin', 'local-source-archive.bin',
                 'independent-mode.bin', 'portable-mode.bin', 'continuity-mode.bin')
        for index, name in enumerate(names):
            with self.subTest(missing=name):
                self.root = self.app / ('missing-state-' + str(index))
                self.assertTrue(self.initialize())
                (self.root / name).unlink()
                before = tree_digest(self.root)
                with self.assertRaises(LocalBrowserError):
                    self.initialize()
                self.assertEqual(tree_digest(self.root), before)

    def test_interruption_keeps_pending_and_retry_does_not_continue(self):
        original = installation.write_encrypted
        calls = 0
        def interrupted(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError('synthetic interruption')
            return original(*args, **kwargs)
        with patch.object(installation, 'write_encrypted', side_effect=interrupted):
            with self.assertRaises(LocalBrowserError):
                self.initialize()
        self.assertTrue((self.root / installation.PENDING).is_file())
        before = tree_digest(self.root)
        with self.assertRaises(LocalBrowserError):
            self.initialize()
        self.assertEqual(tree_digest(self.root), before)

    def test_missing_or_invalid_release_resources_fail_before_state_creation(self):
        for index, name in enumerate(('electron-main.js', 'crypto.worker.js', 'defaults.json')):
            with self.subTest(resource=name):
                self.root = self.app / ('no-resource-' + str(index))
                source = self.app / 'resources' / name
                original = source.read_bytes()
                source.unlink()
                with self.assertRaisesRegex(LocalBrowserError, '发布资源'):
                    self.initialize()
                self.assertFalse(self.root.exists())
                source.write_bytes(original)
        (self.app / 'resources/defaults.json').write_text('[]', encoding='utf-8')
        with self.assertRaisesRegex(LocalBrowserError, '发布资源'):
            self.initialize()
        self.assertFalse(self.root.exists())

    def test_existing_legacy_folder_key_loss_is_not_recreated(self):
        self.assertTrue(self.initialize())
        (self.root / installation.MARKER).unlink()
        (self.root / 'windows.sqlite').write_bytes(b'existing synthetic catalog')
        (self.root / '.portable-vault/.portable-key').unlink()
        before = tree_digest(self.root)
        with self.assertRaises(LocalBrowserError):
            self.initialize()
        self.assertEqual(tree_digest(self.root), before)

    def test_resource_fallback_prefers_existing_data_and_creates_no_copies(self):
        self.assertTrue(self.initialize())
        self.assertEqual(configuration.Configuration(self.root).resources, self.app / 'resources')
        self.assertIn('fixtureField', profile_model.fingerprint_fields())
        self.assertTrue(profile_model.defaults()['fingerprint']['fixtureField'])
        legacy = self.app / 'data/resources'
        legacy.mkdir()
        for name in ('electron-main.js', 'crypto.worker.js', 'defaults.json'):
            (legacy / name).write_bytes((self.app / 'resources' / name).read_bytes())
        (legacy / 'electron-main.js').write_text('/* legacy adapter */', encoding='utf-8')
        (legacy / 'defaults.json').write_text('{"browserFingerPrint":{"legacyField":true}}', encoding='utf-8')
        self.assertEqual(configuration.Configuration(self.root).main, '/* legacy adapter */')
        self.assertIn('legacyField', profile_model.fingerprint_fields())
        fixture = self.app / 'isolated-fixture'
        fixture.mkdir()
        (fixture / 'independent-mode.bin').write_bytes(b'synthetic marker')
        before = tree_digest(fixture)
        self.assertEqual(configuration.Configuration(fixture).resources, legacy)
        self.assertEqual(tree_digest(fixture), before)

    def test_missing_configuration_resources_report_a_fixed_error(self):
        for path in (self.app / 'resources').iterdir():
            path.unlink()
        with self.assertRaisesRegex(LocalBrowserError, '配置适配资源'):
            configuration.Configuration(self.root)

    def test_source_dictionaries_are_read_only_during_explicit_conversion(self):
        self.assertTrue(self.initialize())
        config = configuration.Configuration(self.root)
        config.vendor_data.mkdir(parents=True)
        database = config.vendor_data / 'db.sqlite'
        con = sqlite3.connect(database)
        with con:
            con.execute('CREATE TABLE cache_data_for_server (data_key TEXT,data_value TEXT)')
            con.executemany('INSERT INTO cache_data_for_server VALUES (?,?)',
                            [('Lang', '[{"code":"fixture"}]'), ('WebGLParameters', '{"fixture":{}}')])
        con.close()
        before = tree_digest(config.vendor_data)
        reader = copy.copy(config)
        reader.independent = False
        native = {'Resource': {'fixture': True}, 'DataProtect': None}
        reply = SimpleNamespace(returncode=0, stdout=json.dumps(native).encode())
        bundled_node = self.app.parent / 'runtime/node/node.exe'
        bundled_node.parent.mkdir(parents=True)
        bundled_node.write_bytes(b'synthetic executable, subprocess is mocked')
        info = {'id': '1' * 32, 'browserFingerPrint': {'coreVersion': '104', 'coreProduct': 'chrome', 'fontType': '0'}}
        with patch.object(reader, '_display', return_value={}), \
                patch.object(configuration.subprocess, 'run', return_value=reply) as run, \
                patch('local_source.freeze_source_native', return_value=(native, {})):
            result, signature = reader.build_source(info, sign=False)
        self.assertEqual((result, signature), (native, None))
        payload = json.loads(run.call_args.kwargs['input'])
        self.assertEqual(payload['languages'], [{'code': 'fixture'}])
        self.assertEqual(payload['webgl'], {'fixture': {}})
        self.assertEqual(tree_digest(config.vendor_data), before)
        self.assertNotIn('dictionaries', config.context)
        database.unlink()
        with self.assertRaisesRegex(LocalBrowserError, '来源配置字典'):
            reader._source_dictionaries()

    def test_empty_manager_constructs_without_vendor_or_browser_calls(self):
        from engine_store import EngineStore
        from manager_service import ManagerService
        self.assertTrue(self.initialize())
        config = configuration.Configuration(self.root)
        with patch('manager_service.EngineStore', return_value=EngineStore(self.app / 'engines')), \
                patch('source_database.snapshot', side_effect=AssertionError('No source DB during startup')), \
                patch.object(config, 'vendor', side_effect=AssertionError('No network during startup')):
            service = ManagerService(self.root, configuration=config)
        self.assertEqual(service.store.all(), [])
        self.assertEqual(service.cores(), {})
        self.assertFalse(self.initialize())

    def test_self_check_initializes_before_constructing_manager(self):
        module = runpy.run_path(str(ROOT / 'app/local_browser.pyw'), run_name='clean_install_entry_fixture')
        events = []
        service = SimpleNamespace(store=SimpleNamespace(all=lambda: []), cores=lambda: {},
                                  engines=SimpleNamespace(available=lambda: {}))
        scope = module['main'].__globals__
        with patch.dict(scope, {'initialize_installation': lambda: events.append('initialize'),
                               'ManagerService': lambda: (events.append('manager') or service),
                               'APP_ROOT': self.app}), \
                patch.object(sys, 'argv', ['local_browser.pyw', '--self-check']), \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            module['main']()
        self.assertEqual(events, ['initialize', 'manager'])
        self.assertEqual(json.loads(output.getvalue())['windows'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
