"""Protected extension copy boundaries using synthetic files only."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

from extension_portability import verify_secure_extension_paths
from browser_policy import verify_proxy_extensions
from local_state import LocalBrowserError
from window_sync import WindowSynchronizer


class ExtensionPortabilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='secure-extension-fixture-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.source = self.base / 'source'
        self.staged = self.base / 'staged'
        self.data = self.base / 'package/data'
        self.final = self.data / 'profiles/independent'
        self.write_json(self.source / 'Default/Preferences', {})

    @staticmethod
    def write_json(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding='utf-8')

    @staticmethod
    def digest(root):
        return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in root.rglob('*') if path.is_file()}

    def register(self, path, state=1, *, name='Secure Preferences', identity='synthetic'):
        self.write_json(self.source / 'Default' / name, {
            'extensions': {'settings': {identity: {'state': state, 'path': path}}},
            'protection': {'macs': {'synthetic': 'preserve-protected-content'}}})

    def extension(self, folder):
        self.write_json(folder / 'manifest.json', {
            'manifest_version': 3, 'name': 'Synthetic extension', 'version': '1.0'})
        (folder / 'fixture.js').write_text('/* synthetic asset, never executed */', encoding='utf-8')

    def verify_copy(self, *, rejected=False):
        before = self.digest(self.source)
        shutil.copytree(self.source, self.staged)
        staged_before = self.digest(self.staged)
        if rejected:
            with self.assertRaises(LocalBrowserError):
                verify_secure_extension_paths(self.staged)
        else:
            verify_secure_extension_paths(self.staged)
        self.assertEqual(before, self.digest(self.source))
        self.assertEqual(staged_before, self.digest(self.staged))
        self.assertFalse(self.final.exists())

    def test_no_protected_preferences_keeps_existing_copy_behavior(self):
        self.verify_copy()

    def test_enabled_relative_extension_and_protection_are_copied_unchanged(self):
        relative = 'a' * 32 + '/1.0_0'
        self.extension(self.source / 'Default/Extensions' / relative)
        self.register(relative)
        self.verify_copy()

    def test_relative_secure_and_ordinary_external_preferences_can_both_copy(self):
        relative = 'a' * 32 + '/1.0_0'
        self.extension(self.source / 'Default/Extensions' / relative)
        self.register(relative)
        external = self.base / 'external'
        self.extension(external)
        self.register(str(external), name='Preferences', identity='ordinary-synthetic')
        self.verify_copy()
        protected_before = (self.staged / 'Default/Secure Preferences').read_bytes()
        synchronizer = WindowSynchronizer.__new__(WindowSynchronizer)
        synchronizer._asset_lock = threading.Lock()
        synchronizer.service = SimpleNamespace(root=self.data, _manifest=self.digest,
            _copy_profile=lambda old, new: shutil.copytree(old, new))
        synchronizer._extensions(self.source, self.staged, self.final)
        preferences = json.loads((self.staged / 'Default/Preferences').read_text('utf-8'))
        copied = Path(preferences['extensions']['settings']['ordinary-synthetic']['path'])
        self.assertTrue(copied.is_relative_to(self.data))
        self.assertEqual(self.digest(external), self.digest(copied))
        self.assertEqual(protected_before, (self.staged / 'Default/Secure Preferences').read_bytes())

    def test_enabled_existing_external_absolute_path_is_rejected(self):
        external = self.base / 'external'
        self.extension(external)
        self.register(str(external))
        self.verify_copy(rejected=True)

    def test_enabled_absolute_profile_internal_path_is_not_portable(self):
        internal = self.source / 'Default/Extensions/synthetic/1.0'
        self.extension(internal)
        self.register(str(internal))
        self.verify_copy(rejected=True)

    def test_ordinary_duplicate_does_not_excuse_protected_absolute_path(self):
        external = self.base / 'external'
        self.extension(external)
        self.register(str(external))
        self.register(str(external), name='Preferences')
        self.verify_copy(rejected=True)

    def test_importer_rejects_before_copying_or_rewriting_ordinary_extensions(self):
        external = self.base / 'external'
        self.extension(external)
        self.register(str(external))
        self.register(str(external), name='Preferences')
        shutil.copytree(self.source, self.staged)
        source_before, staged_before = self.digest(self.source), self.digest(self.staged)
        synchronizer = WindowSynchronizer.__new__(WindowSynchronizer)
        synchronizer.service = SimpleNamespace(root=self.data, _manifest=self.digest,
            _copy_profile=lambda old, new: shutil.copytree(old, new))
        with self.assertRaises(LocalBrowserError):
            synchronizer._extensions(self.source, self.staged, self.final)
        self.assertEqual(source_before, self.digest(self.source))
        self.assertEqual(staged_before, self.digest(self.staged))
        self.assertFalse(self.data.exists())

    def test_disabled_absolute_extension_remains_unchanged(self):
        self.register(str(self.base / 'missing-external'), state=0)
        self.verify_copy()

    def test_enabled_missing_relative_dependency_is_rejected(self):
        self.register('a' * 32 + '/1.0_0', state='1')
        self.verify_copy(rejected=True)

    def test_enabled_relative_folder_without_manifest_is_rejected(self):
        relative = 'a' * 32 + '/1.0_0'
        (self.source / 'Default/Extensions' / relative).mkdir(parents=True)
        self.register(relative)
        self.verify_copy(rejected=True)

    def test_path_is_relative_to_extension_install_directory_not_default(self):
        relative = 'Extensions/' + 'a' * 32 + '/1.0_0'
        self.extension(self.source / 'Default' / relative)
        self.register(relative)
        self.verify_copy(rejected=True)

    def test_native_windows_managed_relative_path_is_preserved(self):
        identity = 'a' * 32
        self.extension(self.source / 'Default/Extensions' / identity / '1.0_0')
        self.register(identity + '\\1.0_0')
        self.verify_copy()

    def test_proxy_guard_reads_managed_manifest_from_extensions_install_root(self):
        relative='a'*32+'/1.0_0'
        manifest=self.source/'Default/Extensions'/relative/'manifest.json'
        for filename in ('Preferences','Secure Preferences'):
            for permission in ('permissions','optional_permissions'):
                with self.subTest(filename=filename,permission=permission):
                    self.write_json(self.source/'Default/Preferences',{})
                    self.write_json(self.source/'Default/Secure Preferences',{})
                    self.write_json(manifest,{'manifest_version':3,'name':'Synthetic','version':'1',permission:['proxy']})
                    self.register(relative,name=filename)
                    before=self.digest(self.source)
                    with self.assertRaises(LocalBrowserError):verify_proxy_extensions(self.source)
                    self.assertEqual(self.digest(self.source),before)

    def test_proxy_guard_accepts_existing_managed_nonproxy_extension(self):
        relative='a'*32+'\\1.0_0'
        self.extension(self.source/'Default/Extensions'/relative)
        self.register(relative)
        before=self.digest(self.source)
        verify_proxy_extensions(self.source)
        self.assertEqual(self.digest(self.source),before)

    def test_proxy_guard_rejects_escaping_enabled_manifest(self):
        for relative in ('../outside','C:outside','\\outside'):
            with self.subTest(relative=relative):
                self.register(relative)
                with self.assertRaises(LocalBrowserError):verify_proxy_extensions(self.source)
        self.register('a'*32+'/missing',state=0)
        verify_proxy_extensions(self.source)

    def test_proxy_guard_preserves_missing_manifest_behavior_for_components(self):
        resource=self.base/'engine/resources/pdf'
        resource.mkdir(parents=True)
        for location in (1,5):
            with self.subTest(location=location):
                entry={'state':1,'location':location,'path':str(resource),
                       'manifest':{'manifest_version':2,'name':'Synthetic embedded component','version':'1','permissions':[]}}
                self.write_json(self.source/'Default/Preferences',{'extensions':{'settings':{'a'*32:entry}}})
                before=self.digest(self.source)
                verify_proxy_extensions(self.source)
                self.assertEqual(self.digest(self.source),before)

    def test_component_location_does_not_skip_inline_or_readable_proxy_permissions(self):
        resource=self.base/'engine/resources/pdf'
        resource.mkdir(parents=True)
        for field in ('manifest','active_permissions','granted_permissions'):
            with self.subTest(field=field):
                entry={'state':1,'location':5,'path':str(resource),field:{'permissions':['proxy']}}
                self.write_json(self.source/'Default/Preferences',{'extensions':{'settings':{'a'*32:entry}}})
                with self.assertRaises(LocalBrowserError):verify_proxy_extensions(self.source)
        self.write_json(resource/'manifest.json',{'manifest_version':3,'name':'Synthetic','version':'1','permissions':['proxy']})
        entry={'state':1,'location':5,'path':str(resource)}
        self.write_json(self.source/'Default/Preferences',{'extensions':{'settings':{'a'*32:entry}}})
        with self.assertRaises(LocalBrowserError):verify_proxy_extensions(self.source)

    def test_escaping_drive_relative_and_rooted_paths_are_rejected(self):
        for raw in ('../external', 'C:external', '\\external', '\\\\synthetic-host\\share'):
            with self.subTest(kind=raw.split(':')[0]):
                self.register(raw)
                with self.assertRaises(LocalBrowserError):
                    verify_secure_extension_paths(self.source)

    def test_malformed_protected_preferences_fail_closed_without_writes(self):
        for value in (None, [], {'extensions': None}, {'extensions': {'settings': []}}):
            with self.subTest(kind=type(value).__name__):
                path = self.source / 'Default/Secure Preferences'
                self.write_json(path, value)
                before = path.read_bytes()
                with self.assertRaises(LocalBrowserError):
                    verify_secure_extension_paths(self.source)
                self.assertEqual(before, path.read_bytes())


if __name__ == '__main__':
    unittest.main(verbosity=2)
