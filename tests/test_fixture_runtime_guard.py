"""Real synthetic engine authentication for post-repair acceptance guards."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tools'), str(ROOT / 'tests')]
import fingerprint_continuity
import verify_portable_fixture as fixture
import test_vendor_runtime_restore as restore_fixtures
from local_state import LocalBrowserError


class FixtureRuntimeGuardTests(unittest.TestCase):
    setUp = restore_fixtures.VendorRestoreTests.setUp

    def original(self):
        record = {'id': fixture.IDENTITY, '_native': {'Resource': {'synthetic': True}},
                  '_runtime': {'core_path': str(self.r1), 'core_sha256': fixture_sha(self.r1),
                               'signature_provider': 'local-v1', 'signature_key_id': self.key_id,
                               'core_major': '148', 'launch_args': [], 'language': ''}}
        record['_continuity'] = {'stable': {'synthetic': True},
                                 'binding': fingerprint_continuity.binding_for(record, self.root / 'app/data')}
        return record

    def guarded(self, original, current, *, controlled=None):
        return fixture._current_core(original, Mock(get=Mock(return_value=current)),
            Mock(profiles={fixture.IDENTITY: controlled or current['_runtime']}), self.root / 'app/data', self.root)

    def test_authenticated_committed_r1_to_r2_keeps_old_binding_and_uses_new_core(self):
        original = self.original()
        current = copy.deepcopy(original)
        r2 = self.store.ensure_current(self.r1, self.key_id, '148')
        current['_runtime']['core_path'] = str(r2)
        self.assertEqual(fingerprint_continuity.binding_for(current, self.root / 'app/data'), original['_continuity']['binding'])
        self.assertEqual(self.guarded(original, current), r2)
        self.assertEqual(fixture._launch_core(str(r2), self.guarded(original, current), self.root), r2)
        self.assertEqual(self.guarded(original, original), self.r1)

    def test_changed_native_baseline_binding_key_or_major_is_rejected(self):
        original = self.original()
        changes = [lambda r: r['_native'].update(changed=True),
                   lambda r: r['_continuity']['stable'].update(changed=True),
                   lambda r: r['_continuity']['stable'].update(synthetic=1),
                   lambda r: r['_continuity']['binding'].update(changed=True),
                   lambda r: r['_runtime'].update(signature_key_id='0' * 64),
                   lambda r: r['_runtime'].update(core_major='150')]
        for change in changes:
            current = copy.deepcopy(original)
            change(current)
            with self.subTest(change=change), self.assertRaises((ValueError, LocalBrowserError)):
                self.guarded(original, current)

    def test_external_core_and_uncommitted_controller_core_are_rejected(self):
        original = self.original()
        external = copy.deepcopy(original)
        external['_runtime']['core_path'] = str(self.root.parent / 'outside/BitBrowser.exe')
        with self.assertRaises((ValueError, OSError, LocalBrowserError)):
            self.guarded(original, external)
        current = copy.deepcopy(original)
        r2 = self.store.ensure_current(self.r1, self.key_id, '148')
        current['_runtime']['core_path'] = str(r2)
        with self.assertRaises(ValueError):
            self.guarded(original, current, controlled=original['_runtime'])

    def test_changed_resource_hash_is_still_rejected_by_full_engine_authentication(self):
        original = self.original()
        resource = self.r1.parent / self.spec['resource_root']['file']
        resource.write_bytes(resource.read_bytes() + b'corrupt')
        with self.assertRaises((ValueError, LocalBrowserError)):
            self.guarded(original, original)


def fixture_sha(path):
    from browser_core import sha256
    return sha256(path)


if __name__ == '__main__':
    unittest.main()
