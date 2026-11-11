"""Synthetic files only; cached presentation must never replace launch checks."""
from pathlib import Path
import os
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

from local_state import LocalBrowserError
import signature_lifetime as lifetime
import signature_status as display
from manager_service import ManagerService
from portable_vault import PortableVault
from window_store import WindowStore


class SignatureStatusTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='signature-status-synthetic-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / 'signature.bin'
        self.write(self.path)
        self.cache = display.SignatureStatusCache()

    @staticmethod
    def write(path, *, created=1000, expires=5000):
        path.write_bytes(b'#BT@' + bytes(4) + struct.pack('>I', 64) + bytes(64) +
                         struct.pack('>QQ', created, expires) + bytes(32))

    def test_cache_hits_recompute_expiry_and_clock_rollback_without_reading(self):
        with patch.object(display, 'signature_lifetime', wraps=lifetime.signature_lifetime) as read:
            for now, expected in ((4999, 'active'), (5000, 'active'), (5001, 'expired'), (2000, 'active')):
                self.assertEqual(self.cache.get(self.path, now_ms=now)['status'], expected)
            self.assertEqual(read.call_count, 1)
        with patch.object(display.time, 'time_ns', return_value=5000000001):
            self.assertEqual(self.cache.get(self.path)['status'], 'expired')

    def test_cached_result_cannot_be_mutated_by_caller(self):
        result = self.cache.get(self.path, now_ms=2000)
        original = dict(result)
        result.update(expires_at='changed', status='unknown')
        self.assertEqual(self.cache.get(self.path, now_ms=2000), original)

    def test_renewal_size_change_missing_and_recreation_are_seen(self):
        self.cache.get(self.path, now_ms=2000)
        self.write(self.path, expires=9000)
        value = self.path.stat()
        os.utime(self.path, ns=(value.st_atime_ns, value.st_mtime_ns + 1000000))
        self.assertEqual(self.cache.get(self.path, now_ms=7000)['status'], 'active')
        self.path.write_bytes(b'broken')
        self.assertEqual(self.cache.get(self.path), {'status': 'unknown'})
        self.path.unlink()
        self.assertEqual(self.cache.get(self.path), {'status': 'missing'})
        self.write(self.path)
        self.assertEqual(self.cache.get(self.path, now_ms=2000)['status'], 'active')

    def test_replaced_file_with_preserved_mtime_is_not_a_hit(self):
        self.cache.get(self.path, now_ms=2000)
        old = self.path.stat()
        replacement = self.root / 'replacement.bin'
        self.write(replacement, expires=1500)
        os.utime(replacement, ns=(old.st_atime_ns, old.st_mtime_ns))
        os.replace(replacement, self.path)
        self.assertEqual(self.cache.get(self.path, now_ms=2000)['status'], 'expired')

    def test_read_failure_and_unstable_file_never_return_old_active(self):
        self.cache.get(self.path, now_ms=2000)
        with patch.object(self.cache, '_identity', side_effect=PermissionError()):
            self.assertEqual(self.cache.get(self.path), {'status': 'unknown'})
        self.assertFalse(self.cache._entries)
        with patch.object(self.cache, '_identity', side_effect=[('before',), ('after',)]):
            self.assertEqual(self.cache.get(self.path), {'status': 'unknown'})
        self.assertFalse(self.cache._entries)

    def test_age_bounds_rechecks_even_when_metadata_is_unchanged(self):
        with patch.object(display.time, 'monotonic', return_value=100), \
                patch.object(display, 'signature_lifetime', wraps=lifetime.signature_lifetime) as read:
            self.cache.get(self.path, now_ms=2000)
            with patch.object(display.time, 'monotonic', return_value=129):
                self.cache.get(self.path, now_ms=2000)
            self.assertEqual(read.call_count, 1)
            with patch.object(display.time, 'monotonic', return_value=130):
                self.cache.get(self.path, now_ms=2000)
            self.assertEqual(read.call_count, 2)
            with patch.object(display.time, 'monotonic', return_value=90):
                self.cache.get(self.path, now_ms=2000)
            self.assertEqual(read.call_count, 3)

    def test_cache_is_bounded_and_removed_paths_are_evicted(self):
        cache = display.SignatureStatusCache(limit=2)
        paths = [self.root / ('signature-' + str(index)) for index in range(4)]
        for path in paths:
            self.write(path)
            cache.get(path, now_ms=2000)
        self.assertEqual(len(cache._entries), 2)
        cache.retain(paths[:1])
        self.assertEqual(list(cache._entries), [str(paths[0])])
        cache.retain([])
        self.assertFalse(cache._entries)

    def test_full_scans_above_capacity_keep_hits_on_subsequent_polls(self):
        cache = display.SignatureStatusCache(limit=2)
        paths = [self.root / ('scan-' + str(index)) for index in range(3)]
        for path in paths:
            self.write(path)
        with patch.object(display, 'signature_lifetime', wraps=lifetime.signature_lifetime) as read:
            for path in paths:
                cache.get(path, now_ms=2000)
            self.assertEqual(read.call_count, 3)
            for _ in range(3):
                read.reset_mock()
                cache.retain(paths)
                for path in paths:
                    cache.get(path, now_ms=2000)
                self.assertEqual(read.call_count, 1)
            cache.retain(paths[1:])
            cache.get(paths[2], now_ms=2000)
            self.assertEqual(set(cache._entries), {str(path) for path in paths[1:]})

    def test_invalid_envelopes_do_not_poison_cache_or_change_parser_contract(self):
        for content in (b'', b'broken', b'#BT@' + bytes(4) + struct.pack('>I', 9000)):
            self.path.write_bytes(content)
            with patch.object(display, 'signature_lifetime', wraps=lifetime.signature_lifetime) as read:
                self.assertEqual(self.cache.get(self.path), lifetime.signature_lifetime(self.path))
                self.cache.get(self.path)
                self.assertEqual(read.call_count, 2)
                self.assertFalse(self.cache._entries)

    def test_launch_validation_bypasses_display_cache_and_rejects_bad_signature(self):
        self.write(self.path, created=0, expires=4102444800000)
        self.assertEqual(self.cache.get(self.path)['status'], 'active')
        with patch.object(lifetime, 'signature_lifetime', wraps=lifetime.signature_lifetime) as read:
            with self.assertRaises(LocalBrowserError):
                lifetime.require_current_signature(self.path, core_major='148')
            self.assertGreaterEqual(read.call_count, 1)


class ManagerStatusIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='manager-status-synthetic-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        PortableVault(self.root).initialize()
        self.store = WindowStore(None, self.root)
        self.records = []
        for index in range(3):
            path = self.root / ('signature-' + str(index))
            if index != 2:
                SignatureStatusTests.write(path, created=0, expires=4102444800000 if index == 0 else 1000)
            record = {'id':str(index), 'seq':index + 1, 'created_at':'synthetic',
                      'config_status':'ready', '_runtime':{'fingerprint_path':str(path)}}
            self.store.put(record)
            self.records.append(record)
        self.service = ManagerService.__new__(ManagerService)
        self.service.root = self.root
        self.service.store = self.store
        self.service.controller = SimpleNamespace(statuses=Mock(return_value={
            '0':'已打开', '1':'正在关闭', '2':'启动未完成'}))
        self.service._signature_status = display.SignatureStatusCache()

    def test_public_response_and_pending_precedence_survive_warm_caches(self):
        with patch('profile_delete.get_pending_ids', return_value={'0'}), \
                patch.object(self.store, 'all', side_effect=AssertionError('Full records are unnecessary')):
            first = self.service.statuses()
            rows = first['profiles']
            self.assertEqual([row['status'] for row in rows], ['open','closing','opening'])
            self.assertEqual([row['is_running'] for row in rows], [True,False,False])
            self.assertEqual([row['signature_status'] for row in rows], ['active','expired','missing'])
            self.assertEqual([row['config_status'] for row in rows], ['delete_pending','expired','ready'])
            self.assertTrue(rows[0]['delete_pending'])
            self.assertNotIn('delete_pending',rows[1])
            self.assertTrue(all(row['signature_provider']=='vendor' for row in rows))
            self.assertTrue(all(row['last_opened_at'] is None for row in rows))
            self.assertTrue(all('_runtime' not in row for row in rows))
            with patch.object(self.store, 'unpack', wraps=self.store.unpack) as unpack, \
                    patch.object(display, 'signature_lifetime', wraps=lifetime.signature_lifetime) as read:
                self.assertEqual(self.service.statuses(), first)
                self.assertEqual(unpack.call_count, 0)
                self.assertEqual(read.call_count, 0)

    def test_save_renewal_and_delete_are_visible_next_poll(self):
        with patch('profile_delete.get_pending_ids', return_value=set()):
            self.service.statuses()
            record = self.records[1]
            record['last_opened_at'] = 'later'
            renewed = self.root / 'renewed-signature'
            SignatureStatusTests.write(renewed, created=0, expires=4102444800000)
            record['_runtime']['fingerprint_path'] = str(renewed)
            self.store.put(record)
            with self.store.connect() as connection:
                connection.execute('DELETE FROM profiles WHERE id=?', ('0',))
            rows = self.service.statuses()['profiles']
            self.assertEqual([row['id'] for row in rows], ['1','2'])
            self.assertEqual(rows[0]['last_opened_at'], 'later')
            self.assertEqual(rows[0]['signature_status'], 'active')
            self.assertEqual(rows[0]['config_status'], 'ready')
            self.assertEqual(set(self.service._signature_status._entries), {str(renewed)})

    def test_missing_vault_never_returns_cached_status(self):
        with patch('profile_delete.get_pending_ids', return_value=set()):
            self.service.statuses()
            PortableVault(self.root).key_path.unlink()
            with self.assertRaises(LocalBrowserError):
                self.service.statuses()


if __name__ == '__main__':
    unittest.main()
