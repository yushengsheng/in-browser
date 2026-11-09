"""Synthetic local-root, envelope and DPAPI checks; never reads real profiles."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import multiprocessing
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import local_signer
from local_signer import LocalSigner, MAGIC, MAX_PAYLOAD_BYTES, MAX_VALIDITY_HOURS, VALIDITY_MS
from local_state import LocalBrowserError

NOW = 1800000000000
PAYLOAD = bytes(range(48))
PREFIX_SIZE = 12 + 256 + 16


def source(payload=PAYLOAD, created=1, expires=2, signature_size=256):
    return MAGIC + struct.pack('>I', signature_size) + b'x' * signature_size + struct.pack('>QQ', created, expires) + payload


def initialize_process(root, output):
    try:
        output.put(('ok', LocalSigner(root).key_id))
    except Exception as exc:
        output.put(('error', type(exc).__name__))


class LocalSignerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='local-signer-test-')
        self.root = Path(self.temporary.name)
        self.signer = LocalSigner(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def issue(self, signer=None, original=None):
        with patch.object(local_signer.time, 'time_ns', return_value=NOW * 1_000_000):
            return (signer or self.signer).resign(source() if original is None else original)

    def test_persistent_dpapi_pair_and_public_only(self):
        public = self.signer.public_der
        self.assertEqual(len(public), 294)
        self.assertEqual(self.signer.key_id, hashlib.sha256(public).hexdigest())
        encrypted = (self.signer.directory / 'private.bin').read_bytes()
        self.assertFalse(encrypted.startswith(b'{'))
        again = LocalSigner(self.root)
        self.assertEqual(again.public_der, public)
        self.assertEqual((again.directory / 'private.bin').read_bytes(), encrypted)
        signed = self.issue()
        with patch.object(local_signer, 'read_encrypted', side_effect=AssertionError('Private key must not be read')):
            verifier = LocalSigner(self.root, load_private=False)
            self.assertTrue(verifier.verify(signed, now_ms=NOW))
            with self.assertRaises(LocalBrowserError):
                verifier.resign(source())

    def test_resign_preserves_payload_and_current_root(self):
        original = source()
        signed = self.issue(original=original)
        self.assertEqual(signed[:12], original[:12])
        self.assertEqual(signed[PREFIX_SIZE:], original[PREFIX_SIZE:])
        self.assertEqual(struct.unpack('>QQ', signed[268:284]), (NOW, NOW + VALIDITY_MS))
        self.assertTrue(self.signer.verify(signed, now_ms=NOW))
        self.assertFalse(self.signer.verify(original, now_ms=NOW))
        other = LocalSigner(self.root / 'other')
        self.assertFalse(other.verify(signed, now_ms=NOW))
        self.assertFalse(self.signer.verify(self.issue(other), now_ms=NOW))
        path = self.root / 'synthetic-envelope.bin'
        path.write_bytes(original)
        before = path.read_bytes()
        with patch.object(local_signer.time, 'time_ns', return_value=NOW * 1_000_000):
            from_path = self.signer.resign(path)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(from_path[PREFIX_SIZE:], PAYLOAD)

    def test_time_boundaries_and_tampering(self):
        signed = self.issue()
        self.assertFalse(self.signer.verify(signed, now_ms=NOW - 1))
        self.assertTrue(self.signer.verify(signed, now_ms=NOW + VALIDITY_MS))
        self.assertFalse(self.signer.verify(signed, now_ms=NOW + VALIDITY_MS + 0.001))
        with patch.object(local_signer.time, 'time_ns', return_value=(NOW + VALIDITY_MS) * 1_000_000 + 1):
            self.assertFalse(self.signer.verify(signed))
        for offset in (12, 275, 283, PREFIX_SIZE):
            modified = bytearray(signed)
            modified[offset] ^= 1
            self.assertFalse(self.signer.verify(modified, now_ms=NOW))
        self.assertFalse(self.signer.verify(signed, now_ms=float('nan')))
        self.assertFalse(self.signer.verify(signed, now_ms='invalid'))

    def test_configurable_finite_lifetime(self):
        signer = LocalSigner(self.root, validity_hours=MAX_VALIDITY_HOURS)
        signed = self.issue(signer)
        times = struct.unpack('>QQ', signed[268:284])
        self.assertEqual(times[1] - times[0], MAX_VALIDITY_HOURS * 3_600_000)
        self.assertTrue(LocalSigner(self.root, load_private=False).verify(signed, now_ms=NOW))
        for value in (True, 0, -1, float('nan'), float('inf'), MAX_VALIDITY_HOURS + 1, 10 ** 1000, '24', 0.00000001):
            with self.assertRaises(LocalBrowserError):
                LocalSigner(self.root, validity_hours=value)

    def test_native_aes_compatibility(self):
        native = {'Resource': {'path': 'synthetic'}, 'DataProtect': {'CipherKey': 'synthetic-only'}, 'value': '测试'}
        aes_key = b'k' * 32
        with patch.object(local_signer.time, 'time_ns', return_value=NOW * 1_000_000):
            signed = self.signer.sign_native(native, aes_key)
        encrypted = signed[PREFIX_SIZE:]
        decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(encrypted[:16])).decryptor()
        raw = decryptor.update(encrypted[16:]) + decryptor.finalize()
        pad = raw[-1]
        self.assertEqual(raw[-pad:], bytes([pad]) * pad)
        self.assertEqual(json.loads(raw[:-pad].decode()), native)
        self.assertTrue(self.signer.verify(signed, now_ms=NOW))
        for invalid in ({}, {'DataProtect': {}}, {'DataProtect': {'CipherKey': 'test'}, 'bad': float('nan')}):
            with self.assertRaises(LocalBrowserError):
                self.signer.sign_native(invalid, aes_key)
        with self.assertRaises(LocalBrowserError):
            self.signer.sign_native(native, b'bad')

    def test_envelope_size_structure_and_clock_limits(self):
        malformed = [b'', b'wrong-header', source(signature_size=128), source(payload=b'x' * 16),
                     source(payload=b'x' * 33), source(created=3, expires=2), source(created=0, expires=2),
                     source(expires=2 ** 64 - 1), source(payload=b'x' * (MAX_PAYLOAD_BYTES + 16))]
        for data in malformed:
            with self.assertRaises(LocalBrowserError):
                self.signer.resign(data)
            self.assertFalse(self.signer.verify(data, now_ms=NOW))
        with patch.object(local_signer.time, 'time_ns', return_value=0):
            with self.assertRaises(LocalBrowserError):
                self.signer.resign(source())

    def test_missing_or_corrupt_private_never_overwritten(self):
        private = self.signer.directory / 'private.bin'
        private.write_bytes(b'synthetic-corruption')
        public = self.signer.public_der
        with self.assertRaises(LocalBrowserError):
            LocalSigner(self.root)
        self.assertEqual(private.read_bytes(), b'synthetic-corruption')
        self.assertEqual(self.signer.public_path.read_bytes(), public)
        private.unlink()
        with self.assertRaises(LocalBrowserError):
            LocalSigner(self.root)
        self.assertFalse(private.exists())
        self.signer.public_path.unlink()
        self.signer.directory.rmdir()
        with self.assertRaises(LocalBrowserError):
            LocalSigner(self.root)
        self.assertFalse(self.signer.directory.exists())

    def test_public_corruption_or_replacement_rejected(self):
        self.signer.public_path.write_bytes(b'invalid')
        with self.assertRaises(LocalBrowserError):
            LocalSigner(self.root, load_private=False)
        replacement = LocalSigner(self.root / 'other')
        self.signer.public_path.write_bytes(replacement.public_der)
        with self.assertRaises(LocalBrowserError):
            LocalSigner(self.root)
        with self.assertRaises(LocalBrowserError):
            LocalSigner(self.root, load_private=False)

    def test_concurrent_threads_use_one_key(self):
        fresh = self.root / 'threads'
        with ThreadPoolExecutor(max_workers=8) as pool:
            identities = list(pool.map(lambda _: LocalSigner(fresh).key_id, range(16)))
        self.assertEqual(len(set(identities)), 1)
        self.assertFalse(list(fresh.glob('.local-signing-*')))

    def test_concurrent_processes_use_one_key(self):
        context = multiprocessing.get_context('spawn')
        output = context.Queue()
        fresh = self.root / 'processes'
        processes = [context.Process(target=initialize_process, args=(fresh, output)) for _ in range(3)]
        try:
            for process in processes:
                process.start()
            results = [output.get(timeout=20) for _ in processes]
            for process in processes:
                process.join(timeout=20)
                self.assertEqual(process.exitcode, 0)
            self.assertTrue(all(status == 'ok' for status, _ in results))
            self.assertEqual(len({identity for _, identity in results}), 1)
            self.assertEqual(LocalSigner(fresh).key_id, results[0][1])
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            output.close()
            output.join_thread()


if __name__ == '__main__':
    unittest.main(verbosity=2)
