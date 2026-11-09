"""Temporary-folder-only vault checks; never reads application data or uses DPAPI."""
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import portable_vault
from portable_vault import (DIRECTORY_NAME, KEY_FILENAME, MAGIC, MARKER_FILENAME,
                            MAX_PLAINTEXT_BYTES, PortableVault, PortableVaultError,
                            is_portable)


def initialize_process(root, output):
    try:
        output.put(('ok', PortableVault(root).initialize().key_id))
    except Exception as exc:
        output.put(('error', type(exc).__name__))


class PortableVaultTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='portable-vault-test-')
        self.root = Path(self.temporary.name) / 'source'

    def tearDown(self):
        self.temporary.cleanup()

    def test_read_only_disabled_state_and_explicit_creation(self):
        vault = PortableVault(self.root)
        self.assertFalse(vault.enabled)
        self.assertIsNone(vault.key_id)
        self.assertFalse(self.root.exists())
        with self.assertRaises(PortableVaultError):
            vault.encrypt(b'no implicit key')
        with self.assertRaises(PortableVaultError):
            PortableVault(self.root, key_required=True)
        self.assertIs(vault.initialize(), vault)
        self.assertTrue(vault.enabled)
        self.assertEqual(len(vault.key_path.read_bytes()), 32)
        self.assertEqual(len(vault.marker_path.read_bytes()), 40)
        previous_key = vault.key_path.read_bytes()
        self.assertEqual(PortableVault(self.root).initialize().key_id, vault.key_id)
        self.assertEqual(vault.key_path.read_bytes(), previous_key)

    def test_copy_folder_unlocks_without_windows_or_dpapi(self):
        vault = PortableVault(self.root).initialize()
        source = '便携状态'.encode()
        envelope = vault.encrypt(source)
        self.assertTrue(is_portable(envelope))
        self.assertTrue(is_portable(bytearray(envelope)))
        self.assertTrue(is_portable(memoryview(envelope)))
        self.assertFalse(is_portable(b'other'))
        self.assertFalse(is_portable(None))
        destination = self.root.parent / 'copied'
        shutil.copytree(self.root, destination)
        copied = PortableVault(destination, key_required=True)
        self.assertEqual(copied.key_id, vault.key_id)
        self.assertEqual(copied.decrypt(envelope), source)
        self.assertEqual(vault.decrypt(copied.encrypt(source)), source)
        self.assertNotEqual(envelope, vault.encrypt(source))

    def test_missing_files_corruption_and_wrong_key_fail_closed(self):
        for filename, replacement in ((KEY_FILENAME, None), (MARKER_FILENAME, None),
                                      (KEY_FILENAME, b'wrong-size'),
                                      (KEY_FILENAME, b'w' * 32),
                                      (MARKER_FILENAME, b'x' * 40),
                                      (MARKER_FILENAME, b'x' * 41)):
            with self.subTest(filename=filename, replacement_size=None if replacement is None else len(replacement)):
                root = self.root / str(len(list(self.root.glob('*'))))
                vault = PortableVault(root).initialize()
                path = vault.directory / filename
                if replacement is None:
                    path.unlink()
                else:
                    path.write_bytes(replacement)
                untouched = {p.name: p.read_bytes() for p in vault.directory.iterdir()}
                for action in (lambda: PortableVault(root),
                               lambda: vault.initialize()):
                    with self.assertRaises(PortableVaultError):
                        action()
                self.assertEqual({p.name: p.read_bytes() for p in vault.directory.iterdir()}, untouched)

    def test_unexpected_vault_directory_is_never_replaced(self):
        vault = PortableVault(self.root)
        vault.directory.mkdir(parents=True)
        with self.assertRaises(PortableVaultError):
            vault.initialize()
        self.assertEqual(list(vault.directory.iterdir()), [])
        vault.directory.rmdir()
        vault.directory.write_bytes(b'not-a-directory')
        with self.assertRaises(PortableVaultError):
            PortableVault(self.root)
        self.assertEqual(vault.directory.read_bytes(), b'not-a-directory')

    def test_loaded_vault_never_recreates_deleted_directory(self):
        vault = PortableVault(self.root).initialize()
        shutil.rmtree(vault.directory)
        with self.assertRaises(PortableVaultError):
            vault.initialize()
        with self.assertRaises(PortableVaultError):
            PortableVault(self.root, key_required=True)
        self.assertFalse(vault.directory.exists())

    def test_other_roots_tampering_and_wrong_aad_are_rejected(self):
        vault = PortableVault(self.root).initialize()
        envelope = vault.encrypt(b'payload')
        other = PortableVault(self.root.parent / 'different').initialize()
        with self.assertRaises(PortableVaultError):
            other.decrypt(envelope)
        for offset in (0, len(MAGIC) - 1, len(MAGIC), len(MAGIC) + 32,
                       len(envelope) - 1):
            altered = bytearray(envelope)
            altered[offset] ^= 1
            with self.assertRaises(PortableVaultError):
                vault.decrypt(altered)
        aad = MAGIC + bytes.fromhex(vault.key_id)
        nonce = b'n' * 12
        wrong_aad = aad + nonce + AESGCM(vault.key_path.read_bytes()).encrypt(nonce, b'payload', b'wrong-aad')
        with self.assertRaises(PortableVaultError):
            vault.decrypt(wrong_aad)

    def test_empty_maximum_oversized_and_invalid_inputs(self):
        vault = PortableVault(self.root).initialize()
        for raw in (b'', b'payload', bytearray(b'payload'), memoryview(b'payload')):
            self.assertEqual(vault.decrypt(vault.encrypt(raw)), bytes(raw))
        maximum = b'x' * MAX_PLAINTEXT_BYTES
        self.assertEqual(vault.decrypt(vault.encrypt(maximum)), maximum)
        for invalid in (b'x' * (MAX_PLAINTEXT_BYTES + 1), 'text', None, 3,
                        memoryview(bytearray(MAX_PLAINTEXT_BYTES + 2)).cast('H')):
            with self.assertRaises(PortableVaultError):
                vault.encrypt(invalid)
        for invalid in (b'', MAGIC, MAGIC + b'x' * (MAX_PLAINTEXT_BYTES + 100), 'text', None):
            with self.assertRaises(PortableVaultError):
                vault.decrypt(invalid)

    def test_failed_initialization_does_not_publish_partial_key(self):
        vault = PortableVault(self.root)
        with patch.object(portable_vault.os, 'rename', side_effect=OSError('synthetic failure')):
            with self.assertRaises(PortableVaultError):
                vault.initialize()
        self.assertFalse(vault.directory.exists())
        self.assertEqual(list(self.root.glob('.portable-vault-stage-*')), [])
        self.assertTrue(vault.initialize().enabled)

    def test_threads_publish_one_root(self):
        with ThreadPoolExecutor(max_workers=8) as executor:
            identities = list(executor.map(lambda _: PortableVault(self.root).initialize().key_id, range(16)))
        self.assertEqual(len(set(identities)), 1)
        self.assertEqual(PortableVault(self.root, key_required=True).key_id, identities[0])
        self.assertEqual(list(self.root.glob('.portable-vault-stage-*')), [])

    def test_processes_publish_one_root(self):
        context = multiprocessing.get_context('spawn')
        output = context.Queue()
        processes = [context.Process(target=initialize_process, args=(str(self.root), output)) for _ in range(4)]
        try:
            for process in processes:
                process.start()
            results = [output.get(timeout=20) for _ in processes]
            for process in processes:
                process.join(timeout=20)
            self.assertTrue(all(process.exitcode == 0 for process in processes))
            self.assertTrue(all(status == 'ok' for status, _ in results))
            self.assertEqual(len({identity for _, identity in results}), 1)
            self.assertEqual(PortableVault(self.root, key_required=True).key_id, results[0][1])
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                process.close()
            output.close()
            output.join_thread()


if __name__ == '__main__':
    unittest.main(verbosity=2)
