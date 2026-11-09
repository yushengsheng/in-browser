"""Synthetic checks for authenticated transport and archive boundaries."""
import base64
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import unpack_private_acceptance as transport


class PrivateTransport(unittest.TestCase):
    def bundle(self, folder, members):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            for name, content in members:
                archive.writestr(name, content)
        key, nonce = os.urandom(32), os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(transport.HEADER)
        raw = transport.HEADER + nonce + encryptor.update(stream.getvalue()) + encryptor.finalize() + encryptor.tag
        source = folder / 'fixture.enc'
        source.write_bytes(raw)
        return source, hashlib.sha256(raw).hexdigest(), base64.b64encode(key).decode('ascii')

    def test_authenticated_archive_extracts_without_retaining_plain_zip_or_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            target.mkdir()
            source, digest, key = self.bundle(root, [('private-acceptance.json', '{}'),
                ('app/data/profiles/synthetic/storage', 'synthetic')])
            with patch.dict(os.environ, {'IB_PRIVATE_ACCEPTANCE_KEY': key}):
                result = transport.unpack(source, target, digest)
                self.assertNotIn('IB_PRIVATE_ACCEPTANCE_KEY', os.environ)
            self.assertTrue(result['authenticated'])
            self.assertEqual((target/'app/data/profiles/synthetic/storage').read_text(), 'synthetic')
            self.assertFalse(list(root.glob('authenticated-private-*.zip')))

    def test_tampered_authenticated_tag_extracts_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            target.mkdir()
            source, _, key = self.bundle(root, [('private-acceptance.json', '{}')])
            raw = bytearray(source.read_bytes())
            raw[-1] ^= 1
            source.write_bytes(raw)
            with patch.dict(os.environ, {'IB_PRIVATE_ACCEPTANCE_KEY': key}):
                with self.assertRaises(Exception):
                    transport.unpack(source, target, hashlib.sha256(raw).hexdigest())
            self.assertEqual(list(target.iterdir()), [])
            self.assertFalse(list(root.glob('authenticated-private-*.zip')))

    def test_unsafe_or_colliding_members_extract_nothing(self):
        cases = [
            [('private-acceptance.json', '{}'), ('app/data/../../escape', 'x')],
            [('private-acceptance.json', '{}'), ('app/main.py', 'x')],
            [('private-acceptance.json', '{}'), ('app/data/A', 'x'), ('app/data/a', 'x')],
            [('private-acceptance.json', '{}'), ('app/data/C:stream', 'x')],
            [('private-acceptance.json', '{}'), ('app/data/NUL.txt', 'x')],
            [('private-acceptance.json', '{}'), ('app/data/COM1', 'x')],
            [('private-acceptance.json', '{}'), ('app/data/alias. ', 'x')],
            [('private-acceptance.json', '{}'), ('app/data/control\x01', 'x')],
            [('app/data/only', 'x')],
        ]
        for members in cases:
            with self.subTest(case=cases.index(members)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / 'target'
                target.mkdir()
                source, digest, key = self.bundle(root, members)
                with patch.dict(os.environ, {'IB_PRIVATE_ACCEPTANCE_KEY': key}):
                    with self.assertRaises(ValueError):
                        transport.unpack(source, target, digest)
                self.assertEqual(list(target.iterdir()), [])

    def test_existing_destination_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            target.mkdir()
            existing = target / 'private-acceptance.json'
            existing.write_text('keep')
            source, digest, key = self.bundle(root, [('private-acceptance.json', '{}')])
            with patch.dict(os.environ, {'IB_PRIVATE_ACCEPTANCE_KEY': key}):
                with self.assertRaises(ValueError):
                    transport.unpack(source, target, digest)
            self.assertEqual(existing.read_text(), 'keep')

    def test_explicit_empty_directories_preserve_the_profile_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            target.mkdir()
            source, digest, key = self.bundle(root, [('private-acceptance.json', '{}'),
                ('app/data/', ''), ('app/data/profiles/synthetic/empty/', '')])
            with patch.dict(os.environ, {'IB_PRIVATE_ACCEPTANCE_KEY': key}):
                self.assertTrue(transport.unpack(source, target, digest)['success'])
            self.assertTrue((target/'app/data/profiles/synthetic/empty').is_dir())


if __name__ == '__main__':
    unittest.main(verbosity=2)
