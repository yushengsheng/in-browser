"""Synthetic native envelopes and protection rules for the supported core set."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from core_specs import CORE_SPECS,majors,supports_major
from local_signer import LocalSigner
from local_state import LocalBrowserError
from portable_vault import PortableVault


class CoreCompatibilityTests(unittest.TestCase):
    def test_104_runtime_dictionary_exception_is_empty_and_exact_only(self):
        from local_engine import _runtime_directories
        files={'chrome.dll':{}};expected=['version'];actual=['Dictionaries','version']
        self.assertEqual(_runtime_directories('104',files,actual,expected),expected)
        self.assertEqual(_runtime_directories('112',files,actual,expected),actual)
        self.assertEqual(_runtime_directories('104',{**files,'Dictionaries/extra.bdic':{}},actual,expected),actual)
        nested=['Dictionaries','Dictionaries/nested','version']
        self.assertEqual(_runtime_directories('104',files,nested,expected),nested)

    def test_exact_twenty_one_major_registry_and_unknown_refusal(self):
        expected=('104','112','118','122','124','126','128','130','132','134','136','138','140','142','144','146','148','150','152','154','156')
        self.assertEqual(majors(),expected)
        for major in expected:
            self.assertTrue(supports_major(major));spec=CORE_SPECS[major]
            self.assertRegex(spec['sha256'],'^[0-9a-f]{64}$')
            self.assertGreater(spec['offset'],0);self.assertEqual(len(spec['seeds']),2)
        for major in ('105','125','158','Firefox',None):self.assertFalse(supports_major(major))

    def test_legacy_null_requires_explicit_verified_major_and_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);PortableVault(root).initialize();signer=LocalSigner(root)
            native={'Resource':{'synthetic':True},'DataProtect':None}
            for major in majors():
                with self.subTest(major=major):
                    if int(major)<130:self.assertTrue(signer.verify(signer.sign_native(native,b'x'*32,core_major=major)))
                    else:
                        with self.assertRaises(LocalBrowserError):signer.sign_native(native,b'x'*32,core_major=major)
            for major in (None,'105','158'):
                with self.assertRaises(LocalBrowserError):signer.sign_native(native,b'x'*32,core_major=major)
            for native in ({'DataProtect':None},{'Resource':True,'DataProtect':{}},{'Resource':True,'DataProtect':{'CipherKey':''}}):
                with self.assertRaises(LocalBrowserError):signer.sign_native(native,b'x'*32,core_major='124')

    def test_protected_native_remains_supported_with_unchanged_default_api(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);PortableVault(root).initialize();signer=LocalSigner(root)
            native={'DataProtect':{'CipherKey':'synthetic-only'}}
            self.assertTrue(signer.verify(signer.sign_native(native,b'x'*32)))
            for major in majors():self.assertTrue(signer.verify(signer.sign_native(native,b'x'*32,core_major=major)))


if __name__=='__main__':unittest.main(verbosity=2)
