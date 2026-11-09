"""Native crash recovery changes one preference and keeps an atomic rollback."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from session_recovery import prepare_session
from local_state import LocalBrowserError


class SessionRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.sessions=self.root/'Default/Sessions';self.sessions.mkdir(parents=True)
        self.storage=self.root/'Default/Session Storage';self.storage.mkdir()
        self.preferences=self.root/'Default/Preferences'
        self.original={'profile':{'exit_type':'Crashed','keep':True},'other':{'preserved':1}}
        self.preferences.write_text(json.dumps(self.original))
        self.session=self.sessions/'Session_123'
        self.session.write_bytes(b'SNSS'+struct.pack('<I',3)+b'\x02\x00\x06x\x01\x00\xff')
        (self.storage/'000001.log').write_bytes(b'synthetic native storage')

    def test_repairs_crash_flag_without_changing_native_session_or_storage(self):
        session=self.session.read_bytes();raw=self.preferences.read_bytes()
        self.assertTrue(prepare_session(self.root))
        expected=json.loads(raw);expected['profile']['exit_type']='Normal'
        self.assertEqual(json.loads(self.preferences.read_bytes()),expected)
        self.assertEqual(self.session.read_bytes(),session)
        with zipfile.ZipFile(self.root/'.local-session-recovery.zip') as archive:
            self.assertEqual(archive.read('Default/Preferences'),raw)
            self.assertEqual(archive.read('Default/Sessions/Session_123'),session)
            self.assertEqual(archive.read('Default/Session Storage/000001.log'),b'synthetic native storage')
        self.assertFalse(prepare_session(self.root))

    def test_restore_disabled_or_clean_exit_is_not_modified(self):
        raw=self.preferences.read_bytes()
        self.assertFalse(prepare_session(self.root,restore=False))
        self.assertEqual(self.preferences.read_bytes(),raw)
        self.original['profile']['exit_type']='Normal'
        self.preferences.write_text(json.dumps(self.original))
        self.assertFalse(prepare_session(self.root))
        self.assertFalse((self.root/'.local-session-recovery.zip').exists())

    def test_incomplete_initial_session_is_not_marked_recoverable(self):
        raw=self.preferences.read_bytes()
        for content in (b'SNSS'+struct.pack('<I',3)+b'\x02\x00\x06x',b'invalid',b'SNSS'+struct.pack('<I',5)):
            self.session.write_bytes(content)
            self.assertFalse(prepare_session(self.root))
            self.assertEqual(self.preferences.read_bytes(),raw)

    def test_backup_failure_keeps_original_preferences_and_files(self):
        raw=self.preferences.read_bytes()
        with patch('session_recovery.zipfile.ZipFile.write',side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):prepare_session(self.root)
        self.assertEqual(self.preferences.read_bytes(),raw)
        self.assertFalse(list(self.root.glob('.session-recovery-*.tmp')))

    def test_preferences_commit_failure_retains_original_and_complete_backup(self):
        import session_recovery
        actual=session_recovery.os.replace
        def replace(source,target):
            if Path(target)==self.preferences:raise OSError('synthetic')
            return actual(source,target)
        raw=self.preferences.read_bytes()
        with patch('session_recovery.os.replace',side_effect=replace):
            with self.assertRaises(OSError):prepare_session(self.root)
        self.assertEqual(self.preferences.read_bytes(),raw)
        with zipfile.ZipFile(self.root/'.local-session-recovery.zip') as archive:
            self.assertEqual(archive.read('Default/Preferences'),raw)
        self.assertFalse(list(self.preferences.parent.glob('.session-preferences-*.tmp')))


if __name__=='__main__':unittest.main(verbosity=2)
