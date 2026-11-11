"""Synthetic close authority checks; no browser process or profile is opened."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tools')]
import prepare_all_core_fixture as preparation


class FixtureOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.profile = Path('synthetic-profile').resolve()
        self.core = Path('synthetic-core/BitBrowser.exe').resolve()
        self.signature = Path('synthetic-signature.bin').resolve()
        self.fixture = SimpleNamespace(IDENTITY='release-test')
        self.controller = SimpleNamespace(
            profiles={'release-test': {'core_path': str(self.core),
                                      'fingerprint_path': str(self.signature)}},
            state={'release-test': {'pid': 123}}, _adopt=Mock())
        self.closed = Mock()

    def grant(self, *, pid=123):
        return {'controller': self.controller, 'process': SimpleNamespace(pid=pid, poll=lambda: None),
                'profile': self.profile, 'core': self.core, 'signature': self.signature}

    def close(self, grants):
        preparation.close_seed_browser(self.controller, self.closed, grants, self.profile, self.fixture)

    def test_prelaunch_occupied_profile_never_adopts_or_closes_foreign_process(self):
        with patch('browser_processes.profile_processes', return_value=[object()]), self.assertRaises(ValueError):
            self.close([])
        self.closed.assert_not_called()
        self.controller._adopt.assert_not_called()

    def test_prelaunch_failure_with_empty_profile_does_not_close(self):
        with patch('browser_processes.profile_processes', return_value=[]):
            self.close([])
        self.closed.assert_not_called()

    def test_matching_created_process_closes_with_adoption_disabled(self):
        self.closed.side_effect = lambda identity: self.assertFalse(self.controller._adopt(identity))
        self.close([self.grant()])
        self.closed.assert_called_once_with('release-test')

    def test_different_live_pid_never_authorizes_close(self):
        with self.assertRaises(ValueError):
            self.close([self.grant(pid=456)])
        self.closed.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
