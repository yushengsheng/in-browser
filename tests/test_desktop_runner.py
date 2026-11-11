"""Synthetic OS identities only; no browser or runner provisioning."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import verify_desktop_runner as runner


def facts(**changes):
    value = {'major': 10, 'minor': 0, 'build': 26100, 'product_type': 1,
             'native_architecture': 9, 'native_machine': 0x8664,
             'nonzero_session': True, 'active_session': True,
             'station_visible': True, 'default_input_desktop': True}
    value.update(changes)
    return value


class DesktopRunnerTests(unittest.TestCase):
    def test_real_client_builds_match_the_requested_labels(self):
        for expected, build in (('win10', 19045), ('win11', 22000), ('win11', 26100)):
            with self.subTest(expected=expected, build=build):
                self.assertTrue(runner.evaluate(expected, facts(build=build))['success'])
                other = 'win10' if expected == 'win11' else 'win11'
                self.assertFalse(runner.evaluate(other, facts(build=build))['success'])

    def test_server_product_types_rejected_even_with_matching_builds(self):
        for build in (20348, 26100):
            for product_type in (2, 3):
                self.assertFalse(runner.evaluate(
                    'win10' if build < 22000 else 'win11',
                    facts(build=build, product_type=product_type))['success'])

    def test_arm64_and_x86_rejected_including_x64_emulation(self):
        for architecture, machine in ((12, 0xAA64), (9, 0xAA64), (0, 0x14C)):
            self.assertFalse(runner.evaluate('win11', facts(
                native_architecture=architecture, native_machine=machine))['success'])

    def test_service_disconnected_or_locked_desktop_rejected(self):
        for field in ('nonzero_session', 'active_session', 'station_visible', 'default_input_desktop'):
            with self.subTest(field=field):
                self.assertFalse(runner.evaluate('win11', facts(**{field: False}))['success'])

    def test_old_unknown_and_incomplete_os_identity_rejected(self):
        for value in ({}, facts(major=6), facts(build=9600), facts(native_machine=None)):
            self.assertFalse(runner.evaluate('win11', value)['success'])
        self.assertFalse(runner.evaluate('win12', facts())['success'])

    def test_only_safe_os_fields_are_reported(self):
        result = runner.evaluate('win11', facts(account='synthetic-private',
                                               machine_name='synthetic-private',
                                               path='synthetic-private'))
        self.assertNotIn('synthetic-private', json.dumps(result))

    def test_missing_tools_are_failure_and_never_print_command_output(self):
        with patch.object(runner.shutil, 'which', return_value=None):
            result = runner.host_tools()
        self.assertFalse(result['host_git'])
        self.assertFalse(result['host_gh'])
        self.assertFalse(result['host_pwsh'])

    def test_probe_exception_and_missing_host_tool_fail_with_anonymous_report(self):
        with tempfile.TemporaryDirectory(prefix='desktop-runner-test-') as temporary:
            report_path = Path(temporary) / 'report.json'
            for probe, tools in ((RuntimeError('synthetic-private'), {}),
                                 (None, {'host_gh': False})):
                output = io.StringIO()
                with patch.object(runner, 'windows_facts', return_value=facts(), side_effect=probe), \
                        patch.object(runner, 'host_tools', return_value=tools), redirect_stdout(output):
                    status = runner.main(['--expected', 'win11', '--report', str(report_path)])
                self.assertEqual(status, 1)
                self.assertFalse(json.loads(report_path.read_text())['success'])
                self.assertNotIn('synthetic-private', output.getvalue())
                self.assertNotIn(temporary, output.getvalue())

    def test_long_work_directory_fails_before_fixture_execution(self):
        with tempfile.TemporaryDirectory(prefix='desktop-path-') as temporary:
            report_path = Path(temporary) / 'report.json'
            base = Path(Path.cwd().anchor)
            width = 60 - runner.work_path_length(base)
            for suffix, expected in (('x' * width, True), ('x' * width + '\U0001f600', False)):
                with patch.object(runner, 'windows_facts', return_value=facts()), \
                        patch.object(runner, 'host_tools', return_value={}), redirect_stdout(io.StringIO()):
                    status = runner.main(['--expected', 'win11', '--report', str(report_path),
                                          '--work-dir', str(base / suffix)])
                report = json.loads(report_path.read_text())
                self.assertEqual(status == 0, expected)
                self.assertEqual(report['checks']['work_path_within_60_utf16'], expected)

    def test_manual_workflows_require_desktop_preflight_and_unique_workspace(self):
        for name in ('clean-release-validation.yml', 'all-core-release-validation.yml'):
            source = (ROOT / '.github/workflows' / name).read_text(encoding='utf-8')
            self.assertIn('runs-on: [self-hosted, Windows, X64, "${{ matrix.os }}"]', source)
            self.assertIn('os: [win10, win11]', source)
            self.assertNotIn('windows-2022', source)
            self.assertNotIn('windows-2025', source)
            self.assertLess(source.index('tools/verify_desktop_runner.py'),
                            source.index('gh release download'))
            self.assertIn('[Guid]::NewGuid()', source)
            self.assertIn('group: inbrowser-desktop-acceptance', source)
            self.assertIn('cancel-in-progress: false', source)
            self.assertNotIn('--dir $env:RUNNER_TEMP', source)
        self.assertIn('max-parallel: 1', source)


if __name__ == '__main__':
    unittest.main()
