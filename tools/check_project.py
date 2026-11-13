"""Offline project checks. Only the reviewed fixture allowlist is executable."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 120
MAX_LOG_BYTES = 1024 * 1024
FIXTURES = (
    ('portable-vault-tests.py', 'unittest'),
    ('portable-browser-tests.py', 'unittest'),
    ('portable-state-tests.py', 'json'),
    ('signature-guard-tests.py', 'json'),
    ('local-engine-tests.py', 'unittest'),
    ('local-signer-tests.py', 'unittest'),
    ('sync-source-tests.py', 'sync'),
    ('fingerprint-continuity-tests.py', 'unittest'),
    ('conservative-policy-tests.py', 'json'),
    ('proxy-runtime-protocol-tests.py', 'json'),
)


def python_executable(root=ROOT):
    bundled = root / 'runtime' / 'python' / 'python.exe'
    return str(bundled if bundled.is_file() else Path(sys.executable))


def node_executable(root=ROOT):
    for candidate in (root / 'runtime/node/node.exe', root / 'runtime/node.exe'):
        if candidate.is_file():
            return str(candidate)
    return shutil.which('node')


def child_environment(temporary, python, node=None):
    """Exclude user Python, proxy, account and shell configuration."""
    env = {key: os.environ[key] for key in ('SystemRoot', 'WINDIR', 'COMSPEC') if key in os.environ}
    temporary = Path(temporary)
    for key, name in (('TEMP', 'temp'), ('TMP', 'temp'), ('APPDATA', 'roaming'),
                      ('LOCALAPPDATA', 'local'), ('USERPROFILE', 'user'), ('HOME', 'user')):
        directory = temporary / name
        directory.mkdir(exist_ok=True)
        env[key] = str(directory)
    path = [str(Path(python).parent)]
    if node:
        path.append(str(Path(node).parent))
    system = os.environ.get('SystemRoot')
    if system:
        path.extend((str(Path(system) / 'System32'), system))
    env.update(PATH=os.pathsep.join(dict.fromkeys(path)), PYTHONNOUSERSITE='1',
               PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1', PYTHONIOENCODING='utf-8')
    return env


def redact(text, root=ROOT):
    """Scrub locally before any captured child output enters a report."""
    text = str(text).replace(str(root), '<project>')
    text = re.sub(r'(?i)https?://[^\s\x22\x27<>]+', '<url>', text)
    text = re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '<account>', text)
    text = re.sub(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', '<ip>', text)
    text = re.sub(r'(?i)(?<!\w)(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*(?:%\w+)?', '<ip>', text)
    text = re.sub(r'(?i)[a-z]:[\\/][^\r\n\x22\x27<>]*', '<path>', text)
    text = re.sub(r'(?<!\w)/(?:home|Users|tmp|private|var)/[^\r\n\x22\x27<>]*', '<path>', text)
    text = re.sub(r'\b[A-Za-z0-9+/=_-]{40,}\b', '<opaque-value>', text)
    sensitive = re.compile(r'(?i)password|passwd|username|user_name|account|authorization|'
                           r'api[_-]?key|secret|token|cipherkey|private[_ -]?key')
    return '\n'.join('[redacted sensitive line]' if sensitive.search(line) else line
                     for line in text.splitlines())


def classify_output(style, returncode, stdout, stderr):
    """A zero process exit is insufficient for fixtures reporting JSON."""
    if returncode != 0:
        return False, 'nonzero_exit', {}
    if style == 'unittest':
        match = re.search(r'(?m)^Ran (\d+) tests? in ', stderr)
        ok = re.search(r'(?m)^OK(?:\s+\([^\r\n]*\))?\s*$', stderr)
        passed = bool(match and int(match.group(1)) > 0 and ok)
        return passed, 'ok' if passed else 'missing_unittest_success', {'tests': int(match.group(1))} if match else {}
    reports = []
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(value, dict):
            reports.append(value)
    if any(value.get('success') is False or
           ('checks' in value and (not isinstance(value['checks'], dict) or
                                  not value['checks'] or any(item is not True for item in value['checks'].values())))
           for value in reports):
        return False, 'fixture_reported_failure', {}
    if style == 'sync':
        fixtures = [value.get('fixture_checks_passed') for value in reports]
        passed = any(isinstance(value, list) and value for value in fixtures) and any(
            value.get('direct_request_and_process_checks_passed') is True for value in reports)
        return passed, 'ok' if passed else 'missing_sync_success', {}
    valid = [value for value in reports if value.get('success') is True and isinstance(value.get('checks'), dict) and value['checks']]
    passed = bool(valid)
    return passed, 'ok' if passed else 'missing_fixture_success', {'checks': sum(len(value['checks']) for value in valid)}


def stop_process(process):
    if os.name == 'nt':
        try:
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()
    process.wait(timeout=10)


def run_command(name, command, style, env, *, root=ROOT, timeout=TIMEOUT):
    started = time.monotonic()
    entry = {'name': name, 'status': 'failed'}
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()

    def drain(pipe, buffer):
        with pipe:
            while chunk := pipe.read(8192):
                remaining = MAX_LOG_BYTES - len(buffer)
                buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()

    try:
        process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name != 'nt')
        readers = [threading.Thread(target=drain, args=(pipe, buffer), daemon=True)
                   for pipe, buffer in zip((process.stdout, process.stderr), buffers)]
        for reader in readers:
            reader.start()
        deadline = started + min(timeout, TIMEOUT)
        while process.poll() is None:
            if overflow.is_set() or time.monotonic() >= deadline:
                stop_process(process)
                entry['reason'] = 'output_limit' if overflow.is_set() else 'timeout'
                break
            try:
                process.wait(timeout=min(0.1, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
        for reader in readers:
            reader.join(timeout=2)
        stdout, stderr = [buffer.decode('utf-8', errors='replace') for buffer in buffers]
        if overflow.is_set():
            entry['reason'] = 'output_limit'
        if 'reason' not in entry:
            if style == 'exit':
                passed, reason, detail = process.returncode == 0, 'ok' if process.returncode == 0 else 'nonzero_exit', {}
            else:
                passed, reason, detail = classify_output(style, process.returncode, stdout, stderr)
            entry.update(status='passed' if passed else 'failed', reason=reason, **detail)
        entry['exit_code'] = process.returncode
        if entry['status'] == 'failed':
            entry.update(stdout=redact(stdout, root), stderr=redact(stderr, root), log_truncated=overflow.is_set())
    except OSError as exc:
        entry.update(reason='could_not_start', error_type=type(exc).__name__)
    entry['seconds'] = round(time.monotonic() - started, 3)
    return entry


def source_files(root, suffixes):
    app = root / 'app'
    if not app.is_dir():
        return []
    files = []
    for directory, names, filenames in os.walk(app):
        # app/data contains live accounts, databases, caches and historical backups.
        names[:] = sorted(name for name in names if name not in {'data', '__pycache__', 'local-engines', 'engines', 'node_modules'})
        files.extend(Path(directory) / name for name in sorted(filenames) if Path(name).suffix in suffixes)
    return files


def python_checks(root=ROOT):
    results = []
    files = source_files(root, {'.py', '.pyw'})
    if not files:
        return [{'name': 'python:app', 'status': 'failed', 'reason': 'source_missing'}]
    for path in files:
        entry = {'name': 'python:' + path.relative_to(root).as_posix(), 'status': 'passed'}
        try:
            compile(path.read_bytes(), path.relative_to(root).as_posix(), 'exec')
        except (SyntaxError, UnicodeError, OSError) as exc:
            entry.update(status='failed', reason='compile_failed', error_type=type(exc).__name__)
            if isinstance(exc, SyntaxError):
                entry.update(line=exc.lineno, offset=exc.offset)
        results.append(entry)
    return results


def fixture_main(name):
    """Internal subprocess entry. Keep legacy fixture reports inside this runner."""
    allowed = dict(FIXTURES)
    if name not in allowed or allowed[name] == 'unittest':
        raise ValueError('Fixture is not allowed for this entry point')
    path = ROOT / 'analysis' / name
    sys.path.insert(0, str(ROOT / 'app'))
    sys.argv = [str(path)]
    legacy_reports = {ROOT / 'analysis/signature-guard-tests-report.json',
                      ROOT / 'analysis/proxy-runtime-protocol-report.json'}
    original_write = Path.write_text

    def write_text(target, data, *args, **kwargs):
        if target.resolve() in legacy_reports:
            return len(data)
        return original_write(target, data, *args, **kwargs)

    with patch.object(Path, 'write_text', write_text):
        module = runpy.run_path(str(path), run_name='project_fixture')
        if name == 'sync-source-tests.py':
            module['fixture_tests']()
            module['direct_request_tests']()
        elif name == 'proxy-runtime-protocol-tests.py':
            import asyncio
            print(json.dumps(asyncio.run(module['run']())))
        else:
            module['main']()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline static checks and reviewed synthetic fixtures; no real browser/profile checks.')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--static-only', action='store_true')
    selection.add_argument('--unit-only', action='store_true')
    parser.add_argument('--report', type=Path, default=ROOT / 'analysis/reports/project-check-latest.json')
    parser.add_argument('--_fixture', choices=[name for name, style in FIXTURES if style != 'unittest'], help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args._fixture:
        fixture_main(args._fixture)
        return 0
    if not args.report.is_absolute():
        parser.error('--report must be an absolute path')
    python, node = python_executable(), node_executable()
    entries = []
    with tempfile.TemporaryDirectory(prefix='local-project-check-') as directory:
        env = child_environment(directory, python, node)
        if not args.unit_only:
            entries.extend(python_checks())
            javascript = source_files(ROOT, {'.js'})
            for filename in ('electron-main.js', 'crypto.worker.js'):
                resource = ROOT / 'app/data/resources' / filename
                if resource.is_file():
                    javascript.append(resource)
            for path in javascript:
                name = 'javascript:' + path.relative_to(ROOT).as_posix()
                entries.append(run_command(name, [node, '--check', str(path)], 'exit', env) if node else
                               {'name': name, 'status': 'skipped', 'reason': 'node_unavailable'})
        if not args.static_only:
            contract = ROOT / 'tests/test_project_contracts.py'
            entries.append(run_command('contracts', [python, '-B', str(contract)], 'unittest', env))
            deadline_test = ROOT / 'tests/test_proxy_deadline.py'
            entries.append(run_command('proxy-deadline', [python, '-B', str(deadline_test)], 'unittest', env))
            removed_test = ROOT / 'tests/test_removed_features.py'
            entries.append(run_command('removed-features', [python, '-B', str(removed_test)], 'unittest', env))
            entries.append(run_command('window-layout', [python, '-B', str(ROOT/'tests/test_window_layout.py')], 'unittest', env))
            for filename in ('test_batch_parallel.py','test_engine_validation.py','test_profile_process_scan.py','test_sync_parallel.py','test_engine_portability.py','test_source_sessions.py','test_source_identity.py','test_status_purge_race.py'):
                entries.append(run_command(filename,[python,'-B',str(ROOT/'tests'/filename)],'unittest',env))
            for filename in ('test_status_projection.py', 'test_signature_status.py', 'test_group_operations.py'):
                entries.append(run_command(filename, [python, '-B', str(ROOT/'tests'/filename)], 'unittest', env))
            for filename in ('test_sync_reliability.py','test_source_preparation.py','test_import_progress.py','test_profile_copy.py','test_batch_status.py','test_profile_delete.py','test_delete_integration.py','test_background_probe.py','test_legacy_sources.py','test_core_compatibility.py','test_ip_info_page.py','test_proxy_runtime_stability.py','test_clean_install.py','test_launch_paths.py','test_release_boundary.py','test_process_path_aliases.py','test_environment_compatibility.py'):
                entries.append(run_command(filename,[python,'-B',str(ROOT/'tests'/filename)],'unittest',env))
            entries.append(run_command('profile-launch-path',[python,'-B',str(ROOT/'tests/test_profile_launch_path.py')],'json',env))
            installation = ROOT / 'tests/test_installation_inspector.py'
            entries.append(run_command('installation-inspector', [python, '-B', str(installation)], 'unittest', env))
            recovery = ROOT / 'tests/test_local_runtime_recovery.py'
            entries.append(run_command('local-runtime-recovery', [python, '-B', str(recovery)], 'unittest', env))
            creation = ROOT / 'tests/test_window_creation.py'
            entries.append(run_command('window-creation', [python, '-B', str(creation)], 'unittest', env))
            entries.append(run_command('creation-parity', [python, '-B', str(ROOT/'tests/test_creation_parity.py')], 'unittest', env))
            entries.append(run_command('creation-runtime', [python, '-B', str(ROOT/'tests/test_creation_runtime.py')], 'unittest', env))
            entries.append(run_command('creation-audit', [python, '-B', str(ROOT/'tests/test_creation_audit.py')], 'unittest', env))
            entries.append(run_command('bundled-core-creation', [python, '-B', str(ROOT/'tests/test_bundled_core_creation.py')], 'unittest', env))
            for filename in ('test_update_guard.py','test_inplace_update.py','test_overlay_update.py','test_portable_bootstrap.py'):
                entries.append(run_command(filename,[python,'-B',str(ROOT/'tests'/filename)],'unittest',env))
            entries.append(run_command('direct-portable-launch', [python, '-B', str(ROOT/'tests/test_direct_portable_launch.py')], 'unittest', env))
            entries.append(run_command('manager-webview-close', [python, '-B', str(ROOT/'tests/test_manager_webview_close.py')], 'unittest', env))
            entries.append(run_command('release-builder', [python, '-B', str(ROOT/'tests/test_release_builder.py')], 'unittest', env))
            entries.append(run_command('release-archive', [python, '-B', str(ROOT/'tests/test_release_archive.py')], 'unittest', env))
            entries.append(run_command('desktop-runner', [python, '-B', str(ROOT/'tests/test_desktop_runner.py')], 'unittest', env))
            entries.append(run_command('extension-portability', [python, '-B', str(ROOT/'tests/test_extension_portability.py')], 'unittest', env))
            ssh = ROOT / 'tests/test_ssh_proxy.py'
            entries.append(run_command('ssh-proxy', [python, '-B', str(ssh)], 'unittest', env))
            dynamic = ROOT / 'tests/test_dynamic_proxy.py'
            entries.append(run_command('dynamic-proxy', [python, '-B', str(dynamic)], 'unittest', env))
            entries.append(run_command('import-cookies', [python, '-B', str(ROOT/'tests/test_import_cookies.py')], 'unittest', env))
            entries.append(run_command('session-recovery', [python, '-B', str(ROOT/'tests/test_session_recovery.py')], 'unittest', env))
            entries.append(run_command('private-acceptance-transport', [python, '-B', str(ROOT/'tests/test_private_acceptance_transport.py')], 'unittest', env))
            entries.append(run_command('private-session-verifier', [python, '-B', str(ROOT/'tests/test_private_session_verifier.py')], 'unittest', env))
            entries.append(run_command('vendor-runtime-restore', [python, '-B', str(ROOT/'tests/test_vendor_runtime_restore.py')], 'unittest', env))
            entries.append(run_command('fixture-runtime-guard', [python, '-B', str(ROOT/'tests/test_fixture_runtime_guard.py')], 'unittest', env))
            entries.append(run_command('all-core-fixture-ownership', [python, '-B', str(ROOT/'tests/test_all_core_fixture_ownership.py')], 'unittest', env))
            entries.append(run_command('private-network-diagnostic', [python, '-B', str(ROOT/'tests/test_private_network_diagnostic.py')], 'unittest', env))
            for name, style in FIXTURES:
                path = ROOT / 'analysis' / name
                if not path.is_file():
                    entries.append({'name': name, 'status': 'failed', 'reason': 'fixture_missing'})
                    continue
                command = [python, '-B', str(path)] if style == 'unittest' else [python, '-B', str(Path(__file__)), '--_fixture', name]
                entries.append(run_command(name, command, style, env))
            probe_budget = ROOT / 'tests/test_probe_budget.cjs'
            if not probe_budget.is_file():
                entries.append({'name': 'probe-budget', 'status': 'failed', 'reason': 'fixture_missing'})
            else:
                entries.append(run_command('probe-budget', [node, str(probe_budget)], 'json', env) if node else
                               {'name': 'probe-budget', 'status': 'skipped', 'reason': 'node_unavailable'})
            frontend = ROOT / 'tests/frontend-state.test.js'
            if not frontend.is_file():
                entries.append({'name': 'frontend-state', 'status': 'failed', 'reason': 'fixture_missing'})
            else:
                entries.append(run_command('frontend-state', [node, '--test', str(frontend)], 'exit', env) if node else
                               {'name': 'frontend-state', 'status': 'skipped', 'reason': 'node_unavailable'})
    counts = {status: sum(entry['status'] == status for entry in entries) for status in ('passed', 'failed', 'skipped')}
    report = {'format': 1, 'created_at': datetime.now(timezone.utc).isoformat(),
              'success': counts['failed'] == 0, 'counts': counts, 'checks': entries}
    try:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        descriptor, filename = tempfile.mkstemp(prefix=args.report.name + '.', suffix='.tmp', dir=args.report.parent)
        temporary = Path(filename)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
                handle.write(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, args.report)
        finally:
            temporary.unlink(missing_ok=True)
    except OSError:
        counts['failed'] += 1
        print(json.dumps({'passed': counts['passed'], 'failed': counts['failed'], 'skipped': counts['skipped']}))
        return 1
    print(json.dumps(counts))
    return 1 if counts['failed'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
