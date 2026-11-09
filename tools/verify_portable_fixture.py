"""Explicit portable release acceptance, restricted to one synthetic fixture.

Run the packaged copy with --execute. Without it, no fixture is read or changed.
The original continuity baseline is verified, never replaced. Failed profiles and
processes that cannot close normally are retained; no process is killed.
"""
from __future__ import annotations

import argparse
import copy
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import traceback
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = 'release-test'
NAME = 'Portable release test'
ORIGIN = 'http://localhost:18763'
PORT = 18763
CORE = '148'
_PAGE = b'<!doctype html><html><head><title>Portable release test</title></head><body>Portable release test</body></html>'


def _require(passed):
    if not passed:
        raise ValueError()


def _inside(path, root, *, exists=True):
    """Reject links, junctions and escapes before opening a fixture-owned path."""
    path, root = Path(path).absolute(), Path(root).absolute()
    _require(path.is_relative_to(root))
    for candidate in (root, *reversed(path.relative_to(root).parents), path):
        # Relative parent paths above are expanded below, never against cwd.
        candidate = candidate if candidate.is_absolute() else root / candidate
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            if candidate == path and exists:
                raise
            continue
        _require(not stat.S_ISLNK(info.st_mode)
                 and not getattr(info, 'st_file_attributes', 0) & 0x400)
    _require(path.resolve().is_relative_to(root.resolve()))
    return path.resolve()


def _json_file(path, root, *, limit=65536):
    path = _inside(path, root)
    _require(path.is_file() and path.stat().st_size <= limit)
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    _require(len(raw) <= limit)
    return json.loads(raw)


def _plain_tree(folder, root):
    pending = [_inside(folder, root)]
    count = total = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                _require(count <= 40000)
                path = _inside(entry.path, root)
                info = path.stat()
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                else:
                    _require(stat.S_ISREG(info.st_mode))
                    total += info.st_size
                    _require(total <= 512 * 1024 * 1024)


def fixture_marker(root):
    value = _json_file(root / 'portable-test.json', root, limit=1024)
    _require(isinstance(value, dict) and set(value) == {'format', 'id', 'marker', 'origin', 'core'})
    _require(type(value['format']) is int and value['format'] == 1
             and value['id'] == IDENTITY and value['origin'] == ORIGIN and value['core'] == CORE)
    _require(isinstance(value['marker'], str)
             and re.fullmatch(r'portable-fixture-v1-[0-9a-f]{32}', value['marker']) is not None)
    return value


def _database_check(path, root, queries):
    """Query only a stable temporary copy, including any source WAL."""
    from inspect_installation import database_snapshot
    path = _inside(path, root)
    with tempfile.TemporaryDirectory(prefix='portable-fixture-catalog-') as temporary:
        with database_snapshot(path, Path(temporary) / 'copy.sqlite', time.monotonic() + 20) as (copied, _):
            connection = sqlite3.connect(copied.as_uri() + '?mode=ro', uri=True, timeout=3)
            try:
                deadline = time.monotonic() + 10
                connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                connection.execute('PRAGMA query_only=ON')
                _require(connection.execute('PRAGMA quick_check').fetchone() == ('ok',))
                for query, parameters, expected in queries:
                    _require(connection.execute(query, parameters).fetchall() == expected)
            finally:
                connection.close()


def load_fixture(root, *, allow_session_cookie=False):
    """Authenticate the test identity before allowing production startup code."""
    from inspect_installation import baseline_structure_valid, read_catalog
    from local_state import read_encrypted
    from local_signer import LocalSigner
    from local_engine import LocalEngineStore
    from portable_vault import PortableVault
    import fingerprint_continuity as continuity

    marker = fixture_marker(root)
    data = _inside(root / 'app/data', root)
    _plain_tree(data, root)
    _require(not (data / 'backups').exists() and not list(data.glob('continuity-probe-*')))
    _database_check(data / 'windows.sqlite', root, [
        ('SELECT id FROM profiles ORDER BY id', (), [(IDENTITY,)]),
        ('SELECT count(*) FROM source_bindings', (), [(0,)]),
    ])
    # No account record is decrypted until the outer catalog has exactly the
    # dedicated fixture identity and no imported source bindings.
    catalog = read_catalog(data, time.monotonic() + 30)
    _require(catalog['quick_check'] and len(catalog['records']) == 1)
    record = catalog['records'][0]
    _require(record.get('id') == IDENTITY and record.get('name') == NAME
             and not record.get('archived') and not record.get('_cookie_pending'))
    for field in ('platform', 'username', 'password', 'fa_secret', 'cookie_text'):
        _require(record.get(field, '') == '')
    _require(not any(field.startswith('_source') for field in record))
    proxy = record.get('proxy')
    _require(isinstance(proxy, dict) and proxy.get('type') == 'noproxy')
    _require(all(proxy.get(field, '') in ('', None, 0) for field in ('host', 'port', 'username', 'password')))
    _require(not proxy.get('enable_socks5_udp'))
    runtime = record.get('_runtime')
    _require(isinstance(runtime, dict) and runtime.get('alias') == IDENTITY
             and runtime.get('name') == NAME and str(runtime.get('core_major')) == CORE)
    for field in ('account_platform', 'account_username', 'account_password', 'managed_extension'):
        _require(runtime.get(field, '') == '')
    for values in (record.get('urls', []), runtime.get('initial_urls', []), runtime.get('open_urls_once', [])):
        _require(isinstance(values, list) and all(value in ('about:blank', ORIGIN, ORIGIN + '/') for value in values))
    arguments = runtime.get('launch_args') or []
    _require(isinstance(arguments, list) and len(arguments) <= 32)
    for argument in arguments:
        _require(isinstance(argument, str) and len(argument) <= 1000
                 and (argument.split('=', 1)[0] in continuity._SAFE_SWITCHES
                      or argument == '--disable-background-networking'))
    profile = _inside(runtime['profile_path'], root)
    _require(profile == data / 'profiles' / IDENTITY and profile.is_dir())
    signature = _inside(runtime['fingerprint_path'], root)
    _require(signature.is_relative_to(data / 'fingerprints') and signature.is_file())
    core = _inside(runtime['core_path'], root)
    _require(core.is_relative_to(root / 'app/local-engines') and core.is_file())
    _json_file(profile / 'Local State', root, limit=16 * 1024 * 1024)
    _require(baseline_structure_valid(record.get('_continuity')))
    _require(len(record['_continuity']['stable']) == 46)
    vault = PortableVault(data, key_required=True)
    _inside(vault.key_path, root)
    signer = LocalSigner(data, load_private=False)
    for filename in ('local-signing/public.der', 'local-signing/private.bin', 'local-signing.lock'):
        _inside(data / filename, root)
    for filename in ('portable-mode.bin', 'continuity-mode.bin', 'independent-mode.bin'):
        state = read_encrypted(_inside(data / filename, root), root=data)
        _require(isinstance(state, dict) and state.get('format') == 1)
        if filename != 'independent-mode.bin':
            _require(state.get('state') == 'ready')
    _require(runtime.get('signature_provider') == 'local-v1'
             and runtime.get('signature_key_id') == signer.key_id)
    LocalEngineStore(root / 'app/local-engines').validate(core, signer.key_id, CORE)
    native = record.get('_native')
    _require(isinstance(native, dict) and isinstance(native.get('navigator'), dict)
             and isinstance(native.get('userAgent'), str)
             and type(native['navigator'].get('hardwareConcurrency')) is int)
    cookies = profile / 'Default/Network/Cookies'
    cookie_queries=[
        ('SELECT count(*) FROM cookies WHERE name = ?', ('portable_release',), [(1,)]),
    ]
    if allow_session_cookie:
        cookie_queries.extend([
            ('SELECT count(*) FROM cookies WHERE name NOT IN (?,?) OR host_key NOT IN (?,?)',
             ('portable_release','portable_session','localhost','.localhost'),[(0,)]),
            ('SELECT count(*) FROM cookies WHERE name=?',('portable_session',),[(1,)]),
            ('SELECT count(*) FROM cookies WHERE name=? AND is_persistent=0 AND has_expires=0 AND expires_utc=0',
             ('portable_session',),[(1,)]),
        ])
    else:
        cookie_queries.append(('SELECT count(*) FROM cookies WHERE name != ? OR host_key NOT IN (?,?)',
                               ('portable_release','localhost','.localhost'),[(0,)]))
    _database_check(cookies,root,cookie_queries)
    for relative in ('Default/Login Data', 'Default/Login Data For Account'):
        if (profile / relative).exists():
            _database_check(profile / relative, root, [('SELECT count(*) FROM logins', (), [(0,)])])
    return marker, record, data, profile


class _PageHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def log_message(self, *_):
        pass

    def setup(self):
        self.request.settimeout(3)
        super().setup()

    def do_GET(self):
        okay = self.path == '/' and self.headers.get_all('Host') == ['localhost:' + str(PORT)]
        self.send_response(200 if okay else 404)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(_PAGE) if okay else 0))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        if okay:
            self.wfile.write(_PAGE)


class _PageServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False

    def handle_error(self, *_):
        pass


def _observe(service, marker, native):
    from browser_core import CDP
    with CDP(service.controller.endpoint(IDENTITY), timeout=8) as connection:
        deadline = time.monotonic() + 12
        session = None
        while time.monotonic() < deadline:
            targets = connection.call('Target.getTargets').get('targetInfos', [])
            target = next((row for row in targets if row.get('type') == 'page'
                           and row.get('url') in (ORIGIN, ORIGIN + '/')), None)
            if target is not None:
                session = connection.call('Target.attachToTarget',
                                          {'targetId': target['targetId'], 'flatten': True})['sessionId']
                break
            time.sleep(.1)
        _require(session is not None)
        try:
            expression = ('(location.origin!=='+json.dumps(ORIGIN)+' || document.readyState!=="complete")'
                          '?({ready:"loading"}):({ready:document.readyState,origin:location.origin,'
                          'marker:localStorage.getItem("portable_release"),'
                          'ua:navigator.userAgent,cpu:navigator.hardwareConcurrency})')
            value = {}
            while time.monotonic() < deadline:
                response = connection.call('Runtime.evaluate',
                                           {'expression': expression, 'returnByValue': True}, session=session)
                _require(not response.get('exceptionDetails'))
                value = response.get('result', {}).get('value') or {}
                if value.get('ready') == 'complete':
                    break
                time.sleep(.1)
            cookies = connection.call('Storage.getCookies').get('cookies', [])
            matching = [cookie for cookie in cookies if cookie.get('name') == 'portable_release'
                        and cookie.get('domain') in ('localhost', '.localhost')]
            return {'page_loaded': value.get('ready') == 'complete' and value.get('origin') == ORIGIN,
                    'cookie_persisted': len(matching) == 1 and matching[0].get('value') == marker,
                    'local_storage_persisted': value.get('marker') == marker,
                    'user_agent_matches_native': value.get('ua') == native['userAgent'],
                    'hardware_concurrency_matches_native': value.get('cpu') == native['navigator']['hardwareConcurrency']}
        finally:
            connection.call('Target.detachFromTarget', {'sessionId': session})


def _diagnose(record, data, report):
    import fingerprint_continuity as continuity
    try:
        snapshot = continuity.probe_snapshot(record, data)
        changed = [field for field, expected in record['_continuity']['stable'].items()
                   if snapshot['values'].get(field) != expected or field in snapshot.get('unstable', [])]
        report['continuity_changed_fields'] = sorted(field for field in changed if continuity._safe_field(field))
        report['continuity_diagnosed'] = True
    except Exception as error:
        report['continuity_diagnosed'] = False
        report['diagnosis_error_type'] = type(error).__name__


def _write_report(root, report):
    destination = _inside(root / 'analysis/reports/portable-device.json', root, exists=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix='.portable-device-', suffix='.tmp', dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    if not parser.parse_args().execute:
        print(json.dumps({'executed': False, 'requires_execute': True}))
        return 0
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tools')]
    report = {'success': False, 'executed': True, 'checks': {}, 'rounds': [], 'continuity_rounds': []}
    service = server = server_thread = None
    owned = []
    marker_valid = False
    data = profile = record = baseline = None
    try:
        fixture_marker(ROOT)
        marker_valid = True
        marker, record, data, profile = load_fixture(ROOT)
        from browser_processes import profile_processes
        from manager_service import ManagerService
        import browser_core
        import fingerprint_continuity as continuity
        import portable_browser
        _require(not profile_processes(profile, require_inspectable=True))
        report['checks']['fixture_validated'] = True
        baseline = copy.deepcopy(record['_continuity'])
        private_key = portable_browser._private_key(record.get('_portable_crypt'))
        state, _ = portable_browser._read_state(profile)
        try:
            initial_key = portable_browser._unwrap(state.get('os_crypt', {}).get('encrypted_key'))
            report['source_wrapper_decryptable'] = True
        except browser_core.LocalBrowserError:
            report['source_wrapper_decryptable'] = False
        if report['source_wrapper_decryptable']:
            _require(hmac.compare_digest(initial_key, private_key))
        report['ci_environment'] = os.environ.get('GITHUB_ACTIONS') == 'true'
        if report['ci_environment']:
            _require(not report['source_wrapper_decryptable'])
        original_popen = browser_core.subprocess.Popen
        original_verify = continuity.verify_continuity

        def verify(*values, **options):
            _require(options.get('allow_device_variance') is True)
            result = original_verify(*values, **options)
            _require(result.get('passed') is True and result.get('verification_policy') == 'vendor-compatible-148')
            report['continuity_rounds'].append({key: result[key] for key in (
                'verification_policy', 'device_variance_fields', 'environment_args')})
            return result

        def launch(arguments, *values, **options):
            _require(isinstance(arguments, (list, tuple)) and not options.get('shell'))
            _require(_inside(arguments[0], ROOT) == Path(record['_runtime']['core_path']).resolve())
            profiles = [str(argument).split('=', 1)[1] for argument in arguments
                        if str(argument).startswith('--user-data-dir=')]
            _require(len(profiles) == 1)
            launched_profile = _inside(profiles[0], ROOT)
            probe = (launched_profile.name == 'profile' and launched_profile.parent.parent == data
                     and launched_profile.parent.name.startswith('continuity-probe-'))
            _require(launched_profile == profile or probe)
            _require('--disable-background-networking' in arguments
                     and '--proxy-server=http://127.0.0.1:1' in arguments)
            process = original_popen(arguments, *values, **options)
            owned.append((process, launched_profile))
            return process

        server = _PageServer(('127.0.0.1', PORT), _PageHandler)
        server_thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
        server_thread.start()
        with patch.object(browser_core.subprocess, 'Popen', side_effect=launch), \
                patch.object(continuity, 'verify_continuity', side_effect=verify):
            service = ManagerService(data)
            _require(service.configuration.independent)
            _require(service.store.get(IDENTITY)['_continuity'] == baseline)
            for _ in range(2):
                try:
                    service.open(IDENTITY, offline_test=True, extra_urls=[ORIGIN])
                except browser_core.LocalBrowserError as error:
                    if str(error).startswith('环境连续性检查'):
                        report['continuity_rejected'] = True
                        fields=getattr(error,'changed_fields',None)
                        if isinstance(fields,list):
                            import fingerprint_continuity as continuity
                            report['continuity_changed_fields']=[field for field in fields if continuity._safe_field(field)]
                            report['continuity_diagnosed']=True
                        else:_diagnose(service.store.get(IDENTITY), data, report)
                    raise
                checks = _observe(service, marker['marker'], record['_native'])
                report['rounds'].append(checks)
                _require(all(checks.values()))
                service.close(IDENTITY)
                _require(not profile_processes(profile, require_inspectable=True))
                _require(service.store.get(IDENTITY)['_continuity'] == baseline)
            state, _ = portable_browser._read_state(profile)
            current_key = portable_browser._unwrap(state.get('os_crypt', {}).get('encrypted_key'))
            report['checks']['current_wrapper_matches_fixture_key'] = hmac.compare_digest(current_key, private_key)
            report['checks']['baseline_unchanged'] = service.store.get(IDENTITY)['_continuity'] == baseline
            report['checks']['two_cold_reopens_passed'] = len(report['rounds']) == 2
            report['checks']['production_continuity_checked_twice'] = len(report['continuity_rounds']) == 2
            _require(all(report['checks'].values()))
            report['success'] = True
    except Exception as error:
        report['error_type'] = type(error).__name__
        report['frames']=[{'file':Path(frame.filename).name,'line':frame.lineno}
                          for frame in traceback.extract_tb(error.__traceback__)[-8:]]
    finally:
        # Only an observed launch from this invocation grants closing authority.
        if service is not None and any(path == profile for _, path in owned):
            try:
                state = service.controller.state.get(IDENTITY, {})
                if state.get('pid') in {process.pid for process, path in owned if path == profile}:
                    service.close(IDENTITY)
            except Exception as error:
                report['close_error_type'] = type(error).__name__
                report['success'] = False
        if owned:
            try:
                from browser_processes import profile_processes
                released = all(process.poll() is not None for process, _ in owned)
                released = released and all(not profile_processes(path, require_inspectable=True)
                                            for path in {path for _, path in owned})
                report['checks']['owned_processes_closed'] = released
                report['success'] = report['success'] and released
            except Exception as error:
                report['process_check_error_type'] = type(error).__name__
                report['success'] = False
        report['created_process_count'] = len(owned)
        try:
            if server is not None:
                if server_thread is not None and server_thread.is_alive():
                    server.shutdown()
                server.server_close()
            if server_thread is not None and server_thread.ident is not None:
                server_thread.join(timeout=2)
                _require(not server_thread.is_alive())
        except Exception as error:
            report['server_close_error_type'] = type(error).__name__
            report['success'] = False
        if service is not None and baseline is not None:
            try:
                unchanged = service.store.get(IDENTITY)['_continuity'] == baseline
                report['checks']['baseline_unchanged'] = unchanged
                report['success'] = report['success'] and unchanged
            except Exception:
                report['success'] = False
        if marker_valid:
            try:
                _write_report(ROOT, report)
            except Exception as error:
                report['report_error_type'] = type(error).__name__
                report['success'] = False
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
