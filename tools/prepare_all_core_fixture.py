"""Create one fresh synthetic cross-device fixture without any vendor window.

Run the copy inside a new isolated source package. Only original engine inventory
and a normal signing authorization are read from the vendor installation. Account
profiles, IDs and metadata are never copied, requested or opened.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time
import traceback
import uuid
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def require(value):
    if not value:
        raise ValueError()


def close_seed_browser(controller, original_close, owned, profile, fixture):
    """A successful Popen observation, never profile presence, grants close authority."""
    from compare_vendor_runtime import _close_owned
    _close_owned(controller, original_close, owned, profile, fixture)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--core', required=True)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({'executed': False}))
        return 0
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tools')]
    report = {'success': False, 'synthetic': True, 'core': args.core,
              'real_account_profiles_accessed': False, 'vendor_windows_created': 0}
    controller = server = thread = None
    profile = None
    owned = []
    try:
        from core_specs import supports_major
        from installation import initialize_installation
        from configuration import Configuration
        from creation_fingerprint import creation_defaults, build_native
        from local_signer import LocalSigner
        from local_state import _dpapi_protect
        from portable_browser import capture_profile
        from browser_processes import profile_processes
        from browser_core import BrowserController, CDP, sha256
        import browser_core
        from fingerprint_continuity import create_baseline, verify_continuity
        from window_store import WindowStore, now
        from source_database import snapshot
        from signature_lifetime import require_current_signature, signature_lifetime
        import verify_portable_fixture as fixture
        import verify_login_storage as storage
        require(supports_major(args.core) and args.node.is_file())
        fixture.CORE = args.core
        require(fixture.ROOT.resolve() == ROOT.resolve() and storage.ROOT.resolve() == ROOT.resolve())
        marker_path = ROOT / 'all-core-fixture.json'
        require(marker_path.is_file() and json.loads(marker_path.read_text('utf-8')) == {
            'format': 1, 'core': args.core, 'synthetic': True})
        data = ROOT / 'app/data'
        require(not data.exists() and not args.archive.exists())
        initialize_installation(data)
        configuration = Configuration(data)
        configuration._config_command = lambda: [str(args.node.resolve()), str(ROOT / 'app/config_factory.js')]
        signer = LocalSigner(data, load_private=False)
        core = configuration.local_core(args.core)
        report['exact_core_authenticated'] = True
        record = creation_defaults(args.core)
        record.update(id=fixture.IDENTITY, seq=1, name=fixture.NAME, created_at=now(),
                      archived=False, config_status='ready', urls=[fixture.ORIGIN],
                      _prefs_dirty=False, _cookie_pending=False)
        native, binary = build_native(configuration, record)
        signature = data / 'fingerprints/release-test.bin'
        signature.parent.mkdir()
        signature.write_bytes(binary)
        # Use the current normal session strictly in memory; no production cache write.
        reader = copy.copy(configuration)
        reader.independent = False

        def authorization():
            with snapshot(reader.vendor_data / 'db.sqlite') as connection:
                values = dict(connection.execute(
                    'SELECT config_name,config_value FROM global_configs WHERE config_name IN (?,?,?)',
                    ('app_token', 'service_line', 'locale')))
            require(bool(values.get('app_token')))
            return values

        reader.authorization = authorization
        vendor_signature = ROOT / 'vendor-signature.bin'
        vendor_signature.write_bytes(reader.sign(native, core_major=args.core))
        require_current_signature(vendor_signature, core_major=args.core)
        require(configuration.decode(vendor_signature) == native)
        report['genuine_vendor_signature'] = True
        report['vendor_signature_expires_at'] = signature_lifetime(vendor_signature)['expires_at']
        profile = data / 'profiles' / fixture.IDENTITY
        (profile / 'Default').mkdir(parents=True)
        state = {'os_crypt': {'encrypted_key': base64.b64encode(
            b'DPAPI' + _dpapi_protect(secrets.token_bytes(32))).decode('ascii')}}
        (profile / 'Local State').write_text(json.dumps(state), encoding='utf-8')
        (profile / 'Default/Preferences').write_text(json.dumps({
            'session': {'restore_on_startup': 1}}), encoding='utf-8')
        runtime = {'alias': fixture.IDENTITY, 'name': fixture.NAME, 'profile_path': str(profile),
            'core_path': str(core), 'core_major': args.core, 'core_sha256': sha256(core),
            'fingerprint_path': str(signature), 'fingerprint_sha256': sha256(signature),
            'signature_provider': 'local-v1', 'signature_key_id': signer.key_id,
            'new_profile': True, 'has_launched': False, 'restore_session': True,
            'initial_urls': [fixture.ORIGIN], 'launch_args': [], 'no_system_proxy': True,
            'account_platform': '', 'account_username': '', 'account_password': '',
            'language': native.get('uiLang') or 'en-US'}
        record.update(_runtime=runtime, _native=native, _portable_app=str(ROOT / 'app'))
        record['preferences']['restore_session'] = True
        record['_portable_crypt'] = capture_profile(profile)
        record['_continuity'] = create_baseline(record, data)
        verify_continuity(record, data)
        require(len(record['_continuity']['stable']) == 46)
        report['source_baseline_fields'] = 46
        marker = 'portable-fixture-v1-' + uuid.uuid4().hex
        (ROOT / 'portable-test.json').write_text(json.dumps({'format': 1, 'id': fixture.IDENTITY,
            'marker': marker, 'origin': fixture.ORIGIN, 'core': args.core}), encoding='utf-8')
        store = WindowStore(configuration, data)
        store.put(record)
        server = fixture._PageServer(('127.0.0.1', fixture.PORT), fixture._PageHandler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
        thread.start()
        require(not profile_processes(profile, require_inspectable=True))
        controller = BrowserController(data, settings={'windows': [runtime], 'persistent': False})
        original_close, original_popen = controller.close, browser_core.subprocess.Popen

        def close_owned(identity):
            require(identity == fixture.IDENTITY)
            close_seed_browser(controller, original_close, owned, profile, fixture)

        controller.close = close_owned

        def launch(arguments, *values, **options):
            require(isinstance(arguments, (list, tuple)) and not options.get('shell'))
            require([argument.split('=', 1)[1] for argument in arguments
                     if argument.startswith('--user-data-dir=')] == [str(profile)])
            require(fixture._launch_core(arguments[0], core, ROOT) == core)
            require(not profile_processes(profile, require_inspectable=True))
            process = original_popen(arguments, *values, **options)
            owned.append({'controller': controller, 'process': process, 'profile': profile,
                          'core': core, 'signature': signature})
            return process

        with patch.object(browser_core.subprocess, 'Popen', side_effect=launch):
            controller.open(fixture.IDENTITY, offline_test=True, extra_urls=[fixture.ORIGIN])
        require(len(owned) == 1 and controller.state[fixture.IDENTITY]['pid'] == owned[0]['process'].pid)
        with CDP(controller.endpoint(fixture.IDENTITY), timeout=8) as connection:
            session = storage._origin_session(connection, fixture.ORIGIN)
            try:
                connection.call('Storage.setCookies', {'cookies': [
                    {'name': 'portable_release', 'value': marker, 'url': fixture.ORIGIN,
                     'path': '/', 'expires': time.time() + 86400 * 7, 'sameSite': 'Lax'},
                    {'name': 'portable_session', 'value': marker, 'url': fixture.ORIGIN,
                     'path': '/', 'sameSite': 'Lax'}]})
                require(storage._evaluate(connection, session,
                    'localStorage.setItem("portable_release",' + json.dumps(marker)
                    + ');sessionStorage.setItem("portable_session",' + json.dumps(marker) + ');true') is True)
                require(storage._evaluate(connection, session, storage._indexed_db_expression(marker, seed=True)) is True)
                require(all(storage._observe(connection, session, marker, native, fixture.ORIGIN).values()))
            finally:
                connection.call('Target.detachFromTarget', {'sessionId': session})
        controller.close(fixture.IDENTITY)
        require(not profile_processes(profile, require_inspectable=True))
        record['_runtime'].update(new_profile=False, has_launched=True)
        store.put(record)
        require(capture_profile(profile) == record['_portable_crypt'])
        fixture.load_fixture(ROOT, allow_session_cookie=True)
        storage._restoration_ready(record, profile, fixture, ROOT)
        report['synthetic_storage_seeded'] = True
        args.archive.parent.mkdir(parents=True, exist_ok=True)
        paths = [ROOT / name for name in ('portable-test.json', 'all-core-fixture.json', 'vendor-signature.bin')]
        for folder in (data, core.parent):
            paths.append(folder)
            paths.extend(sorted(folder.rglob('*')))
        # Only the referenced compact kernel enters the fixture; old deployment copies remain local.
        with zipfile.ZipFile(args.archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for path in paths:
                fixture._inside(path, ROOT)
                archive.write(path, path.relative_to(ROOT).as_posix())
        report.update(success=True, bytes=args.archive.stat().st_size, sha256=sha256(args.archive),
                      asset=args.archive.name)
    except Exception as error:
        report.update(error_type=type(error).__name__, frames=[{'file': Path(frame.filename).name,
            'line': frame.lineno} for frame in traceback.extract_tb(error.__traceback__)[-8:]])
    finally:
        if controller is not None:
            try:
                controller.close('release-test')
                from browser_processes import profile_processes
                report['owned_browser_closed'] = not profile_processes(profile, require_inspectable=True)
                report['success'] = report['success'] and report['owned_browser_closed']
            except Exception:
                report['success'] = False
                report['owned_browser_closed'] = False
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=3)
        report['seed_browser_count'] = len(owned)
        destination = ROOT / 'analysis/reports/all-core-preparation.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
