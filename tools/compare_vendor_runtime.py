"""Compare stock and independent 148 only in the synthetic portable package.

Without --execute no fixture is opened or changed. This is an offline diagnostic,
not device acceptance: the production continuity gate and saved baseline remain
unchanged. A new stock engine copy is retained, including after any failure.
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import threading
import time
import traceback
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
_MAX_ENGINE_BYTES = 2 * 1024 * 1024 * 1024
_OFFLINE_ARGUMENTS = frozenset({
    '--disable-background-networking', '--disable-component-update',
    '--disable-sync', '--disable-extensions', '--disable-quic',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost',
    '--proxy-server=http://127.0.0.1:1',
})


def _require(condition):
    if not condition:
        raise ValueError()


def _vendor_signature(path, configuration, native):
    from signature_lifetime import signature_lifetime, verify_signature
    _require(path.is_file() and 32 <= path.stat().st_size <= 2 * 1024 * 1024)
    _require(verify_signature(path))
    lifetime = signature_lifetime(path)
    _require(lifetime['status'] == 'active'
             and datetime.fromisoformat(lifetime['created_at']).timestamp() <= time.time())
    _require(configuration.decode(path) == native)


def _stock_engine(record, fixture, root):
    """Restore only the authenticated public root into a new, bounded copy."""
    import local_engine as engine
    from core_specs import CORE_SPECS
    runtime = record['_runtime']
    executable = fixture._inside(runtime['core_path'], root)
    engine.LocalEngineStore(root / 'app/local-engines').validate(
        executable, runtime['signature_key_id'], '148')
    source = executable.parent
    manifest = fixture._json_file(source / 'manifest.json', root, limit=16 * 1024 * 1024)
    files, directories = manifest['files'], manifest['directories']
    total = sum(item['size'] for item in files.values())
    _require(0 < len(files) <= 10000 and len(directories) <= 10000
             and 0 < total <= _MAX_ENGINE_BYTES)
    spec = CORE_SPECS['148']
    vendor_der = engine._public_der(base64.b64decode(
        manifest['local_trust']['vendor_public_der'], validate=True))
    _require(hashlib.sha256(vendor_der).hexdigest() == engine._VENDOR_DER_SHA256)
    chrome_names = [name for name in files if Path(name).name.casefold() == 'chrome.dll']
    _require(len(chrome_names) == 1)
    chrome_name = chrome_names[0]
    expected = copy.deepcopy(files)
    expected[chrome_name]['sha256'] = spec['sha256']
    resource_revision = manifest['local_trust'].get('resource_root_revision', 0)
    _require(type(resource_revision) is int and resource_revision in (0, 1))
    if resource_revision:
        resource = spec['resource_root']
        expected[resource['file']]['sha256'] = resource['sha256']
    _require(engine._tree_digest(expected, directories)
             == manifest['local_trust']['source_tree_digest'])
    destination = fixture._inside(root / 'analysis/vendor-runtime', root, exists=False)
    _require(not destination.exists())
    destination.parent.mkdir(parents=True, exist_ok=True)
    fixture._inside(destination.parent, root)
    _require(shutil.disk_usage(destination.parent).free >= total + total // 5 + 64 * 1024 * 1024)
    destination.mkdir()
    for name in sorted(directories, key=lambda value: (len(Path(value).parts), value)):
        fixture._inside(destination / name, root, exists=False).mkdir()
    for name in files:
        original = fixture._inside(source / name, root)
        copied = fixture._inside(destination / name, root, exists=False)
        shutil.copy2(original, copied, follow_symlinks=False)
    _require(engine._inventory(destination) == (files, directories)
             and engine._inventory(source) == (files, directories))
    chrome = fixture._inside(destination / chrome_name, root)
    original_mode = stat.S_IMODE(chrome.stat().st_mode)
    try:
        chrome.chmod(original_mode | stat.S_IWUSR)
        with chrome.open('r+b') as stream:
            stream.seek(spec['offset'])
            _require(stream.write(engine._key_block(vendor_der, spec['seeds'])) == 294)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        chrome.chmod(original_mode)
    if resource_revision:
        resource_path = engine._resource_key(destination, spec, vendor_der)
        _require(engine._sha256(resource_path) == resource['sha256'])
    _require(engine._sha256(chrome) == spec['sha256']
             and not (destination / 'manifest.json').exists()
             and engine._inventory(destination) == (expected, directories)
             and engine._inventory(source) == (files, directories))
    return fixture._inside(destination / executable.name, root), expected, directories


def _launch_core(argument, core, fixture, root):
    return fixture._launch_core(argument, core, root)


def _snapshot(connection, session, record, storage, continuity):
    expression = continuity._EXPRESSION.replace(
        'FONT_NAMES', json.dumps(continuity._font_names(record), ensure_ascii=False))
    samples = [continuity._normalize_sample(storage._evaluate(connection, session, expression))
               for _ in range(2)]
    merged = continuity._merge_samples(*samples)
    expected = record['_continuity']['stable']
    _require(set(expected) <= merged['values'].keys()
             and not set(expected).intersection(merged['unstable']))
    return {'values': {field: merged['values'][field] for field in expected},
            'unavailable': merged['unavailable']}


def _changed(first, second, continuity):
    return sorted(field for field in first.keys() | second.keys()
                  if continuity._safe_field(field)
                  and (field not in first or field not in second or first[field] != second[field]))


def _close_owned(controller, original_close, owned, profile, fixture):
    """A matching live Popen observation is the only authority to close."""
    from browser_processes import profile_processes
    runtime = controller.profiles[fixture.IDENTITY]
    eligible = [grant for grant in owned
                if grant['controller'] is controller and grant['process'].poll() is None
                and grant['profile'] == profile
                and grant['core'] == Path(runtime['core_path']).resolve()
                and grant['signature'] == Path(runtime['fingerprint_path']).resolve()]
    if not eligible:
        _require(not profile_processes(profile, require_inspectable=True))
        return
    _require(len(eligible) == 1
             and controller.state.get(fixture.IDENTITY, {}).get('pid') == eligible[0]['process'].pid)
    with patch.object(controller, '_adopt', return_value=False):
        original_close(fixture.IDENTITY)


def _write_report(root, report, fixture):
    destination = fixture._inside(
        root / 'analysis/reports/vendor-runtime-comparison.json', root, exists=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fixture._inside(destination.parent, root)
    descriptor, name = tempfile.mkstemp(prefix='.vendor-runtime-', suffix='.tmp', dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        fixture._inside(destination, root, exists=False)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    if not parser.parse_args(argv).execute:
        print(json.dumps({'executed': False, 'requires_execute': True}))
        return 0
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tools')]
    report = {'success': False, 'executed': True, 'diagnostic_only': True,
              'device_compatibility_not_accepted': True, 'continuity_gate_enforced': False,
              'checks': {}, 'rounds': []}
    fixture = storage = server = server_thread = None
    profile = data = saved = binding = vendor_signature = vendor_digest = None
    stock_core = stock_files = stock_directories = None
    controllers, owned, snapshots = [], [], {}
    active_controller = None
    validated = False
    try:
        import verify_portable_fixture as fixture
        import verify_login_storage as storage
        _require(fixture.ROOT.resolve() == ROOT and storage.ROOT.resolve() == ROOT)
        import app_paths
        _require(app_paths.APP_ROOT.resolve() == (ROOT / 'app').resolve())
        marker, record, data, profile = fixture.load_fixture(ROOT, allow_session_cookie=True)
        validated = True
        report['checks']['strict_fixture_validated'] = True
        from browser_processes import profile_processes
        from configuration import Configuration
        import browser_core
        import fingerprint_continuity as continuity
        import local_engine as engine
        import portable_browser
        from signature_lifetime import require_current_signature, runtime_signature_options
        _require(not profile_processes(profile, require_inspectable=True))
        storage._restoration_ready(record, profile, fixture, ROOT)
        saved = storage._protection(record, fixture, ROOT)
        expected = saved['baseline']['stable']
        _require(len(expected) == 46 and all(continuity._safe_field(field) for field in expected))
        binding_fields = ('core_path', 'core_major', 'core_sha256', 'signature_provider', 'signature_key_id')
        binding = {field: copy.deepcopy(record['_runtime'].get(field)) for field in binding_fields}
        _require(not record['_runtime'].get('local_proxy_mode')
                 and not record['_runtime'].get('local_proxy_port'))
        configuration = Configuration(data)
        _require(configuration.independent)
        require_current_signature(saved['signature'], core_major='148',
                                  **runtime_signature_options(record['_runtime'], data))
        _require(configuration.decode(saved['signature']) == saved['native'])
        vendor_signature = fixture._inside(ROOT / 'vendor-signature.bin', ROOT)
        _vendor_signature(vendor_signature, configuration, saved['native'])
        vendor_digest = browser_core.sha256(vendor_signature)
        report['checks']['both_signatures_match_same_native'] = True
        stock_core, stock_files, stock_directories = _stock_engine(record, fixture, ROOT)
        report['checks']['stock_core_exactly_restored'] = True
        original_popen = browser_core.subprocess.Popen

        def launch(arguments, *values, **options):
            _require(active_controller is not None and isinstance(arguments, (list, tuple))
                     and 1 < len(arguments) <= 128 and not options.get('shell')
                     and all(isinstance(argument, str) for argument in arguments))
            runtime = active_controller.profiles[fixture.IDENTITY]
            core = fixture._inside(runtime['core_path'], ROOT)
            signature = fixture._inside(runtime['fingerprint_path'], ROOT)
            _require(_launch_core(arguments[0], core, fixture, ROOT) == core
                     and (core, signature) in allowed)
            for switch, required in (
                ('--user-data-dir', str(profile)), ('--fingerprint-config', str(signature)),
                ('--remote-debugging-address', '127.0.0.1'),
                ('--proxy-server', 'http://127.0.0.1:1'),
                ('--host-resolver-rules', 'MAP * ~NOTFOUND, EXCLUDE localhost'),
            ):
                actual = [argument.split('=', 1)[1] for argument in arguments
                          if argument.startswith(switch + '=')]
                _require(actual == [required] and switch not in arguments)
            _require(_OFFLINE_ARGUMENTS <= set(arguments)
                     and arguments.count('--restore-last-session') == 1
                     and not any(argument.startswith((
                         '--no-proxy-server', '--proxy-bypass-list', '--load-extension',
                         '--website-', '--headless',
                     )) for argument in arguments)
                     and all(argument.startswith('--') for argument in arguments[1:]))
            _require(browser_core.sha256(core) == runtime['core_sha256']
                     and browser_core.sha256(signature) == runtime['fingerprint_sha256'])
            if signature == vendor_signature:
                _vendor_signature(signature, configuration, saved['native'])
            else:
                require_current_signature(signature, core_major='148',
                                          **runtime_signature_options(runtime, data))
            _require(not profile_processes(profile, require_inspectable=True))
            process = original_popen(arguments, *values, **options)
            owned.append({'process': process, 'profile': profile, 'core': core,
                          'signature': signature, 'controller': active_controller})
            return process

        allowed = {(Path(record['_runtime']['core_path']).resolve(), saved['signature']),
                   (stock_core, vendor_signature)}
        server = fixture._PageServer(('127.0.0.1', fixture.PORT), fixture._PageHandler)
        server_thread = threading.Thread(target=server.serve_forever,
                                         kwargs={'poll_interval': .1}, daemon=True)
        server_thread.start()
        with patch.object(browser_core.subprocess, 'Popen', side_effect=launch):
            for side in ('vendor', 'local'):
                runtime = copy.deepcopy(record['_runtime'])
                runtime.update(environment_args=[], initial_urls=[], open_urls_once=[])
                if side == 'vendor':
                    runtime.update(core_path=str(stock_core), core_sha256=browser_core.sha256(stock_core),
                                   fingerprint_path=str(vendor_signature), fingerprint_sha256=vendor_digest)
                    runtime.pop('signature_provider', None)
                    runtime.pop('signature_key_id', None)
                controller = browser_core.BrowserController(
                    data, settings={'windows': [runtime], 'persistent': False})
                original_close = controller.close

                def close_owned(identity, controller=controller, original_close=original_close):
                    _require(identity == fixture.IDENTITY)
                    _close_owned(controller, original_close, owned, profile, fixture)

                controller.close = close_owned
                controllers.append(controller)
                active_controller = controller
                rounds = []
                for round_number in (1, 2):
                    _require(not profile_processes(profile, require_inspectable=True))
                    portable_browser.prepare_profile(profile, record['_portable_crypt'])
                    before = len(owned)
                    controller.open(fixture.IDENTITY, offline_test=True)
                    _require(len(owned) == before + 1 and owned[-1]['controller'] is controller
                             and controller.state.get(fixture.IDENTITY, {}).get('pid')
                             == owned[-1]['process'].pid)
                    with browser_core.CDP(controller.endpoint(fixture.IDENTITY), timeout=8) as connection:
                        session = storage._origin_session(connection, fixture.ORIGIN)
                        try:
                            checks = storage._observe(connection, session, marker['marker'],
                                                      record['_native'], fixture.ORIGIN)
                            snapshot = _snapshot(connection, session, record, storage, continuity)
                            report['rounds'].append({'side': side, 'round': round_number,
                                                     'checks': checks, 'stable_field_count': len(snapshot['values'])})
                            _require(all(checks.values()))
                            rounds.append(snapshot)
                        finally:
                            connection.call('Target.detachFromTarget', {'sessionId': session})
                    controller.close(fixture.IDENTITY)
                    _require(not profile_processes(profile, require_inspectable=True)
                             and all(grant['process'].poll() is not None for grant in owned))
                    _, current, _, _ = fixture.load_fixture(ROOT, allow_session_cookie=True)
                    _require(all(storage._protection_checks(current, saved, fixture, ROOT).values()))
                    _require({field: current['_runtime'].get(field) for field in binding_fields} == binding)
                    storage._restoration_ready(current, profile, fixture, ROOT)
                merged = continuity._merge_samples(*rounds)
                report['checks'][side + '_stable_complete'] = (
                    not merged['unstable'] and set(merged['values']) == set(expected))
                _require(report['checks'][side + '_stable_complete'])
                snapshots[side] = merged['values']
            report['source_vs_vendor_changed_fields'] = _changed(expected, snapshots['vendor'], continuity)
            report['source_vs_local_changed_fields'] = _changed(expected, snapshots['local'], continuity)
            report['vendor_vs_local_changed_fields'] = _changed(snapshots['vendor'], snapshots['local'], continuity)
            report['source_baseline_matches_vendor'] = not report['source_vs_vendor_changed_fields']
            report['source_baseline_matches_local'] = not report['source_vs_local_changed_fields']
            report['checks']['same_device_vendor_local_46_fields_match'] = (
                not report['vendor_vs_local_changed_fields'])
            _require(report['checks']['same_device_vendor_local_46_fields_match'])
            state, _ = portable_browser._read_state(profile)
            report['checks']['current_wrapper_matches_fixture_key'] = hmac.compare_digest(
                portable_browser._unwrap(state.get('os_crypt', {}).get('encrypted_key')),
                portable_browser._private_key(record['_portable_crypt']))
            _require(report['checks']['current_wrapper_matches_fixture_key'])
            report['success'] = True
    except Exception as error:
        report['error_type'] = type(error).__name__
        report['frames'] = [{'file': Path(frame.filename).name, 'line': frame.lineno}
                            for frame in traceback.extract_tb(error.__traceback__)[-8:]]
    finally:
        for controller in controllers:
            try:
                controller.close(fixture.IDENTITY)
            except Exception as error:
                report['close_error_type'] = type(error).__name__
                report['success'] = False
        if owned:
            try:
                from browser_processes import profile_processes
                report['checks']['owned_processes_closed'] = (
                    all(grant['process'].poll() is not None for grant in owned)
                    and not profile_processes(profile, require_inspectable=True))
                report['success'] = report['success'] and report['checks']['owned_processes_closed']
            except Exception as error:
                report['process_check_error_type'] = type(error).__name__
                report['success'] = False
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
        if validated and saved is not None:
            try:
                _, current, _, _ = fixture.load_fixture(ROOT, allow_session_cookie=True)
                report['checks'].update(storage._protection_checks(current, saved, fixture, ROOT))
                report['checks']['original_core_binding_unchanged'] = (
                    {field: current['_runtime'].get(field) for field in binding} == binding)
                if vendor_signature is not None and vendor_digest is not None:
                    report['checks']['vendor_signature_unchanged'] = (
                        browser_core.sha256(fixture._inside(vendor_signature, ROOT)) == vendor_digest)
                if stock_core is not None:
                    report['checks']['stock_core_unchanged'] = (
                        not (stock_core.parent / 'manifest.json').exists()
                        and engine._inventory(stock_core.parent) == (stock_files, stock_directories))
                report['success'] = report['success'] and all(report['checks'].values())
            except Exception as error:
                report['protection_error_type'] = type(error).__name__
                report['success'] = False
        report['created_process_count'] = len(owned)
        if validated:
            try:
                _write_report(ROOT, report, fixture)
            except Exception as error:
                report['report_error_type'] = type(error).__name__
                report['success'] = False
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
