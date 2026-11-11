"""Verify login storage only in the authenticated synthetic release fixture.

No fixture is read without --execute. Seed once on the source Windows user,
then copy the package and verify normally. The explicit storage diagnostic
uses the same synthetic profile without accepting device compatibility.
"""
from __future__ import annotations

import argparse
import copy
import hmac
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import traceback
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def _require(condition):
    if not condition:
        raise ValueError()


def _evaluate(connection, session, expression):
    reply = connection.call('Runtime.evaluate', {
        'expression': expression, 'returnByValue': True, 'awaitPromise': True,
    }, session=session)
    _require(not reply.get('exceptionDetails'))
    return reply.get('result', {}).get('value')


def _origin_session(connection, origin):
    """Attach to a restored tab; never create or navigate a verification tab."""
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        pages = connection.call('Target.getTargets').get('targetInfos', [])
        targets = [page for page in pages if page.get('type') == 'page'
                   and page.get('url') in (origin, origin + '/')]
        _require(len(targets) <= 1)
        if targets:
            session = connection.call('Target.attachToTarget', {
                'targetId': targets[0]['targetId'], 'flatten': True,
            })['sessionId']
            try:
                while time.monotonic() < deadline:
                    if _evaluate(connection, session,
                                 'location.origin===' + json.dumps(origin)
                                 + '&&document.readyState==="complete"') is True:
                        return session
                    time.sleep(.1)
            except Exception:
                connection.call('Target.detachFromTarget', {'sessionId': session})
                raise
            connection.call('Target.detachFromTarget', {'sessionId': session})
            break
        time.sleep(.1)
    raise ValueError()


def _indexed_db_expression(marker, *, seed=False):
    # A missing database is not created by the read path: abort its upgrade.
    return """new Promise(resolve => {
      let db=null, finished=false, value;
      const finish=okay => {
        if(finished)return; finished=true; clearTimeout(timer);
        if(db)db.close(); resolve(okay===true);
      };
      const timer=setTimeout(()=>finish(false),5000);
      const request=indexedDB.open('portable_login',1);
      request.onblocked=()=>finish(false);
      request.onerror=event=>{event.preventDefault();finish(false);};
      request.onupgradeneeded=()=>{
        if(finished||!SEED){request.transaction.abort();return;}
        if(!request.result.objectStoreNames.contains('tokens'))
          request.result.createObjectStore('tokens');
      };
      request.onsuccess=()=>{
        db=request.result;
        if(finished){db.close();return;}
        if(!db.objectStoreNames.contains('tokens')){finish(false);return;}
        try{
          const tx=db.transaction('tokens',SEED?'readwrite':'readonly');
          const store=tx.objectStore('tokens');
          const operation=SEED?store.put(MARKER,'session'):store.get('session');
          operation.onsuccess=()=>{value=operation.result;};
          tx.oncomplete=()=>finish(SEED||value===MARKER);
          tx.onabort=()=>finish(false);
          tx.onerror=()=>finish(false);
        }catch(_){finish(false);}
      };
    })""".replace('SEED', 'true' if seed else 'false').replace('MARKER', json.dumps(marker))


def _observe(connection, session, marker, native, origin, *, with_session=True):
    expression = ('({local:localStorage.getItem("portable_release")===' + json.dumps(marker)
                  + ',session:sessionStorage.getItem("portable_session")===' + json.dumps(marker)
                  + ',ua:navigator.userAgent===' + json.dumps(native['userAgent'])
                  + ',cpu:navigator.hardwareConcurrency==='
                  + json.dumps(native['navigator']['hardwareConcurrency']) + '})')
    values = _evaluate(connection, session, expression)
    _require(isinstance(values, dict))
    cookies = connection.call('Storage.getCookies').get('cookies', [])
    expected = {'portable_release', 'portable_session'} if with_session else {'portable_release'}
    _require(isinstance(cookies, list) and len(cookies) == len(expected))
    _require(all(cookie.get('name') in expected
                 and cookie.get('domain') in ('localhost', '.localhost')
                 and cookie.get('path') == '/' for cookie in cookies))
    by_name = {name: [cookie for cookie in cookies if cookie.get('name') == name]
               for name in expected}
    checks = {
        'persistent_cookie_preserved': len(by_name['portable_release']) == 1
        and by_name['portable_release'][0].get('value') == marker
        and by_name['portable_release'][0].get('session') is False,
        'local_storage_preserved': values.get('local') is True,
        'user_agent_matches_native': values.get('ua') is True,
        'hardware_concurrency_matches_native': values.get('cpu') is True,
    }
    if with_session:
        session_cookies = by_name['portable_session']
        checks.update({
            'session_cookie_preserved': len(session_cookies) == 1
            and session_cookies[0].get('value') == marker
            and session_cookies[0].get('session') is True,
            'session_storage_restored': values.get('session') is True,
            'indexed_db_preserved': _evaluate(
                connection, session, _indexed_db_expression(marker)) is True,
        })
    return checks


def _protection(record, fixture, root):
    from browser_core import sha256
    runtime = record['_runtime']
    signature = fixture._inside(runtime['fingerprint_path'], root)
    digest = sha256(signature)
    _require(runtime.get('fingerprint_sha256') == digest)
    return {'native': copy.deepcopy(record['_native']),
            'baseline': copy.deepcopy(record['_continuity']),
            'signature': signature, 'sha256': digest,
            'core_sha256': runtime['core_sha256']}


def _protection_checks(record, saved, fixture, root):
    from browser_core import sha256
    runtime = record['_runtime']
    signature = fixture._inside(runtime['fingerprint_path'], root)
    return {
        'native_unchanged': record.get('_native') == saved['native'],
        'baseline_unchanged': record.get('_continuity') == saved['baseline'],
        'signature_unchanged': signature == saved['signature']
        and runtime.get('fingerprint_sha256') == saved['sha256']
        and sha256(signature) == saved['sha256'],
        'core_binding_unchanged': runtime.get('core_sha256') == saved['core_sha256'],
    }


def _saved_session_exists(profile, fixture, root):
    folder = fixture._inside(profile / 'Default/Sessions', root)
    _require(folder.is_dir() and any(
        item.name.startswith('Session_') and fixture._inside(item, root).is_file()
        and item.stat().st_size > 8 for item in folder.iterdir()))


def _restoration_ready(record, profile, fixture, root):
    _require(record.get('preferences', {}).get('restore_session') is True
             and record['_runtime'].get('restore_session') is True
             and not record['_runtime'].get('open_urls_once')
             and not record.get('_prefs_dirty'))
    _saved_session_exists(profile, fixture, root)


def _owned_close(controller, profile, owned, identity):
    eligible = {process.pid for process, path in owned
                if path == profile and process.poll() is None}
    state = controller.state.get(identity, {})
    if state.get('pid') in eligible:
        controller.close(identity)


def _write_report(root, report, fixture):
    destination = fixture._inside(root / 'analysis/reports/login-storage.json', root, exists=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix='.login-storage-', suffix='.tmp', dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--package', type=Path, default=ROOT)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--seed', action='store_true')
    modes.add_argument('--verify', action='store_true')
    modes.add_argument('--storage-only-diagnostic', action='store_true')
    options = parser.parse_args(argv)
    if not options.execute:
        print(json.dumps({'executed': False, 'requires_execute': True}))
        return 0

    sys.dont_write_bytecode = True
    root = options.package.absolute()
    # Import application modules from the selected package, so default paths in
    # dependencies cannot resolve to the developer's real application data.
    sys.path[:0] = [str(root / 'app'), str(root / 'tools')]
    report = {'success': False, 'executed': True, 'seed_only': options.seed,
              'diagnostic_only': options.storage_only_diagnostic,
              'device_compatibility_not_accepted': options.seed or options.storage_only_diagnostic,
              'continuity_gate_enforced': not options.seed and not options.storage_only_diagnostic,
              'checks': {}, 'rounds': [], 'continuity_rounds': []}
    fixture = service = controller = server = server_thread = None
    profile = data = saved = None
    validated = False
    owned = []
    try:
        import verify_portable_fixture as fixture
        _require(fixture.ROOT.resolve() == root.resolve())
        fixture.fixture_marker(root)
        import app_paths
        _require(app_paths.APP_ROOT.resolve() == (root / 'app').resolve())
        marker, record, data, profile = fixture.load_fixture(
            root, **({} if options.seed else {'allow_session_cookie': True}))
        validated = True
        report['checks']['strict_fixture_validated'] = True
        from browser_processes import profile_processes
        from manager_service import ManagerService
        from configuration import Configuration
        from window_store import WindowStore
        import browser_core
        import fingerprint_continuity as continuity
        import portable_browser
        _require(not profile_processes(profile, require_inspectable=True))
        saved = _protection(record, fixture, root)
        _require(len(saved['baseline']['stable']) == 46)
        original_state,_=portable_browser._read_state(profile)
        try:
            original_key=portable_browser._unwrap(original_state.get('os_crypt',{}).get('encrypted_key'))
            report['source_wrapper_decryptable']=True
            _require(hmac.compare_digest(original_key,portable_browser._private_key(record['_portable_crypt'])))
        except browser_core.LocalBrowserError:report['source_wrapper_decryptable']=False
        if os.environ.get('GITHUB_ACTIONS')=='true':_require(not report['source_wrapper_decryptable'])
        if not options.seed:
            _restoration_ready(record, profile, fixture, root)
        else:
            _saved_session_exists(profile, fixture, root)
            _require(os.environ.get('GITHUB_ACTIONS') != 'true')
            state, _ = portable_browser._read_state(profile)
            original_key = portable_browser._unwrap(state.get('os_crypt', {}).get('encrypted_key'))
            _require(hmac.compare_digest(original_key, portable_browser._private_key(record['_portable_crypt'])))
        original_popen = browser_core.subprocess.Popen
        original_verify = continuity.verify_continuity

        def verify(*values, **kwargs):
            _require(kwargs.get('allow_device_variance') is True)
            result = original_verify(*values, **kwargs)
            _require(result.get('passed') is True and result.get('verification_policy')
                     in ('strict', 'vendor-compatible-' + fixture.CORE))
            report['continuity_rounds'].append({key: result[key] for key in (
                'verification_policy', 'device_variance_fields', 'environment_args')})
            return result

        def launch(arguments, *values, **kwargs):
            _require(isinstance(arguments, (list, tuple)) and not kwargs.get('shell'))
            core = fixture._current_core(record, store, controller, data, root)
            _require(fixture._launch_core(arguments[0], core, root) == core)
            profiles = [str(arg).split('=', 1)[1] for arg in arguments
                        if str(arg).startswith('--user-data-dir=')]
            _require(len(profiles) == 1)
            launched = fixture._inside(profiles[0], root)
            probe = (launched.name == 'profile' and launched.parent.parent == data
                     and launched.parent.name.startswith('continuity-probe-'))
            _require(launched == profile or probe and report['continuity_gate_enforced'])
            _require('--disable-background-networking' in arguments
                     and '--proxy-server=http://127.0.0.1:1' in arguments)
            if launched == profile:
                _require('--restore-last-session' in arguments
                         and not any(str(arg).startswith(('http://', 'https://', 'file:')) for arg in arguments))
            process = original_popen(arguments, *values, **kwargs)
            owned.append((process, launched))
            return process

        server = fixture._PageServer(('127.0.0.1', fixture.PORT), fixture._PageHandler)
        server_thread = threading.Thread(target=server.serve_forever,
                                         kwargs={'poll_interval': .1}, daemon=True)
        server_thread.start()
        with patch.object(browser_core.subprocess, 'Popen', side_effect=launch), \
                patch.object(continuity, 'verify_continuity', side_effect=verify):
            if options.seed or options.storage_only_diagnostic:
                store = WindowStore(Configuration(data), data)
                if options.seed:
                    portable_browser.prepare_profile(profile, record['_portable_crypt'])
                    updated = store.get(fixture.IDENTITY)
                    updated['preferences']['restore_session'] = True
                    updated['_runtime']['restore_session'] = True
                    updated['urls'] = [fixture.ORIGIN]
                    updated['_runtime']['initial_urls'] = [fixture.ORIGIN]
                    updated['_runtime'].pop('open_urls_once', None)
                    store.put(updated)
                    _restoration_ready(updated, profile, fixture, root)
                runtime = copy.deepcopy(store.get(fixture.IDENTITY)['_runtime'])
                runtime.pop('open_urls_once', None)
                controller = browser_core.BrowserController(
                    data, settings={'windows': [runtime], 'persistent': False})
            else:
                service = ManagerService(data)
                _require(service.configuration.independent)
                controller, store = service.controller, service.store
            _require(all(_protection_checks(store.get(fixture.IDENTITY), saved, fixture, root).values()))

            for _ in range(1 if options.seed else 2):
                _require(not profile_processes(profile, require_inspectable=True))
                if options.seed:
                    controller.open(fixture.IDENTITY, offline_test=True)
                elif options.storage_only_diagnostic:
                    portable_browser.prepare_profile(profile, record['_portable_crypt'])
                    controller.open(fixture.IDENTITY, offline_test=True)
                else:
                    service.open(fixture.IDENTITY, offline_test=True)
                with browser_core.CDP(controller.endpoint(fixture.IDENTITY), timeout=8) as connection:
                    session = _origin_session(connection, fixture.ORIGIN)
                    try:
                        if options.seed:
                            _require(all(_observe(connection, session, marker['marker'], record['_native'],
                                                  fixture.ORIGIN, with_session=False).values()))
                            connection.call('Storage.setCookies', {'cookies': [{
                                'name': 'portable_session', 'value': marker['marker'],
                                'url': fixture.ORIGIN, 'path': '/', 'secure': False,
                                'httpOnly': False, 'sameSite': 'Lax',
                            }]})
                            _require(_evaluate(connection, session,
                                'sessionStorage.setItem("portable_session",' + json.dumps(marker['marker']) + ');true') is True)
                            _require(_evaluate(connection, session,
                                               _indexed_db_expression(marker['marker'], seed=True)) is True)
                        checks = _observe(connection, session, marker['marker'], record['_native'], fixture.ORIGIN)
                        report['rounds'].append(checks)
                        _require(all(checks.values()))
                    finally:
                        connection.call('Target.detachFromTarget', {'sessionId': session})
                _owned_close(controller, profile, owned, fixture.IDENTITY)
                _require(not profile_processes(profile, require_inspectable=True))
                current = store.get(fixture.IDENTITY)
                _restoration_ready(current, profile, fixture, root)
                report['checks'].update(_protection_checks(current, saved, fixture, root))
                _require(all(report['checks'].values()))
                # Reauthenticate closed storage, including empty Login Data and
                # exactly the two synthetic cookies, after every cold round.
                fixture.load_fixture(root, allow_session_cookie=True)
            report['checks']['seed_completed' if options.seed else 'two_cold_reopens_passed'] = True
            if report['continuity_gate_enforced']:
                report['checks']['production_continuity_checked_twice'] = len(report['continuity_rounds']) == 2
                _require(report['checks']['production_continuity_checked_twice'])
            current_state,_=portable_browser._read_state(profile)
            current_key=portable_browser._unwrap(current_state.get('os_crypt',{}).get('encrypted_key'))
            report['checks']['current_wrapper_matches_fixture_key']=hmac.compare_digest(
                current_key,portable_browser._private_key(record['_portable_crypt']))
            _require(report['checks']['current_wrapper_matches_fixture_key'])
            report['success'] = True
    except Exception as error:
        report['error_type'] = type(error).__name__
        report['frames'] = [{'file': Path(frame.filename).name, 'line': frame.lineno}
                            for frame in traceback.extract_tb(error.__traceback__)[-8:]]
    finally:
        if controller is not None and profile is not None:
            try:
                _owned_close(controller, profile, owned, fixture.IDENTITY)
            except Exception as error:
                report['close_error_type'] = type(error).__name__
                report['success'] = False
        if owned:
            try:
                from browser_processes import profile_processes
                closed = all(process.poll() is not None for process, _ in owned)
                closed = closed and all(not profile_processes(path, require_inspectable=True)
                                        for path in {path for _, path in owned})
                report['checks']['owned_processes_closed'] = closed
                report['success'] = report['success'] and closed
            except Exception as error:
                report['process_check_error_type'] = type(error).__name__
                report['success'] = False
        if validated and saved is not None:
            try:
                _, current, _, _ = fixture.load_fixture(root, allow_session_cookie=not options.seed or bool(report['rounds']))
                report['checks'].update(_protection_checks(current, saved, fixture, root))
                report['success'] = report['success'] and all(report['checks'].values())
            except Exception as error:
                report['protection_error_type'] = type(error).__name__
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
        report['created_process_count'] = len(owned)
        if validated:
            try:
                _write_report(root, report, fixture)
            except Exception as error:
                report['report_error_type'] = type(error).__name__
                report['success'] = False
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
