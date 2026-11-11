"""Explicit 124/148 browser proxy acceptance in a marked synthetic installation.

Browsers visit only local fixtures through authenticated HTTP/SOCKS5 proxies.
Initial synthetic creation may fetch Google's public signed variations seed.
No real account catalog, account profile, or supplied proxy pool is read.
"""
import argparse
from contextlib import ExitStack, contextmanager
import copy
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]


def finish_creations(jobs, identities, *, timeout=45):
    """Cancel only owned jobs; keep the active item and its processes observable."""
    deadline = time.monotonic() + timeout
    failed = False
    threads = []
    for creator, job_id in reversed(jobs):
        try:
            status = creator.status(job_id, missing_ok=True)
            if status and status['state'] in ('running', 'failed', 'interrupted'):
                creator.cancel(job_id)
        except Exception:
            failed = True
            try:
                creator.cancel(job_id)
            except Exception:
                pass
        try:
            thread = creator.thread
            if thread is not None and thread not in threads:
                threads.append(thread)
                thread.join(timeout=max(0, deadline - time.monotonic()))
        except Exception:
            failed = True
        try:
            status = creator.status(job_id, missing_ok=True)
            for item in (status or {}).get('items', []):
                if item.get('state') == 'completed' and item.get('id') and item['id'] not in identities:
                    identities.append(item['id'])
        except Exception:
            failed = True
    pending = sum(thread.is_alive() for thread in threads)
    return {'creation_cleanup_failed': failed, 'creation_threads_remaining': pending,
            'creation_workers_stopped': not failed and pending == 0}


def close_owned_profiles(service, identities, *, creation_stopped):
    if not creation_stopped:
        # A creator can hold service.operations while finishing the current item.
        # Do not acquire that lock after the bounded creator wait has expired.
        return {'normal_close_deferred': True, 'normal_close_failed': False}
    failed = False
    if service is not None:
        for identity in identities:
            try:
                service.close(identity)
            except Exception:
                failed = True
    return {'normal_close_deferred': False, 'normal_close_failed': failed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--cores', default='124,148')
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({'executed': False}))
        return 0
    report = {'success': False, 'synthetic': True, 'browser_network_loopback_only': True,
              'creation_public_seed_network_allowed': True, 'checks': {}, 'results': []}
    service = None
    servers = []
    identities = []
    processes = []
    creation_jobs = []
    fixture = None

    def check(name, value, row=None):
        (report['checks'] if row is None else row['checks'])[name] = bool(value)
        if not value:
            raise AssertionError(name)

    def failure(error):
        result = {'error_type': type(error).__name__, 'frames': [
            {'file': Path(frame.filename).name, 'line': frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)[-8:]]}
        known_checks = set(report['checks']) | {name for row in report['results'] for name in row['checks']}
        if isinstance(error, AssertionError) and error.args and isinstance(error.args[0], str) and error.args[0] in known_checks:
            result['failed_check'] = error.args[0]
        return result

    try:
        marker = ROOT / 'local-creation-test.json'
        if marker.is_symlink() or json.loads(marker.read_text(encoding='utf-8-sig')) != {
                'format': 1, 'purpose': 'isolated-local-creation'}:
            raise ValueError()
        data = ROOT / 'app/data'
        if data.is_symlink() or data.is_junction():
            raise ValueError()
        cores = args.cores.split(',')
        if not cores or any(core not in ('124', '148') for core in cores):
            raise ValueError()
        sys.path.insert(0, str(ROOT / 'app'))
        import browser_core
        import ip_info_page
        import psutil
        from browser_processes import profile_processes
        from creation_fingerprint import creation_defaults
        from installation import initialize_installation
        from manager_service import ManagerService

        existing = 0
        for process in psutil.process_iter(['cmdline']):
            try:
                for argument in process.info.get('cmdline') or []:
                    if str(argument).startswith('--user-data-dir=') and Path(str(argument).split('=', 1)[1]).resolve().is_relative_to(ROOT):
                        existing += 1
            except (psutil.Error, OSError, ValueError):
                pass
        report['preexisting_test_profile_process_count'] = existing
        check('isolated_installation_not_running', existing == 0)
        initialize_installation()
        service = ManagerService()
        check('catalog_empty_before_test', not service.store.all())

        specification = importlib.util.spec_from_file_location(
            'proxy_loopback_fixtures', ROOT / 'analysis/browser-proxy-boundary-regression.py')
        fixture = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(fixture)
        origin = fixture.start(fixture.ThreadingHTTPServer(('127.0.0.1', 0), fixture.Origin))
        direct = fixture.start(fixture.ThreadingHTTPServer(('127.0.0.1', 0), fixture.Origin))
        http = fixture.start(fixture.ThreadingHTTPServer(('127.0.0.1', 0), fixture.Proxy))
        socks = fixture.start(fixture.TCP(('127.0.0.1', 0), fixture.Socks))
        servers.extend((origin, direct, http, socks))
        for server in servers:
            server.daemon_threads = True
        local_url = f'http://{fixture.DOMAIN}:{origin.server_port}'
        service.configuration._proxy_targets = [{'name': 'synthetic loopback', 'url': local_url + '/ip'}]

        popen = browser_core.subprocess.Popen

        def launch(arguments, *values, **options):
            profiles = [str(argument).split('=', 1)[1] for argument in arguments
                        if str(argument).startswith('--user-data-dir=')]
            if profiles and (len(profiles) != 1 or not Path(profiles[0]).resolve().is_relative_to(data)):
                raise ValueError()
            process = popen(arguments, *values, **options)
            worker = any(Path(str(argument)).name == 'proxy_runtime.py' for argument in arguments)
            if profiles or worker:
                processes.append({'process': process, 'profile': Path(profiles[0]).resolve() if profiles else None})
            return process

        def pages(identity):
            with browser_core.CDP(service.controller.endpoint(identity)) as connection:
                return [item for item in connection.call('Target.getTargets').get('targetInfos', [])
                        if item.get('type') == 'page']

        def evaluate(identity, target, expression, *, wait_loaded=False):
            with browser_core.CDP(service.controller.endpoint(identity), timeout=15) as connection:
                session = connection.call('Target.attachToTarget', {'targetId': target, 'flatten': True})['sessionId']
                try:
                    if wait_loaded:
                        end = time.monotonic() + 12
                        while time.monotonic() < end:
                            ready = connection.call('Runtime.evaluate', {
                                'expression': 'document.readyState === "complete" && document.title === "Local proxy boundary"',
                                'returnByValue': True}, session=session)
                            if ready.get('result', {}).get('value'):
                                break
                            time.sleep(.1)
                    reply = connection.call('Runtime.evaluate', {
                        'expression': expression, 'awaitPromise': True, 'returnByValue': True}, session=session)
                    if reply.get('exceptionDetails'):
                        raise ValueError()
                    return reply.get('result', {}).get('value')
                finally:
                    connection.call('Target.detachFromTarget', {'sessionId': session})

        def create(core):
            profile = creation_defaults(core)
            profile.update(name='Synthetic loopback acceptance', urls=['about:blank'])
            profile['preferences']['restore_session'] = True
            profile['created_options']['workbench'] = 'localserver'
            creator = service.creator()
            job_id = uuid.uuid4().hex
            creation_jobs.append((creator, job_id))
            job = creator.start({'request_id': job_id, 'profile': profile, 'count': 1, 'random_each': True})
            deadline = time.monotonic() + 360
            while job['state'] == 'running' and time.monotonic() < deadline:
                time.sleep(.2)
                job = creator.status(job['job_id'])
            check('creation_' + core, job['state'] == 'completed' and job['completed'] == 1)
            identity = job['items'][0]['id']
            identities.append(identity)
            return identity

        @contextmanager
        def tracked_processes():
            guard = patch.object(browser_core.subprocess, 'Popen', side_effect=launch)
            guard.start()
            try:
                yield
            finally:
                report.update(finish_creations(creation_jobs, identities))
                # A timed-out daemon may still spawn a child before interpreter
                # shutdown. Leave tracking installed and report incomplete cleanup.
                if report['creation_workers_stopped']:
                    guard.stop()

        with tracked_processes():
            for core in cores:
                identity = create(core)
                for kind, upstream, handler in (('http', http, fixture.Proxy), ('socks5', socks, fixture.Socks)):
                    row = {'core': core, 'protocol': kind, 'success': False, 'checks': {}}
                    report['results'].append(row)
                    try:
                        record = service.store.get(identity)
                        record['proxy'] = {'type': kind, 'host': '127.0.0.1', 'port': upstream.server_address[1],
                                           'username': 'fixture', 'password': 'password', 'enable_socks5_udp': False}
                        service.store.put(record)
                        service._sync(record)
                        profile_path = Path(record['_runtime']['profile_path']).resolve()
                        native = copy.deepcopy(record['_native'])
                        baseline = copy.deepcopy(record['_continuity'])
                        info_path = '/info-' + core + '-' + kind
                        marker_path = '/session-' + core + '-' + kind
                        info_url, marker_url = local_url + info_path, local_url + marker_path
                        with ExitStack() as stack:
                            stack.enter_context(patch.object(ip_info_page, 'IP_INFO_URL', info_url))
                            stack.enter_context(patch.object(ip_info_page, '_INFO_URLS', frozenset((info_url,))))
                            service.open(identity)
                            listed = pages(identity)
                            check('one_information_tab_created', sum(item['url'] == info_url for item in listed) == 1, row)
                            target = next(item['targetId'] for item in listed if item['url'] == info_url)
                            loaded = evaluate(identity, target, 'document.title === "Local proxy boundary"', wait_loaded=True)
                            check('information_page_loaded_through_proxy', loaded and info_path in fixture.Origin.hits, row)
                            process_id = service.controller.state[identity]['pid']
                            deadline = time.monotonic() + 8
                            while not browser_core._visible_windows(process_id) and time.monotonic() < deadline:
                                time.sleep(.1)
                            check('browser_window_visible', bool(browser_core._visible_windows(process_id)), row)
                            with browser_core.CDP(service.controller.endpoint(identity)) as connection:
                                marker_target = connection.call('Target.createTarget', {'url': marker_url})['targetId']
                            marker_set = evaluate(identity, marker_target,
                                'sessionStorage.setItem("fixture_session", "retained"); document.title === "Local proxy boundary"', wait_loaded=True)
                            check('synthetic_session_set', marker_set, row)
                            result = evaluate(identity, marker_target,
                                "fetch('/data?fresh=' + Date.now()).then(r => r.json()).then(v => v.ok)")
                            check('browser_fetch_through_proxy', result is True, row)
                            before = pages(identity)
                            count = sum(item['profile'] == profile_path for item in processes)
                            service.open(identity)
                            after = pages(identity)
                            check('already_open_preserves_pid_and_tabs', process_id == service.controller.state[identity]['pid']
                                  and {item['targetId'] for item in before} == {item['targetId'] for item in after}
                                  and count == sum(item['profile'] == profile_path for item in processes), row)
                            before_hits = fixture.Origin.hits.count(info_path)
                            service.close(identity)
                            check('first_normal_close_complete', not profile_processes(profile_path), row)
                            service.open(identity)
                            listed = pages(identity)
                            check('reopen_has_one_information_tab', sum(item['url'] == info_url for item in listed) == 1, row)
                            marker_page = next((item for item in listed if item['url'] == marker_url), None)
                            check('session_tab_restored', marker_page is not None, row)
                            check('session_storage_restored', evaluate(identity, marker_page['targetId'],
                                  'sessionStorage.getItem("fixture_session") === "retained"', wait_loaded=True), row)
                            deadline = time.monotonic() + 5
                            while fixture.Origin.hits.count(info_path) <= before_hits and time.monotonic() < deadline:
                                time.sleep(.05)
                            check('reopen_information_request_through_proxy', fixture.Origin.hits.count(info_path) > before_hits, row)
                            forbidden = '/must-not-direct-' + uuid.uuid4().hex
                            handler.available = False
                            try:
                                direct_url = f'http://127.0.0.1:{direct.server_port}' + forbidden
                                expression = 'fetch(' + json.dumps(direct_url) + ').then(() => true).catch(() => false)'
                                result = evaluate(identity, marker_page['targetId'], expression)
                                check('failed_upstream_never_falls_back_direct', result is False and forbidden not in fixture.Origin.hits, row)
                            finally:
                                handler.available = True
                            service.close(identity)
                            check('second_normal_close_complete', not profile_processes(profile_path), row)
                            handler.available = False
                            try:
                                count = sum(item['profile'] == profile_path for item in processes)
                                hits = len(fixture.Origin.hits)
                                try:
                                    service.open(identity)
                                    refused = False
                                except browser_core.LocalBrowserError:
                                    refused = True
                                check('failed_proxy_refuses_new_browser_without_direct', refused
                                      and count == sum(item['profile'] == profile_path for item in processes)
                                      and hits == len(fixture.Origin.hits) and not profile_processes(profile_path), row)
                            finally:
                                handler.available = True
                            current = service.store.get(identity)
                            check('native_and_continuity_baseline_unchanged', current['_native'] == native
                                  and current['_continuity'] == baseline, row)
                        row['success'] = True
                    except Exception as error:
                        row.update(failure(error))
                    finally:
                        handler.available = True
                        try:
                            service.close(identity)
                        except Exception as error:
                            row['cleanup_error_type'] = type(error).__name__
                            row['success'] = False
                    print(json.dumps({'core': core, 'protocol': kind, 'passed': row['success']}), flush=True)
        check('socks_domain_forwarded_to_upstream', fixture.DOMAIN in fixture.Socks.domains)
        check('authenticated_http_requests_observed', bool(fixture.Proxy.requests))
        report['success'] = all(row['success'] for row in report['results'])
    except Exception as error:
        report.update(failure(error))
    finally:
        report.update(close_owned_profiles(service, identities,
                      creation_stopped=report.get('creation_workers_stopped', not creation_jobs)))
        if report['normal_close_failed'] or report['normal_close_deferred']:
            report['success'] = False
        deadline = time.monotonic() + 12
        while any(item['process'].poll() is None for item in processes) and time.monotonic() < deadline:
            time.sleep(.1)
        report['created_browser_and_worker_count'] = len(processes)
        report['remaining_created_process_count'] = sum(item['process'].poll() is None for item in processes)
        report['all_created_processes_closed_normally'] = report['remaining_created_process_count'] == 0 and report.get('creation_workers_stopped', not creation_jobs)
        report['success'] = report['success'] and report['all_created_processes_closed_normally']
        for server in servers:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                report['fixture_cleanup_failed'] = True
                report['success'] = False
        if fixture:
            report['fixture_request_counts'] = {'origin': len(fixture.Origin.hits),
                                                'authenticated_http': len(fixture.Proxy.requests),
                                                'socks_domain': len(fixture.Socks.domains)}
        destination = ROOT / 'analysis/reports/proxy-loopback-live.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(json.dumps(report))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
