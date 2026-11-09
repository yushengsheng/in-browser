"""Compare one private profile's original SOCKS5 and production local relay.

Only an unauthenticated GET / of the authorized page origin is requested. No
cookies, account requests, authorization headers, query, redirect or browser is
used. Private input travels only through local memory/anonymous child pipes.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

WORK = Path(__file__).resolve().parent
ATTEMPT_TIMEOUT = 15
HANDSHAKE_TIMEOUT = 8
MAX_HEADERS = 32768


class DiagnosticError(Exception):
    pass


def require(value):
    if not value:
        raise DiagnosticError()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def socket_budget(connection, deadline, maximum=HANDSHAKE_TIMEOUT):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    connection.settimeout(min(maximum, remaining))


def headers(connection, deadline):
    value = bytearray()
    while b'\r\n\r\n' not in value:
        socket_budget(connection, deadline)
        part = connection.recv(1)
        if not part:
            raise ConnectionError()
        value.extend(part)
        require(len(value) <= MAX_HEADERS)
    line = bytes(value).split(b'\r\n', 1)[0].split()
    require(len(line) >= 2 and line[0].startswith(b'HTTP/') and len(line[1]) == 3 and line[1].isdigit())
    code = int(line[1])
    require(100 <= code <= 599)
    return code


def attempt(payload):
    began = time.monotonic()
    deadline = began + ATTEMPT_TIMEOUT - .3
    mode = payload['mode']
    stage = 'input'
    connection = None
    result = {'mode': mode, 'stage': stage, 'seconds': 0, 'statusclass': None, 'error_type': None}
    guard = threading.Lock()
    timer = None
    finished = False

    def stage_timeout(expected_stage):
        # This callback exists only in the isolated request child. A process
        # boundary also limits DNS and multi-message SOCKS/TLS handshakes which
        # can outlast an individual socket timeout.
        nonlocal finished
        with guard:
            if finished or stage != expected_stage:
                return
            finished = True
            row = {'mode': mode, 'stage': stage, 'seconds': round(time.monotonic() - began, 3),
                   'statusclass': None, 'error_type': 'TimeoutError'}
            os.write(1, canonical(row) + b'\n')
            os._exit(0)

    def progress(value):
        nonlocal stage, timer
        if timer is not None:
            timer.cancel()
        stage = value
        print(json.dumps({'mode': mode, 'stage': stage}), flush=True)
        timer = threading.Timer(min(HANDSHAKE_TIMEOUT, max(.001, deadline - time.monotonic())), stage_timeout, args=(stage,))
        timer.daemon = True
        timer.start()

    try:
        host, port = payload['host'], payload['port']
        authority = ('[' + host + ']' if ':' in host else host) + (':' + str(port) if port != 443 else '')
        require(isinstance(host, str) and host and not any(c in host for c in '\r\n\x00') and type(port) is int and 0 < port < 65536)
        if mode == 'upstream_socks5':
            import socks
            proxy = payload['proxy']
            require(proxy.get('type') == 'socks5')
            progress('socks_handshake')
            connection = socks.socksocket()
            connection.set_proxy(socks.SOCKS5, proxy['host'], int(proxy['port']), rdns=True,
                                 username=proxy.get('username') or None, password=proxy.get('password') or None)
            socket_budget(connection, deadline)
            connection.connect((host, port))
        elif mode == 'production_relay':
            progress('relay_tcp')
            connection = socket.create_connection(('127.0.0.1', payload['relay_port']), timeout=min(HANDSHAKE_TIMEOUT, deadline - time.monotonic()))
            progress('relay_connect')
            connect_authority = ('[' + host + ']' if ':' in host else host) + ':' + str(port)
            socket_budget(connection, deadline)
            connection.sendall(('CONNECT ' + connect_authority + ' HTTP/1.1\r\nHost: ' + connect_authority + '\r\n\r\n').encode('ascii'))
            status = headers(connection, deadline)
            if status != 200:
                result['statusclass'] = str(status // 100) + 'xx'
                raise DiagnosticError()
        else:
            raise DiagnosticError()
        progress('tls_handshake')
        socket_budget(connection, deadline)
        connection = ssl.create_default_context().wrap_socket(connection, server_hostname=host)
        progress('http_headers')
        socket_budget(connection, deadline)
        connection.sendall(('GET / HTTP/1.1\r\nHost: ' + authority + '\r\nUser-Agent: InBrowserNetworkDiagnostic/1\r\n'
                            'Accept: */*\r\nConnection: close\r\n\r\n').encode('ascii'))
        status = headers(connection, deadline)
        result.update(stage='complete', statusclass=str(status // 100) + 'xx')
    except Exception as error:
        result.update(stage=stage, error_type=type(error).__name__)
    finally:
        with guard:
            finished = True
            if timer is not None:
                timer.cancel()
        if connection is not None:
            connection.close()
    result['seconds'] = round(time.monotonic() - began, 3)
    return result


def bounded_attempt(payload):
    began = time.monotonic()
    child = subprocess.Popen([sys.executable, '-B', '-E', str(Path(__file__).resolve()), '--worker'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    output = b''
    timed_out = False
    try:
        output, _ = child.communicate(canonical(payload), timeout=ATTEMPT_TIMEOUT)
    except subprocess.TimeoutExpired:
        timed_out = True
        child.kill()
        output, _ = child.communicate()
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()
    require(len(output) <= 16384)
    rows = [json.loads(line) for line in output.decode('utf-8').splitlines() if line.strip()]
    if timed_out:
        return {'mode': payload['mode'], 'stage': rows[-1].get('stage', 'worker_start') if rows else 'worker_start',
                'seconds': round(time.monotonic() - began, 3), 'statusclass': None, 'error_type': 'TimeoutError'}
    require(child.returncode == 0 and rows)
    result = rows[-1]
    require(set(result) == {'mode', 'stage', 'seconds', 'statusclass', 'error_type'})
    result['seconds'] = round(time.monotonic() - began, 3)
    return result


def run(root):
    # The selected isolated package owns all defaults in the imported modules.
    sys.path[:0] = [str(root / 'app'), str(root / 'tools')]
    from inspect_installation import read_catalog
    from browser_processes import profile_processes
    from proxy_runtime import ProxyRuntime
    from proxy_config import normalize_proxy
    from verify_private_session import load_marker, prepare_service
    from manager_service import ManagerService
    marker = load_marker(root)
    data = root / 'app/data'
    before = read_catalog(data, time.monotonic() + 60)
    require(before['quick_check'] and len(before['records']) == 1)
    service, profile, _ = prepare_service(data, marker, before['records'][0], profile_processes, ManagerService)
    before = read_catalog(data, time.monotonic() + 60)
    record = service.store.all()[0]
    require(not profile_processes(profile, require_inspectable=True))
    saved = digest(record)
    parsed = urlsplit(marker['target_origin'])
    require(parsed.scheme == 'https' and parsed.hostname and parsed.path in ('', '/') and not parsed.query and not parsed.fragment)
    proxy = normalize_proxy(record['proxy'])
    require(proxy['type'] == 'socks5')
    report = {'success': False, 'browser_started': False, 'public_get_only': True, 'authentication_test': False,
              'rounds': [], 'workers_closed': False, 'record_unchanged': False}
    runtime = ProxyRuntime(data)
    prior = runtime.state(record['id'])
    require(not prior or not runtime.owned(prior))
    owned = None
    worker_started = None
    try:
        for _ in range(3):
            require(not profile_processes(profile, require_inspectable=True))
            payload = {'mode': 'upstream_socks5', 'host': parsed.hostname, 'port': parsed.port or 443, 'proxy': proxy}
            direct = bounded_attempt(payload)
            report['rounds'].append(direct)
            print(json.dumps(direct), flush=True)
            require(not profile_processes(profile, require_inspectable=True))
            worker_started = time.time()
            owned = runtime.ensure(copy.deepcopy(record))
            require(owned and runtime.owned(owned) and runtime.control(owned))
            try:
                relayed = bounded_attempt({'mode': 'production_relay', 'host': parsed.hostname, 'port': parsed.port or 443,
                                           'relay_port': owned['port']})
                report['rounds'].append(relayed)
                print(json.dumps(relayed), flush=True)
            finally:
                require(not profile_processes(profile, require_inspectable=True))
                runtime.stop_if_unused(record['id'])
                require(not runtime.owned(owned))
                owned = None
                worker_started = None
        report['success'] = len(report['rounds']) == 6
    finally:
        current = runtime.state(record['id'])
        if owned is None and worker_started is not None and current and runtime.owned(current):
            # ensure may have published a worker before reporting readiness
            # failure. No live worker existed at entry; creation time and exact
            # runtime ownership identify only this invocation's child.
            require(current.get('created', 0) >= worker_started)
            owned = current
        if owned and runtime.owned(owned):
            require(not profile_processes(profile, require_inspectable=True))
            runtime.stop_if_unused(record['id'])
        current = runtime.state(record['id'])
        report['workers_closed'] = not current or not runtime.owned(current)
        after = read_catalog(data, time.monotonic() + 60)
        report['record_unchanged'] = (after['catalog_full_tables_sha256'] == before['catalog_full_tables_sha256']
                                      and len(after['records']) == 1 and digest(after['records'][0]) == saved)
        report['browser_started'] = False
        report['success'] &= report['workers_closed'] and report['record_unchanged']
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--report', type=Path, default=WORK / 'private-network-diagnostic.json')
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    try:
        if args.worker:
            raw = sys.stdin.buffer.read(65537)
            require(len(raw) <= 65536)
            result = attempt(json.loads(raw))
            print(json.dumps(result), flush=True)
            return 0
        if not args.execute:
            print(json.dumps({'executed': False}))
            return 0
        root = args.package
        require(root is not None)
        result = run(root.resolve())
    except Exception as error:
        result = {'success': False, 'error_type': type(error).__name__, 'browser_started': False}
    try:
        args.report.write_text(json.dumps(result, indent=2), encoding='utf-8')
    except Exception as error:
        result['success'] = False
        result['report_error_type'] = type(error).__name__
    print(json.dumps(result), flush=True)
    return 0 if result.get('success') else 1


if __name__ == '__main__':
    raise SystemExit(main())
