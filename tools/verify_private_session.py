"""Explicit real-session acceptance in a single-profile authorized private copy.

private-acceptance.json belongs only in the encrypted private package. Digests use
UTF-8 JSON with ensure_ascii=False, sort_keys=True, separators=(',', ':'), and
allow_nan=False. The response URL digest excludes its query and fragment. Only
natural responses to reloading an existing, explicitly approved page are read.
No authentication request, login action, or business action is sent. On an
evidence timeout, fixed read-only JavaScript returns only page booleans/counts.
"""
import argparse
import base64
from collections import deque
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import traceback
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
MAX_BODY = 1024 * 1024
MAX_EVENTS = 2048
MAX_EVENT_BYTES = 4 * MAX_BODY
AUTH_TIMEOUT = 60
EVENTS = frozenset(('Network.requestWillBeSent', 'Network.responseReceived',
                    'Network.loadingFinished', 'Network.loadingFailed',
                    'Network.requestServedFromCache', 'Page.frameNavigated',
                    'Page.frameStoppedLoading', 'Page.loadEventFired', 'Page.domContentEventFired'))
NETWORK_ERRORS = frozenset(('net::ERR_ABORTED', 'net::ERR_FAILED', 'net::ERR_TIMED_OUT',
    'net::ERR_CONNECTION_CLOSED', 'net::ERR_CONNECTION_RESET', 'net::ERR_CONNECTION_REFUSED',
    'net::ERR_NAME_NOT_RESOLVED', 'net::ERR_INTERNET_DISCONNECTED', 'net::ERR_PROXY_CONNECTION_FAILED',
    'net::ERR_TUNNEL_CONNECTION_FAILED', 'net::ERR_CERT_AUTHORITY_INVALID', 'net::ERR_SSL_PROTOCOL_ERROR',
    'net::ERR_NETWORK_CHANGED', 'net::ERR_BLOCKED_BY_CLIENT', 'net::ERR_BLOCKED_BY_RESPONSE'))
_PAGE_DIAGNOSTIC = r'''(() => {
  const text = document.body ? document.body.textContent || "" : "";
  let localStorageCount = 0, localStorageAccessible = false;
  try { localStorageCount = localStorage.length; localStorageAccessible = true; } catch (_) {}
  return {readyComplete: document.readyState === "complete",
    hasPasswordInput: !!document.querySelector('input[type="password"]'),
    loginPrompt: /请(?:先)?登录|会话(?:已)?过期|登录(?:已)?过期|session expired|sign in|log in/i.test(text),
    trafficError: /系统流量异常高|网络(?:连接)?(?:异常|错误)|无法连接|连接失败|network error|connection failed|proxy error|traffic error/i.test(text),
    bodyEmpty: !text.trim(), iframeCount: document.querySelectorAll("iframe").length,
    localStorageAccessible, localStorageCount};
})()'''
DIAGNOSTIC_FIELDS = frozenset(('audio.offline audio.supported canvas.geometry canvas.text context.secure '
    'devices.kinds devices.supported fonts.metrics locale.options navigator.cookieEnabled '
    'navigator.deviceMemory navigator.hardwareConcurrency navigator.language navigator.languages '
    'navigator.maxTouchPoints navigator.platform navigator.userAgent navigator.vendor navigator.webdriver '
    'screen.availHeight screen.availWidth screen.colorDepth screen.devicePixelRatio screen.height '
    'screen.media screen.orientation screen.pixelDepth screen.width timezone.name uaData.high uaData.low '
    'uaData.supported webgl1.attributes webgl1.extensions webgl1.identity webgl1.limits webgl1.pixels '
    'webgl1.precision webgl1.supported webgl2.attributes webgl2.extensions webgl2.identity webgl2.limits '
    'webgl2.pixels webgl2.precision webgl2.supported baseline binding probe.server probe.navigation '
    'probe.secureContext probe.stability').split())


def error_diagnostics(error):
    """Classify locally; raw exceptions can contain proxy or account details."""
    fields = getattr(error, 'changed_fields', [])
    result = {'error_type': type(error).__name__, 'frames': [
        {'file': Path(frame.filename).name, 'line': frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)[-8:]]}
    if getattr(error, 'code', None) == 'ip_info_failed':
        operations = frozenset(('Target.getTargets', 'Target.attachToTarget', 'Page.reload',
            'Target.detachFromTarget', 'Target.createTarget', 'Target.closeTarget', 'Target.activateTarget'))
        causes = frozenset(('LocalBrowserError', 'OSError', 'TimeoutError', 'ConnectionError',
            'ConnectionResetError', 'ConnectionAbortedError', 'ConnectionRefusedError', 'BrokenPipeError',
            'WebSocketException', 'WebSocketTimeoutException', 'WebSocketConnectionClosedException',
            'WebSocketBadStatusException', 'JSONDecodeError', 'ValueError', 'TypeError', 'KeyError', 'RuntimeError'))
        result['reason_code'] = 'ip_info_failed'
        operation, cause = getattr(error, 'operation', None), getattr(error, 'cause_type', None)
        result['operation'] = operation if isinstance(operation, str) and operation in operations else 'unknown'
        result['cause_type'] = cause if isinstance(cause, str) and cause in causes else 'Exception'
        result['cleanup_failed'] = getattr(error, 'cleanup_failed', False) is True
        return result
    if getattr(error, 'code', None) == 'engine_path_too_long':
        result['reason_code'] = 'engine_path_too_long'
    if isinstance(fields, list) and fields:
        result['reason_code'] = 'continuity_gate'
        result['continuity_changed_fields'] = sorted({f for f in fields if isinstance(f, str) and f in DIAGNOSTIC_FIELDS})
    else:
        message = str(error)
        for prefix, code in (('代理检测未通过', 'proxy_check_failed'),
                             ('本地代理未就绪', 'proxy_runtime_unready'),
                             ('本地代理在检测期间退出', 'proxy_runtime_lost')):
            if message.startswith(prefix):
                result['reason_code'] = code
                break
    return result


class AcceptanceError(Exception):
    pass


class CommandRejected(AcceptanceError):
    pass


class EvidenceTimeout(AcceptanceError):
    pass


class OwnershipError(AcceptanceError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _json(raw):
    def invalid(_):
        raise ValueError()
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=invalid)


def origin(url):
    if not isinstance(url, str) or not 1 <= len(url) <= 16384:
        raise ValueError()
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or any(c in url for c in '\r\n\x00')):
        raise ValueError()
    host = parsed.hostname.lower()
    if ':' in host:
        host = '[' + host + ']'
    return 'https://' + host + (':' + str(parsed.port) if parsed.port not in (None, 443) else '')


def url_digest(url):
    origin(url)
    parsed = urlsplit(url)
    return hashlib.sha256(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', '')).encode('utf-8')).hexdigest()


def _route_digest(url):
    parsed = urlsplit(url)
    return hashlib.sha256(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', parsed.fragment)).encode('utf-8')).hexdigest()


def target_route(connection, target, marker):
    current = connection.call('Target.getTargetInfo', {'targetId': target})['targetInfo']
    if current.get('type') != 'page' or origin(current.get('url')) != marker['target_origin']:
        raise AcceptanceError()
    return _route_digest(current['url'])


def _hash(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def validate_marker(value):
    if (not isinstance(value, dict) or type(value.get('format')) is not int or value['format'] != 1
            or value.get('purpose') != 'authorized-private-session' or value.get('reload_safe') is not True
            or not isinstance(value.get('profile_id'), str)
            or not re.fullmatch('[A-Za-z0-9_-]{1,128}', value['profile_id'])
            or not _hash(value.get('expected_stable_sha256'))):
        raise ValueError()
    target = value.get('target_origin')
    if origin(target) != target:
        raise ValueError()
    if 'target_route_sha256' in value and not _hash(value['target_route_sha256']):
        raise ValueError()
    rule = value.get('auth_rule')
    if (not isinstance(rule, dict) or origin(rule.get('origin')) != rule['origin']
            or not _hash(rule.get('url_sha256')) or rule.get('method') not in ('GET', 'POST')
            or type(rule.get('status')) is not int or not 200 <= rule['status'] < 300):
        raise ValueError()
    matches = rule.get('json_matches')
    if not isinstance(matches, list) or not 1 <= len(matches) <= 8:
        raise ValueError()
    for match in matches:
        path = match.get('path') if isinstance(match, dict) else None
        if (not isinstance(path, list) or not 1 <= len(path) <= 16 or not _hash(match.get('sha256'))
                or any(not (isinstance(part, str) and 1 <= len(part) <= 100
                            or type(part) is int and 0 <= part <= 1000) for part in path)):
            raise ValueError()
    return value


def plain(path):
    path = Path(path)
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError()
    return path


def load_marker(root):
    path = plain(Path(root) / 'private-acceptance.json')
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 65536:
        raise ValueError()
    raw = path.read_bytes()
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError()
    return validate_marker(_json(raw.decode('utf-8-sig')))


def validate_identity(marker, record):
    runtime = record.get('_runtime') or {}
    baseline = record.get('_continuity') or {}
    stable = baseline.get('stable')
    if (record.get('id') != marker['profile_id'] or record.get('archived') or record.get('created_locally')
            or runtime.get('signature_provider') != 'local-v1' or not record.get('_portable_crypt')
            or not isinstance(stable, dict) or not stable
            or digest(stable) != marker['expected_stable_sha256']):
        raise AcceptanceError()


def validate_record(marker, record, data):
    validate_identity(marker, record)
    runtime = record['_runtime']
    if Path(runtime.get('profile_path', '')).resolve() != Path(data).resolve() / 'profiles' / marker['profile_id']:
        raise AcceptanceError()
    return plain(Path(runtime['profile_path']))


def immutable_digest(record):
    return digest({'native': record['_native'], 'continuity': record['_continuity']})


def prepare_service(data, marker, record, profile_processes, service_factory):
    validate_identity(marker, record)
    profile = plain(Path(data) / 'profiles' / marker['profile_id'])
    if profile_processes(profile, require_inspectable=True):
        raise OwnershipError()
    service = service_factory(data)
    if service.configuration.independent is not True:
        raise AcceptanceError()
    records = service.store.all()
    if len(records) != 1:
        raise AcceptanceError()
    record = records[0]
    profile = validate_record(marker, record, data)
    if profile_processes(profile, require_inspectable=True):
        raise OwnershipError()
    return service, profile, immutable_digest(record)


class EventCDP:
    """Single-reader CDP: retain bounded network events across command replies."""

    def __init__(self, endpoint, *, timeout=12):
        import websocket
        self.connection = websocket.create_connection(endpoint, timeout=min(8, timeout), suppress_origin=True)
        self.timeout = timeout
        self.next_id = 0
        self.pending = deque()
        self.pending_bytes = 0

    def _receive(self, deadline):
        import websocket
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.connection.settimeout(min(1, remaining))
        try:
            raw = self.connection.recv()
        except websocket.WebSocketTimeoutException:
            return None
        if not raw or len(raw) > 2 * MAX_BODY + 65536:
            raise AcceptanceError()
        value = _json(raw)
        if not isinstance(value, dict):
            raise AcceptanceError()
        if value.get('method') in EVENTS:
            if len(self.pending) >= MAX_EVENTS or self.pending_bytes + len(raw) > MAX_EVENT_BYTES:
                raise AcceptanceError()
            self.pending.append(value)
            self.pending_bytes += len(raw)
        return value

    def call(self, method, params=None, session=None):
        self.next_id += 1
        command = {'id': self.next_id, 'method': method, 'params': params or {}}
        if session:
            command['sessionId'] = session
        self.connection.send(json.dumps(command))
        deadline = time.monotonic() + self.timeout
        while True:
            value = self._receive(deadline)
            if value is not None and value.get('id') == self.next_id:
                if 'error' in value:
                    raise CommandRejected()
                result = value.get('result', {})
                if not isinstance(result, dict):
                    raise AcceptanceError()
                return result

    def events(self):
        values = list(self.pending)
        self.pending.clear()
        self.pending_bytes = 0
        return values

    def poll(self, timeout=1):
        try:
            self._receive(time.monotonic() + timeout)
        except TimeoutError:
            pass

    def close(self):
        self.connection.close(timeout=min(3, self.timeout))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _matches_url(url, rule):
    try:
        return origin(url) == rule['origin'] and url_digest(url) == rule['url_sha256']
    except (ValueError, TypeError):
        return False


class AuthResponses:
    def __init__(self, session, rule):
        self.session = session
        self.rule = rule
        self.requests = {}
        self.rejected = 0
        self.counts = {key: 0 for key in ('network_events', 'page_events', 'requests_total',
            'request_origin_matches', 'request_url_matches', 'request_method_matches', 'responses_total',
            'matched_responses', 'status_1xx', 'status_2xx', 'status_3xx', 'status_4xx', 'status_5xx',
            'status_other', 'disk_cache_skipped', 'service_worker_skipped', 'prefetch_cache_skipped',
            'served_from_cache_skipped', 'loading_failed', 'loading_cancelled', 'body_unavailable', 'body_mismatch')}
        self.network_errors = {key: 0 for key in sorted(NETWORK_ERRORS)}
        self.network_errors['other'] = 0

    def consume(self, events):
        ready = []
        for event in events:
            if event.get('sessionId') != self.session:
                continue
            method = event.get('method', '')
            if method.startswith('Page.'):
                self.counts['page_events'] += 1
                continue
            self.counts['network_events'] += 1
            params = event.get('params') or {}
            if method == 'Network.loadingFailed':
                self.counts['loading_failed'] += 1
                self.counts['loading_cancelled'] += int(params.get('canceled') is True)
                error = params.get('errorText')
                self.network_errors[error if isinstance(error, str) and error in NETWORK_ERRORS else 'other'] += 1
            elif method == 'Network.responseReceived':
                self.counts['responses_total'] += 1
            identity = params.get('requestId')
            if not isinstance(identity, str) or len(identity) > 512:
                continue
            if method == 'Network.requestWillBeSent':
                self.counts['requests_total'] += 1
                request = params.get('request') or {}
                try:
                    self.counts['request_origin_matches'] += int(origin(request.get('url')) == self.rule['origin'])
                except (ValueError, TypeError):
                    pass
                matches = _matches_url(request.get('url'), self.rule)
                self.counts['request_url_matches'] += int(matches)
                self.counts['request_method_matches'] += int(matches and request.get('method') == self.rule['method'])
                self.requests.pop(identity, None)
                if request.get('method') == self.rule['method'] and _matches_url(request.get('url'), self.rule):
                    if len(self.requests) >= 128:
                        raise AcceptanceError()
                    self.requests[identity] = {'cached': False, 'eligible': False}
            elif identity in self.requests:
                current = self.requests[identity]
                if method == 'Network.requestServedFromCache':
                    current['cached'] = True
                    self.counts['served_from_cache_skipped'] += 1
                elif method == 'Network.responseReceived':
                    response = params.get('response') or {}
                    self.counts['matched_responses'] += 1
                    status = response.get('status')
                    status_class = int(status) // 100 if type(status) in (int, float) and math.isfinite(status) else 0
                    self.counts['status_' + str(status_class) + 'xx' if 1 <= status_class <= 5 else 'status_other'] += 1
                    for field, counter in (('fromDiskCache', 'disk_cache_skipped'),
                                           ('fromServiceWorker', 'service_worker_skipped'),
                                           ('fromPrefetchCache', 'prefetch_cache_skipped')):
                        self.counts[counter] += int(bool(response.get(field)))
                    current['eligible'] = (_matches_url(response.get('url'), self.rule)
                        and response.get('status') == self.rule['status']
                        and 'json' in str(response.get('mimeType', '')).lower()
                        and not any(response.get(key) for key in ('fromDiskCache', 'fromServiceWorker', 'fromPrefetchCache')))
                elif method in ('Network.loadingFinished', 'Network.loadingFailed'):
                    self.requests.pop(identity)
                    size = params.get('encodedDataLength')
                    if (method == 'Network.loadingFinished' and current['eligible'] and not current['cached']
                            and type(size) in (int, float) and math.isfinite(size) and 0 <= size <= MAX_BODY):
                        ready.append(identity)
                    else:
                        self.rejected += 1
        return ready


def body_matches(response, rule):
    body = response.get('body')
    if not isinstance(body, str) or len(body) > (MAX_BODY + 2) // 3 * 4:
        return False
    try:
        raw = base64.b64decode(body, validate=True) if response.get('base64Encoded') else body.encode('utf-8')
        if len(raw) > MAX_BODY:
            return False
        document = _json(raw.decode('utf-8'))
        for match in rule['json_matches']:
            value = document
            for part in match['path']:
                if isinstance(part, str) and isinstance(value, dict):
                    value = value[part]
                elif type(part) is int and isinstance(value, list):
                    value = value[part]
                else:
                    return False
            if not hmac.compare_digest(digest(value), match['sha256']):
                return False
        return True
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError):
        return False


def page_diagnostics(connection, session):
    reply = connection.call('Runtime.evaluate', {'expression': _PAGE_DIAGNOSTIC, 'returnByValue': True}, session=session)
    value = reply.get('result', {}).get('value')
    if reply.get('exceptionDetails') or not isinstance(value, dict):
        return {'available': False}
    result = {'available': True}
    for key in ('readyComplete', 'hasPasswordInput', 'loginPrompt', 'trafficError', 'bodyEmpty', 'localStorageAccessible'):
        if type(value.get(key)) is bool:
            result[key] = value[key]
    for key in ('iframeCount', 'localStorageCount'):
        if type(value.get(key)) is int and 0 <= value[key] <= 100000:
            result[key] = value[key]
    return result


def authenticate(connection, session, rule, *, keepalive=None, report=None):
    connection.events()
    responses = AuthResponses(session, rule)
    diagnostics = {'authenticated': False, 'timed_out': False}
    try:
        connection.call('Page.reload', {'ignoreCache': True}, session=session)
        deadline = time.monotonic() + AUTH_TIMEOUT
        while time.monotonic() < deadline:
            if keepalive:
                keepalive()
            for identity in responses.consume(connection.events()):
                try:
                    body = connection.call('Network.getResponseBody', {'requestId': identity}, session=session)
                except CommandRejected:
                    responses.counts['body_unavailable'] += 1
                    responses.rejected += 1
                    continue
                if body_matches(body, rule):
                    diagnostics['authenticated'] = True
                    return responses.rejected
                responses.counts['body_mismatch'] += 1
                responses.rejected += 1
            connection.poll(min(1, max(.001, deadline - time.monotonic())))
        responses.consume(connection.events())
        diagnostics['timed_out'] = True
        try:
            diagnostics['page'] = page_diagnostics(connection, session)
        except Exception as error:
            diagnostics['page'] = {'available': False, 'error_type': type(error).__name__}
        raise EvidenceTimeout()
    finally:
        diagnostics.update(counts=dict(responses.counts), network_errors=dict(responses.network_errors),
                           rejected_evidence=responses.rejected)
        if report is not None:
            report.setdefault('authentication_attempts', []).append(diagnostics)
            report['counts']['rejected_evidence'] += responses.rejected


def attach_existing(connection, marker, report=None):
    targets = connection.call('Target.getTargets').get('targetInfos', [])
    matches = []
    for target in targets:
        try:
            if target.get('type') == 'page' and origin(target.get('url')) == marker['target_origin']:
                matches.append(target)
        except (ValueError, TypeError):
            continue
    same_origin = matches
    if 'target_route_sha256' in marker:
        matches = [value for value in matches if _route_digest(value['url']) == marker['target_route_sha256']]
    if report is not None:
        routes = {(urlsplit(value['url']).path, urlsplit(value['url']).fragment) for value in same_origin}
        selection = {'same_origin_page_count': len(same_origin), 'same_origin_routes_equal': len(routes) == 1}
        if 'target_route_sha256' in marker:
            selection.update(route_filter_applied=True, route_matching_page_count=len(matches))
        if matches:
            selected = urlsplit(matches[0]['url'])
            selection.update(selected_query_present=bool(selected.query), selected_fragment_present=bool(selected.fragment))
        report.setdefault('page_selections', []).append(selection)
    if not matches:
        raise AcceptanceError()
    target = matches[0]['targetId']
    session = connection.call('Target.attachToTarget', {'targetId': target, 'flatten': True})['sessionId']
    connection.call('Page.enable', session=session)
    connection.call('Network.enable', {'maxResourceBufferSize': MAX_BODY, 'maxTotalBufferSize': 2 * MAX_BODY,
                                     'maxPostDataSize': 0}, session=session)
    return target, session


def owned_identity(service, identity, started):
    try:
        record = service.controller.state[identity]
        if record['created'] >= started and service.controller._record_valid(identity):
            return record['pid'], record['created']
    except Exception:
        pass
    return None


def close_owned(service, identity, owned, profile, profile_processes):
    record = service.controller.state.get(identity)
    if (not record or (record.get('pid'), record.get('created')) != owned
            or not service.controller._record_valid(identity)):
        if profile_processes(profile, require_inspectable=True):
            raise OwnershipError()
        service.proxy_runtime.stop_if_unused(identity)
    else:
        service.close(identity)
    if profile_processes(profile, require_inspectable=True):
        raise OwnershipError()
    worker = service.proxy_runtime.state(identity)
    if worker and service.proxy_runtime.owned(worker):
        raise OwnershipError()


def run(root, marker, duration, report):
    report['stage'] = 'prepare'
    run_began = time.monotonic()
    sys.path[:0] = [str(root / 'app'), str(root / 'tools')]
    from browser_processes import profile_processes
    from inspect_installation import read_catalog
    from manager_service import ManagerService
    data = plain(root / 'app/data')
    catalog = read_catalog(data, time.monotonic() + 30)
    if not catalog['quick_check'] or len(catalog['records']) != 1:
        raise AcceptanceError()
    record = catalog['records'][0]
    identity = marker['profile_id']
    profile = data / 'profiles' / identity
    service = None
    owned = None
    try:
        report['checks']['independent_runtime'] = False
        service, profile, original = prepare_service(data, marker, record, profile_processes, ManagerService)
        report['checks']['independent_runtime'] = True
        report['checks']['single_authorized_profile_closed'] = True
        for round_index in range(2):
            report['stage'] = 'initial_open' if round_index == 0 else 'reopen'
            if profile_processes(profile, require_inspectable=True):
                raise OwnershipError()
            started = time.time()
            try:
                service.open(identity)
            finally:
                owned = owned_identity(service, identity, started)
            if owned is None:
                raise OwnershipError()
            report['counts']['formal_opens'] += 1
            with EventCDP(service.controller.endpoint(identity)) as connection:
                target, session = attach_existing(connection, marker, report=report)
                next_heartbeat = time.monotonic() + 60
                expected_route = None

                def heartbeat(force=False):
                    nonlocal next_heartbeat
                    if not force and time.monotonic() < next_heartbeat:
                        return
                    connection.call('Browser.getVersion')
                    current_route = target_route(connection, target, marker)
                    if expected_route is not None and current_route != expected_route:
                        report['checks']['authenticated_page_route_preserved'] = False
                        raise AcceptanceError()
                    if immutable_digest(service.store.get(identity)) != original:
                        raise AcceptanceError()
                    report['counts']['heartbeats'] += 1
                    next_heartbeat = time.monotonic() + 60
                    print(json.dumps({'heartbeats': report['counts']['heartbeats'],
                                      'authenticated_reloads': report['counts']['authenticated_reloads'],
                                      'elapsed_seconds': round(time.monotonic() - run_began, 3)}), flush=True)

                report['stage'] = 'initial_authentication' if round_index == 0 else 'reopened_authentication'
                authenticate(connection, session, marker['auth_rule'], keepalive=heartbeat, report=report)
                report['counts']['authenticated_rounds'] += 1
                expected_route = target_route(connection, target, marker)
                report['checks']['authenticated_page_route_preserved'] = True
                if round_index == 0:
                    report['stage'] = 'continuous_hold'
                    held_start = time.monotonic()
                    deadline = held_start + duration
                    next_reload = held_start + 600
                    try:
                        while time.monotonic() < deadline:
                            heartbeat()
                            if time.monotonic() >= next_reload:
                                authenticate(connection, session, marker['auth_rule'], keepalive=heartbeat, report=report)
                                report['counts']['authenticated_reloads'] += 1
                                next_reload += 600
                            connection.events()
                            connection.poll(min(1, max(.001, deadline - time.monotonic())))
                        heartbeat(force=True)
                    finally:
                        report['held_duration_seconds'] = round(time.monotonic() - held_start, 3)
                connection.call('Target.detachFromTarget', {'sessionId': session})
            report['stage'] = 'normal_close'
            close_owned(service, identity, owned, profile, profile_processes)
            owned = None
            report['counts']['normal_closes'] += 1
        current = service.store.get(identity)
        report['checks']['native_and_original_baseline_unchanged'] = immutable_digest(current) == original
        report['checks']['stable_hash_matches_authorization'] = digest(current['_continuity']['stable']) == marker['expected_stable_sha256']
        report['checks']['initial_and_reopened_server_authenticated'] = report['counts']['authenticated_rounds'] == 2
        report['checks']['requested_hold_completed'] = report['held_duration_seconds'] >= duration
        report['success'] = all(report['checks'].values())
        if report['success']:
            report['stage'] = 'complete'
    finally:
        if service is not None and owned is not None:
            try:
                close_owned(service, identity, owned, profile, profile_processes)
                report['counts']['normal_closes'] += 1
            except Exception as error:
                report['cleanup_error_type'] = type(error).__name__
                report['success'] = False
        report['checks']['owned_browser_and_proxy_closed'] = not profile_processes(profile, require_inspectable=True)
        if service is not None:
            worker = service.proxy_runtime.state(identity)
            report['checks']['owned_browser_and_proxy_closed'] &= not (worker and service.proxy_runtime.owned(worker))
        report['success'] &= report['checks']['owned_browser_and_proxy_closed']


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError()


def main(argv=None):
    began = time.monotonic()
    report = {'executed': False, 'success': False, 'long_acceptance': False,
              'requested_duration_seconds': 0, 'held_duration_seconds': 0, 'checks': {},
              'counts': {key: 0 for key in ('formal_opens', 'authenticated_rounds', 'authenticated_reloads',
                                           'heartbeats', 'normal_closes', 'rejected_evidence')}}
    destination = ROOT / 'analysis/reports/private-session-live.json'
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument('--execute', action='store_true')
        parser.add_argument('--duration-seconds', type=int, default=7200)
        parser.add_argument('--report', type=Path, default=destination)
        args = parser.parse_args(argv)
        if not args.execute:
            print(json.dumps({'executed': False}))
            return 0
        report['executed'] = True
        destination = args.report
        if not 60 <= args.duration_seconds <= 7200:
            raise ValueError()
        report['requested_duration_seconds'] = args.duration_seconds
        marker = load_marker(ROOT)
        run(ROOT, marker, args.duration_seconds, report)
    except BaseException as error:
        report.update(error_diagnostics(error))
        report['success'] = False
    report['long_acceptance'] = bool(report['success'] and report['requested_duration_seconds'] >= 7200
                                     and report['held_duration_seconds'] >= 7200)
    report['elapsed_seconds'] = round(time.monotonic() - began, 3)
    temporary = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=destination.name + '.', suffix='.tmp', dir=destination.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            json.dump(report, output, ensure_ascii=False, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except Exception as error:
        report['report_error_type'] = type(error).__name__
        report['success'] = False
        report['long_acceptance'] = False
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except Exception as error:
                report['report_cleanup_error_type'] = type(error).__name__
                report['success'] = False
                report['long_acceptance'] = False
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
