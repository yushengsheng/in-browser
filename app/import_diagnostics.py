"""Bounded import failure evidence without exception messages or private data."""
from collections import deque
import hashlib
import os
from pathlib import Path
import re
import sys

from app_paths import APP_ROOT
from import_progress import PHASES


SETTING_KEY = 'sync_failure_diagnostics_v1'
MAX_RECORDS = 100
_INVENTORY_FIELDS = ('members', 'presence', 'dev', 'ino', 'size', 'mtime', 'ctime')
_MEMBER_FIELDS = ('dev', 'ino', 'type', 'size', 'mtime', 'created', 'ctime', 'mode', 'attributes')
_TYPES = frozenset(('Exception', 'LocalBrowserError', 'OSError', 'PermissionError',
    'FileNotFoundError', 'FileExistsError', 'NotADirectoryError', 'IsADirectoryError',
    'TimeoutError', 'ConnectionError', 'ConnectionResetError', 'ConnectionAbortedError',
    'BrokenPipeError', 'ValueError', 'TypeError', 'KeyError', 'IndexError', 'RuntimeError',
    'OverflowError', 'UnicodeError', 'UnicodeDecodeError', 'JSONDecodeError',
    'OperationalError', 'DatabaseError', 'IntegrityError', 'InterfaceError',
    'InvalidTag', 'InvalidSignature', 'ProfileLaunchPathError', 'HTTPError', 'URLError'))
_CODES = frozenset(('source_seed_input', 'source_seed_download', 'source_seed_budget',
    'source_seed_verification', 'ip_info_failed', 'profile_path_invalid',
    'profile_path_changed', 'profile_tree_limit', 'profile_path_too_long')) | frozenset(
    'engine_' + value for value in ('integrity', 'access_denied', 'path_too_long',
    'file_access', 'manifest_json', 'invalid_data', 'path_link', 'duplicate_name',
    'layout', 'manifest', 'core_build', 'trust_manifest', 'tree_manifest', 'public_root',
    'vendor_root', 'stock_hash', 'resource_root', 'resource_hash', 'tree_hash',
    'version', 'invalid_option')) | frozenset('continuity_fetch_' + value for value in (
    'budget', 'message', 'request', 'session', 'request_id', 'reply_id', 'protocol',
    'reply', 'navigation', 'document', 'event', 'event_limit', 'transport'))


def _public_files():
    root = APP_ROOT.resolve()
    return {os.path.normcase(str(path.resolve())): path.name for path in root.iterdir()
            if re.fullmatch(r'[a-z][a-z0-9_]*\.pyw?', path.name)
            and not path.is_symlink() and path.is_file() and path.resolve().parent == root}


def _version():
    value = {'release': 'unknown', 'python': list(sys.version_info[:3]),
             'source_sha256_at_diagnostic_import': {}}
    try:
        with (APP_ROOT.parent / 'VERSION').open(encoding='utf-8-sig') as stream:
            release = stream.read(129).strip()
        if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?', release) and len(release) <= 128:
            value['release'] = release
    except (OSError, UnicodeError):
        pass
    # These are public source bytes at this import, not proof of an older
    # process's loaded code or a substitute for a release integrity check.
    for name in ('window_sync.py', 'profile_copy.py', 'local_source.py'):
        try:
            with (APP_ROOT / name).open('rb') as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) <= 1024 * 1024:
                value['source_sha256_at_diagnostic_import'][name] = hashlib.sha256(raw).hexdigest()
        except OSError:
            pass
    return value


try:
    _FILES = _public_files()
except OSError:
    _FILES = {}
_VERSION = _version()


def _frames(error):
    result = deque(maxlen=12)
    current = error.__traceback__
    for _ in range(256):
        if current is None:
            break
        filename = current.tb_frame.f_code.co_filename
        name = _FILES.get(os.path.normcase(os.path.abspath(filename)))
        if name is not None and type(current.tb_lineno) is int and current.tb_lineno > 0:
            result.append({'file': name, 'line': current.tb_lineno})
        current = current.tb_next
    return list(result)


def _number(value):
    return value if type(value) is int and -(2**31) <= value < 2**32 else None


def _changes(error, limit):
    if limit <= 0:
        return []
    try:
        value = getattr(error, '_import_changes', None)
    except Exception:
        return []
    if type(value) is not list:
        return []
    result = []
    for item in value[:8]:
        if len(result) >= limit:
            break
        if type(item) is not dict or not 4 <= len(item) <= 6 or any(type(key) is not str for key in item):
            continue
        check = item.get('check'); kind = item.get('kind'); fields = item.get('fields')
        if type(check) is not str or type(kind) is not str or kind not in ('directory', 'file'):
            continue
        if check == 'source_inventory':
            if set(item) != {'check', 'kind', 'group', 'fields'}:
                continue
            group = item['group']
            if (type(group) is not str or group not in ('legacy', 'directories', 'critical') or
                    (group == 'directories' and kind != 'directory') or (group == 'critical' and kind != 'file')):
                continue
            allowed = _INVENTORY_FIELDS
            safe = {'check': check, 'kind': kind, 'group': group}
        elif check == 'copy_member':
            required = {'check', 'kind', 'relation', 'fields'}
            optional = {'ino_zero_before', 'ino_zero_after'}
            if not required <= set(item) or set(item) - required - optional:
                continue
            relation = item['relation']
            if type(relation) is not str or relation not in ('parent', 'member'):
                continue
            if any(type(item[key]) is not bool for key in optional if key in item):
                continue
            allowed = _MEMBER_FIELDS
            safe = {'check': check, 'kind': kind, 'relation': relation}
            safe.update((key, item[key]) for key in ('ino_zero_before', 'ino_zero_after') if key in item)
        else:
            continue
        if (type(fields) is not list or not 1 <= len(fields) <= len(allowed) or
                any(type(field) is not str or field not in allowed for field in fields) or
                len(set(fields)) != len(fields)):
            continue
        safe['fields'] = [field for field in allowed if field in fields]
        result.append(safe)
    return result


def failure_record(job_id, ordinal, phase, error):
    """Copy only fixed fields; never format an exception or inspect frame locals."""
    if not isinstance(job_id, str) or not re.fullmatch(r'[0-9a-f]{32}', job_id):
        raise ValueError('Invalid diagnostic job identity')
    # Zero identifies a batch boundary failure before/after an individual item.
    if type(ordinal) is not int or not 0 <= ordinal <= 9999:
        raise ValueError('Invalid diagnostic ordinal')
    errors = []
    seen = set()
    frame_budget = 12
    change_budget = 8
    while error is not None and id(error) not in seen and len(errors) < 4:
        seen.add(id(error))
        name = type(error).__name__
        code = getattr(error, 'code', None)
        frames = _frames(error)[-frame_budget:] if frame_budget else []
        frame_budget -= len(frames)
        errors.append({'type': name if name in _TYPES else 'Exception',
                       'errno': _number(getattr(error, 'errno', None)),
                       'winerror': _number(getattr(error, 'winerror', None)),
                       'code': code if type(code) is str and code in _CODES else None,
                       'frames': frames})
        changes = _changes(error, change_budget)
        if changes:
            errors[-1]['changes'] = changes
            change_budget -= len(changes)
        # from None hides display but retains useful, safely filtered context.
        error = error.__cause__ if error.__cause__ is not None else error.__context__
    if not errors:
        raise ValueError('Missing diagnostic exception')
    return {'format': 1, 'kind': 'failure', 'job_id': job_id, 'ordinal': ordinal,
            'phase': phase if type(phase) is str and phase in PHASES else 'checking',
            'version': {'release': _VERSION['release'], 'python': list(_VERSION['python']),
                        'source_sha256_at_diagnostic_import': dict(_VERSION['source_sha256_at_diagnostic_import'])},
            **errors[0], 'contexts': errors[1:]}


def persist_failure(store, record):
    """Append atomically in the existing encrypted settings value."""
    with store.lock, store.connect() as connection:
        connection.execute('BEGIN IMMEDIATE')
        row = connection.execute('SELECT value FROM settings WHERE key=?', (SETTING_KEY,)).fetchone()
        previous = store.unpack(row[0]) if row else []
        if not isinstance(previous, list):
            raise ValueError('Invalid diagnostic history')
        records = previous[-(MAX_RECORDS - 1):] + [record]
        connection.execute('INSERT OR REPLACE INTO settings VALUES (?,?)', (SETTING_KEY, store.pack(records)))
