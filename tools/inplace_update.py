"""Apply the isolated overlay payload; never move existing account data.

The payload interpreter stays outside the replaced program. Authenticated release
manifests derive every operation. A pending directory and standalone bootstrap
block mixed code until the normal launcher can finish or recover the update.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from functools import wraps
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.pycache_prefix = str(ROOT / ('.program-no-cache-' + os.urandom(16).hex()))
sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tools')]
import update_guard
from update_guard import (UpdateGuardError, verify_release, read_update_policy,
                          _manifest, _ordinary, _exists, _root, _json_file,
                          _verified_file, _identity)

PENDING = '.program-update'
ENTRY = 'app/local_browser.pyw'
LAUNCHER = '启动本地浏览器.cmd'
PACKAGES = '.program-packages'
OVERLAY_MARKER = 'overlay-package.json'
REQUIRED = {'VERSION', '启动本地浏览器.cmd', ENTRY, 'runtime/python/python.exe',
            'runtime/python/pythonw.exe', 'runtime/webview2/msedgewebview2.exe',
            'runtime/manifest.sha256.json'}
NEW_REQUIRED = REQUIRED | {'app/update_guard.py', 'tools/inplace_update.py', OVERLAY_MARKER}
MAX_SECONDS = 3600
MAX_CATALOG_BYTES = 512 * 1024 * 1024
BOOTSTRAP = ("import ctypes,sys\n"
             "try: ctypes.windll.user32.MessageBoxW(None,"
             "'Program update is incomplete. Use the normal launcher to recover.',"
             "'Local Browser',16)\n"
             "except Exception: pass\n"
             "raise SystemExit(1)\n").encode('utf-8')

SCHEMAS = {
    'profiles': {'id', 'seq', 'created_at', 'last_opened_at', 'archived', 'data'},
    'settings': {'key', 'value'},
    'source_bindings': {'source_key', 'profile_id', 'imported_at'},
    'sync_jobs': {'job_id', 'created_at', 'state', 'phase', 'current', 'total',
                  'completed', 'skipped', 'failed', 'cancel_requested', 'message', 'warnings_total'},
    'sync_items': {'job_id', 'ordinal', 'source_key', 'name', 'candidate', 'state', 'message'},
    'import_intents': {'intent_id', 'source_key', 'profile_id', 'work_id', 'state', 'data', 'job_id', 'ordinal'},
    'creation_jobs': {'job_id', 'digest', 'state', 'cancel_requested', 'created_at'},
    'creation_items': {'job_id', 'ordinal', 'source_key', 'profile_id', 'state', 'data', 'message'},
}


class UpdateError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(path):
    value = str(Path(path).resolve())
    if value.startswith('\\\\?\\UNC\\'):
        value = '\\\\' + value[8:]
    elif value.startswith('\\\\?\\'):
        value = value[4:]
    return Path(value)


def closed(roots):
    import psutil
    known = {'bitbrowser.exe', 'msedgewebview2.exe', 'pythonw.exe', 'python.exe'}
    try:
        for process in psutil.process_iter(['pid', 'exe', 'cmdline', 'name']):
            if process.pid == os.getpid():
                continue
            info = process.info
            executable, args = info.get('exe'), info.get('cmdline')
            # Windows virtual processes can report names such as Registry as
            # exe. Only fully qualified paths prove executable ownership.
            executable_path = Path(executable) if executable else None
            absolute_executable = bool(executable_path and executable_path.is_absolute() and executable_path.root)
            paths = [canonical(executable)] if absolute_executable else []
            for i, argument in enumerate(args or []):
                if argument.startswith('--user-data-dir='):
                    paths.append(canonical(argument.split('=', 1)[1].strip('"')))
                elif argument == '--user-data-dir' and i + 1 < len(args):
                    paths.append(canonical(args[i + 1].strip('"')))
                elif argument.lower().endswith(('.py', '.pyw')) and os.path.isabs(argument):
                    paths.append(canonical(argument))
            if any(path == root or path.is_relative_to(root) for path in paths for root in roots):
                raise UpdateError('program_running_or_unknown')
            if not absolute_executable or not args:
                if str(info.get('name') or '').casefold() in known:
                    raise UpdateError('program_running_or_unknown')
    except (psutil.Error, OSError, ValueError):
        raise UpdateError('program_running_or_unknown') from None


def require(condition, code='invalid_installation'):
    if not condition:
        raise UpdateError(code)


def tick(deadline):
    require(time.monotonic() < deadline, 'timeout')


def event(hook, phase, name=''):
    if hook is not None:
        hook(phase, name)


def file_item(path):
    before = _ordinary(path, directory=False)
    require(before.st_size <= 4 * 1024 ** 3, 'resource_limit')
    hashed = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        require(_identity(os.fstat(stream.fileno())) == _identity(before), 'source_changed')
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(block)
            require(size <= before.st_size, 'source_changed')
            hashed.update(block)
    require(size == before.st_size, 'source_changed')
    require(_identity(_ordinary(path, directory=False)) == _identity(before), 'source_changed')
    return {'bytes': before.st_size, 'sha256': hashed.hexdigest()}


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def copy_checked(source, target, expected):
    require(_ordinary(source, directory=False).st_size == expected['bytes'], 'source_changed')
    copy_stream(source, target, expected['bytes'])
    require(file_item(target) == expected and file_item(source) == expected, 'source_changed')


def copy_stream(source, target, expected_size):
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open('rb') as reader, target.open('xb') as writer:
        size = 0
        for block in iter(lambda: reader.read(1024 * 1024), b''):
            size += len(block)
            require(size <= expected_size, 'source_changed')
            writer.write(block)
        require(size == expected_size, 'source_changed')
        writer.flush()
        os.fsync(writer.fileno())


def version(root):
    path = root / 'VERSION'
    require(_ordinary(path, directory=False).st_size <= 128, 'unsupported_version')
    value = path.read_text('utf-8-sig').strip()
    require(re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value), 'unsupported_version')
    return value


def paths(base, target):
    base, target = _root(base).resolve(), _root(target).resolve()
    interpreter = Path(sys.executable).resolve()
    require(base.parent == target / PACKAGES and
            re.fullmatch('[0-9a-f]{32}', base.name), 'invalid_overlay_location')
    require(interpreter.is_relative_to(base) or not interpreter.is_relative_to(target),
            'updater_inside_target')
    require(not _exists(base / PENDING), 'source_update_pending')
    return base, target


@contextmanager
def manager_guard(target):
    """Use precisely the existing manager's normalized directory mutex name."""
    if os.name != 'nt':
        yield
        return
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    name = hashlib.sha256(os.path.normcase(str((target / 'app').resolve())).encode()).hexdigest()[:24]
    handle = kernel.CreateMutexW(None, False, 'LocalBrowser-' + name)
    existed = ctypes.get_last_error() == 183
    require(bool(handle), 'cannot_lock_installation')
    try:
        require(not existed, 'program_running')
        yield
    finally:
        kernel.CloseHandle(handle)


def check_closed(base, target):
    attempts = 5
    for attempt in range(attempts):
        try:
            closed((base, target))
            return
        except Exception:
            if attempt + 1 == attempts:
                raise UpdateError('program_running_or_unknown') from None
            time.sleep(0.2)


def inventory_tree(folder):
    _ordinary(folder, directory=True)
    result = {}
    pending = [folder]
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as entries:
            for entry in entries:
                path = Path(entry.path)
                info = _ordinary(path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                else:
                    result[path.relative_to(folder).as_posix()] = file_item(path)
                require(len(result) <= 40000, 'resource_limit')
    return result


def subset(files, prefix):
    return {name[len(prefix) + 1:]: item for name, item in files.items() if name.startswith(prefix + '/')}


def overlay_package_id(base, files):
    """Return only a package identity authenticated by this payload's manifest."""
    require(OVERLAY_MARKER in files, 'invalid_overlay_package')
    marker = _json_file(base / OVERLAY_MARKER, 4096)
    _verified_file(base, OVERLAY_MARKER, files[OVERLAY_MARKER])
    require(isinstance(marker, dict) and set(marker) == {'format', 'package_id'}
            and type(marker.get('format')) is int and marker['format'] == 1
            and isinstance(marker.get('package_id'), str)
            and re.fullmatch('[0-9a-f]{32}', marker['package_id'])
            and marker['package_id'] == base.name, 'invalid_overlay_package')
    top_names = {name.split('/', 1)[0].casefold() for name in files}
    require(PACKAGES not in top_names and
            not any(name.startswith('.program-update-backup-') for name in top_names),
            'invalid_overlay_package')
    return marker['package_id']


def compatible_source(base):
    public = verify_release(base)
    require(not public['development'] and NEW_REQUIRED <= public['files'].keys(), 'not_a_release')
    overlay_package_id(base, public['files'])
    policy = read_update_policy(base)
    require(policy is not None, 'missing_update_policy')
    runtime_manifest = _json_file(base / 'runtime/manifest.sha256.json', 16 * 1024 * 1024)
    require(runtime_manifest == {'algorithm': 'SHA256', 'files': {
        name[len('runtime/'):]: value for name, value in public['files'].items()
        if name.startswith('runtime/') and name != 'runtime/manifest.sha256.json'}}, 'runtime_manifest_mismatch')
    return public['files'], policy


def authenticated_old(base, old_manifest, old_version, policy):
    require(policy['from_versions'].get(old_version) == file_item(old_manifest)['sha256'], 'unsupported_source_release')
    require(tuple(map(int, version(base).split('.'))) > tuple(map(int, old_version.split('.'))), 'downgrade_or_same_version')
    files = _manifest(old_manifest.parent)
    require(REQUIRED <= files.keys(), 'not_a_release')
    return files


def effective_old_files(target, old_files, new_files):
    """The extraction may replace precisely the verified new root launcher."""
    _verified_file(target, LAUNCHER, new_files[LAUNCHER])
    return {**old_files, LAUNCHER: new_files[LAUNCHER]}


def verify_old_release(target, old_files):
    _root(target)
    policy = read_update_policy(target)
    require(policy is None or 'update-policy.json' in old_files, 'not_a_release')
    for name, expected in old_files.items():
        _verified_file(target, name, expected)
    update_guard._check_active_files(target, old_files)


def verify_overlay_source(base, new_files, policy, manifest_item):
    current_files, current_policy = compatible_source(base)
    require(current_files == new_files and current_policy == policy
            and file_item(base / 'release-manifest.json') == manifest_item, 'source_changed')


def build_operations(old_files, new_files):
    """Derive paths solely from the authenticated manifests, never a journal."""
    operations = []
    for name in sorted(set(old_files) | set(new_files) | {'release-manifest.json'}):
        if name.startswith(('runtime/', 'app/engines/')):
            continue
        if name in ('release-manifest.json', ENTRY) or old_files.get(name) != new_files.get(name):
            operations.append({'name': name, 'kind': 'file', 'old': old_files.get(name), 'new': new_files.get(name)})
    old_runtime, new_runtime = subset(old_files, 'runtime'), subset(new_files, 'runtime')
    if old_runtime != new_runtime:
        operations.insert(0, {'name': 'runtime', 'kind': 'tree', 'old': old_runtime, 'new': new_runtime})
    # Refuse file/directory layout migrations rather than removing unknown trees.
    all_files = set(old_files) | set(new_files)
    require(all(not any(parent.as_posix() in all_files for parent in PurePosixPath(name).parents
                        if str(parent) != '.') for name in all_files), 'layout_migration_required')
    operations.sort(key=lambda op: (op['name'] == ENTRY, op['name'] != 'runtime', op['name']))
    return operations


def validate_data(target, work, deadline):
    """Check v1 markers and a bounded catalog COPY without writing originals."""
    data = target / 'app/data'
    if not _exists(data):
        return {'catalog_rows': 0, 'existing_data': False}
    _ordinary(data, directory=True)
    if not any(data.iterdir()):
        return {'catalog_rows': 0, 'existing_data': False}
    require(not _exists(data / '.installation-pending'), 'data_not_ready')
    from portable_vault import PortableVault
    from local_signer import LocalSigner
    vault = PortableVault(data, key_required=True)
    signer = LocalSigner(data, load_private=False)
    signer._load_private()  # Read-only branch; never create or rotate identities.
    for name, identity in (('portable-mode.bin', vault.key_id), ('continuity-mode.bin', vault.key_id),
                           ('independent-mode.bin', signer.key_id)):
        path = data / name
        require(_ordinary(path, directory=False).st_size <= 1024 * 1024, 'unsupported_data')
        value = json.loads(vault.decrypt(path.read_bytes()))
        require(value.get('format') == 1 and value.get('state') == 'ready'
                and value.get('key_id') == identity, 'unsupported_data')
    originals = []
    total = 0
    for suffix in ('', '-wal', '-shm', '-journal'):
        path = data / ('windows.sqlite' + suffix)
        if not _exists(path):
            require(bool(suffix), 'unsupported_data')
            continue
        info = _ordinary(path, directory=False)
        total += info.st_size
        require(total <= MAX_CATALOG_BYTES and (suffix != '-journal' or info.st_size == 0), 'catalog_not_ready')
        originals.append((suffix, _identity(info), file_item(path)))
    cloned = work / 'catalog-check'
    cloned.mkdir()
    connection = None
    try:
        for suffix, _, item in originals:
            if suffix in ('', '-wal'):
                copy_checked(data / ('windows.sqlite' + suffix), cloned / ('catalog.sqlite' + suffix), item)
        connection = sqlite3.connect((cloned / 'catalog.sqlite').as_uri() + '?mode=ro', uri=True, timeout=5)
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        require(connection.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'catalog_corrupt')
        require(connection.execute('PRAGMA user_version').fetchone()[0] == 0, 'unsupported_data')
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        require({'profiles', 'settings', 'source_bindings'} <= tables and tables <= SCHEMAS.keys(), 'unsupported_data')
        for name in tables:
            details = list(connection.execute('PRAGMA table_xinfo(' + name + ')'))
            require(all(row[6] == 0 for row in details), 'unsupported_data')
            columns = {row[1] for row in details}
            allowed=(SCHEMAS[name],SCHEMAS[name]|{'result_cursor'}) if name in ('sync_jobs','sync_items') else (SCHEMAS[name],)
            require(columns in allowed, 'unsupported_data')
            if name in ('sync_jobs','sync_items') and 'result_cursor' in columns:
                cursor = next(row for row in details if row[1] == 'result_cursor')
                expected = (1, '0', 0) if name == 'sync_jobs' else (0, None, 0)
                require(cursor[2].upper() == 'INTEGER' and cursor[3:6] == expected, 'unsupported_data')
        count = connection.execute('SELECT COUNT(*) FROM profiles').fetchone()[0]
        for suffix, identity, item in originals:
            path = data / ('windows.sqlite' + suffix)
            require(_identity(_ordinary(path, directory=False)) == identity and file_item(path) == item, 'data_changed')
        require({suffix for suffix, _, _ in originals} == {
            suffix for suffix in ('', '-wal', '-shm', '-journal') if _exists(data / ('windows.sqlite' + suffix))}, 'data_changed')
        return {'catalog_rows': count, 'existing_data': True}
    finally:
        if connection is not None:
            connection.close()
        for path in cloned.iterdir():
            _ordinary(path, directory=False)
            require(path.name in ('catalog.sqlite', 'catalog.sqlite-wal', 'catalog.sqlite-shm'), 'unsafe_catalog_cleanup')
            path.unlink()
        cloned.rmdir()


def checked_path(target, name):
    """All mutations are limited to authenticated public paths or fixed caches."""
    require(name == 'runtime' or name == 'app/__pycache__' or
            (name not in ('app', 'app/data', 'app/local-engines', 'app/engines') and
             not name.startswith(('app/data/', 'app/local-engines/'))), 'unsafe_update_path')
    path = target.joinpath(*PurePosixPath(name).parts)
    require(path.is_relative_to(target) and '..' not in PurePosixPath(name).parts, 'unsafe_update_path')
    for parent in path.parents:
        if parent == target:
            break
        if _exists(parent):
            _ordinary(parent, directory=True)
    if _exists(path):
        _ordinary(path)
    return path


def matches(path, expected, kind):
    if not _exists(path):
        return expected is None
    if expected is None:
        return False
    return (inventory_tree(path) if kind == 'tree' else file_item(path)) == expected


def stage(base, target, work, old_files, new_files, operations, deadline):
    size = sum((sum(value['bytes'] for value in op['new'].values()) if op['kind'] == 'tree' else
                op['new']['bytes']) for op in operations if op['new'] is not None)
    require(shutil.disk_usage(target).free >= size + 64 * 1024 * 1024, 'not_enough_space')
    for op in operations:
        tick(deadline)
        path = checked_path(target, op['name'])
        require(matches(path, op['old'], op['kind']), 'unmanaged_or_changed_program')
        if op['new'] is None:
            continue
        destination = work / 'stage' / op['name']
        if op['kind'] == 'tree':
            destination.mkdir(parents=True)
            for name, item in op['new'].items():
                tick(deadline)
                copy_checked(base / op['name'] / name, destination / name, item)
            # Preserve the distribution's legitimate empty runtime directories.
            for directory, folders, _ in os.walk(base / op['name'], followlinks=False):
                for name in folders:
                    child = Path(directory) / name
                    _ordinary(child, directory=True)
                    (destination / child.relative_to(base / op['name'])).mkdir(parents=True, exist_ok=True)
        else:
            copy_checked(base / op['name'], destination, op['new'])
        require(matches(destination, op['new'], op['kind']), 'staging_failed')
    new_cores = {PurePosixPath(name).parts[2] for name in new_files if name.startswith('app/engines/')}
    for core in sorted(new_cores):
        prefix = 'app/engines/' + core
        expected = subset(new_files, prefix)
        path = checked_path(target, prefix)
        require(_exists(path), 'stock_core_missing')
        require(inventory_tree(path) == expected, 'stock_core_conflict')


def finish_directory(target, work, identity):
    destination = target / ('.program-update-backup-' + identity)
    require(not _exists(destination), 'backup_collision')
    os.rename(work, destination)
    return destination


def _context(base, target, work):
    meta = _json_file(work / 'plan.json', 64 * 1024)
    require(isinstance(meta, dict) and set(meta) == {'format', 'id', 'old_version', 'new_manifest', 'overlay_package'}
            and meta.get('format') == 1 and isinstance(meta.get('id'), str)
            and re.fullmatch('[0-9a-f]{32}', meta['id'])
            and meta.get('overlay_package') == base.name, 'invalid_recovery_plan')
    new_files, policy = compatible_source(base)
    require(file_item(base / 'release-manifest.json')['sha256'] == meta['new_manifest'], 'wrong_recovery_release')
    require(isinstance(meta['old_version'], str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', meta['old_version']), 'invalid_recovery_plan')
    old_files = authenticated_old(base, work / 'old/release-manifest.json', meta['old_version'], policy)
    old_files = effective_old_files(target, old_files, new_files)
    operations = build_operations(old_files, new_files)
    for op in operations:
        if op['name'] == 'release-manifest.json':
            op['old'] = file_item(work / 'old/release-manifest.json')
            op['new'] = file_item(base / 'release-manifest.json')
    return meta, old_files, new_files, operations


def _rollback(base, target, work, hook=None):
    # Reject all transaction links, including backups, before deriving a path.
    _ordinary(work, directory=True)
    for path in work.rglob('*'):
        _ordinary(path)
    owner = _json_file(work / 'owner.json', 4096)
    require(isinstance(owner, dict) and set(owner) == {'format', 'id', 'purpose', 'overlay_package'}
            and owner.get('format') == 1 and owner.get('purpose') == 'program-update'
            and isinstance(owner.get('id'), str) and re.fullmatch('[0-9a-f]{32}', owner['id'])
            and owner.get('overlay_package') == base.name, 'unknown_update_state')
    if not _exists(work / 'plan.json'):
        # A crash before the immutable plan cannot have changed any program.
        require({path.name for path in work.iterdir()} <= {
            'owner.json', 'old', 'stage', 'backup', 'catalog-check'}, 'unknown_update_state')
        new_files, policy = compatible_source(base)
        old_version = version(target)
        old_files = authenticated_old(base, target / 'release-manifest.json', old_version, policy)
        old_files = effective_old_files(target, old_files, new_files)
        verify_old_release(target, old_files)
        for path in (work / 'old').rglob('*'):
            if path.is_file():
                require(path.relative_to(work / 'old').as_posix() == 'release-manifest.json'
                        and file_item(path) == file_item(target / 'release-manifest.json'), 'unknown_update_state')
        for path in (work / 'backup').rglob('*'):
            if path.is_file():
                require(path.relative_to(work / 'backup').as_posix() == ENTRY
                        and file_item(path) == old_files[ENTRY], 'unknown_update_state')
        for path in (work / 'stage').rglob('*'):
            if path.is_file():
                name = path.relative_to(work / 'stage').as_posix()
                require(name in new_files or name == 'release-manifest.json', 'unknown_update_state')
        for path in (work / 'catalog-check').rglob('*'):
            require(path.is_file() and path.name in ('catalog.sqlite', 'catalog.sqlite-wal',
                                                     'catalog.sqlite-shm'), 'unknown_update_state')
        return finish_directory(target, work, uuid.uuid4().hex)
    meta, old_files, new_files, operations = _context(base, target, work)
    require(meta['id'] == owner['id'], 'invalid_recovery_plan')
    # Restore runtime first; the entrypoint stays a blocking stub until last.
    operations.sort(key=lambda op: (op['name'] == ENTRY, op['name'] != 'runtime', op['name']))
    for op in operations:
        name = op['name']
        if name == ENTRY:
            continue
        destination, backup = checked_path(target, name), work / 'backup' / name
        if _exists(backup):
            require(matches(backup, op['old'], op['kind']), 'backup_corrupt')
            if _exists(destination):
                require(matches(destination, op['new'], op['kind']), 'changed_after_interruption')
                discarded = work / 'discard' / name
                discarded.parent.mkdir(parents=True, exist_ok=True)
                require(not _exists(discarded), 'ambiguous_recovery_state')
                event(hook, 'before_discard', name)
                os.rename(destination, discarded)
                event(hook, 'after_discard', name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            event(hook, 'before_restore', name)
            os.rename(backup, destination)
            event(hook, 'after_restore', name)
        elif op['old'] is None:
            if _exists(destination):
                require(matches(destination, op['new'], op['kind']), 'changed_after_interruption')
                discarded = work / 'discard' / name
                discarded.parent.mkdir(parents=True, exist_ok=True)
                require(not _exists(discarded), 'ambiguous_recovery_state')
                event(hook, 'before_discard', name)
                os.rename(destination, discarded)
                event(hook, 'after_discard', name)
        else:
            require(matches(destination, op['old'], op['kind']), 'backup_missing')
    # All old public files must match BEFORE restoring a legacy entrypoint that
    # cannot itself recognize a pending update. This is the rollback commit.
    for name, item in old_files.items():
        if name != ENTRY:
            _verified_file(target, name, item)
    update_guard._check_active_files(target, old_files)
    require(file_item(target / 'release-manifest.json') == file_item(work / 'old/release-manifest.json'), 'rollback_incomplete')
    entry_backup = work / 'backup' / ENTRY
    entry = checked_path(target, ENTRY)
    if _exists(entry_backup):
        require(file_item(entry_backup) == old_files[ENTRY], 'backup_corrupt')
        require(not _exists(entry) or file_item(entry) in (old_files[ENTRY], new_files.get(ENTRY),
                {'bytes': len(BOOTSTRAP), 'sha256': hashlib.sha256(BOOTSTRAP).hexdigest()}), 'changed_after_interruption')
        event(hook, 'before_restore_entry', ENTRY)
        os.replace(entry_backup, entry)
        event(hook, 'after_restore_entry', ENTRY)
    else:
        require(file_item(entry) == old_files[ENTRY], 'backup_missing')
    event(hook, 'before_recovery_commit')
    backup = finish_directory(target, work, meta['id'])
    event(hook, 'after_recovery_commit')
    return backup


def public_errors(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except UpdateError:
            raise
        except (OSError, ValueError, TypeError, sqlite3.Error):
            raise UpdateError('validation_or_filesystem_failed') from None
    return wrapped


@public_errors
def recover(base, target, *, hook=None):
    base, target = paths(base, target)
    compatible_source(base)
    with manager_guard(target):
        check_closed(base, target)
        work = target / PENDING
        require(_exists(work), 'no_pending_update')
        backup = _rollback(base, target, work, hook)
        return {'success': True, 'recovered': True, 'data_unchanged': True, 'backup': backup.name}


@public_errors
def update(base, target, *, hook=None):
    base, target = paths(base, target)
    deadline = time.monotonic() + MAX_SECONDS
    new_files, policy = compatible_source(base)
    source_manifest = file_item(base / 'release-manifest.json')
    new_version = version(base)
    with manager_guard(target):
        check_closed(base, target)
        require(not _exists(target / PENDING), 'update_pending')
        old_version = version(target)
        old_files = authenticated_old(base, target / 'release-manifest.json', old_version, policy)
        old_files = effective_old_files(target, old_files, new_files)
        verify_old_release(target, old_files)
        operations = build_operations(old_files, new_files)
        for op in operations:
            if op['name'] == 'release-manifest.json':
                op['old'] = file_item(target / op['name'])
                op['new'] = file_item(base / op['name'])
        identity = uuid.uuid4().hex
        committed = False
        work = target / PENDING
        work.mkdir()
        try:
            write_new(work / 'owner.json', json.dumps({'format': 1, 'id': identity, 'purpose': 'program-update',
                                                      'overlay_package': base.name}).encode())
            copy_checked(target / 'release-manifest.json', work / 'old/release-manifest.json', file_item(target / 'release-manifest.json'))
            data_summary = validate_data(target, work, deadline)
            stage(base, target, work, old_files, new_files, operations, deadline)
            copy_checked(target / ENTRY, work / 'backup' / ENTRY, old_files[ENTRY])
            plan = {'format': 1, 'id': identity, 'old_version': old_version,
                    'new_manifest': file_item(base / 'release-manifest.json')['sha256'],
                    'overlay_package': base.name}
            write_new(work / 'plan.json', json.dumps(plan, sort_keys=True).encode())
            event(hook, 'after_stage')
            verify_overlay_source(base, new_files, policy, source_manifest)
            # A racing old --self-check bypasses the manager mutex. Publish the
            # no-import stub first, then recheck every process before mutations.
            check_closed(base, target)
            write_new(work / 'bootstrap.pyw', BOOTSTRAP)
            os.replace(work / 'bootstrap.pyw', target / ENTRY)
            event(hook, 'after_bootstrap', ENTRY)
            check_closed(base, target)
            for op in operations:
                tick(deadline)
                name = op['name']
                destination, backup = checked_path(target, name), work / 'backup' / name
                if name == ENTRY:
                    # Publish the final entry only after every other new file
                    # is complete. Even an old-style entry can never see mixed code.
                    for public_name, item in new_files.items():
                        if public_name != ENTRY:
                            _verified_file(target, public_name, item)
                if name != ENTRY and op['old'] is not None:
                    require(matches(destination, op['old'], op['kind']), 'program_changed')
                    backup.parent.mkdir(parents=True, exist_ok=True)
                    event(hook, 'before_move_old', name)
                    os.rename(destination, backup)
                    event(hook, 'after_move_old', name)
                if op['new'] is not None:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    if name == ENTRY:
                        os.replace(work / 'stage' / name, destination)
                    else:
                        require(not _exists(destination), 'unmanaged_or_changed_program')
                        os.rename(work / 'stage' / name, destination)
                    event(hook, 'after_publish', name)
            verify_release(target)
            event(hook, 'before_commit')
            verify_overlay_source(base, new_files, policy, source_manifest)
            backup = finish_directory(target, work, identity)
            committed = True
            event(hook, 'after_commit')
            return {'success': True, 'from_version': old_version, 'to_version': new_version,
                    'data_unchanged': True, 'program_files_updated': len(operations),
                    'backup': backup.name, **data_summary}
        except (Exception, KeyboardInterrupt) as error:
            if committed:
                return {'success': True, 'from_version': old_version, 'to_version': new_version,
                        'data_unchanged': True, 'backup': backup.name,
                        'warning': 'post_commit_notification_failed', **data_summary}
            if _exists(work):
                try:
                    check_closed(base, target)
                    _rollback(base, target, work)
                except Exception:
                    raise UpdateError('recovery_required') from None
            if isinstance(error, UpdateError):
                raise
            raise UpdateError('update_failed_program_restored') from None


