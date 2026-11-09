"""Read-only installed-data checks. Output contains counts and hashes only."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

from app_paths import DATA_ROOT
from browser_processes import profile_processes
from configuration import Configuration
from fingerprint_continuity import (binding_for, FORMAT, PROBE_VERSION, MAX_BASELINE_FIELDS,
                                   MAX_SNAPSHOT_BYTES, _REQUIRED, _REQUIRED_STABLE,
                                   _RASTER_FIELDS, _safe_field, _json)
from local_engine import LocalEngineStore
from local_signer import LocalSigner
from local_state import protect, read_encrypted
from portable_paths import decode_record
from portable_browser import _private_key, _validate_databases, _DATABASES

MAX_DATABASE_COPY_BYTES = 512 * 1024 * 1024
MAX_PROFILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_PROFILE_FILES = 200000
MAX_CATALOG_ROWS = 10000
MAX_RECORD_BYTES = 16 * 1024 * 1024
SCAN_TIMEOUT = 120


class SnapshotChanged(Exception):
    pass


def _deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError()


def _plain(path):
    value = Path(path).lstat()
    if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
        raise ValueError()
    return value


def _stamp(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def digest_file(path, deadline=None, limit=MAX_PROFILE_BYTES):
    _deadline(deadline)
    path = Path(path)
    before = _plain(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError()
    value = hashlib.sha256()
    read = 0
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            _deadline(deadline)
            read += len(block)
            if read > limit:
                raise ValueError()
            value.update(block)
    if _stamp(before) != _stamp(path.stat()) or read != before.st_size:
        raise SnapshotChanged()
    return value.hexdigest()


def profile_digest(folder, deadline=None, *, with_identity=False):
    folder = Path(folder)
    _plain(folder)
    value = hashlib.sha256()
    identity = hashlib.sha256()
    total = 0
    count = 0
    paths = []
    for index, path in enumerate(folder.rglob('*')):
        _deadline(deadline)
        if index >= MAX_PROFILE_FILES * 2:
            raise ValueError()
        info = _plain(path)
        if not stat.S_ISREG(info.st_mode):
            continue
        paths.append(path)
        total += info.st_size
        if len(paths) > MAX_PROFILE_FILES or total > MAX_PROFILE_BYTES:
            raise ValueError()
    total = 0
    for path in sorted(paths):
        _deadline(deadline)
        relative = path.relative_to(folder).as_posix()
        before = _plain(path)
        content_hash = digest_file(path, deadline)
        if _stamp(before) != _stamp(path.stat()):
            raise SnapshotChanged()
        value.update(relative.encode('utf-8'))
        value.update(bytes.fromhex(content_hash))
        identity.update(_json([relative, _stamp(before), content_hash]))
        total += before.st_size
        if total > MAX_PROFILE_BYTES:
            raise ValueError()
        count += 1
    summary = {'files': count, 'bytes': total, 'sha256': value.hexdigest()}
    return (summary, identity.hexdigest()) if with_identity else summary


def database_fingerprint(path, deadline):
    """Read bytes only: never ask SQLite to open an original installation file."""
    path = Path(path)
    identity = {}
    total = 0
    for suffix in ('', '-wal', '-shm', '-journal'):
        candidate = path.with_name(path.name + suffix)
        try:
            info = _plain(candidate)
        except FileNotFoundError:
            identity[suffix] = None
            continue
        total += info.st_size
        if total > MAX_DATABASE_COPY_BYTES or (suffix == '-journal' and info.st_size):
            raise ValueError()
        identity[suffix] = (_stamp(info), digest_file(candidate, deadline, MAX_DATABASE_COPY_BYTES))
    if identity[''] is None:
        raise FileNotFoundError()
    return identity


@contextmanager
def database_snapshot(path, destination, deadline):
    """Copy main + WAL without source locks or sidecar creation; reject changes."""
    path, destination = Path(path), Path(destination)
    before = database_fingerprint(path, deadline)
    destination.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ('', '-wal'):
        if before[suffix] is None:
            continue
        source = path.with_name(path.name + suffix)
        target = destination.with_name(destination.name + suffix)
        copied = 0
        with source.open('rb') as reader, target.open('xb') as writer:
            while block := reader.read(1024 * 1024):
                _deadline(deadline)
                copied += len(block)
                if copied > before[suffix][0][2]:
                    raise SnapshotChanged()
                writer.write(block)
        if copied != before[suffix][0][2] or digest_file(target, deadline, MAX_DATABASE_COPY_BYTES) != before[suffix][1]:
            raise SnapshotChanged()
    if database_fingerprint(path, deadline) != before:
        raise SnapshotChanged()
    try:
        yield destination, before
    finally:
        if database_fingerprint(path, deadline) != before:
            raise SnapshotChanged()


def _rows(connection, query, deadline):
    values = []
    for row in connection.execute(query):
        _deadline(deadline)
        if len(values) >= MAX_CATALOG_ROWS:
            raise ValueError()
        if any(isinstance(value, (bytes, str)) and len(value) > MAX_RECORD_BYTES for value in row):
            raise ValueError()
        values.append(row)
    return values


def _decode(payload, root):
    def invalid_constant(_):
        raise ValueError()
    return decode_record(json.loads(protect(payload, decrypt=True, root=root), parse_constant=invalid_constant), root)


def read_catalog(root, deadline):
    with tempfile.TemporaryDirectory(prefix='installation-catalog-') as directory:
        with database_snapshot(root / 'windows.sqlite', Path(directory) / 'catalog.sqlite', deadline) as (copied, identity):
            con = sqlite3.connect(copied.as_uri() + '?mode=ro', uri=True, timeout=5)
            try:
                con.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                con.execute('PRAGMA query_only=ON')
                con.execute('BEGIN')
                quick_check = con.execute('PRAGMA quick_check').fetchone() == ('ok',)
                profiles = _rows(con, 'SELECT id,seq,created_at,last_opened_at,archived,data FROM profiles ORDER BY seq', deadline)
                settings = _rows(con, 'SELECT key,value FROM settings ORDER BY key', deadline)
                bindings = _rows(con, 'SELECT source_key,profile_id,imported_at FROM source_bindings ORDER BY source_key', deadline)
            finally:
                con.close()
            payloads = hashlib.sha256()
            full = hashlib.sha256()
            for rows in (profiles, settings):
                for row in rows:
                    payloads.update(hashlib.sha256(row[-1]).digest())
            for table, rows in (('profiles', profiles), ('settings', settings), ('source_bindings', bindings)):
                full.update(_json(table))
                for row in rows:
                    full.update(_json([{'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
                                       if isinstance(value, bytes) else value for value in row]))
            records = [_decode(row[-1], root) for row in profiles]
            for _key, payload in settings:
                _decode(payload, root)
            return {'records': records, 'quick_check': quick_check,
                    'catalog_payload_sha256': payloads.hexdigest(), 'catalog_full_tables_sha256': full.hexdigest(),
                    'settings': len(settings), 'source_bindings': len(bindings), 'identity': identity}


def baseline_structure_valid(baseline):
    """Mirror verify_continuity's pre-probe contract using its shared constants."""
    if not isinstance(baseline, dict) or baseline.get('format') != FORMAT or baseline.get('probe_version') != PROBE_VERSION:
        return False
    stable, unstable = baseline.get('stable'), baseline.get('unstable')
    if (not isinstance(stable, dict) or not stable or len(stable) > MAX_BASELINE_FIELDS
            or any(not _safe_field(key) for key in stable) or not isinstance(unstable, list)
            or any(not _safe_field(key) for key in unstable)
            or not _REQUIRED <= stable.keys() | set(unstable)
            or not _REQUIRED_STABLE <= stable.keys() or not _RASTER_FIELDS & stable.keys()):
        return False
    try:
        return len(_json(baseline)) <= MAX_SNAPSHOT_BYTES
    except (ValueError, TypeError):
        return False


def inspect_profile(profile, private, deadline):
    try:
        active = bool(profile_processes(profile, require_inspectable=True))
    except Exception as error:
        return {'running': None, 'profile_validation': 'skipped_uninspectable', 'error_type': type(error).__name__}
    if active:
        return {'running': True, 'profile_validation': 'skipped_running'}
    try:
        before = profile_digest(profile, deadline, with_identity=True)
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory(prefix='installation-profile-') as directory, ExitStack() as stack:
            temporary = Path(directory)
            for relative, _table, _column in _DATABASES:
                source = profile / relative
                if source.exists():
                    stack.enter_context(database_snapshot(source, temporary / relative, deadline))
            _validate_databases(temporary, _private_key(private))
            _deadline(deadline)
        after = profile_digest(profile, deadline, with_identity=True)
        active = bool(profile_processes(profile, require_inspectable=True))
        if active or before != after:
            return {'running': active, 'profile_validation': 'skipped_state_changed'}
        return {'running': False, 'profile_validation': 'verified_closed',
                'browser_ciphertext_authenticated': True, 'profile_snapshot': before[0]}
    except Exception as error:
        return {'running': None, 'profile_validation': 'failed', 'error_type': type(error).__name__}


def inspect(root=None):
    result = {'format': 1, 'checked_at': datetime.now(timezone.utc).isoformat(),
              'read_only': True, 'checks': {}, 'profiles': [], 'success': False}
    checks = result['checks']
    root = Path(root) if root is not None else DATA_ROOT
    deadline = time.monotonic() + SCAN_TIMEOUT
    catalog = read_catalog(root, deadline)
    records = catalog['records']
    checks['catalog_quick_check'] = catalog['quick_check']
    checks['settings_decrypted_and_decoded'] = True
    result.update({key: catalog[key] for key in ('catalog_payload_sha256', 'catalog_full_tables_sha256', 'settings', 'source_bindings')})
    result['windows'] = len(records)
    result['archived'] = sum(bool(record.get('archived')) for record in records)
    for marker in ('independent-mode.bin', 'portable-mode.bin', 'continuity-mode.bin'):
        value = read_encrypted(root / marker, root=root)
        checks[marker + '_valid'] = value.get('format') == 1 and value.get('state', 'ready') == 'ready'
    signer = LocalSigner(root, load_private=False)
    # Reading the private record through the current store proves it is portable;
    # no key, field value or raw payload is retained in the diagnostic report.
    private = read_encrypted(root / 'local-signing/private.bin', root=root)
    checks['private_signing_record_readable'] = private.get('key_id') == signer.key_id
    resources = root / 'resources'
    if not resources.is_dir() or not all((resources / name).is_file() for name in ('electron-main.js', 'crypto.worker.js', 'defaults.json')):
        raise FileNotFoundError()
    configuration = Configuration(root)
    engines = LocalEngineStore()
    checked_engines = set()
    for index, record in enumerate(records, 1):
        runtime = record['_runtime']
        profile = Path(runtime['profile_path'])
        _deadline(deadline)
        row = {'alias': index, 'core': str(runtime['core_major'])}
        row['paths_present'] = all(Path(runtime[key]).is_file() if key != 'profile_path' else Path(runtime[key]).is_dir()
                                   for key in ('profile_path', 'fingerprint_path', 'core_path'))
        row['signature_valid'] = signer.verify(runtime['fingerprint_path'])
        row['signature_file_hash_matches'] = digest_file(runtime['fingerprint_path'], deadline) == runtime['fingerprint_sha256']
        row['native_matches_encrypted_config'] = configuration.decode(runtime['fingerprint_path']) == record['_native']
        row['local_signing_identity_matches'] = runtime.get('signature_provider') == 'local-v1' and runtime.get('signature_key_id') == signer.key_id
        pin = (str(runtime['core_path']), str(runtime['core_major']))
        if pin not in checked_engines:
            engines.validate(runtime['core_path'], signer.key_id, runtime['core_major'])
            checked_engines.add(pin)
        baseline = record.get('_continuity')
        row['continuity_structure_valid'] = baseline_structure_valid(baseline)
        row['continuity_binding_matches'] = row['continuity_structure_valid'] and baseline.get('binding') == binding_for(record, root)
        row['stable_signal_count'] = len(baseline['stable']) if row['continuity_structure_valid'] else 0
        row.update(inspect_profile(profile, record.get('_portable_crypt'), deadline))
        result['profiles'].append(row)
    checks['all_record_checks'] = all(row.get(key) for row in result['profiles'] for key in (
        'paths_present', 'signature_valid', 'signature_file_hash_matches', 'native_matches_encrypted_config',
        'local_signing_identity_matches', 'continuity_structure_valid', 'continuity_binding_matches'))
    checks['all_profile_checks_complete'] = all(row.get('browser_ciphertext_authenticated') is True and
                                               'profile_snapshot' in row for row in result['profiles'])
    archive = configuration.source_archive()
    checks['source_archive_local_key_matches'] = archive.get('key_id') == signer.key_id
    result['archived_sources'] = len(archive.get('items') or {})
    result['verified_engine_trees'] = len(checked_engines)
    manifest = json.loads((ROOT / 'runtime/manifest.sha256.json').read_text(encoding='utf-8'))
    checks['bundled_runtime_hashes_match'] = all(
        (ROOT / 'runtime' / name).stat().st_size == item['bytes'] and digest_file(ROOT / 'runtime' / name, deadline) == item['sha256']
        for name, item in manifest['files'].items())
    result['verified_runtime_files'] = len(manifest['files'])
    result['temporary_probe_directories'] = len(list(root.glob('continuity-probe-*')))
    checks['no_abandoned_environment_probes'] = result['temporary_probe_directories'] == 0
    checks['catalog_unchanged_during_inspection'] = database_fingerprint(root / 'windows.sqlite', deadline) == catalog['identity']
    _deadline(deadline)
    result['success'] = all(checks.values())
    return result


def compare_reports(before, current):
    full_available = 'catalog_full_tables_sha256' in before
    unchanged = {
        'catalog_payloads': before.get('catalog_payload_sha256') == current.get('catalog_payload_sha256'),
        'closed_profile_files': [row.get('profile_snapshot') for row in before.get('profiles', [])] ==
                                [row.get('profile_snapshot') for row in current['profiles']]}
    if full_available:
        unchanged['catalog_full_tables'] = before['catalog_full_tables_sha256'] == current.get('catalog_full_tables_sha256')
    current['comparison_coverage'] = {'catalog_full_tables_available_in_previous_report': full_available}
    current['unchanged_since_comparison'] = unchanged
    current['success'] = current['success'] and all(unchanged.values())


def write_report(path, result):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=ROOT / 'analysis/reports/installation-latest.json')
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args(argv)
    try:
        result = inspect()
        if args.compare:
            before = json.loads(args.compare.read_text(encoding='utf-8'))
            compare_reports(before, result)
    except Exception as error:
        result = {'success': False, 'read_only': True, 'error_type': type(error).__name__}
    try:
        write_report(args.report, result)
    except Exception as error:
        result = {'success': False, 'error_type': type(error).__name__}
    print(json.dumps({'success': result['success'], 'windows': result.get('windows'),
                      'verified_engine_trees': result.get('verified_engine_trees'),
                      'verified_runtime_files': result.get('verified_runtime_files'),
                      'checks': result.get('checks'), 'unchanged': result.get('unchanged_since_comparison'),
                      'comparison_coverage': result.get('comparison_coverage'),
                      'error_type': result.get('error_type')}, ensure_ascii=False))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
