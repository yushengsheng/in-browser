"""Read-only release checks performed before application services are imported.

These checks prove consistency with a public checksum manifest, not publisher
identity. No user data, local signing deployments or extra engine inventories
are read, initialized or repaired here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


MAX_MANIFEST = 16 * 1024 * 1024
MAX_FILES = 40000
MAX_BYTES = 4 * 1024 ** 3
PROTECTED = ('app/data', 'app/local-engines')


class UpdateGuardError(ValueError):
    """An incomplete update or inconsistent public release must not start."""


def _require(condition):
    if not condition:
        raise UpdateGuardError('Program installation is incomplete or inconsistent.')


def _ordinary(path, *, directory=None):
    info = path.lstat()
    _require(not stat.S_ISLNK(info.st_mode)
             and not getattr(info, 'st_file_attributes', 0) & 0x400)
    _require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
    if directory is not None:
        _require(stat.S_ISDIR(info.st_mode) == directory)
    return info


def _exists(path):
    # exists() alone misses broken symlinks and other interrupted-update markers.
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _root(path):
    root = Path(os.path.abspath(path))
    for part in (root, *root.parents):
        _ordinary(part, directory=True)
    return root


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _json_file(path, limit):
    before = _ordinary(path, directory=False)
    _require(before.st_size <= limit)
    with path.open('rb') as handle:
        raw = handle.read(limit + 1)
    _require(len(raw) <= limit)
    after = _ordinary(path, directory=False)
    _require(_identity(before) == _identity(after))
    try:
        return json.loads(raw, object_pairs_hook=_unique_pairs,
                          parse_constant=lambda value: _require(False))
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise UpdateGuardError('Invalid public release metadata.') from exc


def _relative_name(name):
    _require(isinstance(name, str) and bool(name) and '\\' not in name and ':' not in name)
    path = PurePosixPath(name)
    _require(not path.is_absolute() and path.as_posix() == name and '..' not in path.parts)
    reserved = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'}
    reserved.update(a + b for a in ('COM', 'LPT') for b in '0123456789¹²³')
    _require(all(part.rstrip(' .') == part and part.split('.')[0].upper() not in reserved
                 and not any(ord(c) < 32 or ord(c) == 127 or c in '<>"|?*' for c in part)
                 for part in path.parts))
    folded = name.casefold()
    _require(folded not in ('release-manifest.json', '.program-update')
             and not folded.startswith('.program-update/'))
    _require(not any(folded == item or folded.startswith(item + '/') for item in PROTECTED))
    return path


def _manifest(root):
    value = _json_file(root / 'release-manifest.json', MAX_MANIFEST)
    _require(isinstance(value, dict) and set(value) == {'algorithm', 'files'}
             and value.get('algorithm') == 'SHA256')
    files = value['files']
    _require(isinstance(files, dict) and 0 < len(files) <= MAX_FILES)
    folded, directories, total = set(), {}, 0
    for name, entry in files.items():
        path = _relative_name(name)
        _require(name.casefold() not in folded)
        folded.add(name.casefold())
        _require(isinstance(entry, dict) and set(entry) == {'bytes', 'sha256'}
                 and type(entry.get('bytes')) is int and 0 <= entry['bytes'] <= MAX_BYTES
                 and isinstance(entry.get('sha256'), str)
                 and re.fullmatch('[0-9a-f]{64}', entry['sha256']) is not None)
        total += entry['bytes']
        _require(total <= MAX_BYTES)
        for parent in path.parents:
            if str(parent) == '.':
                continue
            parent_name = parent.as_posix()
            key = parent_name.casefold()
            _require(key not in directories or directories[key] == parent_name)
            directories[key] = parent_name
    _require(not folded.intersection(directories))
    return files


def read_update_policy(root):
    """Return a strict, public compatibility policy, or None for older releases."""
    path = Path(root) / 'update-policy.json'
    if not _exists(path):
        return None
    value = _json_file(path, 64 * 1024)
    _require(isinstance(value, dict) and set(value) == {'format', 'from_versions', 'data_format'}
             and type(value['format']) is int and value['format'] == 1
             and type(value['data_format']) is int and value['data_format'] == 1)
    versions = value['from_versions']
    _require(isinstance(versions, dict) and 0 < len(versions) <= 1000)
    _require(all(isinstance(version, str) and len(version) <= 128
                 and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?', version)
                 and isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest)
                 for version, digest in versions.items()))
    return value


def _identity(info):
    # Windows path stat derives executable bits from the filename; handle stat
    # cannot do so. Windows ctime also differs between path and handle APIs on
    # Python 3.13; birthtime is the stable creation identity on both APIs.
    mode = info.st_mode & ~0o111 if os.name == 'nt' else info.st_mode
    created = getattr(info, 'st_birthtime_ns', info.st_ctime_ns) if os.name == 'nt' else info.st_ctime_ns
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, created,
            mode, getattr(info, 'st_file_attributes', 0))


def _verified_file(root, name, expected):
    path = root.joinpath(*PurePosixPath(name).parts)
    for parent in path.parents:
        if parent == root:
            break
        _ordinary(parent, directory=True)
    before = _ordinary(path, directory=False)
    _require(before.st_size == expected['bytes'])
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        _require(_identity(before) == _identity(opened))
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            size += len(block)
            _require(size <= expected['bytes'])
            digest.update(block)
        _require(_identity(opened) == _identity(os.fstat(handle.fileno())))
    _require(_identity(before) == _identity(_ordinary(path, directory=False)))
    _require(size == expected['bytes'] and digest.hexdigest() == expected['sha256'])


def _check_active_files(root, files):
    # Legacy caches are left intact. The entrypoint redirects Python's cache
    # lookup before importing any application module, and writes no new cache.
    skipped = {'app/data', 'app/local-engines', 'app/engines',
               'app/__pycache__', 'tools/__pycache__'}
    for name in ('app', 'runtime', 'tools'):
        top = root / name
        if not _exists(top):
            continue
        _ordinary(top, directory=True)
        pending = [top]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    relative = path.relative_to(root).as_posix()
                    if relative.casefold() in skipped:
                        # Check only the boundary, never enumerate private trees.
                        _ordinary(path, directory=True)
                        continue
                    info = _ordinary(path)
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(path)
                    else:
                        _require(relative in files)


def verify_release(root):
    """Verify public files only; deliberately permit an updater's pending marker.

    A source checkout without either release marker keeps its development
    entrypoint. A package carrying update-policy.json must carry its manifest.
    Extra raw engine inventories, private data and legacy app caches are kept.
    """
    try:
        root = _root(root)
        has_manifest = _exists(root / 'release-manifest.json')
        policy = read_update_policy(root)
        if not has_manifest:
            _require(policy is None)
            return {'development': True, 'files': {}, 'verified_files': 0, 'verified_bytes': 0}
        files = _manifest(root)
        if policy is not None:
            _require('update-policy.json' in files)
        for name, expected in files.items():
            _verified_file(root, name, expected)
        _check_active_files(root, files)
        return {'development': False, 'files': files, 'verified_files': len(files),
                'verified_bytes': sum(entry['bytes'] for entry in files.values())}
    except (OSError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        if isinstance(exc, UpdateGuardError):
            raise
        raise UpdateGuardError('Program installation is incomplete or inconsistent.') from exc


def require_complete_installation(root):
    """Refuse every interrupted-update marker before reading release metadata."""
    try:
        root = _root(root)
        _require(not _exists(root / '.program-update'))
        return verify_release(root)
    except OSError as exc:
        raise UpdateGuardError('Program update is incomplete.') from exc
