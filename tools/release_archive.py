"""Authenticate and unpack an empty release without consulting installed apps."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from overlay_layout import PACKAGE_DIRECTORY, MARKER, LAUNCHER, BOOTSTRAP, RETIRED_LAUNCHERS, launcher_bytes

MAX_FILES = 40000
MAX_BYTES = 4 * 1024 ** 3
MAX_MANIFEST = 16 * 1024 ** 2
REQUIRED = ('VERSION', 'release-manifest.json', 'runtime/manifest.sha256.json',
            'runtime/python/python.exe', 'runtime/python/pythonw.exe',
            'runtime/node/node.exe', 'runtime/webview2/msedgewebview2.exe',
            'app/engines/148/BitBrowser.exe', 'app/engines/148/manifest.json',
            'app/resources/pythonnet.config', 'tools/check_project.py')
OVERLAY_REQUIRED = REQUIRED + (MARKER, LAUNCHER, BOOTSTRAP, 'app/local_browser.pyw',
                               'app/update_guard.py', 'tools/inplace_update.py',
                               'tools/overlay_layout.py', 'update-policy.json')


def require(condition):
    if not condition:
        raise ValueError()


def ordinary(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode)
            and not getattr(info, 'st_file_attributes', 0) & 0x400)
    require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))


def relative_name(name):
    require(isinstance(name, str) and bool(name) and '\\' not in name and ':' not in name)
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name and '..' not in path.parts)
    reserved = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'}
    reserved.update(a + b for a in ('COM', 'LPT') for b in '0123456789¹²³')
    require(all(part.rstrip(' .') == part and part.split('.')[0].upper() not in reserved
                and not any(ord(c) < 32 or c in '<>"|?*' for c in part) for part in path.parts))
    return path


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def manifest(raw):
    require(len(raw) <= MAX_MANIFEST)
    value = json.loads(raw, object_pairs_hook=no_duplicates)
    require(isinstance(value, dict) and value.get('algorithm') == 'SHA256')
    files = value.get('files')
    require(isinstance(files, dict) and 0 < len(files) <= MAX_FILES)
    folded = set()
    for name, entry in files.items():
        relative_name(name)
        first = name.split('/')[0].casefold()
        require(first != PACKAGE_DIRECTORY and not first.startswith('.program-update-backup-'))
        require(name.casefold() not in folded)
        folded.add(name.casefold())
        require(isinstance(entry, dict) and type(entry.get('bytes')) is int
                and 0 <= entry['bytes'] <= MAX_BYTES
                and isinstance(entry.get('sha256'), str)
                and re.fullmatch('[0-9a-f]{64}', entry['sha256']) is not None)
    return files


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def package_layout(names, read_small):
    """Return the program prefix after authenticating generated overlay fields."""
    overlay_names = {name for name in names if name.split('/')[0].casefold() == PACKAGE_DIRECTORY}
    if not overlay_names:
        return '', None
    require(all(name.startswith(PACKAGE_DIRECTORY + '/') for name in overlay_names))
    identities = {PurePosixPath(name).parts[1] for name in overlay_names}
    require(len(identities) == 1)
    package_id = next(iter(identities))
    require(re.fullmatch('[0-9a-f]{32}', package_id) is not None)
    prefix = PACKAGE_DIRECTORY + '/' + package_id + '/'
    require(all(name.startswith(prefix) or name == LAUNCHER for name in names))
    require({LAUNCHER, prefix + LAUNCHER, prefix + MARKER, prefix + BOOTSTRAP} <= set(names))
    marker = json.loads(read_small(prefix + MARKER), object_pairs_hook=no_duplicates)
    require(isinstance(marker, dict) and set(marker) == {'format', 'package_id'}
            and type(marker['format']) is int and marker['format'] == 1
            and marker['package_id'] == package_id)
    launcher = launcher_bytes(package_id)
    require(read_small(LAUNCHER) == launcher and read_small(prefix + LAUNCHER) == launcher)
    return prefix, package_id


def extract(archive_path, expected, destination):
    archive_path, destination = Path(archive_path).absolute(), Path(destination).absolute()
    ordinary(archive_path)
    require(re.fullmatch('[0-9a-f]{64}', expected) is not None and digest(archive_path) == expected)
    require(not destination.exists() and not destination.is_symlink())
    for parent in destination.parents:
        if parent.exists():
            ordinary(parent)
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= MAX_FILES)
        require(sum(entry.file_size for entry in entries) <= MAX_BYTES)
        names, files, directories = set(), {}, set()
        for entry in entries:
            name = entry.filename[:-1] if entry.is_dir() else entry.filename
            path = relative_name(name)
            require(name.casefold() not in names and not entry.flag_bits & 1)
            names.add(name.casefold())
            mode = entry.external_attr >> 16
            require(not stat.S_ISLNK(mode) and not entry.external_attr & 0x400)
            if entry.is_dir():
                directories.add(name)
            else:
                files[name] = entry
        # Both layouts also accept one ordinary, user-visible wrapper folder.
        prefix = ''
        if 'release-manifest.json' not in files and LAUNCHER not in files:
            wrappers = {PurePosixPath(name).parts[0] for name in files}
            require(len(wrappers) == 1)
            prefix = next(iter(wrappers)) + '/'
        normalized = {name[len(prefix):]: entry for name, entry in files.items()}
        require(all(name.startswith(prefix) for name in files))
        require(all(name == prefix.rstrip('/') or name.startswith(prefix) for name in directories))
        normalized_directories = {name[len(prefix):] for name in directories if name != prefix.rstrip('/')}
        def read_small(name):
            require(normalized[name].file_size <= 8192)
            return archive.read(normalized[name])
        program_prefix, package_id = package_layout(normalized, read_small)
        program_files = {name[len(program_prefix):]: entry for name, entry in normalized.items()
                         if name.startswith(program_prefix)}
        require(all(name in program_files for name in (OVERLAY_REQUIRED if package_id else REQUIRED)))
        if package_id:
            require(not {name.casefold() for name in RETIRED_LAUNCHERS}.intersection(
                name.casefold() for name in program_files))
            version = read_small(program_prefix + 'VERSION').decode('utf-8-sig').strip()
            require(re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version) is not None)
            require(all(name in (PACKAGE_DIRECTORY, program_prefix.rstrip('/'))
                        or name.startswith(program_prefix) for name in normalized_directories))
        else:
            require(not any(name.split('/')[0].casefold() == PACKAGE_DIRECTORY for name in normalized_directories))
        forbidden = ('app/data', 'app/local-engines', '.git')
        for name in (*program_files, *(name[len(program_prefix):] for name in normalized_directories
                                       if name.startswith(program_prefix))):
            relative = name.casefold()
            require(not any(relative == item or relative.startswith(item + '/') for item in forbidden))
            first = relative.split('/')[0]
            require(first != PACKAGE_DIRECTORY and not first.startswith('.program-update-backup-'))
        # A file cannot also be an ancestor directory, including Windows case aliases.
        file_names = {name.casefold() for name in files}
        require(all(not any(parent.as_posix().casefold() in file_names
                            for parent in PurePosixPath(name).parents if str(parent) != '.')
                    for name in (*files, *directories)))
        require(program_files['release-manifest.json'].file_size <= MAX_MANIFEST
                and program_files['runtime/manifest.sha256.json'].file_size <= MAX_MANIFEST)
        release = manifest(archive.read(program_files['release-manifest.json']))
        require(set(release) == set(program_files) - {'release-manifest.json'})
        runtime = manifest(archive.read(program_files['runtime/manifest.sha256.json']))
        expected_runtime = {name[len('runtime/'):]: value for name, value in release.items()
                            if name.startswith('runtime/') and name != 'runtime/manifest.sha256.json'}
        require(runtime == expected_runtime)
        destination.mkdir(parents=True)
        for name in sorted(directories):
            if name == prefix.rstrip('/'):
                continue
            require(name.startswith(prefix))
            destination.joinpath(*PurePosixPath(name[len(prefix):]).parts).mkdir(parents=True, exist_ok=True)
        total = 0
        for name, entry in normalized.items():
            target = destination.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            hashed, size = hashlib.sha256(), 0
            with archive.open(entry) as source, target.open('xb') as output:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    size += len(block)
                    total += len(block)
                    require(size <= entry.file_size and total <= MAX_BYTES)
                    output.write(block)
                    hashed.update(block)
            require(size == entry.file_size)
            relative = name[len(program_prefix):] if name.startswith(program_prefix) else None
            if relative in release:
                require({'bytes': size, 'sha256': hashed.hexdigest()} == release[relative])
        report = {'success': True, 'files': len(normalized), 'bytes': total,
                'archive_digest_verified': True, 'complete_manifest_verified': True,
                'runtime_manifest_verified': True, 'contains_user_data': False,
                'layout': 'overlay' if package_id else 'flat',
                'program_root': str(destination.joinpath(*PurePosixPath(program_prefix).parts))}
        if package_id:
            report['package_id'] = package_id
        return report


def verify_source(source_root, destination):
    source_root = Path(source_root).resolve()
    destination = Path(destination).resolve()
    sys.path.insert(0, str(source_root / 'tools'))
    from build_release import source_files,UPDATE_POLICY
    files = source_files(source_root)
    expected = {source.relative_to(source_root).as_posix() for source in files}
    actual = {path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()}
    def read_small(name):
        path = destination / name
        ordinary(path)
        require(path.stat().st_size <= 8192)
        return path.read_bytes()
    program_prefix, package_id = package_layout(actual, read_small)
    if package_id:
        destination = destination.joinpath(*PurePosixPath(program_prefix).parts)
        actual = {name[len(program_prefix):] for name in actual if name.startswith(program_prefix)}
        require(MARKER in actual and LAUNCHER in expected)
    require({name for name in actual if not name.startswith(('runtime/', 'app/engines/'))
             and name not in ('release-manifest.json','update-policy.json')
             and not (package_id and name == MARKER)} == expected)
    policy=destination/'update-policy.json'
    if policy.is_file():
        ordinary(policy)
        require(json.loads(policy.read_text('utf-8'))==UPDATE_POLICY)
    for source in files:
        target = destination / source.relative_to(source_root)
        ordinary(target)
        if package_id and source.relative_to(source_root).as_posix() == LAUNCHER:
            require(target.read_bytes() == launcher_bytes(package_id))
        else:
            require(digest(source) == digest(target))
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--source-root', type=Path)
    args = parser.parse_args()
    try:
        report = extract(args.archive, args.sha256, args.destination)
        if args.source_root:
            report['source_files'] = verify_source(args.source_root, args.destination)
            report['source_matches_checkout'] = True
    except Exception as error:
        report = {'success': False, 'error_type': type(error).__name__}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
