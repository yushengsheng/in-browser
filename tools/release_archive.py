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

MAX_FILES = 40000
MAX_BYTES = 4 * 1024 ** 3
MAX_MANIFEST = 16 * 1024 ** 2
REQUIRED = ('VERSION', 'release-manifest.json', 'runtime/manifest.sha256.json',
            'runtime/python/python.exe', 'runtime/python/pythonw.exe',
            'runtime/node/node.exe', 'runtime/webview2/msedgewebview2.exe',
            'app/engines/148/BitBrowser.exe', 'app/engines/148/manifest.json',
            'app/resources/pythonnet.config', 'tools/check_project.py')


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
        # The builder emits a flat ZIP. Also accept a single ordinary wrapper folder.
        prefix = ''
        if 'release-manifest.json' not in files:
            wrappers = {PurePosixPath(name).parts[0] for name in files}
            require(len(wrappers) == 1)
            prefix = next(iter(wrappers)) + '/'
            require(prefix + 'release-manifest.json' in files)
        normalized = {name[len(prefix):]: entry for name, entry in files.items()}
        require(all(name.startswith(prefix) for name in files))
        require(all(name in normalized for name in REQUIRED))
        forbidden = ('app/data', 'app/local-engines', '.git')
        for name in (*files, *directories):
            relative = name[len(prefix):].casefold()
            require(not any(relative == item or relative.startswith(item + '/') for item in forbidden))
        # A file cannot also be an ancestor directory, including Windows case aliases.
        file_names = {name.casefold() for name in files}
        require(all(not any(parent.as_posix().casefold() in file_names
                            for parent in PurePosixPath(name).parents if str(parent) != '.')
                    for name in (*files, *directories)))
        require(normalized['release-manifest.json'].file_size <= MAX_MANIFEST
                and normalized['runtime/manifest.sha256.json'].file_size <= MAX_MANIFEST)
        release = manifest(archive.read(normalized['release-manifest.json']))
        require(set(release) == set(normalized) - {'release-manifest.json'})
        runtime = manifest(archive.read(normalized['runtime/manifest.sha256.json']))
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
            if name in release:
                require({'bytes': size, 'sha256': hashed.hexdigest()} == release[name])
        return {'success': True, 'files': len(normalized), 'bytes': total,
                'archive_digest_verified': True, 'complete_manifest_verified': True,
                'runtime_manifest_verified': True, 'contains_user_data': False}


def verify_source(source_root, destination):
    source_root = Path(source_root).resolve()
    destination = Path(destination).resolve()
    sys.path.insert(0, str(source_root / 'tools'))
    from build_release import source_files
    files = source_files(source_root)
    expected = {source.relative_to(source_root).as_posix() for source in files}
    actual = {path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()}
    require({name for name in actual if not name.startswith(('runtime/', 'app/engines/'))
             and name != 'release-manifest.json'} == expected)
    for source in files:
        target = destination / source.relative_to(source_root)
        ordinary(target)
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
