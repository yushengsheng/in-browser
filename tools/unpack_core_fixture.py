"""Read the pinned public fixture index and unpack one synthetic source-device core."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'app')]
from core_specs import CORE_SPECS
from release_archive import digest, no_duplicates, ordinary, relative_name, require

MAX_FILES = 40000
MAX_BYTES = 4 * 1024 ** 3
MAX_ARCHIVE = 2 * 1024 ** 3
MARKERS = {'portable-test.json', 'vendor-signature.bin', 'all-core-fixture.json'}
PREFIXES = ('app/data/', 'app/local-engines/')


def fixture_index(path):
    ordinary(path)
    require(path.stat().st_size <= 65536)
    index = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=no_duplicates)
    require(isinstance(index, dict) and index.get('format') == 1)
    tag = index.get('release_tag')
    require(isinstance(tag, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,95}', tag))
    fixtures = index.get('fixtures')
    require(isinstance(fixtures, list) and len(fixtures) == len(CORE_SPECS))
    by_core, names = {}, set()
    for entry in fixtures:
        require(isinstance(entry, dict))
        core, asset, checksum, size = (entry.get(key) for key in ('core', 'asset', 'sha256', 'bytes'))
        require(isinstance(core, str) and core in CORE_SPECS and core not in by_core)
        require(isinstance(asset, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip', asset)
                and asset.casefold() not in names)
        require(isinstance(checksum, str) and re.fullmatch('[0-9a-f]{64}', checksum))
        require(type(size) is int and 0 < size < MAX_ARCHIVE)
        names.add(asset.casefold())
        by_core[core] = {'core': core, 'asset': asset, 'sha256': checksum, 'bytes': size}
    require(set(by_core) == set(CORE_SPECS))
    return tag, by_core


def unpack(archive_path, package, core, entry):
    archive_path, package = archive_path.absolute(), package.absolute()
    ordinary(archive_path)
    for parent in archive_path.parents:
        ordinary(parent)
    require(archive_path.stat().st_size == entry['bytes'] and digest(archive_path) == entry['sha256'])
    ordinary(package)
    for parent in package.parents:
        ordinary(parent)
    require((package / 'release-manifest.json').is_file())
    for name in ('app',):
        ordinary(package / name)
    for name in ('app/data', 'app/local-engines', *MARKERS):
        target = package / name
        require(not target.exists() and not target.is_symlink())
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= MAX_FILES and sum(item.file_size for item in entries) <= MAX_BYTES)
        files, directories, folded = {}, set(), set()
        for item in entries:
            name = item.filename[:-1] if item.is_dir() else item.filename
            relative_name(name)
            require(name.casefold() not in folded and not item.flag_bits & 1)
            folded.add(name.casefold())
            require(not stat.S_ISLNK(item.external_attr >> 16) and not item.external_attr & 0x400)
            if item.is_dir():
                require(name in ('app', 'app/data', 'app/local-engines')
                        or name.startswith(PREFIXES))
                directories.add(name)
            else:
                require(name in MARKERS or name.startswith(PREFIXES))
                files[name] = item
        require(MARKERS <= set(files)
                and any(name.startswith('app/data/') for name in files)
                and any(name.startswith('app/local-engines/') for name in files))
        file_names = {name.casefold() for name in files}
        require(all(not any(parent.as_posix().casefold() in file_names
                            for parent in PurePosixPath(name).parents if str(parent) != '.')
                    for name in (*files, *directories)))
        require(files['all-core-fixture.json'].file_size <= 4096)
        marker = json.loads(archive.read(files['all-core-fixture.json']), object_pairs_hook=no_duplicates)
        require(marker == {'format': 1, 'core': core, 'synthetic': True})
        for name in sorted(directories):
            package.joinpath(*PurePosixPath(name).parts).mkdir(parents=True, exist_ok=True)
        total = 0
        for name, item in files.items():
            target = package.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            count = 0
            with archive.open(item) as source, target.open('xb') as output:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    count += len(block);total += len(block)
                    require(count <= item.file_size and total <= MAX_BYTES)
                    output.write(block)
            require(count == item.file_size)
    return {'success': True, 'synthetic': True, 'core': core, 'files': len(files),
            'bytes': total, 'archive_digest_verified': True, 'source_device_fixture': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--github-output', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--core')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        tag, entries = fixture_index(args.manifest)
        if args.plan:
            require(args.github_output is not None)
            matrix = [{'core': core, 'asset': entry['asset']}
                      for core, entry in sorted(entries.items(), key=lambda item: int(item[0]))]
            with args.github_output.open('a', encoding='utf-8') as output:
                output.write('fixtures=' + json.dumps(matrix, separators=(',', ':')) + '\n')
                output.write('fixture_release=' + tag + '\n')
            report = {'success': True, 'cores': len(matrix)}
        else:
            require(args.archive is not None and args.package is not None
                    and args.core in entries and args.report is not None)
            report = unpack(args.archive, args.package, args.core, entries[args.core])
    except Exception as error:
        report = {'success': False, 'error_type': type(error).__name__}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
