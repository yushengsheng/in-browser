"""Decrypt an explicitly supplied acceptance bundle in a disposable runner.

The transport key is an environment secret. Authentication and complete ZIP
validation precede extraction. No data or error messages are logged.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HEADER = b'IBPRIVATE1'
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024


def require(value):
    if not value:
        raise ValueError('Private acceptance precondition failed')


def ordinary(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400)
    require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))


def windows_component(part):
    reserved = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'}
    reserved.update(prefix + suffix for prefix in ('COM', 'LPT') for suffix in '0123456789¹²³')
    return (part.rstrip(' .') == part and part.split('.', 1)[0].upper() not in reserved
            and not any(ord(c) < 32 or c in '<>"|?*' for c in part))


def unpack(source, target, expected):
    import zipfile
    encoded = os.environ.pop('IB_PRIVATE_ACCEPTANCE_KEY', '')
    key = base64.b64decode(encoded, validate=True)
    require(len(key) == 32 and len(expected) == 64)
    require(source.is_file() and len(HEADER) + 28 < source.stat().st_size <= MAX_ARCHIVE)
    require(target.is_dir())
    for parent in (target, *target.parents):
        ordinary(parent)
    digest = hashlib.sha256()
    with source.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    require(digest.hexdigest() == expected)
    handle, name = tempfile.mkstemp(prefix='authenticated-private-', suffix='.zip', dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(handle, 'wb') as output, source.open('rb') as stream:
            require(stream.read(len(HEADER)) == HEADER)
            nonce = stream.read(12)
            stream.seek(-16, 2)
            tag = stream.read(16)
            stream.seek(len(HEADER) + 12)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(HEADER)
            remaining = source.stat().st_size - len(HEADER) - 12 - 16
            while remaining:
                block = stream.read(min(1024 * 1024, remaining))
                require(block)
                output.write(decryptor.update(block))
                remaining -= len(block)
            output.write(decryptor.finalize())
            output.flush()
            os.fsync(output.fileno())
        with zipfile.ZipFile(temporary) as archive:
            members = archive.infolist()
            require(0 < len(members) <= 40000)
            require(sum(item.file_size for item in members) <= MAX_EXPANDED)
            names = set()
            for item in members:
                path = PurePosixPath(item.filename)
                mode = item.external_attr >> 16
                require(not path.is_absolute() and '..' not in path.parts and ':' not in item.filename
                        and '\\' not in item.filename and not stat.S_ISLNK(mode)
                        and 0 <= item.file_size <= 768 * 1024 * 1024)
                require(all(windows_component(part) for part in path.parts))
                require(item.filename == path.as_posix() + ('/' if item.is_dir() else ''))
                require(item.filename == 'private-acceptance.json' or item.filename.startswith(
                    ('app/data/', 'app/local-engines/')))
                folded = item.filename.rstrip('/').casefold()
                require(folded not in names)
                names.add(folded)
                output = target.joinpath(*path.parts)
                require(not output.exists() or (item.is_dir() and output.is_dir()))
                for parent in output.parents:
                    if parent == target.parent:
                        break
                    if parent.exists():
                        ordinary(parent)
            require('private-acceptance.json' in names)
            for item in members:
                output = target.joinpath(*PurePosixPath(item.filename).parts)
                if item.is_dir():
                    output.mkdir(parents=True, exist_ok=True)
                    continue
                output.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as stream, output.open('xb') as destination:
                    shutil.copyfileobj(stream, destination, 1024 * 1024)
        return {'success': True, 'authenticated': True, 'files': len(members)}
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--sha256-file', required=True, type=Path)
    args = parser.parse_args()
    try:
        expected = args.sha256_file.read_text('ascii').strip()
        print(json.dumps(unpack(args.source.resolve(), args.target.resolve(), expected)))
        return 0
    except Exception as error:
        print(json.dumps({'success': False, 'error_type': type(error).__name__}))
        return 1
    finally:
        os.environ.pop('IB_PRIVATE_ACCEPTANCE_KEY', None)


if __name__ == '__main__':
    raise SystemExit(main())
