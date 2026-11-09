"""Deploy isolated native engines with a narrowly replaced public trust root."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import threading
import uuid

from local_state import LocalBrowserError
from core_specs import CORE_SPECS as _SUPPORTED

_VENDOR_DER_SHA256 = 'a06b13013ce57e00dcc222153c0bad1bde7b6cac984e59f4e7bf86495e3e86f8'
_KEY_BYTES = 294
_DEPLOY_LOCK = threading.RLock()


def _fail():
    raise LocalBrowserError('本地独立内核校验未通过，未覆盖原内核或现有部署。')


def _absolute(path):
    return Path(os.path.abspath(path))


def _plain_ancestors(path):
    for current in (path, *path.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            _fail()


def _sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _inventory(folder):
    _plain_ancestors(folder)
    if not folder.is_dir():
        _fail()
    files, directories, names = {}, [], set()
    pending = [folder]
    while pending:
        parent = pending.pop()
        _plain_ancestors(parent)
        with os.scandir(parent) as entries:
            for entry in entries:
                path = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                    _fail()
                relative = path.relative_to(folder).as_posix()
                if relative.casefold() in names:
                    _fail()
                names.add(relative.casefold())
                if parent == folder and entry.name.casefold() == 'manifest.json':
                    if not stat.S_ISREG(info.st_mode):
                        _fail()
                    continue
                if stat.S_ISDIR(info.st_mode):
                    directories.append(relative)
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    _plain_ancestors(path)
                    files[relative] = {'size': info.st_size, 'sha256': _sha256(path)}
                    if len(files) > 100_000:
                        _fail()
                else:
                    _fail()
    return dict(sorted(files.items())), sorted(directories)


def _tree_digest(files, directories):
    content = json.dumps({'files': files, 'directories': directories}, sort_keys=True,
                         separators=(',', ':'), ensure_ascii=True).encode()
    return hashlib.sha256(content).hexdigest()


def _public_der(data):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    if not isinstance(data, bytes) or len(data) != _KEY_BYTES:
        _fail()
    key = serialization.load_der_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048 or key.public_numbers().e != 65537:
        _fail()
    if key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != data:
        _fail()
    return data


def _key_block(data, seeds):
    a, b = seeds
    mask = (1 << 64) - 1
    result = bytearray()
    for octet in data:
        previous = b
        a = ((a << 23) ^ a) & mask
        b = ((a >> 17) ^ (previous >> 26) ^ previous ^ a) & mask
        result.append(((previous + b) & 0xff) ^ octet)
        a = previous
    return bytes(result)


def _read_block(path, offset):
    with path.open('rb') as source:
        source.seek(offset)
        block = source.read(_KEY_BYTES)
    if len(block) != _KEY_BYTES:
        _fail()
    return block


def _restored_sha256(path, offset, original_block):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        remaining = offset
        while remaining:
            block = source.read(min(1024 * 1024, remaining))
            if not block:
                _fail()
            digest.update(block)
            remaining -= len(block)
        if len(source.read(_KEY_BYTES)) != _KEY_BYTES:
            _fail()
        digest.update(original_block)
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _remove_owned_tree(path, root):
    _plain_ancestors(path)
    if not path.resolve().is_relative_to(root.resolve()) or path.resolve() == root.resolve():
        _fail()

    def writable_retry(operation, name, error):
        if not isinstance(error[1], PermissionError):
            raise error[1]
        os.chmod(name, stat.S_IWRITE)
        operation(name)

    shutil.rmtree(path, onerror=writable_retry)


class LocalEngineStore:
    def __init__(self, root=None):
        if root is None:
            from app_paths import APP_ROOT
            root = APP_ROOT / 'local-engines'
        self.root = _absolute(root)
        _plain_ancestors(self.root)

    def validate(self, executable, key_id, major=None):
        """Fully verify an immutable deployed engine and its expected public root."""
        try:
            return self._validate(executable, key_id, major)
        except LocalBrowserError:
            raise
        except Exception:
            _fail()

    def _validate(self, executable, key_id, major=None, expected_folder=None):
        from engine_store import executable_major
        if not isinstance(key_id, str) or not re.fullmatch('[0-9a-f]{64}', key_id):
            _fail()
        executable = _absolute(executable)
        _plain_ancestors(executable)
        folder = executable.parent
        if folder.parent.parent != self.root or folder.parent.name != key_id:
            _fail()
        manifest = folder / 'manifest.json'
        _plain_ancestors(manifest)
        if not manifest.is_file() or manifest.stat().st_size > 16 * 1024 * 1024:
            _fail()
        data = json.loads(manifest.read_text(encoding='utf-8'))
        actual_major = data.get('core_major')
        if actual_major not in _SUPPORTED or (major is not None and str(major) != actual_major):
            _fail()
        if data.get('format') != 1 or data.get('executable') != executable.name or executable.name.casefold() != 'bitbrowser.exe':
            _fail()
        trust = data.get('local_trust', {})
        spec = _SUPPORTED[actual_major]
        source_digest = trust.get('source_tree_digest', '')
        if not re.fullmatch('[0-9a-f]{64}', source_digest) or (expected_folder or folder.name) != actual_major + '-' + source_digest:
            _fail()
        if (trust.get('key_id') != key_id or trust.get('source_chrome_sha') != spec['sha256']
                or trust.get('patch_offset') != hex(spec['offset']) or trust.get('patch_length') != _KEY_BYTES):
            _fail()
        files, directories = _inventory(folder)
        if not files or files != data.get('files') or directories != data.get('directories') or executable.name not in files:
            _fail()
        chrome_names = [name for name in files if Path(name).name.casefold() == 'chrome.dll']
        if len(chrome_names) != 1:
            _fail()
        chrome_name = chrome_names[0]
        chrome = folder / chrome_name
        own_der = _public_der(_key_block(_read_block(chrome, spec['offset']), spec['seeds']))
        if hashlib.sha256(own_der).hexdigest() != key_id:
            _fail()
        vendor_der = _public_der(base64.b64decode(trust.get('vendor_public_der', ''), validate=True))
        if hashlib.sha256(vendor_der).hexdigest() != _VENDOR_DER_SHA256:
            _fail()
        if _restored_sha256(chrome, spec['offset'], _key_block(vendor_der, spec['seeds'])) != spec['sha256']:
            _fail()
        restored_files = {name: dict(item) for name, item in files.items()}
        restored_files[chrome_name]['sha256'] = spec['sha256']
        if _tree_digest(restored_files, directories) != source_digest or executable_major(executable) != actual_major:
            _fail()
        return executable

    def ensure(self, major, source_executable, public_der):
        """Copy a pinned vendor engine, patch only its public key, and publish atomically."""
        try:
            with _DEPLOY_LOCK:
                return self._ensure(str(major), source_executable, _public_der(public_der))
        except LocalBrowserError:
            raise
        except Exception:
            _fail()

    def _ensure(self, major, source_executable, public_der):
        from engine_store import executable_major
        if major not in _SUPPORTED:
            _fail()
        key_id = hashlib.sha256(public_der).hexdigest()
        executable = _absolute(source_executable)
        _plain_ancestors(executable)
        if executable.is_relative_to(self.root):
            return self.validate(executable, key_id, major)
        source = executable.parent
        if self.root.is_relative_to(source) or executable.name.casefold() != 'bitbrowser.exe' or not executable.is_file():
            _fail()
        if executable_major(executable) != major:
            _fail()
        before, directories = _inventory(source)
        chrome_names = [name for name in before if Path(name).name.casefold() == 'chrome.dll']
        if len(chrome_names) != 1:
            _fail()
        chrome_name = chrome_names[0]
        spec = _SUPPORTED[major]
        if before[chrome_name]['sha256'] != spec['sha256']:
            _fail()
        vendor_der = _public_der(_key_block(_read_block(source / chrome_name, spec['offset']), spec['seeds']))
        if hashlib.sha256(vendor_der).hexdigest() != _VENDOR_DER_SHA256:
            _fail()
        source_digest = _tree_digest(before, directories)
        key_folder = self.root / key_id
        destination = key_folder / (major + '-' + source_digest)
        _plain_ancestors(destination)
        if destination.exists():
            return self.validate(destination / executable.name, key_id, major)
        key_folder.mkdir(parents=True, exist_ok=True)
        _plain_ancestors(key_folder)
        total = sum(item['size'] for item in before.values())
        if shutil.disk_usage(key_folder).free < total * 1.15 + 50_000_000:
            raise LocalBrowserError('磁盘空间不足，未部署本地独立内核。')
        staging = key_folder / ('.install-' + uuid.uuid4().hex)
        published = False
        try:
            staging.mkdir()
            for name in sorted(directories, key=lambda value: (len(Path(value).parts), value)):
                (staging / name).mkdir()
            for name in before:
                _plain_ancestors(source / name)
                shutil.copy2(source / name, staging / name, follow_symlinks=False)
            if _inventory(staging) != (before, directories) or _inventory(source) != (before, directories):
                _fail()
            chrome = staging / chrome_name
            old_mode = stat.S_IMODE(chrome.stat().st_mode)
            try:
                chrome.chmod(old_mode | stat.S_IWUSR)
                with chrome.open('r+b') as output:
                    output.seek(spec['offset'])
                    if output.write(_key_block(public_der, spec['seeds'])) != _KEY_BYTES:
                        _fail()
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                chrome.chmod(old_mode)
            after, after_directories = _inventory(staging)
            expected = {name: dict(item) for name, item in before.items()}
            expected[chrome_name]['sha256'] = _sha256(chrome)
            if after != expected or after_directories != directories:
                _fail()
            if _restored_sha256(chrome, spec['offset'], _key_block(vendor_der, spec['seeds'])) != spec['sha256']:
                _fail()
            if _inventory(source) != (before, directories):
                _fail()
            data = {'format': 1, 'core_major': major, 'executable': executable.name,
                    'files': after, 'directories': directories,
                    'local_trust': {'source_chrome_sha': spec['sha256'], 'key_id': key_id,
                                    'patch_offset': hex(spec['offset']), 'patch_length': _KEY_BYTES,
                                    'source_tree_digest': source_digest,
                                    'vendor_public_der': base64.b64encode(vendor_der).decode('ascii')}}
            with (staging / 'manifest.json').open('x', encoding='utf-8') as output:
                json.dump(data, output, ensure_ascii=False, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            self._validate(staging / executable.name, key_id, major, expected_folder=destination.name)
            _plain_ancestors(destination)
            if destination.exists():
                return self.validate(destination / executable.name, key_id, major)
            os.rename(staging, destination)
            published = True
            return self.validate(destination / executable.name, key_id, major)
        except Exception:
            if published and destination.exists():
                _remove_owned_tree(destination, self.root)
            raise
        finally:
            if staging.exists():
                _plain_ancestors(staging)
                if staging.resolve().parent != key_folder.resolve() or not staging.resolve().is_relative_to(self.root.resolve()):
                    _fail()
                _remove_owned_tree(staging, self.root)
