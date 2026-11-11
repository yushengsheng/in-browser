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
from engine_validation import digest_file

_VENDOR_DER_SHA256 = 'a06b13013ce57e00dcc222153c0bad1bde7b6cac984e59f4e7bf86495e3e86f8'
_KEY_BYTES = 294
_SHORT_ID_LENGTH = 16
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
    return digest_file(path)


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


def _runtime_directories(major,files,directories,expected):
    # Chromium 104 chrome_paths.cc creates DIR_APP_DICTIONARIES beside the EXE
    # on Windows, even when no dictionary is used. Only this empty directory
    # is a runtime artifact; any new file, child directory or link still fails.
    if (major=='104' and isinstance(expected,list) and 'Dictionaries' not in expected
            and 'Dictionaries' in directories and not any(name.startswith('Dictionaries/') for name in files)
            and not any(name.startswith('Dictionaries/') for name in directories)):
        return [name for name in directories if name!='Dictionaries']
    return directories


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
    return digest_file(path, offset=offset, replacement=original_block)


def _resource_key(folder, spec, public_der=None):
    """Read/write the independently encoded trust root of the delayed verifier.

    The DataPack member offsets belong to the pinned exact build. Its header,
    resource index and all bytes outside the 294-byte key remain untouched.
    """
    resource = spec['resource_root']
    path = folder / resource['file']
    _plain_ancestors(path)
    with path.open('rb') as source:
        source.seek(resource['offset'])
        block = source.read(resource['length'])
    if (len(block) != resource['length'] or len(block) < 25
            or ((block[24] & 63) ^ 0x15) + 0x39 != resource['key_offset']
            or len(block) - resource['key_offset'] != _KEY_BYTES):
        _fail()
    state = int.from_bytes(block[16:24], 'big')
    mask = (1 << 64) - 1
    stream = bytearray()
    for _ in range(_KEY_BYTES):
        state ^= state >> 33
        state = state * 0xff51afd7ed558ccd & mask
        state ^= state >> 33
        state = state * 0xc4ceb9fe1a85ec53 & mask
        state ^= state >> 33
        stream.append(state & 255)
    offset = resource['offset'] + resource['key_offset']
    decoded = bytes(a ^ b for a, b in zip(block[resource['key_offset']:], stream))
    if public_der is None:
        return _public_der(decoded)
    encoded = bytes(a ^ b for a, b in zip(_public_der(public_der), stream))
    old_mode = stat.S_IMODE(path.stat().st_mode)
    try:
        path.chmod(old_mode | stat.S_IWUSR)
        with path.open('r+b') as output:
            output.seek(offset)
            if output.write(encoded) != _KEY_BYTES:
                _fail()
            output.flush()
            os.fsync(output.fileno())
    finally:
        path.chmod(old_mode)
    return path


def continuity_manifest(data, executable):
    """Keep the existing binding through a proven trust-root-only repair."""
    if data.get('local_trust', {}).get('resource_root_revision') != 1:
        return data
    # Full validation proves the resource reverses to the pinned vendor bytes;
    # arbitrary manifest declarations cannot excuse a resource/code change.
    import copy
    executable = _absolute(executable)
    LocalEngineStore(executable.parent.parent.parent).validate(
        executable, data['local_trust']['key_id'], data['core_major'])
    result = copy.deepcopy(data)
    resource = _SUPPORTED[str(data['core_major'])]['resource_root']
    result['files'][resource['file']]['sha256'] = resource['sha256']
    result['local_trust'].pop('resource_root_revision')
    return result


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
        if folder.parent.parent != self.root:
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
        revision = trust.get('resource_root_revision', 0)
        if revision not in (0, 1) or isinstance(revision, bool):
            _fail()
        suffix = '-r2' if revision else ''
        if not re.fullmatch('[0-9a-f]{64}', source_digest):
            _fail()
        layout = (folder.parent.name, expected_folder or folder.name)
        if layout not in ((key_id, actual_major + '-' + source_digest + suffix),
                          (key_id[:_SHORT_ID_LENGTH], actual_major + '-' + source_digest[:_SHORT_ID_LENGTH] + suffix)):
            _fail()
        if (trust.get('key_id') != key_id or trust.get('source_chrome_sha') != spec['sha256']
                or trust.get('patch_offset') != hex(spec['offset']) or trust.get('patch_length') != _KEY_BYTES):
            _fail()
        files, directories = _inventory(folder)
        directories=_runtime_directories(actual_major,files,directories,data.get('directories'))
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
        if revision:
            resource = spec['resource_root']
            if hashlib.sha256(_resource_key(folder, spec)).hexdigest() != key_id:
                _fail()
            resource_path = folder / resource['file']
            # Recover the original ciphertext with this resource's own stream.
            current_key = _resource_key(folder, spec)
            with resource_path.open('rb') as source:
                source.seek(resource['offset'] + resource['key_offset'])
                current = source.read(_KEY_BYTES)
            original = bytes(a ^ b ^ c for a, b, c in zip(current, current_key, vendor_der))
            if _restored_sha256(resource_path, resource['offset'] + resource['key_offset'], original) != resource['sha256']:
                _fail()
            restored_files[resource['file']]['sha256'] = resource['sha256']
        if _tree_digest(restored_files, directories) != source_digest or executable_major(executable) != actual_major:
            _fail()
        return executable

    def _compact_destination(self, key_id, major, source_digest, revision=0):
        suffix = '-r2' if revision else ''
        return self.root / key_id[:_SHORT_ID_LENGTH] / (major + '-' + source_digest[:_SHORT_ID_LENGTH] + suffix)

    def _check_compact_key_folder(self, key_folder, key_id):
        # Prefixes only choose a path. They never replace the full identities.
        _plain_ancestors(key_folder)
        if not key_folder.exists():
            return
        if not key_folder.is_dir():
            _fail()
        for folder in key_folder.iterdir():
            _plain_ancestors(folder)
            if not folder.is_dir():
                _fail()
            # Interrupted private copies are not published identities. Preserve
            # them for recovery without letting incomplete manifests block retry.
            if re.fullmatch(r'\.install-[0-9a-f]{12}', folder.name):
                continue
            manifest = folder / 'manifest.json'
            _plain_ancestors(manifest)
            if not manifest.is_file() or manifest.stat().st_size > 16 * 1024 * 1024:
                _fail()
            data = json.loads(manifest.read_text(encoding='utf-8'))
            trust = data.get('local_trust', {})
            source_digest = trust.get('source_tree_digest', '')
            revision = trust.get('resource_root_revision', 0)
            major = data.get('core_major')
            if (trust.get('key_id') != key_id or major not in _SUPPORTED
                    or not re.fullmatch('[0-9a-f]{64}', source_digest)
                    or revision not in (0, 1) or isinstance(revision, bool)
                    or folder != self._compact_destination(key_id, major, source_digest, revision)):
                _fail()

    def _existing_destination(self, destination, name, key_id, major, source_digest):
        executable = self.validate(destination / name, key_id, major)
        data = json.loads((destination / 'manifest.json').read_text(encoding='utf-8'))
        if data['local_trust']['source_tree_digest'] != source_digest:
            _fail()
        return executable

    def ensure_current(self, executable, key_id, major=None):
        """Publish a compact, current copy while retaining every older build."""
        try:
            with _DEPLOY_LOCK:
                executable = self.validate(executable, key_id, major)
                source = executable.parent
                data = json.loads((source / 'manifest.json').read_text(encoding='utf-8'))
                source_digest = data['local_trust']['source_tree_digest']
                revision = data['local_trust'].get('resource_root_revision', 0)
                spec = _SUPPORTED[data['core_major']]
                if 'resource_root' not in spec:
                    _fail()
                resource = spec['resource_root']
                if not revision and (data['files'].get(resource['file'], {}).get('sha256') != resource['sha256']
                        or hashlib.sha256(_resource_key(source, spec)).hexdigest() != _VENDOR_DER_SHA256):
                    _fail()
                destination = self._compact_destination(key_id, data['core_major'], source_digest, 1)
                if source == destination:
                    return executable
                self._check_compact_key_folder(destination.parent, key_id)
                _plain_ancestors(destination)
                if destination.exists():
                    return self._existing_destination(destination, executable.name, key_id, data['core_major'], source_digest)
                destination.parent.mkdir(parents=True, exist_ok=True)
                _plain_ancestors(destination.parent)
                files, directories = data['files'], data['directories']
                total = sum(item['size'] for item in files.values())
                if shutil.disk_usage(destination.parent).free < total * 1.15 + 50_000_000:
                    raise LocalBrowserError('磁盘空间不足，未升级独立内核；原内核和资料已保留。')
                staging = destination.parent / ('.install-' + uuid.uuid4().hex[:12])
                published = False
                try:
                    staging.mkdir()
                    for name in sorted(directories, key=lambda value: (len(Path(value).parts), value)):
                        (staging / name).mkdir()
                    for name in files:
                        _plain_ancestors(source / name)
                        shutil.copy2(source / name, staging / name, follow_symlinks=False)
                    if _inventory(staging) != (files, directories):
                        _fail()
                    if not revision:
                        public = _public_der(_key_block(_read_block(source / next(
                            name for name in files if Path(name).name.casefold() == 'chrome.dll'), spec['offset']), spec['seeds']))
                        _resource_key(staging, spec, public)
                    after, after_dirs = _inventory(staging)
                    expected = {name: dict(item) for name, item in files.items()}
                    expected[resource['file']]['sha256'] = _sha256(staging / resource['file'])
                    source_files, source_dirs = _inventory(source)
                    source_dirs = _runtime_directories(data['core_major'],source_files,source_dirs,directories)
                    if after != expected or after_dirs != directories or (source_files,source_dirs) != (files, directories):
                        _fail()
                    data['files'] = after
                    data['local_trust']['resource_root_revision'] = 1
                    with (staging / 'manifest.json').open('x', encoding='utf-8') as output:
                        json.dump(data, output, ensure_ascii=False, sort_keys=True)
                        output.flush()
                        os.fsync(output.fileno())
                    self._validate(staging / executable.name, key_id, data['core_major'], expected_folder=destination.name)
                    self._check_compact_key_folder(destination.parent, key_id)
                    _plain_ancestors(destination)
                    if destination.exists():
                        return self._existing_destination(destination, executable.name, key_id, data['core_major'], source_digest)
                    os.rename(staging, destination)
                    published = True
                    return self.validate(destination / executable.name, key_id, data['core_major'])
                except Exception:
                    if published and destination.exists():
                        _remove_owned_tree(destination, self.root)
                    raise
                finally:
                    if staging.exists():
                        _remove_owned_tree(staging, self.root)
        except LocalBrowserError:
            raise
        except Exception:
            _fail()

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
        destination = self._compact_destination(key_id, major, source_digest)
        key_folder = destination.parent
        self._check_compact_key_folder(key_folder, key_id)
        _plain_ancestors(destination)
        if destination.exists():
            return self._existing_destination(destination, executable.name, key_id, major, source_digest)
        key_folder.mkdir(parents=True, exist_ok=True)
        _plain_ancestors(key_folder)
        total = sum(item['size'] for item in before.values())
        if shutil.disk_usage(key_folder).free < total * 1.15 + 50_000_000:
            raise LocalBrowserError('磁盘空间不足，未部署本地独立内核。')
        staging = key_folder / ('.install-' + uuid.uuid4().hex[:12])
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
            self._check_compact_key_folder(key_folder, key_id)
            _plain_ancestors(destination)
            if destination.exists():
                return self._existing_destination(destination, executable.name, key_id, major, source_digest)
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
