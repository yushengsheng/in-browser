"""Copy a closed installation into a new verified directory; never modify its data."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
# The embedded Python uses an isolated ._pth and omits the script directory.
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'app')]
MANAGED = ('app/data', 'app/local-engines', 'app/engines')
MAX_FILES = 1000000
MAX_BYTES = 1024 ** 4
MAX_MANIFEST = 64 * 1024 * 1024
MAX_TARGET_UNITS = 80
TIMEOUT = 3600
BLOCK = 1024 * 1024


class TransferError(Exception):
    pass


class TargetPathTooDeep(TransferError):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise TransferError()


class TransferDeadline(float):
    def __new__(cls, seconds, progress):
        value = super().__new__(cls, time.monotonic() + seconds)
        value.progress, value.phase, value.files, value.last = progress, 'checking_public', 0, 0
        return value

    def update(self, phase=None, *, force=False):
        if phase is not None:
            self.phase, self.files = phase, 0
        now = time.monotonic()
        if self.progress is not None and (force or now - self.last >= 5):
            self.progress({'stage': self.phase, 'files': self.files})
            self.last = now


def require(condition):
    if not condition:
        raise TransferError()


def io_path(path):
    value = os.path.abspath(str(path))
    if os.name == 'nt' and not value.startswith('\\\\?\\'):
        value = '\\\\?\\UNC\\' + value[2:] if value.startswith('\\\\') else '\\\\?\\' + value
    return Path(value)


def canonical(path):
    value = str(Path(path).resolve())
    if value.startswith('\\\\?\\UNC\\'):
        value = '\\\\' + value[8:]
    elif value.startswith('\\\\?\\'):
        value = value[4:]
    return Path(value)


def plain(path):
    info = io_path(path).lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400)
    require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
    return info


def ancestors(path):
    for current in (path, *path.parents):
        if io_path(current).exists() or io_path(current).is_symlink():
            require(stat.S_ISDIR(plain(current).st_mode))


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def deadline_check(deadline):
    require(time.monotonic() < deadline)
    if isinstance(deadline, TransferDeadline):
        deadline.update()


def digest(path, deadline):
    deadline_check(deadline)
    before = plain(path)
    require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BYTES)
    value, total = hashlib.sha256(), 0
    with io_path(path).open('rb') as handle:
        while block := handle.read(BLOCK):
            deadline_check(deadline)
            total += len(block)
            require(total <= before.st_size)
            value.update(block)
    require(total == before.st_size and stamp(before) == stamp(plain(path)))
    return {'bytes': total, 'sha256': value.hexdigest(), 'stamp': stamp(before)}


def safe_relative(name):
    require(isinstance(name, str) and bool(name) and '\\' not in name and ':' not in name)
    path = PurePosixPath(name)
    require(not path.is_absolute() and name == path.as_posix() and '..' not in path.parts)
    reserved = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'}
    reserved.update(a + b for a in ('COM', 'LPT') for b in '0123456789¹²³')
    require(all(part.rstrip(' .') == part and part.split('.')[0].upper() not in reserved
                and not any(ord(c) < 32 or c in '<>"|?*' for c in part) for part in path.parts))
    return Path(*path.parts)


def inventory(root, prefixes, deadline):
    result, pending, folded, total = {}, [root / p for p in prefixes], set(), 0
    while pending:
        deadline_check(deadline)
        path = pending.pop()
        name = path.relative_to(root).as_posix()
        safe_relative(name)
        require(name.casefold() not in folded and len(result) < MAX_FILES)
        folded.add(name.casefold())
        info = plain(path)
        if isinstance(deadline, TransferDeadline):
            deadline.files += 1
        if stat.S_ISDIR(info.st_mode):
            result[name] = {'directory': True}
            with os.scandir(io_path(path)) as entries:
                pending.extend(path / entry.name for entry in entries)
        else:
            result[name] = digest(path, deadline)
            total += result[name]['bytes']
            require(total <= MAX_BYTES)
    return result


def release_inventory(base, deadline):
    manifest = base / 'release-manifest.json'
    require(plain(manifest).st_size <= MAX_MANIFEST)
    data = json.loads(io_path(manifest).read_text('utf-8'))
    require(data.get('algorithm') == 'SHA256' and isinstance(data.get('files'), dict))
    require(0 < len(data['files']) <= MAX_FILES)
    result, folded = {}, set()
    for name, expected in data['files'].items():
        relative = safe_relative(name)
        require(name.casefold() not in folded and not any(name == p or name.startswith(p + '/')
                for p in MANAGED[:2]))
        folded.add(name.casefold())
        ancestors((base / relative).parent)
        item = digest(base / relative, deadline)
        require(isinstance(expected, dict) and item['bytes'] == expected.get('bytes')
                and item['sha256'] == expected.get('sha256'))
        result[name] = item
        if isinstance(deadline, TransferDeadline):
            deadline.files += 1
    require(all(name in result for name in ('runtime/python/python.exe', 'app/local_browser.pyw',
                                            '启动本地浏览器.cmd')))
    require('release-manifest.json' not in result)
    result['release-manifest.json'] = digest(manifest, deadline)
    # Runtime empty directories are not listed by the release file manifest.
    for prefix in ('runtime', 'app/engines'):
        if not io_path(base / prefix).exists():
            continue
        actual = inventory(base, [prefix], deadline)
        if prefix == 'runtime':
            require(all(name in result for name, item in actual.items() if not item.get('directory')))
        known_roots = {str(PurePosixPath(name).parts[2]) for name in result
                       if name.startswith('app/engines/') and len(PurePosixPath(name).parts) > 3}
        result.update({name: item for name, item in actual.items() if item.get('directory')
                       and (prefix == 'runtime' or name == prefix
                            or PurePosixPath(name).parts[2] in known_roots)})
    return result


@contextmanager
def manager_guards(roots):
    if os.name != 'nt':
        yield
        return
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handles = []
    try:
        for root in sorted(set(roots)):
            key = hashlib.sha256(str(root / 'app').encode()).hexdigest()[:24]
            handle = kernel.CreateMutexW(None, False, 'LocalBrowser-' + key)
            require(bool(handle))
            handles.append(handle)
            require(ctypes.get_last_error() != 183)
        yield
    finally:
        for handle in handles:
            kernel.CloseHandle(handle)


def closed(roots):
    import psutil
    known = {'bitbrowser.exe', 'msedgewebview2.exe', 'pythonw.exe'}
    try:
        for process in psutil.process_iter(['pid', 'exe', 'cmdline', 'name']):
            if process.pid == os.getpid():
                continue
            info = process.info
            executable, args = info.get('exe'), info.get('cmdline')
            if not executable or not args:
                require(str(info.get('name') or '').casefold() not in known)
                continue
            paths = [canonical(executable)]
            for i, argument in enumerate(args):
                if argument.startswith('--user-data-dir='):
                    paths.append(canonical(argument.split('=', 1)[1].strip('"')))
                elif argument == '--user-data-dir' and i + 1 < len(args):
                    paths.append(canonical(args[i + 1].strip('"')))
                elif argument.lower().endswith(('.py', '.pyw')) and os.path.isabs(argument):
                    paths.append(canonical(argument))
            require(not any(path == root or path.is_relative_to(root) for path in paths for root in roots))
    except (psutil.Error, OSError, ValueError):
        raise TransferError() from None


def validate_data(source, deadline):
    sys.path.insert(0, str(ROOT / 'app'))
    from inspect_installation import read_catalog
    from local_signer import LocalSigner
    from local_signer import _envelope
    from local_engine import LocalEngineStore
    from local_state import read_encrypted
    data = io_path(source / 'app/data')
    require((data / 'portable-mode.bin').is_file())
    catalog = read_catalog(data, deadline)
    require(catalog['quick_check'])
    for name in ('independent-mode.bin', 'portable-mode.bin', 'continuity-mode.bin'):
        marker = read_encrypted(data / name, root=data)
        require(marker.get('format') == 1 and marker.get('state', 'ready') == 'ready')
    signer = LocalSigner(data, load_private=False)
    signer._load_private()  # This path only reads; the constructor's creation branch stays disabled.
    engines = LocalEngineStore(io_path(source / 'app/local-engines'))
    checked = set()
    for record in catalog['records']:
        runtime = record.get('_runtime', {})
        require(runtime.get('signature_key_id') == signer.key_id)
        def owned_path(value):
            require(isinstance(value, str) and bool(value))
            path = canonical(value)
            # read_catalog decodes @app against this tool's application, not the selected source.
            if path.is_relative_to(ROOT / 'app'):
                path = source / 'app' / path.relative_to(ROOT / 'app')
            require(path.is_relative_to(source / 'app'))
            return path
        profile = owned_path(runtime.get('profile_path'))
        require(profile.is_relative_to(source / 'app/data') and stat.S_ISDIR(plain(profile).st_mode))
        fingerprint = owned_path(runtime.get('fingerprint_path'))
        require(fingerprint.is_relative_to(source / 'app/data')
                and digest(fingerprint, deadline)['sha256'] == runtime.get('fingerprint_sha256'))
        # Authenticate ownership at the recorded signing time; later renewal remains the app's job.
        require(signer.verify(io_path(fingerprint), now_ms=_envelope(io_path(fingerprint))[2]))
        executable = owned_path(runtime.get('core_path'))
        require(executable.is_relative_to(source / 'app/local-engines'))
        pin = (executable, str(runtime.get('core_major')))
        if pin not in checked:
            deadline_check(deadline)
            engines.validate(io_path(executable), signer.key_id, pin[1])
            checked.add(pin)
    return len(catalog['records'])


def same_content(left, right):
    return ({k: v for k, v in left.items() if k != 'stamp'} ==
            {k: v for k, v in right.items() if k != 'stamp'})


def check_target_paths(destination, entries):
    for name, item in entries.items():
        if name in ('runtime', 'app/engines', 'app/local-engines') or name.startswith(
                ('runtime/', 'app/engines/', 'app/local-engines/')):
            limit = 248 if item.get('directory') else 260
            if len(str(destination / safe_relative(name)).encode('utf-16-le')) // 2 >= limit:
                raise TargetPathTooDeep()


def copy_file(source, destination, expected, deadline):
    destination = io_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    before, value, total = plain(source), hashlib.sha256(), 0
    require(stamp(before) == expected['stamp'])
    with io_path(source).open('rb') as reader, destination.open('xb') as writer:
        while block := reader.read(BLOCK):
            deadline_check(deadline)
            total += len(block)
            require(total <= expected['bytes'])
            writer.write(block)
            value.update(block)
        writer.flush()
        os.fsync(writer.fileno())
    require(total == expected['bytes'] and value.hexdigest() == expected['sha256']
            and stamp(plain(source)) == expected['stamp'])
    os.utime(destination, ns=(before.st_atime_ns, before.st_mtime_ns))


def transfer(base, source, destination, progress=None):
    for value in (base, source):
        ancestors(Path(os.path.abspath(str(value))))
    ancestors(Path(os.path.abspath(str(destination))).parent)
    base, source, destination = (canonical(value) for value in (base, source, destination))
    require(destination not in (base, source))
    require(not any(destination.is_relative_to(root) or root.is_relative_to(destination) for root in (base, source)))
    ancestors(base); ancestors(source); ancestors(destination.parent)
    require(io_path(destination.parent).is_dir() and not io_path(destination).exists()
            and not io_path(destination).is_symlink())
    # A shallow destination is needed even when extended-length copying succeeds.
    if len(str(destination).encode('utf-16-le')) // 2 > MAX_TARGET_UNITS:
        raise TargetPathTooDeep()
    deadline = TransferDeadline(TIMEOUT, progress)
    roots = (base, source)
    with manager_guards(roots):
        closed(roots)
        deadline.update('checking_public', force=True)
        public = release_inventory(base, deadline)
        check_target_paths(destination, public)
        deadline.update('checking_source', force=True)
        private = inventory(source, MANAGED, deadline)
        check_target_paths(destination, private)
        windows = validate_data(source, deadline)
        # Equal stock folder names must describe the same whole tree, not a repaired mixture.
        common_cores = {PurePosixPath(name).parts[2] for name in public
                        if name.startswith('app/engines/') and len(PurePosixPath(name).parts) >= 3}
        for core in common_cores:
            prefix = 'app/engines/' + core
            if prefix not in private:
                continue
            left = {n: i for n, i in public.items() if n == prefix or n.startswith(prefix + '/')}
            right = {n: i for n, i in private.items() if n == prefix or n.startswith(prefix + '/')}
            require(set(left) == set(right) and all(same_content(i, right[n]) for n, i in left.items()))
        merged = dict(public)
        owners = {name: base for name in public}
        for name, item in private.items():
            require(name not in merged or same_content(merged[name], item))
            merged[name], owners[name] = item, source
        require(len({name.casefold() for name in merged}) == len(merged))
        total = sum(item.get('bytes', 0) for item in merged.values())
        require(total <= MAX_BYTES and shutil.disk_usage(io_path(destination.parent)).free >= total + 64 * BLOCK)
        temporary = destination.parent / ('.transfer-' + uuid.uuid4().hex[:12])
        io_path(temporary).mkdir()
        deadline.update('copying', force=True)
        # Intentionally retain an incomplete tree on any failure; never clean user data.
        for name, item in sorted(merged.items()):
            relative = safe_relative(name)
            if item.get('directory'):
                io_path(temporary / relative).mkdir(parents=True, exist_ok=True)
            else:
                copy_file(owners[name] / relative, temporary / relative, item, deadline)
            deadline.files += 1
        deadline.update('verifying', force=True)
        copied = inventory(temporary, [path.name for path in io_path(temporary).iterdir()], deadline)
        expected_names = set(merged)
        for name in tuple(expected_names):
            expected_names.update(p.as_posix() for p in PurePosixPath(name).parents if str(p) != '.')
        require(set(copied) == expected_names)
        require(all(same_content(item, copied[name]) for name, item in merged.items()))
        deadline.update('source_recheck', force=True)
        require(public == release_inventory(base, deadline) and private == inventory(source, MANAGED, deadline))
        require(windows == validate_data(source, deadline))
        closed(roots)
        ancestors(destination.parent)
        require(not io_path(destination).exists())
        # Windows rename never replaces an existing destination; all production use is Windows.
        os.rename(io_path(temporary), io_path(destination))
        deadline.update('finished', force=True)
    return {'success': True, 'files': sum(not item.get('directory', False) for item in merged.values()),
            'windows': windows, 'source_unchanged': True, 'verified': True}


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--execute', action='store_true')
    interactive = False
    try:
        args = parser.parse_args(argv)
        interactive = args.source is None and args.destination is None and not args.execute
        if interactive:
            print('先正常关闭旧程序和当前程序的全部浏览器窗口、管理器。完整账号资料只保存在本机，不会上传。')
            args.source = Path(input('原来能正常打开的旧程序目录：').strip().strip('"'))
            args.destination = Path(input('新的短目标目录（必须不存在，例如 D:\\LB）：').strip().strip('"'))
        else:
            require(args.execute and args.source is not None and args.destination is not None)
        labels = {'checking_public': '校验新版程序', 'checking_source': '校验旧资料', 'copying': '复制文件',
                  'verifying': '复核目标文件', 'source_recheck': '复核源资料', 'finished': '完成'}
        def progress(item):
            print(labels[item['stage']] + '：' + str(item['files']) + ' 项', flush=True)
        result = transfer(ROOT, args.source, args.destination, progress=progress if interactive else None)
        if interactive:
            print('迁移完成，全部文件已校验。请从你输入的新目录启动；旧目录未修改。')
        else:
            print(json.dumps(result))
        return 0
    except TargetPathTooDeep:
        if interactive:
            print('目标目录仍过深，请使用盘符根目录下的短文件夹，例如D:\\LB。源资料未修改，目标未发布。')
        else:
            print(json.dumps({'success': False, 'source_modified_by_tool': False,
                              'error_code': 'target_path_too_deep'}))
        return 1
    except (Exception, KeyboardInterrupt):
        if interactive:
            print('迁移未完成。请确认程序已正常关闭、旧目录完整、新目标不存在且路径较短、磁盘空间充足。源资料未修改；目标旁未完成副本已保留。')
        else:
            print(json.dumps({'success': False, 'source_modified_by_tool': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
