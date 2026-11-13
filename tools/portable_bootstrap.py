"""Prepare a verified portable payload, then launch the original data-root app.

Only the generated root launcher calls this module. Payloads are never used as
application data roots, and incomplete packages never enter application code.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.pycache_prefix = str(ROOT / ('.program-no-cache-' + os.urandom(16).hex()))
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'app')]


def load_tools():
    import inplace_update
    import overlay_layout
    return inplace_update, overlay_layout


@contextmanager
def preparation_guard(target, updater):
    """Serialize package preparation without occupying the manager's mutex."""
    if os.name != 'nt':
        yield
        return
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    key = hashlib.sha256(os.path.normcase(str(target)).encode()).hexdigest()[:24]
    handle = kernel.CreateMutexW(None, False, 'LocalBrowserPackage-' + key)
    existed = ctypes.get_last_error() == 183
    updater.require(bool(handle), 'cannot_lock_installation')
    try:
        updater.require(not existed, 'package_preparation_running')
        yield
    finally:
        kernel.CloseHandle(handle)


def _install(base, target, files, manifest, package_id, updater, layout, hook):
    """Resume only our first-install files; never replace an existing profile."""
    work = target / updater.PENDING
    expected_owner = {'format': 1, 'purpose': 'program-install',
                      'overlay_package': package_id, 'manifest': manifest['sha256']}
    with updater.manager_guard(target):
        updater.check_closed(base, target)
        if not updater._exists(work):
            updater.require({path.name for path in target.iterdir()} <= {
                layout.PACKAGE_DIRECTORY, layout.LAUNCHER}, 'not_an_empty_installation')
            work.mkdir()
            updater.write_new(work / 'owner.json', json.dumps(expected_owner, sort_keys=True).encode())
            updater.event(hook, 'after_install_marker')
        else:
            updater._ordinary(work, directory=True)
            updater.require(updater._json_file(work / 'owner.json', 4096) == expected_owner,
                            'unknown_installation_state')
            updater.require({path.name for path in work.iterdir()} <= {'owner.json', 'stage'},
                            'unknown_installation_state')

        # First installation has never started business code. A newly introduced
        # data tree during interruption is not ours to initialize or repair.
        updater.require(not updater._exists(target / 'app/data')
                        and not updater._exists(target / 'app/local-engines'),
                        'not_an_empty_installation')
        deadline = time.monotonic() + updater.MAX_SECONDS
        expected_files = {**files, 'release-manifest.json': manifest}
        for index, path in enumerate(work.rglob('*')):
            updater.tick(deadline)
            updater.require(index < 80000, 'resource_limit')
            info = updater._ordinary(path)
            if path.is_file() and path != work / 'owner.json':
                updater.require(path.is_relative_to(work / 'stage'), 'unknown_installation_state')
                name = path.relative_to(work / 'stage').as_posix()
                updater.require(name in expected_files and info.st_size <= expected_files[name]['bytes'],
                                'unknown_installation_state')
        updater.update_guard._check_active_files(target, files)
        for name, item in expected_files.items():
            path = updater.checked_path(target, name)
            if updater._exists(path):
                updater.require(updater.file_item(path) == item, 'unmanaged_or_changed_program')
        needed = sum(item['bytes'] for name, item in files.items()
                     if not updater._exists(updater.checked_path(target, name)))
        updater.require(shutil.disk_usage(target).free >= needed + 64 * 1024 * 1024,
                        'not_enough_space')
        pending_files = [(name, item) for name, item in files.items()
                         if name != layout.LAUNCHER]
        pending_files.append(('release-manifest.json', manifest))
        for name, item in pending_files:
            updater.tick(deadline)
            destination = updater.checked_path(target, name)
            if updater._exists(destination):
                updater.require(updater.file_item(destination) == item, 'unmanaged_or_changed_program')
                continue
            staged = updater.checked_path(work / 'stage', name)
            if updater._exists(staged) and updater.file_item(staged) != item:
                # This exact file is owned by the authenticated install marker;
                # a killed copy may leave a partial stage, never a target file.
                staged.unlink()
            if not updater._exists(staged):
                updater.copy_checked(base / name, staged, item)
            updater.event(hook, 'before_install_publish', name)
            updater.require(not updater._exists(destination), 'unmanaged_or_changed_program')
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.rename(staged, destination)
            updater.event(hook, 'after_install_publish', name)
        # Runtime and bundled engines include empty directories that are part
        # of their expected layout, even though file manifests cannot list them.
        directory_count = 0
        for directory in ('runtime', 'app/engines'):
            for current, directories, _ in os.walk(base / directory, followlinks=False):
                for name in directories:
                    updater.tick(deadline)
                    directory_count += 1
                    updater.require(directory_count <= 40000, 'resource_limit')
                    path = Path(current) / name
                    updater._ordinary(path, directory=True)
                    destination = updater.checked_path(target, path.relative_to(base).as_posix())
                    if updater._exists(destination):
                        updater._ordinary(destination, directory=True)
                    else:
                        destination.mkdir(parents=True)
        updater.compatible_source(base)
        updater.require(updater.file_item(base / 'release-manifest.json') == manifest,
                        'source_changed')
        updater.verify_release(target)
        updater.check_closed(base, target)
        updater.event(hook, 'before_install_commit')
        updater.finish_directory(target, work, uuid.uuid4().hex)
        return {'success': True, 'mode': 'installed', 'recovered': False}


def prepare(base, target, *, hook=None):
    updater, layout = load_tools()
    base, target = updater.paths(base, target)
    with preparation_guard(target, updater):
        files, _ = updater.compatible_source(base)
        package_id = updater.overlay_package_id(base, files)
        manifest = updater.file_item(base / 'release-manifest.json')
        updater.require({layout.BOOTSTRAP, 'tools/overlay_layout.py'} <= files.keys(),
                        'not_a_release')
        expected_launcher = layout.launcher_bytes(package_id)
        updater.require(files[layout.LAUNCHER] == {
            'bytes': len(expected_launcher),
            'sha256': hashlib.sha256(expected_launcher).hexdigest()}, 'invalid_overlay_package')
        updater._verified_file(target, layout.LAUNCHER, files[layout.LAUNCHER])
        pending = target / updater.PENDING
        recovered = False
        if updater._exists(pending):
            updater._ordinary(pending, directory=True)
            owner = updater._json_file(pending / 'owner.json', 4096)
            if isinstance(owner, dict) and owner.get('purpose') == 'program-install':
                return _install(base, target, files, manifest, package_id, updater, layout, hook)
            updater.recover(base, target, hook=hook)
            recovered = True
        installed_manifest = target / 'release-manifest.json'
        if not updater._exists(installed_manifest):
            return _install(base, target, files, manifest, package_id, updater, layout, hook)
        if updater.file_item(installed_manifest) == manifest:
            updater.verify_release(target)
            return {'success': True, 'mode': 'current', 'recovered': recovered}
        updater.update(base, target, hook=hook)
        return {'success': True, 'mode': 'updated', 'recovered': recovered}


def launch(target):
    target = Path(target).resolve()
    subprocess.Popen([str(target / 'runtime/python/pythonw.exe'), '-B',
                      str(target / 'app/local_browser.pyw')], cwd=target / 'app',
                     close_fds=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--prepare-only', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        result = prepare(ROOT, args.target)
        if args.prepare_only:
            print(json.dumps(result))
        else:
            launch(args.target)
        return 0
    except Exception as error:
        code = getattr(error, 'code', 'package_incomplete_or_inconsistent')
        if code == 'package_preparation_running' and not args.prepare_only:
            # A competing launcher must exit promptly; a modal dialog here
            # would itself keep the installation occupied for the first one.
            return 0
        if args.prepare_only:
            print(json.dumps({'success': False, 'error': code if code in {
                'program_running', 'program_running_or_unknown', 'package_preparation_running',
                'downgrade_or_same_version', 'unsupported_source_release', 'not_an_empty_installation',
                'not_enough_space', 'unknown_installation_state'} else 'package_incomplete_or_inconsistent'}))
        else:
            message = ('请先正常关闭本目录的管理器和全部浏览器窗口，再重新启动。'
                       if code in ('program_running', 'program_running_or_unknown') else
                       '本目录正在准备新版程序，请等待当前启动完成。'
                       if code == 'package_preparation_running' else
                       '程序包不完整、版本不兼容或更新尚未完成。请保留当前完整目录和资料；'
                       '若解压未完成，请重新完整覆盖同一新版包后正常启动。')
            try:
                ctypes.windll.user32.MessageBoxW(None, message, '无法启动本地浏览器', 0x10)
            except (AttributeError, OSError):
                pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
