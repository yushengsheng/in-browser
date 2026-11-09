"""Restore native saved sessions after a crash, with a bounded local rollback.

Chromium can ignore --restore-last-session when Preferences still says Crashed.
Only that flag is repaired; native navigation and Session Storage stay intact.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import uuid
import zipfile

from local_state import LocalBrowserError


def _plain(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise LocalBrowserError('会话资料包含特殊链接，未修改或启动。')


def _usable(path):
    with path.open('rb') as stream:
        header = stream.read(8)
        if len(header) != 8 or header[:4] != b'SNSS':
            return False
        version = struct.unpack_from('<I', header, 4)[0]
        if version not in (1, 3):
            return False
        marker = version == 1
        navigation = False
        while size := stream.read(2):
            if len(size) != 2:
                break
            length = struct.unpack('<H', size)[0]
            block = stream.read(length)
            if not length or len(block) != length:
                break
            marker |= block[0] == 255
            navigation |= block[0] == 6
        return marker and navigation


def _write_preferences(path, data, original):
    temporary = path.with_name('.session-preferences-' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as output:
            json.dump(data, output, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        if path.read_bytes() != original:
            raise LocalBrowserError('窗口偏好在会话准备期间发生变化，未覆盖或启动。')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_session(profile, *, restore=True):
    if not restore:
        return False
    profile = Path(profile)
    preferences = profile / 'Default/Preferences'
    if not preferences.is_file():
        return False
    _plain(preferences)
    raw = preferences.read_bytes()
    data = json.loads(raw.decode('utf-8-sig'))
    if data.get('profile', {}).get('exit_type') != 'Crashed':
        return False
    sessions = profile / 'Default/Sessions'
    if not sessions.is_dir():
        return False
    _plain(sessions)
    candidates = [file for file in sessions.iterdir()
                  if file.name.startswith('Session_') and file.name[8:].isdigit() and file.is_file()]
    for file in candidates:
        _plain(file)
    if not any(_usable(file) for file in candidates):
        return False

    # Keep one atomic rollback beside this profile. Deleting the window also
    # deletes this backup. No Cookies or other website databases are rewritten.
    files = [preferences]
    for folder in (sessions, profile / 'Default/Session Storage'):
        if not folder.exists():
            continue
        _plain(folder)
        pending = [folder]
        while pending:
            for file in pending.pop().iterdir():
                _plain(file)
                if file.is_dir():
                    pending.append(file)
                elif file.is_file():
                    files.append(file)
                else:
                    raise LocalBrowserError('会话资料包含特殊文件，未修改或启动。')
                if len(files) + len(pending) > 100000:
                    raise LocalBrowserError('会话资料数量超出恢复范围，原资料已保留。')
    def stamp(file):
        info = file.stat()
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
    before = {file: stamp(file) for file in files}
    if shutil.disk_usage(profile).free < sum(value[2] for value in before.values()) + 20_000_000:
        raise LocalBrowserError('磁盘空间不足以备份上次会话，未覆盖资料或启动。')
    temporary = profile / ('.session-recovery-' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('xb') as output:
            with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                for file in files:
                    archive.write(file, file.relative_to(profile).as_posix())
            output.flush()
            os.fsync(output.fileno())
        if any(stamp(file) != value for file, value in before.items()) or preferences.read_bytes() != raw:
            raise LocalBrowserError('会话资料在恢复准备时发生变化，未修改或启动。')
        os.replace(temporary, profile / '.local-session-recovery.zip')
        data['profile']['exit_type'] = 'Normal'
        _write_preferences(preferences, data, raw)
    finally:
        temporary.unlink(missing_ok=True)
    return True
