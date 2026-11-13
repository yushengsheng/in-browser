"""Restore native saved sessions after a crash, with a bounded local rollback.

Chromium can ignore --restore-last-session when Preferences still says Crashed.
Only that flag is repaired; native navigation and Session Storage stay intact.
"""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import uuid
import zipfile

from local_state import LocalBrowserError

MAX_SESSION_BYTES = 64 * 1024 * 1024
MAX_SESSION_TOTAL = 128 * 1024 * 1024
MAX_SESSION_FILES = 1024
MAX_SESSION_COMMANDS = 1000000


def _plain(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise LocalBrowserError('会话资料包含特殊链接，未修改或启动。')


def _inspect_session(path):
    """Recognize live tab navigation records without reconstructing the session.

    Chromium's session_service_commands.cc uses command 6 with a Pickle:
    tab ID, navigation index, URL, UTF-16 title, page state, transition.
    Window binding and close/prune commands distinguish a saved tab from an
    empty initial file or a session whose final tab has already been closed.
    """
    _plain(path)
    before = path.stat()
    if before.st_size > MAX_SESSION_BYTES:
        raise LocalBrowserError('会话资料超出安全检查范围，原资料已保留，未启动。')
    with path.open('rb') as stream:
        header = stream.read(8)
        if len(header) != 8 or header[:4] != b'SNSS':
            return True, False
        version = struct.unpack_from('<I', header, 4)[0]
        if version not in (1, 3):
            return True, False
        marker = version == 1
        stopped = False
        windows = {}
        navigation = {}
        consumed = 8
        commands = 0
        while size := stream.read(2):
            if len(size) != 2:
                break
            length = struct.unpack('<H', size)[0]
            consumed += 2 + length
            commands += 1
            if consumed > MAX_SESSION_BYTES or commands > MAX_SESSION_COMMANDS:
                raise LocalBrowserError('会话资料超出安全检查范围，原资料已保留，未启动。')
            block = stream.read(length)
            if not length or len(block) != length:
                break
            command, payload = block[0], block[1:]
            if command == 255:
                marker = True
            elif stopped:
                continue
            elif command == 0:
                if len(payload) != 8:
                    stopped = True
                    continue
                window, tab = struct.unpack('<ii', payload)
                if window and tab:
                    windows[tab] = window
            elif command == 6:
                value = _navigation(payload)
                if value is None:
                    stopped = True
                    continue
                tab, index = value
                navigation.setdefault(tab, set()).add(index)
            elif command in (16, 17):
                if len(payload) != 16:
                    stopped = True
                    continue
                identity = struct.unpack_from('<i', payload)[0]
                if command == 16:
                    windows.pop(identity, None)
                    navigation.pop(identity, None)
                else:
                    for tab in [tab for tab, window in windows.items() if window == identity]:
                        windows.pop(tab, None)
                        navigation.pop(tab, None)
            elif command in (5, 11, 24):
                expected = 12 if command == 24 else 8
                if len(payload) != expected:
                    stopped = True
                    continue
                tab, index = struct.unpack_from('<ii', payload)
                if index < 0:
                    stopped = True
                    continue
                values = navigation.get(tab, set())
                if command == 5:
                    navigation[tab] = {value for value in values if value < index}
                elif command == 11:
                    navigation[tab] = {value - index for value in values if value >= index}
                else:
                    count = struct.unpack_from('<i', payload, 8)[0]
                    if index < 0 or count < 0:
                        stopped = True
                        continue
                    navigation[tab] = {value if value < index else value - count
                                       for value in values if not index <= value < index + count}
            elif command > 37:
                stopped = True
        after = path.stat()
        _plain(path)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise LocalBrowserError('会话资料在检查期间发生变化，原资料已保留，未启动。')
        return marker, marker and any(windows.get(tab) and values for tab, values in navigation.items())


def _usable(path):
    return _inspect_session(path)[1]


def _navigation(payload):
    if len(payload) < 28 or struct.unpack_from('<I', payload)[0] != len(payload) - 4:
        return None
    tab, index = struct.unpack_from('<ii', payload, 4)
    if not tab or index < 0:
        return None
    offset = 12
    strings = []
    for multiplier in (1, 2, 1):
        if offset + 4 > len(payload):
            return None
        count = struct.unpack_from('<i', payload, offset)[0]
        offset += 4
        if count < 0 or count * multiplier > len(payload) - offset:
            return None
        end = offset + count * multiplier
        strings.append(payload[offset:end])
        offset = (end + 3) & ~3
    if offset + 4 > len(payload):
        return None
    try:
        url = strings[0].decode('utf-8')
        # These are only read for recognition. Native Chromium retains control
        # of its original URLs and encrypted page state; nothing is replayed here.
        if not re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:', url) or any(ord(char) < 32 for char in url):
            return None
        strings[1].decode('utf-16-le')
    except UnicodeError:
        return None
    return tab, index


def _session_candidates(profile):
    profile = Path(os.path.abspath(profile))
    _plain(profile)
    sessions = profile / 'Default/Sessions'
    try:
        _plain(sessions)
    except FileNotFoundError:
        # Check existing ancestors as well, including a broken directory link.
        for path in (sessions.parent, profile):
            try:
                _plain(path)
            except FileNotFoundError:
                pass
        return []
    if not sessions.is_dir() or not sessions.resolve().is_relative_to(profile.resolve()):
        raise LocalBrowserError('会话资料路径不正确，原资料已保留，未启动。')
    candidates = []
    total = 0
    with os.scandir(sessions) as entries:
        for index, entry in enumerate(entries):
            if index >= MAX_SESSION_FILES:
                raise LocalBrowserError('会话资料数量超出安全检查范围，原资料已保留，未启动。')
            if not entry.name.startswith('Session_') or not entry.name[8:].isdigit():
                continue
            if int(entry.name[8:]) > 2**63 - 1:
                continue
            path = Path(entry.path)
            _plain(path)
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise LocalBrowserError('会话资料包含特殊文件，原资料已保留，未启动。')
            total += info.st_size
            if info.st_size > MAX_SESSION_BYTES or total > MAX_SESSION_TOTAL:
                raise LocalBrowserError('会话资料超出安全检查范围，原资料已保留，未启动。')
            candidates.append(path)
    return candidates


def has_saved_session(profile):
    """Read-only, bounded recognition of recoverable native Session_* files."""
    # Chromium selects the newest initialized file, even when its tabs are all
    # closed. Only an unfinished v3 initial state may fall back to an older file.
    for path in sorted(_session_candidates(profile),key=lambda path:int(path.name[8:]),reverse=True):
        selected,usable=_inspect_session(path)
        if selected:return usable
    return False


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
    if not has_saved_session(profile):
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
