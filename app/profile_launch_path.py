"""Select a verified existing spelling for one closed profile, without writes.

The caller owns the existing profile/process guard and per-window lock. This
metadata-only observation is neither a filesystem lock nor a future-path proof.
"""
import os
from pathlib import Path
import stat
import time

from native_paths import absolute_path, io_path, resolved_path

_MESSAGES = {
    'profile_path_invalid': '资料启动路径无法安全确认，尚未启动，资料已保留。',
    'profile_path_changed': '资料路径或目录在检查期间发生变化，尚未启动，资料已保留。',
    'profile_tree_limit': '资料路径检查超出范围或时限，尚未启动，资料已保留。',
    'profile_path_too_long': '现有资料目录过深，部分内核无法完整读取，尚未启动，资料已保留。请将整个程序文件夹移到当前磁盘根目录附近后重试。',
}


class ProfileLaunchPathError(ValueError):
    def __init__(self, code):
        self.code = code if code in _MESSAGES else 'profile_path_invalid'
        super().__init__(_MESSAGES[self.code])


def _fail(code='profile_path_invalid'):
    raise ProfileLaunchPathError(code) from None


def utf16_length(value):
    return len(str(value).encode('utf-16-le', errors='surrogatepass')) // 2


def _kind(info):
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        _fail()
    if stat.S_ISDIR(info.st_mode):
        return 'directory'
    if stat.S_ISREG(info.st_mode):
        return 'file'
    _fail()


def _stamp(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, getattr(info, 'st_file_attributes', 0))


def _identity(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode),
            bool(getattr(info, 'st_file_attributes', 0) & 0x400))


def _chain(path, counts):
    proof = []
    # Do not resolve a junction first and then claim that the target is plain.
    for part in reversed((path, *path.parents)):
        info = io_path(part).lstat()
        counts['lstat_calls'] += 1
        if _kind(info) != 'directory':
            _fail()
        # Shared ancestors legitimately change mtime/ctime/size when another
        # window atomically publishes settings or a sibling profile.
        proof.append((part, _identity(info)))
    return proof


def _recheck(proof, counts):
    for path, expected in proof:
        info = io_path(path).lstat()
        counts['lstat_calls'] += 1
        if _kind(info) != 'directory' or _identity(info) != expected:
            _fail('profile_path_changed')


def _alias(canonical, proposed, counts):
    proposed = Path(proposed)
    if not proposed.is_absolute() or '..' in proposed.parts:
        _fail()
    proposed = absolute_path(proposed)
    proof = _chain(proposed, counts)
    if (resolved_path(proposed) != canonical
            or not io_path(proposed).samefile(io_path(canonical))
            or resolved_path(proposed.parent) != resolved_path(canonical.parent)
            or not io_path(proposed.parent).samefile(io_path(canonical.parent))):
        _fail()
    return proposed, proof


def choose_profile_launch_path(canonical_profile, *, shortener, windows=None,
                               max_entries=1000000, max_depth=128, timeout_seconds=10.0):
    """Return (Path spelling, safe count/length metadata); never alter runtime.

    The Windows branch requires an absolute, canonical, existing plain closed
    profile. Only the passed shortener obtains an existing alternate spelling.
    Unsupported aliases, links, changed directories and incomplete scans reject.
    Existing member paths are tested under the selected root spelling; a short
    name for an individual leaf cannot rescue a root spelling Chromium appends
    long relative names to. Non-Windows keeps the input spelling without scans.
    """
    started = time.perf_counter()
    original = Path(canonical_profile)
    if windows is not None and type(windows) is not bool:
        _fail()
    if windows is None:
        windows = os.name == 'nt'
    if not windows:
        return original, {'windows': False, 'used_short_alias': False, 'checked_existing_tree': False,
            'canonical_root_utf16': utf16_length(original), 'selected_root_utf16': utf16_length(original),
            'entries_checked': 0, 'files_checked': 0, 'directories_checked': 0,
            'max_selected_utf16': 0, 'max_canonical_utf16': 0, 'scandir_calls': 0, 'lstat_calls': 0, 'entry_stat_calls': 0,
            'scan_ms': 0.0, 'caller_closed_guard_required': True}
    try:
        import math
        if (not original.is_absolute() or '..' in original.parts or type(max_entries) is not int or max_entries < 1
                or type(max_depth) is not int or max_depth < 0
                or type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or timeout_seconds <= 0 or not callable(shortener)):
            _fail()
        counts = {'entries_checked': 1, 'files_checked': 0, 'directories_checked': 1,
                  'scandir_calls': 0, 'lstat_calls': 0, 'entry_stat_calls': 0}
        deadline = time.monotonic() + timeout_seconds
        def tick():
            if time.monotonic() > deadline:
                _fail('profile_tree_limit')
        canonical = absolute_path(original)
        canonical_proof = _chain(canonical, counts)
        root_info = io_path(canonical).lstat()
        counts['lstat_calls'] += 1
        if _kind(root_info) != 'directory' or _identity(root_info) != canonical_proof[-1][1]:
            _fail('profile_path_changed')
        root_stamp = _stamp(root_info)
        tick()
        if resolved_path(canonical) != canonical:
            _fail()
        selected, alias_proof = canonical, None
        try:
            proposed = shortener(canonical)
        except (OSError, ValueError, AttributeError):
            proposed = None
        alias_available = proposed is not None
        if alias_available:
            alias, alias_proof = _alias(canonical, proposed, counts)
            if utf16_length(alias) < utf16_length(canonical):
                selected = alias
        _recheck(canonical_proof, counts)
        tick()
        max_selected = utf16_length(selected)
        max_canonical = utf16_length(canonical)
        if max_selected >= 260:
            _fail('profile_path_too_long')
        # One DFS, no sorting, no per-leaf ancestor walk and no cross-call cache.
        stack = [(canonical, Path(), 0, root_stamp)]
        while stack:
            tick()
            folder, relative, depth, expected = stack.pop()
            before = io_path(folder).lstat()
            counts['lstat_calls'] += 1
            if _kind(before) != 'directory' or _stamp(before) != expected:
                _fail('profile_path_changed')
            counts['scandir_calls'] += 1
            with os.scandir(io_path(folder)) as entries:
                for entry in entries:
                    tick()
                    counts['entries_checked'] += 1
                    if counts['entries_checked'] > max_entries or depth + 1 > max_depth:
                        _fail('profile_tree_limit')
                    info = entry.stat(follow_symlinks=False)
                    counts['entry_stat_calls'] += 1
                    kind = _kind(info)
                    name = relative / entry.name
                    selected_length = utf16_length(selected / name)
                    max_selected = max(max_selected, selected_length)
                    max_canonical = max(max_canonical, utf16_length(canonical / name))
                    if selected_length >= 260:
                        _fail('profile_path_too_long')
                    if kind == 'directory':
                        counts['directories_checked'] += 1
                        child = io_path(folder / entry.name).lstat()
                        counts['lstat_calls'] += 1
                        if _kind(child) != 'directory':
                            _fail('profile_path_changed')
                        # Windows DirEntry.stat may omit dev/ino; compare
                        # directory identity through the same API on both sides.
                        stack.append((folder / entry.name, name, depth + 1, _stamp(child)))
                    else:
                        counts['files_checked'] += 1
            after = io_path(folder).lstat()
            counts['lstat_calls'] += 1
            if _kind(after) != 'directory' or _stamp(after) != _stamp(before):
                _fail('profile_path_changed')
        _recheck(canonical_proof, counts)
        root_info = io_path(canonical).lstat()
        counts['lstat_calls'] += 1
        if _kind(root_info) != 'directory' or _stamp(root_info) != root_stamp:
            _fail('profile_path_changed')
        if alias_proof is not None:
            _recheck(alias_proof, counts)
            if (resolved_path(selected) != canonical
                    or not io_path(selected).samefile(io_path(canonical))
                    or not io_path(selected.parent).samefile(io_path(canonical.parent))):
                _fail('profile_path_changed')
        tick()
        return selected, {**counts, 'windows': True, 'used_short_alias': selected != canonical,
            'alias_available': alias_available, 'checked_existing_tree': True,
            'canonical_root_utf16': utf16_length(canonical), 'selected_root_utf16': utf16_length(selected),
            'max_selected_utf16': max_selected, 'max_canonical_utf16': max_canonical,
            'scan_ms': round((time.perf_counter() - started) * 1000, 3), 'caller_closed_guard_required': True}
    except ProfileLaunchPathError:
        raise
    except (OSError, ValueError, TypeError, AttributeError):
        _fail()
