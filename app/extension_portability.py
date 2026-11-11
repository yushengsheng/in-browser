"""Reject protected extension paths that cannot survive a profile copy unchanged."""
import json
from pathlib import Path
import stat

from local_state import LocalBrowserError

_MAX_PREFERENCES_BYTES = 16 * 1024 * 1024
_UNSUPPORTED = '来源启用的受保护扩展依赖绝对路径或不完整的外部文件，当前无法安全迁移；请在来源中正常处理该扩展后重新同步，原资料未修改。'
_UNREADABLE = '来源受保护扩展设置无法完整读取，未提交副本；原资料未修改。'


def _ordinary(path, *, directory=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError()


def verify_secure_extension_paths(profile):
    """Keep protected preferences byte-identical; accept only copied relative assets.

    Ordinary Preferences are handled by the existing importer. An absolute path
    in Secure Preferences cannot be made portable by rewriting the ordinary copy
    of the same extension entry: Chromium also protects the secure registration.
    """
    default = Path(profile) / 'Default'
    preferences = default / 'Secure Preferences'
    if not preferences.exists() and not preferences.is_symlink():
        return
    try:
        _ordinary(default, directory=True)
        _ordinary(preferences)
        if preferences.stat().st_size > _MAX_PREFERENCES_BYTES:
            raise ValueError()
        data = json.loads(preferences.read_text(encoding='utf-8-sig'))
        extensions = data.get('extensions', {})
        settings = extensions.get('settings', {})
        if not isinstance(settings, dict):
            raise ValueError()
    except (OSError, ValueError, TypeError, AttributeError):
        raise LocalBrowserError(_UNREADABLE) from None
    for entry in settings.values():
        if not isinstance(entry, dict) or entry.get('state') not in (1, '1'):
            continue
        raw = entry.get('path')
        if not raw:
            continue
        try:
            if not isinstance(raw, str):
                raise ValueError()
            relative = Path(raw)
            if relative.is_absolute() or relative.drive or relative.root or '..' in relative.parts:
                raise ValueError()
            install_root = default / 'Extensions'
            _ordinary(install_root, directory=True)
            folder = install_root / relative
            if not folder.resolve().is_relative_to(install_root.resolve()):
                raise ValueError()
            current = install_root
            for part in relative.parts:
                current = current / part
                _ordinary(current, directory=True)
            _ordinary(folder / 'manifest.json')
        except (OSError, ValueError, TypeError):
            raise LocalBrowserError(_UNSUPPORTED) from None
