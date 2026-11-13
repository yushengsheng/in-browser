"""Shared, deterministic layout contract for overwrite-safe portable packages."""
import re

PACKAGE_DIRECTORY = '.program-packages'
MARKER = 'overlay-package.json'
LAUNCHER = '启动本地浏览器.cmd'
BOOTSTRAP = 'tools/portable_bootstrap.py'
RETIRED_LAUNCHERS = ('完整迁移到新目录.cmd', '原地更新旧版本.cmd')


def launcher_bytes(package_id):
    if not isinstance(package_id, str) or re.fullmatch('[0-9a-f]{32}', package_id) is None:
        raise ValueError('Invalid package identifier')
    package = '%~dp0' + PACKAGE_DIRECTORY + '\\' + package_id
    lines = ['@echo off', 'setlocal DisableDelayedExpansion',
             'set "IB_PACKAGE=' + package + '"']
    for name in ('runtime\\python\\pythonw.exe', BOOTSTRAP.replace('/', '\\'),
                 'release-manifest.json', MARKER):
        lines.append('if not exist "%IB_PACKAGE%\\' + name + '" goto incomplete')
        lines.append('if exist "%IB_PACKAGE%\\' + name + '\\" goto incomplete')
    lines.extend([
        'start "" /b "%IB_PACKAGE%\\runtime\\python\\pythonw.exe" -B '
        '"%IB_PACKAGE%\\tools\\portable_bootstrap.py" --target "%~dp0."',
        'exit /b %errorlevel%', ':incomplete',
        'echo Incomplete package. Copy the entire new package over this folder, then retry.',
        'pause', 'exit /b 1', '',
    ])
    return '\r\n'.join(lines).encode('ascii')
