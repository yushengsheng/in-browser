"""Create an independent folder root only for a completely empty installation."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat

from app_paths import APP_ROOT, DATA_ROOT
from local_signer import LocalSigner, MAX_VALIDITY_HOURS
from local_state import LocalBrowserError, write_encrypted
from portable_vault import PortableVault, PortableVaultError, MAX_PLAINTEXT_BYTES, is_portable


PENDING = '.installation-pending'
MARKER = 'installation.bin'
_RESOURCES = ('electron-main.js', 'crypto.worker.js', 'defaults.json')
_STATE_FILES = ('configuration-context.bin', 'local-source-archive.bin',
                'independent-mode.bin', 'portable-mode.bin', 'continuity-mode.bin', MARKER)
_FAILURE = '首次安装状态不完整或密钥不匹配，已停止；请保留完整目录，不会重建或覆盖已有资料。'


def _ordinary(path, *, directory=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError()


def _release_resources():
    """Preflight public files before writing any first-install state."""
    try:
        resources = APP_ROOT / 'resources'
        _ordinary(resources, directory=True)
        for name in _RESOURCES:
            path = resources / name
            _ordinary(path)
            if not 0 < path.stat().st_size <= 32 * 1024 * 1024:
                raise ValueError()
        worker = (resources / 'crypto.worker.js').read_text(encoding='utf-8')
        if not re.search(r'function Tn\(\)\{return\[([0-9,\s]+)\]', worker):
            raise ValueError()
        defaults = json.loads((resources / 'defaults.json').read_text(encoding='utf-8'))
        if not isinstance(defaults, dict) or not isinstance(defaults.get('browserFingerPrint'), dict):
            raise ValueError()
    except (OSError, ValueError, TypeError, UnicodeError):
        raise LocalBrowserError('发布资源缺失或损坏，请恢复完整程序包后重试；尚未初始化资料或密钥。') from None


def _read_record(root, name, vault):
    path = root / name
    _ordinary(path)
    with path.open('rb') as handle:
        raw = handle.read(MAX_PLAINTEXT_BYTES + 4097)
    if not is_portable(raw):
        raise ValueError()
    value = json.loads(vault.decrypt(raw))
    if not isinstance(value, dict):
        raise ValueError()
    return value


def _validate(root):
    """Authenticate a root we created; never repair or rotate either key."""
    _ordinary(root / '.portable-vault', directory=True)
    _ordinary(root / 'local-signing', directory=True)
    for name in ('local-signing.lock', 'local-signing/public.der', 'local-signing/private.bin'):
        _ordinary(root / name)
    vault = PortableVault(root, key_required=True)
    # Public-only loading first prevents a missing identity from creating a key.
    signer = LocalSigner(root, load_private=False)
    _read_record(root, 'local-signing/private.bin', vault)
    LocalSigner(root)
    values = {name: _read_record(root, name, vault) for name in _STATE_FILES}
    identity = values[MARKER]
    if (identity.get('format') != 1 or identity.get('state') != 'ready'
            or identity.get('vault_key_id') != vault.key_id
            or identity.get('signing_key_id') != signer.key_id):
        raise ValueError()
    independent = values['independent-mode.bin']
    if (independent.get('format') != 1 or independent.get('state') != 'ready'
            or independent.get('key_id') != signer.key_id or independent.get('provider') != 'local-v1'):
        raise ValueError()
    for name in ('portable-mode.bin', 'continuity-mode.bin'):
        mode = values[name]
        if mode.get('format') != 1 or mode.get('state') != 'ready' or mode.get('key_id') != vault.key_id:
            raise ValueError()
    archive = values['local-source-archive.bin']
    if (archive.get('format') != 1 or archive.get('key_id') != signer.key_id
            or not isinstance(archive.get('items'), dict) or not isinstance(archive.get('engines'), dict)):
        raise ValueError()


def initialize_installation(root=DATA_ROOT):
    """Return True for a new root; preserve existing installations without writes.

    A durable exclusive sentinel makes an interrupted attempt fail closed. It is
    intentionally retained on failure: only an entirely empty root is eligible
    for automatic creation, never a partially created or damaged installation.
    """
    root = Path(root)
    try:
        if root.exists() or root.is_symlink():
            _ordinary(root, directory=True)
            if (root / PENDING).exists() or (root / PENDING).is_symlink():
                raise ValueError()
            if (root / MARKER).exists() or (root / MARKER).is_symlink():
                _validate(root)
                return False
            if any(root.iterdir()):
                # Older installations retain their existing migration and mode
                # rules. Key validation is read-only and cannot create a root.
                if not any((root / name).is_file() for name in ('windows.sqlite', 'settings.bin')):
                    raise ValueError()
                if (root / 'portable-mode.bin').exists() or (root / '.portable-vault').exists():
                    PortableVault(root, key_required=True)
                if (root / 'independent-mode.bin').exists():
                    LocalSigner(root, load_private=False)
                return False
        _release_resources()
        root.mkdir(parents=True, exist_ok=True)
        if any(root.iterdir()):
            raise ValueError()
        with (root / PENDING).open('xb') as handle:
            handle.write(b'local-browser-first-install-v1\n')
            handle.flush()
            os.fsync(handle.fileno())
        if {path.name for path in root.iterdir()} != {PENDING}:
            raise ValueError()
        vault = PortableVault(root).initialize()
        signer = LocalSigner(root, validity_hours=MAX_VALIDITY_HOURS)
        created = datetime.now(timezone.utc).isoformat(timespec='seconds')
        context = {'permissions': {'userType': 1}, 'geo': None, 'variations': None,
                   'badges': {}, 'maxImageBypass': None}
        archive = {'format': 1, 'key_id': signer.key_id, 'items': {}, 'engines': {}, 'created_at': created}
        independent = {'format': 1, 'state': 'ready', 'key_id': signer.key_id,
                       'provider': 'local-v1', 'validity_hours': MAX_VALIDITY_HOURS,
                       'created_at': created, 'profile_count': 0, 'source_count': 0}
        ready = {'format': 1, 'state': 'ready', 'key_id': vault.key_id, 'created_at': created, 'windows': 0}
        for name, value in (('configuration-context.bin', context), ('local-source-archive.bin', archive),
                            ('independent-mode.bin', independent), ('portable-mode.bin', ready),
                            ('continuity-mode.bin', ready)):
            write_encrypted(root / name, value, root=root)
        write_encrypted(root / MARKER, {'format': 1, 'state': 'ready', 'created_at': created,
                                     'vault_key_id': vault.key_id, 'signing_key_id': signer.key_id}, root=root)
        _validate(root)
        (root / PENDING).unlink()
        return True
    except LocalBrowserError:
        raise
    except (OSError, ValueError, TypeError, PortableVaultError):
        raise LocalBrowserError(_FAILURE) from None
