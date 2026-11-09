"""Explicit, add-only migration to one local signing root.

``migrate(service, import_sources=True, progress=None)`` returns counts only.
The optional callback receives a fixed stage name and numeric counts, never
profile metadata, paths, identifiers or exception text. Import polling does
not hold ``service.operations`` and stops after at most 600 seconds.
Importing this module does not migrate, access the network or start a process.
"""
import copy
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import ipaddress
import os
from pathlib import Path
import shutil
import sqlite3
import time
import uuid

from bit_source import BitSource
from browser_core import sha256
from local_engine import LocalEngineStore
from local_runtime import LocalRuntime
from local_signer import LocalSigner, MAX_PAYLOAD_BYTES, MAX_VALIDITY_HOURS
from local_state import LocalBrowserError, read_encrypted, write_encrypted
from window_sync import WindowSynchronizer

_MAX_SOURCES = 1000
_IMPORT_TIMEOUT = 600
_BACKUP_TIMEOUT = 60
_FAILED = '本地独立迁移未完成，未删除来源、原签名或已有副本；请保留本机备份后重试。'
_CONFIRM_FAILED = '无法确认本地独立配置，已停止操作；未请求原厂服务，请保留本地密钥和备份。'


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _notify(progress, stage, counts):
    if progress is not None:
        try:
            progress({'stage': stage, **copy.copy(counts)})
        except Exception:
            # A reporting callback must not interrupt durable migration work.
            pass


def _sync_running(service):
    synchronizer = getattr(service, '_synchronizer', None)
    active = getattr(synchronizer, 'active', None)
    return bool(active and synchronizer.status(active).get('state') == 'running')


def _closed_ready(service, records):
    for record in records:
        if record.get('config_status', 'ready') != 'ready' or service._status(record) != 'closed':
            raise ValueError('An existing window is not closed and ready')
        service._closed(record)
        runtime = record.get('_runtime') or {}
        native = record.get('_native') or {}
        if not runtime or not isinstance(native.get('DataProtect'), dict) or not native['DataProtect'].get('CipherKey'):
            raise ValueError('Incomplete existing configuration')


def _copy_signature(source, destination, expected=None):
    source = Path(source)
    before = source.stat()
    if not source.is_file() or before.st_size > MAX_PAYLOAD_BYTES + 284:
        raise ValueError('Missing or oversized original signature')
    digest = hashlib.sha256()
    with source.open('rb') as incoming, destination.open('xb') as outgoing:
        copied = 0
        while block := incoming.read(1024 * 1024):
            copied += len(block)
            if copied > MAX_PAYLOAD_BYTES + 284:
                raise ValueError('Original signature grew during backup')
            digest.update(block)
            outgoing.write(block)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    after = source.stat()
    stamp = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if (stamp(before) != stamp(after) or sha256(destination) != digest.hexdigest()
            or expected is not None and digest.hexdigest() != expected):
        raise ValueError('Original signature changed during backup')


def _backup(service, records):
    root = Path(service.root)
    name = 'fully-local-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f') + '-' + uuid.uuid4().hex[:8]
    folder = root / 'backups' / name
    folder.mkdir(parents=True, exist_ok=False)
    destination = folder / 'windows.sqlite'
    temporary = folder / 'windows.sqlite.tmp'
    deadline = time.monotonic() + _BACKUP_TIMEOUT

    def limit(_status, _remaining, _total):
        if time.monotonic() >= deadline:
            raise TimeoutError('Catalog backup timed out')

    # SQLite's backup API includes committed WAL pages without copying a live
    # database file or forcing a checkpoint of the original catalog.
    with service.store.lock, service.store.connect() as source:
        with closing(sqlite3.connect(temporary, timeout=5)) as target:
            source.backup(target, pages=256, progress=limit, sleep=0.05)
            if target.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise ValueError('Catalog backup validation failed')
            target.commit()
    os.replace(temporary, destination)
    signatures = folder / 'signatures'
    signatures.mkdir()
    for index, record in enumerate(records, 1):
        runtime = record['_runtime']
        _copy_signature(runtime['fingerprint_path'], signatures / ('existing-' + str(index) + '.bin'),
                        runtime['fingerprint_sha256'])
    # Copy only existing encrypted stores and public identity metadata. Private
    # key material remains in its original DPAPI-protected representation.
    for relative in ('configuration-context.bin', 'settings.bin', 'vendor-session.bin',
                     'local-source-archive.bin', 'independent-mode.bin',
                     'local-signing/private.bin', 'local-signing/public.der', 'local-signing.lock'):
        original = root / relative
        if original.is_file():
            target = folder / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
    return folder


def _confirm(service, records, counts):
    configuration = service.configuration
    configuration.independent = True
    signer = LocalSigner(service.root, load_private=False)
    mode = read_encrypted(Path(service.root) / 'independent-mode.bin')
    if not isinstance(mode, dict) or mode.get('format') != 1 or mode.get('key_id') != signer.key_id:
        raise ValueError('Independent mode identity mismatch')
    archive = configuration.source_archive()
    if archive.get('key_id') != signer.key_id or not isinstance(archive.get('engines'), dict):
        raise ValueError('Archive identity mismatch')
    engines = LocalEngineStore()
    checked = set()
    for major, executable in archive['engines'].items():
        engines.validate(executable, signer.key_id, major)
        checked.add((str(major), str(executable)))
    for record in records:
        runtime = record['_runtime']
        if runtime.get('signature_provider') != 'local-v1' or runtime.get('signature_key_id') != signer.key_id:
            raise ValueError('Existing window identity mismatch')
        pin = (str(runtime['core_major']), str(runtime['core_path']))
        if pin not in checked:
            engines.validate(runtime['core_path'], signer.key_id, runtime['core_major'])
            checked.add(pin)
        if sha256(Path(runtime['fingerprint_path'])) != runtime['fingerprint_sha256'] or not signer.verify(runtime['fingerprint_path']):
            raise ValueError('Existing local signature cannot be confirmed')
        if configuration.decode(runtime['fingerprint_path']) != record.get('_native'):
            raise ValueError('Existing native configuration mismatch')
    counts.update(already_independent=True, enabled=True, sources=len(archive['items']), prepared=len(records))
    return counts


def _archive(service, provider, candidates, records, runtime, backup, counts, progress):
    configuration = service.configuration
    root = provider._settings()
    archive = {'format': 1, 'key_id': runtime.signer.key_id, 'profile_root': str(root),
               'engines': {}, 'items': {}, 'created_at': _now()}
    deployed = {}
    geographies = {}

    def deploy(major, executable):
        pin = (str(major), str(executable))
        if pin not in deployed:
            deployed[pin] = runtime.engines.ensure(major, executable, runtime.signer.public_der)
            counts['engines'] += 1
            _notify(progress, 'deploying', counts)
        archive['engines'].setdefault(str(major), str(deployed[pin]))

    for record in records:
        original = record['_runtime']
        if original.get('signature_provider') == 'local-v1' and original.get('signature_key_id') != runtime.signer.key_id:
            raise ValueError('Existing local window uses another root')
        deploy(original['core_major'], original['core_path'])
    for index, candidate in enumerate(candidates, 1):
        startup = provider.startup(candidate)
        full = startup['info']
        fp=full.get('browserFingerPrint') or {}
        frozen_geo=None
        if any(fp.get(key) for key in ('isIpCreateLanguage','isIpCreateTimeZone','isIpCreatePosition','isIpCreateDisplayLanguage')):
            saved_ip=str(full.get('lastIp') or '')
            parsed_ip=ipaddress.ip_address(saved_ip)
            method=full.get('ipCheckService') or 'ip123in'
            lookup=(saved_ip,str(method))
            if lookup not in geographies:
                geo=configuration.vendor('/v1/apis/ipgeoMethod',{'ip':saved_ip,'method':method,'checkExists':0})
                if not isinstance(geo,dict):raise ValueError('Missing saved source environment')
                geo=copy.deepcopy(geo);geo.setdefault('ip',saved_ip)
                if ipaddress.ip_address(geo['ip'])!=parsed_ip:raise ValueError('Saved source environment identity mismatch')
                geographies[lookup]=geo
            frozen_geo=geographies[lookup]
        native, _ = configuration.build_source(full, sign=False, frozen_geo=frozen_geo)
        protection = (full.get('browserFingerPrint', {}).get('extendOptions') or {}).get('DataProtect')
        if not isinstance(native, dict) or native.get('DataProtect') != protection:
            raise ValueError('Source protection mismatch')
        if (native.get('FontConfig') or {}).get('Files'):
            raise ValueError('Unverified external font dependency')
        provider.revalidate(candidate)
        deploy(candidate['_core_major'], startup['core_path'])
        original_signature = startup.get('signed_path')
        if original_signature is not None:
            _copy_signature(original_signature, backup / 'signatures' / ('source-' + str(index) + '.bin'))
        archive['items'][candidate['source_id'].lower()] = {
            'full': copy.deepcopy(full), 'detail': copy.deepcopy(candidate['info']), 'native': copy.deepcopy(native)}
        counts['archived'] += 1
        _notify(progress, 'archiving', counts)
    # Recheck every source before enabling; no source is copied while running.
    for candidate in candidates:
        provider.revalidate(candidate)
    write_encrypted(Path(service.root) / 'local-source-archive.bin', archive)
    if configuration.source_archive() != archive:
        raise ValueError('Encrypted archive verification failed')


def _import(service, synchronizer, counts, progress):
    preview = synchronizer.preview()
    items = preview['items']
    keys = [item['source_key'] for item in items if item['status'] == 'ready']
    counts['already_imported'] = sum(item['status'] == 'already_imported' for item in items)
    counts['skipped'] = len(items) - len(keys)
    if not keys:
        return counts
    identity = synchronizer.start(keys)['job_id']
    deadline = time.monotonic() + _IMPORT_TIMEOUT
    previous = None
    while True:
        state = synchronizer.status(identity)
        counts.update(imported=int(state.get('completed', 0)), failed=int(state.get('failed', 0)),
                      skipped=len(items) - len(keys) + int(state.get('skipped', 0)))
        counts['pending'] = max(0, len(keys) - counts['imported'] - counts['failed'] - int(state.get('skipped', 0)))
        snapshot = (counts['imported'], counts['failed'], counts['skipped'], counts['pending'])
        if snapshot != previous:
            _notify(progress, 'importing', counts)
            previous = snapshot
        if state.get('state') != 'running':
            if counts['pending']:
                if state.get('state') == 'cancelled':
                    counts['skipped'] += counts['pending']
                else:
                    counts['failed'] += counts['pending']
                counts['pending'] = 0
            return counts
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            synchronizer.cancel(identity)
            counts['timed_out'] = True
            return counts
        time.sleep(min(0.25, remaining))


def migrate(service, import_sources=True, *, progress=None):
    """Prepare and enable local mode; return aggregate, non-sensitive counts.

    An existing mode is verified locally and returned without another import.
    A failed preparation leaves mode disabled and preserves all old signatures.
    A later import failure keeps mode enabled and every committed local copy.
    """
    counts = {'already_independent': False, 'enabled': False, 'existing': 0, 'sources': 0,
              'archived': 0, 'engines': 0, 'prepared': 0, 'already_imported': 0,
              'imported': 0, 'failed': 0, 'skipped': 0, 'pending': 0, 'timed_out': False}
    mode = Path(service.root) / 'independent-mode.bin'
    synchronizer = None
    try:
        with service.operations:
            records = service.store.all()
            counts['existing'] = len(records)
            if mode.exists():
                _notify(progress, 'confirming', counts)
                result = _confirm(service, records, counts)
                _notify(progress, 'completed', result)
                return result
            if getattr(service.configuration, 'independent', False) or _sync_running(service):
                raise ValueError('Migration state is not idle')
            _notify(progress, 'checking', counts)
            _closed_ready(service, records)
            provider = BitSource(service.configuration)
            candidates = provider.discover()
            counts['sources'] = len(candidates)
            if len(candidates) > _MAX_SOURCES or any(candidate.get('status') != 'ready' for candidate in candidates):
                raise ValueError('Every source must be closed and ready')
            _notify(progress, 'backing_up', counts)
            backup = _backup(service, records)
            runtime = LocalRuntime(service)
            _archive(service, provider, candidates, records, runtime, backup, counts, progress)
            _closed_ready(service, records)
            for record in records:
                runtime.prepare(record, force=True)
                counts['prepared'] += 1
                _notify(progress, 'migrating', counts)
            for candidate in candidates:
                provider.revalidate(candidate)
            _closed_ready(service, service.store.all())
            write_encrypted(mode, {'format': 1, 'key_id': runtime.signer.key_id, 'created_at': _now(),
                                  'profile_count': len(records), 'source_count': len(candidates),
                                  'validity_hours': MAX_VALIDITY_HOURS, 'provider': 'local-v1'})
            service.configuration.independent = True
            counts['enabled'] = True
            _notify(progress, 'enabling', counts)
            if import_sources:
                synchronizer = WindowSynchronizer(service)
                service._synchronizer = synchronizer
        # The worker acquires operations for each import. Never wait while the
        # migration caller owns that lock.
        if synchronizer is not None:
            _import(service, synchronizer, counts, progress)
        _notify(progress, 'completed', counts)
        return counts
    except Exception:
        _notify(progress, 'failed', counts)
        if counts['already_independent'] or mode.exists() and not counts['enabled']:
            raise LocalBrowserError(_CONFIRM_FAILED) from None
        raise LocalBrowserError(_FAILED) from None
