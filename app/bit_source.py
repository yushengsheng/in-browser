"""Read-only discovery of BitBrowser profiles already present on this computer."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from local_state import LocalBrowserError
from browser_processes import profile_processes,ProfileProcessSnapshot
from engine_store import executable_major
from core_specs import supports_major
from local_source import source_protection,PUBLIC_SEED_IMPORT_NOTE


_ID = re.compile(r'[a-fA-F0-9]{32}')
_VERSION = re.compile(r'([0-9]{2,3})\.[0-9]+\.[0-9]+\.[0-9]+')
_CHANGED_ERROR = '来源资料或配置已变化，请重新点击同步窗口；尚未复制此来源。'


def _reparse(path):
    value = path.lstat()
    return path.is_symlink() or bool(getattr(value, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _stamp(path):
    value = path.lstat()
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


class BitSource:
    """Candidate dictionaries are private and must never be serialized to the UI."""

    def __init__(self, configuration):
        self.configuration = configuration
        self.vendor_data = Path(configuration.vendor_data).absolute()
        self.database = self.vendor_data / 'db.sqlite'

    def _settings(self):
        if getattr(self.configuration,'independent',False):
            from local_source import profile_root
            root=profile_root(self.configuration)
            if not root.is_absolute():raise LocalBrowserError('本地迁移资料位置无效，未同步。')
            return root
        try:
            con = sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True, timeout=3)
            try:
                values = dict(con.execute(
                    'SELECT config_name,config_value FROM global_configs WHERE config_name=?',
                    ('browser_cache_dir',)))
            finally:
                con.close()
            root = Path(values.get('browser_cache_dir') or self.vendor_data / 'BrowserCache')
            if not root.is_absolute():
                raise ValueError()
            return root.absolute()
        except (OSError, sqlite3.Error, ValueError, TypeError, OverflowError):
            raise LocalBrowserError('无法读取原客户端本机资料位置；原窗口和资料未改动。') from None

    def _detail(self, source_id):
        info = self.configuration.source_detail(source_id)
        if not isinstance(info, dict):
            return None
        if not isinstance(info.get('id'), str) or info['id'].lower() != source_id.lower():
            return None
        return info

    @staticmethod
    def _core_major(info, last_version):
        fp = info.get('browserFingerPrint')
        if not isinstance(fp, dict):
            raise ValueError()
        product = fp.get('coreProduct') or info.get('coreProduct')
        if product != 'chrome':
            raise ValueError()
        major = str(fp.get('coreVersion') or info.get('coreVersion') or '')
        if not re.fullmatch('[0-9]{2,3}', major) or not supports_major(major):
            raise ValueError()
        previous = _VERSION.fullmatch(last_version)
        if not previous or int(previous.group(1)) > int(major):
            raise ValueError()
        return major

    def _candidate(self, root, source_id,processes=None):
        path = root / source_id
        candidate = {'source_key': hashlib.sha256(
            ('bitbrowser-local-v1:' + source_id.lower()).encode()).hexdigest(),
            'source_id': source_id, 'profile_path': path, 'info': None,
            'status': 'missing_data', 'reason': '原本机资料不完整，尚未导入。'}
        try:
            if _reparse(root) or _reparse(path) or not path.resolve().is_relative_to(root.resolve()):
                candidate.update(status='unsupported', reason='来源资料包含特殊目录链接，尚未导入。')
                return candidate
            if not path.is_dir():
                return candidate
            for relative in ['Default', 'Local State', 'Default/Preferences', 'Last Version']:
                item = path / relative
                if not item.exists():
                    return candidate
                if _reparse(item):
                    candidate.update(status='unsupported', reason='来源资料包含特殊目录链接，尚未导入。')
                    return candidate
            if not (path / 'Default').is_dir() or any(
                    not (path / name).is_file() or (path / name).stat().st_size == 0
                    for name in ['Local State', 'Default/Preferences', 'Last Version']):
                return candidate
            try:
                if processes is None:running=bool(profile_processes(path,require_inspectable=True))
                else:
                    if processes.uncertain(path):raise LocalBrowserError('无法确认来源浏览器已关闭，请稍后重新预览。')
                    running=processes.occupied(path)
            except LocalBrowserError as error:
                candidate.update(status='unsupported', reason=str(error))
                return candidate
            detail_error = None
            try:
                info = self._detail(source_id)
            except LocalBrowserError as error:
                detail_error = str(error)
                info = None
            candidate['info'] = info
            if running:
                candidate.update(status='source_open', reason='来源窗口正在运行，请先正常关闭该浏览器窗口后再同步；比特客户端无需运行。')
                return candidate
            with (path / 'Last Version').open('r', encoding='utf-8-sig') as handle:
                last_version = handle.read(257).strip()
            if len(last_version) > 256:
                raise ValueError()
            stale=bool(info is not None and getattr(self.configuration,'independent',False)
                and hasattr(self.configuration,'source_prepared_for_profile')
                and not self.configuration.source_prepared_for_profile(source_id))
            if stale:
                version=_VERSION.fullmatch(last_version)
                if not version or not supports_major(version.group(1)):raise ValueError()
                info=dict(info)
                info['browserFingerPrint']={'coreProduct':'chrome','coreVersion':version.group(1),'os':(info.get('browserFingerPrint') or {}).get('os','')}
                candidate.update(info=info,_needs_preparation=True)
            if info is None:
                if not getattr(self.configuration,'independent',False) or detail_error:
                    candidate['reason'] = detail_error or '本机资料仍在，但来源窗口信息不可读取，尚未导入。'
                    return candidate
                version=_VERSION.fullmatch(last_version)
                if not version or not supports_major(version.group(1)):raise ValueError()
                info={'id':source_id,'name':'待准备的本机窗口','browserFingerPrint':{'coreProduct':'chrome','coreVersion':version.group(1)}}
                candidate.update(info=info,_needs_preparation=True)
            major = self._core_major(info, last_version)
            candidate.update(status='ready', reason=None, _core_major=major,
                             _last_version=last_version, _snapshot=tuple(
                                 _stamp(path / name) for name in
                                 ['', 'Default', 'Local State', 'Default/Preferences', 'Last Version']))
            return candidate
        except LocalBrowserError:
            raise
        except (OSError, ValueError, TypeError):
            candidate.update(status='unsupported', reason='来源资料或内核版本无法安全核对，尚未导入。')
            return candidate

    def discover(self):
        if (Path(getattr(self.configuration,'root',self.vendor_data))/'portable-mode.bin').is_file() and not (self.vendor_data/'db.sqlite').is_file():
            archived=self.configuration.source_archive().get('items',{})
            if hasattr(self.configuration,'prepared_sources'):
                prepared=self.configuration.prepared_sources()
                archived.update({identity:prepared.get(identity) for identity in prepared.ids()})
            return [{'source_key':hashlib.sha256(('bitbrowser-local-v1:'+identity.lower()).encode()).hexdigest(),
                     'source_id':identity,'profile_path':self.configuration.root/'archived-sources'/identity,
                     'info':item.get('detail'),'status':'missing_data','reason':'来源配置已保存在便携目录；已导入窗口从本地副本打开。'}
                    for identity,item in archived.items()]
        root = self._settings()
        try:
            if not root.exists():
                return []
            if not root.is_dir() or _reparse(root):
                raise LocalBrowserError('原客户端资料根目录不受支持，尚未导入。')
            source_ids = sorted(entry.name for entry in root.iterdir() if _ID.fullmatch(entry.name))
            processes=ProfileProcessSnapshot()
            return [self._candidate(root,source_id,processes) for source_id in source_ids]
        except LocalBrowserError:
            raise
        except OSError:
            raise LocalBrowserError('无法枚举原客户端本机资料；原窗口和资料未改动。') from None

    def revalidate(self, candidate):
        source_id = candidate.get('source_id')
        if not isinstance(source_id, str) or not _ID.fullmatch(source_id):
            raise LocalBrowserError('同步来源标识无效，尚未复制资料。')
        root = self._settings()
        expected = root / source_id
        if os.path.normcase(os.path.abspath(candidate.get('profile_path', ''))) != os.path.normcase(str(expected)):
            raise LocalBrowserError(_CHANGED_ERROR)
        fresh = self._candidate(root, source_id)
        if fresh['status'] != 'ready':
            raise LocalBrowserError(fresh['reason'])
        prepared_transition=bool(candidate.get('_needs_preparation')) and not fresh.get('_needs_preparation')
        if candidate.get('_snapshot') != fresh.get('_snapshot') or candidate.get('_core_major') != fresh.get('_core_major') or (candidate.get('info') != fresh.get('info') and not prepared_transition):
            raise LocalBrowserError(_CHANGED_ERROR)
        return fresh

    def _core_path(self, major):
        if getattr(self.configuration,'independent',False):return self.configuration.local_core(major)
        try:
            from source_database import snapshot
            with snapshot(self.database) as con:
                rows = con.execute('SELECT version FROM chrome_versions WHERE chrome=?', (major,)).fetchall()
            if len(rows) != 1 or not isinstance(rows[0][0], str) or not re.fullmatch('[A-Za-z0-9_.-]{1,80}', rows[0][0]):
                raise ValueError()
            version = rows[0][0]
            if version in ['.', '..']:
                raise ValueError()
            root = self.vendor_data / 'Chrome-bin'
            path = root / major / version / 'BitBrowser.exe'
            if any(_reparse(item) for item in [root, root / major, path.parent, path]):
                raise ValueError()
            if not path.is_file() or not path.resolve().is_relative_to(root.resolve()) or executable_major(path) != major:
                raise ValueError()
            return path
        except (OSError, sqlite3.Error, ValueError, TypeError, LocalBrowserError):
            raise LocalBrowserError('未找到与来源资料匹配的完整本机 Chromium 内核，尚未导入。') from None

    def startup(self, candidate):
        fresh = self.revalidate(candidate)
        source_id = fresh['source_id']
        if fresh.get('_needs_preparation'):
            self.configuration.prepare_source(source_id,fresh['_core_major'])
            fresh=self.revalidate(candidate)
        candidate.pop('_needs_preparation',None)
        candidate.update(fresh)
        info = self.configuration.source_settings(source_id)
        try:
            if not isinstance(info, dict) or not isinstance(info.get('id'), str) or info['id'].lower() != source_id.lower():
                raise ValueError()
            major = self._core_major(info, fresh['_last_version'])
            if major != fresh['_core_major']:
                raise ValueError()
            fp = info['browserFingerPrint']
            if fp.get('browserId') and str(fp['browserId']).lower() != source_id.lower():
                raise ValueError()
            extension = fp.get('extendOptions')
            if isinstance(extension, str):
                extension = json.loads(extension)
            fp['extendOptions'] = extension
            source_protection(fp)
        except (ValueError, KeyError, TypeError):
            raise LocalBrowserError('来源完整启动配置或匹配的数据保护参数缺失，尚未导入。') from None
        core = self._core_path(major)
        if getattr(self.configuration,'independent',False):
            self.revalidate(fresh)
            result={'info':info,'signed_path':None,'core_path':core}
            if hasattr(self.configuration,'source_entry'):
                entry=self.configuration.source_entry(source_id)
                if isinstance(entry,dict) and entry.get('import_note'):result['import_note']=entry['import_note']
            return result
        signed_root = self.vendor_data / 'LocalCache'
        signed = signed_root / source_id
        try:
            if signed.exists():
                if _reparse(signed_root) or _reparse(signed) or not signed.is_file() or not signed.resolve().is_relative_to(signed_root.resolve()):
                    raise ValueError()
            else:
                signed = None
        except (OSError, ValueError):
            raise LocalBrowserError('来源签名配置路径不受支持，尚未导入。') from None
        # The caller must compare a decoded cache's DataProtect against this info
        # before reusing its bytes. A matching filename alone is insufficient.
        self.revalidate(fresh)
        result={'info':info,'signed_path':signed,'core_path':core}
        if signed is None:result['import_note']=PUBLIC_SEED_IMPORT_NOTE
        return result
