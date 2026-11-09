"""Transactional encrypted catalog with folder-relative portable runtime paths."""
import copy
from datetime import datetime,timezone
import json
import hashlib
from pathlib import Path
import re
import sqlite3
import threading
from contextlib import contextmanager

from app_paths import APP_ROOT,DATA_ROOT
from local_state import LocalBrowserError,protect,read_encrypted
from profile_model import defaults,PREFERENCES
from signature_lifetime import signature_lifetime


def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')


def source_time(value,fallback=None):
    if not value: return fallback
    try:
        date=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        return date.astimezone(timezone.utc).isoformat(timespec='seconds')
    except ValueError: return fallback


class WindowStore:
    def __init__(self,configuration,root=DATA_ROOT):
        self.root=Path(root).resolve(); self.root.mkdir(parents=True,exist_ok=True)
        self.db=self.root/'windows.sqlite'; self.lock=threading.RLock(); self.configuration=configuration
        with self.connect() as con:
            con.execute('CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY,seq INTEGER NOT NULL UNIQUE,created_at TEXT NOT NULL,last_opened_at TEXT,archived INTEGER NOT NULL DEFAULT 0,data BLOB NOT NULL)')
            con.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value BLOB NOT NULL)')
            con.execute('CREATE TABLE IF NOT EXISTS source_bindings (source_key TEXT PRIMARY KEY,profile_id TEXT NOT NULL UNIQUE,imported_at TEXT NOT NULL)')
        self._migrate()

    @contextmanager
    def connect(self):
        con=sqlite3.connect(self.db,timeout=5)
        try:
            con.execute('PRAGMA journal_mode=WAL'); con.execute('PRAGMA synchronous=FULL')
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally: con.close()

    def pack(self,value):
        from portable_paths import encode_record
        value=encode_record(value,self.root)
        return protect(json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode(),root=self.root)
    def unpack(self,value):
        from portable_paths import decode_record
        return decode_record(json.loads(protect(value,decrypt=True,root=self.root)),self.root)

    def _migrate(self):
        if self.setting('migration_done',False): return
        path=self.root/'settings.bin'
        if not path.exists():
            self.set_setting('migration_done',True); return
        old=read_encrypted(path); extra={}
        snapshot=APP_ROOT.parent/'analysis/private-bootstrap/selected-settings.bin'
        if snapshot.exists():
            extra={item['alias']:item['info'] for item in read_encrypted(snapshot)}
        with self.lock,self.connect() as con:
            for index,runtime in enumerate(old['windows'],1):
                alias=runtime['alias']
                if con.execute('SELECT 1 FROM profiles WHERE id=?',(alias,)).fetchone(): continue
                native=self.configuration.decode(runtime['fingerprint_path'])
                original=extra.get(alias,{})
                record=defaults(str(runtime.get('core_major','148')))
                fp=copy.deepcopy(original.get('browserFingerPrint') or {})
                fp.pop('extendOptions',None)
                if fp: record['fingerprint'].update(fp)
                nav=native.get('navigator',{})
                record['fingerprint'].update({'userAgent':original.get('browserFingerPrint',{}).get('userAgent') or native.get('userAgent',''),
                    'os':nav.get('platform','Win32'),'hardwareConcurrency':nav.get('hardwareConcurrency',8),'deviceMemory':nav.get('deviceMemory',8)})
                for secret in ['id','browserId','createdBy','updateBy','isValidUsername']: record['fingerprint'].pop(secret,None)
                created=source_time(original.get('createdTime'),datetime.fromtimestamp(Path(runtime['profile_path']).stat().st_ctime,timezone.utc).isoformat())
                seq=int(original.get('seq') or index)
                record.update({'id':alias,'seq':seq,'name':runtime.get('name') or original.get('name') or f'窗口 {seq}',
                    'remark':original.get('remark') or '', 'created_at':created,'last_opened_at':source_time(original.get('operTime')),
                    'core_version':str(runtime.get('core_major','148')),'os':nav.get('platform','Win32'),'config_status':'ready','launch_verified':True,
                    'platform':original.get('platform') or '', 'username':original.get('userName') or '', 'password':original.get('password') or '',
                    'fa_secret':original.get('faSecretKey') or '', 'allow_multi_open':bool(original.get('isSynOpen',1)),
                    'urls':list(runtime.get('initial_urls') or []),'archived':False,'cookie_text':'','_native':native,'_runtime':copy.deepcopy(runtime),
                    '_prefs_dirty':False,'_cookie_pending':False,'_empty':False})
                p=native.get('Proxy') or {}
                record['proxy']={'type':p.get('type') or 'noproxy','host':p.get('host') or '', 'port':p.get('port') or '',
                                 'username':p.get('username') or '', 'password':p.get('password') or '', 'enable_socks5_udp':bool(p.get('enable_socks5_udp'))}
                record['preferences']=dict(PREFERENCES)
                record['preferences'].update({'mute_audio':bool(runtime.get('mute_audio')),'disable_gpu':bool(runtime.get('disable_gpu')),
                    'disable_notifications':bool(runtime.get('disable_notifications')),'abort_images':bool(original.get('abortImage')),
                    'abort_media':bool(original.get('abortMedia')),'disable_clipboard':bool(original.get('disableClipboard')),
                    'allowed_signin':bool(original.get('allowedSignin')),'credentials_service':not bool(original.get('credentialsEnableService')),
                    'disable_translate':bool(original.get('disableTranslatePopup')),'memory_saver':bool(native.get('MemorySaverModeEnabled'))})
                con.execute('INSERT INTO profiles VALUES (?,?,?,?,?,?)',(alias,seq,created,record['last_opened_at'],0,self.pack(record)))
            con.execute('INSERT OR REPLACE INTO settings VALUES (?,?)',('migration_done',self.pack(True)))

    def get(self,identity):
        with self.lock,self.connect() as con: row=con.execute('SELECT data FROM profiles WHERE id=?',(str(identity),)).fetchone()
        if not row: raise LocalBrowserError('该窗口记录不存在。')
        return self.unpack(row[0])

    def all(self,include_archived=True):
        with self.lock,self.connect() as con:
            rows=con.execute('SELECT data FROM profiles'+('' if include_archived else ' WHERE archived=0')+' ORDER BY seq').fetchall()
        return [self.unpack(row[0]) for row in rows]

    def put(self,record,include_group=False):
        with self.lock,self.connect() as con:
            con.execute('INSERT INTO profiles VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_opened_at=excluded.last_opened_at,archived=excluded.archived,data=excluded.data',
                        (record['id'],record['seq'],record['created_at'],record.get('last_opened_at'),int(bool(record.get('archived'))),self.pack(record)))
            if include_group and record.get('group'):
                row=con.execute('SELECT value FROM settings WHERE key=?',('groups',)).fetchone()
                groups=self.unpack(row[0]) if row else []
                if record['group'] not in groups:
                    con.execute('INSERT OR REPLACE INTO settings VALUES (?,?)',('groups',self.pack(groups+[record['group']])))

    def setting(self,key,default=None):
        with self.lock,self.connect() as con: row=con.execute('SELECT value FROM settings WHERE key=?',(key,)).fetchone()
        return self.unpack(row[0]) if row else copy.deepcopy(default)

    def set_setting(self,key,value):
        with self.lock,self.connect() as con: con.execute('INSERT OR REPLACE INTO settings VALUES (?,?)',(key,self.pack(value)))

    def source_binding(self,source_key):
        with self.lock,self.connect() as con:
            row=con.execute('SELECT profile_id FROM source_bindings WHERE source_key=?',(source_key,)).fetchone()
        return row[0] if row else None

    def source_bindings(self):
        with self.lock,self.connect() as con:
            return dict(con.execute('SELECT source_key,profile_id FROM source_bindings'))

    @staticmethod
    def validate_import_source(record,source_key):
        metadata=record.get('_source') or {}
        identity=metadata.get('source_id')
        if metadata.get('source_key')!=source_key or not isinstance(identity,str) or not identity:
            raise LocalBrowserError('来源身份与本地绑定不一致，未提交副本。')
        if re.fullmatch('[0-9a-fA-F]{32}',identity):
            expected=hashlib.sha256(('bitbrowser-local-v1:'+identity.lower()).encode()).hexdigest()
            if metadata.get('provider')!='bitbrowser-local-v1' or source_key!=expected:
                raise LocalBrowserError('来源身份与本地绑定不一致，未提交副本。')
        for field in ('_source_info','_source_detail'):
            info=record.get(field) or {}
            if info.get('id') and str(info['id']).lower()!=identity.lower():
                raise LocalBrowserError('完整配置的来源身份不一致，未提交副本。')

    def bind_existing(self,identity,source_key,metadata):
        with self.lock,self.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            row=con.execute('SELECT data FROM profiles WHERE id=?',(identity,)).fetchone()
            if not row:return False
            existing=con.execute('SELECT profile_id FROM source_bindings WHERE source_key=?',(source_key,)).fetchone()
            if existing:return existing[0]==identity
            record=self.unpack(row[0]);record['_source']=metadata
            self.validate_import_source(record,source_key)
            con.execute('UPDATE profiles SET data=? WHERE id=?',(self.pack(record),identity))
            con.execute('INSERT INTO source_bindings VALUES (?,?,?)',(source_key,identity,metadata.get('imported_at') or now()))
            return True

    def commit_import(self,record,source_key,*,intent_id=None):
        with self.lock,self.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            self.validate_import_source(record,source_key)
            intent=None
            if intent_id is not None:
                intent=con.execute('SELECT source_key,profile_id,state,job_id,ordinal FROM import_intents WHERE intent_id=?',(intent_id,)).fetchone()
                if not intent or intent[:3]!=(source_key,record['id'],'prepared'):
                    raise LocalBrowserError('同步提交记录与本次副本不一致，未提交。')
            if con.execute('SELECT 1 FROM source_bindings WHERE source_key=?',(source_key,)).fetchone():
                raise LocalBrowserError('这个来源窗口已经同步，保留已有本地副本。')
            record['seq']=con.execute('SELECT COALESCE(MAX(seq),0)+1 FROM profiles').fetchone()[0]
            con.execute('INSERT INTO profiles VALUES (?,?,?,?,?,?)',(record['id'],record['seq'],record['created_at'],record.get('last_opened_at'),0,self.pack(record)))
            con.execute('INSERT INTO source_bindings VALUES (?,?,?)',(source_key,record['id'],record['_source']['imported_at']))
            if record.get('group'):
                row=con.execute('SELECT value FROM settings WHERE key=?',('groups',)).fetchone();groups=self.unpack(row[0]) if row else []
                if record['group'] not in groups:con.execute('INSERT OR REPLACE INTO settings VALUES (?,?)',('groups',self.pack(groups+[record['group']])))
            if intent_id is not None:
                con.execute("UPDATE import_intents SET state='committed' WHERE intent_id=?",(intent_id,))
                if intent[3] is not None:
                    from sync_state import SyncState
                    SyncState.complete_item(con,intent[3],intent[4],'completed','完整独立副本已保存。')

    @staticmethod
    def public(record,status='closed'):
        data={key:copy.deepcopy(value) for key,value in record.items() if not key.startswith('_')}
        data['fingerprint'].pop('extendOptions',None)
        data['status']='archived' if data.get('archived') else status
        data['is_running']=status=='open'
        data['signature_provider']=record.get('_runtime',{}).get('signature_provider','vendor')
        data['environment_check']=bool(record.get('_continuity'))
        lifetime=signature_lifetime(record.get('_runtime',{}).get('fingerprint_path',''))
        data.update(signature_status=lifetime['status'],signature_created_at=lifetime.get('created_at'),signature_expires_at=lifetime.get('expires_at'))
        if lifetime['status']=='expired':data['config_status']='expired'
        return data
