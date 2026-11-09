"""Explicit folder-key conversion; original DPAPI stores remain in a backup."""
import copy
from contextlib import closing
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time
import uuid

from local_state import LocalBrowserError,read_encrypted,write_encrypted,protect
from portable_vault import PortableVault
from portable_paths import encode_archive

_BIN_FILES=('configuration-context.bin','settings.bin','vendor-session.bin','local-source-archive.bin','independent-mode.bin','local-signing/private.bin')


def migrate(service,*,progress=None):
    from portable_browser import capture_profile
    root=service.root;marker=root/'portable-mode.bin'
    if not service.configuration.independent:raise LocalBrowserError('请先完成独立本地迁移，再准备便携目录。')
    if marker.is_file():
        info=read_encrypted(marker,root=root)
        if info.get('key_id')!=PortableVault(root,key_required=True).key_id:raise LocalBrowserError('便携目录密钥不匹配，未重建或覆盖。')
        if info.get('state')=='ready':return {'already_portable':True,'windows':len(service.store.all())}
    def notify(stage,**counts):
        if progress:progress({'stage':stage,**counts})
    with service.operations:
        records=service.store.all()
        for record in records:service._closed(record)
        captures={}
        for index,record in enumerate(records,1):
            captures[record['id']]=capture_profile(Path(record['_runtime']['profile_path']))
            notify('checking_browser_keys',current=index,total=len(records))
        # Read all old encryption before enabling the new write format.
        bins={name:read_encrypted(root/name,root=root) for name in _BIN_FILES if (root/name).is_file()}
        settings={}
        with service.store.connect() as con:
            settings={key:service.store.unpack(blob) for key,blob in con.execute('SELECT key,value FROM settings')}
        stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
        backup=root/'backups'/('before-portable-'+stamp);backup.mkdir(parents=True,exist_ok=False)
        deadline=time.monotonic()+60
        def bounded(*_):
            if time.monotonic()>deadline:raise TimeoutError()
        with service.store.lock,service.store.connect() as con,closing(sqlite3.connect(backup/'windows.sqlite')) as target:
            con.backup(target,pages=256,progress=bounded,sleep=.05)
            if target.execute('PRAGMA quick_check').fetchone()!=('ok',):raise LocalBrowserError('便携迁移备份校验失败，未启用。')
        for name in _BIN_FILES:
            source=root/name
            if source.is_file():
                dest=backup/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
        notify('backup_created',windows=len(records))
        vault=PortableVault(root).initialize()
        # A durable early marker prevents a deleted vault from silently falling
        # back to a new user key after an interrupted conversion.
        state={'format':1,'key_id':vault.key_id,'created_at':datetime.now(timezone.utc).isoformat(),'state':'converting'}
        write_encrypted(marker,state,root=root)
        for name,value in bins.items():
            if name=='local-source-archive.bin':value=encode_archive(value,root)
            write_encrypted(root/name,value,root=root)
        updated=[]
        for record in records:
            item=copy.deepcopy(record);item['_portable_crypt']=captures[item['id']];item['_portable_app']=str(Path(__file__).resolve().parent)
            updated.append(item)
        with service.store.lock,service.store.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            for record in updated:con.execute('UPDATE profiles SET data=? WHERE id=?',(service.store.pack(record),record['id']))
            for key,value in settings.items():con.execute('UPDATE settings SET value=? WHERE key=?',(service.store.pack(value),key))
        # Runtime identities are transient, not part of a movable user profile.
        write_encrypted(root/'runtime.bin',{},root=root)
        proxy=root/'proxy-runtime'
        if proxy.is_dir():
            for path in proxy.iterdir():
                if path.is_file() and path.suffix in ('.request','.state'):
                    value=read_encrypted(path,root=root)
                    write_encrypted(path,value,root=root)
        state.update(state='ready',windows=len(updated))
        write_encrypted(marker,state,root=root)
        loaded=service.store.all()
        if len(loaded)!=len(records) or any(not r.get('_portable_crypt') for r in loaded):raise LocalBrowserError('便携资料回读检查未完成，请保留备份和文件夹密钥。')
        for item in loaded:service._sync(item)
        notify('portable_ready',windows=len(updated))
        return {'already_portable':False,'windows':len(updated),'folder_encryption':True,'browser_key_maps':len(captures),'backup_created':True}
