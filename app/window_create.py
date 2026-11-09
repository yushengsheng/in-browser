"""Durable local creation queue; reuses authenticated import publication and recovery."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import threading
import uuid

from app_paths import APP_ROOT
from browser_core import sha256
from browser_processes import profile_processes
from creation_fingerprint import creation_defaults,random_fingerprint,validate_profile,build_native,resolve_geo,needs_geo,catalog
from local_state import LocalBrowserError,_dpapi_protect
from portable_browser import capture_profile
from sync_state import WorkerLease
from window_store import now


MAX_CREATE=1000


def _random_resolution(fp):
    choices=catalog()['MobileResolutions'].get(fp['ostype'],['1920x1080','1536x864','1366x768','1440x900','2560x1440'])
    return secrets.choice(choices)


class WindowCreator:
    def __init__(self,service):
        self.service=service;self.store=service.store;self.lock=threading.RLock();self.thread=None
        self.lease=WorkerLease(service.root)
        with self.store.lock,self.store.connect() as con:
            con.execute('CREATE TABLE IF NOT EXISTS creation_jobs (job_id TEXT PRIMARY KEY,digest TEXT NOT NULL,state TEXT NOT NULL,cancel_requested INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL)')
            con.execute('CREATE TABLE IF NOT EXISTS creation_items (job_id TEXT NOT NULL,ordinal INTEGER NOT NULL,source_key TEXT NOT NULL UNIQUE,profile_id TEXT,state TEXT NOT NULL DEFAULT \'pending\',data BLOB,message TEXT NOT NULL DEFAULT \'\',PRIMARY KEY(job_id,ordinal))')
        if self.lease.acquire():
            try:
                with self.store.lock,self.store.connect() as con:
                    con.execute("UPDATE creation_jobs SET state='interrupted' WHERE state='running'")
            finally:self.lease.release()

    def options(self):
        from core_specs import majors
        return {'max_count':MAX_CREATE,'cores':list(majors()),'defaults':creation_defaults(),
                'presets':catalog().get('Presets',[]),'builds':catalog().get('BuildVersions',{}),
                'resolutions':catalog()['MobileResolutions'],'latest':self.latest()}

    def latest(self):
        with self.store.lock,self.store.connect() as con:
            row=con.execute('SELECT job_id FROM creation_jobs ORDER BY rowid DESC LIMIT 1').fetchone()
        return self.status(row[0]) if row else None

    def status(self,job_id,*,missing_ok=False):
        with self.store.lock,self.store.connect() as con:
            row=con.execute('SELECT state,cancel_requested FROM creation_jobs WHERE job_id=?',(job_id,)).fetchone()
            if row is None:
                if missing_ok:return None
                raise LocalBrowserError('创建任务不存在。')
            counts=dict(con.execute('SELECT state,COUNT(*) FROM creation_items WHERE job_id=? GROUP BY state',(job_id,)))
            items=con.execute('SELECT ordinal,profile_id,state,message FROM creation_items WHERE job_id=? AND state IN (\'completed\',\'failed\') ORDER BY ordinal DESC LIMIT 100',(job_id,)).fetchall()[::-1]
        return {'job_id':job_id,'state':row[0],'cancel_requested':bool(row[1]),'total':sum(counts.values()),
            'completed':counts.get('completed',0),'failed':counts.get('failed',0),'pending':counts.get('pending',0),
            'items':[{'index':r[0],'id':r[1],'state':r[2],'message':r[3]} for r in items]}

    def start(self,payload):
        if not getattr(self.service.configuration,'independent',False):
            raise LocalBrowserError('请先完成独立便携初始化，再本地创建窗口。')
        job_id=payload.get('request_id')
        if not isinstance(job_id,str) or not re.fullmatch('[0-9a-f]{32}',job_id):raise LocalBrowserError('创建请求标识无效。')
        count=payload.get('count',1)
        if type(count) is not int or not 1<=count<=MAX_CREATE:raise LocalBrowserError('每批创建数量须为1至1000的整数。')
        profile=validate_profile(payload.get('profile'))
        random_each=payload.get('random_each',True)
        if type(random_each) is not bool:raise LocalBrowserError('批量指纹模式无效。')
        proxy_lines=payload.get('proxy_lines') or []
        if not isinstance(proxy_lines,list) or len(proxy_lines) not in (0,1,count):raise LocalBrowserError('批量代理须为空、1条共用或与创建数量一致。')
        from proxy_config import parse_proxy
        proxies=[parse_proxy(line,profile['proxy']['type'] if profile['proxy']['type']!='noproxy' else 'socks5')['proxy'] for line in proxy_lines]
        digest=hashlib.sha256(json.dumps({'profile':profile,'count':count,'random':random_each,'proxies':proxies},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        with self.lock:
            with self.store.lock,self.store.connect() as con:
                prior=con.execute('SELECT digest FROM creation_jobs WHERE job_id=?',(job_id,)).fetchone()
            if prior:
                if prior[0]!=digest:raise LocalBrowserError('请求标识已用于不同配置；请重新打开创建表单。')
                return self.status(job_id)
            if self.thread and self.thread.is_alive():raise LocalBrowserError('已有创建任务正在运行。')
            if not self.lease.acquire():raise LocalBrowserError('同步、创建或删除正在处理，请稍后重试。')
            try:
                with self.store.lock,self.store.connect() as con:
                    con.execute('BEGIN IMMEDIATE')
                    if con.execute("SELECT 1 FROM creation_jobs WHERE state IN ('running','interrupted','failed')").fetchone():
                        raise LocalBrowserError('请先继续或取消上次创建任务。')
                    con.execute('INSERT INTO creation_jobs(job_id,digest,state,created_at) VALUES (?,?,?,?)',(job_id,digest,'running',now()))
                    common=copy.deepcopy(profile['fingerprint'])
                    generated=random_fingerprint(common)
                    for field in ('canvasValue','webGLValue','audioContextValue','clientRectNoiseValue','computerName','macAddr','hostIP'):
                        if common.get(field) in ('',None):common[field]=generated[field]
                    if not random_each and str(common.get('resolutionType'))=='2':
                        common.update(resolutionType='1',resolution=_random_resolution(common))
                    for index in range(1,count+1):
                        value=copy.deepcopy(profile)
                        value['fingerprint']=random_fingerprint(profile['fingerprint']) if random_each else copy.deepcopy(common)
                        if str(value['fingerprint'].get('resolutionType'))=='2':
                            value['fingerprint'].update(resolutionType='1',resolution=_random_resolution(value['fingerprint']))
                        if count>1:value['name']=(value['name'][:85] or '新窗口')+' '+str(index)
                        if proxies:value['proxy']=copy.deepcopy(proxies[0 if len(proxies)==1 else index-1])
                        key=hashlib.sha256(('local-created-v1:'+job_id+':'+str(index)).encode()).hexdigest()
                        con.execute('INSERT INTO creation_items(job_id,ordinal,source_key,data) VALUES (?,?,?,?)',(job_id,index,key,self.store.pack(value)))
                self._launch(job_id)
            except Exception:self.lease.release();raise
        return self.status(job_id)

    def cancel(self,job_id):
        with self.store.lock,self.store.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            row=con.execute('SELECT state FROM creation_jobs WHERE job_id=?',(job_id,)).fetchone()
            con.execute('UPDATE creation_jobs SET cancel_requested=1 WHERE job_id=?',(job_id,))
            con.execute("UPDATE creation_jobs SET state='cancelled' WHERE job_id=? AND state IN ('interrupted','failed')",(job_id,))
            if row and row[0] in ('interrupted','failed'):
                con.execute("UPDATE creation_items SET state='completed',profile_id=(SELECT profile_id FROM source_bindings WHERE source_key=creation_items.source_key),message='本地独立窗口已创建。' WHERE job_id=? AND EXISTS(SELECT 1 FROM source_bindings WHERE source_key=creation_items.source_key)",(job_id,))
                con.execute('UPDATE creation_items SET data=NULL WHERE job_id=?',(job_id,))
        return self.status(job_id)

    def resume(self,job_id):
        with self.lock:
            if self.thread and self.thread.is_alive():raise LocalBrowserError('创建任务正在运行。')
            if not self.lease.acquire():raise LocalBrowserError('同步、创建或删除正在处理，请稍后重试。')
            try:
                with self.store.lock,self.store.connect() as con:
                    con.execute('BEGIN IMMEDIATE')
                    row=con.execute('SELECT state FROM creation_jobs WHERE job_id=?',(job_id,)).fetchone()
                    if row is None or row[0] not in ('interrupted','failed'):raise LocalBrowserError('该创建任务不能继续。')
                    con.execute("UPDATE creation_items SET state='pending',message='' WHERE job_id=? AND state='failed'",(job_id,))
                    con.execute("UPDATE creation_jobs SET state='running',cancel_requested=0 WHERE job_id=?",(job_id,))
                self._launch(job_id)
            except Exception:self.lease.release();raise
        return self.status(job_id)

    def _launch(self,job_id):
        self.thread=threading.Thread(target=self._run,args=(job_id,),daemon=True,name='local-window-create')
        self.thread.start()

    def _run(self,job_id):
        try:
            helper=self.service.synchronizer()
            executable=None
            while True:
                with self.store.lock,self.store.connect() as con:
                    job=con.execute('SELECT cancel_requested FROM creation_jobs WHERE job_id=?',(job_id,)).fetchone()
                    row=con.execute("SELECT ordinal,source_key,data FROM creation_items WHERE job_id=? AND state='pending' ORDER BY ordinal LIMIT 1",(job_id,)).fetchone()
                if not job or job[0] or not row:break
                index,key,data=row
                try:
                    with self.service.operations:
                        helper._recover_intents(key)
                        identity=self.store.source_binding(key)
                        if not identity:
                            profile=self.store.unpack(data)
                            if executable is None:
                                try:executable=self.service.configuration.local_core(profile['core_version'])
                                except LocalBrowserError as error:
                                    with self.store.lock,self.store.connect() as con:
                                        con.execute("UPDATE creation_items SET state='failed',message=? WHERE job_id=? AND state='pending'",(str(error),job_id))
                                    break
                            identity=self._create(helper,profile,key,executable)
                        with self.store.lock,self.store.connect() as con:
                            con.execute("UPDATE creation_items SET state='completed',profile_id=?,data=NULL,message=? WHERE job_id=? AND ordinal=?",(identity,'本地独立窗口已创建。',job_id,index))
                except Exception as error:
                    message=str(error) if isinstance(error,LocalBrowserError) else '创建未完成；已有窗口已保留，可重试未完成项。'
                    with self.store.lock,self.store.connect() as con:
                        con.execute("UPDATE creation_items SET state='failed',message=? WHERE job_id=? AND ordinal=?",(message,job_id,index))
            with self.store.lock,self.store.connect() as con:
                job=con.execute('SELECT cancel_requested FROM creation_jobs WHERE job_id=?',(job_id,)).fetchone()
                failed=con.execute("SELECT 1 FROM creation_items WHERE job_id=? AND state='failed' LIMIT 1",(job_id,)).fetchone()
                if job:con.execute('UPDATE creation_jobs SET state=? WHERE job_id=?',('cancelled' if job[0] else 'failed' if failed else 'completed',job_id))
                if job and job[0]:con.execute('UPDATE creation_items SET data=NULL WHERE job_id=?',(job_id,))
        except Exception:
            with self.store.lock,self.store.connect() as con:
                con.execute("UPDATE creation_jobs SET state='interrupted' WHERE job_id=?",(job_id,))
        finally:
            with self.lock:self.lease.release()

    def _create(self,helper,profile,key,executable=None):
        from fingerprint_continuity import create_baseline,verify_continuity
        identity='profile-'+uuid.uuid4().hex
        intent=helper.state.intent(uuid.uuid4().hex,key,identity,uuid.uuid4().hex)
        work,final,signature=helper._intent_paths(intent)
        try:
            work.mkdir(parents=True,exist_ok=False)
            with (work/'.sync-owner.bin').open('xb') as output:
                output.write(self.store.pack({'format':1,'ownership':helper.state.validate_intent(intent)}));output.flush();os.fsync(output.fileno())
            staged=work/'profile';(staged/'Default').mkdir(parents=True)
            if profile.get('duplicate_check') and profile.get('username') and any(
                    p.get('username')==profile['username'] and p.get('platform')==profile.get('platform') and not p.get('archived') for p in self.store.all()):
                raise LocalBrowserError('已有相同平台和用户名的本地窗口。')
            with self.store.lock,self.store.connect() as con:seq=con.execute('SELECT COALESCE(MAX(seq),0)+1 FROM profiles').fetchone()[0]
            profile.update(id=identity,seq=seq,created_at=now(),archived=False,last_opened_at=None,config_status='ready',
                launch_verified=False,created_locally=True,_prefs_dirty=True,_empty=False,
                _cookie_pending=bool(profile.get('cookie_text')),_portable_app=str(APP_ROOT),
                _source={'provider':'local-created-v1','source_key':key,'source_id':'new-'+uuid.uuid4().hex,'imported_at':now()})
            if needs_geo(profile['fingerprint']):
                options=profile['created_options']
                if options.get('dynamic_proxy_url'):
                    from dynamic_proxy import fetch_proxy
                    profile['proxy']=fetch_proxy(options['dynamic_proxy_url'],options['dynamic_proxy_type'],profile['proxy'])
                profile['_creation_geo']=resolve_geo(profile['proxy'])
            native,binary=build_native(self.service.configuration,profile)
            signed=work/'fingerprint.bin';signed.write_bytes(binary)
            executable=executable or self.service.configuration.local_core(profile['core_version'])
            from local_signer import LocalSigner
            signer=LocalSigner(self.service.root,load_private=False)
            previous={'alias':identity,'profile_path':str(final),'core_path':str(executable),'core_major':profile['core_version'],
                'core_sha256':sha256(executable),'fingerprint_path':str(signature),'fingerprint_sha256':sha256(signed),
                'signature_provider':'local-v1','signature_key_id':signer.key_id,'new_profile':True,'has_launched':False}
            width=profile['fingerprint'].get('openWidth');height=profile['fingerprint'].get('openHeight')
            if type(width) in (int,float) and type(height) in (int,float) and 320<=width<=16384 and 240<=height<=16384:
                previous['window_size_once']=[width,height]
            profile['_native']=native;profile['_runtime']=self.service._runtime(profile,previous)
            if profile['fingerprint'].get('isIpCreateDisplayLanguage'):profile['_runtime']['language']=native.get('uiLang') or ''
            state={'os_crypt':{'encrypted_key':base64.b64encode(b'DPAPI'+_dpapi_protect(secrets.token_bytes(32))).decode()}}
            (staged/'Local State').write_text(json.dumps(state),encoding='utf-8')
            (staged/'Default/Preferences').write_text('{}',encoding='utf-8')
            profile['_portable_crypt']=capture_profile(staged)
            probe=copy.deepcopy(profile);probe['_runtime'].update(profile_path=str(staged),fingerprint_path=str(signed))
            profile['_continuity']=create_baseline(probe,self.service.root)
            probe['_continuity']=profile['_continuity'];verify_continuity(probe,self.service.root)
            for path in staged.rglob('*'):
                if path.is_file():helper._flush_file(path)
            helper._flush_file(signed)
            intent=helper.state.prepare(intent['intent_id'],profile,self.service._manifest(staged),sha256(signed))
            helper._complete_intent(intent)
            return identity
        except Exception:
            # The existing publication journal decides whether commit already won.
            # Never remove a tree after an uncertain prepared/committed result.
            helper._recover_intents(key)
            bound=self.store.source_binding(key)
            if bound:return bound
            raise
