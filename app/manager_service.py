"""Local window CRUD, real signing, and owned browser lifecycle operations."""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import threading
import time
import uuid

from app_paths import DATA_ROOT
from browser_core import BrowserController,CDP,sha256
from local_state import LocalBrowserError,read_encrypted,write_encrypted
from browser_processes import profile_processes
from configuration import Configuration
from profile_model import defaults,sanitize,parse_cookies
from window_store import WindowStore,now
from engine_store import EngineStore,executable_major
from proxy_runtime import ProxyRuntime
from signature_lifetime import signature_lifetime,require_current_signature,runtime_signature_options


class ManagerService:
    def __init__(self,root=DATA_ROOT,configuration=None,*,portable_recovery=False):
        self.root=Path(root).resolve(); self.root.mkdir(parents=True,exist_ok=True)
        portable_marker=self.root/'portable-mode.bin'
        if portable_marker.is_file() and not portable_recovery:
            portable_state=read_encrypted(portable_marker,root=self.root)
            if portable_state.get('format')!=1 or portable_state.get('state')!='ready':
                raise LocalBrowserError('便携迁移尚未完成，请在原电脑完成恢复后再复制；未启动浏览器或覆盖资料。')
        continuity_marker=self.root/'continuity-mode.bin'
        if continuity_marker.is_file():
            continuity_state=read_encrypted(continuity_marker,root=self.root)
            if continuity_state.get('format')!=1 or continuity_state.get('state')!='ready':
                raise LocalBrowserError('环境连续性基线尚未准备完成，未启动账号窗口。')
        self.configuration=configuration or Configuration(self.root)
        self.store=WindowStore(self.configuration,self.root)
        from portable_paths import relocate
        relocate(self)
        self.engines=EngineStore()
        self.operations=threading.RLock(); self.window=None
        self.controller=BrowserController(self.root,settings={'windows':[p['_runtime'] for p in self.store.all()], 'persistent':False})
        self._synchronizer=None
        self.proxy_runtime=ProxyRuntime(self.root)
        from profile_delete import recover_pending_deletions
        try:recover_pending_deletions(self)
        except (LocalBrowserError,OSError):pass  # The authenticated plan keeps unfinished windows blocked.

    def _require_available(self,identity):
        from profile_delete import is_pending
        if is_pending(self.root,identity):
            raise LocalBrowserError('该窗口的永久删除尚未完成，请重试删除或重启继续清理。')

    def _public(self,p,status='closed',pending=None):
        from profile_delete import get_pending_ids
        data=self.store.public(p,status)
        if p['id'] in (get_pending_ids(self.root) if pending is None else pending):
            data.update(delete_pending=True,config_status='delete_pending')
        return data

    def detail(self,identity):
        with self.operations:
            self._require_available(identity)
            p=self.store.get(identity)
            return self._public(p,self._status(p))

    def activate(self,identity):
        with self.operations:
            self._require_available(identity)
            self.controller.activate(identity)
            return {'activated':True}

    def delete(self,identity):
        from profile_delete import delete_profile
        return delete_profile(self,identity)

    def delete_many(self,identities):
        from profile_delete import delete_profiles
        return delete_profiles(self,identities)

    def synchronizer(self):
        if self._synchronizer is not None:return self._synchronizer
        with self.operations:
            if self._synchronizer is None:
                from window_sync import WindowSynchronizer
                self._synchronizer=WindowSynchronizer(self)
            return self._synchronizer

    def cores(self):
        found={}
        if getattr(self.configuration,'independent',False):
            for p in self.store.all():
                runtime=p['_runtime']
                if runtime.get('signature_provider')=='local-v1' and Path(runtime['core_path']).is_file():found[str(runtime['core_major'])]=runtime['core_path']
            if not found:
                for major in self.configuration.source_archive().get('engines',{}):found[str(major)]=str(self.configuration.local_core(major))
            return found
        folder=self.configuration.vendor_data/'Chrome-bin'
        if folder.exists():
            for major in folder.iterdir():
                if major.is_dir() and major.name.isdigit():
                    builds=[p/'BitBrowser.exe' for p in major.iterdir() if p.is_dir() and (p/'BitBrowser.exe').is_file()]
                    if builds: found[major.name]=str(sorted(builds)[-1])
        for p in self.store.all():
            item=p['_runtime']
            if Path(item['core_path']).is_file(): found[str(item['core_major'])]=item['core_path']
        found.update(self.engines.available())
        return found

    def _sync(self,p): self.controller.profiles[p['id']]=copy.deepcopy(p['_runtime'])

    def _status(self,p,values=None):
        value=self.controller.status(p['id']) if values is None else values[p['id']]
        return {'已打开':'open','未打开':'closed','启动未完成':'opening','已在其他进程打开':'open','正在关闭':'closing'}.get(value,'closed')

    def statuses(self):
        from profile_delete import get_pending_ids
        pending=get_pending_ids(self.root)
        rows=[];profiles=self.store.all()
        values=self.controller.statuses(p['id'] for p in profiles)
        for p in profiles:
            status=self._status(p,values)
            lifetime=signature_lifetime(p['_runtime']['fingerprint_path'])
            rows.append({'id':p['id'],'status':status,'is_running':status=='open','last_opened_at':p.get('last_opened_at'),
                'signature_status':lifetime['status'],'signature_expires_at':lifetime.get('expires_at'),'signature_provider':p['_runtime'].get('signature_provider','vendor'),
                'config_status':'expired' if lifetime['status']=='expired' else p.get('config_status','ready')})
            if p['id'] in pending:rows[-1].update(delete_pending=True,config_status='delete_pending')
        return {'profiles':rows}

    def listing(self):
        from profile_delete import get_pending_ids
        pending=get_pending_ids(self.root)
        rows=self.store.all()
        values=self.controller.statuses(p['id'] for p in rows)
        return {'profiles':[self._public(p,self._status(p,values),pending) for p in rows],
                'groups':self.store.setting('groups',[]),'tags':sorted({t for p in rows for t in p.get('tags',[])})}

    def bootstrap(self):
        from core_specs import CORE_SPECS
        data=self.listing(); cores=self.cores()
        default=defaults('148' if '148' in cores else next(iter(cores),'148'))
        data.update(cores=sorted(cores,key=int),defaults=default,settings=self.settings(),
            capabilities={'signature_required':True,'signing_online':not self.configuration.independent,'signature_has_expiry':True,'signature_verified_core_majors':sorted(CORE_SPECS,key=int),'permanent_offline_confirmed':self.configuration.independent,'independent_runtime':self.configuration.independent,'portable_mode':(self.root/'portable-mode.bin').is_file(),'environment_continuity':(self.root/'continuity-mode.bin').is_file(),'encryption_provider':'folder-key' if (self.root/'portable-mode.bin').is_file() else 'windows-user','proxy_edit_requires_signing':False,'proxy_routing':'local','local_storage_only':True,'create':False,'sync_windows':True,
                          'proxy_types':['noproxy','http','https','socks5'],'native_version':'7.2.0',
                          'bundled_cores':sorted(cores if self.configuration.independent else self.engines.available(),key=int),'strict_proxy_gate':True})
        data['sync_job']=self.synchronizer().latest()
        return data

    def settings(self):
        base={'start_page':'','download_dir':'','browser_path':'','confirm_close':True,'close_behavior':'keep_browsers'}
        base.update(self.store.setting('application',{})); return base

    def _closed(self,p):
        if profile_processes(Path(p['_runtime']['profile_path'])):
            raise LocalBrowserError('请先正常关闭该窗口，再修改代理或指纹配置。')

    def _runtime(self,p,previous=None):
        fp=p['fingerprint']; settings=self.settings(); core=str(fp['coreVersion'])
        local=(previous or {}).get('signature_provider')=='local-v1' or getattr(self.configuration,'independent',False)
        if local:
            from local_engine import LocalEngineStore
            from local_signer import LocalSigner
            signer=LocalSigner(self.root,load_private=False)
            bundled=LocalEngineStore().validate(previous['core_path'],signer.key_id,core) if previous and previous.get('signature_provider')=='local-v1' else self.configuration.local_core(core)
        else:
            path=self.cores().get(core)
            if not path:raise LocalBrowserError('所选内核未在本机部署。')
            executable=Path(path)
            if previous and str(previous.get('core_major'))==core:
                pinned=Path(previous['core_path'])
                if pinned.resolve().is_relative_to(self.engines.root) and (not settings['browser_path'] or not Path(settings['browser_path']).is_file()):executable=pinned
            if settings['browser_path']:
                selected=Path(settings['browser_path'])
                if selected.is_file():
                    if selected.name.casefold()!='bitbrowser.exe':raise LocalBrowserError('请选择比特内核可执行文件作为部署来源。')
                    if executable_major(selected)!=core: raise LocalBrowserError('手动内核版本与窗口配置不同，请清空手动路径或选择匹配版本。')
                    executable=selected
                elif not executable.resolve().is_relative_to(self.engines.root):raise LocalBrowserError('内核导入来源不存在，并且本地尚未部署对应版本。')
            bundled=self.engines.install(core,executable)
        running_previous=previous and str(previous.get('core_major'))==core and profile_processes(Path(previous['profile_path']))
        # An upgrade may encounter a still-running instance from the old path.
        # Keep its identity until it exits; the next launch uses our local copy.
        executable=Path(previous['core_path']) if running_previous else bundled
        same_core=previous and os.path.normcase(str(executable))==os.path.normcase(previous['core_path'])
        if not same_core and executable_major(executable)!=core: raise LocalBrowserError('已安装内核的实际版本与所选配置不匹配。')
        launch_args=[part.strip() for part in re.split(r'[\r\n]+|,\s*(?=--)',str(fp.get('launchArgs') or '')) if part.strip()]
        from browser_policy import validate_launch_args
        validate_launch_args(launch_args,proxy_active=True)
        runtime=copy.deepcopy(previous) if previous else {'alias':p['id'],'profile_path':str(self.root/'profiles'/p['id']),'new_profile':True,'has_launched':False}
        if local:runtime.update(signature_provider='local-v1',signature_key_id=signer.key_id)
        runtime.update(name=p['name'],core_path=str(executable),core_sha256=previous['core_sha256'] if same_core else sha256(executable),core_major=core,
            language=str(fp.get('displayLanguages') or ''),initial_urls=p['urls'] or ([settings['start_page']] if settings['start_page'] else []),restore_session=p['preferences'].get('restore_session',True),
            launch_args=launch_args,no_system_proxy=True,account_platform=p.get('platform') or '',
            account_username=p.get('username') or '',account_password=p.get('password') or '')
        for key in ['mute_audio','disable_gpu','disable_notifications']: runtime[key]=p['preferences'].get(key,False)
        return runtime

    def save(self,incoming,*,allow_fingerprint=True):
        with self.operations:
            if not isinstance(incoming,dict):raise LocalBrowserError('窗口配置格式不正确。')
            if not incoming.get('id'):raise LocalBrowserError('仅支持编辑已导入的窗口；新增来源须具备完整本地迁移配置和资料。')
            self._require_available(incoming['id'])
            old=self.store.get(incoming['id'])
            if old.get('archived'): raise LocalBrowserError('请先从回收站恢复该窗口。')
            p=sanitize(incoming,old)
            # Imported fields may use numeric strings or spaced resolutions.
            # Normalization alone must not turn a metadata edit into re-signing.
            baseline=sanitize(self.store.public(old))
            for key in ['fingerprint','proxy','preferences']:
                candidate=sanitize({key:p[key]})[key]
                if candidate==baseline[key]: p[key]=copy.deepcopy(old[key])
            if not allow_fingerprint and p['fingerprint']!=old['fingerprint']:raise LocalBrowserError('此版本的指纹配置只读，不能在本地更换。')
            p['name']=p['name'].strip() or '窗口 '+str(p['seq'])
            cookies=parse_cookies(p.get('cookie_text',''),p)
            if p.get('duplicate_check') and p.get('username'):
                if any(x['id']!=p['id'] and not x.get('archived') and x.get('platform')==p.get('platform') and x.get('username')==p.get('username') for x in self.store.all()):
                    raise LocalBrowserError('已有相同平台和用户名的本地窗口。')
            needs_config=any(p.get(k)!=old.get(k) for k in ['fingerprint','preferences'])
            if old['_runtime'].get('signature_provider')=='local-v1' and p['fingerprint']!=old['fingerprint']:
                raise LocalBrowserError('独立本地窗口保留迁移时的原指纹，不重新生成或更换指纹。')
            proxy_changed=p['proxy']!=old['proxy']
            if p['proxy'].get('enable_socks5_udp'):raise LocalBrowserError('本地独立代理目前支持TCP，不支持SOCKS5 UDP；请关闭UDP选项。')
            if needs_config or proxy_changed: self._closed(old)
            if proxy_changed:self.proxy_runtime.stop_if_unused(p['id'])
            if p.get('cookie_text')!=old.get('cookie_text'): self._closed(old)
            if int(p['core_version'])<int(old['core_version']): raise LocalBrowserError('已有资料不能降级内核，原有资料和配置已保留。')
            runtime=self._runtime(p,old.get('_runtime'))
            if any(p['fingerprint'].get(k)!=old['fingerprint'].get(k) for k in ['openWidth','openHeight']):
                runtime['window_size_once']=[p['fingerprint'].get('openWidth') or 1280,p['fingerprint'].get('openHeight') or 720]
            if p['urls']!=old.get('urls'): runtime['open_urls_once']=p['urls']
            new_file=None; temporary=None
            try:
                if needs_config:
                    if runtime.get('signature_provider')=='local-v1':native,binary=self.configuration.build_local(p,p['_native'],previous_preferences=old.get('preferences'))
                    else:native,binary=self.configuration.build(p,p['_native'],empty=bool(p.get('_empty')))
                    folder=self.root/'fingerprints'; folder.mkdir(exist_ok=True)
                    new_file=folder/(p['id']+'-'+uuid.uuid4().hex+'.bin')
                    temporary=new_file.with_suffix('.tmp')
                    with temporary.open('wb') as output: output.write(binary); output.flush(); os.fsync(output.fileno())
                    os.replace(temporary,new_file)
                    runtime.update(fingerprint_path=str(new_file),fingerprint_sha256=sha256(new_file))
                    p['_native']=native; p['_prefs_dirty']=True; p['launch_verified']=False
                if old['core_version']!=p['core_version']:
                    self._copy_profile(Path(old['_runtime']['profile_path']),self.root/'backups'/(p['id']+'-'+uuid.uuid4().hex))
                if p.get('cookie_text')!=old.get('cookie_text'): p['_cookie_pending']=bool(cookies)
                p.update(_runtime=runtime,_empty=False,config_status='ready',updated_at=now())
                if proxy_changed:
                    runtime.pop('local_proxy_port',None)
                self.store.put(p,include_group=True)
            except Exception:
                if new_file and new_file.parent.resolve()==(self.root/'fingerprints').resolve(): new_file.unlink(missing_ok=True)
                if temporary: temporary.unlink(missing_ok=True)
                raise
            self._sync(p)
            return self.store.public(p,self._status(p))

    @staticmethod
    def _manifest(folder):
        return {str(p.relative_to(folder)):sha256(p) for p in folder.rglob('*') if p.is_file()}

    def _copy_profile(self,source,target):
        if profile_processes(source): raise LocalBrowserError('请先正常关闭要复制的窗口。')
        files=list(source.rglob('*'))
        if any(p.is_symlink() or getattr(p.lstat(),'st_file_attributes',0)&0x400 for p in files): raise LocalBrowserError('资料包含特殊链接，已停止复制。')
        total=sum(p.stat().st_size for p in files if p.is_file())
        target.parent.mkdir(parents=True,exist_ok=True)
        if shutil.disk_usage(target.parent).free<total*1.1+20_000_000: raise LocalBrowserError('磁盘空间不足，未复制或修改资料。')
        before=self._manifest(source); temporary=target.with_name(target.name+'.copying')
        if temporary.exists() or target.exists(): raise LocalBrowserError('复制目标已存在，未覆盖。')
        try:
            for attempt in range(3):
                try:
                    shutil.copytree(source,temporary)
                    break
                except PermissionError:
                    # Virus scanners/indexers can briefly hold a newly created
                    # directory on Windows. Only retry our unpublished copy.
                    if temporary.exists() and temporary.resolve().parent==target.resolve().parent:shutil.rmtree(temporary)
                    if attempt==2:raise
                    time.sleep(.15*(attempt+1))
            if before!=self._manifest(source) or before!=self._manifest(temporary): raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')
            for attempt in range(3):
                try:
                    os.replace(temporary,target)
                    break
                except PermissionError:
                    if attempt==2:raise
                    time.sleep(.15*(attempt+1))
        except Exception:
            if temporary.exists() and temporary.resolve().parent==target.resolve().parent: shutil.rmtree(temporary)
            raise

    def _preferences(self,p):
        from profile_preferences import apply_preferences
        return apply_preferences(self,p)

    def open(self,identity,*,offline_test=False,extra_urls=None):
        with self.operations:
            self._require_available(identity)
            p=self.store.get(identity)
            if p.get('archived'): raise LocalBrowserError('请先恢复回收站中的窗口。')
            already=self._status(p)=='open'
            if self._status(p)=='closing':raise LocalBrowserError('窗口正在正常保存并退出，请稍候再打开。')
            if not already and (getattr(self.configuration,'independent',False) or p['_runtime'].get('signature_provider')=='local-v1'):
                from local_runtime import LocalRuntime
                p=LocalRuntime(self).prepare(p)
            if not already and (self.root/'continuity-mode.bin').is_file():
                from fingerprint_continuity import verify_continuity
                verify_continuity(p,self.root)
            if not already and (self.root/'portable-mode.bin').is_file():
                from portable_browser import prepare_profile
                if not p.get('_portable_crypt'):raise LocalBrowserError('此窗口尚未准备便携加密资料，未启动，避免丢失登录数据。')
                prepare_profile(Path(p['_runtime']['profile_path']),p['_portable_crypt'])
            if not already:require_current_signature(p['_runtime']['fingerprint_path'],core_major=p['_runtime'].get('core_major'),**runtime_signature_options(p['_runtime'],self.root))
            def before_launch():
                if already:
                    raise LocalBrowserError('窗口刚刚退出，请重新点击打开，以完成新窗口的环境和代理检查；本次未重新启动。')
                if not offline_test and p['proxy']['type']!='noproxy':
                    if not route or not self.proxy_runtime.owned(route) or not self.proxy_runtime.control(route):
                        raise LocalBrowserError('本地代理未就绪，未启动浏览器，也未改为直连。')
                    # Test the exact relay the browser will use, including its
                    # authenticated upstream, rather than a separate shortcut.
                    checked=self.configuration.proxy_test({'type':'http','host':'127.0.0.1','port':route['port'],'username':'','password':''})
                    if not checked.get('success'):raise LocalBrowserError('代理检测未通过，未启动浏览器。'+checked.get('message',''))
                    if not self.proxy_runtime.owned(route) or not self.proxy_runtime.control(route):
                        raise LocalBrowserError('本地代理在检测期间退出，未启动浏览器，也未改为直连。')
            if not already:
                p['_runtime']=self._runtime(p,p['_runtime']); self._sync(p)
                self._preferences(p)
            bootstrap_blank=bool(p.get('_cookie_pending') and p['_runtime'].get('new_profile') and not p['_runtime'].get('has_launched'))
            route=None
            try:
                if not offline_test and (not already or p['proxy']['type']!='noproxy' or p['_runtime'].get('local_proxy_mode')=='local'):
                    route=self.proxy_runtime.ensure(p)
                    if not already:
                        p['_runtime']['local_proxy_mode']='local' if route else 'direct'
                        if route:p['_runtime']['local_proxy_port']=route['port']
                        else:p['_runtime'].pop('local_proxy_port',None)
                        self._sync(p)
                self.controller.open(identity,offline_test=offline_test,extra_urls=extra_urls,bootstrap_blank=bootstrap_blank,before_launch=before_launch)
            except Exception:
                if not profile_processes(Path(p['_runtime']['profile_path'])):self.proxy_runtime.stop_if_unused(identity)
                raise
            try:
                if p.get('_cookie_pending'):
                    with CDP(self.controller.endpoint(identity)) as connection:
                        sessions=[]
                        for target in connection.call('Target.getTargets').get('targetInfos',[]):
                            if target.get('type')=='page' and target.get('url','').startswith(('http://','https://')):
                                session=connection.call('Target.attachToTarget',{'targetId':target['targetId'],'flatten':True})['sessionId']
                                connection.call('Page.stopLoading',session=session); sessions.append(session)
                        connection.call('Storage.setCookies',{'cookies':parse_cookies(p['cookie_text'],p)})
                        for session in sessions: connection.call('Page.reload',{'ignoreCache':True},session=session)
                        if bootstrap_blank:
                            targets=connection.call('Target.getTargets').get('targetInfos',[])
                            blank=next((t for t in targets if t.get('type')=='page' and t.get('url')=='about:blank'),None)
                            urls=list(extra_urls) if extra_urls is not None else p['_runtime'].get('initial_urls',[])
                            for index,url in enumerate(urls):
                                if index==0 and blank:
                                    session=connection.call('Target.attachToTarget',{'targetId':blank['targetId'],'flatten':True})['sessionId']
                                    connection.call('Page.navigate',{'url':url},session=session)
                                else: connection.call('Target.createTarget',{'url':url})
                    p['_cookie_pending']=False
                if not already: p['last_opened_at']=now()
                p['launch_verified']=True; p['_runtime']['new_profile']=False; p['_runtime']['has_launched']=True
                p['_runtime'].pop('window_size_once',None); p['_runtime'].pop('open_urls_once',None)
                self.store.put(p); self._sync(p)
            except Exception:
                if not already:
                    try: self.controller.close(identity)
                    except Exception: pass
                raise
            if not already and not offline_test:
                from ip_info_page import show_ip_info
                try:
                    with CDP(self.controller.endpoint(identity),timeout=5) as connection:show_ip_info(connection)
                except Exception:
                    raise LocalBrowserError('浏览器已打开，但IP信息页未能打开；请手动访问 https://ifconfig.co/ 查看当前出口。原有资料和代理保持不变。') from None
            return self.store.public(p,'open')

    def close(self,identity):
        with self.operations:
            self.controller.close(identity)
            self.proxy_runtime.stop_if_unused(identity)
            return self.store.public(self.store.get(identity),'closed')

    def archive(self,identity,restore=False):
        with self.operations:
            self._require_available(identity)
            p=self.store.get(identity)
            if not restore: self._closed(p)
            p['archived']=not restore; self.store.put(p); return self.store.public(p)

    def groups_save(self,payload):
        with self.operations,self.store.lock,self.store.connect() as con:
            groups=list(dict.fromkeys(str(g).strip()[:100] for g in payload.get('groups',[]) if str(g).strip()))
            if len(groups)>500: raise LocalBrowserError('分组数量过多。')
            renames=payload.get('renames') or {}
            rows=con.execute('SELECT id,data FROM profiles').fetchall()
            for identity,blob in rows:
                p=self.store.unpack(blob); old=p.get('group',''); new=renames.get(old,old)
                if new not in groups: new=''
                if old!=new:
                    p['group']=new
                    con.execute('UPDATE profiles SET data=? WHERE id=?',(self.store.pack(p),identity))
            con.execute('INSERT OR REPLACE INTO settings VALUES (?,?)',('groups',self.store.pack(groups)))
            return {'groups':groups}

    def export_profiles(self,payload):
        import webview
        if not self.window: raise LocalBrowserError('请在桌面界面选择导出位置。')
        selected=set(payload.get('ids') or [])
        rows=[p for p in self.store.all() if not selected or p['id'] in selected]
        target=self.window.create_file_dialog(webview.FileDialog.SAVE,save_filename='本地窗口配置.localprofiles',file_types=('本地加密配置 (*.localprofiles)',))
        if not target: return {'cancelled':True}
        file=Path(target[0] if isinstance(target,(tuple,list)) else target)
        write_encrypted(file,{'format':'local-profiles-1','profiles':rows})
        return {'message':'配置已加密导出到本机文件；浏览器资料目录未打包。'}

    def request(self,action,payload=None):
        from api import dispatch
        return dispatch(self,action,payload)
