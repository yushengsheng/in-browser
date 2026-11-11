"""Add-only, verified snapshots of local BitBrowser windows; never mirror deletes."""
import copy
import hashlib
from itertools import chain
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
import traceback
import uuid
from urllib.parse import unquote

from bit_source import BitSource
from app_paths import APP_ROOT
from local_state import LocalBrowserError,read_encrypted
from browser_processes import profile_processes
from browser_core import sha256
from profile_model import defaults,PREFERENCES,sanitize,fingerprint_fields
from proxy_config import normalize_proxy
from window_store import now,source_time
from sync_state import SyncState,WorkerLease

MAX_SYNC_SOURCES=9999
SYNC_PREVIEW_TTL=600
_INTERNAL_START=object()


def source_key(identity):
    return hashlib.sha256(('bitbrowser-local-v1:'+str(identity).lower()).encode()).hexdigest()


def _source_tags(info):
    output=[]
    for field in ['tags','browserTags','browserTagRelVo']:
        values=info.get(field) or []
        if not isinstance(values,list):continue
        for value in values:
            if isinstance(value,str):name=value
            elif isinstance(value,dict):
                nested=value.get('browserTag')
                name=value.get('name') or value.get('tagName') or (nested.get('name') if isinstance(nested,dict) else None)
            else:continue
            if name and str(name) not in output:output.append(str(name))
    return output


class WindowSynchronizer:
    def __init__(self,service,provider=None):
        from profile_delete import get_pending_ids
        self.service=service;self.provider=provider or BitSource(service.configuration)
        self.lock=threading.RLock();self.candidates={};self.active=None;self.diagnostics={}
        self.preview_id=None;self.preview_created=0;self.confirmed_jobs={}
        self.state=SyncState(service.store);self.lease=WorkerLease(service.root);self._job_item=None
        if self.lease.acquire():
            try:
                self.state.interrupt_running()
                if not get_pending_ids(service.root):self._recover_intents()
            finally:self.lease.release()
        if not get_pending_ids(service.root):self._bind_legacy()

    def _require_delete_finished(self):
        from profile_delete import get_pending_ids
        if get_pending_ids(self.service.root):
            raise LocalBrowserError('永久删除清理尚未完成，请先重试删除或重启继续清理，再同步来源窗口。')

    def _bind_legacy(self):
        # One-time adoption of the two explicitly imported historical profiles.
        # The old snapshot is optional; every new sync records origin in SQLite.
        snapshot=APP_ROOT.parent/'analysis/private-bootstrap/selected-settings.bin'
        if not snapshot.is_file():return
        try:items=read_encrypted(snapshot)
        except Exception:return
        for item in items:
            alias=item.get('alias');info=item.get('info') or {};identity=info.get('id')
            if alias not in ['window-1','window-2'] or not re.fullmatch(r'[A-Fa-f0-9]{32}',str(identity or '')):continue
            try:record=self.service.store.get(alias)
            except LocalBrowserError:continue
            if record.get('_source') or record.get('seq')!=info.get('seq'):continue
            key=source_key(identity)
            self.service.store.bind_existing(alias,key,{'provider':'bitbrowser-local-v1','source_key':key,'source_id':identity,'imported_at':now(),'legacy':True})

    def _discover(self):
        candidates=self.provider.discover();unique={};conflicts=set()
        for candidate in candidates:
            key=candidate['source_key']
            if key in unique and unique[key]!=candidate:conflicts.add(key)
            else:unique[key]=candidate
        for key in conflicts:
            unique[key]=dict(unique[key],status='unsupported',reason='同一来源标识出现冲突，未选择或覆盖任何资料。')
        return unique,conflicts

    def preview(self):
        with self.lock:
            if getattr(self,'worker',None) is not None and self.worker.is_alive():
                raise LocalBrowserError('同步任务正在处理，请先查看当前进度。')
            self.preview_id=None;self.candidates={}
            unique,conflicts=self._discover();items=[]
            bindings=self.service.store.source_bindings()
            self.candidates=unique
            for candidate in unique.values():
                info=candidate.get('info') or {};fp=info.get('browserFingerPrint') or {};key=candidate['source_key']
                bound=key in bindings and key not in conflicts
                status='already_imported' if bound and key not in conflicts else candidate['status']
                items.append({'source_key':key,'name':str(info.get('name') or '本机资料窗口'),'seq':info.get('seq'),
                    'os':fp.get('os') or info.get('os') or '', 'core_version':str(fp.get('coreVersion') or info.get('coreVersion') or ''),
                    'created_at':source_time(info.get('createdTime')),'status':status,
                    'reason':'已保留独立本地副本，本次跳过，不覆盖现有资料。' if bound else candidate.get('reason'),
                    'has_local_data':candidate['status'] in ['ready','source_open']})
            self.preview_id=secrets.token_hex(16);self.preview_created=time.monotonic()
            return {'preview_id':self.preview_id,'expires_in':SYNC_PREVIEW_TTL,'items':items,
                    'counts':{key:sum(p['status']==key for p in items) for key in ['ready','already_imported','source_open','missing_data','unsupported']}}

    def _confirm_preview(self,keys,preview_id):
        if not isinstance(preview_id,str) or not preview_id:
            raise LocalBrowserError('请先检测可同步窗口，再点击开始同步。')
        if not isinstance(keys,list) or any(not isinstance(key,str) for key in keys):
            raise LocalBrowserError('同步来源选择格式无效。')
        selected=tuple(dict.fromkeys(keys))
        if not selected or len(selected)>MAX_SYNC_SOURCES:
            raise LocalBrowserError('请选择1至9999个已检测的窗口，再开始同步。')
        previous=self.confirmed_jobs.get(preview_id)
        if previous:
            if frozenset(selected)!=previous['keys']:
                raise LocalBrowserError('本次检测已开始同步，请重新检测后选择窗口。')
            return {'job_id':previous['job_id']}
        if preview_id!=self.preview_id or time.monotonic()-self.preview_created>SYNC_PREVIEW_TTL:
            raise LocalBrowserError('检测结果已过期，请重新检测可同步窗口。')
        if any(key not in self.candidates or self.candidates[key]['status']!='ready' for key in selected):
            raise LocalBrowserError('所选来源不在可同步检测结果内，请重新检测。')
        fresh,conflicts=self._discover()
        bindings=self.service.store.source_bindings()
        if any(key in conflicts or key in bindings or fresh.get(key)!=self.candidates[key] for key in selected):
            self.preview_id=None
            raise LocalBrowserError('来源资料、位置或同步状态已变化，请重新检测；尚未开始复制。')
        return None

    def start(self,keys=None,*,preview_id=_INTERNAL_START):
        with self.lock:
            self._require_delete_finished()
            if preview_id is not _INTERNAL_START:
                existing=self._confirm_preview(keys,preview_id)
                if existing:return existing
            if getattr(self,'worker',None) is not None and self.worker.is_alive():return {'job_id':self.active}
            if keys is not None and (not isinstance(keys,list) or any(not isinstance(key,str) for key in keys)):
                raise LocalBrowserError('同步来源选择格式无效。')
            if not self.candidates:self.preview()
            selected=list(dict.fromkeys(keys if keys is not None else [k for k,c in self.candidates.items() if c['status']=='ready']))
            if any(key not in self.candidates for key in selected):raise LocalBrowserError('来源列表已失效，请重新读取本机窗口。')
            if len(selected)>MAX_SYNC_SOURCES:raise LocalBrowserError('一次最多同步9999个本机窗口，请分批操作。')
            if not self.lease.acquire():
                latest=self.state.latest()
                if latest and latest['state']=='running':return {'job_id':latest['job_id']}
                raise LocalBrowserError('另一个管理器正在恢复同步，请稍后重试。')
            identity=uuid.uuid4().hex
            try:
                self._require_delete_finished()
                self.state.interrupt_running()
                self.state.create(identity,(self.candidates[key] for key in selected))
                self._launch(identity)
                if preview_id is not _INTERNAL_START:
                    self.confirmed_jobs[preview_id]={'keys':frozenset(selected),'job_id':identity}
                    for previous in list(self.confirmed_jobs)[:-8]:self.confirmed_jobs.pop(previous,None)
            except Exception:
                self.lease.release();raise
            return {'job_id':identity}

    def _launch(self,identity):
        self.active=identity;self.diagnostics[identity]=[]
        for previous in list(self.diagnostics)[:-8]:self.diagnostics.pop(previous,None)
        self.worker=threading.Thread(target=self._run,args=(identity,),name='local-window-sync',daemon=True)
        self.worker.start()

    def latest(self):return self.state.latest()

    def status(self,identity,*,after=None,missing_ok=False):return self.state.status(identity,after=after,missing_ok=missing_ok)

    def resume(self,identity):
        with self.lock:
            self._require_delete_finished()
            if getattr(self,'worker',None) is not None and self.worker.is_alive():
                raise LocalBrowserError('同步任务正在处理，请等待当前任务完成。')
            if not self.lease.acquire():raise LocalBrowserError('另一个同步任务正在处理，请稍后重试。')
            try:
                self._require_delete_finished()
                self.state.interrupt_running();self._recover_intents();self.state.resume(identity);self._launch(identity)
            except Exception:self.lease.release();raise
        return {'job_id':identity}

    def cancel(self,identity):
        self.state.cancel(identity)
        return {'requested':True}

    def _update(self,identity,**values):
        self.state.update(identity,**values)

    def _run(self,identity):
        try:
            for index,candidate in self.state.pending(identity):
                if self.state.cancelled(identity):
                    self._update(identity,state='cancelled',phase='finished');return
                self.state.begin_item(identity,index);self._job_item=(identity,index)
                key=candidate['source_key'];result={'source_key':key}
                try:
                    with self.service.operations:
                        if self.service.store.source_binding(key):result.update(status='skipped',message='该来源已经同步，保留原有副本。')
                        elif candidate['status']!='ready':result.update(status='skipped',message=candidate.get('reason') or '来源尚未准备好。')
                        else:
                            imported=self._import(candidate,lambda phase:self._update(identity,phase=phase))
                            result.update(status='skipped' if imported is False else 'completed',message='该来源已经同步，保留原有副本。' if imported is False else '完整独立副本已保存。')
                except LocalBrowserError as exc:result.update(status='failed',message=str(exc))
                except Exception as exc:
                    # Developer diagnostics contain only source-code locations,
                    # never exception text, paths, account fields or credentials.
                    self.diagnostics[identity].append({'type':type(exc).__name__,'errno':getattr(exc,'errno',None),'winerror':getattr(exc,'winerror',None),
                        'frames':[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(exc.__traceback__)]})
                    self.diagnostics[identity]=self.diagnostics[identity][-100:]
                    result.update(status='failed',message='本次同步未完成，来源和已有本地窗口未修改。请检查磁盘、文件占用或授权。')
                self.state.finish_item(identity,index,result['status'],result['message'])
                self._job_item=None
            self._update(identity,state='completed',phase='finished')
        except Exception:
            try:self._update(identity,state='interrupted',phase='finished',message='同步任务中止，已完成的副本仍保留，可继续剩余项。')
            except Exception:pass
        finally:
            with self.lock:self._job_item=None;self.lease.release()

    def _startup(self,candidate):
        from local_source import source_protection
        startup=self.provider.startup(candidate);full=startup['info'];fp=full['browserFingerPrint'];protection=source_protection(fp)
        proxy=normalize_proxy({'type':full.get('proxyType') or 'noproxy','host':full.get('host') or '', 'port':full.get('port') or '',
            'username':full.get('proxyUserName') or '', 'password':full.get('proxyPassword') or '', 'enable_socks5_udp':bool(full.get('enableSocks5Udp'))})
        # A leftover LocalCache may predate a fingerprint edit. Source identity,
        # proxy and protection-key equality alone cannot prove all fields match.
        native,binary=self.service.configuration.build_source(full)
        if native.get('DataProtect')!=protection:raise LocalBrowserError('启动文件与来源资料的保护参数不一致，未提交副本。')
        if (native.get('FontConfig') or {}).get('Files'):raise LocalBrowserError('来源使用当前内核未验证的额外字体文件，不能将其标记为完整可用；来源未修改。')
        if str(fp.get('coreVersion'))!=str(candidate.get('_core_major') or fp.get('coreVersion')):raise LocalBrowserError('来源内核配置已变化，请重新读取。')
        return startup,native,binary,proxy

    def _extensions(self,source,staged,final):
        """Rebase extension filesystem references; never enable vendor cloud sync."""
        from extension_portability import verify_secure_extension_paths
        verify_secure_extension_paths(staged)
        path=staged/'Default/Preferences'
        try:data=json.loads(path.read_text(encoding='utf-8-sig'))
        except Exception:raise LocalBrowserError('来源浏览器偏好文件无法完整读取，未提交副本。') from None
        changed=False;notes=[]
        for entry in (data.get('extensions',{}).get('settings',{}) or {}).values():
            if not isinstance(entry,dict):continue
            raw=entry.get('path')
            if not isinstance(raw,str) or not raw:continue
            original=Path(raw)
            if not original.is_absolute():continue
            if original.resolve().is_relative_to(source.resolve()):
                entry['path']=str(final/original.resolve().relative_to(source.resolve()));changed=True;continue
            if original.name.casefold()=='bithelper':
                entry['state']=0;entry['disable_reasons']=[1];changed=True;notes.append('原厂云同步助手保持禁用，原扩展资料保留。')
            if not original.is_dir() or not (original/'manifest.json').is_file():
                if entry.get('state')==1:raise LocalBrowserError('来源启用的外部扩展文件不完整，未提交副本。')
                continue
            if str(original).startswith('\\\\'):raise LocalBrowserError('来源依赖网络共享扩展，尚不能作为完整本地副本同步。')
            manifest=self.service._manifest(original)
            digest=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
            asset=self.service.root/'assets/extensions'/digest
            if not asset.exists():self.service._copy_profile(original,asset)
            if self.service._manifest(asset)!=manifest:raise LocalBrowserError('扩展资源复制校验失败，未提交副本。')
            entry['path']=str(asset);changed=True
        if changed:
            temporary=path.with_suffix('.sync-tmp')
            with temporary.open('w',encoding='utf-8') as output:json.dump(data,output,ensure_ascii=False);output.flush();os.fsync(output.fileno())
            os.replace(temporary,path)
        return notes

    def _record(self,candidate,full,native,proxy,identity,final,config_path,manifest,notes,engine_path=None,*,fingerprint_hash=None):
        detail=candidate.get('info') or {};info=copy.deepcopy(full);info.update(detail)
        rawfp={k:copy.deepcopy(v) for k,v in full['browserFingerPrint'].items() if k in fingerprint_fields()}
        core=str(rawfp['coreVersion']);record=defaults(core);record['fingerprint'].update(rawfp)
        nav=native.get('navigator') or {}
        record['fingerprint'].update(os=rawfp.get('os') or nav.get('platform') or 'Win32')
        source_created=source_time(info.get('createdTime'));created=source_created or now();opened=source_time(info.get('operTime'))
        record.update(id=identity,seq=0,name=str(info.get('name') or ('窗口 '+str(info.get('seq') or ''))),remark=str(info.get('remark') or ''),
            group=str(info.get('groupName') or ''),tags=_source_tags(info),created_at=created,last_opened_at=opened,source_seq=info.get('seq'),
            source_created_at=source_created,source_last_opened_at=opened,imported_at=now(),os=record['fingerprint']['os'],core_version=core,
            proxy=proxy,platform=str(info.get('platform') or ''),username=str(info.get('userName') or ''),password=str(info.get('password') or ''),
            fa_secret=str(info.get('faSecretKey') or ''),cookie_text='',archived=False,allow_multi_open=bool(info.get('isSynOpen',1)),duplicate_check=False,
            config_status='ready',launch_verified=False,import_notes=notes)
        urls=info.get('url') or []
        if isinstance(urls,str):
            decoded=[]
            for value in urls.split(','):
                try:value=unquote(value,errors='strict')
                except UnicodeError:raise LocalBrowserError('来源启动网址编码无效，未提交副本。') from None
                decoded.extend(re.split(r',(?=(?:https?|chrome|chrome-extension|about|file):)',value.strip()))
            urls=[value for value in decoded if value]
        record['urls']=sanitize({'urls':urls if isinstance(urls,list) else []})['urls']
        prefs=dict(PREFERENCES)
        for dest,origin in [('mute_audio','muteAudio'),('disable_gpu','disableGpu'),('disable_notifications','disableNotifications'),
                ('abort_images','abortImage'),('abort_media','abortMedia'),('disable_clipboard','disableClipboard'),('allowed_signin','allowedSignin'),('disable_translate','disableTranslatePopup')]:prefs[dest]=bool(info.get(origin))
        prefs['credentials_service']=not bool(info.get('credentialsEnableService'));prefs['memory_saver']=bool(native.get('MemorySaverModeEnabled'));prefs['restore_session']=True
        record.update(preferences=prefs,_native=native,_source_info=copy.deepcopy(full),_source_detail=copy.deepcopy(detail),
            _source_manifest=manifest,_source={'provider':'bitbrowser-local-v1','source_key':candidate['source_key'],'source_id':candidate['source_id'],'imported_at':record['imported_at']},
            _empty=False,_prefs_dirty=False,_cookie_pending=False)
        runtime=self.service._runtime(record)
        runtime.update(profile_path=str(final),fingerprint_path=str(config_path),fingerprint_sha256=fingerprint_hash or sha256(config_path),new_profile=False,has_launched=True)
        if engine_path:runtime.update(core_path=str(engine_path),core_sha256=sha256(engine_path))
        if rawfp.get('isIpCreateDisplayLanguage'):runtime['language']=native.get('appLocale') or runtime['language']
        record['_runtime']=runtime
        return record

    def _prepare_record(self,record,candidate,staged,work):
        """Prepare new portable keys and continuity before a copy becomes durable."""
        from import_preparation import prepare_import
        return prepare_import(self.service,record,candidate,staged,work)

    def _warning(self,job_id):
        try:self.state.warning(job_id)
        except Exception:pass

    def _intent_paths(self,intent):
        self.state.validate_intent(intent)
        if (not re.fullmatch('[0-9a-f]{32}',intent['intent_id']) or
                not re.fullmatch('[0-9a-f]{32}',intent['work_id']) or
                not re.fullmatch('profile-[0-9a-f]{32}',intent['profile_id'])):
            raise LocalBrowserError('同步恢复记录的目标无效，未清理任何资料。')
        root=self.service.root.resolve()
        work=root/'.sync-work'/intent['work_id'];final=root/'profiles'/intent['profile_id']
        config=root/'fingerprints'/(intent['profile_id']+'.bin')
        for path in (work,work/'profile',work/'fingerprint.bin',work/'.sync-owner.bin',final,config):
            if not path.resolve().is_relative_to(root):
                raise LocalBrowserError('同步恢复目标越界，未清理任何资料。')
            for part in (path,*path.parents):
                if part==root:break
                try:attributes=getattr(part.lstat(),'st_file_attributes',0)
                except FileNotFoundError:continue
                if part.is_symlink() or attributes&0x400:
                    raise LocalBrowserError('同步恢复目标包含特殊链接，未清理任何资料。')
        return work,final,config

    @staticmethod
    def _plain_tree(folder):
        for path in chain((folder,),folder.rglob('*')):
            if path.is_symlink() or getattr(path.lstat(),'st_file_attributes',0)&0x400:
                raise LocalBrowserError('同步副本包含特殊链接，未发布或清理资料。')

    def _clean_work(self,intent):
        from delete_stores import _remove_work
        work,_,_=self._intent_paths(intent)
        if work.exists():
            if profile_processes(work/'profile',require_inspectable=True):
                raise LocalBrowserError('同步暂存副本仍在使用，已保留等待恢复。')
            work,_,_=self._intent_paths(intent)
            _remove_work(self.service,work,self.service.root,self.state.validate_intent(intent))

    @staticmethod
    def _publish(source,target):
        # Windows rename rejects existing files and directories atomically and
        # also works on removable filesystems without hard-link support.
        if target.exists():raise LocalBrowserError('本地目标已存在，未覆盖。')
        if os.name=='nt' or source.is_dir():os.rename(source,target)
        else:
            os.link(source,target)
            source.unlink()

    @staticmethod
    def _flush_file(path):
        previous=path.stat().st_mode
        changed=not bool(previous&stat.S_IWRITE)
        try:
            if changed:path.chmod(previous|stat.S_IWRITE)
            with path.open('r+b') as handle:os.fsync(handle.fileno())
        finally:
            if changed:path.chmod(previous)

    def _complete_intent(self,intent):
        store=self.service.store;work,final,config=self._intent_paths(intent)
        bound=store.source_binding(intent['source_key'])
        if bound:
            if bound!=intent['profile_id']:
                raise LocalBrowserError('该来源已有其他本地绑定，恢复副本已保留供核查。')
            record=store.get(bound);store.validate_import_source(record,intent['source_key'])
            runtime=record['_runtime']
            if Path(runtime['profile_path']).resolve()!=final or Path(runtime['fingerprint_path']).resolve()!=config:
                raise LocalBrowserError('已提交绑定与恢复目标不一致，未清理资料。')
            if not final.is_dir() or not config.is_file() or sha256(config)!=runtime['fingerprint_sha256']:
                raise LocalBrowserError('已提交副本尚不能完整核对，暂存资料已保留供恢复。')
            if intent['job_id']:
                self.state.finish_item(intent['job_id'],intent['ordinal'],'completed','完整独立副本已保存。')
        else:
            if intent['state']=='copying':
                if final.exists() or config.exists():
                    raise LocalBrowserError('未完成的同步存在已发布目标，已保留供核查。')
                self._clean_work(intent);self.state.discard_intent(intent['intent_id']);return None
            if intent['state']!='prepared' or not intent['data']:
                raise LocalBrowserError('同步恢复记录不完整，已保留副本。')
            data=intent['data'];record=data['record'];runtime=record['_runtime']
            store.validate_import_source(record,intent['source_key'])
            if (record['id']!=intent['profile_id'] or Path(runtime['profile_path']).resolve()!=final or
                    Path(runtime['fingerprint_path']).resolve()!=config or runtime['fingerprint_sha256']!=data['signature_hash']):
                raise LocalBrowserError('同步恢复记录与目标身份不一致，未覆盖资料。')
            profile=final if final.exists() else work/'profile'
            signed=config if config.exists() else work/'fingerprint.bin'
            if profile_processes(profile,require_inspectable=True):
                raise LocalBrowserError('同步恢复副本仍在使用，已保留等待恢复。')
            self._plain_tree(profile)
            self._plain_tree(signed)
            if self.service._manifest(profile)!=data['manifest'] or sha256(signed)!=data['signature_hash']:
                raise LocalBrowserError('同步恢复副本校验不一致，已保留资料，未提交。')
            work,final,config=self._intent_paths(intent)
            final.parent.mkdir(parents=True,exist_ok=True)
            work,final,config=self._intent_paths(intent)
            config.parent.mkdir(parents=True,exist_ok=True)
            work,final,config=self._intent_paths(intent)
            if not final.exists():
                self._intent_paths(intent);self._publish(profile,final)
            if not config.exists():
                self._intent_paths(intent);self._publish(signed,config)
            self._intent_paths(intent)
            try:store.commit_import(record,intent['source_key'],intent_id=intent['intent_id'])
            except Exception:
                # A commit can succeed before the caller loses its result. Never
                # remove a published tree while the authoritative read is uncertain.
                if store.source_binding(intent['source_key'])!=intent['profile_id']:raise
                saved=store.get(intent['profile_id']);store.validate_import_source(saved,intent['source_key'])
                record=saved
        try:self.service._sync(record)
        except Exception:self._warning(intent['job_id'])
        try:
            self._clean_work(intent);self.state.discard_intent(intent['intent_id'])
        except Exception:self._warning(intent['job_id'])
        return record

    def _recover_intents(self,key=None):
        blocked=False
        for intent in self.state.intents(key):
            try:self._complete_intent(intent)
            except Exception:
                blocked=True
                if not intent.get('_authentication_failed'):self._warning(intent['job_id'])
        if key is not None and blocked:
            raise LocalBrowserError('此来源仍有待核实的同步副本；已保留资料，请恢复后再试。')

    def _import(self,candidate,phase):
        service=self.service;self._recover_intents(candidate['source_key'])
        if service.store.source_binding(candidate['source_key']):return False
        candidate=self.provider.revalidate(candidate);source=Path(candidate['profile_path'])
        if profile_processes(source):raise LocalBrowserError('来源窗口仍在运行，请正常关闭后再同步。')
        phase('preparing');startup,native,binary,proxy=self._startup(candidate)
        full=startup['info'];core=str(full['browserFingerPrint']['coreVersion'])
        if getattr(service.configuration,'independent',False):
            engine_path=service.configuration.local_core(core)
        else:engine_path=service.engines.install(core,startup['core_path']) if startup.get('core_path') else None
        identity='profile-'+uuid.uuid4().hex;work_id=uuid.uuid4().hex;intent_id=uuid.uuid4().hex
        intent=self.state.intent(intent_id,candidate['source_key'],identity,work_id,self._job_item)
        work,final,config=self._intent_paths(intent);staged=work/'profile'
        prepared=False;created=False
        try:
            work,final,config=self._intent_paths(intent)
            work.mkdir(parents=True,exist_ok=False);created=True
            self._intent_paths(intent)
            marker=service.store.pack({'format':1,'ownership':self.state.validate_intent(intent)})
            with (work/'.sync-owner.bin').open('xb') as output:
                output.write(marker);output.flush();os.fsync(output.fileno())
            self._intent_paths(intent);phase('copying');service._copy_profile(source,staged)
            manifest=service._manifest(staged);phase('validating')
            self.provider.revalidate(candidate)
            notes=self._extensions(source,staged,final)
            if startup.get('import_note'):notes.append(startup['import_note'])
            signed=work/'fingerprint.bin'
            with signed.open('wb') as output:output.write(binary);output.flush();os.fsync(output.fileno())
            record=self._record(candidate,full,native,proxy,identity,final,config,manifest,notes,engine_path,fingerprint_hash=sha256(signed))
            record=self._prepare_record(record,candidate,staged,work)
            self.provider.revalidate(candidate)
            self._plain_tree(staged)
            for path in staged.rglob('*'):
                if path.is_file():self._flush_file(path)
            self._flush_file(signed);signature_hash=sha256(signed)
            record['_runtime']['fingerprint_sha256']=signature_hash
            published_manifest=service._manifest(staged)
            intent=self.state.prepare(intent_id,record,published_manifest,signature_hash);prepared=True
            phase('committing')
            self._complete_intent(intent)
            return True
        except Exception:
            if not prepared:
                # Preparation may have committed even when its response was lost.
                durable=next(iter(self.state.intents(candidate['source_key'])),None)
                if durable and durable['intent_id']==intent_id and durable['state']=='copying':
                    try:
                        if created:self._clean_work(intent)
                        self.state.discard_intent(intent_id)
                    except Exception:self._warning(intent['job_id'])
            raise
