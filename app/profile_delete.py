"""Recoverable permanent deletion of explicitly selected, locally owned windows.

This removes the program's identified recoverable copies. It cannot promise
physical erasure from SSD firmware, operating-system snapshots or external copies.
"""
from contextlib import nullcontext
from pathlib import Path
import re
import sqlite3
import uuid

from browser_processes import profile_processes
from delete_paths import DeleteError,absolute,checked,remove
from delete_stores import execute_plan,identities,make_plan,validate_plan
from local_state import LocalBrowserError,read_encrypted,write_encrypted
from sync_state import WorkerLease

_PENDING='.profile-delete.bin'
_FAILED='永久删除尚未完成，部分本地资料可能已清理；请重试或重启以继续，未完成前不能打开或恢复该窗口。'
_PARTIAL='窗口记录已删除，但删除后的存储清理尚未完成；重试或重启会继续清理。'


def _pending_files(root):
    root=absolute(root);checked(root,root)
    output=[]
    for path in root.iterdir():
        if path.name==_PENDING or re.fullmatch(re.escape(_PENDING)+r'\.[A-Za-z0-9_-]+\.tmp',path.name):
            checked(path,root);output.append(path)
    return sorted(output,key=lambda path:path.name!=_PENDING)


def _read_pending(root):
    root=absolute(root);checked(root/'.portable-vault',root,tree=True);plans={}
    try:
        for path in _pending_files(root):
            value=read_encrypted(path,root=root)
            if not isinstance(value,dict) or value.get('format')!=1 or not isinstance(value.get('plans'),list):raise ValueError()
            for plan in value['plans']:
                if isinstance(plan,dict) and plan.get('root')!=str(root):
                    # Folder-key authentication survives a complete directory
                    # move. All authorized targets remain relative; no previous
                    # absolute path is ever followed during recovery.
                    from portable_vault import is_portable
                    if not is_portable(path.read_bytes()):raise ValueError()
                    plan=dict(plan,root=str(root))
                validate_plan(plan,root)
                token=plan.get('token')
                if not isinstance(token,str) or not re.fullmatch('[0-9a-f]{32}',token):raise ValueError()
                if token in plans and plans[token]!=plan:raise ValueError()
                plans[token]=plan
        return list(plans.values())
    except Exception:
        raise DeleteError('删除恢复计划损坏、无法认证或路径发生变化，已停止清理；请保留资料目录。') from None


def get_pending_ids(root):
    return {identity for plan in _read_pending(root) for identity in plan['identities']}


def is_pending(root,identity):
    return str(identity) in get_pending_ids(root)


def _write_pending(root,plans):
    path=checked(absolute(root)/_PENDING,root)
    # Authenticate and validate every plan and every deletion tree before the
    # first write. The atomic encrypted journal is the recovery authority.
    for plan in plans:validate_plan(plan,root,trees=True)
    write_encrypted(path,{'format':1,'plans':plans},root=root)
    loaded=_read_pending(root)
    if {item['token'] for item in loaded}!={item['token'] for item in plans}:
        raise DeleteError('删除恢复计划未能可靠保存，未继续清理。')


def _clear_pending(root,plan):
    plans=_read_pending(root)
    remaining=[item for item in plans if item['token']!=plan['token']]
    if remaining:_write_pending(root,remaining)
    # A process can stop between writing an encrypted temporary file and
    # replacing the journal. Remove every authenticated completed plan copy.
    for path in _pending_files(root):
        value=read_encrypted(path,root=root)
        kept=[item for item in value['plans'] if item['token']!=plan['token']]
        if kept!=value['plans']:
            if kept:write_encrypted(path,{'format':1,'plans':kept},root=root)
            else:remove(path,root)


def _assert_closed(service,plan):
    root=absolute(service.root)
    for identity in plan['identities']:
        # Only use the existing normal-close workflow. Never kill a process or
        # infer that an inaccessible process is already gone.
        with service.store.lock,service.store.connect() as con:
            exists=con.execute('SELECT 1 FROM profiles WHERE id=?',(identity,)).fetchone()
        if exists:service.close(identity)
        else:
            runtime=getattr(service,'proxy_runtime',None)
            if runtime is not None:runtime.stop_if_unused(identity)
        profile=checked(root/'profiles'/identity,root)
        if profile_processes(profile,require_inspectable=True):
            raise DeleteError('窗口仍在保存或运行，未继续删除；请正常关闭后重试。')
    for value in plan['targets']:
        if value.startswith('backups/') and '/' not in value[len('backups/'):]:profile=root/value
        elif value.startswith('.sync-work/'):profile=root/value/'profile'
        else:continue
        if profile_processes(checked(profile,root),require_inspectable=True):
            raise DeleteError('历史资料副本仍被浏览器占用，未继续删除；请正常关闭后重试。')
    runtime=getattr(service,'proxy_runtime',None)
    if runtime is not None:
        for identity in plan['identities']:
            runtime.stop_if_unused(identity)
            for path in runtime.paths(identity):checked(path,root)


def _purge_runtime(service,plan):
    root=absolute(service.root);controller=getattr(service,'controller',None)
    runtime=getattr(service,'proxy_runtime',None)
    for identity in plan['identities']:
        if runtime is not None:
            runtime.stop_if_unused(identity)
            for path in runtime.paths(identity):remove(path,root)
        if controller is not None:
            lock=getattr(controller,'lock',None)
            with lock if lock is not None else nullcontext():
                for field in ('profiles','state','_status_cache','_windowless_since'):
                    value=getattr(controller,field,None)
                    if isinstance(value,dict):value.pop(identity,None)
                value=getattr(controller,'_closing_workers',None)
                if isinstance(value,set):value.discard(identity)
                settings=getattr(controller,'settings',None)
                if isinstance(settings,dict) and isinstance(settings.get('windows'),list):
                    settings['windows']=[item for item in settings['windows'] if item.get('alias')!=identity]
    configuration=service.configuration
    if hasattr(configuration,'_source_archive_cache'):configuration._source_archive_cache=None
    prepared=getattr(configuration,'_prepared_sources',None)
    if prepared is not None:prepared._ids_cache=None


def _logically_deleted(service,selected):
    try:
        with service.store.lock,service.store.connect() as con:
            return not con.execute('SELECT 1 FROM profiles WHERE id IN ('+','.join('?' for _ in selected)+') LIMIT 1',selected).fetchone()
    except Exception:return False


def _run(service,plan):
    _assert_closed(service,plan)
    execute_plan(service,plan)
    if not _logically_deleted(service,plan['identities']):raise DeleteError(_FAILED)
    _purge_runtime(service,plan)
    _clear_pending(service.root,plan)
    return {'deleted':True,'cleanup_complete':True}


def recover_pending_deletions(service):
    """Attempt authenticated work only; failures remain guarded and retryable."""
    with service.operations:
        root=absolute(service.root);plans=_read_pending(root)
        if not plans:return {'completed':0,'pending':0}
        checked(root/'.sync-worker.lock',root)
        lease=WorkerLease(root)
        if not lease.acquire():return {'completed':0,'pending':len(plans)}
        completed=0
        try:
            for plan in plans:
                try:_run(service,plan);completed+=1
                except Exception:continue
        finally:lease.release()
        return {'completed':completed,'pending':len(_read_pending(root))}


def delete_profiles(service,values):
    """Delete up to 100 windows serially, scanning/compacting each store once.

    A batch is one confirmed recovery operation. Any incomplete stage leaves
    all selected identities guarded until that same operation can finish.
    """
    selected=identities(values)
    with service.operations:
        root=absolute(service.root);checked(root,root)
        checked(root/'.sync-worker.lock',root)
        lease=WorkerLease(root)
        if not lease.acquire():raise DeleteError('来源同步仍在运行，请等待同步结束后再永久删除。')
        plan=None
        try:
            pending=_read_pending(root)
            if pending:
                for old in pending:
                    if set(selected)<=set(old['identities']):plan=old
                    _run(service,old)
                    if set(selected)<=set(old['identities']):return {'deleted':True,'cleanup_complete':True}
            records=[service.store.get(identity) for identity in selected]
            # Preflight all historic stores, identities and literal parent chains
            # before normal closing may write runtime state.
            plan=make_plan(service,records);plan['token']=uuid.uuid4().hex
            _assert_closed(service,plan)
            _write_pending(root,[plan])
            return _run(service,plan)
        except Exception:
            if plan is not None and _logically_deleted(service,selected):
                try:_purge_runtime(service,plan)
                except Exception:pass
                return {'deleted':True,'cleanup_complete':False,'message':_PARTIAL}
            raise DeleteError(_FAILED) from None
        finally:lease.release()


def delete_profile(service,identity):
    return delete_profiles(service,[identity])
