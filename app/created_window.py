"""Explicit launch options for locally created windows; imported profiles are excluded."""
import copy
import json
import os
from pathlib import Path
import uuid

from browser_core import sha256
from browser_processes import profile_processes
from creation_fingerprint import build_native,normalize_options,random_fingerprint,resolve_geo,needs_geo
from delete_paths import checked,remove
from local_state import LocalBrowserError
from window_store import fingerprint_unreferenced


def prepare_launch(service,record,*,offline_test=False):
    if not record.get('created_locally'):return record
    options=normalize_options(record.get('created_options') or {})
    fp=record['fingerprint']
    automatic=needs_geo(fp)
    if not options['random_each_open'] and (not automatic or offline_test):return record
    from fingerprint_continuity import verify_continuity,create_baseline
    verify_continuity(record,service.root,allow_device_variance=True)
    updated=copy.deepcopy(record)
    if automatic and not offline_test:
        route=None
        try:
            route=service.proxy_runtime.ensure(record)
            proxy={'type':'http','host':'127.0.0.1','port':route['port']} if route else record['proxy']
            geo=resolve_geo(proxy)
            if route and (not service.proxy_runtime.owned(route) or not service.proxy_runtime.control(route)):
                raise LocalBrowserError('代理在环境检测期间退出，未修改或启动窗口。')
        finally:
            if route:service.proxy_runtime.stop_if_unused(record['id'])
        updated['_creation_geo']=geo
    if options['random_each_open']:updated['fingerprint']=random_fingerprint(fp)
    if updated['fingerprint']==fp and updated.get('_creation_geo')==record.get('_creation_geo'):return record
    native,binary=build_native(service.configuration,updated,record['_native'])
    if native==record['_native']:return record
    target=Path(service.root)/'fingerprints'/(record['id']+'-'+uuid.uuid4().hex+'.bin')
    temporary=target.with_suffix('.tmp');attempted=False
    try:
        with temporary.open('xb') as stream:stream.write(binary);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,target)
        updated['_native']=native
        updated['_runtime'].update(fingerprint_path=str(target),fingerprint_sha256=sha256(target))
        if fp.get('isIpCreateDisplayLanguage'):updated['_runtime']['language']=native.get('uiLang') or ''
        updated['_continuity']=create_baseline(updated,service.root)
        verify_continuity(updated,service.root)
        attempted=True;service.store.put(updated);service._sync(updated)
        return updated
    except Exception:
        if not attempted or fingerprint_unreferenced(service.store,record['id'],target):target.unlink(missing_ok=True)
        raise
    finally:temporary.unlink(missing_ok=True)


def apply_launch_cleanup(service,record):
    if not record.get('created_locally'):return
    options=normalize_options(record.get('created_options') or {})
    profile=Path(record['_runtime']['profile_path'])
    if profile!=Path(service.root)/'profiles'/record['id'] or profile_processes(profile,require_inspectable=True):
        raise LocalBrowserError('窗口资料归属或关闭状态无法确认，未执行启动清理。')
    targets=[]
    if options['clear_cache']:
        targets.extend(('Default/Cache','Default/Code Cache','Default/GPUCache','GPUCache','ShaderCache','GrShaderCache','DawnGraphiteCache'))
        if not options['clear_cache_without_extensions']:targets.append('Default/Service Worker/CacheStorage')
    if options['clear_cookies']:targets.extend(('Default/Network/Cookies','Default/Cookies'))
    if options['clear_history']:targets.extend(('Default/History','Default/History Provider Cache','Default/Visited Links','Default/Top Sites'))
    for relative in targets:
        path=checked(profile/relative,service.root,tree=True)
        remove(path,service.root)
        for suffix in ('-wal','-shm','-journal'):remove(Path(str(path)+suffix),service.root)


def check_egress(record,result):
    if not record.get('created_locally'):return
    if str(record.get('fingerprint',{}).get('webRTC'))=='0':
        public_ip=(record.get('_native') or {}).get('WebRTC',{}).get('PublicIP')
        if not public_ip or not result.get('egress_ip') or public_ip!=result['egress_ip']:
            raise LocalBrowserError('WebRTC替换地址与浏览器实际出口不同或无法核实，已停止打开；请重新尝试。')
    options=normalize_options(record.get('created_options') or {})
    previous=record.get('_last_creation_egress') or {}
    if options['stop_ip_change'] and previous.get('ip') and previous['ip']!=result.get('egress_ip'):
        raise LocalBrowserError('出口IP与上次成功打开时不同，已按设置停止打开。')
    country=(result.get('geo') or {}).get('country')
    if options['stop_country_change'] and previous.get('country') and previous['country']!=country:
        raise LocalBrowserError('出口国家与上次成功打开时不同或无法核实，已按设置停止打开。')
    record['_pending_creation_egress']={'ip':result.get('egress_ip'),'country':country}
