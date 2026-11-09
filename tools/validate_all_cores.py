"""Explicit live core validation, restricted to windows created by this run.

Private identities stay in an encrypted local ledger. Never mutate preexisting
vendor windows or construct a manager using the real catalog for testing.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid
from urllib.request import Request,build_opener,ProxyHandler

if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'app'),str(ROOT/'tools')]
from local_state import read_encrypted,write_encrypted

MAJORS=('104','112','118','122','124','126','128','130','132','134','136','138','140','142','144','146','148','150','152','154','156')
WORK=ROOT/'analysis/core-validation'
LEDGER=WORK/'owned-windows.bin'
_OPENER=build_opener(ProxyHandler({}))
_STAGE='entry'


def api(route,payload=None,timeout=30):
    request=Request('http://127.0.0.1:54345'+route,data=json.dumps(payload or {}).encode(),headers={'Content-Type':'application/json'})
    with _OPENER.open(request,timeout=timeout) as response:
        raw=response.read(32_000_001)
        if len(raw)>32_000_000:raise ValueError('Response size limit')
        value=json.loads(raw)
    if value.get('success') is not True:
        # Do not propagate vendor error messages: they can contain private paths.
        raise RuntimeError('Vendor request refused')
    return value.get('data')


def list_windows():
    rows={};page=0
    while True:
        data=api('/browser/list',{'page':page,'pageSize':100})
        items=data.get('list') if isinstance(data,dict) else None
        if not isinstance(items,list):raise ValueError('List format')
        for item in items:
            identity=item.get('id')
            if not isinstance(identity,str) or not re.fullmatch('[a-fA-F0-9]{32}',identity):raise ValueError('Window identity')
            rows[identity]=item
        if len(rows)>=int(data.get('totalNum',0)):return rows
        if not items or page>1000:raise ValueError('List pagination')
        page+=1


def save(ledger):write_encrypted(LEDGER,ledger,root=ROOT/'app/data')


def load():
    value=read_encrypted(LEDGER,root=ROOT/'app/data')
    if value.get('format')!=1 or not re.fullmatch('[a-f0-9]{32}',value.get('run','')):raise ValueError('Ledger format')
    return value


def owned(ledger,major):
    item=ledger['tests'].get(major)
    if not item or not item.get('id') or item['id'] in ledger['original_ids']:raise ValueError('No owned test window')
    detail=api('/browser/detail',{'id':item['id']})
    fp=detail.get('browserFingerPrint') or {}
    if detail.get('name')!=item['name'] or str(fp.get('coreVersion') or detail.get('coreVersion'))!=major:
        raise ValueError('Owned window identity changed')
    return item,detail


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['init','create','open','sample','close','status','sandbox','import','verify','discard','cleanup'])
    parser.add_argument('--major',choices=MAJORS)
    parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    if not args.execute:print(json.dumps({'executed':False}));return 0
    WORK.mkdir(parents=True,exist_ok=True)
    if args.action=='init':
        if LEDGER.exists():
            ledger=load()
        else:
            rows=list_windows()
            ledger={'format':1,'run':uuid.uuid4().hex,'original_ids':list(rows),'tests':{},
                'original_rows':{identity:hashlib.sha256(json.dumps(row,sort_keys=True,ensure_ascii=False).encode()).hexdigest() for identity,row in rows.items()}}
            save(ledger)
        print(json.dumps({'initialized':True,'original_vendor_windows':len(ledger['original_ids']),'owned_tests':len(ledger['tests'])}));return 0
    ledger=load()
    if args.action=='status':
        print(json.dumps({'owned_tests':[{'major':major,'created':bool(value.get('id')),'opened':value.get('opened',False),'closed':value.get('closed',False)} for major,value in ledger['tests'].items()]}));return 0
    if args.action=='sandbox':
        import shutil
        target=WORK/'sandbox-data'
        if target.exists():
            if ledger.get('sandbox')!=str(target):raise ValueError('Unknown sandbox')
        else:
            target.mkdir()
            for folder in ('.portable-vault','local-signing'):
                shutil.copytree(ROOT/'app/data'/folder,target/folder)
            for name in ('local-signing.lock','portable-mode.bin','continuity-mode.bin','independent-mode.bin',
                         'configuration-context.bin','local-source-archive.bin'):
                shutil.copyfile(ROOT/'app/data'/name,target/name)
            ledger['sandbox']=str(target);save(ledger)
        print(json.dumps({'sandbox_ready':True}));return 0
    if args.action=='cleanup':
        from manager_service import ManagerService
        from browser_processes import profile_processes
        from delete_paths import checked,remove
        target=WORK/'sandbox-data'
        if ledger.get('sandbox')!=str(target):raise ValueError('Unknown sandbox')
        selected=[]
        service=ManagerService(target)
        for major,item in ledger['tests'].items():
            if not item.get('verification') or not all(item['verification'].values()):raise ValueError('Unverified test')
            if item.get('local_id'):
                record=service.store.get(item['local_id'])
                if record['_source']['source_id'].lower()!=item['id'].lower():raise ValueError('Local ownership')
                selected.append(item['local_id'])
        if selected:
            result=service.delete_many(selected)
            if result.get('deleted') is not True or result.get('cleanup_complete') is not True:raise ValueError('Test cleanup incomplete')
            for item in ledger['tests'].values():item.pop('local_id',None)
            ledger['local_tests_deleted']=True;save(ledger)
        from configuration import Configuration
        from local_source import profile_root
        configuration=Configuration(ROOT/'app/data');source_root=profile_root(configuration)
        for major,item in ledger['tests'].items():
            if item.get('source_deleted'):continue
            owned(ledger,major)
            profile=checked(source_root/item['id'],source_root,tree=True)
            if profile_processes(profile,require_inspectable=True):raise ValueError('Source still running')
            api('/browser/delete',{'id':item['id']},timeout=30)
            # Only the exact authenticated test profile/cache may be removed.
            # Never infer ownership from a name prefix or search other accounts.
            remove(profile,source_root)
            cache=configuration.vendor_data/'LocalCache'
            remove(checked(cache/item['id'],cache),cache)
            item['source_deleted']=True;save(ledger)
            print(json.dumps({'major':major,'owned_source_deleted':True}),flush=True)
        if service.store.all():raise ValueError('Unexpected sandbox rows')
        remove(checked(target,WORK,tree=True),WORK)
        ledger['cleanup_complete']=True;save(ledger)
        print(json.dumps({'cleanup_complete':True,'owned_tests':len(ledger['tests']),'existing_profiles_deleted':0}));return 0
    major=args.major
    if major is None:raise ValueError('Major required')
    if args.action=='create':
        item=ledger['tests'].setdefault(major,{'name':'LocalCoreTest-'+ledger['run'][:12]+'-'+major})
        if not item.get('id'):
            # Recover a response lost after the remote create before retrying.
            found=[row for identity,row in list_windows().items() if identity not in ledger['original_ids'] and row.get('name')==item['name']] if item.get('create_attempted') else []
            if len(found)>1:raise ValueError('Ambiguous test window')
            item['create_attempted']=True
            save(ledger)
            created=found[0] if found else api('/browser/update',{'name':item['name'],'remark':'Owned local compatibility validation '+ledger['run'],
                'proxyMethod':2,'proxyType':'noproxy','url':'about:blank','browserFingerPrint':{'coreVersion':major,'coreProduct':'chrome','ostype':'PC','os':'Win32'}})
            identity=created.get('id')
            if not re.fullmatch('[a-fA-F0-9]{32}',str(identity)) or identity in ledger['original_ids']:raise ValueError('Create identity')
            item['id']=identity;save(ledger)
        owned(ledger,major)
        print(json.dumps({'major':major,'created':True}));return 0
    if args.action in ('verify','discard'):
        item=ledger['tests'].get(major)
        if not item or item.get('id') in ledger['original_ids'] or item.get('name')!='LocalCoreTest-'+ledger['run'][:12]+'-'+major:
            raise ValueError('No authenticated owned test')
        detail=None
    else:item,detail=owned(ledger,major)
    if args.action=='open':
        result=api('/browser/open',{'id':item['id']},timeout=300)
        if not isinstance(result,dict):raise ValueError('Open result')
        item.update(opened=True,closed=False,connection=result);save(ledger)
        print(json.dumps({'major':major,'opened':True,'result_fields':list(result)}))
    elif args.action=='close':
        api('/browser/close',{'id':item['id']},timeout=30)
        item['closed']=True;save(ledger)
        print(json.dumps({'major':major,'close_requested':True}))
    elif args.action=='sample':
        global _STAGE
        import copy
        import psutil
        from browser_core import CDP,_endpoint,sha256
        from browser_processes import _switch_values
        from configuration import Configuration
        from engine_store import executable_major
        import fingerprint_continuity as fc
        connection=item['connection'];process=psutil.Process(int(connection['pid']))
        _STAGE='source_process'
        command=process.cmdline();executable=Path(process.exe())
        profiles=_switch_values(command,'--user-data-dir');signatures=_switch_values(command,'--fingerprint-config')
        if len(profiles)!=1 or len(signatures)!=1 or executable_major(executable)!=major:raise ValueError('Source process identity')
        profile=Path(profiles[0]).resolve();signature=Path(signatures[0]).resolve()
        if profile.name.lower()!=item['id'].lower():raise ValueError('Source profile ownership')
        item.update(source_profile=str(profile),source_core=str(executable),source_signature=str(signature));save(ledger)
        folder=WORK/'signatures';folder.mkdir(exist_ok=True)
        import shutil
        shutil.copyfile(signature,folder/(major+'.bin'))
        _STAGE='decode_native'
        config=Configuration(ROOT/'app/data');native=config.decode(signature)
        names=fc._font_names({'_native':native});expression=fc._EXPRESSION.replace('FONT_NAMES',json.dumps(names,ensure_ascii=False))
        port=int(str(connection['http']).rsplit(':',1)[1].rstrip('/'))
        page=fc._LoopbackPage();url=page.start()
        _STAGE='sample_cdp'
        try:
            with CDP(_endpoint(port),timeout=15) as cdp:
                pages=[p for p in cdp.call('Target.getTargets').get('targetInfos',[]) if p.get('type')=='page']
                if not pages:raise ValueError('No source page')
                session=cdp.call('Target.attachToTarget',{'targetId':pages[0]['targetId'],'flatten':True})['sessionId']
                fc._navigate_local_page(cdp,session,url)
                samples=[]
                for _ in range(2):
                    result=cdp.call('Runtime.evaluate',{'expression':expression,'awaitPromise':True,'returnByValue':True},session=session)
                    if result.get('exceptionDetails'):raise ValueError('Source evaluation')
                    samples.append(fc._normalize_sample(result.get('result',{}).get('value')))
                sample=fc._merge_samples(*samples)
                marker='owned-'+ledger['run']+'-'+major
                cdp.call('Storage.setCookies',{'cookies':[{'name':'local_core_compatibility','value':marker,'url':'http://localhost/','path':'/','expires':time.time()+30*86400}]})
                cookie_present=any(cookie.get('name')=='local_core_compatibility' and cookie.get('value')==marker for cookie in cdp.call('Storage.getCookies').get('cookies',[]))
                result=cdp.call('Runtime.evaluate',{'expression':'localStorage.setItem("local_core_compatibility",'+json.dumps(marker)+');true','returnByValue':True},session=session)
                if not cookie_present or result.get('result',{}).get('value') is not True:raise ValueError('Test persistence setup')
        finally:page.close()
        item.update(source_sample=sample,source_native=native,source_profile=str(profile),source_core=str(executable),
            source_signature=str(signature),source_url=url,marker=marker,source_signature_hash=sha256(signature),sampled=True)
        save(ledger)
        print(json.dumps({'major':major,'source_sampled':True,'fields':len(sample['values']),'unstable_fields':sample['unstable'],'test_cookie_set':True}))
    elif args.action=='import':
        from manager_service import ManagerService
        from window_sync import source_key
        from browser_processes import profile_processes
        from check_project import redact
        if not item.get('sampled') or not item.get('closed'):raise ValueError('Sample and close source first')
        if profile_processes(Path(item['source_profile']),require_inspectable=True):raise ValueError('Source still running')
        target=WORK/'sandbox-data'
        if ledger.get('sandbox')!=str(target):raise ValueError('Unknown sandbox')
        service=ManagerService(target);sync=service.synchronizer();sync.preview();key=source_key(item['id'])
        candidate=sync.candidates.get(key)
        if not candidate or candidate.get('source_id','').lower()!=item['id'].lower():raise ValueError('Candidate identity')
        if candidate.get('status')!='ready':
            print(json.dumps({'major':major,'imported':False,'candidate_status':candidate.get('status'),'reason':redact(candidate.get('reason',''))},ensure_ascii=False));return 1
        job_id=sync.start([key])['job_id'];deadline=time.monotonic()+900
        while time.monotonic()<deadline:
            status=sync.status(job_id)
            if status['state']!='running':break
            time.sleep(.5)
        else:raise TimeoutError('Import deadline')
        identity=service.store.source_binding(key)
        if identity:
            record=service.store.get(identity)
            if record['_source']['source_id'].lower()!=item['id'].lower():raise ValueError('Imported identity')
            item['local_id']=identity;save(ledger)
        success=status['state']=='completed' and status['completed']==1 and status['failed']==0 and bool(identity)
        output={'major':major,'imported':success,'completed':status['completed'],'failed':status['failed']}
        if not success:output['reasons']=[redact(row.get('message','')) for row in status.get('items',[])]
        print(json.dumps(output,ensure_ascii=False));return 0 if success else 1
    elif args.action=='discard':
        from manager_service import ManagerService
        target=WORK/'sandbox-data'
        if ledger.get('sandbox')!=str(target):raise ValueError('Unknown sandbox')
        service=ManagerService(target);identity=item.get('local_id')
        if identity:
            record=service.store.get(identity)
            if record['_source']['source_id'].lower()!=item['id'].lower():raise ValueError('Local copy ownership')
            result=service.delete(identity)
            if not result.get('deleted') or not result.get('cleanup_complete'):raise ValueError('Cleanup incomplete')
            item.pop('local_id',None);item.pop('verification',None);save(ledger)
        print(json.dumps({'major':major,'own_local_test_deleted':True}))
    elif args.action=='verify':
        _STAGE='local_probe'
        import copy
        import ctypes
        from ctypes import wintypes
        import subprocess
        import threading
        from unittest.mock import patch
        from urllib.parse import urlsplit
        from browser_core import CDP
        import browser_core
        import fingerprint_continuity as fc
        from configuration import Configuration
        from manager_service import ManagerService
        from browser_processes import profile_processes
        target=WORK/'sandbox-data'
        if ledger.get('sandbox')!=str(target) or not item.get('local_id'):raise ValueError('No owned local copy')
        service=ManagerService(target);identity=item['local_id'];record=service.store.get(identity)
        if record['_source']['source_id'].lower()!=item['id'].lower():raise ValueError('Local copy ownership')
        snapshot=fc.probe_snapshot(copy.deepcopy(record),target)
        reference=item['source_sample']
        changes=[key for key,value in reference['values'].items() if key not in reference['unstable'] and
            (snapshot['values'].get(key)!=value or key in snapshot['unstable'])]
        checks={'source_fingerprint_matches':not changes,'native_protection_matches':record['_native'].get('DataProtect')==item['source_native'].get('DataProtect')}
        if changes:
            print(json.dumps({'major':major,'verified':False,'changed_fields':[k for k in changes if fc._safe_field(k)]}));return 1
        url=item['source_url'];parsed=urlsplit(url)
        if parsed.scheme!='http' or parsed.hostname!='localhost' or not re.fullmatch('/[0-9a-f]{32}',parsed.path):raise ValueError('Owned localhost origin')
        page=fc._LoopbackPage();page.server=fc._ProbeHTTPServer(('127.0.0.1',parsed.port),fc._ProbePageHandler)
        page.server.probe_path=parsed.path
        page.thread=threading.Thread(target=page.server.serve_forever,kwargs={'poll_interval':.05},daemon=True)
        page.thread.start();page.started=True
        user=ctypes.WinDLL('user32',use_last_error=True)
        user.CreateDesktopW.argtypes=[wintypes.LPCWSTR,wintypes.LPCWSTR,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p]
        user.CreateDesktopW.restype=wintypes.HANDLE
        user.CloseDesktop.argtypes=[wintypes.HANDLE];user.CloseDesktop.restype=wintypes.BOOL
        desktop_name='LocalCoreValidation_'+uuid.uuid4().hex
        desktop=user.CreateDesktopW(desktop_name,None,None,0,0x01ff,None)
        if not desktop:page.close();raise OSError('Test desktop unavailable')
        original=browser_core.subprocess.Popen
        def launch(arguments,*values,**options):
            locations=[arg.split('=',1)[1] for arg in arguments if arg.startswith('--user-data-dir=')]
            if len(locations)!=1 or not Path(locations[0]).resolve().is_relative_to(target.resolve()):raise ValueError('Unexpected test process')
            startup=subprocess.STARTUPINFO();startup.lpDesktop=desktop_name;options['startupinfo']=startup
            return original(arguments,*values,**options)
        forbidden=AssertionError('Independent verification must never contact the vendor')
        try:
            with patch.object(browser_core.subprocess,'Popen',side_effect=launch), \
                    patch.object(Configuration,'vendor',side_effect=forbidden), \
                    patch.object(Configuration,'authorization',side_effect=forbidden), \
                    patch.object(Configuration,'_source_request',side_effect=forbidden):
                for cycle in (1,2):
                    try:
                        _STAGE='local_open_'+str(cycle)
                        service.open(identity,offline_test=True,extra_urls=['about:blank'])
                        with CDP(service.controller.endpoint(identity),timeout=15) as cdp:
                            pages=[p for p in cdp.call('Target.getTargets').get('targetInfos',[]) if p.get('type')=='page']
                            if not pages:raise ValueError('No local page')
                            session=cdp.call('Target.attachToTarget',{'targetId':pages[0]['targetId'],'flatten':True})['sessionId']
                            fc._navigate_local_page(cdp,session,url)
                            cookies=cdp.call('Storage.getCookies').get('cookies',[])
                            checks['cookie_cycle_'+str(cycle)]=any(cookie.get('name')=='local_core_compatibility' and cookie.get('value')==item['marker'] for cookie in cookies)
                            response=cdp.call('Runtime.evaluate',{'expression':'localStorage.getItem("local_core_compatibility")','returnByValue':True},session=session)
                            checks['storage_cycle_'+str(cycle)]=response.get('result',{}).get('value')==item['marker']
                            expression=fc._EXPRESSION.replace('FONT_NAMES',json.dumps(fc._font_names(record),ensure_ascii=False))
                            response=cdp.call('Runtime.evaluate',{'expression':expression,'awaitPromise':True,'returnByValue':True},session=session)
                            actual=fc._normalize_sample(response.get('result',{}).get('value'))
                            checks['fingerprint_cycle_'+str(cycle)]=all(actual['values'].get(key)==value for key,value in reference['values'].items() if key not in reference['unstable'])
                    finally:service.close(identity)
                checks['no_owned_browser_alive']=not profile_processes(Path(record['_runtime']['profile_path']),require_inspectable=True)
        finally:
            page.close()
            checks['desktop_closed']=bool(user.CloseDesktop(desktop))
        success=all(checks.values());item['verification']=checks;save(ledger)
        print(json.dumps({'major':major,'verified':success,'checks':checks},ensure_ascii=False));return 0 if success else 1
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as exc:
        from check_project import redact
        print(json.dumps({'success':False,'error_type':type(exc).__name__,'stage':_STAGE,'safe_error':redact(str(exc))},ensure_ascii=False));raise SystemExit(1)
