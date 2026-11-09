"""Explicit live acceptance in a marked, isolated empty distribution only."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
import traceback
import uuid

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--cores',default='148')
    parser.add_argument('--batch',type=int,default=2)
    parser.add_argument('--require-short-path',action='store_true',help='Require every engine resource tree to exceed MAX_PATH and use a verified alias')
    args=parser.parse_args()
    if not args.execute:print(json.dumps({'executed':False}));return 0
    report={'success':False,'synthetic':True,'results':[]}
    service=None;owned=[]
    try:
        marker=ROOT/'local-creation-test.json'
        if marker.is_symlink() or json.loads(marker.read_text(encoding='utf-8'))!={'format':1,'purpose':'isolated-local-creation'}:raise ValueError()
        if (ROOT/'app/data').is_symlink() or (ROOT/'app/data').is_junction():raise ValueError()
        sys.path[:0]=[str(ROOT/'app')]
        from core_specs import supports_major
        from creation_fingerprint import creation_defaults
        from installation import initialize_installation
        from manager_service import ManagerService
        from browser_core import CDP,_check_launch_paths
        from browser_processes import profile_processes
        from local_signer import LocalSigner
        cores=args.cores.split(',')
        if any(not supports_major(core) for core in cores) or not 1<=args.batch<=5:raise ValueError()
        initialize_installation();service=ManagerService();creator=service.creator()
        if any(not p.get('created_locally') or p.get('username') or p.get('password') or p.get('cookie_text') for p in service.store.all()):raise ValueError()
        def create(core,count):
            p=creation_defaults(core);p.update(name='Isolated creation test',urls=['about:blank'])
            job=creator.start({'request_id':uuid.uuid4().hex,'profile':p,'count':count,'random_each':True})
            deadline=time.monotonic()+300
            while job['state']=='running' and time.monotonic()<deadline:
                time.sleep(.2);job=creator.status(job['job_id'])
            if job['state']!='completed' or job['completed']!=count:
                row={'core':core,'creation_completed':False,'error_messages':[v['message'] for v in job['items']]}
                report['results'].append(row);raise ValueError()
            return [item['id'] for item in job['items']]
        for core in cores:
            identities=create(core,1);identity=identities[0];owned.append(identity)
            record=service.store.get(identity);native=record['_native'];baseline=record['_continuity']
            row={'core':core,'creation_completed':True,'baseline_fields':len(baseline['stable']),'rounds':[]}
            report['results'].append(row)
            if args.require_short_path:
                executable=Path(record['_runtime']['core_path'])
                manifest=json.loads((executable.parent/'manifest.json').read_text(encoding='utf-8'))
                maximum=max(len(str(executable.parent/name).encode('utf-16-le'))//2 for name in manifest['files'])
                selected=_check_launch_paths(executable)
                row['path_checks']={'deep_resources':maximum>=260,'same_executable':selected.samefile(executable),
                    'alias_selected':str(selected)!=str(executable),'resources_fit':all(len(str(selected.parent/name).encode('utf-16-le'))//2<260 for name in manifest['files'])}
                if not all(row['path_checks'].values()):raise ValueError()
            for _ in range(2):
                service.open(identity,offline_test=True,extra_urls=['about:blank'])
                if args.require_short_path:
                    import psutil
                    process=psutil.Process(service.controller.state[identity]['pid'])
                    arguments=process.cmdline()
                    row['path_checks']['process_uses_alias']=Path(arguments[0]).resolve()==executable.resolve() and str(Path(arguments[0]))!=str(executable)
                    row['path_checks']['process_identified']=service.controller._record_valid(identity)
                    if not all(row['path_checks'].values()):raise ValueError()
                with CDP(service.controller.endpoint(identity)) as connection:
                    targets=connection.call('Target.getTargets')['targetInfos']
                    page=next(t for t in targets if t['type']=='page' and t['url']=='about:blank')
                    session=connection.call('Target.attachToTarget',{'targetId':page['targetId'],'flatten':True})['sessionId']
                    try:
                        result=connection.call('Runtime.evaluate',{'expression':'({ua:navigator.userAgent,cpu:navigator.hardwareConcurrency})','returnByValue':True},session=session)['result']['value']
                    finally:connection.call('Target.detachFromTarget',{'sessionId':session})
                service.close(identity)
                row['rounds'].append({'ua_matches_native':result['ua']==native['userAgent'],
                    'cpu_matches_native':result['cpu']==native['navigator']['hardwareConcurrency'],
                    'profile_closed':not profile_processes(Path(record['_runtime']['profile_path']),require_inspectable=True),
                    'baseline_unchanged':service.store.get(identity)['_continuity']==baseline})
                if not all(row['rounds'][-1].values()):raise ValueError()
            deleted=service.delete(identity)
            row['delete_complete']=deleted.get('deleted') is True and deleted.get('cleanup_complete') is True
            row['profile_removed']=not Path(record['_runtime']['profile_path']).exists()
            row['signature_removed']=not Path(record['_runtime']['fingerprint_path']).exists()
            if not row['delete_complete'] or not row['profile_removed'] or not row['signature_removed']:raise ValueError()
            owned.remove(identity)
            print(json.dumps({'core':core,'passed':True}),flush=True)
        batch=create(cores[-1],args.batch);owned.extend(batch)
        records=[service.store.get(identity) for identity in batch]
        report['batch']={'count':len(batch),'unique_noise':len({r['fingerprint']['canvasValue'] for r in records})==len(batch),
            'unique_storage_keys':len({r['_portable_crypt']['key_id'] for r in records})==len(batch)}
        deleted=service.delete_many(batch)
        report['batch']['delete_complete']=deleted.get('deleted') is True and deleted.get('cleanup_complete') is True
        if not all(v for k,v in report['batch'].items() if k!='count'):raise ValueError()
        owned.clear();report['success']=True
    except Exception as error:
        report['error_type']=type(error).__name__
        report['frames']=[{'file':Path(frame.filename).name,'line':frame.lineno} for frame in traceback.extract_tb(error.__traceback__)[-6:]]
    finally:
        if service is not None:
            for identity in owned:
                try:service.close(identity)
                except Exception:report['normal_close_failed']=True;report['success']=False
        destination=ROOT/'analysis/reports/local-creation-live.json'
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(report,ensure_ascii=False))
    return 0 if report['success'] else 1


if __name__=='__main__':raise SystemExit(main())
