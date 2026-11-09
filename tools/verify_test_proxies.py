"""Explicit live checks of the user's encrypted, numbered test proxies only."""
import argparse
from datetime import date
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from local_state import _dpapi_protect
from portable_vault import PortableVault
from proxy_check import ProxyChecker
from proxy_runtime import ProxyRuntime


def load_proxies():
    rows=json.loads(_dpapi_protect((ROOT/'analysis/private/test-proxies.bin').read_bytes(),decrypt=True))
    if not isinstance(rows,list) or not 1<=len(rows)<=20:raise ValueError()
    for index,row in enumerate(rows,1):
        if row['alias']!='test-'+str(index) or date.fromisoformat(row['expires'])<date.today():raise ValueError()
    return rows


def is_test_worker(arguments,work,identities):
    return (isinstance(arguments,(list,tuple)) and len(arguments)==4
        and Path(arguments[1]).resolve()==(ROOT/'app/proxy_runtime.py').resolve()
        and Path(arguments[2]).resolve()==work/'proxy-runtime' and arguments[3] in identities)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    if not parser.parse_args().execute:print(json.dumps({'executed':False}));return 0
    result={'success':False,'checks':[]};work=None;runtime=None;owned=[];workers=[]
    try:
        rows=load_proxies();work=Path(tempfile.mkdtemp(prefix='test-proxy-check-')).resolve()
        PortableVault(work).initialize();runtime=ProxyRuntime(work)
        popen=subprocess.Popen
        def launch(arguments,*values,**options):
            worker=is_test_worker(arguments,work,owned)
            process=popen(arguments,*values,**options)
            if worker:workers.append(process)
            return process
        for row in rows:
            for kind in ('socks5','http'):
                identity=row['alias']+'-'+kind;profile=work/'profiles'/identity;profile.mkdir(parents=True)
                proxy={key:row[key] for key in ('host','port','username','password')};proxy['type']=kind
                record={'id':identity,'proxy':proxy,'_runtime':{'alias':identity,'profile_path':str(profile),
                    'core_path':str(work/'fixture.exe'),'fingerprint_path':str(work/'fixture.bin')}}
                owned.append(identity);started=time.monotonic()
                try:
                    with patch.object(subprocess,'Popen',side_effect=launch):state=runtime.ensure(record)
                    if not state or not runtime.owned(state) or not runtime.control(state):raise ValueError()
                    checked=ProxyChecker().test({'type':'http','host':'127.0.0.1','port':state['port']})
                    good=checked.get('success') is True and runtime.owned(state) and runtime.control(state)
                    result['checks'].append({'alias':row['alias'],'type':kind,'success':good,
                        'timed_out':checked.get('timed_out',False),'elapsed_ms':round((time.monotonic()-started)*1000)})
                except Exception as exc:result['checks'].append({'alias':row['alias'],'type':kind,'success':False,'error_type':type(exc).__name__})
                finally:runtime.stop_if_unused(identity)
                print(json.dumps(result['checks'][-1]),flush=True)
        result['all_protocols_passed']=all(item['success'] for item in result['checks'])
        result['usable_proxies']=sum(any(item['alias']==row['alias'] and item['success'] for item in result['checks']) for row in rows)
        result['success']=result['all_protocols_passed']
    except Exception as exc:result['error_type']=type(exc).__name__
    finally:
        safe=True
        if runtime:
            for identity in owned:
                try:
                    runtime.stop_if_unused(identity);state=runtime.state(identity)
                    if state and runtime.owned(state):safe=False
                except Exception:safe=False
        safe=safe and all(process.poll() is not None for process in workers)
        if work and safe:
            if (work.parent!=Path(tempfile.gettempdir()).resolve() or not work.name.startswith('test-proxy-check-')
                    or work.is_symlink() or any(p.is_symlink() or p.is_junction() for p in work.rglob('*'))):safe=False
            else:
                try:shutil.rmtree(work)
                except OSError:safe=False
        result['owned_workers_and_files_cleaned']=safe;result['success']=result['success'] and safe
    report=ROOT/'analysis/reports/test-proxy-check.json';report.parent.mkdir(parents=True,exist_ok=True)
    report.write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result))
    return 0 if result['success'] else 1


if __name__=='__main__':raise SystemExit(main())
