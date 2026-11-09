"""Explicit synthetic native Cookie compatibility in a marked test package."""
import argparse
import base64
import copy
import json
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import traceback
import time
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--cores',default='104,124,128,130,148,156')
    args=parser.parse_args()
    if not args.execute:print(json.dumps({'executed':False}));return 0
    report={'success':False,'synthetic':True,'results':[]};work=None;controllers=[]
    try:
        if json.loads((ROOT/'local-creation-test.json').read_text())!={'format':1,'purpose':'isolated-local-creation'}:raise ValueError()
        sys.path.insert(0,str(ROOT/'app'))
        from browser_core import BrowserController,CDP,sha256
        from browser_processes import profile_processes
        from configuration import Configuration
        from core_specs import supports_major
        from creation_fingerprint import creation_defaults,random_fingerprint,build_native
        from import_cookies import materialize
        from local_state import _dpapi_protect
        from local_signer import LocalSigner
        from portable_browser import capture_profile
        cores=args.cores.split(',')
        if any(not supports_major(core) for core in cores):raise ValueError()
        data=ROOT/'app/data';configuration=Configuration(data)
        work=Path(tempfile.mkdtemp(prefix='import-cookie-validation-',dir=ROOT/'analysis')).resolve()
        (work/'local-signing').mkdir()
        for name in ('local-signing/public.der','local-signing.lock'):shutil.copy2(data/name,work/name)
        signer=LocalSigner(data,load_private=False)
        for core in cores:
            folder=work/core;folder.mkdir();profile=folder/'profile';(profile/'Default').mkdir(parents=True)
            key=secrets.token_bytes(32)
            (profile/'Local State').write_text(json.dumps({'os_crypt':{'encrypted_key':base64.b64encode(b'DPAPI'+_dpapi_protect(key)).decode()}}),encoding='utf-8')
            (profile/'Default/Preferences').write_text('{}',encoding='utf-8')
            record=creation_defaults(core);record['fingerprint']=random_fingerprint(record['fingerprint']);record.update(id='fixture_'+core,seq=1)
            native,binary=build_native(configuration,record);signature=folder/'fingerprint.bin';signature.write_bytes(binary)
            executable=configuration.local_core(core)
            runtime={'alias':record['id'],'profile_path':str(profile),'core_path':str(executable),'core_sha256':sha256(executable),'core_major':core,
                'fingerprint_path':str(signature),'fingerprint_sha256':sha256(signature),'signature_provider':'local-v1','signature_key_id':signer.key_id,
                'new_profile':True,'has_launched':False,'restore_session':True,'initial_urls':[],'launch_args':[]}
            cookie={'name':'login','value':'synthetic','domain':'fixture.invalid','path':'/','secure':True,'httpOnly':True,'expires':time.time()+86400}
            record.update(_runtime=runtime,_native=native,_source_info={'cookie':json.dumps([cookie,
                {**cookie,'name':'session','session':True,'expires':-1},
                {**cookie,'name':'explicit_expiry','session':True}])})
            before_key=capture_profile(profile)
            materialize(SimpleNamespace(root=work),record,profile)
            controller=BrowserController(folder,settings={'windows':[runtime],'persistent':False});controller.root=work;controllers.append(controller)
            row={'core':core,'rounds':[]};report['results'].append(row)
            for round_number in range(2):
                if materialize(SimpleNamespace(root=work),record,profile):raise ValueError()
                controller.open(runtime['alias'],offline_test=True,extra_urls=['about:blank'])
                with CDP(controller.endpoint(runtime['alias'])) as connection:
                    values={v['name']:v for v in connection.call('Storage.getCookies')['cookies'] if v['domain']=='fixture.invalid'}
                    expected='synthetic' if round_number==0 else 'rotated'
                    checks={'persistent_cookie':values.get('login',{}).get('value')==expected,
                        'session_cookie':values.get('session',{}).get('value')=='synthetic' and values['session']['session'],
                        'explicit_expiry_overrides_session_hint':values.get('explicit_expiry',{}).get('value')=='synthetic' and not values['explicit_expiry']['session'],
                        'http_only':values.get('login',{}).get('httpOnly') is True}
                    if round_number==0:connection.call('Storage.setCookies',{'cookies':[{**cookie,'value':'rotated'}]})
                controller.close(runtime['alias'])
                checks['same_oscrypt_key']=capture_profile(profile)==before_key
                checks['same_native']=record['_native']==native
                row['rounds'].append(checks)
                if not all(checks.values()):raise ValueError()
            print(json.dumps({'core':core,'passed':True}),flush=True)
        report['success']=True
    except Exception as error:
        report['error_type']=type(error).__name__
        report['frames']=[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)[-5:]]
    finally:
        cleanup=True
        for controller in controllers:
            try:controller.close(next(iter(controller.profiles)))
            except Exception:cleanup=False
        if work is not None:
            if any(profile_processes(p.parent,require_inspectable=True) for p in work.glob('*/profile/Local State')):cleanup=False
            if cleanup and work.parent==(ROOT/'analysis').resolve() and not work.is_symlink():shutil.rmtree(work)
        report['cleanup_complete']=cleanup
        report['success']=report['success'] and cleanup
        path=ROOT/'analysis/reports/import-cookie-native-live.json';path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
    return 0 if report['success'] else 1


if __name__=='__main__':raise SystemExit(main())
