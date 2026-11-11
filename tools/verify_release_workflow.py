"""Explicit clean release creation, synthetic import and relocated storage acceptance."""
from __future__ import annotations
import argparse
import base64
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid
from contextlib import ExitStack
from unittest.mock import patch

HERE=Path(__file__).resolve()
PURPOSE={'format':1,'synthetic':True,'purpose':'clean-release-acceptance'}

def require(value):
    if not value:raise ValueError()

def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')

def fail(report,error):
    report['error_type']=type(error).__name__
    report['frames']=[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)[-8:]]

def digest(path):
    result=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):result.update(block)
    return result.hexdigest()

def tree(root):
    files={};dirs=[];file_max=0;dir_max=len(str(root).encode('utf-16-le'))//2
    for path in root.rglob('*'):
        require(not path.is_symlink() and not path.is_junction())
        length=len(str(path).encode('utf-16-le'))//2
        relative=path.relative_to(root).as_posix()
        if path.is_dir():dirs.append(relative);dir_max=max(dir_max,length)
        elif path.is_file():files[relative]={'size':path.stat().st_size,'sha256':digest(path)};file_max=max(file_max,length)
        else:raise ValueError()
    value={'files':dict(sorted(files.items())),'directories':sorted(dirs)}
    return value,{'file_count':len(files),'directory_count':len(dirs),'file_max_utf16':file_max,'directory_max_utf16':dir_max,
                  'tree_sha256':hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()}

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_GET(self):
        body=b'<!doctype html><title>Synthetic portable contract</title><p>Local synthetic fixture</p>'
        self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8')
        self.send_header('Content-Length',str(len(body)));self.end_headers()
        try:self.wfile.write(body)
        except OSError:pass

def phase(args):
    root=Path(args.root).resolve();data=root/'app/data'
    require(json.loads((root/'clean-release-test.json').read_text(encoding='utf-8'))==PURPOSE)
    sys.dont_write_bytecode=True
    sys.path[:0]=[str(root/'app'),str(root/'tools')]
    import psutil
    import browser_core
    import fingerprint_continuity
    import portable_browser
    from browser_processes import profile_processes
    from configuration import Configuration
    from creation_fingerprint import creation_defaults
    from installation import initialize_installation
    from local_state import read_encrypted,write_encrypted
    from manager_service import ManagerService
    from verify_login_storage import _evaluate,_observe,_origin_session,_indexed_db_expression
    from window_sync import WindowSynchronizer,source_key
    from window_create import WindowCreator
    report={'success':False,'synthetic':True,'phase':args.phase,'rounds':[],'physical_second_machine':False,
            'physical_external_drive':False,'simulated_other_user':args.phase=='verify','source_api_synthetic':True}
    service=None;active=None;owned=[];alias_calls=[];source_calls=[];continuity_calls=[];prepare_calls=[]
    original_popen=subprocess.Popen;original_verify=fingerprint_continuity.verify_continuity;original_prepare=portable_browser.prepare_profile
    origin='http://localhost:'+str(args.port)

    def launch(arguments,*pos,**kw):
        if isinstance(arguments,(list,tuple)):
            profiles=[Path(a.split('=',1)[1]).resolve() for a in arguments if isinstance(a,str) and a.startswith('--user-data-dir=')]
            if profiles:
                require(len(profiles)==1 and profiles[0].is_relative_to(root))
                executable=Path(arguments[0]).resolve();require(executable.is_relative_to(root))
                process=original_popen(arguments,*pos,**kw);seen=psutil.Process(process.pid)
                require(seen.ppid()==os.getpid() and Path(seen.exe()).samefile(executable))
                require(any(a.startswith('--user-data-dir=') for a in seen.cmdline()))
                owned.append((process,profiles[0],seen.create_time()));return process
        return original_popen(arguments,*pos,**kw)
    def verify(*pos,**kw):
        result=original_verify(*pos,**kw);continuity_calls.append(kw.get('allow_device_variance') is True);return result
    def prepare(*pos,**kw):
        result=original_prepare(*pos,**kw);prepare_calls.append(result);return result
    def no_alias(*pos,**kw):alias_calls.append(True);raise AssertionError()
    def no_source(*pos,**kw):source_calls.append(True);raise AssertionError()
    def close():
        if service is None or active is None:return
        state=service.controller.state.get(active,{})
        match=[entry for entry in owned if entry[0].pid==state.get('pid') and entry[0].poll() is None]
        if match:
            process,profile,created=match[0];seen=psutil.Process(process.pid)
            require(seen.ppid()==os.getpid() and seen.create_time()==created)
            require(profile==Path(service.store.get(active)['_runtime']['profile_path']).resolve())
            require(service.controller._record_valid(active));service.close(active)
    def attach(connection,url):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            pages=connection.call('Target.getTargets')['targetInfos']
            selected=[p for p in pages if p.get('type')=='page' and p.get('url')==url];require(len(selected)<=1)
            if selected:
                session=connection.call('Target.attachToTarget',{'targetId':selected[0]['targetId'],'flatten':True})['sessionId']
                if _evaluate(connection,session,'location.href==='+json.dumps(url)+'&&document.readyState==="complete"') is True:return session
                connection.call('Target.detachFromTarget',{'sessionId':session})
            time.sleep(.1)
        raise ValueError()
    def canonical_native(record):
        value=copy.deepcopy(record['_native']);font=value.get('FontConfig')
        if isinstance(font,dict) and isinstance(font.get('BasePath'),str):
            base=Path(font['BasePath']);require(base.is_relative_to(root/'app'))
            font['BasePath']='@app/'+base.relative_to(root/'app').as_posix()
        return value
    def snapshot(record):
        return {'native':canonical_native(record),'baseline':copy.deepcopy(record['_continuity']),
                'crypt':copy.deepcopy(record['_portable_crypt']),'binding':fingerprint_continuity.binding_for(record,data)}
    def observe(connection,record,saved):
        session=_origin_session(connection,origin)
        checks=_observe(connection,session,saved['marker'],record['_native'],origin)
        history=connection.call('Page.getNavigationHistory',session=session)
        checks['navigation_preserved']=([v['url'] for v in history['entries']]==saved['history'] and history['currentIndex']==saved['history_index'])
        deadline=time.monotonic()+15
        while True:
            pages=connection.call('Target.getTargets')['targetInfos']
            checks['two_tabs_restored']=all(sum(p.get('type')=='page' and p.get('url')==url for p in pages)==1 for url in (origin+'/',origin+'/extra'))
            if checks['two_tabs_restored'] or time.monotonic()>=deadline:break
            time.sleep(.1)
        connection.call('Target.detachFromTarget',{'sessionId':session});return checks

    started=time.monotonic()
    def trace_create(function):
        def wrapped(*pos,**kw):
            try:return function(*pos,**kw)
            except Exception as error:
                entry={};fail(entry,error)
                trace=error.__traceback__
                while trace:
                    if trace.tb_frame.f_code.co_name=='_font_names':
                        local=trace.tb_frame.f_locals
                        entry['configured_font_count']=len(local.get('configured',[]))
                        entry['probe_font_count']=len(local.get('names',[]))
                    trace=trace.tb_next
                report.setdefault('creation_diagnostics',[]).append(entry);raise
        return wrapped
    try:
        count=0
        for process in psutil.process_iter(['pid','name','exe','cmdline','ppid']):
            try:
                info=process.info
                if str(info.get('name') or '').casefold() not in ('bitbrowser.exe','chrome.exe'):continue
                require(info.get('exe') is not None and isinstance(info.get('cmdline'),list))
                require(not Path(info['exe']).resolve().is_relative_to(root));count+=1
            except psutil.NoSuchProcess:pass
        report['existing_browser_processes_checked']=count
        report['isolated_user_directories']=all(Path(os.environ[key]).is_dir() and not any(Path(os.environ[key]).iterdir()) for key in ('APPDATA','LOCALAPPDATA','USERPROFILE'))
        require(report['isolated_user_directories'])
        report['system_path_only']=all(Path(p).resolve().is_relative_to(Path(os.environ['SystemRoot']).resolve()) for p in os.environ['PATH'].split(os.pathsep))
        require(report['system_path_only'])
        with ExitStack() as stack:
            stack.enter_context(patch.object(WindowCreator,'_create',trace_create(WindowCreator._create)))
            stack.enter_context(patch.object(Configuration,'local_core',trace_create(Configuration.local_core)))
            stack.enter_context(patch.object(browser_core.subprocess,'Popen',launch))
            stack.enter_context(patch.object(fingerprint_continuity,'verify_continuity',verify))
            stack.enter_context(patch.object(portable_browser,'prepare_profile',prepare))
            if args.phase in ('verify','isolate'):
                stack.enter_context(patch.object(browser_core,'_short_executable_path',no_alias))
                for name in ('vendor','source_settings','source_detail','prepare_source'):
                    stack.enter_context(patch.object(Configuration,name,no_source))
            if args.phase=='seed':
                require(not data.exists());require(initialize_installation(data) is True)
                service=ManagerService(data);profile=creation_defaults('148')
                profile.update(name='Synthetic portable contract',urls=[origin+'/'])
                profile['created_options'].update(workbench='disable',random_each_open=False)
                profile['fingerprint'].update(fontType='2',font='Arial')
                creator=service.creator();job=creator.start({'request_id':uuid.uuid4().hex,'profile':profile,'count':1,'random_each':False})
                deadline=time.monotonic()+300
                while job['state']=='running' and time.monotonic()<deadline:time.sleep(.2);job=creator.status(job['job_id'])
                report['creation_completed']=job['state']=='completed' and job['completed']==1
                if not report['creation_completed']:
                    report['creation_failed_count']=job.get('failed');raise ValueError()
                active=job['items'][0]['id'];record=service.store.get(active)
                require(record['_native']['FontConfig']['Names'] and not record['_native']['FontConfig']['Files'])
                service.open(active,offline_test=True,extra_urls=[origin+'/'])
                saved=snapshot(record);saved['marker']=uuid.uuid4().hex
                with browser_core.CDP(service.controller.endpoint(active),timeout=8) as connection:
                    session=_origin_session(connection,origin)
                    for url in (origin+'/step',origin+'/'):
                        connection.call('Page.navigate',{'url':url},session=session)
                        connection.call('Target.detachFromTarget',{'sessionId':session});session=attach(connection,url)
                    connection.call('Storage.setCookies',{'cookies':[
                        {'name':'portable_release','value':saved['marker'],'url':origin,'expires':time.time()+86400},
                        {'name':'portable_session','value':saved['marker'],'url':origin}]})
                    require(_evaluate(connection,session,'localStorage.setItem("portable_release",'+json.dumps(saved['marker'])+');sessionStorage.setItem("portable_session",'+json.dumps(saved['marker'])+');true') is True)
                    require(_evaluate(connection,session,_indexed_db_expression(saved['marker'],seed=True)) is True)
                    require(all(_observe(connection,session,saved['marker'],record['_native'],origin).values()))
                    history=connection.call('Page.getNavigationHistory',session=session)
                    saved.update(history=[v['url'] for v in history['entries']],history_index=history['currentIndex'])
                    connection.call('Target.createTarget',{'url':origin+'/extra','newWindow':False,'background':False})
                    extra=attach(connection,origin+'/extra')
                    connection.call('Target.detachFromTarget',{'sessionId':extra});connection.call('Target.detachFromTarget',{'sessionId':session});time.sleep(2)
                close();require(not profile_processes(Path(record['_runtime']['profile_path']),require_inspectable=True))
                source=Path(args.source).resolve();require(not source.exists() and not source.is_relative_to(root))
                shutil.copytree(Path(record['_runtime']['profile_path']),source)
                source_id=uuid.uuid4().hex
                full={'id':source_id,'name':'Synthetic source import','seq':1,'url':[origin+'/'],'proxyType':'noproxy',
                      'browserFingerPrint':copy.deepcopy(record['fingerprint'])}
                full['browserFingerPrint']['extendOptions']={'DataProtect':copy.deepcopy(record['_native']['DataProtect'])}
                candidate={'source_key':source_key(source_id),'source_id':source_id,'profile_path':str(source),'status':'ready','info':copy.deepcopy(full),'_core_major':'148'}
                source_before=tree(source)[0]
                class Provider:
                    def discover(self):return [copy.deepcopy(candidate)]
                    def revalidate(self,value):
                        require(value['source_id']==source_id and tree(source)[0]==source_before);return copy.deepcopy(candidate)
                    def startup(self,value):return {'info':copy.deepcopy(full),'core_path':record['_runtime']['core_path']}
                def build_source(_self,info,**kw):
                    require(info['id']==source_id);native=copy.deepcopy(record['_native'])
                    return native,_self.sign(native,core_major='148')
                sync=WindowSynchronizer(service,provider=Provider());service._synchronizer=sync
                with patch.object(Configuration,'build_source',build_source):
                    require(sync.preview()['counts']['ready']==1);job=sync.start([candidate['source_key']]);deadline=time.monotonic()+300
                    job=sync.status(job['job_id'])
                    while job['state']=='running' and time.monotonic()<deadline:time.sleep(.2);job=sync.status(job['job_id'])
                report['sync_completed']=job['state']=='completed' and job['completed']==1
                if not report['sync_completed']:
                    report['sync_diagnostics']=[{'type':v['type'],'frames':v['frames']} for v in sync.diagnostics.get(job['job_id'],[])];raise ValueError()
                imported=service.store.source_binding(candidate['source_key']);require(imported and imported!=active)
                require(tree(source)[0]==source_before)
                records={active:copy.deepcopy(saved),imported:dict(snapshot(service.store.get(imported)),marker=saved['marker'],history=saved['history'],history_index=saved['history_index'])}
                for identity,expected in records.items():
                    active=identity;service.open(identity,offline_test=True)
                    with browser_core.CDP(service.controller.endpoint(identity),timeout=8) as connection:checks=observe(connection,service.store.get(identity),expected)
                    close();require(all(checks.values()))
                write_encrypted(data/'workflow-fixture.bin',{'records':records,'original_root':str(root),'original_source':str(source),'source_id':source_id},root=data)
                with service.store.connect() as con:con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                report.update(profile_count=len(records),baseline_fields=[len(v['baseline']['stable']) for v in records.values()],
                              filtered_fonts=True,source_unchanged=True,real_copy_capture_baseline_publish_commit=True,five_storage_types_seeded=True,two_tabs_navigation_seeded=True)
            elif args.phase=='isolate':
                service=ManagerService(data);fixture=read_encrypted(data/'workflow-fixture.bin',root=data)
                active=next(iter(fixture['records']));expected=fixture['records'][active]
                service.open(active,offline_test=True)
                barrier=Path(args.barrier);role=args.role;require(role in ('a','b'))
                def mark(name):save(barrier/(role+'-'+name+'.json'),{'ready':True})
                def wait(name):
                    deadline=time.monotonic()+120
                    while time.monotonic()<deadline:
                        if (barrier/name).is_file():return
                        time.sleep(.1)
                    raise TimeoutError()
                with browser_core.CDP(service.controller.endpoint(active),timeout=8) as connection:
                    session=_origin_session(connection,origin)
                    require(_evaluate(connection,session,'localStorage.setItem("portable_isolation",'+json.dumps(role)+');localStorage.getItem("portable_isolation")==='+json.dumps(role)) is True)
                    connection.call('Target.detachFromTarget',{'sessionId':session})
                mark('open');wait(('b' if role=='a' else 'a')+'-open.json')
                if role=='a':
                    with browser_core.CDP(service.controller.endpoint(active),timeout=8) as connection:
                        checks=observe(connection,service.store.get(active),expected)
                        session=_origin_session(connection,origin)
                        checks['own_storage_unchanged']=_evaluate(connection,session,'localStorage.getItem("portable_isolation")==="a"') is True
                        connection.call('Target.detachFromTarget',{'sessionId':session})
                    close();mark('closed');wait('b-closed.json')
                    checks['normal_close_independent']=not profile_processes(Path(service.store.get(active)['_runtime']['profile_path']),require_inspectable=True)
                    report['checks']=checks
                else:
                    wait('a-closed.json')
                    require(service.controller._record_valid(active))
                    with browser_core.CDP(service.controller.endpoint(active),timeout=8) as connection:
                        checks=observe(connection,service.store.get(active),expected)
                        session=_origin_session(connection,origin)
                        checks['own_storage_unchanged']=_evaluate(connection,session,'localStorage.getItem("portable_isolation")==="b"') is True
                        connection.call('Target.detachFromTarget',{'sessionId':session})
                    checks['sibling_closed_this_still_open']=service.controller._record_valid(active)
                    close();mark('closed');checks['normal_close']=not profile_processes(Path(service.store.get(active)['_runtime']['profile_path']),require_inspectable=True)
                    report['checks']=checks
                require(all(report['checks'].values()));report.update(same_profile_id_from_clone=True,same_keys_from_clone=True,source_api_calls=len(source_calls))
            else:
                require(args.phase=='verify');service=ManagerService(data);fixture=read_encrypted(data/'workflow-fixture.bin',root=data)
                require(not Path(fixture['original_root']).exists() and not Path(fixture['original_source']).exists())
                report['old_paths_unavailable']=True;report['profile_count']=len(fixture['records'])
                report['root_utf16']=len(str(root).encode('utf-16-le'))//2;require(report['root_utf16']<=80)
                corrupt={}
                for identity,expected in fixture['records'].items():
                    record=service.store.get(identity);path=Path(record['_runtime']['profile_path'])/'Local State'
                    value=json.loads(path.read_text(encoding='utf-8'));value['os_crypt']['encrypted_key']=base64.b64encode(b'DPAPI'+b'synthetic-invalid-wrapper').decode()
                    path.write_text(json.dumps(value),encoding='utf-8');corrupt[identity]=digest(path)
                    try:portable_browser._unwrap(value['os_crypt']['encrypted_key'])
                    except Exception:pass
                    else:raise ValueError()
                report['old_dpapi_wrappers_unreadable']=True
                for identity,expected in fixture['records'].items():
                    for round_index in range(2):
                        active=identity;before=len(continuity_calls);before_prepare=len(prepare_calls)
                        service.open(identity,offline_test=True)
                        record=service.store.get(identity)
                        with browser_core.CDP(service.controller.endpoint(identity),timeout=8) as connection:checks=observe(connection,record,expected)
                        close();current=service.store.get(identity);current_snapshot=snapshot(current)
                        checks.update(native_normalized_preserved=current_snapshot['native']==expected['native'],baseline_preserved=current_snapshot['baseline']==expected['baseline'],
                                      portable_key_preserved=current_snapshot['crypt']==expected['crypt'],binding_preserved=current_snapshot['binding']==expected['binding'],
                                      formal_continuity=any(continuity_calls[before:]),formal_prepare=len(prepare_calls)>before_prepare,
                                      normal_close=not profile_processes(Path(current['_runtime']['profile_path']),require_inspectable=True),
                                      no_short_alias=not alias_calls,no_source_api=not source_calls)
                        if round_index==0:checks['dpapi_same_key_rewrapped']=any(prepare_calls[before_prepare:])
                        else:checks['dpapi_wrapper_reused']=not any(prepare_calls[before_prepare:])
                        report['rounds'].append({'profile_index':list(fixture['records']).index(identity)+1,'round':round_index+1,'checks':checks})
                        require(all(checks.values()))
                report.update(short_alias_calls=len(alias_calls),source_api_calls=len(source_calls))
            report['success']=True
    except Exception as error:fail(report,error)
    finally:
        try:close()
        except Exception as error:report['close_error_type']=type(error).__name__;report['success']=False
        report['owned_browser_count']=len(owned);report['owned_processes_exited']=all(p.poll() is not None for p,_,_ in owned)
        report['owned_process_exit_codes']=[p.poll() for p,_,_ in owned]
        report['success']=report['success'] and report['owned_processes_exited'];report['elapsed_seconds']=round(time.monotonic()-started,1)
        save(Path(args.report),report);print(json.dumps(report,ensure_ascii=False),flush=True)
    return 0 if report['success'] else 1


def clean_environment(base):
    """Only Windows platform variables and newly created empty user folders."""
    platform=('SystemRoot','WINDIR','COMSPEC','SystemDrive','ProgramFiles','ProgramFiles(x86)',
              'ProgramW6432','CommonProgramFiles','CommonProgramFiles(x86)','CommonProgramW6432',
              'ProgramData','ALLUSERSPROFILE','PUBLIC','OS','PROCESSOR_ARCHITECTURE',
              'PROCESSOR_IDENTIFIER','PROCESSOR_LEVEL','PROCESSOR_REVISION','NUMBER_OF_PROCESSORS')
    env={key:os.environ[key] for key in platform if key in os.environ}
    env['PATH']=os.pathsep.join(str(Path(os.environ['SystemRoot'])/p) for p in ('System32','','System32/Wbem'))
    env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',PYTHONUTF8='1',PYTHONIOENCODING='utf-8')
    for key,folder in (('APPDATA','a'),('LOCALAPPDATA','l'),('USERPROFILE','u'),('HOME','u'),('TEMP','t'),('TMP','t')):
        path=base/folder;path.mkdir(parents=True,exist_ok=True);env[key]=str(path)
    return env


def orchestrate(args):
    package=Path(args.package).resolve();work=Path(args.work_dir).absolute();report_path=Path(args.report).absolute()
    report={'success':False,'synthetic':True,'phases':[], 'physical_second_machine':False,
            'physical_external_drive':False,'same_physical_windows_user':True,
            'dpapi_failure_simulated':True,'source_api_synthetic':True}
    server=None;children=[]
    try:
        require(os.name=='nt' and not (package/'app/data').exists())
        require(not work.exists() and not work.is_symlink() and work.parent.is_dir())
        require(not work.is_relative_to(package) and not package.is_relative_to(work))
        require(not report_path.is_relative_to(work) and not report_path.is_relative_to(package))
        require(len(str(work).encode('utf-16-le'))//2<=60)
        # Verify the public distribution again before introducing synthetic data.
        sys.path[:0]=[str(package/'tools'),str(package/'app')]
        from portable_transfer import release_inventory,TransferDeadline
        release_inventory(package,TransferDeadline(120,None))
        original,original_summary=tree(package)
        require(original_summary['file_count']<=40000)
        work.mkdir();seed=work/'A';sibling=work/'B';source=work/'synthetic-source'
        moved=work.with_name(work.name+'-moved');retained=work.with_name(work.name+'-retained')
        require(not moved.exists() and not retained.exists())
        shutil.copytree(package,seed)
        require(tree(seed)[0]==original)
        save(seed/'clean-release-test.json',PURPOSE)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
        server_thread=threading.Thread(target=server.serve_forever,daemon=True);server_thread.start()
        def command_for(name,selected,envbase,role=None):
            destination=report_path.parent/('clean-'+name+('-'+role if role else '')+'.json')
            command=[str(selected/'runtime/python/python.exe'),'-B',str(selected/'tools/verify_release_workflow.py'),
                     '--execute','--phase',name,'--root',str(selected),'--source',str(source),
                     '--port',str(server.server_port),'--report',str(destination)]
            if role:command.extend(['--role',role,'--barrier',str(work/'barrier')])
            return command,clean_environment(envbase),destination
        def collect(name,returncode,destination):
            require(destination.is_file() and destination.stat().st_size<=256*1024)
            value=json.loads(destination.read_text(encoding='utf-8'))
            require(isinstance(value,dict) and value.get('synthetic') is True)
            report['phases'].append(value);save(report_path,report)
            print(json.dumps({'phase':name,'success':value.get('success') is True}),flush=True)
            require(returncode==0 and value.get('success') is True)
        def run(name,selected,envbase):
            command,env,destination=command_for(name,selected,envbase)
            completed=subprocess.run(command,cwd=selected,env=env,stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=900)
            collect(name,completed.returncode,destination)
        run('seed',seed,work/'e-seed')
        shutil.copytree(seed,sibling)
        for role,selected in (('a',seed),('b',sibling)):
            command,env,destination=command_for('isolate',selected,work/('e-isolate-'+role),role)
            children.append((role,subprocess.Popen(command,cwd=selected,env=env,stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL),destination))
        for role,process,destination in children:
            collect('isolate-'+role,process.wait(timeout=240),destination)
        report['same_parent_sibling_isolation']=True
        # Exercise the shipped migration entry point, including manifest, closed-profile,
        # directory-key and full-tree verification. The source remains untouched.
        transfer=subprocess.run([str(seed/'runtime/python/python.exe'),'-B',str(seed/'tools/portable_transfer.py'),
                                 '--execute','--source',str(seed),'--destination',str(moved)],
                                cwd=seed,env=clean_environment(work/'e-transfer'),stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=900)
        require(len(transfer.stdout)<=256*1024 and transfer.returncode==0)
        lines=[json.loads(line) for line in transfer.stdout.decode('utf-8').splitlines() if line.startswith('{')]
        migration=next((item for item in reversed(lines) if item.get('success') is True),None)
        require(migration and migration.get('source_unchanged') is True and migration.get('verified') is True
                and migration.get('windows')==2)
        report['migration']={key:migration[key] for key in ('success','files','windows','source_unchanged','verified')}
        save(moved/'clean-release-test.json',PURPOSE)
        # Make all old package and synthetic source paths unavailable without deleting them.
        os.rename(work,retained)
        require(not work.exists());report['old_paths_unavailable']=True
        run('verify',moved,retained/'e-verify')
        report['public_package_unchanged']=tree(package)[0]==original
        require(report['public_package_unchanged'])
        report['success']=True
    except Exception as error:
        fail(report,error)
    finally:
        if any(process.poll() is None for _,process,_ in children):
            report['owned_child_still_running']=True;report['success']=False
        if server:
            server.shutdown();server.server_close();server_thread.join(timeout=2)
        save(report_path,report);print(json.dumps(report,ensure_ascii=False),flush=True)
    return 0 if report['success'] else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--package',type=Path)
    parser.add_argument('--work-dir',type=Path)
    parser.add_argument('--report',type=Path)
    parser.add_argument('--phase',choices=('seed','verify','isolate'))
    parser.add_argument('--root');parser.add_argument('--source');parser.add_argument('--port',type=int)
    parser.add_argument('--role',choices=('a','b'));parser.add_argument('--barrier')
    args=parser.parse_args()
    if not args.execute:print(json.dumps({'executed':False}));return 0
    require(args.report is not None)
    if args.phase:
        require(args.root and args.source and args.port and 0<args.port<65536)
        return phase(args)
    require(args.package and args.work_dir)
    return orchestrate(args)


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'success':False,'error_type':type(error).__name__}),flush=True);raise SystemExit(1)
