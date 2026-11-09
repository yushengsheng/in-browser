"""Explicit browser acceptance using empty profiles, local fixtures and test proxies.

No account profile is copied or opened. Credentials and returned IPs stay in memory.
"""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
import traceback
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'app'),str(ROOT/'tools')]
import browser_core
import ip_info_page
from browser_processes import profile_processes
from inspect_installation import read_catalog
from manager_service import ManagerService
from proxy_check import ProxyChecker
from verify_test_proxies import is_test_worker,load_proxies


def pages(service,identity):
    with browser_core.CDP(service.controller.endpoint(identity)) as c:
        return [p for p in c.call('Target.getTargets').get('targetInfos',[]) if p.get('type')=='page']


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    if not parser.parse_args().execute:print(json.dumps({'executed':False}));return 0
    report={'success':False,'checks':{}};work=None;service=None;servers=[];owned=[];workers=[];identities=[]
    def check(name,passed):
        report['checks'][name]=bool(passed)
        if not passed:raise AssertionError(name)
    try:
        original=read_catalog(ROOT/'app/data',time.monotonic()+30)
        template=next(p for p in original['records'] if str(p['_runtime']['core_major'])=='148')
        report['tested_core']='148'
        work=Path(tempfile.mkdtemp(prefix='proxy-ip-browser-')).resolve()
        for name in ('.portable-vault','local-signing'):shutil.copytree(ROOT/'app/data'/name,work/name)
        for name in ('local-signing.lock','independent-mode.bin','configuration-context.bin'):
            shutil.copy2(ROOT/'app/data'/name,work/name)
        config=work/'fixture-fingerprint.bin';shutil.copy2(template['_runtime']['fingerprint_path'],config)
        spec=importlib.util.spec_from_file_location('proxy_boundary_fixtures',ROOT/'analysis/browser-proxy-boundary-regression.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        origin=fixture.start(fixture.ThreadingHTTPServer(('127.0.0.1',0),fixture.Origin));servers.append(origin)
        http=fixture.start(fixture.ThreadingHTTPServer(('127.0.0.1',0),fixture.Proxy));servers.append(http)
        socks=fixture.start(fixture.TCP(('127.0.0.1',0),fixture.Socks));servers.append(socks)
        local_url=f'http://{fixture.DOMAIN}:{origin.server_port}'
        service=ManagerService(work)
        popen=browser_core.subprocess.Popen
        def launch(arguments,*values,**options):
            profiles=[str(arg).split('=',1)[1] for arg in arguments if str(arg).startswith('--user-data-dir=')]
            worker=is_test_worker(arguments,work,identities)
            if profiles:
                if len(profiles)!=1 or not Path(profiles[0]).resolve().is_relative_to(work):raise ValueError()
            process=popen(arguments,*values,**options)
            if profiles:owned.append(process)
            if worker:workers.append(process)
            return process
        def record_for(proxy):
            p=copy.deepcopy(template);identity='ip-page-'+uuid.uuid4().hex;identities.append(identity)
            p.update(id=identity,seq=len(identities),name='Isolated IP page test',proxy=proxy,urls=['about:blank'],
                platform='',username='',password='',cookie_text='',archived=False,_prefs_dirty=False,_cookie_pending=False)
            for key in list(p):
                if key.startswith('_source') or key in ('_portable_crypt','_continuity'):p.pop(key)
            p['preferences']['restore_session']=False
            profile=work/'profiles'/identity;(profile/'Default').mkdir(parents=True)
            (profile/'Default/Preferences').write_text('{}','utf-8')
            p['_runtime'].update(alias=identity,name=p['name'],profile_path=str(profile),fingerprint_path=str(config),
                new_profile=True,has_launched=False,restore_session=False,initial_urls=['about:blank'],open_urls_once=[],
                account_platform='',account_username='',account_password='',launch_args=['--disable-background-networking'])
            for key in ('managed_extension','local_proxy_port','local_proxy_mode'):p['_runtime'].pop(key,None)
            service.store.put(p);service._sync(p);return p
        with patch.object(browser_core.subprocess,'Popen',side_effect=launch):
            for kind,upstream,handler in (('http',http,fixture.Proxy),('socks5',socks,fixture.Socks)):
                proxy={'type':kind,'host':'127.0.0.1','port':upstream.server_address[1],'username':'fixture','password':'password'}
                p=record_for(proxy);identity=p['id'];info=local_url+'/info'
                service.configuration._proxy_targets=[{'name':'local fixture','url':local_url+'/ip'}]
                with patch.object(ip_info_page,'IP_INFO_URL',info),patch.object(ip_info_page,'_INFO_URLS',frozenset((info,))):
                    service.open(identity)
                    listed=pages(service,identity);check(kind+'_info_created',sum(t['url']==info for t in listed)==1)
                    deadline=time.monotonic()+10
                    while not browser_core._visible_windows(service.controller.state[identity]['pid']) and time.monotonic()<deadline:time.sleep(.1)
                    check(kind+'_browser_window_observed',bool(browser_core._visible_windows(service.controller.state[identity]['pid'])))
                    with browser_core.CDP(service.controller.endpoint(identity)) as c:
                        marker=c.call('Target.createTarget',{'url':local_url+'/account-marker'})['targetId']
                    before=pages(service,identity);service.open(identity);after=pages(service,identity)
                    check(kind+'_existing_window_preserves_tabs',len(before)==len(after) and any(t['targetId']==marker for t in after))
                    service.close(identity)
                    current=service.store.get(identity);current['preferences']['restore_session']=True
                    current['_runtime'].update(restore_session=True,initial_urls=[],open_urls_once=[])
                    service.store.put(current);service._sync(current);hits=fixture.Origin.hits.count('/info')
                    service.open(identity);listed=pages(service,identity)
                    check(kind+'_reopen_reuses_info',sum(t['url']==info for t in listed)==1)
                    check(kind+'_account_marker_restored',any(t['url']==local_url+'/account-marker' for t in listed))
                    deadline=time.monotonic()+5
                    while fixture.Origin.hits.count('/info')<=hits and time.monotonic()<deadline:time.sleep(.05)
                    check(kind+'_reopen_requests_through_proxy',fixture.Origin.hits.count('/info')>hits)
                    service.close(identity)
                    try:
                        handler.available=False;launches=len(owned);hits=len(fixture.Origin.hits)
                        try:service.open(identity);rejected=False
                        except browser_core.LocalBrowserError:rejected=True
                        check(kind+'_bad_proxy_refuses_launch_without_direct',rejected and len(owned)==launches and len(fixture.Origin.hits)==hits)
                    finally:handler.available=True
                check(kind+'_normal_close_releases_process',not profile_processes(Path(p['_runtime']['profile_path'])))
                print(json.dumps({'fixture_completed':kind}),flush=True)
            # The maintained real page is visited by the actual browser through
            # a supplied test proxy; only equality/loaded booleans are retained.
            row=load_proxies()[0];proxy={key:row[key] for key in ('host','port','username','password')};proxy['type']='socks5'
            p=record_for(proxy);identity=p['id'];del service.configuration._proxy_targets
            native_before=copy.deepcopy(p['_native']);signature_before=config.read_bytes()
            service.open(identity);listed=pages(service,identity)
            target=next(t for t in listed if t['url']==ip_info_page.IP_INFO_URL)
            with browser_core.CDP(service.controller.endpoint(identity),timeout=15) as c:
                session=c.call('Target.attachToTarget',{'targetId':target['targetId'],'flatten':True})['sessionId']
                deadline=time.monotonic()+25;loaded=False
                while time.monotonic()<deadline:
                    value=c.call('Runtime.evaluate',{'expression':'document.readyState==="complete" && document.title.toLowerCase().includes("ifconfig")','returnByValue':True},session=session)
                    if value.get('result',{}).get('value'):loaded=True;break
                    time.sleep(.2)
                check('real_echoip_page_loaded',loaded)
                response=c.call('Runtime.evaluate',{'expression':'fetch("/json",{cache:"no-store"}).then(r=>r.json()).then(v=>v.ip)','awaitPromise':True,'returnByValue':True},session=session)
                page_ip=response.get('result',{}).get('value');c.call('Target.detachFromTarget',{'sessionId':session})
            state=service.proxy_runtime.state(identity)
            checked=ProxyChecker().test({'type':'http','host':'127.0.0.1','port':state['port']})
            check('browser_exit_matches_same_relay_probe',checked.get('success') is True and bool(page_ip) and page_ip==checked.get('egress_ip'))
            check('native_and_signed_configuration_unchanged',service.store.get(identity)['_native']==native_before and config.read_bytes()==signature_before)
            service.close(identity)
        after=read_catalog(ROOT/'app/data',time.monotonic()+30)
        check('original_catalog_unchanged',original['catalog_full_tables_sha256']==after['catalog_full_tables_sha256'])
        report['success']=True
    except Exception as exc:
        report.update(error_type=type(exc).__name__,frames=[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(exc.__traceback__)])
        if isinstance(exc,AssertionError):report['failed_check']=str(exc)
    finally:
        if service:
            for identity in identities:
                try:service.close(identity)
                except Exception:pass
        safe=all(p.poll() is not None for p in owned+workers)
        if service:
            for identity in identities:
                try:
                    state=service.proxy_runtime.state(identity)
                    if state and service.proxy_runtime.owned(state):safe=False
                except Exception:safe=False
        for server in servers:
            server.shutdown();server.server_close()
        if work and safe:
            if (work.parent!=Path(tempfile.gettempdir()).resolve() or not work.name.startswith('proxy-ip-browser-')
                    or work.is_symlink() or any(p.is_symlink() or p.is_junction() for p in work.rglob('*'))):safe=False
            else:
                try:shutil.rmtree(work)
                except OSError:safe=False
        report['owned_processes_and_files_cleaned']=safe;report['success']=report['success'] and safe
    dest=ROOT/'analysis/reports/proxy-ip-browser.json';dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(report,indent=2),'utf-8');print(json.dumps(report))
    return 0 if report['success'] else 1


if __name__=='__main__':raise SystemExit(main())
