"""Explicit real-WebView creation flow in a marked synthetic installation."""
import argparse
import json
from pathlib import Path
import sys
import threading
import time
import traceback

ROOT=Path(__file__).resolve().parents[1]

EXPRESSION=r'''(async()=>{
  const q=s=>document.querySelector(s);
  const wait=async(predicate)=>{
    const deadline=Date.now()+240000;
    while(Date.now()<deadline){if(predicate())return;await new Promise(r=>setTimeout(r,100));}
    throw new Error('Synthetic UI timeout');
  };
  const checks={};
  await wait(()=>typeof state!=='undefined'&&state.connected&&!state.loading);
  checks.entries_visible=['#new-window-button','#batch-create-button','#create-button'].every(s=>q(s)&&!q(s).hidden&&q(s).getBoundingClientRect().width>0);
  q('#batch-create-button').click();
  await wait(()=>state.creatingDraft&&!q('#profile-drawer').hidden);
  await new Promise(resolve=>setTimeout(resolve,250));
  checks.batch_default=state.draft.creation.count===10;
  const set=(path,value)=>{
    const element=q(`[data-field="${path}"]`);
    element.value=value;element.dispatchEvent(new Event('input',{bubbles:true}));element.dispatchEvent(new Event('change',{bubbles:true}));
  };
  set('creation.count','2');set('name','Synthetic UI creation');
  q('[data-section="fingerprint"]').click();
  checks.fingerprint_editable=!q('[data-field="fingerprint.coreVersion"]').disabled;
  checks.all_cores=q('[data-field="fingerprint.coreVersion"]').options.length===22;
  set('fingerprint.os','MacIntel');
  checks.os_preset_applied=/Macintosh/.test(state.draft.fingerprint.userAgent);
  set('fingerprint.os','Win32');set('fingerprint.coreVersion','148');
  checks.drawer_visible=q('#profile-drawer').getBoundingClientRect().right<=innerWidth+1;
  const requestId=state.creation.requestId;
  q('#save-profile').click();
  await wait(()=>state.creation.job?.job_id===requestId&&!state.saving);
  await wait(()=>state.creation.job.state!=='running');
  checks.batch_completed=state.creation.job.state==='completed'&&state.creation.job.completed===2;
  checks.progress_visible=q('#creation-dialog').open&&q('#creation-summary').textContent.includes('2');
  await refreshProfiles();
  const ids=(state.creation.job.items||[]).filter(i=>i.state==='completed').map(i=>i.id);
  checks.records_listed=ids.length===2&&ids.every(id=>state.profiles.some(p=>p.id===id));
  return {checks,ids};
})()'''


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    if not parser.parse_args().execute:print(json.dumps({'executed':False}));return 0
    report={'success':False,'synthetic':True,'checks':{}};service=None;window=None;owned=[];before=set()
    try:
        marker=ROOT/'local-creation-test.json'
        if marker.is_symlink() or json.loads(marker.read_text())!={'format':1,'purpose':'isolated-local-creation'}:raise ValueError()
        sys.path.insert(0,str(ROOT/'app'))
        from installation import initialize_installation
        from manager_service import ManagerService
        from browser_processes import profile_processes
        initialize_installation();service=ManagerService()
        rows=service.store.all()
        if any(not r.get('created_locally') or r.get('username') or r.get('password') or r.get('cookie_text') or
               profile_processes(Path(r['_runtime']['profile_path']),require_inspectable=True) for r in rows):raise ValueError()
        before={r['id'] for r in rows}
        if service.creator().latest() and service.creator().latest()['state']=='running':raise ValueError()
        import webview
        webview.settings['WEBVIEW2_RUNTIME_PATH']=str(ROOT/'runtime/webview2')
        class Bridge:
            def request(self,action,payload=None):return service.request(action,payload)
        window=webview.create_window('本地创建功能验收',str(ROOT/'app/ui/index.html'),js_api=Bridge(),width=1460,height=920,min_size=(900,600))
        service.window=window
        def test():
            try:
                event=threading.Event();value={}
                def accept(result):
                    if isinstance(result,dict):value.update(result)
                    event.set()
                window.evaluate_js(EXPRESSION,callback=accept)
                if not event.wait(260):raise ValueError()
                report['checks']=value.get('checks') or {}
                owned.extend(value.get('ids') or [])
                report['success']=bool(report['checks']) and all(report['checks'].values())
            except Exception as error:
                report['error_type']=type(error).__name__
            finally:
                try:
                    for r in service.store.all():
                        if r['id'] not in before and r.get('created_locally') and r.get('name','').startswith('Synthetic UI creation') and r['id'] not in owned:owned.append(r['id'])
                    deleted=[]
                    for identity in owned:
                        record=service.store.get(identity)
                        if identity in before or not record.get('created_locally') or not record.get('name','').startswith('Synthetic UI creation'):raise ValueError()
                        deleted.append(service.delete(identity).get('cleanup_complete') is True)
                    report['checks']['owned_windows_deleted']=bool(deleted) and all(deleted)
                    report['success']=report['success'] and all(report['checks'].values())
                except Exception:report['success']=False;report['cleanup_failed']=True
                window.destroy()
        window.events.loaded+=lambda:threading.Thread(target=test,daemon=True).start()
        webview.start(gui='edgechromium',private_mode=True,storage_path=str(ROOT/'analysis/ui-validation-webview'))
    except Exception as error:
        report['error_type']=type(error).__name__
        report['frames']=[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)[-5:]]
    path=ROOT/'analysis/reports/creation-ui-live.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
    return 0 if report['success'] else 1


if __name__=='__main__':raise SystemExit(main())
