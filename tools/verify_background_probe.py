"""Explicit live test: empty profiles, existing signed configs, localhost only.

Never construct ManagerService, copy account profiles, update baselines or kill
processes. Output is limited to counts, safe field names and error classes.
"""
import argparse
import copy
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
sys.path.insert(0,str(ROOT/'tools'))

import browser_core
import fingerprint_continuity as continuity
from inspect_installation import read_catalog


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    if not args.execute:
        print(json.dumps({'executed':False,'requires_execute':True}));return 0
    summary={'success':False,'results':[],'test_window_observed':False,'test_foreground_observed':False}
    workspace=None;owned=[];stop=threading.Event();watcher=None
    try:
        data=ROOT/'app/data';before=read_catalog(data,time.monotonic()+30)
        records=before['records']
        workspace=Path(tempfile.mkdtemp(prefix='background-probe-validation-')).resolve()
        (workspace/'local-signing').mkdir()
        for name in ('local-signing/public.der','local-signing.lock'):
            shutil.copyfile(data/name,workspace/name)
        user=ctypes.WinDLL('user32',use_last_error=True)
        user.GetForegroundWindow.restype=wintypes.HWND
        user.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
        original_popen=browser_core.subprocess.Popen

        def launch(arguments,*values,**options):
            profiles=[value.split('=',1)[1] for value in arguments if value.startswith('--user-data-dir=')]
            private_desktop=getattr(options.get('startupinfo'),'lpDesktop','') or ''
            if (len(profiles)!=1 or not Path(profiles[0]).resolve().is_relative_to(workspace)
                    or ('--headless=new' not in arguments and not private_desktop.startswith('LocalContinuityProbe_'))
                    or arguments[-1]!='about:blank'):
                raise ValueError()
            process=original_popen(arguments,*values,**options);owned.append(process);return process

        def observe():
            try:
                while not stop.wait(.01):
                    active=[process.pid for process in tuple(owned) if process.poll() is None]
                    for pid in active:
                        if browser_core._visible_windows(pid):summary['test_window_observed']=True
                    foreground=wintypes.DWORD()
                    user.GetWindowThreadProcessId(user.GetForegroundWindow(),ctypes.byref(foreground))
                    if foreground.value in active:summary['test_foreground_observed']=True
            except Exception:summary['observation_failed']=True

        watcher=threading.Thread(target=observe,daemon=True);watcher.start()
        with patch.object(browser_core.subprocess,'Popen',side_effect=launch):
            for index,record in enumerate(records,1):
                started=time.monotonic();snapshot=continuity.probe_snapshot(copy.deepcopy(record),workspace)
                stable=record['_continuity']['stable']
                changed=[key for key,value in stable.items() if snapshot['values'].get(key)!=value or key in snapshot.get('unstable',[])]
                result={'window':index,'core':str(record['_runtime']['core_major']),
                    'passed':not changed,'stable_fields':len(stable),
                    'changed_fields':[key for key in changed if continuity._safe_field(key)],
                    'seconds':round(time.monotonic()-started,2)}
                summary['results'].append(result)
        after=read_catalog(data,time.monotonic()+30)
        summary['catalog_unchanged']=before['catalog_full_tables_sha256']==after['catalog_full_tables_sha256']
        summary['no_owned_browser_alive']=all(process.poll() is not None for process in owned)
        summary['no_probe_directories']=not list(workspace.glob('continuity-probe-*'))
        summary['success']=bool(records) and all(result['passed'] for result in summary['results']) and all(
            summary[key] for key in ('catalog_unchanged','no_owned_browser_alive','no_probe_directories'))
    except Exception as exc:summary['error_type']=type(exc).__name__
    finally:
        stop.set()
        if watcher is not None:watcher.join(timeout=2)
        summary['success']=summary['success'] and not any(summary.get(key) for key in
            ('test_window_observed','test_foreground_observed','observation_failed'))
        if workspace is not None:
            # A failed live probe can retain a running process. Preserve its
            # directory exactly as the production normal-close policy requires.
            if all(process.poll() is not None for process in owned) and not list(workspace.glob('continuity-probe-*')):
                if workspace.parent!=Path(tempfile.gettempdir()).resolve() or workspace.is_symlink():
                    summary['success']=False
                else:
                    try:shutil.rmtree(workspace)
                    except OSError:summary['success']=False
            else:summary['test_directory_retained']=True
    print(json.dumps(summary,ensure_ascii=False))
    return 0 if summary['success'] else 1


if __name__=='__main__':raise SystemExit(main())
