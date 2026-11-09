"""Measure rendering candidates against an unchanged synthetic source baseline.

Only the dedicated release fixture is accepted. Every measurement uses a new
empty probe; this never opens an account profile or registers another baseline.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
CANDIDATES=(
    ('original',(),False),
    ('normal-window',(),True),
    ('original-reduced-motion',('--force-prefers-reduced-motion',),False),
    ('original-no-reduced-motion',('--force-prefers-no-reduced-motion',),False),
    ('d3d11',('--use-angle=d3d11','--ignore-gpu-blocklist'),False),
    ('d3d11-no-compositing',('--use-angle=d3d11','--ignore-gpu-blocklist','--disable-gpu-compositing'),False),
    ('swiftshader',('--use-angle=swiftshader','--enable-unsafe-swiftshader'),False),
    ('software-canvas',('--disable-gpu',),False),
    ('srgb',('--force-color-profile=srgb',),False),
)


def changes(expected,actual):
    return sorted(key for key,value in expected.items() if actual.get(key)!=value)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--package',type=Path)
    args=parser.parse_args()
    if not args.execute:print(json.dumps({'executed':False}));return 0
    result={'executed':True,'diagnostic_only':True,'success':False,'candidates':[]};package=None;owned=[];validated=False
    try:
        if args.package is None:raise ValueError()
        package=args.package.resolve()
        sys.path[:0]=[str(package/'app'),str(package/'tools')]
        from verify_portable_fixture import _inside,load_fixture
        from inspect_installation import read_catalog
        import fingerprint_continuity as fc
        import browser_core
        from browser_processes import profile_processes
        _,record,data,profile=load_fixture(package)
        validated=True
        if profile_processes(profile,require_inspectable=True):raise ValueError()
        before=read_catalog(data,time.monotonic()+30)
        baseline=copy.deepcopy(record['_continuity']);expected=baseline['stable']
        signature=Path(record['_runtime']['fingerprint_path']);signature_digest=hashlib.sha256(signature.read_bytes()).hexdigest()
        original_open=browser_core.BrowserController.open;original_arguments=fc._launch_arguments
        original_popen=browser_core.subprocess.Popen
        core=Path(record['_runtime']['core_path']).resolve()
        current={'visible':False,'flags':(),'backend':'unknown'}

        def launch(arguments,*values,**options):
            paths=[str(arg).split('=',1)[1] for arg in arguments if str(arg).startswith('--user-data-dir=')]
            if (Path(arguments[0]).resolve()!=core or len(paths)!=1 or
                    Path(paths[0]).resolve().parent.parent!=data or
                    not Path(paths[0]).parent.name.startswith('continuity-probe-') or
                    '--proxy-server=http://127.0.0.1:1' not in arguments):raise ValueError()
            process=original_popen(arguments,*values,**options);owned.append(process);return process

        def open_probe(controller,alias,**options):
            if not options.get('background_probe') or not options.get('offline_test'):raise ValueError()
            if current['visible']:options.pop('background_probe')
            value=original_open(controller,alias,**options)
            try:
                with browser_core.CDP(controller.endpoint(alias),timeout=5) as c:
                    info=c.call('SystemInfo.getInfo');gpu=info.get('gpu',{})
                renderer=str(gpu.get('auxAttributes',{}).get('glRenderer','')).lower()
                current['backend']=next((name for name in ('swiftshader','d3d11','vulkan','opengl') if name in renderer),'other')
            except Exception:current['backend']='unknown'
            return value

        def probe_arguments(runtime):
            # Production validation still checks all original arguments. Only
            # this isolated diagnostic adds the named constant candidates.
            return original_arguments(runtime)+list(current['flags'])

        with patch.object(browser_core.subprocess,'Popen',side_effect=launch), \
                patch.object(browser_core.BrowserController,'open',new=open_probe), \
                patch.object(fc,'_launch_arguments',side_effect=probe_arguments):
            for name,flags,visible in CANDIDATES:
                current.update(visible=visible,flags=flags,backend='unknown')
                item={'candidate':name,'normal_window':visible};started=time.monotonic()
                try:
                    sample=fc.probe_snapshot(copy.deepcopy(record),data);values=sample['values']
                    item.update(measured=True,changed_fields=changes(expected,values),unstable_fields=sample.get('unstable',[]))
                    item['original_baseline_matches']=not item['changed_fields'] and not sample.get('unstable')
                    item['media_queries_changed']=sorted(key for key,value in expected.get('screen.media',{}).items()
                                                        if values.get('screen.media',{}).get(key)!=value)
                    wanted=expected.get('fonts.metrics',[]);actual=values.get('fonts.metrics',[])
                    item['font_family_indices_changed']=[index for index,value in enumerate(wanted)
                        if index>=len(actual) or actual[index]!=value]
                    for prefix in ('webgl1','webgl2'):
                        old=set(expected.get(prefix+'.extensions',[]));new=set(values.get(prefix+'.extensions',[]))
                        item[prefix+'_extensions_missing']=sorted(old-new)
                        item[prefix+'_extensions_extra']=sorted(new-old)
                    source=expected.get('devices.kinds',{});target=values.get('devices.kinds',{})
                    item['device_kind_counts_match']={key:target.get(key)==value for key,value in source.items()}
                except Exception as exc:item.update(measured=False,error_type=type(exc).__name__)
                item.update(actual_backend=current['backend'],seconds=round(time.monotonic()-started,2))
                result['candidates'].append(item);print(json.dumps(item),flush=True)
        after=read_catalog(data,time.monotonic()+30)
        result['catalog_unchanged']=before['catalog_full_tables_sha256']==after['catalog_full_tables_sha256']
        result['baseline_unchanged']=after['records'][0]['_continuity']==baseline
        result['native_signature_unchanged']=hashlib.sha256(signature.read_bytes()).hexdigest()==signature_digest
        result['success']=all(item['measured'] for item in result['candidates']) and all(
            result[key] for key in ('catalog_unchanged','baseline_unchanged','native_signature_unchanged'))
    except Exception as exc:result['error_type']=type(exc).__name__
    finally:
        result['owned_processes_exited']=all(process.poll() is not None for process in owned)
        result['success']=result['success'] and result['owned_processes_exited']
    if validated:
        try:
            destination=_inside(package/'analysis/reports/portable-candidates.json',package,exists=False)
            destination.parent.mkdir(parents=True,exist_ok=True)
            descriptor,name=tempfile.mkstemp(prefix='.portable-candidates-',suffix='.tmp',dir=destination.parent)
            temporary=Path(name)
            try:
                with os.fdopen(descriptor,'w',encoding='utf-8') as stream:
                    json.dump(result,stream,indent=2);stream.flush();os.fsync(stream.fileno())
                os.replace(temporary,destination)
            finally:temporary.unlink(missing_ok=True)
        except Exception as exc:result.update(success=False,report_error_type=type(exc).__name__)
    print(json.dumps(result));return 0 if result['success'] else 1


if __name__=='__main__':raise SystemExit(main())
