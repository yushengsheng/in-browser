"""Apply explicit profile preferences; retain restoration metadata before writes."""
import copy
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

from local_state import LocalBrowserError


def _first_clipboard_prompt(record):
    runtime=record.get('_runtime') or {}
    return (record.get('created_locally') and runtime.get('new_profile')
            and not runtime.get('has_launched')
            and not record.get('preferences',{}).get('disable_clipboard'))


def prepare_clipboard(record):
    """Apply the stock launch preference without recalculating the fingerprint."""
    from browser_processes import profile_processes
    profile=Path(record['_runtime']['profile_path'])
    path=profile/'Default/Preferences'
    if profile_processes(profile,require_inspectable=True):
        raise LocalBrowserError('窗口资料正在使用，未修改剪贴板设置；请正常关闭后重试。')
    try:
        before=path.lstat()
        if (not stat.S_ISREG(before.st_mode) or path.is_symlink()
                or getattr(before,'st_file_attributes',0)&stat.FILE_ATTRIBUTE_REPARSE_POINT
                or before.st_size>16*1024*1024):raise ValueError()
        raw=path.read_bytes()
        data=json.loads(raw.decode('utf-8-sig'))
        disabled=bool(record.get('preferences',{}).get('disable_clipboard'))
        settings=data.get('profile',{}).get('default_content_setting_values',{})
        exceptions=data.get('profile',{}).get('content_settings',{}).get('exceptions',{})
        desired=None if _first_clipboard_prompt(record) else 2 if disabled else 1
        matches='clipboard' not in settings if desired is None else settings.get('clipboard')==desired
        cleared=not disabled or ('clipboard' not in exceptions and data.get('clipboard')=={})
        if matches and cleared:return False
        values=data.setdefault('profile',{}).setdefault('default_content_setting_values',{})
        if desired is None:values.pop('clipboard',None)
        else:values['clipboard']=desired
        if disabled:
            data['clipboard']={}
            data['profile'].setdefault('content_settings',{}).setdefault('exceptions',{}).pop('clipboard',None)
        if path.read_bytes()!=raw or profile_processes(profile,require_inspectable=True):raise ValueError()
        descriptor,name=tempfile.mkstemp(prefix='.clipboard-',suffix='.tmp',dir=path.parent)
        temporary=Path(name)
        try:
            with os.fdopen(descriptor,'w',encoding='utf-8') as output:
                json.dump(data,output,ensure_ascii=False);output.flush();os.fsync(output.fileno())
            if path.read_bytes()!=raw or profile_processes(profile,require_inspectable=True):raise ValueError()
            backup=path.with_suffix('.clipboard-backup')
            if not backup.exists():
                with backup.open('xb') as output:output.write(raw);output.flush();os.fsync(output.fileno())
            os.replace(temporary,path)
        finally:temporary.unlink(missing_ok=True)
        return True
    except (OSError,ValueError,TypeError,AttributeError):
        raise LocalBrowserError('剪贴板设置未能完整准备，窗口资料未覆盖；请保留资料后重试。') from None


def apply_preferences(service,p):
    if not p.get('_prefs_dirty'): return
    folder=Path(p['_runtime']['profile_path'])/'Default'; folder.mkdir(parents=True,exist_ok=True)
    path=folder/'Preferences'; data=json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}
    options=p['preferences']; data.setdefault('signin',{}).update(allowed=options['allowed_signin'],allowed_on_next_startup=options['allowed_signin'])
    data['credentials_enable_service']=options['credentials_service']
    if options['disable_translate']:
        data.setdefault('translate',{})['enabled']=False; data.setdefault('translate_ignored_count_for_language',{})['en']=2
    else: data.pop('translate',None)
    profile=data.setdefault('profile',{}); values=profile.setdefault('default_content_setting_values',{})
    if _first_clipboard_prompt(p):values.pop('clipboard',None)
    else:values['clipboard']=2 if options['disable_clipboard'] else 1
    limit_images=bool(p.get('created_locally') and p.get('created_options',{}).get('image_limit_kb'))
    values['images']=2 if options['abort_images'] and not limit_images else 1
    if options['disable_clipboard']: profile.setdefault('content_settings',{}).setdefault('exceptions',{}).pop('clipboard',None)
    values['notifications']=2 if options['disable_notifications'] else 0
    if options['disable_notifications']:
        exceptions=profile.setdefault('content_settings',{}).setdefault('exceptions',{})
        if '_notification_previous' not in p: p['_notification_previous']=copy.deepcopy(exceptions.get('notifications',{}))
        exceptions.pop('notifications',None)
    elif '_notification_previous' in p:
        profile.setdefault('content_settings',{}).setdefault('exceptions',{})['notifications']=copy.deepcopy(p['_notification_previous'])
    download=service.settings()['download_dir']
    download_managed=p.get('_download_managed',False)
    if download:
        destination=Path(download).expanduser()
        if not destination.is_absolute(): raise LocalBrowserError('下载目录须为绝对路径。')
        destination.mkdir(parents=True,exist_ok=True); data.setdefault('download',{}).update(default_directory=str(destination),prompt_for_download=False)
        p['_download_managed']=True;download_managed=True
    elif p.get('_download_managed'):
        data.setdefault('download',{}).pop('default_directory',None); data['download'].pop('prompt_for_download',None)
        download_managed=False
    temporary=path.with_suffix('.local-tmp')
    # Persist restoration metadata before changing the browser's file. A later
    # catalog failure must not make a retry overwrite the original backup.
    service.store.put(p)
    if path.exists(): shutil.copy2(path,path.with_suffix('.local-backup'))
    with temporary.open('w',encoding='utf-8') as output: json.dump(data,output,ensure_ascii=False); output.flush(); os.fsync(output.fileno())
    os.replace(temporary,path)
    if '_download_managed' in p:p['_download_managed']=download_managed
    extension=service.root/'extensions'/p['id']
    if options['abort_media'] or options['abort_images'] or extension.exists():
        extension.mkdir(parents=True,exist_ok=True)
        manifest={'manifest_version':3,'name':'本地媒体加载控制','version':'1.0.0','permissions':['declarativeNetRequest'],
            'host_permissions':['<all_urls>'],'declarative_net_request':{'rule_resources':[{'id':'media','enabled':True,'path':'rules.json'}]}}
        types=(['media'] if options['abort_media'] else [])+(['image'] if options['abort_images'] and not limit_images else [])
        rules=[{'id':1,'priority':1,'action':{'type':'block'},'condition':{'urlFilter':'|','resourceTypes':types}}] if types else []
        (extension/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False),encoding='utf-8')
        (extension/'rules.json').write_text(json.dumps(rules),encoding='utf-8')
        p['_runtime']['managed_extension']=str(extension)
    if not options['disable_notifications']: p.pop('_notification_previous',None)
    p['_prefs_dirty']=False; service.store.put(p); service._sync(p)
