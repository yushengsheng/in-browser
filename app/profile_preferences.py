"""Apply explicit profile preferences; retain restoration metadata before writes."""
import copy
import json
import os
from pathlib import Path
import shutil

from local_state import LocalBrowserError


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
    values['clipboard']=2 if options['disable_clipboard'] else 1
    values['images']=2 if options['abort_images'] else 1
    if options['disable_clipboard']: profile.setdefault('content_settings',{}).setdefault('exceptions',{}).pop('clipboard',None)
    values['notifications']=2 if options['disable_notifications'] else 0
    if options['disable_notifications']:
        exceptions=profile.setdefault('content_settings',{}).setdefault('exceptions',{})
        if '_notification_previous' not in p: p['_notification_previous']=copy.deepcopy(exceptions.get('notifications',{}))
        exceptions.pop('notifications',None)
    elif '_notification_previous' in p:
        profile.setdefault('content_settings',{}).setdefault('exceptions',{})['notifications']=copy.deepcopy(p['_notification_previous'])
    download=service.settings()['download_dir']
    if download:
        destination=Path(download).expanduser()
        if not destination.is_absolute(): raise LocalBrowserError('下载目录须为绝对路径。')
        destination.mkdir(parents=True,exist_ok=True); data.setdefault('download',{}).update(default_directory=str(destination),prompt_for_download=False)
        p['_download_managed']=True
    elif p.get('_download_managed'):
        data.setdefault('download',{}).pop('default_directory',None); data['download'].pop('prompt_for_download',None)
        p['_download_managed']=False
    temporary=path.with_suffix('.local-tmp')
    # Persist restoration metadata before changing the browser's file. A later
    # catalog failure must not make a retry overwrite the original backup.
    service.store.put(p)
    if path.exists(): shutil.copy2(path,path.with_suffix('.local-backup'))
    with temporary.open('w',encoding='utf-8') as output: json.dump(data,output,ensure_ascii=False); output.flush(); os.fsync(output.fileno())
    os.replace(temporary,path)
    extension=service.root/'extensions'/p['id']
    if options['abort_media'] or options['abort_images'] or extension.exists():
        extension.mkdir(parents=True,exist_ok=True)
        manifest={'manifest_version':3,'name':'本地媒体加载控制','version':'1.0.0','permissions':['declarativeNetRequest'],
            'host_permissions':['<all_urls>'],'declarative_net_request':{'rule_resources':[{'id':'media','enabled':True,'path':'rules.json'}]}}
        types=(['media'] if options['abort_media'] else [])+(['image'] if options['abort_images'] else [])
        rules=[{'id':1,'priority':1,'action':{'type':'block'},'condition':{'urlFilter':'|','resourceTypes':types}}] if types else []
        (extension/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False),encoding='utf-8')
        (extension/'rules.json').write_text(json.dumps(rules),encoding='utf-8')
        p['_runtime']['managed_extension']=str(extension)
    if not options['disable_notifications']: p.pop('_notification_previous',None)
    p['_prefs_dirty']=False; service.store.put(p); service._sync(p)
