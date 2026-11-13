"""Shared launch/extension rules for an explicitly selected browser proxy."""
import json
from pathlib import Path
import re

from local_state import LocalBrowserError

PROXY_SWITCHES={'--proxy-server','--proxy-bypass-list','--proxy-pac-url','--proxy-auto-detect',
    '--no-proxy-server','--host-resolver-rules','--force-webrtc-ip-handling-policy','--webrtc-ip-handling-policy',
    '--enable-quic','--disable-quic','--origin-to-force-quic-on'}
MANAGED_SWITCHES={'--user-data-dir','--fingerprint-config','--remote-debugging-port','--remote-debugging-address',
    '--profile-directory','--load-extension'}


def switch_name(argument):
    if not isinstance(argument,str) or any(ord(c)<32 or ord(c)==127 for c in argument):
        raise LocalBrowserError('启动参数格式无效，未启动浏览器。')
    name=argument.split('=',1)[0]
    if not re.fullmatch(r'--[A-Za-z0-9][A-Za-z0-9-]*',name):
        raise LocalBrowserError('启动参数格式无效，未启动浏览器。')
    return name.lower()


def validate_launch_args(arguments,*,proxy_active):
    for argument in arguments:
        name=switch_name(argument)
        if name in MANAGED_SWITCHES or proxy_active and name in PROXY_SWITCHES:
            raise LocalBrowserError('自定义启动参数不能覆盖资料、控制接口或受管代理规则。')


def verify_running_proxy_args(arguments,port):
    expected={'--proxy-server':'http://127.0.0.1:'+str(port),'--proxy-bypass-list':'<-loopback>',
              '--force-webrtc-ip-handling-policy':'disable_non_proxied_udp','--host-resolver-rules':'MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
              '--disable-quic':None}
    seen={}
    try:
        for argument in arguments:
            if not argument.startswith('--'):continue
            name=switch_name(argument)
            if name in PROXY_SWITCHES or name=='--disable-quic':
                if name not in expected or name in seen:return False
                seen[name]=argument.split('=',1)[1] if '=' in argument else None
        return seen==expected
    except (LocalBrowserError,TypeError,ValueError):return False


def _proxy_permission(value):
    if not isinstance(value,dict):return False
    return any(isinstance(value.get(field),list) and any(str(p).lower()=='proxy' for p in value[field])
               for field in ('permissions','api','optional_permissions'))


def verify_proxy_extensions(profile,managed_extension=None):
    """Reject enabled extensions able to replace the browser proxy settings."""
    manifests=[]
    try:
        for filename in ('Preferences','Secure Preferences'):
            path=Path(profile)/'Default'/filename
            if not path.is_file():continue
            if path.stat().st_size>16*1024*1024:raise ValueError()
            data=json.loads(path.read_text(encoding='utf-8-sig'))
            for entry in (data.get('extensions',{}).get('settings',{}) or {}).values():
                if not isinstance(entry,dict) or entry.get('state') not in (1,'1'):continue
                if any(_proxy_permission(entry.get(field)) for field in ('manifest','active_permissions','granted_permissions')):
                    raise LocalBrowserError('已启用扩展具有修改浏览器代理的权限，无法保证当前代理持续生效；请先正常禁用该扩展再打开。')
                raw=entry.get('path')
                if isinstance(raw,str) and raw:
                    folder=Path(raw)
                    if not folder.is_absolute():
                        if folder.drive or folder.root or '..' in folder.parts:raise ValueError()
                        folder=Path(profile)/'Default/Extensions'/folder
                    manifests.append(folder/'manifest.json')
        if managed_extension:manifests.append(Path(managed_extension)/'manifest.json')
        for manifest in manifests:
            if not manifest.is_file():continue
            if manifest.stat().st_size>1024*1024:raise ValueError()
            if _proxy_permission(json.loads(manifest.read_text(encoding='utf-8-sig'))):
                raise LocalBrowserError('已启用扩展具有修改浏览器代理的权限，无法保证当前代理持续生效；请先正常禁用该扩展再打开。')
    except LocalBrowserError:raise
    except (OSError,ValueError,TypeError):
        raise LocalBrowserError('无法核对浏览器扩展的代理权限，未启动；原资料未改动。') from None
