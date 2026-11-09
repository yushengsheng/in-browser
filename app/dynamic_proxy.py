"""Bounded, explicit proxy-provider extraction for locally created windows."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from urllib.parse import urlsplit

from local_state import LocalBrowserError
from proxy_config import normalize_proxy,parse_proxy

TIMEOUT=10
MAX_BYTES=65536


def validate_url(value):
    if not isinstance(value,str) or len(value)>8192:raise LocalBrowserError('代理提取链接格式无效。')
    if not value:return ''
    parsed=urlsplit(value)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.fragment or any(c in value for c in '\r\n\x00'):
        raise LocalBrowserError('代理提取链接须为完整的HTTP或HTTPS地址。')
    return value


def parse_result(raw,kind,fallback=None):
    """Accept one endpoint only; never silently choose one out of several."""
    fallback=fallback or {}
    text=raw.decode('utf-8-sig').strip() if isinstance(raw,bytes) else raw.strip()
    try:value=json.loads(text)
    except ValueError:value=text
    for _ in range(6):
        if isinstance(value,list):
            if len(value)!=1:raise ValueError()
            value=value[0];continue
        if isinstance(value,dict):
            if value.get('success') is False:raise ValueError()
            host=value.get('host') or value.get('ip') or value.get('server')
            port=value.get('port')
            if host and port:
                return normalize_proxy({'type':kind,'host':host,'port':port,
                    'username':value.get('username',value.get('user',fallback.get('username',''))),
                    'password':value.get('password',value.get('pass',fallback.get('password','')))})
            for field in ('data','result','proxy','proxies','list'):
                if field in value:value=value[field];break
            else:raise ValueError()
            continue
        if isinstance(value,str):
            lines=[line.strip() for line in value.splitlines() if line.strip()]
            if len(lines)!=1:raise ValueError()
            proxy=parse_proxy(lines[0],kind)['proxy']
            if not proxy['username'] and not proxy['password']:
                proxy.update(username=fallback.get('username',''),password=fallback.get('password',''))
            return normalize_proxy(proxy)
        raise ValueError()
    raise ValueError()


def fetch_proxy(url,kind='socks5',fallback=None):
    validate_url(url)
    if not url or kind not in ('http','https','socks5','ssh'):raise LocalBrowserError('请选择有效的提取代理协议。')
    try:
        result=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--extract-worker'],
            input=json.dumps({'url':url,'type':kind,'fallback':fallback or {}}).encode(),capture_output=True,
            timeout=TIMEOUT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        value=json.loads(result.stdout)
        if result.returncode or not value.get('success'):raise ValueError()
        return normalize_proxy(value['proxy'])
    except Exception:
        raise LocalBrowserError('10秒内未能提取到唯一有效代理，未启动浏览器，也未改为直连。请检查提取链接或服务商返回格式。') from None


def _worker():
    import requests
    raw=sys.stdin.buffer.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES:raise ValueError()
    payload=json.loads(raw);validate_url(payload['url'])
    with requests.Session() as session:
        session.trust_env=False
        with session.get(payload['url'],timeout=(4,6),stream=True,allow_redirects=False) as response:
            if response.status_code!=200:raise ValueError()
            data=bytearray()
            for chunk in response.iter_content(4096):
                data.extend(chunk)
                if len(data)>MAX_BYTES:raise ValueError()
    return {'success':True,'proxy':parse_result(data.decode('utf-8-sig'),payload['type'],payload['fallback'])}


def prepare_dynamic_proxy(service,record):
    if not record.get('created_locally') or not (record.get('created_options') or {}).get('dynamic_proxy_url'):return record
    import copy
    options=record['created_options']
    proxy=fetch_proxy(options['dynamic_proxy_url'],options['dynamic_proxy_type'],record['proxy'])
    if proxy==record['proxy']:return record
    service._closed(record);service.proxy_runtime.stop_if_unused(record['id'])
    updated=copy.deepcopy(record);updated['proxy']=proxy
    updated['_runtime']=service._runtime(updated,record['_runtime'])
    updated['_runtime'].pop('local_proxy_port',None)
    service.store.put(updated);service._sync(updated)
    return updated


if __name__=='__main__' and sys.argv[1:]==['--extract-worker']:
    watchdog=threading.Timer(TIMEOUT,lambda:os._exit(2));watchdog.daemon=True;watchdog.start()
    try:reply=_worker()
    except Exception:reply={'success':False}
    finally:watchdog.cancel()
    sys.stdout.buffer.write(json.dumps(reply).encode('utf-8'))
