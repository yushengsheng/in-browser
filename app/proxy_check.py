"""Bounded proxy connectivity probes. Every fallback retains the same proxy."""
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from urllib.parse import quote

import requests

from proxy_config import normalize_proxy

PROBE_TARGETS=(
    {'name':'网络出口检测（ipify）','url':'https://api64.ipify.org?format=json'},
    {'name':'备用出口检测（ipify）','url':'https://api.ipify.org?format=json'},
    {'name':'备用出口检测（echoip）','url':'https://ifconfig.co/json'},
    {'name':'备用网络检测','url':'https://ipinfo.io/json'},
)
CHECK_TIMEOUT=10
_MAX_INPUT_BYTES=256*1024


def _failure(*,timed_out=False,attempts=None):
    result={'success':False,'message':('代理IP不可用：检测超过10秒，请更换代理或检查网络。' if timed_out else
        '代理IP不可用：连接、认证或出口检测失败。')+'未启动浏览器，也未改为直连。'}
    if timed_out:result['timed_out']=True
    if attempts is not None:result['attempts']=attempts
    return result

class ProxyChecker:
    def __init__(self,targets=None,*,require_geo=False):
        self.targets=targets or PROBE_TARGETS
        self.require_geo=require_geo

    def test(self,value):
        started=time.monotonic();deadline=started+CHECK_TIMEOUT
        proxy=normalize_proxy(value)
        payload=json.dumps({'proxy':proxy,'targets':self.targets,'deadline':deadline,'require_geo':self.require_geo},ensure_ascii=False).encode('utf-8')
        if len(payload)>_MAX_INPUT_BYTES:return _failure()
        executable=Path(sys.executable)
        if executable.name.casefold()=='pythonw.exe':executable=executable.with_name('python.exe')
        process=None
        try:
            # A process boundary also bounds DNS, TLS, and continuously slow bodies;
            # requests' socket timeout alone does not bound the whole response.
            process=subprocess.Popen([str(executable),'-E','-s','-B',str(Path(__file__).resolve()),'--probe-worker'],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            remaining=deadline-time.monotonic()
            if remaining<=0:return _failure(timed_out=True)
            output,_=process.communicate(payload,timeout=remaining)
            if time.monotonic()>=deadline or process.returncode==2:return _failure(timed_out=True)
            if process.returncode!=0 or len(output)>65536:return _failure()
            result=json.loads(output)
            if not isinstance(result,dict) or not isinstance(result.get('success'),bool):return _failure()
            if result['success']:
                ipaddress.ip_address(result['egress_ip'])
                result['elapsed_ms']=round((time.monotonic()-started)*1000)
            return result
        except subprocess.TimeoutExpired:
            return _failure(timed_out=True)
        except Exception:
            return _failure()
        finally:
            if process is not None:
                if process.poll() is None:process.kill()
                process.communicate()

    def _probe(self,value,deadline):
        proxy=normalize_proxy(value);kind=proxy['type'];mapping={}
        if kind=='ssh':
            from ssh_proxy import probe_route
            with probe_route(proxy) as port:
                return self._probe({'type':'http','host':'127.0.0.1','port':port},deadline)
        if kind!='noproxy':
            host=proxy['host'];host='['+host+']' if ':' in host else host
            auth=''
            if proxy['username'] or proxy['password']:auth=quote(proxy['username'],safe='')+':'+quote(proxy['password'],safe='')+'@'
            address=('socks5h' if kind=='socks5' else kind)+'://'+auth+host+':'+str(proxy['port'])
            mapping={'http':address,'https':address}
        started=time.monotonic();attempts=0
        for target in self.targets:
            remaining=deadline-time.monotonic()
            if remaining<1:break
            attempts+=1
            try:
                with requests.Session() as session:
                    session.trust_env=False
                    with session.get(target['url'],proxies=mapping,timeout=(min(4,remaining),min(6,remaining)),stream=True,allow_redirects=False) as response:
                        response.raise_for_status()
                        if response.status_code!=200:raise ValueError()
                        raw=bytearray()
                        for block in response.iter_content(4096):
                            raw.extend(block)
                            if len(raw)>65536 or time.monotonic()>deadline:raise ValueError()
                        data=json.loads(raw)
                        ip=str(data.get('ip') or data.get('query') or data.get('address') or '')
                        ipaddress.ip_address(ip)
                result={'success':True,'egress_ip':ip,'message':'代理连接与出口检测通过' if kind!='noproxy' else '网络连接成功',
                        'source':target['name'],'elapsed_ms':round((time.monotonic()-started)*1000)}
                if self.require_geo:
                    from creation_fingerprint import geo_result
                    result['geo']=geo_result(data)
                return result
            except Exception:continue
        return _failure(timed_out=time.monotonic()>=deadline,attempts=attempts)


def _worker():
    raw=sys.stdin.buffer.read(_MAX_INPUT_BYTES+1)
    if len(raw)>_MAX_INPUT_BYTES:raise ValueError()
    payload=json.loads(raw)
    deadline=float(payload['deadline'])
    remaining=min(CHECK_TIMEOUT,deadline-time.monotonic())
    if remaining<=0:return _failure(timed_out=True)
    # Also expire if the manager disappears while a socket/DNS operation blocks.
    watchdog=threading.Timer(remaining,lambda:os._exit(2));watchdog.daemon=True;watchdog.start()
    try:
        return ProxyChecker(targets=payload['targets'],require_geo=payload.get('require_geo') is True)._probe(payload['proxy'],deadline)
    finally:watchdog.cancel()


if __name__=='__main__' and sys.argv[1:]==['--probe-worker']:
    try:reply=_worker()
    except Exception:reply=_failure()
    sys.stdout.buffer.write(json.dumps(reply,ensure_ascii=False).encode('utf-8'))
