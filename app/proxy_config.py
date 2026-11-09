"""Single proxy text grammar shared by forms, imports and launch validation."""
import ipaddress
import re
from urllib.parse import unquote,urlsplit

from local_state import LocalBrowserError

PROTOCOLS={'http':'http','https':'https','socks5':'socks5','socks5h':'socks5','socks':'socks5','ssh':'ssh'}

def _fields(kind,host,port,username='',password=''):
    host=str(host or '').strip().strip('[]')
    if not host or any(c.isspace() or c in '/@|\\?#' for c in host): raise LocalBrowserError('代理主机格式无效。')
    if ':' in host:
        try: ipaddress.IPv6Address(host)
        except ValueError: raise LocalBrowserError('IPv6代理地址格式无效，请使用[地址]:端口。') from None
    try: port=int(port)
    except (TypeError,ValueError): raise LocalBrowserError('代理端口必须是整数。') from None
    if not 1<=port<=65535: raise LocalBrowserError('代理端口须在1到65535之间。')
    if kind not in ['http','https','socks5','ssh']: raise LocalBrowserError('不支持此代理协议。')
    if any(c in str(username)+str(password) for c in '\r\n\x00'): raise LocalBrowserError('代理认证信息不能包含换行或空字符。')
    return {'type':kind,'host':host,'port':port,'username':str(username),'password':str(password),'enable_socks5_udp':False}

def parse_proxy(text,default_type='socks5'):
    if not isinstance(text,str) or not text.strip() or len(text)>8192: raise LocalBrowserError('请粘贴一条有效代理，最多8192字符。')
    text=text.strip().replace('：',':')
    if '\n' in text or '\r' in text: raise LocalBrowserError('一次只能识别一条代理。')
    kind=default_type if default_type in ['http','https','socks5','ssh'] else 'socks5';scheme=re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*)://',text)
    if scheme:
        kind=PROTOCOLS.get(scheme.group(1).lower())
        if not kind: raise LocalBrowserError('只支持HTTP、HTTPS、SOCKS5和SSH代理。')
        text=text[scheme.end():]
    ignored=0
    if '|' in text:
        parts=[p.strip() for p in text.split('|')]
        if len(parts)<2: raise LocalBrowserError('代理格式应为主机|端口|用户名|密码。')
        host,port=parts[:2];username=parts[2] if len(parts)>2 else '';password=parts[3] if len(parts)>3 else '';ignored=max(0,len(parts)-4);format='pipe'
    elif '@' in text:
        try:
            parsed=urlsplit(kind+'://'+text)
            if parsed.path not in ['', '/'] or parsed.query or parsed.fragment: raise ValueError()
            host,port=parsed.hostname,parsed.port;username=unquote(parsed.username or '');password=unquote(parsed.password or '')
        except ValueError: raise LocalBrowserError('代理地址格式无效；支持协议://用户名:密码@主机:端口。') from None
        format='uri'
    else:
        if text.endswith('/'): text=text[:-1]
        match=re.fullmatch(r'\[([^\]]+)\]:(\d+)(?::([^:]*):(.+))?',text)
        if match: host,port,username,password=match.groups();username=username or '';password=password or '';format='ipv6'
        else:
            parts=text.split(':')
            if len(parts)==1 and re.search(r'\s',text): parts=re.split(r'\s+',text,maxsplit=4)
            if len(parts)!=2 and len(parts)<4: raise LocalBrowserError('支持主机:端口、主机:端口:用户名:密码，或用竖线分隔。')
            host,port=parts[:2];username=parts[2] if len(parts)>2 else '';password=parts[3] if len(parts)>3 else '';ignored=max(0,len(parts)-4);format='fields'
    return {'proxy':_fields(kind,host,port,username,password),'format':format,'ignored_metadata':ignored}

def normalize_proxy(value):
    if not isinstance(value,dict): raise LocalBrowserError('代理配置格式不正确。')
    kind=value.get('type','noproxy');host=str(value.get('host') or '').strip().replace('：',':')
    if any(mark in host for mark in ['://','|','@']) or (':' in host and not _is_ipv6(host)) or re.search(r'\s',host):
        return parse_proxy(host,kind)['proxy']
    if kind=='noproxy': return {'type':'noproxy','host':'','port':'','username':'','password':'','enable_socks5_udp':False}
    result=_fields(kind,host,value.get('port'),value.get('username') or '',value.get('password') or '')
    result['enable_socks5_udp']=bool(value.get('enable_socks5_udp',False));return result

def _is_ipv6(value):
    try:ipaddress.IPv6Address(value.strip('[]'));return True
    except ValueError:return False
