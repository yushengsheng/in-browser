"""Single proxy text grammar shared by forms, imports and launch validation."""
from datetime import datetime
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


_BULK_SCHEME=r'(?:(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)[:：]//)?'
_BULK_PORT=(
    r'(?:[ \u3000]*(?P<token>[:：][|｜]|[|｜][:：]|----|[,，:：|｜;；、\t])[ \u3000]*|(?P<space>[ \u3000]+))'
    r'(?P<port>[0-9]+)')
_BULK_HEAD=re.compile(_BULK_SCHEME+r'(?P<host>\[[^\[\]\\\r\n]+\]|(?:(?!----)[^\s\\/@?#\[\],，:：|｜;；、])+)'+_BULK_PORT)
_BULK_BARE_IPV6=re.compile(_BULK_SCHEME+r'(?P<host>[0-9a-fA-F.:]+(?:%[\w.-]+)?)(?=[ \u3000]*[|｜])'+_BULK_PORT)
_BULK_SPACES=re.compile(r'[ \u3000]+')
_BULK_PIPE_AFTER_PORT=re.compile(r'[ \u3000]*([|｜])')
_BULK_LEADING=re.compile(r'[\s\\]*')
_BULK_END_PORT=re.compile(r'[ \u3000]*\\')
_BULK_FORMAT='请使用同一种分隔符填写主机、端口，可再填写账号、密码及一栏到期日期。'


def _bulk_head(line,start=0):
    limit=min(len(line),start+8192)
    head=_BULK_HEAD.match(line,start,limit)
    if not head or head['token'] in (':','：'):
        bare=_BULK_BARE_IPV6.match(line,start,limit)
        if bare and _is_ipv6(bare['host']):
            return bare
    return head


def _bulk_separator(head):
    token=head['token']
    if token is None:
        return _BULK_SPACES
    if token in (':','：'):
        # Suppliers also use host:port|account|password.
        mixed=_BULK_PIPE_AFTER_PORT.match(head.string,head.end())
        if mixed:
            token=mixed[1]
    return re.compile(re.escape(token))


def _bulk_proxy_rows(text):
    for line in re.split(r'[\r\n]+',text):
        start=0
        while (start:=_BULK_LEADING.match(line,start).end())<len(line):
            end=len(line)
            if line.find('\\',start)>=0 and (head:=_bulk_head(line,start)):
                after_port=head.end()
                if marker:=_BULK_END_PORT.match(line,after_port):
                    end=marker.end()-1
                else:
                    # Only the third separator after the port opens metadata.
                    # All preceding backslashes belong to the credentials.
                    separator=_bulk_separator(head)
                    for number,mark in enumerate(separator.finditer(line,after_port),1):
                        if number==3:
                            slash=line.find('\\',mark.end())
                            if slash>=0:
                                end=slash
                            break
            yield line[start:end].strip()
            start=end+1
            if start>=len(line):
                break


def bulk_proxy_count(text):
    return sum(1 for _ in _bulk_proxy_rows(text)) if isinstance(text,str) else 0


def _bulk_expiry(value):
    value=value.replace('年','-').replace('月','-').replace('日','').replace('：',':')
    date=re.fullmatch(r'([0-9]{4})([-./])([0-9]{1,2})\2([0-9]{1,2})([T ].+)?',value)
    if date:
        value=f'{date[1]}-{int(date[3]):02d}-{int(date[4]):02d}'+(date[5] or '')
    elif not re.fullmatch('[0-9]{8}',value):
        return False
    try:
        datetime.fromisoformat(value)
        return True
    except ValueError:
        return False


def _parse_bulk_row(row,protocol):
    if len(row)>8192 or '\x00' in row:
        raise LocalBrowserError('代理含无效字符或超过8192字符。')
    head=_bulk_head(row)
    if not head:
        raise LocalBrowserError(_BULK_FORMAT)
    if head['scheme'] and PROTOCOLS.get(head['scheme'].lower())!=protocol:
        raise LocalBrowserError('代理与所选协议不一致。')
    separator=_bulk_separator(head)
    fields=[part.strip() for part in separator.split(row[head.end():],maxsplit=3)]
    if fields[0]:
        raise LocalBrowserError(_BULK_FORMAT)
    extra=fields[1:]
    username=password=''
    if len(extra)==1:
        if extra[0] and not re.fullmatch(r'[\\\s]+',extra[0]):
            raise LocalBrowserError(_BULK_FORMAT)
    elif extra:
        username,password=extra[:2]
        if bool(username)!=bool(password):
            raise LocalBrowserError('代理账号与密码须同时填写或同时留空。')
        if len(extra)==3:
            expiry=re.sub('(?:'+separator.pattern+r')\Z','',extra[2],count=1).strip()
            if expiry and not _bulk_expiry(expiry):
                raise LocalBrowserError('第五栏须为到期日期。如果账号或密码含有此次使用的分隔符，请换一种分隔符。')
    return _fields(protocol,head['host'].replace('：',':'),head['port'],username,password)


def parse_bulk_proxies(text,protocol,count):
    if protocol not in ('socks5','http','https','ssh'):
        raise LocalBrowserError('请选择有效的代理协议。')
    if not isinstance(text,str):
        raise LocalBrowserError('请粘贴代理文本。')
    proxies=[]
    for number,row in enumerate(_bulk_proxy_rows(text),1):
        if number>count:
            raise LocalBrowserError(f'代理条数超过所选窗口数（{count}），请核对后重试。')
        try:
            proxy=_parse_bulk_row(row,protocol)
        except LocalBrowserError as exc:
            raise LocalBrowserError(f'第 {number} 条代理：{exc}') from None
        proxies.append(proxy)
    if len(proxies)!=count:
        raise LocalBrowserError(f'已选择 {count} 个窗口，识别到 {len(proxies)} 条代理，请核对后重试。')
    return proxies


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
