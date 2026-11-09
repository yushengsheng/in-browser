"""Local profile validation and consistent, persisted fingerprint choices."""
import copy
import json
import math
from pathlib import Path
import re
from urllib.parse import urlparse

from app_paths import APP_ROOT
from local_state import LocalBrowserError
from proxy_config import normalize_proxy

FP_EXTRA=['font','mediaDeviceValue','speechVoicesValue','speechVoices','clientRectNoiseEnabled',
          'clientRectNoiseValue','webglparameterscode','defaultAccuracy','navigatorVendor','architecture','bitness',
          'iswow64','uamodel','deviceInfoEnabled','computerName','modelName','manufacturerName','macAddr','webgpu',
          'portScanProtect','portWhiteList','launchArgs','totalDiskSpace','enablePlugins','plugins','ignoreHttpsErrors']
PREFERENCES={'mute_audio':False,'disable_gpu':False,'disable_notifications':False,'abort_images':False,
             'abort_media':False,'disable_clipboard':False,'allowed_signin':False,'credentials_service':True,
             'disable_translate':True,'memory_saver':False,'restore_session':True}


def defaults(core='148'):
    source=APP_ROOT/'data/resources/defaults.json'
    if not source.is_file():source=APP_ROOT/'resources/defaults.json'
    raw=json.loads(source.read_text(encoding='utf-8')) if source.exists() else {'browserFingerPrint':{}}
    fp=copy.deepcopy(raw['browserFingerPrint'])
    fp.update({'coreVersion':str(core),'coreProduct':'chrome','ostype':'PC','os':'Win32','platformVersion':'10.0.0',
               'osVersion':'10','architecture':'x86','bitness':64,'navigatorVendor':'Google Inc.',
               'languages':'zh-CN,zh','displayLanguages':'zh-CN','timeZone':'Asia/Shanghai','resolution':'1920x1080',
               'hardwareConcurrency':8,'deviceMemory':8,'font':'','webRTC':'3','webGLMeta':'1','webglparameterscode':'',
               'webGLManufacturer':'Google Inc. (Intel)','webGLRender':'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)',
               'clientRectNoiseEnabled':True,'clientRectNoiseValue':0,'defaultAccuracy':10,'fontType':'0',
               'speechVoices':'1','mediaDevice':'1','deviceInfoEnabled':False,'computerName':'','macAddr':'',
               'iswow64':False,'uamodel':'','modelName':'','manufacturerName':'','totalDiskSpace':'',
               'launchArgs':'','disableSslCipherSuitesFlag':False,'disableSslCipherSuites':'','portScanProtect':'0','portWhiteList':''})
    result={'name':'','group':'','tags':[],'remark':'','os':fp['os'],'core_version':str(core),
            'proxy':{'type':'noproxy','host':'','port':'','username':'','password':''},'platform':'','username':'','password':'',
            'fa_secret':'','allow_multi_open':True,'duplicate_check':False,'urls':[],'cookie_text':'',
            'fingerprint':fp,'preferences':dict(PREFERENCES)}
    fp['userAgent']=ua_for(fp)
    return result


def ua_for(fp):
    version=str(fp.get('coreVersion') or '148')+'.0.0.0'
    kind=fp.get('ostype','PC'); system=fp.get('os','Win32')
    if kind=='Android': return f'Mozilla/5.0 (Linux; Android {str(fp.get("platformVersion") or "14").split(".")[0]}; {fp.get("uamodel") or "Pixel 8"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Mobile Safari/537.36'
    if kind=='IOS': return f'Mozilla/5.0 (iPhone; CPU iPhone OS {str(fp.get("platformVersion") or "18.0").replace(".","_")} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/{version} Mobile/15E148 Safari/604.1'
    platform='Macintosh; Intel Mac OS X 10_15_7' if system=='MacIntel' else ('X11; Linux x86_64' if system.startswith('Linux') else 'Windows NT 10.0; Win64; x64')
    return f'Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36'


def fingerprint_fields():
    source=APP_ROOT/'data/resources/defaults.json'
    if not source.is_file():source=APP_ROOT/'resources/defaults.json'
    raw=json.loads(source.read_text(encoding='utf-8'))
    return set(raw['browserFingerPrint'])|set(FP_EXTRA)


def sanitize(profile,base=None):
    if not isinstance(profile,dict): raise LocalBrowserError('窗口配置格式不正确。')
    result=copy.deepcopy(base) if base else defaults(str((profile.get('fingerprint') or {}).get('coreVersion') or '148'))
    for field,limit in [('name',100),('group',100),('remark',500),('platform',2000),('username',100),('password',100),('fa_secret',500)]:
        if field in profile:
            value=str(profile[field] or '')
            if len(value)>limit: raise LocalBrowserError(f'{field} 内容过长。')
            result[field]=value
    if 'tags' in profile:
        if not isinstance(profile['tags'],list) or len(profile['tags'])>100: raise LocalBrowserError('标签格式不正确。')
        result['tags']=list(dict.fromkeys(str(t).strip()[:100] for t in profile['tags'] if str(t).strip()))
    for key in ['allow_multi_open','duplicate_check']:
        if key in profile: result[key]=bool(profile[key])
    if 'urls' in profile:
        urls=profile['urls']
        if not isinstance(urls,list) or len(urls)>100: raise LocalBrowserError('启动网址最多100条。')
        clean=[]
        for value in urls:
            value=str(value).strip()
            if not value: continue
            parsed=urlparse(value)
            if parsed.scheme not in ['http','https','chrome','chrome-extension','about','file'] or len(value)>10000:
                raise LocalBrowserError('网址须包含 http://、https:// 或支持的浏览器协议。')
            clean.append(value)
        result['urls']=list(dict.fromkeys(clean))
    if 'proxy' in profile:
        result['proxy']=normalize_proxy(profile['proxy'])
    if 'preferences' in profile:
        prefs=profile['preferences']
        if not isinstance(prefs,dict): raise LocalBrowserError('偏好配置格式不正确。')
        result['preferences']={key:bool(prefs.get(key,result.get('preferences',{}).get(key,default))) for key,default in PREFERENCES.items()}
    if 'fingerprint' in profile:
        incoming=profile['fingerprint']
        if not isinstance(incoming,dict): raise LocalBrowserError('指纹配置格式不正确。')
        for key in fingerprint_fields():
            if key in incoming: result['fingerprint'][key]=copy.deepcopy(incoming[key])
    fp=result['fingerprint']; core=str(fp.get('coreVersion') or result.get('core_version') or '148')
    if not core.isdigit(): raise LocalBrowserError('内核版本格式不正确。')
    fp['coreVersion']=core; fp['coreProduct']='chrome'
    if fp.get('ostype') not in ['PC','Android','IOS']: raise LocalBrowserError('请选择有效的系统类型。')
    if not str(fp.get('os','')).strip(): raise LocalBrowserError('请选择操作系统。')
    if str(fp.get('resolutionType'))=='1':
        fp['resolution']=re.sub(r'\s*[x×]\s*','x',str(fp.get('resolution') or '').strip())
        match=re.fullmatch(r'(\d{2,5})x(\d{2,5})',fp['resolution'])
        if not match or not all(100<=int(n)<=32768 for n in match.groups()): raise LocalBrowserError('分辨率须为有效的宽x高，例如1920x1080。')
    if not fp.get('isIpCreateTimeZone') and fp.get('timeZone'):
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(str(fp['timeZone']))
        except Exception: raise LocalBrowserError('请输入有效的IANA时区名称。') from None
    if not str(fp.get('userAgent','')).strip(): fp['userAgent']=ua_for(fp)
    if len(fp['userAgent'])>4000 or any(ch in fp['userAgent'] for ch in '\r\n\x00'): raise LocalBrowserError('User-Agent格式不正确或过长。')
    for key,low,high in [('openWidth',320,16384),('openHeight',240,16384),('hardwareConcurrency',1,256),('deviceMemory',.25,1024),
                         ('devicePixelRatio',.1,10),('colorDepth',1,64),('defaultAccuracy',1,100000),('canvasValue',-1e12,1e12),
                         ('webGLValue',-1e12,1e12),('audioContextValue',-1e12,1e12),('clientRectNoiseValue',-1e12,1e12)]:
        value=fp.get(key)
        if value in ('',None): continue
        try: number=float(value)
        except (ValueError,TypeError): raise LocalBrowserError(f'{key} 必须为有效数字。') from None
        if not math.isfinite(number) or not low<=number<=high: raise LocalBrowserError(f'{key} 数值超出范围。')
        fp[key]=int(number) if number.is_integer() else number
    for key,low,high in [('lat',-90,90),('lng',-180,180)]:
        if fp.get(key) not in ('',None):
            try: number=float(fp[key])
            except (ValueError,TypeError): raise LocalBrowserError('经纬度格式不正确。') from None
            if not math.isfinite(number) or not low<=number<=high: raise LocalBrowserError('经纬度超出范围。')
            fp[key]=number
    fp['portScanProtect']='1' if fp.get('portScanProtect') in [True,1,'1'] else '0'
    ports=str(fp.get('portWhiteList') or '')
    if ports:
        try:
            if any(not 1<=int(p.strip())<=65535 for p in ports.split(',')): raise ValueError()
        except ValueError: raise LocalBrowserError('端口白名单须为逗号分隔的有效端口。') from None
    if fp.get('disableSslCipherSuitesFlag') and not str(fp.get('disableSslCipherSuites') or '').strip():
        raise LocalBrowserError('启用禁用SSL套件时须填写套件列表。')
    for key in ['mediaDeviceValue','speechVoicesValue','plugins']:
        value=fp.get(key)
        if value:
            try: json.loads(value) if isinstance(value,str) else json.dumps(value)
            except (ValueError,TypeError): raise LocalBrowserError(f'{key} 必须为有效JSON。') from None
    if fp.get('webgpu') in ['0','1','']: fp['webgpu']=None
    if fp.get('webgpu'):
        try: value=json.loads(fp['webgpu']) if isinstance(fp['webgpu'],str) else fp['webgpu']
        except ValueError: raise LocalBrowserError('WebGPU必须为有效JSON对象。') from None
        if not isinstance(value,dict): raise LocalBrowserError('WebGPU必须为JSON对象。')
    plugins=fp.get('plugins')
    if plugins:
        value=json.loads(plugins) if isinstance(plugins,str) else plugins
        if not isinstance(value,list): raise LocalBrowserError('插件配置必须为JSON数组。')
    result['core_version']=core; result['os']=fp['os']
    if 'cookie_text' in profile:
        value=str(profile.get('cookie_text') or '')
        if len(value)>2_000_000: raise LocalBrowserError('Cookie内容超过本地导入上限。')
        result['cookie_text']=value
    return result


def parse_cookies(text,profile):
    text=text.lstrip('\ufeff')
    if not text.strip(): return []
    try: items=json.loads(text)
    except ValueError:
        if '\t' in text or text.lstrip().startswith('# Netscape HTTP Cookie File'):
            items=[]
            for line in text.splitlines():
                http_only=line.startswith('#HttpOnly_')
                if not line.strip() or (line.startswith('#') and not http_only):continue
                if http_only:line=line[len('#HttpOnly_'):]
                parts=line.split('\t')
                if len(parts)!=7 or parts[1] not in ('TRUE','FALSE') or parts[3] not in ('TRUE','FALSE'):
                    raise LocalBrowserError('Netscape Cookie须为7列制表符分隔格式。') from None
                domain,subdomains,path,secure,expiry,name,value=parts
                if not domain or not path.startswith('/') or not expiry.isdigit():
                    raise LocalBrowserError('Netscape Cookie域名、路径或到期时间无效。') from None
                domain=('.'+domain.lstrip('.')) if subdomains=='TRUE' else domain.lstrip('.')
                cookie={'name':name,'value':value,'domain':domain,'path':path,'secure':secure=='TRUE','httpOnly':http_only}
                if int(expiry)>0:cookie['expires']=int(expiry)
                items.append(cookie)
            if not items:raise LocalBrowserError('Netscape Cookie文件中没有有效记录。') from None
            return parse_cookies(json.dumps(items),profile)
        website=profile.get('platform') or next(iter(profile.get('urls') or []),'')
        parsed=urlparse(website)
        if parsed.scheme not in ['http','https'] or not parsed.hostname:
            raise LocalBrowserError('请求头Cookie格式需要先填写平台网址或启动网址。') from None
        items=[{'name':part.split('=',1)[0].strip(),'value':part.split('=',1)[1].strip(),'url':website,'path':'/'}
               for part in text.removeprefix('Cookie:').split(';') if '=' in part]
        if not items: raise LocalBrowserError('Cookie内容不是有效JSON或请求头格式。')
    if isinstance(items,dict): items=items.get('cookies')
    if not isinstance(items,list) or len(items)>10000: raise LocalBrowserError('Cookie须为JSON数组，最多10000条。')
    allowed={'name','value','url','domain','path','secure','httpOnly','sameSite','expires','priority','sameParty','sourceScheme','sourcePort','partitionKey'}
    output=[]
    for item in items:
        if not isinstance(item,dict) or not isinstance(item.get('name'),str) or not isinstance(item.get('value'),str):
            raise LocalBrowserError('每条Cookie必须包含字符串name和value。')
        if not item.get('domain') and not item.get('url'): raise LocalBrowserError('Cookie缺少domain或url。')
        cookie={k:v for k,v in item.items() if k in allowed}
        if cookie.get('expires',0)==-1: cookie.pop('expires')
        if cookie.get('sameSite') not in (None,'Strict','Lax','None'): raise LocalBrowserError('Cookie SameSite 值不正确。')
        output.append(cookie)
    return output
