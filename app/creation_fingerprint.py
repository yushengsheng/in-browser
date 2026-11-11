"""Local fingerprint generation; feeds the existing native configuration compiler."""
import base64
import copy
from functools import lru_cache
import hashlib
import json
import math
import re
from pathlib import Path
import secrets
import subprocess
import threading

from app_paths import APP_ROOT
from core_specs import supports_major
from local_state import LocalBrowserError,read_encrypted,write_encrypted
from profile_model import defaults,sanitize,parse_cookies,ua_for

_CREATION_SEED_LOCK=threading.RLock()
_CREATION_SEED_CACHE_LIMIT=8*1024*1024
_NOISE_BYPASS_SHA256='e68c7b2fccf852b081582b8446d60715ca6b990d90ebf92564da1af310d686f2'


def needs_geo(fp):
    return str(fp.get('webRTC'))=='0' or any(fp.get(field) for field in (
        'isIpCreateLanguage','isIpCreateTimeZone','isIpCreateDisplayLanguage','isIpCreatePosition'))


def creation_variations(configuration,native,core):
    """Cache verified public seeds for this exact local core and full UA version."""
    from local_source import public_variations,_verify_variations,_VARIATIONS_LIMIT
    def checked(value):
        if not isinstance(value,dict) or set(value)!= {'Seed','Sign'}:raise ValueError()
        seed=value['Seed'];signature=value['Sign']
        if not isinstance(seed,str) or not 1<=len(seed)<=((_VARIATIONS_LIMIT+2)//3)*4:raise ValueError()
        _verify_variations(base64.b64decode(seed,validate=True),signature)
        return copy.deepcopy(value)
    root=Path(configuration.root);path=root/'creation-variations.bin'
    try:
        version=native.get('userAgentVersion');core=str(core)
        if not isinstance(version,str) or not re.fullmatch(r'[0-9]{2,3}(?:\.[0-9]+){0,3}',version) or version.split('.')[0]!=core or not supports_major(core):raise ValueError()
        key=core+':'+version
        with _CREATION_SEED_LOCK:
            cache={'format':1,'entries':{}}
            if path.exists():
                if path.is_symlink() or not path.is_file() or path.stat().st_size>_CREATION_SEED_CACHE_LIMIT+4096:raise ValueError()
                cache=read_encrypted(path,root=root)
                if not isinstance(cache,dict) or cache.get('format')!=1 or not isinstance(cache.get('entries'),dict) or len(cache['entries'])>32:raise ValueError()
                for identity,value in cache['entries'].items():
                    if not isinstance(identity,str) or not re.fullmatch(r'[0-9]{2,3}:[0-9]{2,3}(?:\.[0-9]+){0,3}',identity) or identity.split(':')[0]!=identity.split(':')[1].split('.')[0] or not isinstance(value,dict):raise ValueError()
            entries=cache['entries']
            if key in entries:return checked(entries[key])
            value=checked(public_variations(native))
            entries[key]=value
            while len(entries)>32 or len(json.dumps(cache,separators=(',',':')).encode())>_CREATION_SEED_CACHE_LIMIT:
                entries.pop(next(iter(entries)))
            write_encrypted(path,cache,root=root)
            return copy.deepcopy(value)
    except Exception:
        raise LocalBrowserError('新窗口的对应版本公开运行种子无法取得、缓存无效或签名校验失败；请检查网络及完整程序目录后重试，尚未创建窗口。') from None


@lru_cache(maxsize=1)
def catalog():
    value=json.loads((APP_ROOT/'resources/creation-catalog.json').read_text(encoding='utf-8'))
    if value.get('format')!=1 or not isinstance(value.get('Lang'),list) or not isinstance(value.get('WebGLParameters'),dict):
        raise LocalBrowserError('本地创建资源不完整，请恢复完整程序包。')
    resolutions=value.get('MobileResolutions')
    if not isinstance(resolutions,dict) or any(not isinstance(resolutions.get(kind),list) or not 1<=len(resolutions[kind])<=100 or any(
            not isinstance(item,str) or not re.fullmatch(r'\d{2,5}x\d{2,5}',item) for item in resolutions[kind]) for kind in ('Android','IOS')):
        raise LocalBrowserError('本地移动设备分辨率资源不完整，请恢复完整程序包。')
    noise=value.get('NoiseBypassDefaults')
    if not isinstance(noise,dict):raise LocalBrowserError('本地原生噪声规则资源不完整，请恢复完整程序包。')
    for component in ('canvasContext','WebGL'):
        domains=noise.get(component,{}).get('bypassDomains')
        if not isinstance(domains,list) or len(domains)!=33 or not all(isinstance(domain,str) for domain in domains) or hashlib.sha256(
                json.dumps(domains,separators=(',',':')).encode()).hexdigest()!=_NOISE_BYPASS_SHA256:
            raise LocalBrowserError('本地原生噪声规则资源不完整，请恢复完整程序包。')
    return value


def creation_defaults(core='148'):
    profile=defaults(core)
    profile['fingerprint'].update(isIpCreateLanguage=False,isIpCreateTimeZone=False,isIpCreatePosition=False,
        isIpCreateDisplayLanguage=False,resolutionType='1',resolution='1920x1080',windowSizeLimit=True,
        speechVoices='1',fontType='0',portScanProtect='0',deviceInfoEnabled=True,position='0',clientRectNoiseValue=None)
    profile['name']='新窗口'
    profile['fingerprint'].update(preset(profile['fingerprint']))
    profile['fingerprint']['webGLMeta']='0'
    profile['created_options']=normalize_options({})
    return profile


def preset(fp,*,random=False):
    choices=[p for p in catalog().get('Presets',[]) if p['ostype']==fp.get('ostype','PC') and p['os']==fp.get('os','Win32')]
    exact=[p for p in choices if p['core']==str(fp.get('coreVersion','148'))]
    choices=exact or choices
    if not choices:return {'userAgent':ua_for(fp)}
    selected=copy.deepcopy((secrets.choice(choices) if random else choices[0])['values'])
    version=catalog().get('BuildVersions',{}).get(str(fp['coreVersion']),str(fp['coreVersion'])+'.0.0.0')
    selected['userAgent']=re.sub(r'(Chrome/|CriOS/)[0-9.]+',lambda m:m.group(1)+version,selected['userAgent'])
    return selected


def random_fingerprint(fp):
    """The observed renderer ranges; noise is generated once, never at normal open."""
    fp=copy.deepcopy(fp)
    for field,low,high in [('canvasValue',10000,1000000),('webGLValue',10000,1000000),
                           ('audioContextValue',1,100),('clientRectNoiseValue',1,999999)]:
        fp[field]=low+secrets.randbelow(high-low+1)
    fp.update(hardwareConcurrency=secrets.choice([4,8,12,16]),deviceMemory=secrets.choice([4,8,16]),
        computerName='DESKTOP-'+secrets.token_hex(4).upper(),macAddr='02:'+':'.join(secrets.token_hex(1) for _ in range(5)))
    fp['hostIP']='192.168.'+str(secrets.randbelow(254)+1)+'.'+str(secrets.randbelow(254)+1)
    fp.update(preset(fp,random=True))
    return fp


def _font_name_round_trips(name):
    return isinstance(name,str) and bool(name) and name==name.strip() and ',' not in name


def freeze_random_font(configuration,fp):
    if str(fp.get('fontType'))!='2' or str(fp.get('font') or '').strip():return False
    requested=copy.deepcopy(fp);requested['fontType']='1'
    names=configuration._font_config(requested)['Names']
    names=[name for name in names if _font_name_round_trips(name)]
    if not names:raise LocalBrowserError('未找到可用于随机选择的字体，请改用系统字体或指定本机已有字体。')
    count=max(1,min(len(names),max(20,len(names)*3//4)))
    from fingerprint_continuity import _font_names
    selected=[];probe={'_native':{'FontConfig':{'Names':selected}}}
    for name in secrets.SystemRandom().sample(names,count):
        selected.append(name)
        try:_font_names(probe)
        except LocalBrowserError:selected.pop()
    if not selected:raise LocalBrowserError('未找到可用于随机选择的字体，请改用系统字体或指定本机已有字体。')
    fp['font']=','.join(sorted(selected))
    return True


def validate_profile(incoming):
    if not isinstance(incoming,dict) or incoming.get('id'):
        raise LocalBrowserError('新建配置格式不正确。')
    profile=sanitize(incoming)
    profile['created_options']=normalize_options(incoming.get('created_options') or {})
    if not supports_major(profile['core_version']):raise LocalBrowserError('所选内核尚未完成适配。')
    parse_cookies(profile.get('cookie_text',''),profile)
    fp=profile['fingerprint']
    for field,modes in {'canvas':('0','1'),'webGL':('0','1'),'audioContext':('0','1'),
            'webGLMeta':('0','1'),'fontType':('0','1','2'),'mediaDevice':('0','1'),
            'speechVoices':('0','1'),'doNotTrack':('0','1'),'webRTC':('0','1','2','3'),'position':('0','1','2')}.items():
        if str(fp.get(field)) not in modes:raise LocalBrowserError('指纹模式无效：'+field)
    systems={'PC':('Win32','MacIntel','Linux x86_64'),'Android':('Linux armv81',),'IOS':('iPhone',)}
    if fp['os'] not in systems[fp['ostype']]:raise LocalBrowserError('设备类型与操作系统不匹配。')
    if fp.get('bitness') not in (32,64):raise LocalBrowserError('架构位数须为32或64。')
    if not fp.get('isIpCreateLanguage') and not str(fp.get('languages') or '').strip():raise LocalBrowserError('请填写浏览器语言或启用IP匹配。')
    if not fp.get('isIpCreateTimeZone') and not str(fp.get('timeZone') or '').strip():raise LocalBrowserError('请填写时区或启用IP匹配。')
    if str(fp.get('position'))=='1' and not fp.get('isIpCreatePosition') and any(fp.get(k) in ('',None) for k in ('lat','lng')):
        raise LocalBrowserError('允许位置访问时，请填写经纬度或启用IP匹配。')
    for field in ('precisionData','totalDiskSpace'):
        if fp.get(field) not in ('',None):
            try:number=float(fp[field])
            except (ValueError,TypeError):raise LocalBrowserError(field+'须为有效非负数。') from None
            if not math.isfinite(number) or number<0:raise LocalBrowserError(field+'须为有效非负数。')
    if str(fp.get('resolutionType')) not in ('0','1','2'):raise LocalBrowserError('分辨率模式无效。')
    if profile['proxy'].get('enable_socks5_udp'):raise LocalBrowserError('当前独立代理不支持UDP，不能创建为可用配置。')
    if str(fp.get('webGLMeta'))=='0' and not (fp.get('webGLManufacturer') and fp.get('webGLRender')):
        raise LocalBrowserError('自定义WebGL需要完整的厂商与渲染器信息。')
    if str(fp.get('mediaDevice'))=='0' and not fp.get('mediaDeviceValue'):
        raise LocalBrowserError('自定义媒体设备需填写有效JSON。')
    if str(fp.get('speechVoices'))=='0' and not fp.get('speechVoicesValue'):
        raise LocalBrowserError('自定义语音需填写有效JSON。')
    if fp.get('webglparameterscode') and str(fp['webglparameterscode']) not in catalog()['WebGLParameters']:
        raise LocalBrowserError('WebGL参数代码不在已适配目录中。')
    return profile


def normalize_options(value):
    if not isinstance(value,dict):raise LocalBrowserError('新窗口常用设置格式无效。')
    result={key:False for key in ('clear_cache','clear_cache_without_extensions','clear_cookies','clear_history',
        'random_each_open','stop_ip_change','stop_country_change','enable_background_mode')}
    for key in result:
        if key in value and type(value[key]) is not bool:raise LocalBrowserError('常用设置需要开关值。')
        result[key]=value.get(key,False)
    limit=value.get('image_limit_kb',0)
    if type(limit) is not int or not 0<=limit<=102400:raise LocalBrowserError('图片大小限制须为0至102400 KiB的整数。')
    result['image_limit_kb']=limit
    from dynamic_proxy import validate_url
    result['dynamic_proxy_url']=validate_url(value.get('dynamic_proxy_url',''))
    kind=value.get('dynamic_proxy_type','socks5')
    if kind not in ('http','https','socks5','ssh'):raise LocalBrowserError('提取代理协议无效。')
    result['dynamic_proxy_type']=kind
    workbench=value.get('workbench','localserver')
    if workbench not in ('localserver','disable'):raise LocalBrowserError('IP信息页选项无效。')
    result['workbench']=workbench
    return result


def geo_result(data):
    from zoneinfo import ZoneInfo
    timezone=data.get('timezone');languages=data.get('languages')
    latitude=float(data['latitude']);longitude=float(data['longitude'])
    country=str(data.get('country_code') or '')
    if not isinstance(timezone,str) or not isinstance(languages,str) or not languages.strip():raise ValueError()
    ZoneInfo(timezone)
    if not math.isfinite(latitude) or not math.isfinite(longitude) or not -90<=latitude<=90 or not -180<=longitude<=180:raise ValueError()
    if len(country)!=2 or not country.isalpha():raise ValueError()
    return {'ip':str(data['ip']),'timeZone':timezone,'languages':languages,'latitude':latitude,'longitude':longitude,'country':country.upper()}


def resolve_geo(proxy):
    from proxy_check import ProxyChecker
    checked=ProxyChecker(targets=[{'name':'IP环境信息','url':'https://ipapi.co/json/'}],require_geo=True).test(proxy)
    if not checked.get('success') or not checked.get('geo'):
        raise LocalBrowserError('无法在10秒内取得当前代理的完整位置、时区及语言，未用默认环境替代；请稍后重试或手动设置。')
    return checked['geo']


def _previous_font_config(fp,previous_native):
    if str(fp.get('fontType','0')) not in ('1','2') or not isinstance(previous_native,dict):return None
    font=previous_native.get('FontConfig')
    if not isinstance(font,dict) or font.get('Files')!=[]:return None
    names=font.get('Names')
    if not isinstance(names,list) or not names or any(not isinstance(name,str) or not name.strip() for name in names):return None
    requested=[name.strip() for name in str(fp.get('font') or '').split(',') if name.strip()]
    if requested and requested!=names:return None
    # Automatic IP/noise recompilation must retain the already signed selection,
    # including older random records whose public font field was left empty.
    if not requested and str(fp.get('fontType'))=='2' and all(_font_name_round_trips(name) for name in names):
        fp['font']=','.join(names)
    return copy.deepcopy(font)


def build_native(configuration,profile,previous_native=None):
    """New keys belong only to this new window; imported payloads never enter here."""
    font=_previous_font_config(profile['fingerprint'],previous_native)
    if font is None:freeze_random_font(configuration,profile['fingerprint'])
    fp=copy.deepcopy(profile['fingerprint']);prefs=profile['preferences']
    for field in ('lat','lng','precisionData'):
        if fp.get(field)=='':fp[field]=None
    protection=copy.deepcopy(previous_native.get('DataProtect')) if previous_native is not None else None if int(fp['coreVersion'])<130 else {'CipherKey':secrets.token_hex(32),'Areas':{
        key:True for key in ('ExtensionIndexedDB','ExtensionManagedStorage','ExtensionCookies','LocalStorage',
                            'ExtensionSyncStorage','Cookies','IndexedDB','ExtensionLocalStorage')}}
    fp['extendOptions']={'DataProtect':protection,'MemorySaverModeEnabled':bool(prefs.get('memory_saver'))}
    for component in ('canvasContext','WebGL'):
        source=catalog()['NoiseBypassDefaults'][component] if previous_native is None else previous_native.get(component,{})
        if isinstance(source,dict) and 'bypassDomains' in source:
            fp['extendOptions'][component]={'bypassDomains':copy.deepcopy(source['bypassDomains'])}
    if previous_native is not None:
        for key in ('Variations','battery'):
            if key in previous_native:fp['extendOptions'][key]=copy.deepcopy(previous_native[key])
    for field in ('mediaDeviceValue','speechVoicesValue','plugins'):
        if isinstance(fp.get(field),(list,dict)):fp[field]=json.dumps(fp[field],ensure_ascii=False)
    if isinstance(fp.get('webgpu'),str):fp['webgpu']=json.loads(fp['webgpu']) if fp['webgpu'].strip() else None
    if font is None and str(fp.get('fontType','0'))!='0':
        requested=copy.deepcopy(fp);requested['fontType']='1'
        font=configuration._font_config(requested)
    data=catalog()
    payload={'sourceFile':str(configuration.resources/'electron-main.js'),
        'info':{'id':profile['id'],'seq':profile['seq'],'browserFingerPrint':fp,'proxyType':'noproxy',
                'abortImage':prefs.get('abort_images',False),'abortImageMaxSize':profile.get('created_options',{}).get('image_limit_kb',0)},
        'display':configuration._display(),'allowLegacyProtection':protection is None,
        'rejectRandomization':False,'languages':data['Lang'],'webgl':data['WebGLParameters'],
        'permissions':{'userType':1},'geo':profile.get('_creation_geo'),'variations':None,'badges':{'badge':'seq','toolbarBadge':'seq'},
        'fontConfig':font,'bypassRules':[]}
    try:
        result=subprocess.run(configuration._config_command(),input=json.dumps(payload,ensure_ascii=False,allow_nan=False).encode(),
            capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:raise ValueError()
        native=json.loads(result.stdout)
        if native.get('DataProtect')!=protection or native.get('navigator',{}).get('platform')!=fp['os']:raise ValueError()
        if not fp.get('isIpCreatePosition') or str(fp.get('position'))=='2':
            for field,target in (('lat','latitude'),('lng','longitude'),('precisionData','accuracy')):
                if fp.get(field) in ('',None):
                    if target=='accuracy':native['geoPosition'].pop(target,None)
                    else:native['geoPosition'][target]=None
        if previous_native is None:native['Variations']=creation_variations(configuration,native,fp['coreVersion'])
        native.pop('notificationsMode',None)
        return native,configuration.sign(native,core_major=fp['coreVersion'])
    except LocalBrowserError:raise
    except Exception:
        raise LocalBrowserError('本地指纹编译未完成；新窗口尚未提交，已有资料未改动。') from None
