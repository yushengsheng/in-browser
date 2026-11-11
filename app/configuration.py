"""Version-specific adaptation, with normal vendor authorization and local-only data."""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import threading
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler

from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from app_paths import APP_ROOT,DATA_ROOT
from local_state import LocalBrowserError,read_encrypted,write_encrypted

_SOURCE_ENGINE_LOCK=threading.RLock()


def resource_path(name,root=DATA_ROOT):
    for directory in (Path(root)/'resources',APP_ROOT/'data/resources',APP_ROOT/'resources'):
        path=directory/name
        if path.is_file():return path
    raise LocalBrowserError('配置适配资源缺失，请恢复完整程序包后重试。')


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*_):return None


class Configuration:
    def __init__(self,root=DATA_ROOT):
        self.root=Path(root); self.resources=resource_path('electron-main.js',self.root).parent
        self.independent=(self.root/'independent-mode.bin').is_file()
        resource_path('defaults.json',self.root)
        self.main=(self.resources/'electron-main.js').read_text(encoding='utf-8')
        worker=resource_path('crypto.worker.js',self.root).read_text(encoding='utf-8')
        match=re.search(r'function Tn\(\)\{return\[([0-9,\s]+)\]',worker)
        if not match: raise LocalBrowserError('原内核配置适配版本不匹配。')
        self._key=hashlib.sha256(''.join(chr(int(n)) for n in match.group(1).split(',')).encode()).digest()
        self.lock=threading.RLock()
        self.vendor_data=Path(os.environ['APPDATA'])/'BitBrowser'
        self.cache=self.root/'configuration-context.bin'
        self.context=read_encrypted(self.cache) if self.cache.exists() else {} if self.independent else self._initial_context()

    def _initial_context(self):
        source=APP_ROOT/'data/configuration-context.bin'
        if source.exists() and source.resolve()!=self.cache.resolve():
            context=read_encrypted(source);write_encrypted(self.cache,context);return context
        original=APP_ROOT.parent/'analysis/private-bootstrap'
        context={'permissions':{'userType':1},'geo':None,'variations':None,'badges':{},'maxImageBypass':None}
        for name in ['auxiliary.bin','preferences.bin']:
            p=original/name
            if p.exists(): context.update(read_encrypted(p))
        con=sqlite3.connect((self.vendor_data/'db.sqlite').as_uri()+'?mode=ro',uri=True,timeout=3)
        try:
            context['dictionaries']={k:json.loads(v) for k,v in con.execute(
                'SELECT data_key,data_value FROM cache_data_for_server WHERE data_key IN (?,?,?)',('Lang','WebGLParameters','BypassRules'))}
        finally: con.close()
        write_encrypted(self.cache,context)
        return context

    def _source_dictionaries(self):
        dictionaries=self.context.get('dictionaries')
        if isinstance(dictionaries,dict) and all(key in dictionaries for key in ('Lang','WebGLParameters')):
            return dictionaries
        # A clean independent installation has no vendor-derived context.
        # Read these dictionaries only during an explicitly requested import.
        try:
            from source_database import snapshot
            with snapshot(self.vendor_data/'db.sqlite') as con:
                dictionaries={key:json.loads(value) for key,value in con.execute(
                    'SELECT data_key,data_value FROM cache_data_for_server WHERE data_key IN (?,?,?)',
                    ('Lang','WebGLParameters','BypassRules'))}
            if not isinstance(dictionaries.get('Lang'),(list,dict)) or not isinstance(dictionaries.get('WebGLParameters'),dict):
                raise ValueError()
            return dictionaries
        except (LocalBrowserError,OSError,sqlite3.Error,ValueError,TypeError):
            raise LocalBrowserError('首次导入所需的来源配置字典不可用，请在比特正常登录后重新同步；本地资料未改动。') from None

    def authorization(self):
        if self.independent:raise LocalBrowserError('当前为独立本地模式，不读取原厂登录或授权。')
        cache=APP_ROOT/'data/vendor-session.bin';values={}
        database=self.vendor_data/'db.sqlite'
        if database.is_file():
            try:
                con=sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=3)
                try:values=dict(con.execute('SELECT config_name,config_value FROM global_configs WHERE config_name IN (?,?,?)',('app_token','service_line','locale')))
                finally:con.close()
                if values.get('app_token'):
                    if not cache.exists() or read_encrypted(cache)!=values:write_encrypted(cache,values)
            except (sqlite3.Error,OSError):pass
        if not values.get('app_token') and cache.exists():values=read_encrypted(cache)
        if not values.get('app_token'):raise LocalBrowserError('原内核授权会话不可用，请先在比特客户端正常登录；已保存窗口资料未改动。')
        return values

    def vendor(self,path,payload=None):
        if self.independent:raise LocalBrowserError('当前为独立本地模式，不调用原厂服务。')
        allowed=['/v1/sysUsers/getFingerSign','/v1/apis/ipgeoMethod','/users/currentUser','/v1/sysUsers/getOSStoken']
        if path not in allowed: raise LocalBrowserError('此本地程序不调用云端窗口或同步接口。')
        values=self.authorization()
        token=values.get('app_token')
        if not token: raise LocalBrowserError('原内核授权会话不可用，请先在比特客户端登录后重试。')
        line=values.get('service_line') or 'line1'
        match=re.search(re.escape(line)+r':\{client:`([^`]+)`,web:`([^`]+)`,webapi:`([^`]+)`',self.main)
        if not match or not match.group(3).startswith('https://'):
            match=re.search(r'line1:\{client:`([^`]+)`,web:`([^`]+)`,webapi:`([^`]+)`',self.main)
        if not match or not match.group(3).startswith('https://'): raise LocalBrowserError('未找到原程序可用的安全授权线路。')
        body=payload.encode() if isinstance(payload,str) else (json.dumps(payload).encode() if payload is not None else None)
        req=Request(match.group(3)+path,data=body,method='POST' if payload is not None else 'GET',
                    headers={'Content-Type':'application/json;charset=UTF-8','Authorization':'Bearer '+token,'Language':values.get('locale') or 'zh'})
        try:
            with build_opener(ProxyHandler({})).open(req,timeout=20) as reply:
                raw=reply.read(2_000_001)
                if len(raw)>2_000_000: raise ValueError()
                result=json.loads(raw)
        except Exception:
            raise LocalBrowserError('无法取得原内核授权或IP信息，请检查网络及原客户端登录；已有配置未改动。') from None
        if result.get('code')!=20000:
            raise LocalBrowserError('原内核服务未接受此次请求；请检查登录或授权，已有配置未改动。')
        return result['result']

    def source_settings(self,identity):
        return self._source_request(identity,full=True)

    def source_detail(self,identity,*,timeout=20):
        """Read one locally discovered source, without the desktop LocalAPI."""
        return self._source_request(identity,full=False,timeout=timeout)

    def _source_request(self,identity,*,full,timeout=20):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',str(identity)):raise LocalBrowserError('来源窗口标识格式无效。')
        if getattr(self,'independent',False):
            source=self.source_entry(identity)
            if not source:
                if not full:return None
                raise LocalBrowserError('此来源尚未补齐启动配置，请重新预览并同步；已有本地窗口仍可独立运行。')
            return copy.deepcopy(source['full' if full else 'detail'])
        values=self.authorization();line=values.get('service_line') or 'line1'
        match=re.search(re.escape(line)+r':\{client:`([^`]+)`,web:`([^`]+)`,webapi:`([^`]+)`',self.main)
        if not match or not match.group(1).startswith('https://'):match=re.search(r'line1:\{client:`([^`]+)`,web:`([^`]+)`,webapi:`([^`]+)`',self.main)
        if not match or not match.group(1).startswith('https://'):raise LocalBrowserError('未找到原厂安全配置读取线路。')
        route='/v1/browserInfos/'+('getApi/' if full else '')+str(identity)
        request=Request(match.group(1)+route,headers={'Authorization':'Bearer '+values['app_token'],'x-api-auth':'1','Language':values.get('locale') or 'zh','Content-Type':'application/json;charset=UTF-8'})
        try:
            with build_opener(ProxyHandler({}),_NoRedirect()).open(request,timeout=timeout) as response:
                raw=response.read(16_000_001)
                if len(raw)>16_000_000:raise ValueError()
                data=json.loads(raw)
            if data.get('code')!=20000 or not isinstance(data.get('result'),dict):raise ValueError()
            return data['result']
        except Exception:
            label='完整授权配置' if full else '窗口信息'
            raise LocalBrowserError('无法取得来源'+label+'；本机资料仍保留。请检查网络及比特授权是否有效，无需启动比特客户端。') from None

    def build_source(self,info,*,sign=True,frozen_geo=None):
        """Original source fields and opaque protection options, without randomization."""
        from local_source import source_protection,freeze_source_native
        fp=info.get('browserFingerPrint') or {}
        protected=source_protection(fp)
        if self.independent:
            source=self.source_entry(str(info.get('id') or ''))
            if not source or info!=source.get('full'):raise LocalBrowserError('来源与本地迁移配置不一致，未同步。')
            native=copy.deepcopy(source['native'])
            if native.get('DataProtect')!=protected:
                raise LocalBrowserError('本地迁移配置的数据保护参数不匹配，未同步。')
            return native,self.sign(native,core_major=fp.get('coreVersion')) if sign else None
        with self.lock:
            original=copy.deepcopy(info);fp=original.get('browserFingerPrint') or {}
            font_config=None
            if str(fp.get('fontType','0'))!='0':
                if fp.get('ostype')!='PC' or not str(fp.get('os') or '').startswith('Win'):
                    raise LocalBrowserError('此来源需要额外跨系统字体文件，当前内核尚未验证该资源的独立加载，不能标为完整可用。')
                from font_assets import FontAssets
                assets=FontAssets(self);names=assets._json('fonts/names/Windows.json');baseline=list(names.get('en-US',[]))
                locale=str(fp.get('displayLanguages') or fp.get('languages') or '').casefold()
                for key,values in names.items():
                    if key!='en-US' and key.casefold() in locale:baseline.extend(values)
                if not baseline:raise LocalBrowserError('来源字体目录不完整，尚未同步。')
                font_config={'BasePath':str(self.root/'font-assets/filters-only-no-files'),'Names':baseline+str(fp.get('font') or '').split(','),'BlockFallbackList':[],'Files':[]}
            geo=copy.deepcopy(frozen_geo)
            if any(fp.get(k) for k in ['isIpCreateLanguage','isIpCreateTimeZone','isIpCreatePosition','isIpCreateDisplayLanguage']):
                if frozen_geo is None:
                    proxy={'type':original.get('proxyType') or 'noproxy','host':original.get('host') or '', 'port':original.get('port') or '',
                           'username':original.get('proxyUserName') or '', 'password':original.get('proxyPassword') or ''}
                    tested=self.proxy_test(proxy)
                    if not tested.get('success'):raise LocalBrowserError('来源配置需要按IP生成环境，但当前网络检测失败；未同步为可用窗口。')
                    geo=self.vendor('/v1/apis/ipgeoMethod',{'ip':tested['egress_ip'],'method':original.get('ipCheckService') or 'ip123in','checkExists':0})
                if not isinstance(geo,dict) or not geo.get('timeZone'):
                    raise LocalBrowserError('来源IP环境信息不完整，未使用默认位置或猜测值迁移。')
                if frozen_geo is not None:
                    if any(fp.get(key) for key in ['isIpCreateLanguage','isIpCreateDisplayLanguage']) and not (isinstance(geo.get('languages'),str) and geo['languages'].strip()):
                        raise LocalBrowserError('来源最后保存的语言信息不完整，未使用默认语言迁移。')
                    if fp.get('isIpCreatePosition'):
                        try:
                            latitude=float(geo['latitude']);longitude=float(geo['longitude'])
                            if not (math.isfinite(latitude) and math.isfinite(longitude) and -90<=latitude<=90 and -180<=longitude<=180):raise ValueError()
                        except (KeyError,ValueError,TypeError,OverflowError):
                            raise LocalBrowserError('来源最后保存的位置信息不完整，未使用默认位置迁移。') from None
            dictionaries=self._source_dictionaries()
            payload={'sourceFile':str(self.resources/'electron-main.js'),'info':original,'display':self._display(),'rejectRandomization':True,'allowLegacyProtection':protected is None,
                'languages':dictionaries['Lang'],'webgl':dictionaries['WebGLParameters'],'permissions':self.context.get('permissions') or {'userType':1},
                'geo':geo,'variations':self.context.get('variations') if str(fp.get('coreVersion'))=='148' else None,
                'badges':self.context.get('badges') or {},'maxImageBypass':self.context.get('maxImageBypass'),'touchColor':self.context.get('touchColor'),
                'fontConfig':font_config,'bypassRules':[]}
            try:
                result=subprocess.run(self._config_command(),input=json.dumps(payload,ensure_ascii=False,allow_nan=False).encode(),capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode:raise ValueError()
                native=json.loads(result.stdout)
            except Exception:raise LocalBrowserError('来源启动配置转换失败，未修改来源或提交不完整副本。') from None
            if native.get('DataProtect')!=protected:raise LocalBrowserError('来源数据保护参数不匹配，已停止同步。')
            native,_=freeze_source_native(self,original,native)
            return native,self.sign(native,core_major=fp.get('coreVersion')) if sign else None

    def decode(self,path):
        return self.decode_bytes(Path(path).read_bytes())

    def decode_bytes(self,data):
        if data[:8]!=b'#BT@'+bytes(4): raise LocalBrowserError('指纹文件格式不正确。')
        for start in range(8,min(len(data)-32,4096)+1):
            if (len(data)-start)%16: continue
            try:
                decryptor=Cipher(algorithms.AES(self._key),modes.CBC(data[start:start+16])).decryptor()
                plain=decryptor.update(data[start+16:])+decryptor.finalize(); pad=plain[-1]
                if not 1<=pad<=16 or plain[-pad:]!=bytes([pad])*pad: continue
                value=json.loads(plain[:-pad].decode())
                if isinstance(value,dict) and value.get('Resource'):
                    protected=value.get('DataProtect')
                    if protected is None or (isinstance(protected,dict) and protected.get('CipherKey')):return value
            except (ValueError,UnicodeError): continue
        raise LocalBrowserError('无法读取匹配的数据保护配置，已停止操作。')

    def sign(self,config,*,core_major=None):
        if self.independent:
            from local_signer import LocalSigner,MAX_VALIDITY_HOURS
            return LocalSigner(self.root,validity_hours=MAX_VALIDITY_HOURS).sign_native(config,self._key,core_major=core_major)
        from local_source import source_protection
        source_protection({'coreVersion':core_major,'extendOptions':{'DataProtect':config.get('DataProtect')}})
        iv=os.urandom(16); raw=json.dumps(config,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
        pad=16-len(raw)%16; cipher=Cipher(algorithms.AES(self._key),modes.CBC(iv)).encryptor()
        encrypted=iv+cipher.update(raw+bytes([pad])*pad)+cipher.finalize()
        signature=self.vendor('/v1/sysUsers/getFingerSign',hashlib.sha256(encrypted).hexdigest())
        if not isinstance(signature,str) or not re.fullmatch('[a-fA-F0-9]+',signature) or len(signature)%2:
            raise LocalBrowserError('原内核返回的签名格式不受支持，旧配置未修改。')
        return b'#BT@'+bytes(4)+bytes.fromhex(signature)+encrypted

    def _archive_data(self):
        path=self.root/'local-source-archive.bin'
        try:
            info=path.stat();stamp=(info.st_size,info.st_mtime_ns,info.st_ctime_ns)
            cached=getattr(self,'_source_archive_cache',None)
            if cached and cached[0]==stamp:return cached[1]
            data=read_encrypted(path)
            from portable_paths import decode_archive
            data=decode_archive(data,self.root)
            if not isinstance(data,dict) or data.get('format')!=1 or not isinstance(data.get('items'),dict):raise ValueError()
            from local_signer import LocalSigner
            if data.get('key_id')!=LocalSigner(self.root,load_private=False).key_id:raise ValueError()
            self._source_archive_cache=(stamp,data)
            return data
        except (OSError,ValueError,TypeError):
            raise LocalBrowserError('本地迁移配置缺失或损坏；未请求原厂服务，请保留本地备份。') from None

    def source_archive(self):
        return copy.deepcopy(self._archive_data())

    def prepared_sources(self):
        if not hasattr(self,'_prepared_sources'):
            from local_source import PreparedSources
            self._prepared_sources=PreparedSources(self.root)
        return self._prepared_sources

    def source_entry(self,identity):
        prepared=self.prepared_sources().get(str(identity).lower())
        return prepared or self._archive_data().get('items',{}).get(str(identity).lower())

    def source_prepared_for_profile(self,identity):
        from local_source import profile_identity,source_signature_identity
        value=self.prepared_sources().get(str(identity).lower())
        if not value or not value.get('profile_identity') or not value.get('native_source'):return False
        try:return value['profile_identity']==profile_identity(self,identity) and value['native_source']==source_signature_identity(self,identity)
        except LocalBrowserError:return False

    def prepare_source(self,identity,core):
        from local_source import prepare
        return prepare(self,identity,core)

    def local_core(self,major):
        from core_specs import supports_major
        from engine_store import EngineStore
        from local_engine import LocalEngineStore
        from local_signer import LocalSigner
        from bit_source import BitSource
        from portable_paths import encode_archive
        major=str(major)
        if not supports_major(major):raise LocalBrowserError('此内核精确构建尚未验证，未部署或更新本地映射。')
        with _SOURCE_ENGINE_LOCK:
            archive=self._archive_data();engines=archive.get('engines',{})
            store=LocalEngineStore()
            if major in engines:
                existing=store.ensure_current(engines[major],archive['key_id'],major)
                if str(existing)==engines[major]:return existing
                updated=copy.deepcopy(archive)
                updated['engines'][major]=str(existing)
                write_encrypted(self.root/'local-source-archive.bin',encode_archive(updated,self.root),root=self.root)
                self._source_archive_cache=None
                return existing
            signer=LocalSigner(self.root,load_private=False)
            if signer.key_id!=archive['key_id']:raise LocalBrowserError('本地内核与签名根不匹配，未更新映射。')
            bundled=EngineStore();candidate=bundled.root/major
            if candidate.exists() or candidate.is_symlink():source=bundled.resolve(major)
            else:
                reader=copy.copy(self);reader.independent=False
                source=BitSource(reader)._core_path(major)
            path=store.ensure(major,source,signer.public_der)
            path=store.ensure_current(path,archive['key_id'],major)
            path=store.validate(path,archive['key_id'],major)
            updated=copy.deepcopy(archive)
            updated.setdefault('engines',{})[major]=str(path)
            try:write_encrypted(self.root/'local-source-archive.bin',encode_archive(updated,self.root),root=self.root)
            except OSError:
                raise LocalBrowserError('本地独立内核映射保存失败；原映射已保留，尚未同步窗口。') from None
            self._source_archive_cache=None
            return path

    def proxy_test(self,proxy):
        from proxy_check import ProxyChecker
        return ProxyChecker(targets=getattr(self,'_proxy_targets',None)).test(proxy)

    @staticmethod
    def _config_command():
        bundled=APP_ROOT.parent/'runtime/node/node.exe'
        if not bundled.is_file():raise LocalBrowserError('随包配置转换运行环境缺失，请恢复完整便携目录和runtime。')
        return [str(bundled),str(APP_ROOT/'config_factory.js')]

    def _display(self):
        # Same primary-monitor logical units used by the original Electron screen API.
        import ctypes
        from ctypes import wintypes
        user=ctypes.WinDLL('user32'); user.SetProcessDpiAwarenessContext.argtypes=[ctypes.c_void_p]
        user.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        class Info(ctypes.Structure): _fields_=[('size',wintypes.DWORD),('monitor',wintypes.RECT),('work',wintypes.RECT),('flags',wintypes.DWORD)]
        user.MonitorFromPoint.argtypes=[wintypes.POINT,wintypes.DWORD]; user.MonitorFromPoint.restype=wintypes.HANDLE
        handle=user.MonitorFromPoint(wintypes.POINT(0,0),1); info=Info(); info.size=ctypes.sizeof(info)
        user.GetMonitorInfoW.argtypes=[wintypes.HANDLE,ctypes.POINTER(Info)]
        if not user.GetMonitorInfoW(handle,ctypes.byref(info)): raise LocalBrowserError('无法读取主显示器配置。')
        x=wintypes.UINT(); y=wintypes.UINT(); sh=ctypes.WinDLL('shcore')
        sh.GetDpiForMonitor.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.POINTER(wintypes.UINT),ctypes.POINTER(wintypes.UINT)]
        if sh.GetDpiForMonitor(handle,0,ctypes.byref(x),ctypes.byref(y))!=0: raise LocalBrowserError('无法读取显示缩放。')
        scale=x.value/96
        return {'size':{'width':round((info.monitor.right-info.monitor.left)/scale),'height':round((info.monitor.bottom-info.monitor.top)/scale)},
                'workAreaSize':{'width':round((info.work.right-info.work.left)/scale),'height':round((info.work.bottom-info.work.top)/scale)},'scaleFactor':scale}

    def _font_config(self,fp):
        from font_assets import FontAssets
        if not hasattr(self,'_fonts'): self._fonts=FontAssets(self)
        return self._fonts.build(fp)

    def build(self,profile,native,*,empty=False):
        if self.independent:return self.build_local(profile,native)
        from local_source import source_protection
        with self.lock:
            fp=copy.deepcopy(profile['fingerprint']); prefs=profile['preferences']; proxy=profile['proxy']
            geo=self.context.get('geo')
            needs_geo=any(fp.get(k) for k in ['isIpCreateLanguage','isIpCreateTimeZone','isIpCreatePosition','isIpCreateDisplayLanguage'])
            if needs_geo:
                if proxy['type']=='noproxy': geo=self.vendor('/v1/apis/ipgeoMethod',{'ip':'','method':'ip123in','checkExists':0})
                else:
                    tested=self.proxy_test(proxy)
                    if not tested['success']: raise LocalBrowserError(tested['message'])
                    geo=self.vendor('/v1/apis/ipgeoMethod',{'ip':tested['egress_ip'],'method':'ip123in','checkExists':0})
                if not isinstance(geo,dict) or not geo.get('timeZone'): raise LocalBrowserError('未取得代理对应IP环境信息，请改为手动时区/语言/位置后重试。')
            extension={key:copy.deepcopy(native[key]) for key in ['DataProtect','canvasContext','WebGL','MemorySaverModeEnabled'] if key in native}
            # Only preserve non-output extra keys; the original conversion owns mapped values.
            extension['canvasContext']={k:v for k,v in extension.get('canvasContext',{}).items() if k=='bypassDomains'}
            extension['WebGL']={k:v for k,v in extension.get('WebGL',{}).items() if k=='bypassDomains'}
            extension['MemorySaverModeEnabled']=bool(prefs.get('memory_saver'))
            fp['extendOptions']=extension
            for key in ['mediaDeviceValue','speechVoicesValue','plugins']:
                if isinstance(fp.get(key),(list,dict)): fp[key]=json.dumps(fp[key],ensure_ascii=False)
            if isinstance(fp.get('webgpu'),str):
                try: fp['webgpu']=json.loads(fp['webgpu']) if fp['webgpu'].strip() else None
                except ValueError: raise LocalBrowserError('WebGPU 配置须为JSON对象。') from None
            info={'id':profile['id'],'seq':profile['seq'],'browserFingerPrint':fp,'proxyType':proxy['type'],
                  'host':proxy.get('host',''),'port':proxy.get('port'),'proxyUserName':proxy.get('username',''),
                  'proxyPassword':proxy.get('password',''),'enableSocks5Udp':proxy.get('enable_socks5_udp',False),
                  'abortImage':prefs.get('abort_images',False),'abortImageMaxSize':0,'disableNotifications':False}
            dictionaries=self.context['dictionaries']; variations=self.context.get('variations')
            if str(fp['coreVersion'])!='148': variations=None
            payload={'sourceFile':str(self.resources/'electron-main.js'),'info':info,'display':self._display(),'allowLegacyProtection':source_protection(fp) is None,
                     'languages':dictionaries['Lang'],'webgl':dictionaries['WebGLParameters'],'permissions':self.context.get('permissions') or {'userType':1},
                     'geo':geo,'variations':variations,'badges':{'badge':'seq','toolbarBadge':'seq'},'maxImageBypass':self.context.get('maxImageBypass'),
                     'touchColor':self.context.get('touchColor'),'fontConfig':self._font_config(fp),'bypassRules':[]}
            try:
                result=subprocess.run(self._config_command(),input=json.dumps(payload,ensure_ascii=False,allow_nan=False).encode(),
                                      capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode: raise ValueError()
                made=json.loads(result.stdout)
            except Exception: raise LocalBrowserError('原版指纹转换未完成，请检查所填参数；旧配置未改动。') from None
            if made.get('DataProtect')!=native.get('DataProtect'): raise LocalBrowserError('数据保护参数发生变化，已停止保存。')
            output={} if empty else copy.deepcopy(native)
            output.update(made)
            # The vendor's popup-suppression mode grants permission. This manager's
            # explicit block switch uses Chromium's deny setting instead.
            output.pop('notificationsMode',None)
            if variations is None: output.pop('Variations',None)
            binary=self.sign(output,core_major=fp.get('coreVersion'))
            return output,binary

    def build_local(self,profile,native,*,previous_preferences=None):
        """Preferences never recalculate a migrated fingerprint or contact geo APIs."""
        from local_signer import LocalSigner,MAX_VALIDITY_HOURS
        prefs=profile['preferences'];output=copy.deepcopy(native)
        if previous_preferences is None or prefs.get('memory_saver')!=previous_preferences.get('memory_saver'):
            output['MemorySaverModeEnabled']=bool(prefs.get('memory_saver'))
        if previous_preferences is None or prefs.get('abort_images')!=previous_preferences.get('abort_images'):
            output['maxImageBytes']=0 if prefs.get('abort_images') else None
        if profile.get('created_locally'):
            output['maxImageBytes']=int(profile.get('created_options',{}).get('image_limit_kb',0))*1024 if prefs.get('abort_images') else None
        if previous_preferences is None or prefs.get('disable_notifications')!=previous_preferences.get('disable_notifications'):
            output.pop('notificationsMode',None)
        core=(profile.get('_runtime') or {}).get('core_major') or (profile.get('fingerprint') or {}).get('coreVersion')
        binary=LocalSigner(self.root,validity_hours=MAX_VALIDITY_HOURS).sign_native(output,self._key,core_major=core)
        return output,binary
