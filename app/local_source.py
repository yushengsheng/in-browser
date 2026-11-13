"""Prepare only locally discovered sources, then retain independent encrypted copies."""
import base64
import copy
from contextlib import contextmanager
import errno
import hashlib
from http.client import IncompleteRead,RemoteDisconnected
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import stat
import struct
import threading
import time
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError,URLError
import zlib

from local_state import LocalBrowserError,protect,read_encrypted,write_encrypted
from portable_paths import encode_path,decode_path
from source_database import snapshot,stamp

_ID=re.compile('[0-9a-fA-F]{32}')
_SOURCE_LIMIT=16*1024*1024+4096+32
_DERIVED_POSITION=('latitude','longitude','accuracy')
PUBLIC_SEED_IMPORT_NOTE='原厂未保留历史运行种子，使用对应版本公开签名种子首次登记'
_VARIATIONS_LIMIT=2*1024*1024
_VARIATIONS_CACHE={}
_VARIATIONS_LOCK=threading.Lock()
_PROFILE_METADATA_BYTES=16*1024*1024
_PROFILE_DATABASE_BYTES=512*1024*1024
_PROFILE_SESSION_BYTES=128*1024*1024
_PROFILE_SESSION_FILE_BYTES=64*1024*1024
_PROFILE_SESSION_ENTRIES=1024
_PROFILE_IDENTITY_FILES=1044
_PROFILE_IDENTITY_SECONDS=20
_PROFILE_DATABASES=('Default/Network/Cookies','Default/Cookies',
    'Default/Login Data','Default/Login Data For Account')
# Chromium components/variations/variations_seed_store.cc, kPublicKey (BSD).
_VARIATIONS_PUBLIC_DER=bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004'
    '517c314b5042dd59da0bfa4344337c5fa10bd582f6ac0419726c40d43e56e2a080'
    'a041b3237b71c98087de350d2571097fb4152bff824dd3fec5ef20c6a310bf')


class _NoSeedRedirect(HTTPRedirectHandler):
    def redirect_request(self,*_):return None


def _variations_key():
    from cryptography.hazmat.primitives import serialization
    return serialization.load_der_public_key(_VARIATIONS_PUBLIC_DER)


def _verify_variations(compressed,signature):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    if not isinstance(signature,str) or not 1<=len(signature)<=1024 or not 1<=len(compressed)<=_VARIATIONS_LIMIT:raise ValueError()
    unpacker=zlib.decompressobj(31)
    seed=unpacker.decompress(compressed,16*1024*1024+1)
    if not seed or len(seed)>16*1024*1024 or not unpacker.eof or unpacker.unconsumed_tail or unpacker.unused_data:raise ValueError()
    _variations_key().verify(base64.b64decode(signature,validate=True),seed,ec.ECDSA(hashes.SHA256()))


def _retry_seed_download(error):
    if isinstance(error,HTTPError):return error.code in (408,500,502,503,504)
    if isinstance(error,URLError):error=error.reason
    if isinstance(error,ssl.SSLError):return False
    if isinstance(error,(TimeoutError,ConnectionResetError,ConnectionAbortedError,BrokenPipeError,
                         RemoteDisconnected,IncompleteRead)):return True
    if isinstance(error,socket.gaierror):return error.errno==socket.EAI_AGAIN
    return isinstance(error,OSError) and error.errno in (errno.ETIMEDOUT,errno.ECONNRESET,errno.ECONNABORTED,errno.EPIPE)


def public_variations(native):
    """Use Ho's public, UA-milestone seed protocol; never guess a different version."""
    code='source_seed_input'
    try:
        version=native.get('userAgentVersion')
        if not isinstance(version,str) or not re.fullmatch(r'[0-9]{2,3}(?:\.[0-9]+){0,3}',version):raise ValueError()
        major=version.split('.')[0];now=time.monotonic()
        with _VARIATIONS_LOCK:
            cached=_VARIATIONS_CACHE.get(major)
            if cached and now<cached[0]:return copy.deepcopy(cached[1])
        request=Request('https://clientservices.googleapis.com/chrome-variations/seed?channel=stable&milestone='+major,
            headers={'A-IM':'gzip'})
        # A first socket timeout must leave room for the single retry. DNS and
        # socket operations still are not a hard wall-clock cap.
        deadline=now+15;code='source_seed_download';opener=build_opener(ProxyHandler({}),_NoSeedRedirect())
        for attempt in range(2):
            remaining=deadline-time.monotonic()
            if remaining<=0:code='source_seed_budget';raise TimeoutError()
            code='source_seed_download'
            try:
                with opener.open(request,timeout=min(5 if attempt==0 else 10,remaining)) as response:
                    if response.status!=200:
                        if attempt==0 and response.status in (408,500,502,503,504):continue
                        raise ValueError()
                    signature=response.headers.get('x-seed-signature')
                    length=response.headers.get('Content-Length')
                    code='source_seed_verification'
                    if length is not None and (not str(length).isdigit() or int(length)>_VARIATIONS_LIMIT):raise ValueError()
                    chunks=[];size=0;code='source_seed_download'
                    while True:
                        if time.monotonic()>=deadline:code='source_seed_budget';raise TimeoutError()
                        block=response.read1(min(64*1024,_VARIATIONS_LIMIT+1-size))
                        if not block:break
                        chunks.append(block);size+=len(block)
                        if size>_VARIATIONS_LIMIT:code='source_seed_verification';raise ValueError()
                compressed=b''.join(chunks);code='source_seed_verification'
                _verify_variations(compressed,signature)
                if time.monotonic()>=deadline:code='source_seed_budget';raise TimeoutError()
                break
            except Exception as error:
                retry=code=='source_seed_download' and _retry_seed_download(error)
                if isinstance(error,HTTPError):error.close()
                if code=='source_seed_download' and time.monotonic()>=deadline:code='source_seed_budget';raise
                if attempt or not retry:raise
        value={'Seed':base64.b64encode(compressed).decode('ascii'),'Sign':signature}
        with _VARIATIONS_LOCK:
            if time.monotonic()>=deadline:code='source_seed_budget';raise TimeoutError()
            for key in list(_VARIATIONS_CACHE):
                if time.monotonic()>=_VARIATIONS_CACHE[key][0]:_VARIATIONS_CACHE.pop(key)
            if len(_VARIATIONS_CACHE)>=32:_VARIATIONS_CACHE.pop(next(iter(_VARIATIONS_CACHE)))
            _VARIATIONS_CACHE[major]=(time.monotonic()+3600,copy.deepcopy(value))
        return value
    except Exception:
        error=LocalBrowserError('来源未保留历史运行种子，且对应版本公开种子暂时无法取得或签名校验失败；未使用其他版本种子，请稍后重新同步。')
        error.code=code
        raise error from None


def _source_cache_present(configuration,identity):
    path=Path(configuration.vendor_data).absolute()/'LocalCache'/_identity(identity)
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        try:
            for parent in path.parents:
                try:info=parent.lstat()
                except FileNotFoundError:continue
                if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise ValueError()
            return False
        except (OSError,ValueError):pass
    except OSError:pass
    raise LocalBrowserError('来源启动缓存路径无法安全核对，未读取其他位置。') from None


def _source_signature(configuration,identity):
    """Read exactly this source's ordinary cache file, with two stable hashes."""
    identity=_identity(identity)
    path=Path(configuration.vendor_data).absolute()/'LocalCache'/identity
    def file_stamp(info):return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
    def inspect():
        for current in (path,*path.parents):
            info=current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise ValueError()
            if current==path:
                if not stat.S_ISREG(info.st_mode) or not 32<=info.st_size<=_SOURCE_LIMIT:raise ValueError()
            elif not stat.S_ISDIR(info.st_mode):raise ValueError()
        return file_stamp(path.lstat())
    try:
        before=inspect();reads=[]
        for _ in range(2):
            with path.open('rb') as stream:
                opened=file_stamp(os.fstat(stream.fileno()))
                # Windows path stat and handle stat can expose different ctime
                # semantics; compare each API to itself, and shared identity across APIs.
                if opened[:4]!=before[:4]:raise ValueError()
                raw=stream.read(_SOURCE_LIMIT+1)
                if len(raw)>_SOURCE_LIMIT or file_stamp(os.fstat(stream.fileno()))!=opened:raise ValueError()
            if inspect()!=before:raise ValueError()
            reads.append(hashlib.sha256(raw).hexdigest())
        if reads[0]!=reads[1]:raise ValueError()
        return raw,{'format':1,'source_id':identity,'present':True,'file':before,'sha256':reads[0]}
    except (OSError,ValueError,TypeError):
        raise LocalBrowserError('来源实际启动配置缺失、正在变化或包含特殊链接；请正常重新打开并关闭此来源后再同步。') from None


def source_signature_identity(configuration,identity):
    identity=_identity(identity)
    if not _source_cache_present(configuration,identity):return {'format':1,'source_id':identity,'present':False}
    return _source_signature(configuration,identity)[1]


def freeze_source_native(configuration,info,rebuilt):
    """Freeze only authenticated launch-derived fields after all static fields match."""
    try:
        identity=_identity(info['id']);fp=info['browserFingerPrint']
        if fp.get('browserId') and _identity(fp['browserId'])!=identity:raise ValueError()
        protected=source_protection(fp)
        if not isinstance(rebuilt,dict) or rebuilt.get('DataProtect')!=protected:raise ValueError()
        if not _source_cache_present(configuration,identity):
            frozen=copy.deepcopy(rebuilt);frozen['Variations']=public_variations(rebuilt)
            evidence=source_signature_identity(configuration,identity)
            if evidence.get('present') is not False:raise ValueError()
            return frozen,evidence
        raw,evidence=_source_signature(configuration,identity)
        if raw[:8]!=b'#BT@'+bytes(4) or len(raw)<12:raise ValueError()
        length=struct.unpack('>I',raw[8:12])[0]
        if length!=256:raise ValueError()
        start=12+length+16;times=raw[12+length:start]
        if len(times)!=16:raise ValueError()
        created,expires=struct.unpack('>QQ',times)
        if not 0<created<expires<=253402300799999:raise ValueError()
        encrypted=raw[start:]
        if len(encrypted)<32 or len(encrypted)%16:raise ValueError()
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from signature_lifetime import _verification_key
        _verification_key().verify(raw[12:12+length],hashlib.sha256(encrypted).digest()+times,padding.PKCS1v15(),hashes.SHA256())
        cached=configuration.decode_bytes(raw)
        if not isinstance(rebuilt,dict) or cached.get('DataProtect')!=protected or rebuilt.get('DataProtect')!=protected:raise ValueError()
        expected=copy.deepcopy(rebuilt);observed=copy.deepcopy(cached)
        expected.pop('Variations',None);observed.pop('Variations',None)
        freeze_position=bool(fp.get('isIpCreatePosition')) and fp.get('position') not in (2,'2')
        if freeze_position:
            for value in (expected,observed):
                position=value.get('geoPosition')
                if not isinstance(position,dict):raise ValueError()
                latitude,longitude,accuracy=(position[key] for key in _DERIVED_POSITION)
                if any(isinstance(item,bool) or not isinstance(item,(int,float)) or not math.isfinite(item) for item in (latitude,longitude,accuracy)):raise ValueError()
                if not (-90<=latitude<=90 and -180<=longitude<=180 and accuracy>=0):raise ValueError()
                for key in _DERIVED_POSITION:position.pop(key)
        def canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)
        if canonical(expected)!=canonical(observed):raise ValueError()
        frozen=copy.deepcopy(rebuilt)
        if 'Variations' in cached:frozen['Variations']=copy.deepcopy(cached['Variations'])
        else:frozen.pop('Variations',None)
        if freeze_position:
            for key in _DERIVED_POSITION:frozen['geoPosition'][key]=copy.deepcopy(cached['geoPosition'][key])
        if source_signature_identity(configuration,identity)!=evidence:raise ValueError()
        return frozen,evidence
    except LocalBrowserError:raise
    except Exception:
        raise LocalBrowserError('来源实际启动签名无效、已过时或与当前完整配置不匹配；请正常重新打开并关闭此来源后再同步，未猜测指纹。') from None


def source_protection(fp):
    """Preserve the vendor's protection mode; older verified cores may have none."""
    try:
        extension=fp.get('extendOptions')
        if isinstance(extension,str):extension=json.loads(extension)
        if extension is not None and not isinstance(extension,dict):raise ValueError()
        protected=(extension or {}).get('DataProtect')
        if isinstance(protected,dict):
            if not isinstance(protected.get('CipherKey'),str) or not protected['CipherKey']:raise ValueError()
            return protected
        from core_specs import supports_major
        major=str(fp.get('coreVersion') or '')
        if protected is not None or not supports_major(major) or int(major)>=130:raise ValueError()
        return None
    except (ValueError,TypeError,AttributeError):
        raise LocalBrowserError('来源数据保护配置缺失或与已验证内核规则不符，未复制资料。') from None


def _identity(value):
    if not isinstance(value,str) or not _ID.fullmatch(value):raise LocalBrowserError('来源窗口标识无效，未读取其他窗口。')
    return value.lower()


def _validate(value):
    try:
        identity=_identity(value['id']);full=value['full'];fp=full['browserFingerPrint']
        if value.get('format')!=1 or _identity(full['id'])!=identity:raise ValueError()
        if fp.get('browserId') and _identity(fp['browserId'])!=identity:raise ValueError()
        protected=source_protection(fp)
        if value['native'].get('DataProtect')!=protected:raise ValueError()
        evidence=value.get('native_source')
        if evidence is not None:
            if not isinstance(evidence,dict) or evidence.get('format')!=1 or evidence.get('source_id')!=identity:raise ValueError()
            if evidence.get('present') is not False:
                if (not re.fullmatch('[0-9a-f]{64}',evidence.get('sha256',''))
                        or not isinstance(evidence.get('file'),list) or len(evidence['file'])!=5
                        or any(isinstance(item,bool) or not isinstance(item,int) for item in evidence['file'])):raise ValueError()
        digest=hashlib.sha256(json.dumps(full,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()).hexdigest()
        if value.get('configuration_sha256',digest)!=digest:raise ValueError()
        return identity,digest
    except (KeyError,ValueError,TypeError,AttributeError):
        raise LocalBrowserError('来源准备配置的身份或保护参数不匹配，未保存或套用。') from None


def globals_for(configuration):
    database=configuration.vendor_data/'db.sqlite'
    current=stamp(database)
    cached=getattr(configuration,'_live_globals',None)
    if cached and cached[0]==current:return cached[1]
    with snapshot(database) as con:
        values=dict(con.execute('SELECT config_name,config_value FROM global_configs WHERE config_name IN (?,?,?,?)',
            ('browser_cache_dir','app_token','service_line','locale')))
    configuration._live_globals=(current,values)
    return values


def profile_root(configuration):
    if (configuration.vendor_data/'db.sqlite').is_file():
        value=globals_for(configuration).get('browser_cache_dir') or configuration.vendor_data/'BrowserCache'
    else:value=getattr(configuration,'_archive_data',configuration.source_archive)()['profile_root']
    root=Path(value)
    if not root.is_absolute():raise LocalBrowserError('本机来源资料位置无效，未导入。')
    return root.absolute()


def _profile_stamp(info):
    return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns]


def _profile_inventory(root,folder,deadline):
    """Inspect fixed preparation inputs and one bounded native session directory."""
    def inspect(path,kind,optional=False):
        if time.monotonic()>=deadline:raise ValueError()
        try:info=path.lstat()
        except FileNotFoundError:
            if optional:return None
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise ValueError()
        if not (stat.S_ISDIR(info.st_mode) if kind=='directory' else stat.S_ISREG(info.st_mode)):raise ValueError()
        if not path.resolve().is_relative_to(root.resolve()):raise ValueError()
        return _profile_stamp(info)

    # Reject redirected ancestors even when an optional child is absent.
    for parent in (root,*root.parents):
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise ValueError()
    legacy={relative:inspect(folder/relative,'directory' if relative in ('','Default') else 'file')
            for relative in ('','Default','Local State','Default/Preferences','Last Version')}
    directories={relative:inspect(folder/relative,'directory',True)
                 for relative in ('Default/Network','Default/Sessions')}
    critical={};groups={'metadata':0,'database':0,'session':0};files={}
    def add(relative,group,limit,optional=True):
        value=legacy[relative] if relative in legacy else inspect(folder/relative,'file',optional)
        if value is not None:
            if value[2]>limit:raise ValueError()
            groups[group]+=value[2];files[relative]=value
        if relative not in legacy:critical[relative]=value
    for relative in ('Local State','Default/Preferences','Last Version'):
        add(relative,'metadata',_PROFILE_METADATA_BYTES,False)
    for database in _PROFILE_DATABASES:
        for suffix in ('','-wal','-shm','-journal'):
            add(database+suffix,'database',_PROFILE_DATABASE_BYTES)
    add('Default/~TabGroups','session',_PROFILE_METADATA_BYTES)
    if directories['Default/Sessions'] is not None:
        with os.scandir(folder/'Default/Sessions') as entries:
            for index,entry in enumerate(entries):
                if index>=_PROFILE_SESSION_ENTRIES or time.monotonic()>=deadline:raise ValueError()
                if entry.name.startswith(('Session_','Tabs_')):
                    add('Default/Sessions/'+entry.name,'session',_PROFILE_SESSION_FILE_BYTES,False)
    if (groups['database']>_PROFILE_DATABASE_BYTES or groups['session']>_PROFILE_SESSION_BYTES or
            len(files)>_PROFILE_IDENTITY_FILES):raise ValueError()
    return {'legacy':legacy,'directories':directories,'critical':critical,'files':files}


def _profile_digest(path,expected,deadline):
    digest=hashlib.sha256();size=0
    if _profile_stamp(path.lstat())!=expected:raise ValueError()
    with path.open('rb') as stream:
        opened=_profile_stamp(os.fstat(stream.fileno()))
        # Windows path and descriptor ctime differ; each API is compared to
        # itself, while shared identity/length/mtime must agree across APIs.
        if opened[:4]!=expected[:4] or not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):raise ValueError()
        while True:
            if time.monotonic()>=deadline:raise ValueError()
            block=stream.read(min(1024*1024,expected[2]+1-size))
            if not block:break
            size+=len(block)
            if size>expected[2]:raise ValueError()
            digest.update(block)
        if size!=expected[2] or _profile_stamp(os.fstat(stream.fileno()))!=opened:raise ValueError()
    if _profile_stamp(path.lstat())!=expected:raise ValueError()
    return digest.hexdigest()


def profile_identity(configuration,identity):
    """Bind preparation to bounded, twice-read closed-source configuration inputs."""
    identity=_identity(identity);deadline=time.monotonic()+_PROFILE_IDENTITY_SECONDS
    try:
        root=profile_root(configuration);folder=root/identity
        before=_profile_inventory(root,folder,deadline);hashes=None
        for _ in range(2):
            observed={relative:_profile_digest(folder/relative,value,deadline)
                      for relative,value in sorted(before['files'].items())}
            if hashes is not None and hashes!=observed:raise ValueError()
            if _profile_inventory(root,folder,deadline)!=before:raise ValueError()
            hashes=observed
        output=[value+([hashes[relative]] if relative in hashes else [])
                for relative,value in before['legacy'].items()]
        critical={relative:None if value is None else {'file':value,'sha256':hashes[relative]}
                  for relative,value in before['critical'].items()}
        return {'path':os.path.normcase(str(folder.absolute())),'files':output,
                'critical':{'format':1,'directories':before['directories'],'files':critical}}
    except (OSError,ValueError,TypeError):
        raise LocalBrowserError('来源关键资料正在变化、超出安全检查范围或不能安全读取，请正常关闭后重新准备。') from None


class PreparedSources:
    def __init__(self,root):self.root=Path(root);self.database=self.root/'prepared-sources.sqlite';self._ids_cache=None

    @contextmanager
    def connect(self):
        con=sqlite3.connect(self.database,timeout=5)
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback();raise
        finally:con.close()

    def ids(self):
        if not self.database.is_file():return set()
        current=stamp(self.database)
        if self._ids_cache and self._ids_cache[0]==current:return self._ids_cache[1]
        with self.connect() as con:
            result={row[0] for row in con.execute('SELECT source_id FROM sources')}
        self._ids_cache=(current,result)
        return result

    def get(self,identity):
        identity=_identity(identity)
        if identity not in self.ids():return None
        with self.connect() as con:
            row=con.execute('SELECT payload FROM sources WHERE source_id=?',(identity,)).fetchone()
        if not row:return None
        try:
            value=json.loads(protect(row[0],decrypt=True,root=self.root))
            if _validate(value)[0]!=identity:raise ValueError()
            font=value.get('native',{}).get('FontConfig')
            if isinstance(font,dict) and font.get('BasePath'):font['BasePath']=decode_path(font['BasePath'],self.root)
            return value
        except (ValueError,TypeError,KeyError):
            raise LocalBrowserError('本地来源准备缓存不匹配或损坏，未套用其他窗口配置。') from None

    def put(self,value):
        identity,digest=_validate(value);value=copy.deepcopy(value);value['configuration_sha256']=digest
        font=value.get('native',{}).get('FontConfig')
        if isinstance(font,dict) and font.get('BasePath'):font['BasePath']=encode_path(font['BasePath'],self.root)
        raw=json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
        if len(raw)>16*1024*1024:raise LocalBrowserError('来源配置超过安全大小，未保存。')
        encrypted=protect(raw,root=self.root)
        with self.connect() as con:
            con.execute('PRAGMA journal_mode=WAL');con.execute('PRAGMA synchronous=FULL')
            con.execute('CREATE TABLE IF NOT EXISTS sources (source_id TEXT PRIMARY KEY,payload BLOB NOT NULL)')
            con.execute('INSERT INTO sources VALUES (?,?) ON CONFLICT(source_id) DO UPDATE SET payload=excluded.payload',(identity,encrypted))
        self._ids_cache=None


def _reader(configuration):
    """Use the owner's session for metadata preview or preparation, never launch."""
    values=globals_for(configuration) if (configuration.vendor_data/'db.sqlite').is_file() else {}
    session=configuration.root/'vendor-session.bin'
    if not values.get('app_token') and session.is_file():values=read_encrypted(session,root=configuration.root)
    if not values.get('app_token'):raise LocalBrowserError('首次导入需联网补齐来源配置；请先在比特正常登录，已有本地窗口不受影响。')
    reader=copy.copy(configuration);reader.independent=False
    reader.authorization=lambda:dict(values)
    return reader


def prepare(configuration,identity,expected_core):
    identity=_identity(identity)
    before=profile_identity(configuration,identity)
    native_before=source_signature_identity(configuration,identity)
    reader=_reader(configuration)
    full=reader.source_settings(identity)
    try:
        if _identity(full['id'])!=identity:raise ValueError()
        fp=full['browserFingerPrint']
        if fp.get('browserId') and _identity(fp['browserId'])!=identity:raise ValueError()
        if str(fp['coreVersion'])!=str(expected_core) or fp.get('coreProduct')!='chrome':raise ValueError()
        extension=fp.get('extendOptions')
        if isinstance(extension,str):extension=json.loads(extension);fp['extendOptions']=extension
        protected=source_protection(fp)
    except (ValueError,TypeError,KeyError):
        raise LocalBrowserError('返回的来源标识、内核或保护配置不匹配，未复制资料。') from None
    frozen=None
    if any(fp.get(key) for key in ('isIpCreateLanguage','isIpCreateTimeZone','isIpCreatePosition','isIpCreateDisplayLanguage')):
        saved=full.get('lastIp')
        if not saved and (configuration.vendor_data/'db.sqlite').is_file():
            with snapshot(configuration.vendor_data/'db.sqlite') as con:
                rows=con.execute('SELECT value FROM browser_temp_data WHERE browser_id=? AND type=?',(identity,'LAST_IP_SYNCED')).fetchall()
            if len(rows)==1:
                try:saved=json.loads(rows[0][0]).get('lastIp')
                except (ValueError,TypeError):pass
        try:parsed=ipaddress.ip_address(str(saved or ''))
        except ValueError:raise LocalBrowserError('来源最后使用的出口信息缺失，未用当前网络猜测原指纹。') from None
        frozen=reader.vendor('/v1/apis/ipgeoMethod',{'ip':str(parsed),'method':full.get('ipCheckService') or 'ip123in','checkExists':0})
        if not isinstance(frozen,dict):raise LocalBrowserError('来源保存的网络环境信息不完整，未导入。')
        frozen=copy.deepcopy(frozen)
        if frozen.get('ip') and ipaddress.ip_address(str(frozen['ip']))!=parsed:raise LocalBrowserError('来源网络环境对应错误，未导入。')
        frozen['ip']=str(parsed)
    native,_=reader.build_source(full,sign=False,frozen_geo=frozen)
    if native.get('DataProtect')!=protected:raise LocalBrowserError('资料保护配置与来源不匹配，未保存。')
    if profile_identity(configuration,identity)!=before:
        raise LocalBrowserError('补齐配置期间来源资料已变化，未保存旧配置与新资料的组合，请重新同步。')
    if source_signature_identity(configuration,identity)!=native_before:
        raise LocalBrowserError('补齐配置期间来源实际启动文件已变化，请正常关闭来源后重新同步。')
    value={'format':1,'id':identity,'full':full,'detail':copy.deepcopy(full),'native':native,'profile_identity':before,
        'native_source':native_before,
        'configuration_sha256':hashlib.sha256(json.dumps(full,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()}
    if native_before.get('present') is False:value['import_note']=PUBLIC_SEED_IMPORT_NOTE
    configuration.prepared_sources().put(value)
    return value
