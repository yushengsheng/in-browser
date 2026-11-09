"""Installed-font filtering; the kernel's external-font path is not used."""
import base64
from email.utils import formatdate
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import quote

import requests
from local_state import LocalBrowserError

class FontAssets:
    def __init__(self,configuration):
        self.configuration=configuration; self.root=configuration.root/'font-assets'; self.root.mkdir(exist_ok=True)
        self.credentials=None; self.expires=0

    def _get(self,key,limit):
        if not re.fullmatch(r'fonts/names/(?:Windows|macOS|Linux|iOS|Android)\.json',key):
            raise LocalBrowserError('字体资源路径不受支持。')
        if not self.credentials or time.monotonic()>self.expires:
            self.credentials=self.configuration.vendor('/v1/sysUsers/getOSStoken',{'refresh':True})
            self.expires=time.monotonic()+300
        credentials=self.credentials; bucket='browser-fingerprint-assets'; date=formatdate(usegmt=True)
        token=credentials.get('securityToken') or credentials.get('stsToken')
        if not token or not credentials.get('accessKeyId') or not credentials.get('accessKeySecret'):
            raise LocalBrowserError('未取得原字体资源的正常访问授权。')
        canonical='GET\n\n\n'+date+'\nx-oss-security-token:'+token+'\n/'+bucket+'/'+key
        signature=base64.b64encode(hmac.new(credentials['accessKeySecret'].encode(),canonical.encode(),hashlib.sha1).digest()).decode()
        try:
            with requests.Session() as session:
                session.trust_env=False
                with session.get('https://'+bucket+'.oss-accelerate.aliyuncs.com/'+quote(key,safe='/'),
                    headers={'Date':date,'x-oss-security-token':token,'Authorization':'OSS '+credentials['accessKeyId']+':'+signature},timeout=(6,25),stream=True) as reply:
                    reply.raise_for_status(); raw=bytearray()
                    for block in reply.iter_content(65536):
                        raw.extend(block)
                        if len(raw)>limit: raise ValueError()
                    return bytes(raw)
        except Exception: raise LocalBrowserError('字体资源下载失败，请检查网络和原客户端授权；窗口未保存。') from None

    def _json(self,key):
        path=self.root/key
        if path.exists(): raw=path.read_bytes()
        else:
            raw=self._get(key,5_000_000)
            try: json.loads(raw)
            except ValueError: raise LocalBrowserError('原字体资源格式无效。') from None
            path.parent.mkdir(parents=True,exist_ok=True); temporary=path.with_suffix('.tmp')
            temporary.write_bytes(raw); os.replace(temporary,path)
        return json.loads(raw)

    def build(self,fp):
        if str(fp.get('fontType','0'))=='0': return None
        import winreg
        installed=set()
        for hive in [winreg.HKEY_LOCAL_MACHINE,winreg.HKEY_CURRENT_USER]:
            try:
                with winreg.OpenKey(hive,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts') as key:
                    for index in range(winreg.QueryInfoKey(key)[1]):
                        name=winreg.EnumValue(key,index)[0].split(' (')[0]
                        installed.update(part.strip() for part in name.split(' & ') if part.strip())
            except OSError: pass
        requested=[n.strip() for n in str(fp.get('font') or '').split(',') if n.strip()]
        known={n.casefold() for n in installed}
        if any(not any(alias.casefold() in known for alias in name.split(';')) for name in requested):
            raise LocalBrowserError('所选字体未在本机安装。当前内核附加字体文件存在加载兼容问题，请使用已安装字体或系统字体模式。')
        if str(fp.get('fontType'))=='1':
            names=requested or sorted(installed)
            if not names: raise LocalBrowserError('未找到可用的本机字体。')
            return {'BasePath':str(self.root/'filters-only-no-files'),'Names':names,'BlockFallbackList':[],'Files':[]}
        kind=fp.get('ostype'); system=str(fp.get('os',''))
        platform=kind if kind in ['Android','IOS'] else ('macOS' if system=='MacIntel' else 'Linux' if system.startswith('Linux') else 'Windows')
        if platform=='IOS': platform='iOS'
        names=self._json('fonts/names/'+platform+'.json'); major=int(str(fp.get('platformVersion') or '0').split('.')[0])
        if platform=='Windows':
            baseline=list(names.get('en-US',[])); locale=str(fp.get('displayLanguages') or fp.get('languages') or '').lower()
            for key,value in names.items():
                if key!='en-US' and key.lower() in locale: baseline.extend(value)
        elif platform=='macOS': baseline=names.get('15' if major>=15 else '14',[])
        elif platform=='Android': baseline=names.get('14' if major>=14 else '13',[])
        elif platform=='iOS': baseline=names.get('18',[])
        else: baseline=names
        if not isinstance(baseline,list) or not baseline: raise LocalBrowserError('所选平台没有匹配的字体目录。')
        baseline=[name for name in baseline if any(alias.casefold() in known for alias in name.split(';'))]
        names=list(dict.fromkeys(baseline+requested))
        if not names: raise LocalBrowserError('所选平台的字体尚未在本机安装，请改用系统字体或指定本机已有字体。')
        return {'BasePath':str(self.root/'filters-only-no-files'),'Names':names,'BlockFallbackList':[],'Files':[]}
