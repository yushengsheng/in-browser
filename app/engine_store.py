"""Verified, self-contained browser installations with atomic local deployment."""
import ctypes
from ctypes import wintypes
import json
import hashlib
import os
from pathlib import Path
import shutil
import threading
import uuid

from browser_core import APP_ROOT,LocalBrowserError
from engine_validation import digest_file as sha256
from native_paths import absolute_path, io_path, resolved_path, tree_paths

def executable_major(path):
    library=ctypes.WinDLL('version',use_last_error=True)
    library.GetFileVersionInfoSizeW.argtypes=[wintypes.LPCWSTR,ctypes.POINTER(wintypes.DWORD)]
    library.GetFileVersionInfoW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p]
    library.VerQueryValueW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.UINT)]
    size=library.GetFileVersionInfoSizeW(str(io_path(path)),None)
    if not size: raise LocalBrowserError('无法验证所选内核的版本。')
    buffer=ctypes.create_string_buffer(size);value=ctypes.c_void_p();length=wintypes.UINT()
    if not library.GetFileVersionInfoW(str(io_path(path)),0,size,buffer) or not library.VerQueryValueW(buffer,'\\',ctypes.byref(value),ctypes.byref(length)):
        raise LocalBrowserError('无法验证所选内核的版本。')
    fields=ctypes.cast(value,ctypes.POINTER(wintypes.DWORD))
    if length.value<52 or fields[0]!=0xFEEF04BD:raise LocalBrowserError('所选文件不含有效的内核版本。')
    return str(fields[2]>>16)

class EngineStore:
    def __init__(self,root=None):
        self.root=resolved_path(root or APP_ROOT/'engines');self.lock=threading.RLock();self.checked={};self.source_manifests={}

    def available(self):
        result={}
        if io_path(self.root).exists():
            for folder in (absolute_path(item) for item in io_path(self.root).iterdir()):
                if folder.name.isdigit() and io_path(folder/'manifest.json').is_file():
                    try:result[folder.name]=str(self.resolve(folder.name))
                    except LocalBrowserError:pass
        return result

    def resolve(self,major):
        if not str(major).isdigit():raise LocalBrowserError('内核版本格式不正确。')
        return self._resolve_folder(self.root/str(major),str(major))

    def _resolve_folder(self,folder,major):
        manifest=folder/'manifest.json'
        try:
            if not resolved_path(folder).is_relative_to(self.root):raise ValueError()
            data=json.loads(io_path(manifest).read_text(encoding='utf-8'))
            if data.get('core_major')!=str(major) or data.get('format')!=1:raise ValueError()
            for relative,item in data['files'].items():
                path=resolved_path(folder/relative)
                if not path.is_relative_to(resolved_path(folder)) or not io_path(path).is_file() or io_path(path).stat().st_size!=item['size']:raise ValueError()
                stamp=(io_path(path).stat().st_mtime_ns,io_path(path).stat().st_size)
                key=str(path)
                if self.checked.get(key)!=stamp:
                    if sha256(path)!=item['sha256']:raise ValueError()
                    self.checked[key]=stamp
            executable=resolved_path(folder/data['executable'])
            if not executable.is_relative_to(resolved_path(folder)) or str(executable.relative_to(resolved_path(folder))) not in data['files'] or executable.name.casefold()!='bitbrowser.exe':raise ValueError()
            if executable_major(executable)!=str(major):raise ValueError()
            return executable
        except Exception:raise LocalBrowserError('本地内核不完整或文件发生变化，请重新部署对应内核；未使用原安装目录兜底。') from None

    def install(self,major,source):
        major=str(major)
        if not major.isdigit():raise LocalBrowserError('内核版本格式不正确。')
        with self.lock:
            executable=resolved_path(source);source=executable.parent
            if source.is_relative_to(self.root) and io_path(source/'manifest.json').is_file():return self._resolve_folder(source,major)
            if executable_major(executable)!=major:raise LocalBrowserError('内核版本与安装来源不符。')
            files=list(tree_paths(source))
            if any(io_path(p).is_symlink() or getattr(io_path(p).lstat(),'st_file_attributes',0)&0x400 for p in files):raise LocalBrowserError('内核包含特殊链接，未部署。')
            stamp=tuple((str(p.relative_to(source)),io_path(p).stat().st_size,io_path(p).stat().st_mtime_ns) for p in files if io_path(p).is_file())
            cached=self.source_manifests.get(str(source))
            if cached and cached[0]==stamp:before=cached[1]
            else:
                before={str(p.relative_to(source)):{'size':io_path(p).stat().st_size,'sha256':sha256(p)} for p in files if io_path(p).is_file()}
                self.source_manifests[str(source)]=(stamp,before)
            destination=self.root/major
            if io_path(destination).exists():
                current=json.loads(io_path(destination/'manifest.json').read_text(encoding='utf-8'))
                if current.get('files')==before:return self._resolve_folder(destination,major)
                # Keep earlier builds immutable for windows already imported.
                digest=hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest()[:16]
                destination=self.root/(major+'-'+digest)
                if io_path(destination).exists():
                    if json.loads(io_path(destination/'manifest.json').read_text(encoding='utf-8')).get('files')!=before:raise LocalBrowserError('本地内核版本目录冲突，未覆盖。')
                    return self._resolve_folder(destination,major)
            io_path(self.root).mkdir(parents=True,exist_ok=True)
            total=sum(io_path(p).stat().st_size for p in files if io_path(p).is_file())
            if shutil.disk_usage(io_path(self.root)).free<total*1.15+50_000_000:raise LocalBrowserError('磁盘空间不足，未部署内核。')
            staging=self.root/('.install-'+uuid.uuid4().hex)
            try:
                shutil.copytree(io_path(source),io_path(staging))
                if any(sha256(staging/name)!=item['sha256'] or sha256(source/name)!=item['sha256'] for name,item in before.items()):raise LocalBrowserError('内核复制校验失败，原文件未修改。')
                data={'format':1,'core_major':major,'executable':executable.name,'files':before}
                manifest=staging/'manifest.json'
                with io_path(manifest).open('w',encoding='utf-8') as output:json.dump(data,output,ensure_ascii=False);output.flush();os.fsync(output.fileno())
                os.replace(io_path(staging),io_path(destination))
                return self._resolve_folder(destination,major)
            except Exception:
                if io_path(staging).exists() and resolved_path(staging).parent==self.root:shutil.rmtree(io_path(staging))
                raise
