"""A private Windows desktop for legacy probes without unified headless mode."""
import ctypes
from ctypes import wintypes
import os
import subprocess
import uuid

from local_state import LocalBrowserError


class ProbeDesktop:
    def __init__(self):
        self.handle=None
        if os.name!='nt':raise LocalBrowserError('此旧版内核的后台环境验证需要Windows，未启动窗口。')
        self.user=ctypes.WinDLL('user32',use_last_error=True)
        self.user.CreateDesktopW.argtypes=[wintypes.LPCWSTR,wintypes.LPCWSTR,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p]
        self.user.CreateDesktopW.restype=wintypes.HANDLE
        self.user.CloseDesktop.argtypes=[wintypes.HANDLE]
        self.user.CloseDesktop.restype=wintypes.BOOL
        self.name='LocalContinuityProbe_'+uuid.uuid4().hex
        self.handle=self.user.CreateDesktopW(self.name,None,None,0,0x01ff,None)
        if not self.handle:raise LocalBrowserError('无法创建旧版内核的后台验证桌面，未显示或启动检查窗口。')

    def startupinfo(self):
        if not self.handle:raise LocalBrowserError('后台验证桌面已关闭，未启动检查窗口。')
        info=subprocess.STARTUPINFO();info.lpDesktop=self.name
        return info

    def close(self):
        if self.handle:
            if not self.user.CloseDesktop(self.handle):raise LocalBrowserError('后台验证桌面未能释放，请保留资料并重启电脑后再试。')
            self.handle=None
