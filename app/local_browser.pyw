"""Local desktop manager. Browser profiles remain owned by independent kernels."""
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from browser_core import APP_ROOT,DATA_ROOT
from manager_service import ManagerService
from installation import initialize_installation

TITLE='本地指纹浏览器'

class Bridge:
    def __init__(self,service): self._service=service
    def request(self,action,payload=None): return self._service.request(action,payload)

def main():
    if '--self-check' in sys.argv:
        initialize_installation()
        s=ManagerService(); rows=s.store.all()
        print(json.dumps({'windows':len(rows),'profiles_present':all(Path(p['_runtime']['profile_path']).is_dir() for p in rows),
            'fingerprints_present':all(Path(p['_runtime']['fingerprint_path']).is_file() for p in rows),'installed_cores':len(s.cores()),'bundled_cores':sorted(s.engines.available(),key=int),'ui_present':(APP_ROOT/'ui/index.html').is_file()},ensure_ascii=False))
        return
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateMutexW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.LPCWSTR]; kernel.CreateMutexW.restype=wintypes.HANDLE
    handle=kernel.CreateMutexW(None,False,'LocalBrowser-'+hashlib.sha256(str(APP_ROOT).encode()).hexdigest()[:24])
    try:
        if ctypes.get_last_error()==183:
            user=ctypes.WinDLL('user32'); user.FindWindowW.argtypes=[wintypes.LPCWSTR,wintypes.LPCWSTR]; user.FindWindowW.restype=wintypes.HWND
            window=user.FindWindowW(None,TITLE)
            if window: user.ShowWindow(window,9); user.SetForegroundWindow(window)
            return
        import webview
        bundled_webview=APP_ROOT.parent/'runtime/webview2'
        if (bundled_webview/'msedgewebview2.exe').is_file():webview.settings['WEBVIEW2_RUNTIME_PATH']=str(bundled_webview)
        initialize_installation()
        service=ManagerService()
        window=webview.create_window(TITLE,str(APP_ROOT/'ui/index.html'),js_api=Bridge(service),width=1460,height=920,min_size=(900,600),background_color='#f5f7fa',text_select=True)
        service.window=window
        def closing():
            if not service.operations.acquire(blocking=False):
                ctypes.windll.user32.MessageBoxW(None,'请等待当前操作完成后再退出。','正在处理',0x40); return False
            try:
                settings=service.settings()
                if settings['confirm_close'] and not window.create_confirmation_dialog('退出管理器','确定退出本地管理器？'+('已打开的浏览器将正常保存并关闭。' if settings['close_behavior']=='close_browsers' else '已打开的浏览器会继续运行。')): return False
                if settings['close_behavior']=='close_browsers':
                    errors=0
                    for identity in list(service.controller.profiles):
                        try: service.close(identity)
                        except Exception: errors+=1
                    if errors:
                        ctypes.windll.user32.MessageBoxW(None,'部分浏览器仍在保存，请稍候再退出；未强制结束进程。','尚未退出',0x40); return False
            finally: service.operations.release()
        window.events.closing+=closing
        webview.start(gui='edgechromium',private_mode=True,storage_path=str(DATA_ROOT/'manager-webview'))
    except Exception:
        ctypes.windll.user32.MessageBoxW(None,'无法启动本地管理器。请保留完整程序目录、目录密钥及运行环境；便携模式不要求原Windows用户。','无法启动',0x10)
    finally:
        if handle:
            kernel.CloseHandle.argtypes=[wintypes.HANDLE]; kernel.CloseHandle(handle)

if __name__=='__main__': main()
