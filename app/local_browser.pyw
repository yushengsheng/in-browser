"""Local desktop manager. Browser profiles remain owned by independent kernels."""
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode=True
# Do not read historical application bytecode after replacing source files.
# This random, uncreated path also prevents direct pythonw launches using it.
sys.pycache_prefix=str(Path(__file__).resolve().parents[1]/('.program-no-cache-'+os.urandom(16).hex()))
sys.path.insert(0,str(Path(__file__).resolve().parent))
try:
    from update_guard import require_complete_installation
    require_complete_installation(Path(__file__).resolve().parents[1])
except Exception:
    if '--self-check' in sys.argv:
        print(json.dumps({'success':False,'error':'program_update_incomplete_or_corrupt'}))
    else:
        try:
            ctypes.windll.user32.MessageBoxW(None,'程序更新尚未完成或公共程序文件校验失败。请保留当前目录与资料，使用更新工具恢复后再启动。','无法启动',0x10)
        except (AttributeError,OSError):
            pass
    raise SystemExit(1)

from browser_core import APP_ROOT,DATA_ROOT
from manager_service import ManagerService
from installation import initialize_installation

BASE_TITLE='本地指纹浏览器'

def _window_title():
    try:
        with (APP_ROOT.parent/'VERSION').open(encoding='utf-8-sig') as handle:
            version=handle.read(129).strip()
        if len(version)<=128 and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?',version):
            return BASE_TITLE+' v'+version
    except (OSError,UnicodeError):
        pass
    return BASE_TITLE

TITLE=_window_title()

class Bridge:
    def __init__(self,service): self._service=service
    def request(self,action,payload=None): return self._service.request(action,payload)

def _focus_existing_manager():
    import psutil
    user=ctypes.WinDLL('user32')
    user.FindWindowExW.argtypes=[wintypes.HWND,wintypes.HWND,wintypes.LPCWSTR,wintypes.LPCWSTR]
    user.FindWindowExW.restype=wintypes.HWND
    user.GetWindowTextW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
    user.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
    user.ShowWindow.argtypes=[wintypes.HWND,ctypes.c_int]
    user.SetForegroundWindow.argtypes=[wintypes.HWND]
    entry=os.path.normcase(str(APP_ROOT/'local_browser.pyw'))
    runtime=Path(sys.executable).resolve().parent
    window=None
    for _ in range(1024):
        window=user.FindWindowExW(None,window,None,None)
        if not window:return False
        title=ctypes.create_unicode_buffer(256)
        user.GetWindowTextW(window,title,len(title))
        if title.value!=BASE_TITLE and not title.value.startswith(BASE_TITLE+' v'):continue
        owner=wintypes.DWORD();user.GetWindowThreadProcessId(window,ctypes.byref(owner))
        try:
            process=psutil.Process(owner.value)
            with process.oneshot():
                created=process.create_time();executable=Path(process.exe()).resolve()
                arguments=process.cmdline()
            if executable.parent!=runtime or executable.name.casefold() not in ('python.exe','pythonw.exe'):continue
            if not any(os.path.normcase(str(Path(value).resolve()))==entry for value in arguments[1:]
                       if isinstance(value,str) and Path(value).suffix.casefold()=='.pyw'):continue
            current=wintypes.DWORD();user.GetWindowThreadProcessId(window,ctypes.byref(current))
            if current.value!=owner.value or abs(psutil.Process(owner.value).create_time()-created)>=.01:continue
            user.ShowWindow(window,9);user.SetForegroundWindow(window)
            return True
        except (psutil.Error,OSError,ValueError):continue
    return False

def _guard_initial_webview_cleanup(window):
    browser=window.native.browser
    original_cleanup=browser.clear_user_data
    def cleanup():
        # pywebview 6.1 reads BrowserProcessId before disposing its control.
        # Early close has no CoreWebView2 yet; retain potentially busy cache.
        if browser.webview.CoreWebView2 is None:
            browser.webview.Dispose()
            return
        return original_cleanup()
    browser.clear_user_data=cleanup

def main():
    if '--self-check' in sys.argv:
        initialize_installation()
        s=ManagerService(); rows=s.store.all()
        print(json.dumps({'windows':len(rows),'profiles_present':all(Path(p['_runtime']['profile_path']).is_dir() for p in rows),
            'fingerprints_present':all(Path(p['_runtime']['fingerprint_path']).is_file() for p in rows),'installed_cores':len(s.cores()),'bundled_cores':sorted(s.engines.available(),key=int),'ui_present':(APP_ROOT/'ui/index.html').is_file()},ensure_ascii=False))
        return
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateMutexW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.LPCWSTR]; kernel.CreateMutexW.restype=wintypes.HANDLE
    handle=kernel.CreateMutexW(None,False,'LocalBrowser-'+hashlib.sha256(os.path.normcase(str(APP_ROOT)).encode()).hexdigest()[:24])
    try:
        if ctypes.get_last_error()==183:
            _focus_existing_manager()
            return
        bundled_webview=APP_ROOT.parent/'runtime/webview2'
        if not (bundled_webview/'msedgewebview2.exe').is_file():
            raise RuntimeError('随包WebView2运行环境缺失，请恢复完整便携目录；不会改用系统环境。')
        os.environ['WEBVIEW2_BROWSER_EXECUTABLE_FOLDER']=str(bundled_webview)
        os.environ['WEBVIEW2_USER_DATA_FOLDER']=str(DATA_ROOT/'manager-webview')
        for name in ('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS','WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER',
                     'WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER'):
            os.environ.pop(name,None)
        import webview
        webview.settings['WEBVIEW2_RUNTIME_PATH']=str(bundled_webview)
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
                service.shutdown_batches()
            finally: service.operations.release()
        window.events.closing+=closing
        window.events.before_show+=_guard_initial_webview_cleanup
        webview.start(gui='edgechromium',private_mode=True,storage_path=str(DATA_ROOT/'manager-webview'))
    except Exception:
        ctypes.windll.user32.MessageBoxW(None,'无法启动本地管理器。请保留完整程序目录、目录密钥及运行环境；便携模式不要求原Windows用户。','无法启动',0x10)
    finally:
        if handle:
            kernel.CloseHandle.argtypes=[wintypes.HANDLE]; kernel.CloseHandle(handle)

if __name__=='__main__': main()
