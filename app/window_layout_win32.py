"""Small Win32 adapter: thread-local DPI context and non-activating window moves."""
import ctypes
from ctypes import wintypes as w
import os

from local_state import LocalBrowserError


class MonitorInfo(ctypes.Structure):
    _fields_ = [('size', w.DWORD), ('monitor', w.RECT), ('work', w.RECT),
                ('flags', w.DWORD), ('device', w.WCHAR * 32)]


class MinMaxInfo(ctypes.Structure):
    _fields_ = [(name, w.POINT) for name in
                ('reserved', 'max_size', 'max_position', 'min_track', 'max_track')]


class Desktop:
    def __init__(self):
        if os.name != 'nt':
            raise LocalBrowserError('窗口排列仅支持 Windows 桌面。')
        self.user = ctypes.WinDLL('user32', use_last_error=True)
        self.window_callback = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
        self.monitor_callback = ctypes.WINFUNCTYPE(w.BOOL, w.HANDLE, w.HDC, ctypes.POINTER(w.RECT), w.LPARAM)
        signatures = {
            'EnumWindows': ([self.window_callback, w.LPARAM], w.BOOL),
            'EnumDisplayMonitors': ([w.HDC, ctypes.POINTER(w.RECT), self.monitor_callback, w.LPARAM], w.BOOL),
            'GetMonitorInfoW': ([w.HANDLE, ctypes.POINTER(MonitorInfo)], w.BOOL),
            'GetWindowThreadProcessId': ([w.HWND, ctypes.POINTER(w.DWORD)], w.DWORD),
            'GetClassNameW': ([w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int),
            'GetWindow': ([w.HWND, w.UINT], w.HWND),
            'GetWindowLongW': ([w.HWND, ctypes.c_int], w.LONG),
            'IsWindowVisible': ([w.HWND], w.BOOL),
            'IsIconic': ([w.HWND], w.BOOL),
            'IsZoomed': ([w.HWND], w.BOOL),
            'ShowWindowAsync': ([w.HWND, ctypes.c_int], w.BOOL),
            'GetWindowRect': ([w.HWND, ctypes.POINTER(w.RECT)], w.BOOL),
            'SetWindowPos': ([w.HWND, w.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.UINT], w.BOOL),
            'SendMessageTimeoutW': ([w.HWND, w.UINT, w.WPARAM, w.LPARAM, w.UINT, w.UINT,
                                     ctypes.POINTER(ctypes.c_size_t)], w.LPARAM),
            'SetThreadDpiAwarenessContext': ([ctypes.c_void_p], ctypes.c_void_p),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.user, name)
            function.argtypes, function.restype = args, result
        self.dwm = ctypes.WinDLL('dwmapi')
        self.dwm.DwmGetWindowAttribute.argtypes = [w.HWND, w.DWORD, ctypes.c_void_p, w.DWORD]
        self.dwm.DwmGetWindowAttribute.restype = ctypes.c_long

    def __enter__(self):
        self.previous_dpi = self.user.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
        if not self.previous_dpi:
            self.previous_dpi = self.user.SetThreadDpiAwarenessContext(ctypes.c_void_p(-3))
        if not self.previous_dpi:
            raise LocalBrowserError('无法取得显示器缩放坐标，请在 Windows 桌面重试。')
        return self

    def __exit__(self, *_):
        self.user.SetThreadDpiAwarenessContext(self.previous_dpi)

    def monitors(self):
        result, errors = [], []
        def visit(handle, _dc, _rect, _data):
            info = MonitorInfo()
            info.size = ctypes.sizeof(info)
            if not self.user.GetMonitorInfoW(handle, ctypes.byref(info)):
                errors.append(True)
                return True
            rect = info.work
            if rect.right > rect.left and rect.bottom > rect.top:
                result.append(dict(id=info.device, primary=bool(info.flags & 1), x=rect.left, y=rect.top,
                                   width=rect.right - rect.left, height=rect.bottom - rect.top))
            return True
        if not self.user.EnumDisplayMonitors(None, None, self.monitor_callback(visit), 0) or errors:
            raise LocalBrowserError('无法读取显示器工作区，请重试。')
        result.sort(key=lambda m: (not m['primary'], m['x'], m['y'], m['id']))
        for index, item in enumerate(result, 1):
            item['label'] = f"显示器 {index}{'（主屏）' if item['primary'] else ''} · {item['width']} × {item['height']}"
        return result

    def _browser_window(self, handle):
        if not self.user.IsWindowVisible(handle) or self.user.GetWindow(handle, 4):
            return False
        if self.user.GetWindowLongW(handle, -20) & 0x80:
            return False
        name = ctypes.create_unicode_buffer(256)
        if not self.user.GetClassNameW(handle, name, len(name)) or name.value != 'Chrome_WidgetWin_1':
            return False
        cloaked = w.DWORD()
        if self.dwm.DwmGetWindowAttribute(handle, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) != 0:
            return False
        return not cloaked.value

    def owns(self, handle, pid):
        owner = w.DWORD()
        self.user.GetWindowThreadProcessId(handle, ctypes.byref(owner))
        return owner.value == pid and self._browser_window(handle)

    def windows(self):
        result = {}
        def visit(handle, _data):
            if self._browser_window(handle):
                owner = w.DWORD()
                self.user.GetWindowThreadProcessId(handle, ctypes.byref(owner))
                if owner.value:
                    result.setdefault(owner.value, []).append(handle)
            return True
        if not self.user.EnumWindows(self.window_callback(visit), 0):
            raise LocalBrowserError('无法读取桌面窗口，请重试。')
        return result

    def move(self, handle, rect):
        if self.user.IsIconic(handle) or self.user.IsZoomed(handle):
            if not self.user.ShowWindowAsync(handle, 4):  # SW_SHOWNOACTIVATE restores without focusing.
                return False
        return bool(self.user.SetWindowPos(handle, None, *rect, 0x0004 | 0x0010 | 0x0200 | 0x4000))

    def rectangle(self, handle):
        if self.user.IsIconic(handle) or self.user.IsZoomed(handle):
            return None
        rect = w.RECT()
        if not self.user.GetWindowRect(handle, ctypes.byref(rect)):
            return None
        return rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top

    def constrained_size(self, handle, requested, timeout_ms):
        info, result = MinMaxInfo(), ctypes.c_size_t()
        # System messages marshal this structure across processes; a hung window
        # must not turn arrangement into an unbounded synchronous call.
        if not self.user.SendMessageTimeoutW(handle, 0x24, 0, ctypes.addressof(info),
                                            0x0001 | 0x0002, timeout_ms, ctypes.byref(result)):
            return None
        minimum = (info.min_track.x, info.min_track.y)
        maximum = (info.max_track.x, info.max_track.y)
        if any(not 0 < low <= high <= 32767 for low, high in zip(minimum, maximum)):
            return None
        return tuple(max(low, min(value, high)) for value, low, high in zip(requested, minimum, maximum))
