"""Arrange owned desktop windows without touching browser profiles or lifecycle."""
from contextlib import contextmanager
import math
import os
from pathlib import Path
import time

import psutil
from browser_processes import ProfileProcessSnapshot, _is_browser, _switch_values
from local_state import LocalBrowserError

DEFAULTS = dict(mode='auto', monitor='primary', start_x=0, start_y=0,
                width=640, height=600, columns=3, gap_x=0, gap_y=0,
                step_x=30, step_y=30, order='asc')
SETTING_KEY = 'window_layout'
LIMITS = dict(start_x=(0, 100000), start_y=(0, 100000), width=(120, 32767),
              height=(40, 32767), columns=(1, 1000), gap_x=(0, 10000),
              gap_y=(0, 10000), step_x=(0, 10000), step_y=(0, 10000))


def validate_settings(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise LocalBrowserError('排列设置格式不正确。')
    settings = {**DEFAULTS, **value}
    if settings['mode'] not in ('auto', 'grid', 'cascade') or settings['order'] not in ('asc', 'desc'):
        raise LocalBrowserError('请选择有效的排列方式和顺序。')
    if not isinstance(settings['monitor'], str) or not 1 <= len(settings['monitor']) <= 128:
        raise LocalBrowserError('请选择有效的显示器。')
    for key, (lower, upper) in LIMITS.items():
        number = settings[key]
        if type(number) is not int or not lower <= number <= upper:
            raise LocalBrowserError('排列参数须为范围内的整数；窗口宽度至少120、高度至少40像素。')
    return settings


def select_monitor(settings, monitors):
    if not monitors:
        raise LocalBrowserError('未找到可用的桌面显示器。')
    primary = next((m for m in monitors if m['primary']), monitors[0])
    if settings['monitor'] == 'primary':
        return primary, False
    return next(((m, False) for m in monitors if m['id'] == settings['monitor']), (primary, True))


def rectangles(settings, monitor, count):
    """Physical pixels, relative to the selected monitor's taskbar-free work area."""
    if not count:
        return []
    width, height = monitor['width'], monitor['height']
    left, top = monitor['x'], monitor['y']
    if settings['mode'] == 'auto':
        options = []
        for columns in range(1, min(count, width // 120) + 1):
            rows = math.ceil(count / columns)
            w, h = width // columns, height // rows
            if h >= 40:
                # Prefer roughly landscape cells, then fewer unoccupied cells.
                options.append((abs(math.log((w / h) / (4 / 3))), columns * rows - count, columns, rows))
        if not options:
            raise LocalBrowserError('窗口过多，当前显示器放不下最小尺寸；请减少已打开窗口或使用对角线排列。')
        _, _, columns, rows = min(options)
        return [(left + (i % columns) * width // columns, top + (i // columns) * height // rows,
                 ((i % columns + 1) * width // columns) - (i % columns) * width // columns,
                 ((i // columns + 1) * height // rows) - (i // columns) * height // rows) for i in range(count)]
    x, y, w, h = (settings[key] for key in ('start_x', 'start_y', 'width', 'height'))
    if x + w > width or y + h > height:
        raise LocalBrowserError('起始位置或窗口尺寸超出显示器工作区；请调整参数或选择自适应。')
    if settings['mode'] == 'grid':
        columns = min(settings['columns'], count)
        rows = math.ceil(count / columns)
        if x + columns * w + (columns - 1) * settings['gap_x'] > width or y + rows * h + (rows - 1) * settings['gap_y'] > height:
            raise LocalBrowserError('当前宫格参数无法在显示器内排下全部窗口；请调整参数或选择自适应。')
        offsets = [((i % columns) * (w + settings['gap_x']), (i // columns) * (h + settings['gap_y'])) for i in range(count)]
    else:
        limits = [(available // step) + 1 for available, step in
                  ((width - x - w, settings['step_x']), (height - y - h, settings['step_y'])) if step]
        cycle = min(limits) if limits else 1
        offsets = [((i % cycle) * settings['step_x'], (i % cycle) * settings['step_y']) for i in range(count)]
    return [(left + x + dx, top + y + dy, w, h) for dx, dy in offsets]


def _canonical(path):
    return os.path.normcase(str(Path(path).resolve()))


def _owned_process(pid, created, runtime, root):
    """Revalidate PID creation time, main-process switches and exact package paths."""
    try:
        profile, fingerprint = (Path(runtime[key]).resolve() for key in ('profile_path', 'fingerprint_path'))
        if not profile.is_relative_to(root) or profile == root or not fingerprint.is_relative_to(root):
            return False
        process = psutil.Process(pid)
        with process.oneshot():
            if abs(process.create_time() - created) >= .01 or _canonical(process.exe()) != _canonical(runtime['core_path']):
                return False
            args = process.cmdline()
        if not _is_browser(args):
            return False
        for flag, expected in (('--user-data-dir', profile), ('--fingerprint-config', fingerprint)):
            values = _switch_values(args, flag)
            if (sum(arg == flag or arg.startswith(flag + '=') for arg in args) != 1 or
                    len(values) != 1 or not values[0].strip('"') or _canonical(values[0].strip('"')) != _canonical(expected)):
                return False
        return True
    except (psutil.Error, OSError, ValueError, TypeError, KeyError):
        return False


def _targets(service, desktop, settings):
    profiles = sorted((p for p in service.store.all() if not p.get('archived')),
                      key=lambda p: p['seq'], reverse=settings['order'] == 'desc')
    snapshot = ProfileProcessSnapshot(browser_names=[Path(p['_runtime']['core_path']).name for p in profiles])
    windows = desktop.windows()
    targets, seen, uncertain = [], set(), False
    for profile in profiles:
        runtime = profile['_runtime']
        for process in snapshot.browsers(runtime['profile_path']):
            try:
                created = process.create_time()
            except psutil.Error:
                uncertain = True
                continue
            if not _owned_process(process.pid, created, runtime, service.root):
                uncertain = True
                continue
            for handle in sorted(windows.get(process.pid, [])):
                if handle not in seen:
                    targets.append((handle, process.pid, created, runtime))
                    seen.add(handle)
        uncertain = uncertain or snapshot.uncertain(runtime['profile_path'])
    return targets, uncertain


@contextmanager
def _operation(service):
    if not service.operations.acquire(blocking=False):
        raise LocalBrowserError('程序正在处理其他窗口操作，请稍后再排列。')
    try:
        yield
    finally:
        service.operations.release()


def get_settings(service):
    from window_layout_win32 import Desktop
    settings = validate_settings(service.store.setting(SETTING_KEY, {}))
    with Desktop() as desktop:
        monitors = desktop.monitors()
    _, fallback = select_monitor(settings, monitors)
    return dict(settings=settings, monitors=monitors, monitor_fallback=fallback)


def save_settings(service, value):
    settings = validate_settings(value)
    with _operation(service):
        service.store.set_setting(SETTING_KEY, settings)
    return {'settings': settings}


def arrange(service):
    from window_layout_win32 import Desktop
    with _operation(service), Desktop() as desktop:
        settings = validate_settings(service.store.setting(SETTING_KEY, {}))
        monitor, fallback = select_monitor(settings, desktop.monitors())
        targets, uncertain = _targets(service, desktop, settings)
        planned = rectangles(settings, monitor, len(targets))
        result = dict(arranged=0, failed=0, skipped=0, total=len(targets), adjusted=0)
        pending = []
        constraint_deadline = None
        def valid(target):
            handle, pid, created, runtime = target
            return _owned_process(pid, created, runtime, service.root) and desktop.owns(handle, pid)
        for target, rect in zip(targets, planned):
            if not valid(target):
                result['skipped'] += 1
            else:
                before = desktop.rectangle(target[0])
                if desktop.move(target[0], rect):
                    pending.append((target, rect, before))
                else:
                    result['failed'] += 1
        deadline = time.monotonic() + 2
        while pending:
            remaining = []
            for target, rect, before in pending:
                if not valid(target):
                    result['skipped'] += 1
                    continue
                actual = desktop.rectangle(target[0])
                # DPI-unaware windows can round a physical coordinate by one pixel.
                if actual and all(abs(a - b) <= 1 for a, b in zip(actual, rect)):
                    result['arranged'] += 1
                elif (checked := time.monotonic()) >= deadline:
                    adjusted = False
                    if actual and all(abs(a - b) <= 1 for a, b in zip(actual[:2], rect[:2])):
                        adjusted = actual != before
                        if not adjusted:
                            if constraint_deadline is None:
                                constraint_deadline = checked + .2
                            query_budget = constraint_deadline - checked
                            if query_budget > 0:
                                size = desktop.constrained_size(target[0], rect[2:], min(100, max(1, int(query_budget * 1000))))
                                if not valid(target):
                                    result['skipped'] += 1
                                    continue
                                current = desktop.rectangle(target[0])
                                adjusted = (size is not None and size != rect[2:] and current == actual
                                            and all(abs(a - b) <= 1 for a, b in zip(actual[2:], size)))
                    if adjusted:
                        result['arranged'] += 1
                        result['adjusted'] += 1
                    else:
                        result['failed'] += 1
                else:
                    remaining.append((target, rect, before))
            pending = remaining
            if pending:
                time.sleep(.04)
    message = f"已排列 {result['arranged']} 个窗口。" if targets else (
        '未找到可确认归属的已打开窗口。' if uncertain else '当前没有可排列的已打开窗口。')
    if uncertain:
        message += '部分进程信息无法读取，未确认归属的窗口没有移动。'
    if result['skipped']:
        message += f"{result['skipped']} 个窗口已关闭或归属变化，已跳过。"
    if result['failed']:
        message += f"{result['failed']} 个窗口未完成排列，请重试。"
    if result['adjusted']:
        message += f"{result['adjusted']} 个窗口受浏览器尺寸限制，实际大小已由系统调整。"
    if fallback:
        message += '原显示器未连接，本次使用主显示器。'
    return dict(result, message=message)
