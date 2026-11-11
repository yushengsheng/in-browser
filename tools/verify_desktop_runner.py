"""Fail closed unless acceptance runs on the requested interactive x64 desktop."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def windows_facts():
    if os.name != 'nt':
        raise RuntimeError()

    class Version(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('major', wintypes.DWORD),
                    ('minor', wintypes.DWORD), ('build', wintypes.DWORD),
                    ('platform', wintypes.DWORD), ('service_pack', wintypes.WCHAR * 128),
                    ('service_major', wintypes.WORD), ('service_minor', wintypes.WORD),
                    ('suite', wintypes.WORD), ('product_type', wintypes.BYTE),
                    ('reserved', wintypes.BYTE)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    user = ctypes.WinDLL('user32', use_last_error=True)
    version = Version()
    version.size = ctypes.sizeof(version)
    query_version = ctypes.WinDLL('ntdll').RtlGetVersion
    query_version.argtypes = [ctypes.POINTER(Version)]
    query_version.restype = wintypes.LONG
    if query_version(ctypes.byref(version)) != 0:
        raise RuntimeError()

    # SYSTEM_INFO starts with the native architecture WORD. A 64-byte buffer
    # accommodates both native layouts, including an emulated Python process.
    system_info = ctypes.create_string_buffer(64)
    kernel.GetNativeSystemInfo.argtypes = [ctypes.c_void_p]
    kernel.GetNativeSystemInfo.restype = None
    kernel.GetNativeSystemInfo(system_info)
    architecture = ctypes.c_ushort.from_buffer(system_info).value
    # IsWow64Process2 identifies the actual host even under ARM64 x64 emulation.
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.WORD),
                                      ctypes.POINTER(wintypes.WORD)]
    kernel.IsWow64Process2.restype = wintypes.BOOL
    process_machine, native_machine = wintypes.WORD(), wintypes.WORD()
    if not kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process_machine),
                                  ctypes.byref(native_machine)):
        raise RuntimeError()
    session = wintypes.DWORD()
    kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.ProcessIdToSessionId.restype = wintypes.BOOL
    if not kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
        raise RuntimeError()

    user.GetProcessWindowStation.argtypes = []
    user.GetProcessWindowStation.restype = wintypes.HANDLE
    user.GetUserObjectInformationW.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                               ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.POINTER(wintypes.DWORD)]
    user.GetUserObjectInformationW.restype = wintypes.BOOL

    class ObjectFlags(ctypes.Structure):
        _fields_ = [('inherit', wintypes.BOOL), ('reserved', wintypes.BOOL),
                    ('flags', wintypes.DWORD)]

    needed = wintypes.DWORD()
    flags = ObjectFlags()
    station_visible = bool(user.GetUserObjectInformationW(
        user.GetProcessWindowStation(), 1, ctypes.byref(flags), ctypes.sizeof(flags),
        ctypes.byref(needed)) and flags.flags & 1)
    user.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    user.OpenInputDesktop.restype = wintypes.HANDLE
    user.CloseDesktop.argtypes = [wintypes.HANDLE]
    user.CloseDesktop.restype = wintypes.BOOL
    user.GetThreadDesktop.argtypes = [wintypes.DWORD]
    user.GetThreadDesktop.restype = wintypes.HANDLE
    kernel.GetCurrentThreadId.argtypes = []
    kernel.GetCurrentThreadId.restype = wintypes.DWORD

    def default_desktop(handle):
        name = ctypes.create_unicode_buffer(256)
        return bool(handle and user.GetUserObjectInformationW(
            handle, 2, name, ctypes.sizeof(name), ctypes.byref(needed))
            and name.value.casefold() == 'default')

    desktop = user.OpenInputDesktop(0, False, 1)
    try:
        input_desktop = default_desktop(desktop) and default_desktop(
            user.GetThreadDesktop(kernel.GetCurrentThreadId()))
    finally:
        if desktop:
            user.CloseDesktop(desktop)

    wts = ctypes.WinDLL('wtsapi32', use_last_error=True)
    wts.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                               ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
                                               ctypes.POINTER(wintypes.DWORD)]
    wts.WTSQuerySessionInformationW.restype = wintypes.BOOL
    wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    wts.WTSFreeMemory.restype = None
    state = ctypes.c_void_p()
    state_size = wintypes.DWORD()
    active_session = False
    if wts.WTSQuerySessionInformationW(None, session.value, 8,
                                     ctypes.byref(state), ctypes.byref(state_size)):
        try:
            active_session = (state_size.value == ctypes.sizeof(ctypes.c_int)
                              and ctypes.cast(state, ctypes.POINTER(ctypes.c_int))[0] == 0)
        finally:
            wts.WTSFreeMemory(state)
    return {'major': version.major, 'minor': version.minor, 'build': version.build,
            'product_type': version.product_type, 'native_architecture': architecture,
            'native_machine': native_machine.value,
            'nonzero_session': session.value != 0, 'active_session': active_session,
            'station_visible': station_visible, 'default_input_desktop': input_desktop}


def evaluate(expected, facts):
    desktop = (facts.get('major') == 10 and facts.get('minor') == 0
               and facts.get('product_type') == 1 and facts.get('build', 0) >= 10240)
    actual = ('win11' if facts['build'] >= 22000 else 'win10') if desktop else 'unsupported'
    checks = {'windows_client': desktop, 'native_x64': facts.get('native_architecture') == 9
              and facts.get('native_machine') == 0x8664,
              'label_matches': expected in ('win10', 'win11') and actual == expected,
              'interactive_session': facts.get('nonzero_session') is True
                                     and facts.get('active_session') is True,
              'visible_station': facts.get('station_visible') is True,
              'default_input_desktop': facts.get('default_input_desktop') is True}
    # Copy only numerical OS facts; names, paths, account and machine IDs never leave the host.
    report = {'format': 1, 'success': all(checks.values()), 'checks': checks,
              'detected_desktop': actual}
    for field in ('major', 'minor', 'build', 'product_type', 'native_architecture', 'native_machine'):
        value = facts.get(field)
        if type(value) is int:
            report[field] = value
    return report


def host_tools():
    checks = {'host_python_310': sys.version_info >= (3, 10)}
    for name in ('git', 'gh', 'pwsh'):
        command = shutil.which(name)
        arguments = (['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
                      'if ($PSVersionTable.PSVersion.Major -lt 7) { exit 1 }']
                     if name == 'pwsh' else ['--version'])
        try:
            checks['host_' + name] = bool(command) and subprocess.run(
                [command, *arguments], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=15, check=False).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            checks['host_' + name] = False
    return checks


def work_path_length(path):
    return len(str(path.absolute()).encode('utf-16-le')) // 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected', required=True, choices=('win10', 'win11'))
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path)
    args = parser.parse_args(argv)
    try:
        report = evaluate(args.expected, windows_facts())
        report['checks'].update(host_tools())
        if args.work_dir is not None:
            report['work_path_utf16'] = work_path_length(args.work_dir)
            report['checks']['work_path_within_60_utf16'] = report['work_path_utf16'] <= 60
        report['success'] = all(report['checks'].values())
    except Exception:
        report = {'format': 1, 'success': False, 'checks': {'system_probe': False}}
    try:
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    except Exception:
        report['success'] = False
        report['checks']['report_written'] = False
    print(json.dumps(report))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
