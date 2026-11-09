"""Profile/main-process identity shared by the controller and proxy worker."""
import os
from pathlib import Path

import psutil
from local_state import LocalBrowserError


def _canonical_profile(profile):
    return os.path.normcase(str(Path(profile).resolve()))


class ProfileProcessSnapshot:
    """One request's process index; never grants authority to control a browser."""

    def __init__(self, *, browser_names=()):
        self._profiles = {}
        self._occupied = set()
        self._profile_keys = {}
        self._pids = set()
        self._unreadable_pids = set()
        self._uncertain_profiles = set()
        self.incomplete = False
        names = {'bitbrowser.exe', *(str(name).casefold() for name in browser_names)}
        try:
            for process in psutil.process_iter(['pid', 'cmdline', 'exe', 'create_time', 'name']):
                try:
                    info = process.info
                    self._pids.add(process.pid)
                    args = info.get('cmdline')
                    if not args:
                        self._unreadable_pids.add(process.pid)
                        if (str(info.get('name') or '').casefold() in names or
                                Path(info.get('exe') or '').name.casefold() in names):
                            self.incomplete = True
                        continue
                    for value in _switch_values(args, '--user-data-dir'):
                        if value:
                            key = self._profile_key(value.strip('"'))
                            self._occupied.add(key)
                            if _is_browser(args):self._profiles.setdefault(key, {})[process.pid] = info.get('create_time')
                except (psutil.Error, OSError, ValueError, TypeError):
                    self.incomplete = True
        except (psutil.Error, OSError, ValueError):
            self.incomplete = True

    def has_pid(self, pid):
        return pid in self._pids

    def _profile_key(self, profile):
        value = str(profile)
        if value not in self._profile_keys:
            self._profile_keys[value] = _canonical_profile(profile)
        return self._profile_keys[value]

    def uncertain(self, profile, *, pid=None):
        return (self.incomplete or pid in self._unreadable_pids or
                self._profile_key(profile) in self._uncertain_profiles)

    def occupied(self,profile):
        return self._profile_key(profile) in self._occupied

    def browsers(self, profile):
        expected = self._profile_key(profile)
        result = []
        for pid, created in self._profiles.get(expected, {}).items():
            try:
                # A fresh Process avoids trusting an iterator object's cached PID identity.
                process = psutil.Process(pid)
                with process.oneshot():
                    if created is None or abs(process.create_time() - created) >= .01:
                        self._uncertain_profiles.add(expected)
                        continue
                    args = process.cmdline()
                if not args:
                    self._uncertain_profiles.add(expected)
                    continue
                if _is_browser(args) and any(
                        self._profile_key(value.strip('"')) == expected
                        for value in _switch_values(args, '--user-data-dir') if value):
                    result.append(process)
                else:
                    self._uncertain_profiles.add(expected)
            except psutil.NoSuchProcess:
                continue
            except (psutil.Error, OSError, ValueError, TypeError):
                self._uncertain_profiles.add(expected)
        return result


def profile_processes(profile: Path, *, require_inspectable=False):
    expected = _canonical_profile(profile)
    result = []
    for process in psutil.process_iter(['pid', 'cmdline', 'exe', 'create_time', 'name']):
        try:
            args = process.info['cmdline'] or []
            if require_inspectable and not args and (
                    str(process.info.get('name') or '').casefold() == 'bitbrowser.exe' or
                    Path(process.info.get('exe') or '').name.casefold() == 'bitbrowser.exe'):
                raise LocalBrowserError('无法核对某个比特内核的运行状态，请先正常关闭来源浏览器窗口后重试。')
            if any(_canonical_profile(value.strip('"')) == expected
                   for value in _switch_values(args, '--user-data-dir') if value):
                result.append(process)
        except (psutil.Error, OSError, ValueError):
            continue
    return result


def _switch_values(args, name):
    values = []
    for index, argument in enumerate(args):
        if argument.startswith(name + '='):
            values.append(argument.split('=', 1)[1])
        elif argument == name and index + 1 < len(args):
            values.append(args[index + 1])
    return values


def _is_browser(args):
    return not any(arg == '--type' or arg.startswith('--type=') for arg in args)


def _profile_browsers(profile):
    result = []
    for process in profile_processes(profile):
        try:
            if _is_browser(process.cmdline()):
                result.append(process)
        except psutil.Error:
            pass
    return result
