"""Explicit Windows acceptance: initialize a clean copy, show its UI, close normally.

No user data or browser cores are copied. Failures retain the isolated directory
and any still-running owned processes; this tool never terminates a process.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'clean-start-validation-'


def _ordinary(path, *, directory=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError()


def _copy_tree(source, destination):
    """Copy ordinary files only, with finite public-package size/count limits."""
    _ordinary(source, directory=True)
    count = total = 0
    destination.mkdir()
    for directory, folders, files in os.walk(source, followlinks=False):
        current = Path(directory)
        target = destination / current.relative_to(source)
        for name in folders:
            _ordinary(current / name, directory=True)
            (target / name).mkdir()
        for name in files:
            path = current / name
            _ordinary(path)
            count += 1
            total += path.stat().st_size
            if count > 20000 or total > 2 * 1024 ** 3:
                raise ValueError()
            shutil.copy2(path, target / name)


def _prepare(work):
    _ordinary(ROOT / 'VERSION')
    shutil.copy2(ROOT / 'VERSION', work / 'VERSION')
    app = work / 'app'
    app.mkdir()
    # Enumerate only top-level public source files, never descend into app/data.
    for source in (ROOT / 'app').iterdir():
        if source.suffix.lower() in ('.py', '.pyw', '.js'):
            _ordinary(source)
            shutil.copy2(source, app / source.name)
    for name, filenames in (('ui', ('app.js', 'index.html', 'style.css')),
                            ('resources', ('electron-main.js', 'crypto.worker.js', 'defaults.json','signature-verification-public.der','creation-catalog.json'))):
        (app/name).mkdir()
        for filename in filenames:
            source=ROOT/'app'/name/filename
            _ordinary(source)
            shutil.copy2(source,app/name/filename)
    (work / 'runtime').mkdir()
    _copy_tree(ROOT / 'runtime/webview2', work / 'runtime/webview2')
    return app


def _environment(work, python):
    platform = ('SystemRoot', 'WINDIR', 'COMSPEC', 'SystemDrive', 'ProgramFiles', 'ProgramFiles(x86)',
                'ProgramW6432', 'CommonProgramFiles', 'CommonProgramFiles(x86)', 'CommonProgramW6432',
                'ProgramData', 'ALLUSERSPROFILE', 'PUBLIC', 'OS', 'PROCESSOR_ARCHITECTURE',
                'PROCESSOR_IDENTIFIER', 'PROCESSOR_LEVEL', 'PROCESSOR_REVISION', 'NUMBER_OF_PROCESSORS')
    env = {key: os.environ[key] for key in platform if key in os.environ}
    for key, name in (('APPDATA', 'roaming'), ('LOCALAPPDATA', 'local'),
                      ('USERPROFILE', 'user'), ('HOME', 'user'), ('TEMP', 'temp'), ('TMP', 'temp')):
        path = work / 'environment' / name
        path.mkdir(parents=True, exist_ok=True)
        env[key] = str(path)
    paths = [str(python.parent)]
    if env.get('SystemRoot'):
        paths.extend((str(Path(env['SystemRoot']) / 'System32'), env['SystemRoot']))
    env.update(PATH=os.pathsep.join(paths), PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1',
               PYTHONUTF8='1', PYTHONIOENCODING='utf-8')
    return env


def _same_path(left, right):
    return os.path.normcase(str(Path(left).resolve())) == os.path.normcase(str(Path(right).resolve()))


def _manager_instances(entry, executables):
    import psutil
    found = []
    for process in psutil.process_iter(('pid', 'exe', 'cmdline')):
        try:
            info = process.info
            if (info['exe'] and any(_same_path(info['exe'], value) for value in executables)
                    and any(_same_path(argument, entry) for argument in (info['cmdline'] or [])[1:]
                            if not argument.startswith('-'))):
                found.append(info['pid'])
        except (psutil.Error, OSError, ValueError):
            continue
    return found


def _identity(pid):
    import psutil
    return psutil.Process(pid).create_time()


def _remember(process, identities):
    import psutil
    try:
        owner = psutil.Process(process.pid)
        identities[owner.pid] = owner.create_time()
        for child in owner.children(recursive=True):
            identities[child.pid] = child.create_time()
    except psutil.NoSuchProcess:
        pass


def _alive(identities):
    import psutil
    for pid, created in identities.items():
        try:
            process = psutil.Process(pid)
            if abs(process.create_time() - created) < .01 and process.is_running():
                return True
        except psutil.NoSuchProcess:
            continue
    return False


def _owned_manager(process, created, pythonw, entry):
    import psutil
    try:
        current = psutil.Process(process.pid)
        arguments = current.cmdline()
        return (process.poll() is None and abs(current.create_time() - created) < .01
                and _same_path(current.exe(), pythonw) and len(arguments) == 3
                and _same_path(arguments[0], pythonw) and arguments[1] == '-B'
                and _same_path(arguments[2], entry))
    except (psutil.Error, OSError, ValueError):
        return False


def _readiness_expression(url):
    return r'''(async () => {
      const query = selector => document.querySelector(selector);
      const empty = query('#empty-state'), rows = query('#profile-rows');
      const connection = query('#connection-status'), error = query('#service-error');
      const pageLoaded = document.readyState === 'complete' && location.href === EXPECTED_URL
        && document.title === '本地指纹浏览器' && !!query('#panel-profiles');
      const frontend = typeof state !== 'undefined' && typeof initialized !== 'undefined'
        && initialized && state.connected && state.settingsLoaded && !state.loading
        && Array.isArray(state.profiles) && state.profiles.length === 0
        && state.capabilities.independent_runtime === true && state.capabilities.portable_mode === true;
      const dom = !!empty && !empty.hidden && empty.getBoundingClientRect().height > 0
        && getComputedStyle(empty).visibility !== 'hidden' && !!rows && rows.children.length === 0
        && query('#total-count')?.textContent.trim() === '0'
        && connection?.classList.contains('connected') && error?.hidden === true
        && query('#refresh-button')?.disabled === false;
      let bridge = false;
      if (pageLoaded && frontend && dom && typeof window.pywebview?.api?.request === 'function') {
        try {
          let reply = await Promise.race([window.pywebview.api.request('list', {include_archived: true}),
            new Promise(resolve => setTimeout(() => resolve(null), 500))]);
          if (typeof reply === 'string') reply = JSON.parse(reply);
          bridge = reply?.ok === true && Array.isArray(reply.data?.profiles) && reply.data.profiles.length === 0;
        } catch (_) {}
      }
      return {page_loaded: pageLoaded, bootstrap_empty_list_ready: Boolean(pageLoaded && frontend && dom && bridge)};
    })()'''.replace('EXPECTED_URL', json.dumps(url))


def _ui_launcher(app, work, title):
    """Observe the original window through pywebview's public read-only API."""
    launcher = app / '_verify_clean_start.pyw'
    report = work / 'page-readiness.json'
    nonce = secrets.token_hex(16)
    source = r'''import json,os,runpy,sys,threading,time
from pathlib import Path
from urllib.parse import unquote,urlparse
from urllib.request import url2pathname
APP=Path(APP_VALUE)
REPORT=Path(REPORT_VALUE)
NONCE=NONCE_VALUE
EXPECTED_TITLE=TITLE_VALUE
EXPRESSION=EXPRESSION_VALUE
sys.path.insert(0,str(APP))
import webview
original_create=webview.create_window
state={'nonce':NONCE,'window_source_verified':False,'loaded_event_observed':False,
       'local_page_url':False,'evaluation_callback_returned':False,
       'page_loaded':False,'bootstrap_empty_list_ready':False}
def publish():
    temporary=REPORT.with_suffix('.tmp')
    with temporary.open('w',encoding='utf-8') as handle:
        json.dump(state,handle);handle.flush();os.fsync(handle.fileno())
    os.replace(temporary,REPORT)
def observe(window):
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        try:
            url=window.get_current_url() or ''
            parsed=urlparse(url)
            state['local_page_url']=bool(
                (parsed.scheme=='file' and parsed.netloc in ('','localhost')
                 and Path(url2pathname(parsed.path)).resolve()==(APP/'ui/index.html').resolve())
                or (parsed.scheme=='http' and parsed.hostname=='127.0.0.1' and parsed.port
                    and unquote(parsed.path).endswith('/index.html') and not parsed.username and not parsed.password))
            if state['local_page_url']:
                completed=threading.Event();value={}
                def accept(result,target=value,event=completed):
                    if isinstance(result,dict):target.update(result)
                    event.set()
                expression=EXPRESSION.replace(json.dumps('__verify_current_url__'),json.dumps(url))
                window.evaluate_js(expression,callback=accept)
                state['evaluation_callback_returned']=completed.wait(max(0,min(1,deadline-time.monotonic())))
                state['page_loaded']=state['page_loaded'] or value.get('page_loaded') is True
                state['bootstrap_empty_list_ready']=value.get('bootstrap_empty_list_ready') is True
            publish()
            if state['bootstrap_empty_list_ready']:return
        except Exception as error:
            state['evaluation_error_type']=type(error).__name__;publish()
        time.sleep(.1)
def create(title,url=None,*args,**kwargs):
    if title!=EXPECTED_TITLE or not isinstance(url,str) or Path(url).resolve()!=(APP/'ui/index.html').resolve():
        raise ValueError()
    window=original_create(title,url,*args,**kwargs)
    state['window_source_verified']=True;publish()
    started=threading.Event()
    def loaded():
        if started.is_set():return
        started.set();state['loaded_event_observed']=True;publish()
        threading.Thread(target=observe,args=(window,),daemon=True).start()
    window.events.loaded+=loaded
    return window
webview.create_window=create
runpy.run_path(str(APP/'local_browser.pyw'),run_name='__main__')
'''
    for key, value in (('APP_VALUE', str(app)), ('REPORT_VALUE', str(report)), ('NONCE_VALUE', nonce),
                       ('TITLE_VALUE', title),
                       ('EXPRESSION_VALUE', _readiness_expression('__verify_current_url__'))):
        source = source.replace(key, repr(value))
    compile(source, str(launcher), 'exec')
    launcher.write_text(source, encoding='utf-8')
    return launcher, report, nonce


def _wait_page(manager, created, pythonw, entry, report, nonce, identities):
    state = {'page_loaded': False, 'bootstrap_empty_list_ready': False, 'page_diagnostics': {}}
    deadline = time.monotonic() + 22
    while time.monotonic() < deadline and _owned_manager(manager, created, pythonw, entry):
        _remember(manager, identities)
        try:
            _ordinary(report)
            with report.open('rb') as handle:
                raw = handle.read(16385)
            if len(raw) > 16384:
                raise ValueError()
            value = json.loads(raw)
            if not isinstance(value, dict) or value.get('nonce') != nonce:
                raise ValueError()
            diagnostics = {key: value.get(key) is True for key in ('window_source_verified',
                'loaded_event_observed', 'local_page_url', 'evaluation_callback_returned')}
            diagnostics['page_report_nonce_valid'] = True
            if isinstance(value.get('evaluation_error_type'), str):
                diagnostics['evaluation_error_type'] = value['evaluation_error_type'][:80]
            state['page_diagnostics'] = diagnostics
            trusted = all(diagnostics.get(key) is True for key in ('window_source_verified', 'loaded_event_observed',
                          'local_page_url', 'evaluation_callback_returned', 'page_report_nonce_valid'))
            state['page_loaded'] = trusted and value.get('page_loaded') is True
            state['bootstrap_empty_list_ready'] = state['page_loaded'] and value.get('bootstrap_empty_list_ready') is True
            if state['bootstrap_empty_list_ready']:
                return state
        except FileNotFoundError:
            pass
        except Exception as error:
            state['page_diagnostics']['report_error_type'] = type(error).__name__
        time.sleep(.1)
    return state


class Windows:
    def __init__(self, title):
        self.title = title
        self.user = ctypes.WinDLL('user32', use_last_error=True)
        self.callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        self.user.EnumWindows.argtypes = [self.callback, wintypes.LPARAM]
        self.user.EnumWindows.restype = wintypes.BOOL
        self.user.IsWindowVisible.argtypes = [wintypes.HWND]
        self.user.IsWindowVisible.restype = wintypes.BOOL
        self.user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        self.user.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        self.user.GetWindowRect.restype = wintypes.BOOL
        self.user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        self.user.PostMessageW.restype = wintypes.BOOL

    def visible(self, pid):
        found = []
        @self.callback
        def visit(window, _):
            owner = wintypes.DWORD()
            self.user.GetWindowThreadProcessId(window, ctypes.byref(owner))
            if owner.value != pid or not self.user.IsWindowVisible(window):
                return True
            title = ctypes.create_unicode_buffer(256)
            rectangle = wintypes.RECT()
            self.user.GetWindowTextW(window, title, len(title))
            if (title.value == self.title and self.user.GetWindowRect(window, ctypes.byref(rectangle))
                    and rectangle.right > rectangle.left and rectangle.bottom > rectangle.top):
                found.append(window)
            return True
        if not self.user.EnumWindows(visit, 0):
            raise OSError()
        return found

    def close(self, window):
        if not self.user.PostMessageW(window, 0x0010, 0, 0):  # WM_CLOSE follows the normal UI exit path.
            raise OSError()


def _run_child(arguments, app, env, work, name, owned, identities):
    stdout = work / (name + '.stdout')
    with stdout.open('wb') as output, (work / (name + '.stderr')).open('wb') as errors:
        child = subprocess.Popen(arguments, cwd=app, env=env, stdin=subprocess.DEVNULL,
                                 stdout=output, stderr=errors, creationflags=subprocess.CREATE_NO_WINDOW)
        owned.append(child)
        _remember(child, identities)
        if child.wait(timeout=60) != 0:
            raise RuntimeError()
    with stdout.open('rb') as handle:
        raw = handle.read(16385)
    if len(raw) > 16384:
        raise ValueError()
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    if not parser.parse_args().execute:
        print(json.dumps({'executed': False, 'requires_execute': True}))
        return 0
    report = {'executed': True, 'success': False, 'checks': {},
              'page_loaded': False, 'bootstrap_empty_list_ready': False}
    work = None
    manager = windows = shown = created = ui_entry = None
    owned = []
    identities = {}
    def check(name, passed):
        report['checks'][name] = bool(passed)
        if not passed:
            raise AssertionError()
    try:
        if os.name != 'nt':
            raise OSError()
        python = Path(sys.executable).resolve()
        pythonw = python.with_name('pythonw.exe')
        _ordinary(pythonw)
        _ordinary(ROOT / 'runtime/webview2/msedgewebview2.exe')
        report['existing_project_instances'] = len(_manager_instances(ROOT / 'app/local_browser.pyw', (python, pythonw)))
        work = Path(tempfile.mkdtemp(prefix=PREFIX)).resolve()
        app = _prepare(work)
        check('copy_version_matches_source', (work / 'VERSION').read_bytes() == (ROOT / 'VERSION').read_bytes())
        title = '本地指纹浏览器 v' + (work / 'VERSION').read_text('utf-8-sig').strip()
        entry = app / 'local_browser.pyw'
        env = _environment(work, python)
        check('copy_had_no_prior_instance', not _manager_instances(entry, (python, pythonw)))
        check('copy_started_without_data', not (app / 'data').exists())
        raw = _run_child([str(python), '-B', str(entry), '--self-check'], app, env, work,
                         'self-check', owned, identities)
        result = json.loads(raw)
        check('clean_self_check', result.get('windows') == 0 and result.get('profiles_present') is True
              and result.get('fingerprints_present') is True and result.get('installed_cores') == 0
              and result.get('bundled_cores') == [] and result.get('ui_present') is True)
        settings = ("import sys; sys.path.insert(0," + repr(str(app)) + "); "
                    "from manager_service import ManagerService; s=ManagerService(); "
                    "assert not s.store.all(); s.store.set_setting('application', "
                    "{'confirm_close':False,'close_behavior':'close_browsers'})")
        _run_child([str(python), '-B', '-c', settings], app, env, work, 'settings', owned, identities)
        check('isolated_exit_settings_saved', True)
        windows = Windows(title)
        ui_entry, page_report, nonce = _ui_launcher(app, work, title)
        with (work / 'manager.stdout').open('wb') as output, (work / 'manager.stderr').open('wb') as errors:
            manager = subprocess.Popen([str(pythonw), '-B', str(ui_entry)], cwd=app, env=env,
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            owned.append(manager)
            created = _identity(manager.pid)
            identities[manager.pid] = created
            deadline = time.monotonic() + 45
            shown = None
            while time.monotonic() < deadline and manager.poll() is None:
                _remember(manager, identities)
                if _owned_manager(manager, created, pythonw, ui_entry):
                    visible = windows.visible(manager.pid)
                    if visible:
                        shown = visible[0]
                        break
                time.sleep(.1)
            check('manager_identity_verified', _owned_manager(manager, created, pythonw, ui_entry))
            check('manager_window_visible', shown is not None)
            check('manager_native_title_verified', shown is not None)
            report.update(_wait_page(manager, created, pythonw, ui_entry, page_report, nonce, identities))
            check('page_loaded', report['page_loaded'])
            check('bootstrap_empty_list_ready', report['bootstrap_empty_list_ready'])
            _remember(manager, identities)
            check('same_visible_window_before_close', _owned_manager(manager, created, pythonw, ui_entry)
                  and shown in windows.visible(manager.pid))
            windows.close(shown)
            check('manager_exited_normally', manager.wait(timeout=30) == 0)
        deadline = time.monotonic() + 10
        while _alive(identities) and time.monotonic() < deadline:
            time.sleep(.1)
        check('owned_processes_exited', all(child.poll() is not None for child in owned) and not _alive(identities))
        check('isolated_vendor_database_absent', not (Path(env['APPDATA']) / 'BitBrowser/db.sqlite').exists())
        report['success'] = True
    except Exception as error:
        report['error_type'] = type(error).__name__
    finally:
        if manager is not None and manager.poll() is None and shown is not None and windows is not None:
            try:
                if (_owned_manager(manager, created, pythonw, ui_entry) and shown in windows.visible(manager.pid)):
                    _remember(manager, identities)
                    windows.close(shown)
                    report['failure_manager_closed_normally'] = manager.wait(timeout=30) == 0
                    deadline = time.monotonic() + 10
                    while _alive(identities) and time.monotonic() < deadline:
                        time.sleep(.1)
            except Exception as error:
                report['normal_close_error_type'] = type(error).__name__
        if work is not None:
            if report['success']:
                try:
                    if (work.parent != Path(tempfile.gettempdir()).resolve() or not work.name.startswith(PREFIX)
                            or work.is_symlink() or _alive(identities)):
                        raise ValueError()
                    shutil.rmtree(work)
                except Exception as error:
                    report['success'] = False
                    report['cleanup_error_type'] = type(error).__name__
            report['test_directory_retained'] = work.exists()
        try:
            report['no_owned_process_alive'] = all(child.poll() is not None for child in owned) and not _alive(identities)
        except Exception as error:
            report['no_owned_process_alive'] = False
            report['observation_error_type'] = type(error).__name__
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
