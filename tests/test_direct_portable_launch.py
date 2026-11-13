"""Synthetic direct-launch checks. No real data or browser is opened."""
import ast
import argparse
from contextlib import ExitStack, contextmanager, nullcontext
import ctypes
from ctypes import wintypes
import io
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import MagicMock, patch

import psutil

ROOT = Path(__file__).resolve().parents[1]
# A staged payload already adds one package layer. Keep launcher fixtures beside
# that payload so this routing test does not accidentally become a MAX_PATH test.
TEST_ROOT = (ROOT.parent.parent if ROOT.parent.name == '.program-packages'
             and re.fullmatch('[0-9a-f]{32}', ROOT.name) else ROOT)
TEST_RUNS = TEST_ROOT / 'analysis/test-runs'
SYNTHETIC_PACKAGE_ID = '0123456789abcdef0123456789abcdef'


@contextmanager
def launcher_fixture():
    TEST_RUNS.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix='direct-portable-', dir=TEST_RUNS)
    base = Path(temporary.name)
    marker = base / '.fixture-owner.json'
    owner = {'pid': os.getpid(), 'purpose': 'synthetic-direct-launch', 'scope': str(base)}
    marker.write_text(json.dumps(owner), 'utf-8')
    try:
        yield base
    finally:
        safe = base.resolve().parent == TEST_RUNS.resolve()
        safe = safe and json.loads(marker.read_text('utf-8')) == owner
        for directory, folders, files in os.walk(base, followlinks=False):
            for name in (*folders, *files):
                info = (Path(directory) / name).lstat()
                safe = safe and not stat.S_ISLNK(info.st_mode)
                safe = safe and not getattr(info, 'st_file_attributes', 0) & 0x400
        for process in psutil.process_iter(['exe']):
            if process.info['exe']:
                safe = safe and not Path(process.info['exe']).resolve().is_relative_to(base)
        if not safe:
            temporary._finalizer.detach()
            raise AssertionError('synthetic_launcher_cleanup_refused')
        temporary.cleanup()
        if base.exists():
            raise AssertionError('synthetic_launcher_cleanup_incomplete')


class DirectLaunch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with launcher_fixture() as base:
            probe = base
            (base / 'nested').mkdir()
            (base / 'nested/probe.txt').write_text('cleanup probe', 'utf-8')
        if probe.exists():
            raise AssertionError('synthetic_launcher_preflight_failed')

    @staticmethod
    def launcher_bytes(generated=False):
        if generated:
            layout = runpy.run_path(str(ROOT / 'tools/overlay_layout.py'))
            return layout['launcher_bytes'](SYNTHETIC_PACKAGE_ID), SYNTHETIC_PACKAGE_ID
        raw = (ROOT / '启动本地浏览器.cmd').read_bytes()
        matched = re.search(rb'set "IB_PACKAGE=%~dp0\.program-packages\\([0-9a-f]{32})"', raw)
        if b'IB_PACKAGE' in raw and matched is None:
            raise AssertionError('synthetic_launcher_layout_unknown')
        return raw, matched.group(1).decode('ascii') if matched else None

    @staticmethod
    def copy_interpreter(runtime):
        runtime.mkdir(parents=True)
        # Only the embeddable interpreter; no site packages or private data.
        for source in (ROOT / 'runtime/python').iterdir():
            if source.is_file():
                shutil.copy2(source, runtime / source.name)

    def wait_for_fixture_processes(self, owned, started):
        for process in psutil.process_iter(['exe', 'cmdline', 'create_time']):
            info = process.info
            if not info['exe'] or Path(info['exe']).resolve() not in owned:
                continue
            executable = Path(info['exe']).resolve()
            expected_entry = owned[executable]
            self.assertGreaterEqual(info['create_time'], started - 2)
            self.assertIn(str(expected_entry), info['cmdline'] or [])
            try:
                process.wait(timeout=10)
            except psutil.TimeoutExpired:
                # Only this fixture's exact interpreter and entry may be stopped.
                self.assertEqual(Path(process.exe()).resolve(), executable)
                self.assertEqual(process.create_time(), info['create_time'])
                self.assertIn(str(expected_entry), process.cmdline())
                process.terminate()
                process.wait(timeout=10)
                self.fail('synthetic_interpreter_did_not_exit')
            except psutil.NoSuchProcess:
                pass

    def launcher(self, name, *, delayed=False, missing=None, generated=False):
        raw, package_id = self.launcher_bytes(generated)
        with launcher_fixture() as base:
            root = base / name
            app = root / 'app'
            runtime = root / 'runtime/python'
            app.mkdir(parents=True)
            self.copy_interpreter(runtime)
            (root / 'runtime/webview2').mkdir()
            (root / 'runtime/webview2/msedgewebview2.exe').write_bytes(b'synthetic, never executed')
            launcher = root / 'start.cmd'
            launcher.write_bytes(raw)
            (app / 'local_browser.pyw').write_text(
                "import json,os,sys\nfrom pathlib import Path\n"
                "here=Path(__file__).resolve().parent\n"
                "result={'cwd_ok':Path.cwd()==here,"
                "'exe_ok':Path(sys.executable).resolve()==here.parent/'runtime/python/pythonw.exe',"
                "'isolated':bool(sys.flags.isolated),"
                "'ignore_environment':bool(sys.flags.ignore_environment),"
                "'outside_path_absent':all('synthetic_external' not in x for x in sys.path),"
                "'pid':os.getpid()}\n"
                "pending=here/'fixture-result.tmp'\n"
                "pending.write_text(json.dumps(result),'utf-8')\n"
                "pending.replace(here/'fixture-result.json')\n", 'utf-8')
            owned = {(runtime / 'pythonw.exe').resolve(): app / 'local_browser.pyw'}
            startup_root = root
            if package_id:
                startup_root = root / '.program-packages' / package_id
                self.copy_interpreter(startup_root / 'runtime/python')
                tools = startup_root / 'tools'
                tools.mkdir()
                # The stub tests CMD routing only. Preparation transactions have
                # their own fixtures; the final Popen is the production launch().
                shutil.copy2(ROOT / 'tools/portable_bootstrap.py', tools / 'fixture_production_bootstrap.py')
                (startup_root / 'release-manifest.json').write_text('{"synthetic":true}', 'utf-8')
                (startup_root / 'overlay-package.json').write_text(json.dumps(
                    {'format': 1, 'package_id': package_id}), 'utf-8')
                (tools / 'portable_bootstrap.py').write_text(
                    "import json,os,runpy,sys\nfrom pathlib import Path\n"
                    "payload=Path(__file__).resolve().parents[1]\n"
                    "assert len(sys.argv)==3 and sys.argv[1]=='--target'\n"
                    "target=Path(sys.argv[2]).resolve()\n"
                    "assert target==payload.parent.parent\n"
                    "result={'target_ok':target==payload.parent.parent,"
                    "'exe_ok':Path(sys.executable).resolve()==payload/'runtime/python/pythonw.exe',"
                    "'isolated':bool(sys.flags.isolated),"
                    "'ignore_environment':bool(sys.flags.ignore_environment),"
                    "'outside_path_absent':all('synthetic_external' not in x for x in sys.path)}\n"
                    "(target/'app/bootstrap-result.json').write_text(json.dumps(result),'utf-8')\n"
                    "module=runpy.run_path(str(payload/'tools/fixture_production_bootstrap.py'),"
                    "run_name='synthetic_bootstrap_import')\n"
                    "module['launch'](target)\n", 'utf-8')
                owned[(startup_root / 'runtime/python/pythonw.exe').resolve()] = tools / 'portable_bootstrap.py'
            if missing:
                (startup_root / missing).unlink()
            env = os.environ.copy()
            env.update(PYTHONHOME=str(base / 'synthetic_external_home'),
                       PYTHONPATH=str(base / 'synthetic_external_path'), TEMP=str(base), TMP=str(base))
            command = '"{}" /d /v:{} /s /c ""{}""'.format(
                os.environ.get('COMSPEC', 'cmd.exe'), 'on' if delayed else 'off', launcher)
            started = time.time()
            try:
                result = subprocess.run(command, cwd=base, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                if missing:
                    self.assertEqual(result.returncode, 1)
                    self.assertFalse((app / 'fixture-result.json').exists())
                    self.assertFalse((app / 'bootstrap-result.json').exists())
                    return
                self.assertEqual(result.returncode, 0)
                marker = app / 'fixture-result.json'
                deadline = time.monotonic() + 5
                while not marker.is_file() and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertTrue(marker.is_file(), 'synthetic_launcher_did_not_reach_bundled_python')
                observed = json.loads(marker.read_text('utf-8'))
                self.assertIsInstance(observed.pop('pid'), int)
                self.assertTrue(all(observed.values()))
                if package_id:
                    self.assertTrue(all(json.loads((app / 'bootstrap-result.json').read_text('utf-8')).values()))
                    self.assertFalse((startup_root / 'app').exists())
            finally:
                self.wait_for_fixture_processes(owned, started)

    def test_spaces_chinese_arbitrary_cwd_and_python_env(self):
        self.launcher('移动盘 便携目录')

    def test_exclamation_path_with_inherited_delayed_expansion(self):
        self.launcher('移动盘 !合成! 便携目录', delayed=True)

    def test_launcher_refuses_incomplete_bundle(self):
        _, package_id = self.launcher_bytes()
        components = ('runtime/python/pythonw.exe', 'tools/portable_bootstrap.py',
                      'release-manifest.json', 'overlay-package.json') if package_id else (
                      'runtime/python/pythonw.exe', 'runtime/webview2/msedgewebview2.exe', 'app/local_browser.pyw')
        for missing in components:
            with self.subTest(component=missing):
                self.launcher('移动盘 便携目录', missing=missing)

    def test_generated_cmd_spaces_chinese_arbitrary_cwd_and_python_env(self):
        self.launcher('移动盘 生成入口 便携目录', generated=True)

    def test_generated_cmd_exclamation_with_inherited_delayed_expansion(self):
        self.launcher('移动盘 !生成入口! 便携目录', delayed=True, generated=True)

    def test_generated_cmd_refuses_missing_payload_components(self):
        for missing in ('runtime/python/pythonw.exe', 'tools/portable_bootstrap.py',
                        'release-manifest.json', 'overlay-package.json'):
            with self.subTest(component=missing):
                self.launcher('移动盘 生成入口 便携目录', missing=missing, generated=True)

    def manager(self, root, *, present=True, version=None):
        app = root / 'app'
        app.mkdir()
        if version is not None:
            (root / 'VERSION').write_bytes(version)
        runtime = root / 'runtime/webview2'
        runtime.mkdir(parents=True)
        if present:
            (runtime / 'msedgewebview2.exe').write_bytes(b'synthetic, never executed')
        webview = types.ModuleType('webview')
        webview.settings = {}
        webview.create_window = MagicMock(return_value=MagicMock())
        captured = {}
        def start(**kwargs):
            captured.update(runtime=webview.settings.get('WEBVIEW2_RUNTIME_PATH'),
                            title=webview.create_window.call_args.args[0],
                            executable_env=os.environ.get('WEBVIEW2_BROWSER_EXECUTABLE_FOLDER'),
                            user_data_env=os.environ.get('WEBVIEW2_USER_DATA_FOLDER'),
                            browser_args=os.environ.get('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS'),
                            debugger_wait=os.environ.get('WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER'))
        webview.start = MagicMock(side_effect=start)
        core = types.ModuleType('browser_core')
        core.APP_ROOT, core.DATA_ROOT = app, app / 'data'
        manager = types.ModuleType('manager_service')
        manager.ManagerService = MagicMock(return_value=types.SimpleNamespace())
        installation = types.ModuleType('installation')
        installation.initialize_installation = MagicMock()
        guard = types.ModuleType('update_guard')
        guard.require_complete_installation = MagicMock()
        kernel = types.SimpleNamespace(CreateMutexW=MagicMock(return_value=1), CloseHandle=MagicMock())
        user = types.SimpleNamespace(MessageBoxW=MagicMock())
        env = {'WEBVIEW2_BROWSER_EXECUTABLE_FOLDER':str(root / 'outside-runtime'),
               'WEBVIEW2_USER_DATA_FOLDER':str(root / 'outside-user-data'),
               'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS':'--remote-debugging-port=12345',
               'WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER':'1'}
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, browser_core=core, manager_service=manager,
                                           installation=installation, webview=webview, update_guard=guard))
            stack.enter_context(patch.object(ctypes, 'WinDLL', return_value=kernel))
            stack.enter_context(patch.object(ctypes, 'get_last_error', return_value=0))
            stack.enter_context(patch.object(ctypes, 'windll', types.SimpleNamespace(user32=user)))
            stack.enter_context(patch.dict(os.environ, env))
            stack.enter_context(patch.object(sys, 'argv', ['local_browser.pyw']))
            previous_path = list(sys.path)
            previous_cache = sys.pycache_prefix, sys.dont_write_bytecode
            try:
                namespace = runpy.run_path(str(ROOT / 'app/local_browser.pyw'), run_name='portable_synthetic')
                namespace['main']()
            finally:
                sys.path[:] = previous_path
                sys.pycache_prefix, sys.dont_write_bytecode = previous_cache
        return captured, installation.initialize_installation.call_count, webview.start.call_count

    def test_missing_bundled_webview_refuses_before_installation(self):
        with tempfile.TemporaryDirectory(prefix='webview-synthetic-') as directory:
            captured, installations, starts = self.manager(Path(directory), present=False)
            self.assertEqual((installations, starts), (0, 0))

    def test_webview_external_environment_cannot_redirect_runtime_or_data(self):
        with tempfile.TemporaryDirectory(prefix='webview-synthetic-') as directory:
            root = Path(directory)
            captured, installations, starts = self.manager(root)
            self.assertEqual((installations, starts), (1, 1))
            self.assertEqual(captured['runtime'], str(root / 'runtime/webview2'))
            self.assertEqual(captured['executable_env'], str(root / 'runtime/webview2'))
            self.assertEqual(captured['user_data_env'], str(root / 'app/data/manager-webview'))
            self.assertFalse(captured['browser_args'])
            self.assertFalse(captured['debugger_wait'])

    def test_native_title_reads_version_from_its_bundle(self):
        with tempfile.TemporaryDirectory(prefix='version-synthetic-') as directory:
            version = (ROOT / 'VERSION').read_bytes()
            captured, installations, starts = self.manager(Path(directory), version=version)
            self.assertEqual((installations, starts), (1, 1))
            self.assertEqual(captured['title'], '本地指纹浏览器 v' + version.decode('utf-8-sig').strip())

    def test_title_follows_moved_bundle_metadata(self):
        with tempfile.TemporaryDirectory(prefix='version-synthetic-') as directory:
            captured, installations, starts = self.manager(Path(directory), version=b'\xef\xbb\xbf9.8.7\r\n')
            self.assertEqual((installations, starts), (1, 1))
            self.assertEqual(captured['title'], '本地指纹浏览器 v9.8.7')

    def test_missing_or_invalid_version_does_not_break_startup(self):
        for version in (None, b'', b'\xff', b'0.2.7\nother', b'9' * 129):
            with self.subTest(version_present=version is not None), \
                    tempfile.TemporaryDirectory(prefix='version-synthetic-') as directory:
                captured, installations, starts = self.manager(Path(directory), version=version)
                self.assertEqual((installations, starts), (1, 1))
                self.assertEqual(captured['title'], '本地指纹浏览器')

    @staticmethod
    def config_command(app):
        tree = ast.parse((ROOT / 'app/configuration.py').read_text('utf-8-sig'))
        configuration = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Configuration')
        method = next(node for node in configuration.body if isinstance(node, ast.FunctionDef) and node.name == '_config_command')
        method.decorator_list = []
        namespace = {'APP_ROOT': app, 'LocalBrowserError': RuntimeError}
        exec(compile(ast.Module(body=[method], type_ignores=[]), '<synthetic_config>', 'exec'), namespace)
        return namespace['_config_command']

    def test_missing_bundled_node_never_uses_path_node(self):
        with tempfile.TemporaryDirectory(prefix='node-synthetic-') as directory:
            root = Path(directory)
            command = self.config_command(root / 'app')
            with patch('shutil.which', return_value=str(root / 'system-node.exe')) as which:
                with self.assertRaises(RuntimeError):
                    command()
                which.assert_not_called()

    def test_existing_bundled_node_uses_absolute_bundle_path(self):
        with tempfile.TemporaryDirectory(prefix='node-synthetic-') as directory:
            root = Path(directory)
            bundled = root / 'runtime/node/node.exe'
            bundled.parent.mkdir(parents=True)
            bundled.write_bytes(b'synthetic, never executed')
            command = self.config_command(root / 'app')
            with patch('shutil.which', return_value=str(root / 'system-node.exe')) as which:
                self.assertEqual(command(), [str(bundled), str(root / 'app/config_factory.js')])
                which.assert_not_called()

    def focus_manager(self, *, match=True, reused_pid=False, title='本地指纹浏览器 v9.8.7'):
        with tempfile.TemporaryDirectory(prefix='sibling-manager-fixture-') as directory:
            root=Path(directory)
            apps={11:root/'A/app',22:root/'B/app'}
            python=root/'B/runtime/python/pythonw.exe'
            user=types.SimpleNamespace(FindWindowExW=MagicMock(side_effect=[101,202,0]),
                GetWindowTextW=MagicMock(),GetWindowThreadProcessId=MagicMock(),
                ShowWindow=MagicMock(),SetForegroundWindow=MagicMock())
            owners={101:11,202:22}
            def caption(window,buffer,size):buffer.value=title
            user.GetWindowTextW.side_effect=caption
            def owner(window,pointer):pointer._obj.value=owners[window]
            user.GetWindowThreadProcessId.side_effect=owner
            calls={11:0,22:0}
            def process(pid):
                calls[pid]+=1
                created=2 if reused_pid and pid==22 and calls[pid]>1 else 1
                entry=apps[pid]/('local_browser.pyw' if match or pid==11 else 'other.pyw')
                return types.SimpleNamespace(oneshot=nullcontext,create_time=lambda:created,
                    exe=lambda:str(apps[pid].parent/'runtime/python/pythonw.exe'),
                    cmdline=lambda:[str(python),'-B',str(entry)])
            tree=ast.parse((ROOT/'app/local_browser.pyw').read_text('utf-8-sig'))
            method=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='_focus_existing_manager')
            scope={'ctypes':ctypes,'wintypes':wintypes,'Path':Path,'os':os,'sys':sys,
                   'APP_ROOT':apps[22],'BASE_TITLE':'本地指纹浏览器'}
            exec(compile(ast.Module(body=[method],type_ignores=[]),'<synthetic_manager>','exec'),scope)
            with patch.object(ctypes,'WinDLL',return_value=user),patch.object(sys,'executable',str(python)),\
                    patch('psutil.Process',side_effect=process):
                focused=scope['_focus_existing_manager']()
            return focused,user

    def test_repeated_launch_focuses_only_its_own_sibling_manager(self):
        focused,user=self.focus_manager()
        self.assertTrue(focused)
        user.ShowWindow.assert_called_once_with(202,9)
        user.SetForegroundWindow.assert_called_once_with(202)

    def test_existing_unversioned_manager_can_still_be_focused(self):
        focused,user=self.focus_manager(title='本地指纹浏览器')
        self.assertTrue(focused)
        user.ShowWindow.assert_called_once_with(202,9)
        user.SetForegroundWindow.assert_called_once_with(202)

    def test_unrelated_title_in_same_process_is_not_focused(self):
        focused,user=self.focus_manager(title='unrelated synthetic dialog')
        self.assertFalse(focused)
        user.ShowWindow.assert_not_called()
        user.SetForegroundWindow.assert_not_called()

    def test_same_runtime_with_different_entry_never_focuses(self):
        focused,user=self.focus_manager(match=False)
        self.assertFalse(focused)
        user.ShowWindow.assert_not_called()
        user.SetForegroundWindow.assert_not_called()

    def test_reused_manager_pid_never_focuses(self):
        focused,user=self.focus_manager(reused_pid=True)
        self.assertFalse(focused)
        user.ShowWindow.assert_not_called()
        user.SetForegroundWindow.assert_not_called()

    def test_clean_acceptance_preserves_platform_and_isolates_user_environment(self):
        scope = runpy.run_path(str(ROOT / 'tools/verify_clean_start.py'), run_name='clean_environment_fixture')
        platform = ('SystemRoot', 'WINDIR', 'COMSPEC', 'SystemDrive', 'ProgramFiles', 'ProgramFiles(x86)',
                    'ProgramW6432', 'CommonProgramFiles', 'CommonProgramFiles(x86)', 'CommonProgramW6432',
                    'ProgramData', 'ALLUSERSPROFILE', 'PUBLIC', 'OS', 'PROCESSOR_ARCHITECTURE',
                    'PROCESSOR_IDENTIFIER', 'PROCESSOR_LEVEL', 'PROCESSOR_REVISION', 'NUMBER_OF_PROCESSORS')
        isolated = (('APPDATA', 'roaming'), ('LOCALAPPDATA', 'local'), ('USERPROFILE', 'user'),
                    ('HOME', 'user'), ('TEMP', 'temp'), ('TMP', 'temp'))
        excluded = ('USERNAME', 'USERDOMAIN', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                    'API_TOKEN', 'OPENAI_API_KEY', 'PYTHONHOME', 'PYTHONPATH')
        parent_environment = dict(os.environ)
        with launcher_fixture() as base:
            inherited = {key: 'synthetic-platform-' + str(index) for index, key in enumerate(platform)}
            inherited.update(SystemRoot=str(base / 'synthetic-windows'), SystemDrive=base.drive)
            inherited.update({key: str(base / 'inherited-user-directory') for key, _ in isolated})
            inherited.update({key: 'synthetic-excluded-value' for key in excluded})
            with patch.dict(os.environ, inherited, clear=True):
                before = dict(os.environ)
                environment = scope['_environment'](base, base / 'runtime/python/python.exe')
                self.assertTrue(dict(os.environ) == before, 'synthetic_parent_environment_changed')
                for key in platform:
                    self.assertEqual(environment[key], inherited[key])
                for key, folder in isolated:
                    expected = base / 'environment' / folder
                    self.assertEqual(environment[key], str(expected))
                    self.assertTrue(expected.is_dir() and expected.resolve().is_relative_to(base.resolve()))
                    self.assertNotEqual(environment[key], inherited[key])
                for key in excluded:
                    self.assertNotIn(key, environment)
        self.assertTrue(dict(os.environ) == parent_environment, 'synthetic_parent_environment_not_restored')

    def test_clean_acceptance_copies_version_and_requires_native_title(self):
        scope=runpy.run_path(str(ROOT/'tools/verify_clean_start.py'),run_name='clean_acceptance_fixture')
        with tempfile.TemporaryDirectory(prefix='clean-title-synthetic-') as directory:
            root=Path(directory)
            with patch.dict(scope['_prepare'].__globals__, _copy_tree=lambda source,target:target.mkdir()):
                app=scope['_prepare'](root)
            version=(root/'VERSION').read_text('utf-8-sig').strip()
            self.assertEqual((root/'VERSION').read_bytes(), (ROOT/'VERSION').read_bytes())
            expected='本地指纹浏览器 v'+version
            launcher,report,nonce=scope['_ui_launcher'](app,root,expected)
            self.assertIn('EXPECTED_TITLE='+repr(expected), launcher.read_text('utf-8'))
            self.assertIn("document.title === '本地指纹浏览器'", scope['_readiness_expression']('about:blank'))
            captions={101:expected,202:'本地指纹浏览器'}
            user=types.SimpleNamespace(**{name:MagicMock() for name in ('EnumWindows','IsWindowVisible',
                'GetWindowThreadProcessId','GetWindowTextW','GetWindowRect','PostMessageW')})
            user.EnumWindows.side_effect=lambda callback,_:all(callback(window,0) for window in captions)
            user.IsWindowVisible.return_value=True
            def owner(window,pointer):pointer._obj.value=22
            def caption(window,buffer,size):buffer.value=captions[window]
            def rectangle(window,pointer):
                pointer._obj.right=1460;pointer._obj.bottom=920
                return True
            user.GetWindowThreadProcessId.side_effect=owner
            user.GetWindowTextW.side_effect=caption
            user.GetWindowRect.side_effect=rectangle
            with patch.object(ctypes,'WinDLL',return_value=user):
                self.assertEqual(scope['Windows'](expected).visible(22), [101])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path)
    options = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DirectLaunch)
    names = [test.id().rsplit('.', 1)[-1] for test in suite]
    # Keep tracebacks in memory; the public output only contains synthetic counts.
    result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    failed = {test.id().rsplit('.', 1)[-1] for test, _ in result.failures + result.errors}
    report = {'success':result.wasSuccessful(), 'checks':{name:name not in failed for name in names},
              'passed':result.testsRun-len(failed), 'failed':sorted(failed),
              'real_browser_started':False, 'real_user_data_accessed':False}
    if options.report:
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(report, ensure_ascii=False))
    print('Ran {} tests in synthetic fixtures'.format(result.testsRun), file=sys.stderr)
    print('OK' if result.wasSuccessful() else 'FAILED (failures={}, errors={})'.format(
        len(result.failures), len(result.errors)), file=sys.stderr)
    sys.exit(0 if result.wasSuccessful() else 1)
