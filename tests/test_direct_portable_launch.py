"""Synthetic direct-launch checks. No real data or browser is opened."""
import ast
import argparse
from contextlib import ExitStack, nullcontext
import ctypes
from ctypes import wintypes
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import MagicMock, patch

import psutil

ROOT = Path(__file__).resolve().parents[1]


class DirectLaunch(unittest.TestCase):
    def launcher(self, name, *, delayed=False, missing=None):
        with tempfile.TemporaryDirectory(prefix='direct-portable-synthetic-') as directory:
            base = Path(directory)
            root = base / name
            app = root / 'app'
            runtime = root / 'runtime/python'
            app.mkdir(parents=True)
            runtime.mkdir(parents=True)
            (root / 'runtime/webview2').mkdir()
            (root / 'runtime/webview2/msedgewebview2.exe').write_bytes(b'synthetic, never executed')
            # Only copy the embeddable interpreter itself, never site packages or app data.
            for source in (ROOT / 'runtime/python').iterdir():
                if source.is_file():
                    shutil.copy2(source, runtime / source.name)
            launcher = root / 'start.cmd'
            launcher.write_bytes((ROOT / '启动本地浏览器.cmd').read_bytes())
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
            if missing:
                (root / missing).unlink()
            env = os.environ.copy()
            env.update(PYTHONHOME=str(base / 'synthetic_external_home'),
                       PYTHONPATH=str(base / 'synthetic_external_path'))
            command = '"{}" /d /v:{} /s /c ""{}""'.format(
                os.environ.get('COMSPEC', 'cmd.exe'), 'on' if delayed else 'off', launcher)
            started = time.time()
            result = subprocess.run(command, cwd=base, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            if missing:
                self.assertEqual(result.returncode, 1)
                self.assertFalse((app / 'fixture-result.json').exists())
                return
            self.assertEqual(result.returncode, 0)
            marker = app / 'fixture-result.json'
            deadline = time.monotonic() + 5
            while not marker.is_file() and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertTrue(marker.is_file(), 'synthetic_launcher_did_not_reach_bundled_python')
            observed = json.loads(marker.read_text('utf-8'))
            try:
                process = psutil.Process(observed.pop('pid'))
                self.assertGreaterEqual(process.create_time(), started-2)
                self.assertEqual(Path(process.exe()).resolve(), runtime / 'pythonw.exe')
                self.assertIn(str(app / 'local_browser.pyw'), process.cmdline())
                # The result file proves execution, not interpreter exit. Wait before removal.
                try:
                    process.wait(timeout=10)
                except psutil.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=10)
                    self.fail('synthetic_interpreter_did_not_exit')
            except psutil.NoSuchProcess:
                pass
            self.assertTrue(all(observed.values()))

    def test_spaces_chinese_arbitrary_cwd_and_python_env(self):
        self.launcher('移动盘 便携目录')

    def test_exclamation_path_with_inherited_delayed_expansion(self):
        self.launcher('移动盘 !合成! 便携目录', delayed=True)

    def test_launcher_refuses_incomplete_bundle(self):
        for missing in ('runtime/python/pythonw.exe', 'runtime/webview2/msedgewebview2.exe',
                        'app/local_browser.pyw'):
            with self.subTest(component=missing):
                self.launcher('移动盘 便携目录', missing=missing)

    def manager(self, root, *, present=True):
        app = root / 'app'
        app.mkdir()
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
        kernel = types.SimpleNamespace(CreateMutexW=MagicMock(return_value=1), CloseHandle=MagicMock())
        user = types.SimpleNamespace(MessageBoxW=MagicMock())
        env = {'WEBVIEW2_BROWSER_EXECUTABLE_FOLDER':str(root / 'outside-runtime'),
               'WEBVIEW2_USER_DATA_FOLDER':str(root / 'outside-user-data'),
               'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS':'--remote-debugging-port=12345',
               'WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER':'1'}
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, browser_core=core, manager_service=manager,
                                           installation=installation, webview=webview))
            stack.enter_context(patch.object(ctypes, 'WinDLL', return_value=kernel))
            stack.enter_context(patch.object(ctypes, 'get_last_error', return_value=0))
            stack.enter_context(patch.object(ctypes, 'windll', types.SimpleNamespace(user32=user)))
            stack.enter_context(patch.dict(os.environ, env))
            stack.enter_context(patch.object(sys, 'argv', ['local_browser.pyw']))
            previous_path = list(sys.path)
            try:
                namespace = runpy.run_path(str(ROOT / 'app/local_browser.pyw'), run_name='portable_synthetic')
                namespace['main']()
            finally:
                sys.path[:] = previous_path
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

    def focus_manager(self, *, match=True, reused_pid=False):
        with tempfile.TemporaryDirectory(prefix='sibling-manager-fixture-') as directory:
            root=Path(directory)
            apps={11:root/'A/app',22:root/'B/app'}
            python=root/'B/runtime/python/pythonw.exe'
            user=types.SimpleNamespace(FindWindowExW=MagicMock(side_effect=[101,202,0]),
                GetWindowThreadProcessId=MagicMock(),ShowWindow=MagicMock(),SetForegroundWindow=MagicMock())
            owners={101:11,202:22}
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
                   'APP_ROOT':apps[22],'TITLE':'本地指纹浏览器'}
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
        options.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(report, ensure_ascii=False))
    print('Ran {} tests in synthetic fixtures'.format(result.testsRun), file=sys.stderr)
    print('OK' if result.wasSuccessful() else 'FAILED (failures={}, errors={})'.format(
        len(result.failures), len(result.errors)), file=sys.stderr)
    sys.exit(0 if result.wasSuccessful() else 1)
