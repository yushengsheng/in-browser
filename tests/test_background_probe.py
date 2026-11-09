"""Synthetic launch boundaries; never launch a real browser or read user data."""
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))

import browser_core as core


class BackgroundProbeTests(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory(prefix='background-probe-fixture-')
        self.addCleanup(directory.cleanup)
        self.root=Path(directory.name)
        self.profile=self.root/'empty-profile';self.profile.mkdir()
        self.executable=self.root/'BitBrowser.exe';self.executable.write_bytes(b'synthetic-core')
        self.config=self.root/'fingerprint.bin';self.config.write_bytes(b'synthetic-signature')
        self.runtime={'alias':'probe_synthetic','profile_path':str(self.profile),
            'core_path':str(self.executable),'core_sha256':core.sha256(self.executable),'core_major':'148',
            'fingerprint_path':str(self.config),'fingerprint_sha256':core.sha256(self.config),
            'new_profile':True,'restore_session':False,'launch_args':[]}

    def launch(self,*,background=True,changes=None,offline=True,blank=True,urls=None,expect_no_launch=False,desktop=None,
               visibility=None,expect_timeout=False,launch_path=None):
        runtime=copy.deepcopy(self.runtime);runtime.update(changes or {})
        controller=core.BrowserController(self.root,settings={'windows':[runtime],'persistent':False})
        controller._save=Mock();controller.endpoint=Mock(return_value='synthetic-endpoint')
        process=Mock(pid=12345);process.poll.return_value=None
        visible=Mock(return_value=[] if background else [1]) if visibility is None else visibility
        with patch.object(controller,'_ensure_record',return_value=False), \
                patch.object(core,'_check_launch_paths',wraps=core._check_launch_paths) as paths, \
                patch.object(core,'_profile_browsers',return_value=[]), \
                patch.object(core,'_visible_windows',side_effect=visible), \
                patch('signature_lifetime.require_current_signature') as signature, \
                patch.object(core.subprocess,'Popen',return_value=process) as popen, \
                patch.object(core.psutil,'Process',return_value=SimpleNamespace(create_time=lambda:100)):
            if expect_no_launch:popen.side_effect=AssertionError('A refused launch must not create a process')
            if launch_path is not None:paths.return_value=launch_path
            def open_browser():
                return controller.open(runtime['alias'],offline_test=offline,extra_urls=['about:blank'] if urls is None else urls,
                                       bootstrap_blank=blank,background_probe=background,background_desktop=desktop)
            if expect_timeout:
                with self.assertRaisesRegex(core.LocalBrowserError,'窗口启动超时'):open_browser()
                result=None
                process.kill.assert_not_called();process.terminate.assert_not_called()
            else:result=open_browser()
        return popen.call_args,signature.call_count,result,controller

    def test_background_probe_retains_offline_signature_and_profile_checks(self):
        call,signatures,result,controller=self.launch()
        args=call.args[0]
        self.assertEqual(args.count('--headless=new'),1)
        self.assertIn('--disable-extensions',args)
        self.assertIn('--disable-background-networking',args)
        self.assertIn('--proxy-server=http://127.0.0.1:1',args)
        self.assertIn('--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost',args)
        self.assertIn('--user-data-dir='+str(self.profile.resolve()),args)
        self.assertEqual(args[-1],'about:blank')
        self.assertEqual(signatures,2)
        self.assertTrue(result['ready']);self.assertFalse(result['window_observed'])
        controller.endpoint.assert_called_once()

    def test_normal_browser_launch_keeps_existing_visible_mode(self):
        call,_,result,_=self.launch(background=False)
        self.assertFalse(any(arg.startswith('--headless') for arg in call.args[0]))
        self.assertTrue(result['ready']);self.assertTrue(result['window_observed'])

    def test_launch_alias_is_used_by_executable_resources_and_working_directory(self):
        alias=self.root/'short-spelling'/'BitBrowser.exe'
        call,_,_,controller=self.launch(launch_path=alias)
        self.assertEqual(call.args[0][0],str(alias))
        self.assertIn('--file-url-path-alias=/gen='+str(alias.parent/'gen'),call.args[0])
        self.assertEqual(call.kwargs['cwd'],alias.parent)
        self.assertEqual(controller.profiles[self.runtime['alias']]['core_path'],str(self.executable))

    def test_path_limit_cause_survives_environment_probe_wrapping(self):
        import fingerprint_continuity as continuity
        error=core.LocalBrowserError('程序目录层级过深');error.code='engine_path_too_long'
        before=copy.deepcopy(self.runtime)
        controller=Mock();controller.profiles={'synthetic':{}};controller.open.side_effect=error
        with patch.object(continuity,'BrowserController',return_value=controller), \
                patch.object(continuity,'profile_processes',return_value=[]):
            with self.assertRaises(core.LocalBrowserError) as caught:
                continuity.probe_snapshot({'_runtime':self.runtime},self.root)
        self.assertIs(caught.exception,error)
        self.assertEqual(self.runtime,before)

    def test_normal_launch_waits_for_visible_window_after_control_is_ready(self):
        visible=Mock(side_effect=[[],[],[1]])
        with patch.object(core.time,'sleep') as sleep:
            _,_,result,controller=self.launch(background=False,visibility=visible)
        self.assertTrue(result['ready']);self.assertTrue(result['window_observed'])
        self.assertEqual(controller.endpoint.call_count,3)
        self.assertEqual(sleep.call_count,2)

    def test_normal_launch_without_visible_window_uses_existing_deadline_and_keeps_process(self):
        elapsed=[0.0]
        def sleep(delay):elapsed[0]+=delay
        with patch.object(core.time,'monotonic',side_effect=lambda:elapsed[0]), \
                patch.object(core.time,'sleep',side_effect=sleep):
            _,_,result,controller=self.launch(background=False,visibility=lambda pid:[],expect_timeout=True)
        self.assertIsNone(result)
        self.assertAlmostEqual(elapsed[0],25)
        self.assertEqual(controller.state[self.runtime['alias']]['pid'],12345)
        self.assertFalse(controller.state[self.runtime['alias']]['ready'])
        self.assertFalse(controller.state[self.runtime['alias']]['window_observed'])
        self.assertNotIn('has_launched',controller.profiles[self.runtime['alias']])

    def test_verified_environment_flags_are_shared_by_probe_and_normal_launch(self):
        environment=['--force-prefers-no-reduced-motion','--use-angle=d3d11','--ignore-gpu-blocklist']
        for background in (True,False):
            with self.subTest(background=background):
                call,_,_,_=self.launch(background=background,changes={'environment_args':environment})
                for argument in environment:self.assertEqual(call.args[0].count(argument),1)
                self.assertEqual(self.runtime['launch_args'],[])

    def test_environment_flags_cannot_inject_proxy_or_unsupported_options(self):
        for arguments in (['--proxy-server=http://fixture.invalid'],['--use-angle=swiftshader'],
                          ['--ignore-gpu-blocklist'],['--force-prefers-reduced-motion','--force-prefers-no-reduced-motion']):
            with self.subTest(arguments=arguments),self.assertRaises(core.LocalBrowserError):
                self.launch(changes={'environment_args':arguments},expect_no_launch=True)

    def test_background_mode_rejects_account_or_nonisolated_launch_before_popen(self):
        cases=[{'offline':False},{'blank':False},{'urls':['https://synthetic.invalid/']},
               {'changes':{'new_profile':False}},{'changes':{'restore_session':True}},
               {'changes':{'managed_extension':'synthetic-extension'}},
               *({'changes':{key:'synthetic-account'}} for key in ('account_platform','account_username','account_password'))]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs),self.assertRaises(core.LocalBrowserError):self.launch(**kwargs,expect_no_launch=True)

    def test_fingerprint_hash_mismatch_still_refuses_background_probe(self):
        with self.assertRaises(core.LocalBrowserError):
            self.launch(changes={'fingerprint_sha256':'0'*64})

    def test_104_uses_private_desktop_without_old_headless_renderer(self):
        with self.assertRaises(core.LocalBrowserError):self.launch(changes={'core_major':'104'},expect_no_launch=True)
        desktop=Mock();desktop.startupinfo.return_value=SimpleNamespace(lpDesktop='synthetic-private-desktop')
        call,signatures,_,_=self.launch(changes={'core_major':'104'},desktop=desktop)
        self.assertFalse(any(arg.startswith('--headless') for arg in call.args[0]))
        self.assertIs(call.kwargs['startupinfo'],desktop.startupinfo.return_value)
        self.assertEqual(call.kwargs['cwd'],self.profile.resolve())
        self.assertEqual(signatures,2)
        with self.assertRaises(core.LocalBrowserError):self.launch(background=False,desktop=desktop,expect_no_launch=True)

    def test_private_desktop_creation_is_fail_closed_and_close_is_idempotent(self):
        from probe_display import ProbeDesktop
        user=Mock();user.CreateDesktopW.return_value=123;user.CloseDesktop.return_value=True
        with patch('probe_display.ctypes.WinDLL',return_value=user):
            desktop=ProbeDesktop();info=desktop.startupinfo()
            self.assertTrue(info.lpDesktop.startswith('LocalContinuityProbe_'))
            desktop.close();desktop.close()
            user.CloseDesktop.assert_called_once_with(123)
            with self.assertRaises(core.LocalBrowserError):desktop.startupinfo()
            user.CreateDesktopW.return_value=0
            with self.assertRaises(core.LocalBrowserError):ProbeDesktop()


if __name__=='__main__':unittest.main(verbosity=2)
