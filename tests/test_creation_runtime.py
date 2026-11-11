"""New-window runtime options must not change imported-window behavior."""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from creation_fingerprint import creation_defaults
from manager_service import ManagerService


class CreationRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.engine=ROOT/'tests/synthetic-runtime-engine.exe'
        self.profile=creation_defaults()
        self.profile.update(id='synthetic-runtime',created_locally=True,_native={'uiLang':'en-US'})
        self.profile['fingerprint'].update(displayLanguages='zh-CN',isIpCreateDisplayLanguage=True)
        self.service=SimpleNamespace(root=ROOT/'tests/synthetic-data',
            configuration=SimpleNamespace(independent=False),
            settings=lambda:{'browser_path':'','start_page':''},cores=lambda:{'148':str(self.engine)},
            engines=SimpleNamespace(root=self.engine.parent,install=lambda *args:self.engine))
        self.previous={'core_major':'148','core_path':str(self.engine),'core_sha256':'synthetic',
            'profile_path':str(ROOT/'tests/synthetic-profile'),'language':'en-US','creation_options_version':1}

    def runtime(self,profile=None,previous=None):
        with patch('manager_service.profile_processes',return_value=[]):
            return ManagerService._runtime(self.service,profile or self.profile,previous or self.previous)

    def test_ip_language_survives_each_runtime_rebuild(self):
        before=copy.deepcopy(self.profile)
        first=self.runtime()
        self.assertEqual(first['language'],'en-US')
        self.assertEqual(self.runtime(previous=first)['language'],'en-US')
        self.assertEqual(before,self.profile)

    def test_manual_and_imported_language_keep_existing_behavior(self):
        for created,ip in ((False,True),(False,False),(True,False)):
            with self.subTest(created=created,ip=ip):
                self.profile['created_locally']=created
                self.profile['fingerprint']['isIpCreateDisplayLanguage']=ip
                self.assertEqual(self.runtime()['language'],'zh-CN')

    def test_certificate_toggle_only_applies_to_created_window_and_can_be_disabled(self):
        before=copy.deepcopy(self.profile)
        self.assertNotIn('--ignore-certificate-errors',self.runtime()['launch_args'])
        self.profile['fingerprint']['ignoreHttpsErrors']=True
        enabled=self.runtime()
        self.assertEqual(enabled['launch_args'].count('--ignore-certificate-errors'),1)
        self.assertEqual(self.runtime(previous=enabled)['launch_args'].count('--ignore-certificate-errors'),1)
        self.profile['fingerprint']['ignoreHttpsErrors']=False
        self.assertNotIn('--ignore-certificate-errors',self.runtime(previous=enabled)['launch_args'])
        self.profile['fingerprint']['ignoreHttpsErrors']=True
        self.profile['created_locally']=False
        self.assertNotIn('--ignore-certificate-errors',self.runtime()['launch_args'])
        self.assertFalse(before['fingerprint']['ignoreHttpsErrors'])

    def test_preexisting_created_window_does_not_silently_change_launch_binding(self):
        self.previous.pop('creation_options_version')
        self.profile['fingerprint']['ignoreHttpsErrors']=True
        self.assertNotIn('--ignore-certificate-errors',self.runtime()['launch_args'])

    def test_certificate_option_reaches_continuity_only_for_new_creation_runtime(self):
        from fingerprint_continuity import _launch_arguments
        from local_state import LocalBrowserError
        self.profile['fingerprint']['ignoreHttpsErrors']=True
        runtime=self.runtime()
        self.assertEqual(_launch_arguments(runtime),['--ignore-certificate-errors'])
        legacy=copy.deepcopy(runtime);legacy.pop('creation_options_version')
        with self.assertRaises(LocalBrowserError):_launch_arguments(legacy)
        runtime['launch_args']=['--ignore-certificate-errors=unexpected']
        with self.assertRaises(LocalBrowserError):_launch_arguments(runtime)

    def test_custom_switch_is_preserved_without_duplicate_or_bypassing_policy(self):
        self.profile['fingerprint'].update(ignoreHttpsErrors=True,launchArgs='--ignore-certificate-errors')
        self.assertEqual(self.runtime()['launch_args'],['--ignore-certificate-errors'])
        self.profile['fingerprint']['launchArgs']='--proxy-server=synthetic'
        from local_state import LocalBrowserError
        with self.assertRaises(LocalBrowserError):self.runtime()


if __name__=='__main__':unittest.main()
