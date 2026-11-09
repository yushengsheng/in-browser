"""Synthetic CDP and manager fixtures; no account profiles, network or browser."""
import copy
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from ip_info_page import IP_INFO_URL,show_ip_info
from local_state import LocalBrowserError
from manager_service import ManagerService


class InfoTabTests(unittest.TestCase):
    def connection(self,pages):
        def call(method,params=None,session=None):
            if method=='Target.getTargets':return {'targetInfos':pages}
            if method=='Target.createTarget':return {'targetId':'new-info'}
            if method=='Target.attachToTarget':return {'sessionId':'info-session'}
            return {}
        return Mock(call=Mock(side_effect=call))

    def test_new_tab_keeps_all_existing_pages_and_uses_browser_network(self):
        connection=self.connection([{'type':'page','url':'https://synthetic.invalid/account','targetId':'account'}])
        self.assertEqual(show_ip_info(connection),'new-info')
        connection.call.assert_any_call('Target.createTarget',{'url':IP_INFO_URL,'background':False})
        self.assertFalse(any(call.args[0] in ('Page.navigate','Target.closeTarget','Network.setUserAgentOverride','Emulation.setDeviceMetricsOverride') for call in connection.call.call_args_list))

    def test_restored_info_tab_is_refreshed_without_accumulating_tabs(self):
        connection=self.connection([{'type':'page','url':IP_INFO_URL,'targetId':'restored-info'},
                                    {'type':'page','url':'https://synthetic.invalid/account','targetId':'account'}])
        self.assertEqual(show_ip_info(connection),'restored-info')
        connection.call.assert_any_call('Page.reload',{'ignoreCache':True},session='info-session')
        connection.call.assert_any_call('Target.detachFromTarget',{'sessionId':'info-session'})
        self.assertFalse(any(call.args[0]=='Target.createTarget' for call in connection.call.call_args_list))

    def test_similar_urls_and_non_page_targets_are_never_reused(self):
        for url,kind in [('https://ifconfig.co.evil.invalid/','page'),(IP_INFO_URL+'?ip=synthetic','page'),(IP_INFO_URL,'service_worker')]:
            with self.subTest(url=url,kind=kind):self.assertEqual(show_ip_info(self.connection([{'type':kind,'url':url,'targetId':'other'}])),'new-info')

    def test_missing_creation_receipt_fails_instead_of_claiming_page_opened(self):
        connection=self.connection([]);connection.call.side_effect=lambda *args,**kwargs:{}
        with self.assertRaises(LocalBrowserError):show_ip_info(connection)


class ManagerRouteTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='proxy-launch-synthetic-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.record={'id':'synthetic','proxy':{'type':'socks5','host':'synthetic-upstream.invalid','port':1234,'username':'synthetic-user','password':'synthetic-password'},
            '_runtime':{'alias':'synthetic','profile_path':str(self.root/'profile'),'fingerprint_path':'synthetic-signature',
                        'core_major':'148','new_profile':False,'has_launched':True},'_cookie_pending':False}

    def service(self,*,opened=False,direct=False):
        service=ManagerService.__new__(ManagerService);service.root=self.root;service.operations=threading.RLock()
        record=copy.deepcopy(self.record)
        if direct:record['proxy']={'type':'noproxy'}
        service._require_available=Mock();service._status=Mock(return_value='open' if opened else 'closed')
        service._runtime=Mock(side_effect=lambda p,previous:copy.deepcopy(previous));service._preferences=Mock();service._sync=Mock()
        service.store=SimpleNamespace(get=Mock(return_value=record),put=Mock(),public=lambda p,status:{'id':p['id'],'status':status})
        service.configuration=SimpleNamespace(independent=False,proxy_test=Mock(return_value={'success':True}))
        service.proxy_runtime=SimpleNamespace(ensure=Mock(return_value=None if direct else {'port':32123}),owned=Mock(return_value=True),
                                             control=Mock(return_value=True),stop_if_unused=Mock())
        service.controller=Mock()
        service.controller.open.side_effect=lambda *args,**kwargs:kwargs['before_launch']() if not opened else None
        return service,record

    def run_open(self,service,**kwargs):
        with patch('manager_service.require_current_signature'),patch('manager_service.CDP') as cdp,patch('ip_info_page.show_ip_info') as show:
            result=service.open('synthetic',**kwargs)
        return result,show,cdp

    def test_new_proxy_window_checks_actual_loopback_route_then_opens_ip_tab(self):
        service,record=self.service();native=copy.deepcopy(record)
        result,show,_=self.run_open(service)
        service.configuration.proxy_test.assert_called_once_with({'type':'http','host':'127.0.0.1','port':32123,'username':'','password':''})
        self.assertEqual(service.proxy_runtime.control.call_count,2);show.assert_called_once()
        self.assertEqual(record['proxy'],native['proxy']);self.assertEqual(result['status'],'open')

    def test_already_open_and_offline_probe_do_not_open_info_tabs_or_probe(self):
        for opened,offline in ((True,False),(False,True)):
            with self.subTest(opened=opened,offline=offline):
                service,_=self.service(opened=opened);_,show,_=self.run_open(service,offline_test=offline)
                show.assert_not_called();service.configuration.proxy_test.assert_not_called()

    def test_explicit_direct_mode_opens_info_tab_without_adding_proxy(self):
        service,record=self.service(direct=True);_,show,_=self.run_open(service)
        show.assert_called_once();service.configuration.proxy_test.assert_not_called()
        self.assertEqual(record['_runtime']['local_proxy_mode'],'direct')

    def test_route_failure_stops_before_info_tab_and_never_retries_direct(self):
        service,_=self.service();service.configuration.proxy_test.return_value={'success':False,'message':'synthetic failure'}
        with patch('manager_service.require_current_signature'),patch('manager_service.profile_processes',return_value=[]),patch('ip_info_page.show_ip_info') as show:
            with self.assertRaises(LocalBrowserError):service.open('synthetic')
        show.assert_not_called();self.assertEqual(service.proxy_runtime.ensure.call_count,1)
        service.store.put.assert_not_called()

    def test_ip_tab_failure_reports_browser_remains_open_without_changing_native(self):
        service,record=self.service();before=copy.deepcopy(record)
        with patch('manager_service.require_current_signature'),patch('manager_service.CDP'),patch('ip_info_page.show_ip_info',side_effect=RuntimeError('synthetic private detail')):
            with self.assertRaisesRegex(LocalBrowserError,'浏览器已打开，但IP信息页未能打开') as failure:service.open('synthetic')
        self.assertNotIn('synthetic private detail',str(failure.exception))
        service.controller.close.assert_not_called();self.assertEqual(record['proxy'],before['proxy'])


if __name__=='__main__':unittest.main(verbosity=2)
