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

    def test_created_direct_webrtc_replacement_checks_actual_egress_before_launch(self):
        service,record=self.service(direct=True)
        record.update(created_locally=True,fingerprint={'webRTC':'0'},created_options={},
                      _native={'WebRTC':{'PublicIP':'192.0.2.1'}})
        with patch('created_window.prepare_launch',side_effect=lambda s,p,**kw:p), \
                patch('created_window.apply_launch_cleanup'), \
                patch('dynamic_proxy.prepare_dynamic_proxy',side_effect=lambda s,p:p), \
                patch('proxy_check.ProxyChecker') as checker:
            checker.return_value.test.return_value={'success':True,'egress_ip':'192.0.2.1'}
            self.run_open(service)
            checker.return_value.test.assert_called_once_with(record['proxy'])
        self.assertEqual(record['_pending_creation_egress'] if '_pending_creation_egress' in record else record['_last_creation_egress'],
                         {'ip':'192.0.2.1','country':None})

    def test_created_direct_webrtc_mismatch_refuses_launch_and_skips_info_tab(self):
        service,record=self.service(direct=True)
        record.update(created_locally=True,fingerprint={'webRTC':'0'},created_options={},
                      _native={'WebRTC':{'PublicIP':'192.0.2.1'}})
        with patch('created_window.prepare_launch',side_effect=lambda s,p,**kw:p), \
                patch('created_window.apply_launch_cleanup'), \
                patch('dynamic_proxy.prepare_dynamic_proxy',side_effect=lambda s,p:p), \
                patch('proxy_check.ProxyChecker') as checker, \
                patch('manager_service.require_current_signature'), \
                patch('manager_service.profile_processes',return_value=[]), \
                patch('ip_info_page.show_ip_info') as show:
            checker.return_value.test.return_value={'success':True,'egress_ip':'192.0.2.2'}
            with self.assertRaises(LocalBrowserError):service.open('synthetic')
            show.assert_not_called();service.store.put.assert_not_called()

    def test_local_maintenance_precedes_created_environment_probe(self):
        service,record=self.service(direct=True)
        record.update(created_locally=True,fingerprint={'webRTC':'3'},created_options={})
        record['_runtime']['signature_provider']='local-v1'
        order=[]
        def maintain(p):order.append('maintenance');return p
        def prepare(s,p,**kw):order.append('created_environment');return p
        with patch('local_runtime.LocalRuntime') as runtime, \
                patch('created_window.prepare_launch',side_effect=prepare), \
                patch('created_window.apply_launch_cleanup'), \
                patch('dynamic_proxy.prepare_dynamic_proxy',side_effect=lambda s,p:p):
            runtime.return_value.prepare.side_effect=maintain
            self.run_open(service)
        self.assertEqual(order,['maintenance','created_environment'])

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

    def test_continuity_verified_arguments_reach_real_launch_without_changing_native(self):
        service,record=self.service();record['_native']={'synthetic':True};native=copy.deepcopy(record['_native'])
        record['_continuity']={'synthetic':'original-baseline'};baseline=copy.deepcopy(record['_continuity'])
        arguments=['--force-prefers-no-reduced-motion','--use-angle=d3d11','--ignore-gpu-blocklist']
        observed=[];persisted=[]
        service.store.put.side_effect=lambda value:persisted.append(copy.deepcopy(value))
        def launch(*values,**options):
            observed.extend(record['_runtime'].get('environment_args',[]));options['before_launch']()
        service.controller.open.side_effect=launch
        with tempfile.TemporaryDirectory() as directory:
            service.root=Path(directory);(service.root/'continuity-mode.bin').write_bytes(b'synthetic')
            with patch('fingerprint_continuity.verify_continuity',return_value={'environment_args':arguments}) as verify:
                self.run_open(service)
        verify.assert_called_once_with(record,service.root,allow_device_variance=True);self.assertEqual(observed,arguments)
        self.assertNotIn('environment_args',record['_runtime'])
        service.controller.open.assert_called_once();self.assertEqual(record['_native'],native)
        self.assertTrue(persisted)
        self.assertTrue(all('environment_args' not in value['_runtime'] for value in persisted))
        self.assertTrue(all(value['_continuity']==baseline and value['_native']==native for value in persisted))

    def test_stock_device_variance_result_opens_with_original_arguments_and_is_not_persisted(self):
        service,record=self.service();record['_native']={'synthetic':True}
        record['_runtime']['launch_args']=['--lang=zh-CN']
        record['_continuity']={'synthetic':'original-baseline'}
        before=copy.deepcopy(record);observed=[];persisted=[]
        service.store.put.side_effect=lambda value:persisted.append(copy.deepcopy(value))
        def launch(*values,**options):
            observed.append(copy.deepcopy(record));options['before_launch']()
        service.controller.open.side_effect=launch
        with tempfile.TemporaryDirectory() as directory:
            service.root=Path(directory);(service.root/'continuity-mode.bin').write_bytes(b'synthetic')
            with patch('fingerprint_continuity.verify_continuity',return_value={
                    'passed':True,'environment_args':[],'device_variance_fields':['fonts.metrics'],
                    'verification_policy':'vendor-compatible-148'}) as verify:
                self.run_open(service)
        verify.assert_called_once_with(record,service.root,allow_device_variance=True)
        self.assertEqual(len(observed),1)
        self.assertEqual(observed[0]['_runtime']['environment_args'],[])
        self.assertEqual(observed[0]['_runtime']['launch_args'],before['_runtime']['launch_args'])
        self.assertEqual(record['_native'],before['_native'])
        self.assertEqual(record['_continuity'],before['_continuity'])
        self.assertTrue(persisted)
        for value in persisted:
            self.assertNotIn('environment_args',value['_runtime'])
            self.assertNotIn('verification_policy',value)
            self.assertNotIn('device_variance_fields',value)

    def test_incompatible_device_stops_before_cookie_rewrap_preferences_or_launch(self):
        service,_=self.service()
        with tempfile.TemporaryDirectory() as directory:
            service.root=Path(directory)
            for name in ('continuity-mode.bin','portable-mode.bin'):(service.root/name).write_bytes(b'synthetic')
            with patch('fingerprint_continuity.verify_continuity',side_effect=LocalBrowserError('环境连续性检查未通过（fonts.metrics）')), \
                    patch('portable_browser.prepare_profile') as rewrap:
                with self.assertRaises(LocalBrowserError):service.open('synthetic')
        rewrap.assert_not_called();service._preferences.assert_not_called()
        service.proxy_runtime.ensure.assert_not_called();service.controller.open.assert_not_called()
        service.store.put.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)
