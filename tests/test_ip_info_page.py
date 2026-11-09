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
    def connection(self,pages,*,on_snapshot=None):
        pages=copy.deepcopy(pages);snapshots=0
        def call(method,params=None,session=None):
            nonlocal snapshots
            if method=='Target.getTargets':
                snapshots+=1
                if on_snapshot:on_snapshot(snapshots,pages)
                return {'targetInfos':copy.deepcopy(pages)}
            if method=='Target.createTarget':
                pages.append({'type':'page','url':IP_INFO_URL,'targetId':'new-info'})
                return {'targetId':'new-info'}
            if method=='Target.closeTarget':
                pages[:]=[page for page in pages if page['targetId']!=params['targetId']]
                return {'success':True}
            return {}
        connection=Mock(call=Mock(side_effect=call));connection.pages=pages
        return connection

    def test_new_tab_keeps_all_existing_pages_and_uses_browser_network(self):
        connection=self.connection([{'type':'page','url':'https://synthetic.invalid/account','targetId':'account'}])
        self.assertEqual(show_ip_info(connection),'new-info')
        connection.call.assert_any_call('Target.createTarget',{'url':IP_INFO_URL,'background':False})
        self.assertFalse(any(call.args[0] in ('Page.navigate','Target.closeTarget','Network.setUserAgentOverride','Emulation.setDeviceMetricsOverride') for call in connection.call.call_args_list))

    def test_restored_info_tab_is_replaced_only_after_new_page_is_confirmed(self):
        connection=self.connection([{'type':'page','url':IP_INFO_URL,'targetId':'restored-info'},
                                    {'type':'page','url':'https://synthetic.invalid/account','targetId':'account'}])
        self.assertEqual(show_ip_info(connection),'new-info')
        calls=[value.args[0] for value in connection.call.call_args_list]
        self.assertEqual(calls,['Target.getTargets','Target.createTarget','Target.getTargets',
            'Target.getTargets','Target.closeTarget','Target.getTargets','Target.activateTarget'])
        self.assertEqual({page['targetId'] for page in connection.pages},{'account','new-info'})
        self.assertFalse(any(value.startswith('Page.') or value in ('Target.attachToTarget','Target.detachFromTarget') for value in calls))

    def test_similar_urls_and_non_page_targets_are_never_reused(self):
        for url,kind in [('https://ifconfig.co.evil.invalid/','page'),(IP_INFO_URL+'?ip=synthetic','page'),(IP_INFO_URL,'service_worker')]:
            with self.subTest(url=url,kind=kind):self.assertEqual(show_ip_info(self.connection([{'type':kind,'url':url,'targetId':'other'}])),'new-info')

    def test_missing_creation_receipt_fails_instead_of_claiming_page_opened(self):
        connection=self.connection([{'type':'page','url':IP_INFO_URL,'targetId':'old'}]);original=connection.call.side_effect
        connection.call.side_effect=lambda method,*args,**kwargs:{} if method=='Target.createTarget' else original(method,*args,**kwargs)
        with self.assertRaises(LocalBrowserError) as failure:show_ip_info(connection)
        self.assertEqual(failure.exception.operation,'Target.createTarget')
        self.assertFalse(any(value.args[0]=='Target.closeTarget' for value in connection.call.call_args_list))

    def test_each_cdp_failure_has_a_fixed_operation_without_original_private_text(self):
        for operation in ('Target.getTargets','Target.closeTarget','Target.createTarget','Target.activateTarget'):
            pages=[] if operation=='Target.createTarget' else [{'type':'page','url':IP_INFO_URL,'targetId':'info'}]
            connection=self.connection(pages);original=connection.call.side_effect
            def call(method,params=None,session=None):
                if method==operation:raise TimeoutError('synthetic-private-account-or-proxy')
                return original(method,params,session)
            connection.call.side_effect=call
            with self.subTest(operation=operation),self.assertRaises(LocalBrowserError) as failure:
                show_ip_info(connection)
            self.assertEqual(failure.exception.code,'ip_info_failed')
            self.assertEqual(failure.exception.operation,operation)
            self.assertEqual(failure.exception.cause_type,'TimeoutError')
            self.assertNotIn('synthetic-private',str(failure.exception))

    def test_new_target_wrong_url_or_reused_id_cannot_close_any_old_page(self):
        for altered in ('wrong-url','reused-id'):
            def change(number,pages):
                if number==2:
                    pages[-1]['url']='https://synthetic.invalid/account'
            connection=self.connection([{'type':'page','url':IP_INFO_URL,'targetId':'old'}],on_snapshot=change)
            original=connection.call.side_effect
            if altered=='reused-id':
                connection.call.side_effect=lambda method,*args,**kwargs:{'targetId':'old'} if method=='Target.createTarget' else original(method,*args,**kwargs)
            with self.subTest(altered=altered),self.assertRaises(LocalBrowserError):show_ip_info(connection)
            self.assertFalse(any(value.args[0]=='Target.closeTarget' for value in connection.call.call_args_list))

    def test_old_info_changed_to_account_or_disappeared_before_close_is_preserved(self):
        for disappeared in (False,True):
            def change(number,pages):
                if number==3:
                    if disappeared:pages[:]=[page for page in pages if page['targetId']!='old']
                    else:pages[0]['url']='https://synthetic.invalid/account'
            connection=self.connection([{'type':'page','url':IP_INFO_URL,'targetId':'old'}],on_snapshot=change)
            self.assertEqual(show_ip_info(connection),'new-info')
            self.assertFalse(any(value.args[0]=='Target.closeTarget' for value in connection.call.call_args_list))

    def test_only_the_first_initial_info_page_is_replaced_and_other_info_pages_are_preserved(self):
        def change(number,pages):
            if number==2:pages.append({'type':'page','url':IP_INFO_URL,'targetId':'concurrent-info'})
        connection=self.connection([{'type':'page','url':IP_INFO_URL,'targetId':'old1'},
            {'type':'page','url':IP_INFO_URL.rstrip('/'),'targetId':'old2'},
            {'type':'page','url':IP_INFO_URL+'?private=value','targetId':'similar'}],on_snapshot=change)
        self.assertEqual(show_ip_info(connection),'new-info')
        closed=[value.args[1]['targetId'] for value in connection.call.call_args_list if value.args[0]=='Target.closeTarget']
        self.assertEqual(closed,['old1'])
        self.assertEqual({page['targetId'] for page in connection.pages},{'old2','similar','concurrent-info','new-info'})

    def test_close_failure_or_unconfirmed_removal_is_not_reported_as_success(self):
        for result in (False,True):
            connection=self.connection([{'type':'page','url':IP_INFO_URL,'targetId':'old'}]);original=connection.call.side_effect
            connection.timeout=.001
            connection.call.side_effect=lambda method,*args,**kwargs:{'success':result} if method=='Target.closeTarget' else original(method,*args,**kwargs)
            with self.subTest(result=result),self.assertRaises(LocalBrowserError):show_ip_info(connection)
            self.assertEqual({page['targetId'] for page in connection.pages},{'old','new-info'})
            self.assertFalse(any(value.args[0]=='Target.activateTarget' for value in connection.call.call_args_list))

    def test_new_target_disappearing_before_final_snapshot_fails(self):
        def change(number,pages):
            if number==3:pages[:]=[page for page in pages if page['targetId']!='new-info']
        connection=self.connection([],on_snapshot=change);connection.timeout=.001
        with self.assertRaises(LocalBrowserError):show_ip_info(connection)

    def test_same_new_id_exact_blank_exact_is_confirmed_before_close_and_after_close(self):
        clock=[0.0]
        def change(number,pages):
            if number in (3,5):
                next(page for page in pages if page['targetId']=='new-info')['url']='about:blank'
            if number in (4,6):
                next(page for page in pages if page['targetId']=='new-info')['url']=IP_INFO_URL
        connection=self.connection([{'type':'page','url':IP_INFO_URL,'targetId':'old'}],on_snapshot=change)
        with patch('ip_info_page.time.monotonic',side_effect=lambda:clock[0]), \
                patch('ip_info_page.time.sleep',side_effect=lambda duration:clock.__setitem__(0,clock[0]+duration)):
            self.assertEqual(show_ip_info(connection),'new-info')
        self.assertEqual(sum(value.args[0]=='Target.createTarget' for value in connection.call.call_args_list),1)
        self.assertEqual(sum(value.args[0]=='Target.closeTarget' for value in connection.call.call_args_list),1)
        self.assertEqual({page['targetId'] for page in connection.pages},{'new-info'})
        self.assertAlmostEqual(clock[0],.1)

    def test_blank_creation_and_pending_close_only_recheck_the_same_targets(self):
        clock=[0.0];observed=[]
        def change(number,pages):
            if number==2:pages[-1]['url']='about:blank'
            if number==3:pages[-1]['url']=IP_INFO_URL
            if number==6:pages[:]=[page for page in pages if page['targetId']!='old']
        connection=self.connection([{'type':'page','url':IP_INFO_URL,'targetId':'old'}],on_snapshot=change)
        connection.timeout=1.0;original=connection.call.side_effect
        def call(method,*args,**kwargs):
            observed.append((method,connection.timeout))
            if method=='Target.closeTarget':return {'success':True}
            return original(method,*args,**kwargs)
        connection.call.side_effect=call
        with patch('ip_info_page.time.monotonic',side_effect=lambda:clock[0]), \
                patch('ip_info_page.time.sleep',side_effect=lambda duration:clock.__setitem__(0,clock[0]+duration)):
            self.assertEqual(show_ip_info(connection),'new-info')
        methods=[method for method,_ in observed]
        self.assertEqual(methods.count('Target.createTarget'),1)
        self.assertEqual(methods.count('Target.closeTarget'),1)
        self.assertEqual(connection.timeout,1.0)
        self.assertGreater(clock[0],0)
        remaining=[timeout for method,timeout in observed[2:]]
        self.assertTrue(all(0<timeout<=1 for timeout in remaining))
        self.assertEqual(remaining,sorted(remaining,reverse=True))

    def test_confirmation_deadline_refuses_without_repeating_create_and_restores_timeout(self):
        clock=[0.0]
        def change(number,pages):
            if number>=2:pages[-1]['url']=''
        connection=self.connection([{'type':'page','url':IP_INFO_URL,'targetId':'old'}],on_snapshot=change)
        connection.timeout=.1
        with patch('ip_info_page.time.monotonic',side_effect=lambda:clock[0]), \
                patch('ip_info_page.time.sleep',side_effect=lambda duration:clock.__setitem__(0,clock[0]+duration)):
            with self.assertRaises(LocalBrowserError) as failure:show_ip_info(connection)
        self.assertEqual(failure.exception.operation,'Target.getTargets')
        self.assertEqual(failure.exception.cause_type,'TimeoutError')
        self.assertEqual(connection.timeout,.1)
        self.assertEqual(clock[0],.1)
        self.assertEqual(sum(value.args[0]=='Target.createTarget' for value in connection.call.call_args_list),1)
        self.assertFalse(any(value.args[0]=='Target.closeTarget' for value in connection.call.call_args_list))

    def test_initially_absent_new_target_is_confirmed_without_creating_another(self):
        clock=[0.0]
        def change(number,pages):
            if number==2:pages.clear()
            if number==3:pages.append({'type':'page','url':IP_INFO_URL,'targetId':'new-info'})
        connection=self.connection([],on_snapshot=change)
        with patch('ip_info_page.time.monotonic',side_effect=lambda:clock[0]), \
                patch('ip_info_page.time.sleep',side_effect=lambda duration:clock.__setitem__(0,clock[0]+duration)):
            self.assertEqual(show_ip_info(connection),'new-info')
        self.assertEqual(sum(value.args[0]=='Target.createTarget' for value in connection.call.call_args_list),1)

    def test_confirmation_budget_is_finite_capped_and_compatible_with_missing_mock_timeout(self):
        from ip_info_page import _confirmation_budget
        class Connection:pass
        connection=Connection()
        self.assertEqual(_confirmation_budget(connection),5)
        for value,expected in ((2,2),(20,5),(0,5),(-1,5),(True,5),(None,5),('private',5),(float('nan'),5)):
            connection.timeout=value
            self.assertEqual(_confirmation_budget(connection),expected)

    def test_confirmation_exception_restores_the_original_timeout_and_absent_attribute(self):
        class Connection:pass
        for initial in (None,2.0):
            connection=Connection()
            if initial is not None:connection.timeout=initial
            def fail():
                self.assertGreater(connection.timeout,0)
                self.assertAlmostEqual(connection.timeout,.1)
                raise RuntimeError('synthetic')
            with patch('ip_info_page.time.monotonic',return_value=1):
                with self.assertRaises(RuntimeError):
                    from ip_info_page import _within_confirmation
                    _within_confirmation(connection,1.1,fail)
            if initial is None:self.assertFalse(hasattr(connection,'timeout'))
            else:self.assertEqual(connection.timeout,initial)


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
        self.assertEqual(failure.exception.code,'ip_info_failed')
        self.assertEqual(failure.exception.operation,'unknown')
        self.assertEqual(failure.exception.cause_type,'RuntimeError')
        service.controller.close.assert_not_called();self.assertEqual(record['proxy'],before['proxy'])

    def test_ip_page_safe_diagnostics_survive_manager_wrapping_without_closing_window(self):
        service,record=self.service();record['_native']={'synthetic':True};before=copy.deepcopy(record)
        error=LocalBrowserError('synthetic-private-account-or-proxy')
        error.operation='Page.reload';error.cause_type='WebSocketTimeoutException';error.cleanup_failed=True
        with patch('manager_service.require_current_signature'),patch('manager_service.CDP'), \
                patch('ip_info_page.show_ip_info',side_effect=error):
            with self.assertRaises(LocalBrowserError) as failure:service.open('synthetic')
        self.assertEqual(failure.exception.operation,'Page.reload')
        self.assertEqual(failure.exception.cause_type,'WebSocketTimeoutException')
        self.assertIs(failure.exception.cleanup_failed,True)
        self.assertNotIn('synthetic-private',str(failure.exception))
        self.assertEqual(record['_native'],before['_native'])
        service.controller.close.assert_not_called()

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
