"""Synthetic proxy-switch, extension and pre-network gate boundaries."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
from browser_policy import validate_launch_args,verify_running_proxy_args,verify_proxy_extensions
from local_state import LocalBrowserError
from manager_service import ManagerService
from proxy_runtime import ProxyRuntime


def main():
    checks={}
    def check(name,value):
        checks[name]=bool(value)
        if not value:raise AssertionError(name)
    forbidden=['--NO-PROXY-SERVER','--PROXY-SERVER=direct://','--PROXY-BYPASS-LIST=*','--FORCE-WEBRTC-IP-HANDLING-POLICY=default','--disable-quic','--DISABLE-QUIC','--enable-quic','--host-resolver-rules=MAP * 127.0.0.1','--proxy-server =direct://','--REMOTE-DEBUGGING-PORT=12345']
    for index,arg in enumerate(forbidden):
        try:validate_launch_args([arg],proxy_active=True)
        except LocalBrowserError:pass
        else:raise AssertionError('Unsafe argument accepted')
    check('mixed_case_control_and_proxy_overrides_rejected',True)
    expected=['--proxy-server=http://127.0.0.1:12345','--proxy-bypass-list=<-loopback>','--force-webrtc-ip-handling-policy=disable_non_proxied_udp','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1','--disable-quic']
    check('complete_running_route_accepted',verify_running_proxy_args(expected,12345))
    check('later_duplicate_direct_override_rejected',not verify_running_proxy_args(expected+['--NO-PROXY-SERVER'],12345))
    check('duplicate_quic_rejected',not verify_running_proxy_args(expected+['--DISABLE-QUIC'],12345))
    check('old_route_without_dns_guard_rejected',not verify_running_proxy_args([x for x in expected if not x.startswith('--host-resolver')],12345))
    with tempfile.TemporaryDirectory(prefix='conservative-policy-') as folder:
        root=Path(folder);(root/'Default').mkdir()
        for name in ['Preferences','Secure Preferences']:
            file=root/'Default'/name
            file.write_text(json.dumps({'extensions':{'settings':{'fixture':{'state':1,'manifest':{'permissions':['proxy']}}}}}))
            try:verify_proxy_extensions(root)
            except LocalBrowserError:pass
            else:raise AssertionError('Proxy extension accepted')
            file.write_text('{}')
        check('both_extension_preference_files_checked',True)
        ext=root/'extension';ext.mkdir();(ext/'manifest.json').write_text('{"permissions":["proxy"]}')
        try:verify_proxy_extensions(root,str(ext))
        except LocalBrowserError:pass
        else:raise AssertionError('Managed proxy extension accepted')
        check('actual_enabled_extension_manifest_checked',True)
        (ext/'manifest.json').write_text('{"permissions":["storage"]}');verify_proxy_extensions(root,str(ext))
        check('ordinary_extension_preserved',True)
        record={'id':'fixture','archived':False,'proxy':{'type':'noproxy'},'_runtime':{'profile_path':str(root),'core_path':str(root/'BitBrowser.exe'),'fingerprint_path':str(root/'fixture.bin')},'last_opened_at':None}
        service=ManagerService.__new__(ManagerService);service.root=root;service.operations=threading.RLock();service.configuration=SimpleNamespace(independent=False)
        service.store=SimpleNamespace(get=lambda _:copy.deepcopy(record),put=Mock(),public=lambda p,status:p)
        service._status=lambda _:'closed';service.controller=SimpleNamespace(open=Mock());service.proxy_runtime=SimpleNamespace(ensure=Mock())
        (root/'continuity-mode.bin').write_bytes(b'fixture')
        with patch('fingerprint_continuity.verify_continuity',side_effect=LocalBrowserError('fixture mismatch')) as gate,patch('portable_browser.prepare_profile') as unwrap:
            try:service.open('fixture')
            except LocalBrowserError:pass
            else:raise AssertionError('Environment difference accepted')
            check('drift_blocks_before_proxy_browser_or_crypt_write',gate.call_count==1 and not service.controller.open.called and not service.proxy_runtime.ensure.called and not unwrap.called)
        service._status=lambda _:'open';service._sync=Mock()
        with patch('fingerprint_continuity.verify_continuity',side_effect=AssertionError('Existing window should only activate')) as gate:
            service.open('fixture');check('already_open_does_not_launch_another_probe',gate.call_count==0 and service.controller.open.call_count==1)
        record['proxy']={'type':'http','host':'127.0.0.1','port':12345,'username':'','password':'','enable_socks5_udp':False}
        service.controller.open.reset_mock();service.proxy_runtime=ProxyRuntime(root)
        fake=SimpleNamespace(cmdline=lambda:[],exe=lambda:str(root/'BitBrowser.exe'))
        with patch('proxy_runtime._profile_browsers',return_value=[fake]):
            try:service.open('fixture')
            except LocalBrowserError:pass
            else:raise AssertionError('Unproven old browser route activated')
        check('existing_proxy_window_requires_route_evidence',not service.controller.open.called)
    print(json.dumps({'success':all(checks.values()),'checks':checks}))


if __name__=='__main__':main()
