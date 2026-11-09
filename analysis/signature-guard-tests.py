"""Synthetic RSA/lifetime boundaries and pre-launch failure without real profiles."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import Mock,patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import signature_lifetime as lifetime
from browser_core import BrowserController,LocalBrowserError,sha256
from manager_service import ManagerService
from window_store import WindowStore


def main():
    report={'success':False,'checks':{}}
    def check(name,value):
        report['checks'][name]=bool(value)
        if not value:raise AssertionError(name)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=1800000000000;cipher=b'x'*48
    def envelope(created=now-1000,expires=now+1000,payload=cipher):
        times=struct.pack('>QQ',created,expires);signature=key.sign(hashlib.sha256(payload).digest()+times,padding.PKCS1v15(),hashes.SHA256())
        return b'#BT@'+bytes(4)+struct.pack('>I',len(signature))+signature+times+payload
    try:
      with tempfile.TemporaryDirectory(prefix='local-signature-guard-') as directory:
        root=Path(directory);file=root/'signature.bin';file.write_bytes(envelope())
        check('active_before_expiry',lifetime.signature_lifetime(file,now_ms=now)['status']=='active')
        check('exact_millisecond_boundary_matches_native',lifetime.signature_lifetime(file,now_ms=now+1000)['status']=='active')
        check('strictly_after_boundary_expired',lifetime.signature_lifetime(file,now_ms=now+1000.001)['status']=='expired')
        with patch.object(lifetime.time,'time_ns',return_value=(now+1000)*1000000+1):check('default_clock_does_not_truncate_last_millisecond',lifetime.signature_lifetime(file)['status']=='expired')
        with patch.object(lifetime,'_verification_key',return_value=key.public_key()):
            check('valid_rsa_message_accepted',lifetime.verify_signature(file))
            digest=sha256(file)
            with patch.object(lifetime.time,'time_ns',return_value=now*1000000):check('current_signed_configuration_allowed',lifetime.require_current_signature(file,core_major='148')['status']=='active')
            try:lifetime.require_current_signature(file,core_major='149')
            except LocalBrowserError:check('unverified_kernel_version_rejected',True)
            else:check('unverified_kernel_version_rejected',False)
            check('verification_never_rewrites_file',sha256(file)==digest)
            real_verify=lifetime.verify_signature;clock={'ns':now*1000000}
            def verify_then_expire(path):
                valid=real_verify(path);clock['ns']=(now+1000)*1000000+1;return valid
            with patch.object(lifetime.time,'time_ns',side_effect=lambda:clock['ns']),patch.object(lifetime,'verify_signature',side_effect=verify_then_expire):
                try:lifetime.require_current_signature(file,core_major='148')
                except LocalBrowserError:check('expiry_during_rsa_verification_rejected',True)
                else:check('expiry_during_rsa_verification_rejected',False)
            for label,offset in [('rsa',12),('created',12+256+7),('expiry',12+256+15),('ciphertext',12+256+16)]:
                modified=bytearray(envelope());modified[offset]^=1;file.write_bytes(modified)
                check(label+'_tamper_rejected',not lifetime.verify_signature(file))
            file.write_bytes(envelope(expires=now-1,created=now-1000))
            with patch.object(lifetime.time,'time_ns',return_value=now*1000000):
                try:lifetime.require_current_signature(file,core_major='148')
                except LocalBrowserError:check('expired_signed_configuration_rejected',True)
                else:check('expired_signed_configuration_rejected',False)
            for label,data in [('wrong_magic',b'bad'),('oversized_length',b'#BT@'+bytes(4)+struct.pack('>I',999999)),('truncated_times',envelope()[:12+256+8]),('unaligned_cipher',envelope()[:-1]),('created_after_expiry',envelope(created=now+2000,expires=now+1000)),('datetime_overflow',envelope(created=1,expires=2**64-1))]:
                file.write_bytes(data);check(label+'_unknown',lifetime.signature_lifetime(file,now_ms=now)['status']=='unknown')
            check('missing_file_status',lifetime.signature_lifetime(root/'missing.bin')['status']=='missing')
            file.write_bytes(envelope(created=1,expires=2));before=file.read_bytes()
            profile=root/'profile';profile.mkdir();(profile/'Local State').write_text('{}')
            executable=root/'test.exe';executable.write_bytes(b'fixture')
            runtime={'alias':'fixture','core_major':'148','profile_path':str(profile),'core_path':str(executable),'core_sha256':sha256(executable),'fingerprint_path':str(file),'fingerprint_sha256':sha256(file)}
            controller=BrowserController(root,settings={'windows':[runtime],'persistent':False})
            with patch.object(controller,'_ensure_record',return_value=False),patch('browser_core._profile_browsers',return_value=[]),patch.object(controller,'_core_valid',return_value=True),patch('browser_core.subprocess.Popen') as launch:
                try:controller.open('fixture')
                except LocalBrowserError:pass
                check('controller_expiry_prevents_process_creation',launch.call_count==0)
            file.write_bytes(envelope());runtime['fingerprint_sha256']=sha256(file);clock={'ns':now*1000000}
            def delayed_gate():clock['ns']=(now+1000)*1000000+1
            with patch.object(controller,'_ensure_record',return_value=False),patch('browser_core._profile_browsers',return_value=[]),patch.object(controller,'_core_valid',return_value=True),patch('browser_core.subprocess.Popen') as launch,patch.object(lifetime.time,'time_ns',side_effect=lambda:clock['ns']):
                try:controller.open('fixture',before_launch=delayed_gate)
                except LocalBrowserError:pass
                check('proxy_delay_crossing_expiry_prevents_process_creation',launch.call_count==0)
            file.write_bytes(before);runtime['fingerprint_sha256']=sha256(file)
            record={'id':'fixture','fingerprint':{'extendOptions':{'private':'not-public'}},'proxy':{'type':'noproxy'},'_runtime':runtime,'config_status':'ready','archived':False}
            public=WindowStore.public(record)
            check('public_reports_expired_configuration',public['config_status']=='expired' and public['signature_status']=='expired')
            check('public_excludes_file_path_and_private_fingerprint',not any(k.startswith('_') for k in public) and 'extendOptions' not in public['fingerprint'])
            service=ManagerService.__new__(ManagerService);service.operations=threading.RLock();service.store=SimpleNamespace(get=lambda _:copy.deepcopy(record),put=Mock(),public=WindowStore.public)
            service.root=root;service.configuration=SimpleNamespace(independent=False)
            service._status=lambda _:'closed';service._runtime=Mock(side_effect=AssertionError('No runtime work expected'));service._preferences=Mock(side_effect=AssertionError('No profile changes expected'));service.proxy_runtime=SimpleNamespace(ensure=Mock(side_effect=AssertionError('No proxy expected')))
            try:service.open('fixture')
            except LocalBrowserError:pass
            check('manager_expiry_precedes_runtime_preferences_and_proxy',service._runtime.call_count==0 and service._preferences.call_count==0 and service.proxy_runtime.ensure.call_count==0)
            check('failed_launch_preserves_signature',file.read_bytes()==before)
            service._status=lambda _:'open';service.controller=SimpleNamespace(open=Mock());service._sync=Mock()
            with patch('manager_service.require_current_signature',side_effect=AssertionError('Already open should only activate')):
                returned=service.open('fixture')
            check('already_open_window_is_not_forcibly_closed_after_expiry',returned['is_running'] and service.controller.open.call_count==1)
      report['success']=all(report['checks'].values())
    except Exception as exc:
        report['error_type']=type(exc).__name__
        if isinstance(exc,AssertionError):report['failed_check']=str(exc)
    Path(__file__).with_name('signature-guard-tests-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
