"""Read the native #BT@ envelope lifetime without changing or renewing it."""
from datetime import datetime,timezone
from functools import lru_cache
import hashlib
from pathlib import Path
import struct
import time

from local_state import LocalBrowserError

_PUBLIC_KEY_SHA256='a06b13013ce57e00dcc222153c0bad1bde7b6cac984e59f4e7bf86495e3e86f8'


@lru_cache(maxsize=1)
def _verification_key():
    from cryptography.hazmat.primitives import serialization
    data=(Path(__file__).resolve().parent/'resources/signature-verification-public.der').read_bytes()
    if hashlib.sha256(data).hexdigest()!=_PUBLIC_KEY_SHA256:raise ValueError('Unexpected verification key')
    return serialization.load_der_public_key(data)


def verify_signature(path):
    """Match native VerifyUpdate(SHA256(ciphertext)), VerifyUpdate(times16)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        with Path(path).open('rb') as handle:
            header=handle.read(12)
            if len(header)!=12 or header[:8]!=b'#BT@'+bytes(4):return False
            length=struct.unpack('>I',header[8:])[0]
            if not 64<=length<=4096:return False
            signature=handle.read(length);times=handle.read(16)
            if len(signature)!=length or len(times)!=16:return False
            digest=hashlib.sha256();size=0
            while block:=handle.read(1024*1024):digest.update(block);size+=len(block)
            if size<32 or size%16:return False
        _verification_key().verify(signature,digest.digest()+times,padding.PKCS1v15(),hashes.SHA256())
        return True
    except Exception:return False


def signature_lifetime(path, *, now_ms=None):
    try:
        with Path(path).open('rb') as handle:
            header=handle.read(12)
            if len(header)!=12 or header[:8]!=b'#BT@'+bytes(4):return {'status':'unknown'}
            size=struct.unpack('>I',header[8:])[0]
            if size<64 or size>4096:return {'status':'unknown'}
            handle.seek(size,1)
            times=handle.read(16)
            if len(times)!=16:return {'status':'unknown'}
            created,expires=struct.unpack('>QQ',times)
            payload_start=handle.tell();handle.seek(0,2);payload_size=handle.tell()-payload_start
            if payload_size<32 or payload_size%16 or expires<created:return {'status':'unknown'}
            created_at=datetime.fromtimestamp(created/1000,timezone.utc).isoformat(timespec='milliseconds')
            expires_at=datetime.fromtimestamp(expires/1000,timezone.utc).isoformat(timespec='milliseconds')
        expired=time.time_ns()>expires*1000000 if now_ms is None else now_ms>expires
        return {'status':'expired' if expired else 'active','created_at':created_at,'expires_at':expires_at,
                'validity_hours':(expires-created)/3600000}
    except FileNotFoundError:return {'status':'missing'}
    except (OSError,ValueError,OverflowError,struct.error):return {'status':'unknown'}


def _require_active(info):
    if info['status']=='expired':
        raise LocalBrowserError('原厂启动签名已到期，未启动浏览器，本地资料未改变。更换代理不会延长签名期限；重新打开需要原厂有效签名。')
    if info['status']!='active':
        raise LocalBrowserError('无法确认原厂启动签名的有效期，未启动浏览器。请保留现有资料和配置。')


def runtime_signature_options(runtime, root):
    if runtime.get('signature_provider') == 'local-v1':
        return {'local_root':root,'key_id':runtime.get('signature_key_id'),'core_path':runtime.get('core_path')}
    return {}


def require_current_signature(path, *, core_major=None, local_root=None, key_id=None, core_path=None):
    from core_specs import CORE_SPECS
    if str(core_major) not in CORE_SPECS:
        raise LocalBrowserError('该内核版本的签名规则尚未验证，未启动浏览器。')
    if local_root is not None:
        from local_signer import LocalSigner
        from local_engine import LocalEngineStore
        signer=LocalSigner(local_root,load_private=False)
        if signer.key_id!=key_id or not signer.verify(path):
            raise LocalBrowserError('本地启动签名校验未通过，未启动浏览器；资料和原配置已保留。')
        LocalEngineStore().validate(core_path,key_id,core_major)
        return signature_lifetime(path)
    _require_active(signature_lifetime(path))
    if not verify_signature(path):
        raise LocalBrowserError('原厂启动签名校验未通过，未启动浏览器，避免以缺失指纹的普通浏览器继续使用；本地资料未改变。')
    info=signature_lifetime(path)
    _require_active(info)
    return info
