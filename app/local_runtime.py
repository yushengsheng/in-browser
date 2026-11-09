"""Migrate/renew a local window without changing its encrypted native payload."""
import copy
import os
from pathlib import Path
import struct
import time
import uuid

from local_state import LocalBrowserError
from local_signer import LocalSigner,MAX_VALIDITY_HOURS
from local_engine import LocalEngineStore
from signature_lifetime import verify_signature
from window_store import fingerprint_unreferenced


class LocalRuntime:
    def __init__(self,service):
        self.service=service;self.root=service.root
        self.signer=LocalSigner(self.root,validity_hours=MAX_VALIDITY_HOURS)
        self.engines=LocalEngineStore()

    def prepare(self,record,*,force=False):
        from browser_core import sha256
        service=self.service;service._closed(record)
        runtime=record['_runtime'];source=Path(runtime['fingerprint_path'])
        if sha256(source)!=runtime['fingerprint_sha256']:
            raise LocalBrowserError('原启动配置已变化，未迁移或重签；资料已保留。')
        local=runtime.get('signature_provider')=='local-v1'
        if local:
            if runtime.get('signature_key_id')!=self.signer.key_id:
                raise LocalBrowserError('本地签名根与窗口不匹配，请保留原密钥和资料。')
            with source.open('rb') as handle:header=handle.read(284)
            if len(header)!=284:raise LocalBrowserError('本地启动配置不完整，未重签。')
            created,expires=struct.unpack('>QQ',header[268:284])
            if not self.signer.verify(source,now_ms=created):
                raise LocalBrowserError('本地启动配置完整性校验失败，未重签或启动。')
            current=time.time_ns()//1_000_000
            executable=self.engines.ensure_current(runtime['core_path'],self.signer.key_id,runtime['core_major'])
            if not force and created<=current and expires-current>30*86400000:
                if Path(runtime['core_path'])!=executable:
                    updated=copy.deepcopy(record)
                    updated['_runtime'].update(core_path=str(executable),core_sha256=sha256(executable))
                    service.store.put(updated);service._sync(updated)
                    return updated
                return record
        else:
            if not verify_signature(source):
                raise LocalBrowserError('原启动配置验签未通过，未迁移；不会将未知配置标记为本地可用。')
            executable=self.engines.ensure(runtime['core_major'],runtime['core_path'],self.signer.public_der)
            executable=self.engines.ensure_current(executable,self.signer.key_id,runtime['core_major'])
        if service.configuration.decode(source)!=record.get('_native'):
            raise LocalBrowserError('窗口配置与加密启动资料不一致，未迁移或重签。')
        binary=self.signer.resign(source)
        folder=self.root/'fingerprints';folder.mkdir(parents=True,exist_ok=True)
        target=folder/(record['id']+'-local-'+uuid.uuid4().hex+'.bin');temporary=target.with_suffix('.tmp')
        saved=False;commit_attempted=False
        try:
            with temporary.open('xb') as output:output.write(binary);output.flush();os.fsync(output.fileno())
            os.replace(temporary,target)
            updated=copy.deepcopy(record)
            updated['_runtime'].update(core_path=str(executable),core_sha256=sha256(executable),fingerprint_path=str(target),
                fingerprint_sha256=sha256(target),signature_provider='local-v1',signature_key_id=self.signer.key_id)
            updated['config_status']='ready'
            commit_attempted=True
            service.store.put(updated);saved=True;service._sync(updated)
            return updated
        finally:
            temporary.unlink(missing_ok=True)
            if not saved and (not commit_attempted or fingerprint_unreferenced(service.store,record['id'],target)):
                target.unlink(missing_ok=True)
