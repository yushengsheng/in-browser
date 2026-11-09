"""Enroll new imported copies before publication, without visiting account sites."""
import copy
from pathlib import Path

from app_paths import APP_ROOT
from browser_core import sha256
from fingerprint_continuity import binding_for,create_baseline,verify_continuity
from local_state import LocalBrowserError
from portable_browser import capture_profile


def prepare_import(service,record,candidate,staged,work):
    root=Path(service.root)
    portable=(root/'portable-mode.bin').is_file()
    continuity=(root/'continuity-mode.bin').is_file()
    if not portable and not continuity:return record
    runtime=record['_runtime']
    if runtime.get('signature_provider')!='local-v1':
        raise LocalBrowserError('新来源未准备为本地独立配置，未提交资料。')
    if portable:
        record['_portable_crypt']=capture_profile(Path(staged))
        record['_portable_app']=str(APP_ROOT)
    if record.get('_source_info'):
        from import_cookies import materialize
        materialize(service,record,staged,signature=Path(work)/'fingerprint.bin',work_parent=Path(work))
    if continuity:
        probe=copy.deepcopy(record)
        signature=Path(work)/'fingerprint.bin'
        probe['_runtime'].update(profile_path=str(staged),fingerprint_path=str(signature),fingerprint_sha256=sha256(signature))
        probe['_continuity']=create_baseline(probe,root)
        verify_continuity(probe,root)
        if probe['_continuity']['binding']!=binding_for(record,root):
            raise LocalBrowserError('新来源环境登记与发布配置不匹配，未提交资料。')
        record['_continuity']=probe['_continuity']
    return record
