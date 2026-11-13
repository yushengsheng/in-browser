"""Enroll new imported copies before publication, without visiting account sites."""
import copy
from pathlib import Path

from app_paths import APP_ROOT
from browser_core import sha256
from fingerprint_continuity import binding_for,create_baseline,verify_continuity
from local_state import LocalBrowserError
from portable_browser import capture_profile
from import_progress import emit


def prepare_import(service,record,candidate,staged,work):
    root=Path(service.root)
    portable=(root/'portable-mode.bin').is_file()
    continuity=(root/'continuity-mode.bin').is_file()
    if not portable and not continuity:return record
    runtime=record['_runtime']
    if runtime.get('signature_provider')!='local-v1':
        raise LocalBrowserError('新来源未准备为本地独立配置，未提交资料。')
    if portable:
        emit('portable_keys')
        record['_portable_crypt']=capture_profile(Path(staged))
        record['_portable_app']=str(APP_ROOT)
    if record.get('_source_info'):
        from source_sessions import collect_source_restore
        restore=collect_source_restore(staged,runtime,record.get('urls') or (),source_record=record)
        if restore:record['_source_session_restore']=restore
        emit('cookies')
        from import_cookies import materialize
        materialize(service,record,staged,signature=Path(work)/'fingerprint.bin',work_parent=Path(work))
    if continuity:
        probe=copy.deepcopy(record)
        signature=Path(work)/'fingerprint.bin'
        probe['_runtime'].update(profile_path=str(staged),fingerprint_path=str(signature),fingerprint_sha256=sha256(signature))
        emit('baseline_first',done=0,total=3,unit='steps')
        probe['_continuity']=create_baseline(probe,root,progress=lambda stage:emit(
            'baseline_first' if stage=='first' else 'baseline_second',
            done=0 if stage=='first' else 1,total=3,unit='steps'))
        emit('baseline_verify',done=2,total=3,unit='steps')
        verify_continuity(probe,root)
        if probe['_continuity']['binding']!=binding_for(record,root):
            raise LocalBrowserError('新来源环境登记与发布配置不匹配，未提交资料。')
        record['_continuity']=probe['_continuity']
        emit('baseline_verify',done=3,total=3,unit='steps')
    return record
