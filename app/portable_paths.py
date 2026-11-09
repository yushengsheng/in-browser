"""Folder-relative managed paths; native payloads rebase only on relocation."""
import copy
import json
import os
from pathlib import Path,PurePosixPath
import uuid

from local_state import LocalBrowserError

_RUNTIME_PATHS=('profile_path','fingerprint_path','core_path','managed_extension')


def enabled(root):return (Path(root)/'portable-mode.bin').is_file()


def encode_path(value,root):
    if not isinstance(value,str) or not value:return value
    path=Path(value)
    if not path.is_absolute():return value
    for prefix,base in [('@data/',Path(root).resolve()),('@app/',Path(__file__).resolve().parent)]:
        try:relative=path.resolve().relative_to(base)
        except (ValueError,OSError):continue
        return prefix+relative.as_posix()
    return value


def decode_path(value,root):
    if not isinstance(value,str):return value
    for prefix,base in [('@data/',Path(root).resolve()),('@app/',Path(__file__).resolve().parent)]:
        if value.startswith(prefix):
            relative=PurePosixPath(value[len(prefix):])
            if relative.is_absolute() or any(part in ('..','') or ':' in part or '\\' in part for part in relative.parts):
                raise LocalBrowserError('便携资料路径无效，未访问文件夹外资料。')
            result=base.joinpath(*relative.parts).resolve()
            if not result.is_relative_to(base):raise LocalBrowserError('便携资料路径越界，已停止。')
            return str(result)
    return value


def encode_record(value,root):
    if not enabled(root) or not isinstance(value,dict):return value
    result=copy.deepcopy(value)
    if isinstance(result.get('_runtime'),dict):
        for field in _RUNTIME_PATHS:
            if field in result['_runtime']:result['_runtime'][field]=encode_path(result['_runtime'][field],root)
    else:
        for field in ('download_dir','browser_path'):
            if field in result:result[field]=encode_path(result[field],root)
    return result


def decode_record(value,root):
    if not isinstance(value,dict):return value
    if isinstance(value.get('_runtime'),dict):
        for field in _RUNTIME_PATHS:
            if field in value['_runtime']:value['_runtime'][field]=decode_path(value['_runtime'][field],root)
    else:
        for field in ('download_dir','browser_path'):
            if field in value:value[field]=decode_path(value[field],root)
    return value


def encode_archive(value,root):
    result=copy.deepcopy(value)
    result['engines']={major:encode_path(path,root) for major,path in result.get('engines',{}).items()}
    result['_portable_app']=str(Path(__file__).resolve().parent)
    return result


def decode_archive(value,root):
    value['engines']={major:decode_path(path,root) for major,path in value.get('engines',{}).items()}
    return value


def _rebase(value,previous,current):
    if not isinstance(value,str) or not value:return value
    try:relative=Path(value).relative_to(Path(previous))
    except ValueError:return value
    result=(Path(current)/relative).resolve()
    if not result.is_relative_to(Path(current).resolve()):raise LocalBrowserError('便携资源路径越界，未修改。')
    return str(result)


def relocate(service):
    """Re-sign only relocated filesystem references, preserve all other native fields."""
    from browser_core import sha256
    from local_signer import LocalSigner,MAX_VALIDITY_HOURS
    if not enabled(service.root):return
    from profile_delete import get_pending_ids
    pending=get_pending_ids(service.root)
    current=str(Path(__file__).resolve().parent)
    signer=None
    for record in service.store.all():
        if record['id'] in pending:continue
        previous=record.get('_portable_app')
        if not previous or os.path.normcase(previous)==os.path.normcase(current):continue
        service._closed(record)
        runtime=record['_runtime'];config=Path(runtime['fingerprint_path'])
        if sha256(config)!=runtime['fingerprint_sha256'] or service.configuration.decode(config)!=record['_native']:
            raise LocalBrowserError('便携启动配置与资料不一致，未重新定位或启动。')
        if signer is None:signer=LocalSigner(service.root,validity_hours=MAX_VALIDITY_HOURS)
        native=copy.deepcopy(record['_native'])
        font=native.get('FontConfig')
        if isinstance(font,dict) and isinstance(font.get('BasePath'),str):font['BasePath']=_rebase(font['BasePath'],previous,current)
        if native!=record['_native']:
            target=config.with_name(config.stem+'-moved-'+uuid.uuid4().hex+'.bin');temporary=target.with_suffix('.tmp')
            try:
                with temporary.open('xb') as output:output.write(signer.sign_native(native,service.configuration._key,core_major=runtime.get('core_major')));output.flush();os.fsync(output.fileno())
                os.replace(temporary,target)
            finally:temporary.unlink(missing_ok=True)
            runtime.update(fingerprint_path=str(target),fingerprint_sha256=sha256(target));record['_native']=native
        prefs=Path(runtime['profile_path'])/'Default/Preferences'
        if prefs.is_file():
            data=json.loads(prefs.read_text(encoding='utf-8-sig'));changed=False
            for extension in (data.get('extensions',{}).get('settings',{}) or {}).values():
                if isinstance(extension,dict) and isinstance(extension.get('path'),str):
                    updated=_rebase(extension['path'],previous,current)
                    if updated!=extension['path']:extension['path']=updated;changed=True
            download=data.get('download')
            if isinstance(download,dict) and isinstance(download.get('default_directory'),str):
                updated=_rebase(download['default_directory'],previous,current)
                if updated!=download['default_directory']:download['default_directory']=updated;changed=True
            if changed:
                temporary=prefs.with_suffix('.portable-tmp')
                with temporary.open('w',encoding='utf-8') as output:json.dump(data,output,ensure_ascii=False);output.flush();os.fsync(output.fileno())
                os.replace(temporary,prefs)
        record['_portable_app']=current;service.store.put(record)
