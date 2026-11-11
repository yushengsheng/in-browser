"""Verified profile copies with bounded retries for each filesystem operation."""
import hashlib
import os
from pathlib import Path
import shutil
import stat
import time

from import_progress import emit
from local_state import LocalBrowserError


def _retry(operation):
    for attempt in range(3):
        try:return operation()
        except PermissionError:
            if attempt==2:raise
            time.sleep(.15*(attempt+1))


def _info(path):
    info=_retry(path.lstat)
    if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
        raise LocalBrowserError('资料包含特殊链接，已停止复制。')
    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise LocalBrowserError('资料包含特殊文件，已停止复制。')
    return info


def _identity(info):
    return info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode)


def _state(info):
    # Python's Windows stat/fstat can disagree about legacy ctime after copy2.
    changed=getattr(info,'st_birthtime_ns',info.st_ctime_ns) if os.name=='nt' else info.st_ctime_ns
    mode=stat.S_IMODE(info.st_mode)
    # Windows path stat derives execute bits from the suffix; fstat cannot.
    if os.name=='nt':mode&=~(stat.S_IXUSR|stat.S_IXGRP|stat.S_IXOTH)
    return (_identity(info),info.st_size,info.st_mtime_ns,changed,
            mode,getattr(info,'st_file_attributes',0))


def _parents(path):
    result={}
    for parent in reversed(path.parents):
        try:info=_info(parent)
        except FileNotFoundError:continue
        if not stat.S_ISDIR(info.st_mode):raise LocalBrowserError('资料目录边界无效，已停止复制。')
        result[parent]=_identity(info)
    return result


def _check_parents(parents):
    if any(_identity(_info(path))!=identity for path,identity in parents.items()):
        raise LocalBrowserError('资料目录边界发生变化，已停止复制。')


def _inventory(root,*,progress=False):
    _parents(root)
    result={Path('.'): _info(root)}
    if not stat.S_ISDIR(result[Path('.')].st_mode):
        raise LocalBrowserError('资料目录无效，已停止复制。')
    stack=[Path('.')];count=0
    if progress:emit('inventory',done=0,unit='files')
    while stack:
        relative=stack.pop();folder=root/relative
        if _state(_info(folder))!=_state(result[relative]):
            raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')
        def entries():
            with os.scandir(folder) as items:return sorted(items,key=lambda item:item.name)
        for entry in _retry(entries):
            name=relative/entry.name;info=_info(root/name);result[name]=info
            if stat.S_ISDIR(info.st_mode):stack.append(name)
            else:count+=1
            if progress:emit('inventory',done=count,unit='files')
    if progress:emit('inventory',done=count,total=count,unit='files')
    return result


def _same_inventory(before,after):
    return before.keys()==after.keys() and all(_state(info)==_state(after[name]) for name,info in before.items())


def _member(root,name,inventory,*,stable=True):
    # An unchanged immediate directory identity keeps each access in its recorded
    # directory. Full ancestor/link checks bracket each phase and publication.
    for relative in ((name.parent,name) if name!=Path('.') else (name,)):
        expected=inventory[relative];actual=_info(root/relative)
        if (_state(actual) if stable else _identity(actual))!=(_state(expected) if stable else _identity(expected)):
            raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')


def _hashes(root,inventory,parents,phase=None):
    _check_parents(parents)
    total=sum(info.st_size for info in inventory.values() if stat.S_ISREG(info.st_mode))
    done=0;result={};directory=None
    if phase:emit(phase,done=0,total=total,unit='bytes')
    for name,info in inventory.items():
        if not stat.S_ISREG(info.st_mode):continue
        if name.parent!=directory:
            _member(root,name.parent,inventory);directory=name.parent
        digest=hashlib.sha256()
        with (root/name).open('rb') as handle:
            if _state(os.fstat(handle.fileno()))!=_state(info):
                raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')
            while block:=handle.read(1024*1024):
                digest.update(block);done+=len(block)
                if phase:emit(phase,done=done,total=total,unit='bytes')
            if _state(os.fstat(handle.fileno()))!=_state(info):
                raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')
        result[str(name)]=digest.hexdigest()
    if not _same_inventory(inventory,_inventory(root)):
        raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')
    _check_parents(parents)
    if phase:emit(phase,done=done,total=total,unit='bytes')
    return result


def manifest(folder):
    folder=Path(os.path.abspath(folder))
    return _hashes(folder,_inventory(folder),_parents(folder))


def _directory_metadata(source,target):
    shutil.copystat(source,target,follow_symlinks=False)
    if os.name=='nt':
        import ctypes
        from ctypes import wintypes
        # copystat preserves times/mode but omits Windows hidden/system flags.
        flags=(target.stat().st_file_attributes&~0x6)|(source.stat().st_file_attributes&0x6)
        setter=ctypes.WinDLL('kernel32',use_last_error=True).SetFileAttributesW
        setter.argtypes=(wintypes.LPCWSTR,wintypes.DWORD);setter.restype=wintypes.BOOL
        if not setter(str(target),flags):raise ctypes.WinError(ctypes.get_last_error())


def _cleanup(folder,identity,parents):
    _check_parents(parents)
    if not os.path.lexists(folder):return
    if _identity(_info(folder))!=identity:
        raise LocalBrowserError('复制暂存目录的归属发生变化，已保留目录。')
    def writable(operation,path,error):
        if not isinstance(error,PermissionError):raise error
        os.chmod(path,os.lstat(path).st_mode|stat.S_IWRITE,follow_symlinks=False)
        _retry(lambda:operation(path))
    _retry(lambda:shutil.rmtree(folder,onexc=writable))


def _copy_tree(source,temporary,inventory,total):
    completed=set();done=0;file_failure=None
    destinations={Path('.'): _identity(_info(temporary))}
    children={name:set() for name,info in inventory.items() if stat.S_ISDIR(info.st_mode)}
    for name in inventory:
        if name!=Path('.'):children[name.parent].add(name.name)
    emit('copying',done=0,total=total,unit='bytes')

    def directory(folder,names):
        name=Path(folder).relative_to(source)
        if name not in children or set(names)!=children[name] or _state(_info(Path(folder)))!=_state(inventory[name]):
            raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')
        output=temporary/name
        if os.path.lexists(output):
            current=_info(output)
            if not stat.S_ISDIR(current.st_mode) or destinations.get(name,_identity(current))!=_identity(current):
                raise LocalBrowserError('复制暂存目录类型发生变化，已停止复制。')
            destinations[name]=_identity(current)
        return ()

    def file(original,output):
        nonlocal done,file_failure
        original=Path(original);output=Path(output);name=original.relative_to(source)
        parent=_info(output.parent)
        if not stat.S_ISDIR(parent.st_mode) or destinations.get(name.parent,_identity(parent))!=_identity(parent):
            raise LocalBrowserError('复制暂存目录的归属发生变化，已停止复制。')
        destinations[name.parent]=_identity(parent)
        expected=inventory.get(name)
        if expected is None or not stat.S_ISREG(expected.st_mode) or _state(_info(original))!=_state(expected):
            raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')
        if name in completed:return str(output)
        def copy():
            try:return shutil.copy2(original,output,follow_symlinks=False)
            except PermissionError:
                if os.path.lexists(output):
                    info=_info(output)
                    if not stat.S_ISREG(info.st_mode):raise LocalBrowserError('复制暂存文件类型发生变化，已停止复制。')
                    output.chmod(info.st_mode|stat.S_IWRITE);output.unlink()
                raise
        try:result=_retry(copy)
        except PermissionError as error:
            file_failure=error;raise
        completed.add(name);done+=expected.st_size
        emit('copying',done=done,total=total,unit='bytes')
        return result

    for attempt in range(3):
        try:
            shutil.copytree(source,temporary,copy_function=file,ignore=directory,symlinks=True,dirs_exist_ok=True)
            break
        except (PermissionError,shutil.Error):
            # copytree aggregates directory failures. Rewalk only our own tree;
            # completed files are retained, while each file retry stays bounded.
            if file_failure is not None:raise file_failure
            if attempt==2:raise
            time.sleep(.15*(attempt+1))
    for name,info in reversed(tuple(inventory.items())):
        if stat.S_ISDIR(info.st_mode):
            if _state(_info(source/name))!=_state(info) or not stat.S_ISDIR(_info(temporary/name).st_mode):
                raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')
            _retry(lambda:_directory_metadata(source/name,temporary/name))


def copy_profile(source,target):
    source=Path(os.path.abspath(source));target=Path(os.path.abspath(target))
    if source==target or source in target.parents or target in source.parents:
        raise LocalBrowserError('资料复制的来源和目标目录重叠，已停止复制。')
    source_parents=_parents(source);_parents(target)
    files=_inventory(source,progress=True)
    total=sum(info.st_size for info in files.values() if stat.S_ISREG(info.st_mode))
    _retry(lambda:target.parent.mkdir(parents=True,exist_ok=True))
    target_parents=_parents(target)
    if shutil.disk_usage(target.parent).free<total*1.1+20_000_000:
        raise LocalBrowserError('磁盘空间不足，未复制或修改资料。')
    temporary=target.with_name(target.name+'.copying')
    if os.path.lexists(temporary) or os.path.lexists(target):
        raise LocalBrowserError('复制目标已存在，未覆盖。')
    before=_hashes(source,files,source_parents,'source_hash')
    created=None
    try:
        _check_parents(target_parents)
        _retry(temporary.mkdir);created=_identity(_info(temporary))
        _copy_tree(source,temporary,files,total)
        if before!=_hashes(source,files,source_parents,'source_verify'):
            raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')
        copied=_inventory(temporary)
        if files.keys()!=copied.keys() or any(stat.S_IFMT(info.st_mode)!=stat.S_IFMT(copied[name].st_mode) for name,info in files.items()):
            raise LocalBrowserError('资料复制清单不完整，未将副本标记为完成。')
        verified=_hashes(temporary,copied,target_parents,'copy_verify')
        if before!=verified or not _same_inventory(files,_inventory(source)):
            raise LocalBrowserError('资料在复制时发生变化，未将副本标记为完成。')
        def publish():
            _check_parents(target_parents)
            if os.path.lexists(target):raise LocalBrowserError('复制目标已存在，未覆盖。')
            if _identity(_info(temporary))!=created:
                raise LocalBrowserError('复制暂存目录的归属发生变化，已停止复制。')
            # On Windows rename refuses an existing destination, including empty directories.
            os.rename(temporary,target)
        _retry(publish)
        return verified
    except Exception:
        if created is not None:_cleanup(temporary,created,target_parents)
        raise
