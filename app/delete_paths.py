"""Literal path checks for the narrowly owned permanent-deletion targets."""
import os
from pathlib import Path
import shutil
import stat

from local_state import LocalBrowserError


class DeleteError(LocalBrowserError):
    pass


def absolute(path):
    value=Path(path)
    if not value.is_absolute() or '..' in value.parts:
        raise DeleteError('删除路径无法确认，已停止清理；请保留资料并重试。')
    return Path(os.path.abspath(value))


def checked(path,root,*,tree=False):
    """Check the literal parent chain before resolving or walking a target."""
    root=absolute(root);path=absolute(path)
    try:
        if os.path.commonpath((os.path.normcase(root),os.path.normcase(path)))!=os.path.normcase(str(root)):
            raise ValueError()
    except ValueError:
        raise DeleteError('删除路径超出受管资料目录，已停止清理。') from None
    for item in reversed((path,*path.parents)):
        try:info=item.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise DeleteError('删除路径含链接或重解析点，已停止清理；未访问链接目标。')
        if item!=path and not stat.S_ISDIR(info.st_mode):
            raise DeleteError('删除路径的父目录无效，已停止清理。')
    if tree and path.is_dir():
        stack=[path]
        while stack:
            folder=stack.pop()
            with os.scandir(folder) as entries:
                for entry in entries:
                    info=entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
                        raise DeleteError('受管资料含链接或重解析点，已停止清理；未访问链接目标。')
                    if stat.S_ISDIR(info.st_mode):stack.append(Path(entry.path))
                    elif not stat.S_ISREG(info.st_mode):
                        raise DeleteError('受管资料含未知特殊文件，已停止清理。')
    return path


def relative(path,root):
    return checked(path,root).relative_to(absolute(root)).as_posix()


def from_relative(value,root):
    if (not isinstance(value,str) or not value or '\\' in value or ':' in value or
            value.startswith('/') or any(part in ('','..','.') for part in value.split('/'))):
        raise DeleteError('删除恢复计划的路径无效，已停止清理。')
    return checked(absolute(root).joinpath(*value.split('/')),root)


def remove(path,root):
    path=checked(path,root,tree=True)
    if path==absolute(root):raise DeleteError('不能删除共享资料根目录。')
    try:info=path.lstat()
    except FileNotFoundError:return
    if stat.S_ISDIR(info.st_mode):
        def writable(method,name,_error):
            selected=checked(Path(name),root)
            selected.chmod(selected.stat().st_mode|stat.S_IWRITE)
            method(name)
        shutil.rmtree(path,onexc=writable)
    elif stat.S_ISREG(info.st_mode):
        try:path.unlink()
        except PermissionError:
            path.chmod(info.st_mode|stat.S_IWRITE);path.unlink()
    else:raise DeleteError('删除目标不是普通文件或目录，已停止清理。')
