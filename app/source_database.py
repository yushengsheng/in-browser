"""Stable byte snapshots of the source client's SQLite database; no source writes."""
from contextlib import contextmanager
import hashlib
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
import time

from local_state import LocalBrowserError

MAX_BYTES=512*1024*1024


def stamp(path):
    output=[]
    for suffix in ('','-wal','-shm','-journal'):
        item=Path(str(path)+suffix)
        try:value=item.lstat()
        except FileNotFoundError:output.append(None);continue
        if not stat.S_ISREG(value.st_mode) or getattr(value,'st_file_attributes',0)&0x400:
            raise LocalBrowserError('来源数据库含特殊链接，未读取或改动资料。')
        output.append((value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns))
    return tuple(output)


def _digest(path,deadline):
    value=hashlib.sha256();size=0
    with path.open('rb') as stream:
        while block:=stream.read(1024*1024):
            size+=len(block)
            if time.monotonic()>=deadline or size>MAX_BYTES:raise ValueError()
            value.update(block)
    return value.digest()


@contextmanager
def snapshot(database):
    """SQLite can create sidecars in mode=ro; only connect our temporary copy."""
    database=Path(database);deadline=time.monotonic()+20
    before=stamp(database)
    if before[0] is None:raise LocalBrowserError('本机来源数据库不存在，请保留原窗口资料。')
    if sum(item[2] for item in before if item)>MAX_BYTES or (before[3] and before[3][2]):
        raise LocalBrowserError('本机来源数据库尚未稳定，请稍后重新预览。')
    with tempfile.TemporaryDirectory(prefix='local-source-db-') as directory:
        copied=Path(directory)/'source.sqlite'
        hashes={}
        try:
            for suffix,index in (('',0),('-wal',1)):
                if before[index] is None:continue
                original=Path(str(database)+suffix);target=Path(str(copied)+suffix)
                hashes[suffix]=_digest(original,deadline)
                shutil.copyfile(original,target)
                if _digest(target,deadline)!=hashes[suffix]:raise ValueError()
            if stamp(database)!=before:raise ValueError()
            con=sqlite3.connect(copied.as_uri()+'?mode=ro',uri=True,timeout=3)
            try:
                con.execute('PRAGMA query_only=ON')
                con.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
                yield con
            finally:con.close()
            if stamp(database)!=before or any(_digest(Path(str(database)+suffix),deadline)!=value for suffix,value in hashes.items()):
                raise ValueError()
        except (OSError,sqlite3.Error,ValueError):
            raise LocalBrowserError('来源数据库正在变化或无法安全读取，请稍后重试；原资料未改动。') from None
