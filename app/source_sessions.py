"""Read a vendor tab snapshot once while importing an isolated profile copy."""
import hashlib
import json
import os
from pathlib import Path
import stat
import re
from urllib.parse import unquote,urlsplit

from local_state import LocalBrowserError
from session_recovery import has_saved_session

MAX_TAB_BYTES = 4 * 1024 * 1024
MAX_TABS = 1000
MAX_NODES = 4096
MAX_DEPTH = 16
MAX_URL_LENGTH = 10000
SAFE_CHROME_PAGES = {'newtab', 'history', 'downloads', 'bookmarks', 'settings', 'extensions', 'version', 'password-manager'}
TAB_GROUP_CORE_SHA256 = '591c5de91f4dd55c680c5e394e93ed3e3b48f73960c820a4d14e61d773653691'


def _reject():
    raise LocalBrowserError('来源标签恢复资料格式、网址或路径无法安全核实，未提交副本；原资料已保留。')


def _plain(path):
    for current in (path, *path.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            _reject()


def _url(value):
    if (not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH
            or '\\' in value or any(ord(char) <= 32 or ord(char) == 127 for char in value)):
        _reject()
    try:
        value.encode('utf-8')
        parsed = urlsplit(value)
        if parsed.scheme in ('http', 'https'):
            if not parsed.hostname or parsed.port is not None and not 1 <= parsed.port <= 65535:
                _reject()
        elif parsed.scheme == 'chrome' and parsed.netloc in SAFE_CHROME_PAGES:
            pass
        elif value not in ('about:blank', 'about:newtab'):
            _reject()
    except (ValueError, UnicodeError):
        _reject()
    return value


def _unique(values):
    if not isinstance(values, (tuple, list)) or len(values) > MAX_TABS:
        _reject()
    return list(dict.fromkeys(_url(value) for value in values))


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def pending_source_tabs(record):
    """Validate the private one-shot request without consulting live sources."""
    marker=record.get('_source_session_restore')
    if marker is None:return None
    if not isinstance(marker,dict) or type(marker.get('format')) is not int or marker.get('format')!=1:
        _reject()
    if marker.get('pending') is not True:return None
    values=_unique(marker.get('urls'))
    if not values:_reject()
    return values


def pending_source_restore(record):
    values=pending_source_tabs(record)
    if values is None:return None
    marker=record['_source_session_restore']
    mode=marker.get('mode','arguments')
    if mode not in ('arguments','tab-group-store'):_reject()
    if mode=='tab-group-store' and not re.fullmatch('[0-9a-f]{64}',str(marker.get('snapshot_sha256',''))):
        _reject()
    return {**marker,'mode':mode,'urls':values}


def native_tab_groups_supported(runtime):
    from core_specs import CORE_SPECS
    # LocalEngineStore validates the complete deployed tree against this exact
    # stock digest; a major version alone is not evidence for the native switch.
    return (runtime.get('signature_provider')=='local-v1' and str(runtime.get('core_major'))=='148'
            and CORE_SPECS.get('148',{}).get('sha256')==TAB_GROUP_CORE_SHA256)


def source_startup_urls(record):
    """Mirror the vendor's ordinary URL selection; dynamic dashboards are unknown."""
    full=record.get('_source_info') or {};detail=record.get('_source_detail') or {}
    if not isinstance(full,dict) or not isinstance(detail,dict):_reject()
    info={**full,**detail}
    if info.get('rpaRun') or info.get('robotUrls'):
        return None
    if info.get('ignoreDefaultUrls'):
        return _unique([info['newPageUrl']] if info.get('newPageUrl') else [])
    raw=info.get('url',record.get('urls') or [])
    if isinstance(raw,str):
        if len(raw)>MAX_TAB_BYTES:_reject()
        values=[]
        for value in raw.split(','):
            try:
                if not re.search(r'%(?![0-9a-fA-F]{2})',value):value=unquote(value,errors='strict')
            except UnicodeError:pass
            values.append(value)
    elif isinstance(raw,list):values=list(raw)
    else:_reject()
    if len(values)>MAX_TABS or any(not isinstance(value,str) for value in values):_reject()
    values=list(dict.fromkeys(values))
    values=[value for value in values if value.endswith('/') or value+'/' not in values]
    platform=info.get('platform',record.get('platform') or '')
    if not isinstance(platform,str):_reject()
    if platform.endswith('/'):platform=platform[:-1]
    if platform and all(platform not in value for value in values):values.insert(0,platform)
    return _unique([value for value in values if value])


def _normalized_urls(urls):
    return {url[:-1] if url.endswith('/') else url for url in urls}


def _read_snapshot(profile):
    profile = Path(os.path.abspath(profile))
    _plain(profile)
    if not profile.is_dir():
        _reject()
    path = profile / 'Default/~TabGroups'
    _plain(path)
    if not path.resolve().is_relative_to(profile.resolve()):
        _reject()
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_TAB_BYTES:
        _reject()
    try:
        def stamp(value):
            return value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns
        with path.open('rb') as stream:
            opened=os.fstat(stream.fileno())
            if stamp(opened)[:4]!=stamp(info)[:4]:_reject()
            raw = stream.read(MAX_TAB_BYTES + 1)
            if stamp(os.fstat(stream.fileno()))!=stamp(opened):_reject()
        _plain(path)
        after = path.lstat()
        if (len(raw) > MAX_TAB_BYTES or
                stamp(info)!=stamp(after)):
            _reject()
        data = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_object)
    except (OSError, ValueError, UnicodeError, RecursionError):
        _reject()
    if (not isinstance(data, dict) or not isinstance(data.get('roots'), list)
            or type(data.get('version')) is not int or data['version'] < 1):
        _reject()
    if len(data['roots']) > MAX_NODES:
        _reject()
    return data,hashlib.sha256(raw).hexdigest()


def _snapshot_urls(data,*,native=False):
    if native and data['version']!=1:_reject()
    urls = []
    pending = [(node, 1) for node in reversed(data['roots'])]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH or not isinstance(node, dict):
            _reject()
        if node.get('type') == 'url':
            if node.get('children'):
                _reject()
            urls.append(_url(node.get('url')))
            if len(urls) > MAX_TABS:
                _reject()
        elif node.get('type') == 'folder' and isinstance(node.get('children'), list):
            if native and depth!=1:_reject()
            if len(pending) + len(node['children']) + count > MAX_NODES:
                _reject()
            pending.extend((child, depth + 1) for child in reversed(node['children']))
        else:
            _reject()
    return urls


def collect_source_tabs(profile, fallback_urls=()):
    """Legacy URL fallback; prefer the native saved session when available."""
    if has_saved_session(profile):return []
    snapshot=_read_snapshot(profile)
    urls=_snapshot_urls(snapshot[0]) if snapshot else []
    return list(dict.fromkeys(urls)) if urls else _unique(fallback_urls)


def collect_source_restore(profile,runtime,fallback_urls=(),*,startup_urls=(),source_record=None):
    """Choose a one-shot import plan without changing the copied snapshot."""
    if has_saved_session(profile):return None
    snapshot=_read_snapshot(profile)
    native=native_tab_groups_supported(runtime)
    urls=_snapshot_urls(snapshot[0],native=native) if snapshot else []
    if native and urls:
        # The official launcher filters this file against its current URL list.
        # Use the untouched copied file only when that filtering is a no-op.
        complex_snapshot=any(node.get('type')=='folder' for node in snapshot[0]['roots']) or len(urls)!=len(_normalized_urls(urls))
        try:
            allowed=source_startup_urls(source_record) if source_record is not None else startup_urls
            allowed=_unique(allowed) if allowed is not None else None
        except LocalBrowserError:
            if complex_snapshot:raise
            allowed=None
        if allowed is not None and _normalized_urls(urls)==_normalized_urls(allowed):
            return {'format':1,'pending':True,'mode':'tab-group-store',
                    'snapshot_sha256':snapshot[1],'urls':list(dict.fromkeys(urls))}
        if complex_snapshot:
            raise LocalBrowserError('来源标签组与当前启动网址不一致，无法保证分组和重复标签完整恢复，未提交副本；原资料已保留。')
        if allowed is not None:
            return {'format':1,'pending':True,'urls':allowed} if allowed else None
    urls=list(dict.fromkeys(urls)) if urls else _unique(fallback_urls)
    return {'format':1,'pending':True,'urls':urls} if urls else None


def verify_tab_group_restore(profile,runtime,marker,*,verify_engine=False):
    """Recheck the exact pending snapshot immediately before native launch."""
    request=pending_source_restore({'_source_session_restore':marker})
    if (not request or request['mode']!='tab-group-store' or not native_tab_groups_supported(runtime)
            or has_saved_session(profile)):_reject()
    if verify_engine:
        from local_engine import LocalEngineStore
        LocalEngineStore().validate(runtime['core_path'],runtime.get('signature_key_id'),runtime['core_major'])
    snapshot=_read_snapshot(profile)
    if not snapshot or snapshot[1]!=request['snapshot_sha256']:_reject()
    urls=_snapshot_urls(snapshot[0],native=True)
    if not urls or list(dict.fromkeys(urls))!=request['urls']:_reject()
