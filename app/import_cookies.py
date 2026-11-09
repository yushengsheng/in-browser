"""Materialize the vendor's startup Cookie snapshot before any account page loads.

The matching native engine writes encrypted rows in an isolated empty profile.
Only those rows are merged into the closed imported copy. Existing sessions and
other site storage are never opened or rewritten by the temporary browser.
"""
import copy
from datetime import datetime
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time
import uuid

from browser_core import BrowserController,CDP
from browser_processes import profile_processes
from delete_paths import checked
from local_state import LocalBrowserError

_FAILED='来源启动Cookie未能完整恢复，未打开账号页面；原资料及恢复备份已保留。'
_EXPIRY_REVISION=2
_CHROME_EPOCH_US=11644473600000000


def source_cookies(info,*,now=None):
    raw=(info or {}).get('cookie')
    if raw is None or raw=='':return []
    if isinstance(raw,str):
        if len(raw)>2_000_000:raise ValueError()
        raw=json.loads(raw)
    if not isinstance(raw,list) or len(raw)>10000:raise ValueError()
    now=time.time() if now is None else now
    result={}
    def flag(value):return value in (True,1,'1','true')
    for item in raw:
        if not isinstance(item,dict):raise ValueError()
        name=item.get('name');value=item.get('value');domain=item.get('domain')
        if not isinstance(name,str) or not name or not isinstance(value,str) or not isinstance(domain,str):raise ValueError()
        if any(c in name+value+domain for c in '\r\n\x00') or any(c.isspace() for c in domain) or not re.fullmatch(r'\.?[A-Za-z0-9_.:-]+',domain):raise ValueError()
        domain=domain.lower()
        path=item.get('path') or '/'
        if not isinstance(path,str) or not path.startswith('/') or any(c in path for c in '\r\n\x00'):raise ValueError()
        cookie={'name':name,'value':value,'domain':domain,'path':path,
            'secure':flag(item.get('secure',False)),'httpOnly':flag(item.get('httpOnly',False))}
        if flag(item.get('hostOnly',False)) or name.startswith('__Host-'):cookie['domain']=domain.lstrip('.')
        if name.startswith(('__Secure-','__Host-')):cookie['secure']=True
        if name.startswith('__Host-'):cookie['path']='/'
        same=str(item.get('sameSite') or '').lower()
        if same in ('strict','lax','none','no_restriction'):
            cookie['sameSite']={'strict':'Strict','lax':'Lax','none':'None','no_restriction':'None'}[same]
        elif same not in ('','unspecified'):raise ValueError()
        expiry=next((item[k] for k in ('expirationDate','expires','expiry') if item.get(k) not in (None,'')),None)
        if expiry is not None and expiry!=-1:
            try:expiry=float(expiry)
            except (TypeError,ValueError):
                if not isinstance(expiry,str):raise ValueError() from None
                date=datetime.fromisoformat(expiry.replace('Z','+00:00'))
                if date.tzinfo is None:raise ValueError()
                expiry=date.timestamp()
            if expiry>1_000_000_000_000:expiry/=1000
            if not math.isfinite(expiry) or expiry<-1 or expiry>253402300799:raise ValueError()
            if expiry!=-1:
                expiry=math.floor(expiry)
                if expiry<=now:continue
                cookie['expires']=expiry
        if item.get('partitionKey') is not None:
            key=item['partitionKey']
            if not isinstance(key,dict) or not isinstance(key.get('topLevelSite'),str):raise ValueError()
            cookie['partitionKey']=copy.deepcopy(key)
        identity=(domain,name,path,json.dumps(cookie.get('partitionKey'),sort_keys=True))
        result[identity]=cookie
    return list(result.values())


def _identity(cookie):
    partition=cookie.get('partitionKey') or {}
    return (cookie['domain'],cookie['name'],cookie.get('path','/'),
            partition.get('topLevelSite',''),bool(partition.get('hasCrossSiteAncestor',False)))


def _probe_runtime(record,seed,signature=None):
    runtime=copy.deepcopy(record['_runtime'])
    runtime.update(alias='cookie_seed_'+uuid.uuid4().hex,profile_path=str(seed),new_profile=True,has_launched=False,
        restore_session=False,initial_urls=[],open_urls_once=[],account_platform='',account_username='',account_password='',launch_args=[])
    if signature:runtime.update(fingerprint_path=str(signature))
    for field in ('managed_extension','local_proxy_mode','local_proxy_port'):runtime.pop(field,None)
    return runtime


def _cleanup_probe(controller,desktop,closed,temporary,root):
    cleanup=True
    if controller is not None and not closed:
        try:controller.close(next(iter(controller.profiles)))
        except Exception:cleanup=False
    if desktop is not None:
        try:desktop.close()
        except Exception:cleanup=False
    if temporary is not None:
        try:
            if profile_processes(temporary/'profile',require_inspectable=True):cleanup=False
            if cleanup:checked(temporary,root,tree=True);shutil.rmtree(temporary)
        except Exception:cleanup=False
    if not cleanup:raise LocalBrowserError(_FAILED) from None


def _expiry_candidates(info,*,now=None):
    raw=(info or {}).get('cookie') or []
    if isinstance(raw,str):
        if len(raw)>2_000_000:raise ValueError()
        raw=json.loads(raw)
    if not isinstance(raw,list) or len(raw)>10000:raise ValueError()
    result={}
    for item in raw:
        for cookie in source_cookies({'cookie':[item]},now=now):
            key=_identity(cookie)
            if item.get('session') in (True,1,'1','true') and 'expires' in cookie:result[key]=cookie
            else:result.pop(key,None)
    return list(result.values())


def _session_rows(database,cookies,record):
    """Read only exact identities; opaque DataProtect values require native proof."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from portable_browser import _private_key
    cipher=AESGCM(_private_key(record['_portable_crypt']))
    deadline=time.monotonic()+20;total=0;result=[]
    con=sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=5)
    try:
        con.execute('PRAGMA query_only=ON');con.execute('BEGIN')
        con.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
        columns=[r[1] for r in con.execute('PRAGMA table_info(cookies)')]
        required={'host_key','name','path','encrypted_value','expires_utc','has_expires','is_persistent','is_secure','is_httponly'}
        if not required.issubset(columns) or any(not re.fullmatch('[a-z_]+',key) for key in columns):raise ValueError()
        version=int(con.execute("SELECT value FROM meta WHERE key='version'").fetchone()[0])
        if not 1<=version<=1000:raise ValueError()
        for cookie in cookies:
            rows=con.execute('SELECT rowid,'+','.join(columns)+' FROM cookies WHERE host_key=? AND name=? AND path=?',
                (cookie['domain'],cookie['name'],cookie['path'])).fetchall()
            matches=[]
            for row in rows:
                current=dict(zip(('rowid',*columns),row));partition=current.get('top_frame_site_key') or ''
                ancestor=bool(current.get('has_cross_site_ancestor')) if partition else False
                if (partition,ancestor)!=_identity(cookie)[3:]:continue
                if any(current[key] not in (0,None) for key in ('expires_utc','has_expires','is_persistent')):continue
                if bool(current['is_secure'])!=cookie['secure'] or bool(current['is_httponly'])!=cookie['httpOnly']:continue
                matches.append(current)
            if len(matches)>1:raise ValueError()
            if not matches:continue
            current=matches[0];encrypted=current['encrypted_value']
            if not isinstance(encrypted,bytes) or len(encrypted)>1024*1024:raise ValueError()
            total+=len(encrypted)
            if total>64*1024*1024 or time.monotonic()>=deadline:raise ValueError()
            if encrypted:
                if not encrypted.startswith(b'v10') or len(encrypted)<31:raise ValueError()
                clear=cipher.decrypt(encrypted[3:15],encrypted[15:],None)
                if version>=24:
                    digest=hashlib.sha256(current['host_key'].encode()).digest()
                    direct=len(clear)>=32 and hmac.compare_digest(clear[:32],digest)
                    if direct:clear=clear[32:]
                else:direct=True
                if direct and not hmac.compare_digest(clear,cookie['value'].encode()):continue
            elif not isinstance(current.get('value'),str) or not hmac.compare_digest(current['value'].encode(),cookie['value'].encode()):continue
            result.append({'cookie':cookie,'row':current,'columns':columns})
        return result
    finally:con.close()


def _expiry_us(seconds):
    if not isinstance(seconds,(int,float)) or not math.isfinite(seconds) or not 0<seconds<=253402300799:raise ValueError()
    return int(seconds*1_000_000)+_CHROME_EPOCH_US


def _update_expiry(database,rows,*,clone=False):
    deadline=time.monotonic()+20
    con=sqlite3.connect(database.as_uri()+'?mode=rw',uri=True,timeout=5)
    try:
        con.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
        con.execute('PRAGMA synchronous=FULL');con.execute('BEGIN IMMEDIATE')
        if con.execute('PRAGMA quick_check').fetchone()!=('ok',):raise ValueError()
        if clone:
            con.execute('CREATE TEMP TABLE expiry_candidates (identity INTEGER PRIMARY KEY)')
            con.executemany('INSERT INTO expiry_candidates VALUES(?)',[(item['row']['rowid'],) for item in rows])
            con.execute('DELETE FROM cookies WHERE rowid NOT IN (SELECT identity FROM expiry_candidates)')
        count=0
        for item in rows:
            columns=item['columns'];original=item['row'];cookie=item['cookie']
            current=con.execute('SELECT rowid,'+','.join(columns)+' FROM cookies WHERE rowid=?',(original['rowid'],)).fetchone()
            if current is None or dict(zip(('rowid',*columns),current))!=original:raise ValueError()
            expires=item.get('expires',cookie['expires'])
            if expires<=time.time():continue
            before=con.total_changes
            changed=con.execute('UPDATE cookies SET expires_utc=?,has_expires=1,is_persistent=1 WHERE rowid=?',(_expiry_us(expires),original['rowid']))
            if changed.rowcount!=1 or con.total_changes-before!=1:raise ValueError()
            expected={**original,'expires_utc':_expiry_us(expires),'has_expires':1,'is_persistent':1}
            after=con.execute('SELECT rowid,'+','.join(columns)+' FROM cookies WHERE rowid=?',(original['rowid'],)).fetchone()
            if after is None or dict(zip(('rowid',*columns),after))!=expected:raise ValueError()
            count+=1
        con.commit();return count
    except Exception:
        con.rollback();raise
    finally:con.close()


def _native_expiry(service,record,profile,database,rows,backup):
    """The matching offline engine authenticates protected values and its expiry cap."""
    temporary=None;controller=None;desktop=None;closed=False
    try:
        temporary=Path(tempfile.mkdtemp(prefix='cookie-seed-',dir=backup)).resolve()
        seed=temporary/'profile';(seed/'Default').mkdir(parents=True)
        state=profile/'Local State'
        if state.stat().st_size>16*1024*1024:raise ValueError()
        shutil.copy2(state,seed/'Local State');(seed/'Default/Preferences').write_text('{}',encoding='utf-8')
        if database.stat().st_size>512*1024*1024:raise ValueError()
        target=seed/database.relative_to(profile);target.parent.mkdir(parents=True,exist_ok=True)
        incoming=sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=5);copy_con=sqlite3.connect(target)
        deadline=time.monotonic()+20
        def progress(*_):
            if time.monotonic()>=deadline:raise TimeoutError()
        try:incoming.backup(copy_con,pages=128,progress=progress,sleep=.05)
        finally:copy_con.close();incoming.close()
        _update_expiry(target,rows,clone=True)
        runtime=_probe_runtime(record,seed)
        controller=BrowserController(temporary,settings={'windows':[runtime],'persistent':False});controller.root=service.root
        presentation={}
        if str(runtime.get('core_major'))=='104':
            from probe_display import ProbeDesktop
            desktop=ProbeDesktop();presentation['background_desktop']=desktop
        controller.open(runtime['alias'],offline_test=True,extra_urls=['about:blank'],bootstrap_blank=True,background_probe=True,**presentation)
        with CDP(controller.endpoint(runtime['alias'])) as connection:
            actual={_identity(cookie):cookie for cookie in connection.call('Storage.getCookies')['cookies']}
            authenticated=[];to_set=[]
            for item in rows:
                cookie=item['cookie'];current=actual.get(_identity(cookie))
                if current is None or bool(current.get('secure'))!=cookie['secure'] or bool(current.get('httpOnly'))!=cookie['httpOnly']:raise ValueError()
                if not isinstance(current.get('value'),str):raise ValueError()
                if not hmac.compare_digest(current['value'].encode(),cookie['value'].encode()):continue
                # Re-submit only an already authenticated current value in the clone.
                # The engine applies the same expiry cap as a fresh source import.
                bounded={key:current[key] for key in ('name','value','domain','path','secure','httpOnly')}
                bounded['expires']=cookie['expires']
                for key in ('sameSite','partitionKey'):
                    if key in current:bounded[key]=copy.deepcopy(current[key])
                to_set.append(bounded);authenticated.append(item)
            if to_set:connection.call('Storage.setCookies',{'cookies':to_set})
            actual={_identity(cookie):cookie for cookie in connection.call('Storage.getCookies')['cookies']} if to_set else {}
            verified=[]
            for item in authenticated:
                cookie=item['cookie'];current=actual.get(_identity(cookie))
                if current is None or not isinstance(current.get('value'),str) or not hmac.compare_digest(current['value'].encode(),cookie['value'].encode()) or bool(current.get('secure'))!=cookie['secure'] or bool(current.get('httpOnly'))!=cookie['httpOnly']:raise ValueError()
                expires=current.get('expires')
                if not isinstance(expires,(int,float)) or not math.isfinite(expires) or expires<=time.time():raise ValueError()
                verified.append({**item,'expires':min(expires,cookie['expires'])})
        controller.close(runtime['alias']);closed=True
        return verified
    finally:
        _cleanup_probe(controller,desktop,closed,temporary,service.root)


def _repair_expiry(service,record):
    cookies=_expiry_candidates(record['_source_info'])
    if not cookies:return 0
    profile=Path(record['_runtime']['profile_path']).resolve();service._closed(record)
    if profile_processes(profile,require_inspectable=True):raise ValueError()
    database=profile/'Default/Network/Cookies'
    if not database.is_file():database=profile/'Default/Cookies'
    if not database.is_file():return 0
    checked(database,service.root)
    rows=_session_rows(database,cookies,record)
    if not rows:return 0
    backup=Path(service.root)/'backups'/(record['id']+'-'+uuid.uuid4().hex)
    service._copy_profile(profile,backup)
    verified=_native_expiry(service,record,profile,database,rows,backup)
    service._closed(record)
    if profile_processes(profile,require_inspectable=True):raise ValueError()
    return _update_expiry(database,verified) if verified else 0


def _merge_database(source,target,session_keys,expected_count):
    """Use the engine's exact schema and unique constraints, within one transaction."""
    incoming=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=5)
    connection=None
    deadline=time.monotonic()+20
    try:
        incoming.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
        incoming.execute('PRAGMA query_only=ON')
        columns=[r[1] for r in incoming.execute('PRAGMA table_info(cookies)')]
        if not columns or any(not re.fullmatch('[a-z_]+',name) for name in columns):raise ValueError()
        rows=incoming.execute('SELECT '+','.join(columns)+' FROM cookies').fetchall()
        if len(rows)!=expected_count or len(rows)>10000:raise ValueError()
        target.parent.mkdir(parents=True,exist_ok=True)
        if not target.exists():
            # An ordinary empty database from the same engine provides its schema.
            connection=sqlite3.connect(target)
            incoming.backup(connection)
        else:connection=sqlite3.connect(target.as_uri()+'?mode=rw',uri=True,timeout=5)
        connection.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
        if connection.execute('PRAGMA quick_check').fetchone()!=('ok',):raise ValueError()
        if columns!=[r[1] for r in connection.execute('PRAGMA table_info(cookies)')]:raise ValueError()
        connection.execute('PRAGMA synchronous=FULL');connection.execute('BEGIN IMMEDIATE')
        values=[]
        for row in rows:
            row=list(row)
            partition=row[columns.index('top_frame_site_key')] if 'top_frame_site_key' in columns else ''
            # Some native schemas set this bit on unpartitioned Cookies too.
            # It identifies a partition only when a top-level site exists.
            ancestor=(bool(row[columns.index('has_cross_site_ancestor')])
                      if partition and 'has_cross_site_ancestor' in columns else False)
            identity=tuple(row[columns.index(k)] for k in ('host_key','name','path'))+(
                partition,ancestor)
            if identity in session_keys:
                for name in ('expires_utc','has_expires','is_persistent'):
                    if name in columns:row[columns.index(name)]=0
            values.append(row)
        connection.executemany('INSERT OR REPLACE INTO cookies ('+','.join(columns)+') VALUES ('+','.join('?' for _ in columns)+')',values)
        connection.commit()
        return len(values)
    except Exception:
        if connection:connection.rollback()
        raise
    finally:
        incoming.close()
        if connection:connection.close()


def materialize(service,record,profile,*,signature=None,work_parent=None):
    """No source or account network is used, and all borrowed keys stay local."""
    if record.get('created_locally') or not record.get('_source_info'):return False
    if record.get('_startup_cookies',{}).get('format')==1:return False
    profile=Path(profile).resolve();temporary=None;controller=None;desktop=None;closed=False
    try:
        if profile_processes(profile,require_inspectable=True):raise ValueError()
        cookies=source_cookies(record['_source_info'])
        if not cookies:
            record['_startup_cookies']={'format':1,'expiry_revision':_EXPIRY_REVISION,'count':0};return True
        temporary=Path(tempfile.mkdtemp(prefix='cookie-seed-',dir=work_parent or service.root)).resolve()
        seed=temporary/'profile';(seed/'Default').mkdir(parents=True)
        # The original OSCrypt wrapper is read, never regenerated or printed.
        state=profile/'Local State'
        if state.stat().st_size>16*1024*1024:raise ValueError()
        shutil.copy2(state,seed/'Local State')
        (seed/'Default/Preferences').write_text('{}',encoding='utf-8')
        runtime=_probe_runtime(record,seed,signature)
        controller=BrowserController(temporary,settings={'windows':[runtime],'persistent':False});controller.root=service.root
        presentation={}
        if str(runtime.get('core_major'))=='104':
            from probe_display import ProbeDesktop
            desktop=ProbeDesktop();presentation['background_desktop']=desktop
        controller.open(runtime['alias'],offline_test=True,extra_urls=['about:blank'],bootstrap_blank=True,background_probe=True,**presentation)
        session_keys={_identity(v) for v in cookies if 'expires' not in v}
        seeded=copy.deepcopy(cookies)
        for v in seeded:
            if 'expires' not in v:v['expires']=time.time()+86400
        with CDP(controller.endpoint(runtime['alias'])) as connection:
            connection.call('Storage.setCookies',{'cookies':seeded})
            actual={_identity(v):v for v in connection.call('Storage.getCookies')['cookies']}
            for v in seeded:
                current=actual.get(_identity(v))
                if current is None or current['value']!=v['value'] or bool(current['httpOnly'])!=v['httpOnly'] or bool(current['secure'])!=v['secure']:raise ValueError()
        controller.close(runtime['alias']);closed=True
        if profile_processes(profile,require_inspectable=True):raise ValueError()
        source=seed/'Default/Network/Cookies'
        if not source.is_file():source=seed/'Default/Cookies'
        relative=source.relative_to(seed)
        target=checked(profile/relative,service.root)
        if not target.exists() and relative.as_posix()!='Default/Cookies' and (profile/'Default/Cookies').is_file():raise ValueError()
        count=_merge_database(source,target,session_keys,len(seeded))
        record['_startup_cookies']={'format':1,'expiry_revision':_EXPIRY_REVISION,'count':count}
        return True
    except Exception:
        raise LocalBrowserError(_FAILED) from None
    finally:
        _cleanup_probe(controller,desktop,closed,temporary,service.root)


def prepare_existing(service,record):
    marker=record.get('_startup_cookies') or {}
    if record.get('created_locally') or not record.get('_source_info') or (marker.get('format')==1 and marker.get('expiry_revision',0)>=_EXPIRY_REVISION):return record
    updated=copy.deepcopy(record)
    if marker.get('format')==1:
        try:
            count=0 if marker.get('user_cookie_override') or record.get('_cookie_pending') or record.get('cookie_text') else _repair_expiry(service,record)
            updated['_startup_cookies']={**marker,'expiry_revision':_EXPIRY_REVISION,'expiry_repaired':count}
        except Exception:raise LocalBrowserError(_FAILED) from None
    elif record.get('_cookie_pending') or record.get('cookie_text'):
        updated['_startup_cookies']={'format':1,'expiry_revision':_EXPIRY_REVISION,'user_cookie_override':True}
    elif source_cookies(record['_source_info']):
        profile=Path(record['_runtime']['profile_path'])
        service._closed(record)
        backup=Path(service.root)/'backups'/(record['id']+'-'+uuid.uuid4().hex)
        service._copy_profile(profile,backup)
        materialize(service,updated,profile,work_parent=backup)
    else:updated['_startup_cookies']={'format':1,'expiry_revision':_EXPIRY_REVISION,'count':0}
    service.store.put(updated);service._sync(updated)
    return updated
