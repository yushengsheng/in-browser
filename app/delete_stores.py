"""Identify and prune only documented local copies of selected window records."""
from contextlib import closing
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time

from app_paths import APP_ROOT
from delete_paths import DeleteError,absolute,checked,from_relative,relative,remove
from local_state import read_encrypted,write_encrypted

_ID=re.compile(r'[A-Za-z0-9_-]{1,80}')
_HEX=re.compile(r'[0-9a-f]{64}')
_SOURCE=re.compile(r'[0-9a-fA-F]{32}')
_BIN_KINDS={'settings.bin':'settings','runtime.bin':'runtime',
            'local-source-archive.bin':'archive','selected-settings.bin':'selected'}


def identities(values):
    result=list(dict.fromkeys(str(value) for value in values))
    if not result or len(result)>100 or any(not _ID.fullmatch(value) for value in result):
        raise DeleteError('窗口标识无效或一次选择超过100个窗口，未开始删除。')
    return result


def _signature_name(name,identity):
    return re.fullmatch(re.escape(identity)+r'(?:-(?:local-)?[0-9a-f]{32})?'
                        r'(?:-moved-[0-9a-f]{32})*\.(?:bin|tmp)',name) is not None


def _profile_backup(name,identity):
    return re.fullmatch(re.escape(identity)+r'-[0-9a-f]{32}(?:\.copying)?',name) is not None


def _proxy_name(name,identity):
    return re.fullmatch(re.escape(identity)+r'\.(?:request|state|ssh-hosts\.bin)(?:\.[A-Za-z0-9_-]+\.tmp)?',name) is not None


def _digest(path):
    value=hashlib.sha256();size=0
    with path.open('rb') as stream:
        while block:=stream.read(1024*1024):
            size+=len(block)
            if size>16*1024*1024+284:raise DeleteError('历史签名超过可认证大小，已停止清理。')
            value.update(block)
    return value.hexdigest()


def _protection(record):
    value=(record.get('_native') or record.get('native') or {}).get('DataProtect')
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                                    ensure_ascii=False,allow_nan=False).encode()).hexdigest() if value else None


def _sources(record):
    result=set()
    for value in ((record.get('_source') or {}).get('source_id'),
                  (record.get('_source_info') or {}).get('id'),
                  (record.get('_source_detail') or {}).get('id')):
        if isinstance(value,str) and _SOURCE.fullmatch(value):result.add(value.lower())
    return result


def _source_key(identity):
    return hashlib.sha256(('bitbrowser-local-v1:'+identity.lower()).encode()).hexdigest()


def _references(records):
    return [absolute(value) for item in records for field in ('profile_path','fingerprint_path','managed_extension')
            if isinstance(value:=item.get('_runtime',{}).get(field),str) and value and Path(value).is_absolute()]


def _related(first,second):
    first=os.path.normcase(str(absolute(first)));second=os.path.normcase(str(absolute(second)))
    try:return os.path.commonpath((first,second)) in (first,second)
    except ValueError:return False


def _reference_path(value,root):
    if not isinstance(value,str) or not value:return None
    for prefix,base in (('@data/',root),('@app/',APP_ROOT)):
        if value.startswith(prefix):
            parts=value[len(prefix):].split('/')
            if any(part in ('','..','.') or ':' in part or '\\' in part for part in parts):
                raise DeleteError('历史恢复文件的便携引用无效，已停止清理。')
            return absolute(absolute(base).joinpath(*parts))
    if value.startswith('@'):raise DeleteError('历史恢复文件含未知便携引用，已停止清理。')
    return absolute(value) if Path(value).is_absolute() else None


def _bin_references(value,kind,selected,root):
    if kind!='settings':return []
    references=[]
    for runtime in value['windows']:
        if not isinstance(runtime,dict):raise DeleteError('历史恢复文件的窗口引用无法识别，已停止清理。')
        if runtime.get('alias') in selected:continue
        for field in ('profile_path','fingerprint_path','managed_extension'):
            path=_reference_path(runtime.get(field),root)
            if path is not None:references.append(path)
    return references


def _database(path,root,*,readonly=False):
    checked(path,root)
    for suffix in ('-wal','-shm','-journal'):checked(Path(str(path)+suffix),root)
    con=sqlite3.connect(path.as_uri()+'?mode='+('ro' if readonly else 'rw'),uri=True,timeout=2)
    con.execute('PRAGMA busy_timeout=2000')
    return con


def _tables(con):
    return {row[0]:{item[1] for item in con.execute('PRAGMA table_info("'+row[0]+'")')}
            for row in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            if re.fullmatch('[a-zA-Z_][a-zA-Z0-9_]*',row[0])}


def _catalog(path,root,store):
    with closing(_database(path,root,readonly=True)) as con:
        tables=_tables(con)
        if 'profiles' in tables:
            if (not {'id','seq','data'}<=tables['profiles'] or not {'key','value'}<=tables.get('settings',set()) or
                    ('source_bindings' in tables and not {'source_key','profile_id'}<=tables['source_bindings'])):
                raise DeleteError('已发现无法识别的历史目录库，删除尚未完成；未删除整份共享备份。')
            records=[]
            for identity,blob in con.execute('SELECT id,data FROM profiles ORDER BY seq'):
                record=store.unpack(blob)
                if not isinstance(record,dict) or record.get('id')!=identity:raise DeleteError('历史目录库的窗口身份不一致，已停止删除。')
                records.append(record)
            bindings=list(con.execute('SELECT source_key,profile_id FROM source_bindings')) if 'source_bindings' in tables else []
            return 'catalog',records,bindings
        if tables.keys()=={'sources'} and {'source_id','payload'}<=tables['sources']:
            # Authenticate every row before making any destructive change.
            from local_state import protect
            for identity,blob in con.execute('SELECT source_id,payload FROM sources'):
                value=json.loads(protect(blob,decrypt=True,root=root))
                if str(value.get('id','')).lower()!=str(identity).lower():
                    raise DeleteError('来源缓存身份不一致，已停止删除。')
            return 'prepared',[],[]
        raise DeleteError('已发现无法识别的历史数据库，删除尚未完成；未删除整份共享备份。')


def _bin_kind(name):
    for filename,kind in _BIN_KINDS.items():
        if name==filename or re.fullmatch(re.escape(filename)+r'\.[A-Za-z0-9_-]+\.tmp',name):return kind
    return None


def _bin_value(path,root,kind):
    value=read_encrypted(path,root=root)
    if kind=='selected':valid=isinstance(value,list) and all(isinstance(item,dict) and 'alias' in item for item in value)
    elif kind=='settings':valid=isinstance(value,dict) and isinstance(value.get('windows'),list)
    elif kind=='runtime':valid=isinstance(value,dict)
    else:valid=isinstance(value,dict) and value.get('format')==1 and isinstance(value.get('items'),dict)
    if not valid:raise DeleteError('历史恢复文件的格式无法识别，删除尚未完成；未删除整份共享备份。')
    return value


def _bin_sources(value,kind,selected):
    result=set()
    if kind=='selected':
        for item in value:
            source=(item.get('info') or {}).get('id')
            if item.get('alias') in selected and isinstance(source,str) and _SOURCE.fullmatch(source):result.add(source.lower())
    return result


def _bootstrap(root):
    # This one legacy location is read by WindowStore migration. Never search
    # arbitrary parent folders when the service is using an isolated data root.
    if absolute(root)!=absolute(APP_ROOT/'data'):return None
    return absolute(APP_ROOT.parent/'analysis/private-bootstrap')


def _files(root,selected,all_ids):
    output=[];backup=root/'backups'
    if not backup.exists():return output
    checked(backup,root,tree=True)
    stack=[backup]
    while stack:
        folder=stack.pop()
        for path in folder.iterdir():
            if path.is_dir():
                if folder==backup and any(_profile_backup(path.name,identity) for identity in all_ids):continue
                stack.append(path)
            elif path.is_file():output.append(path)
            if len(output)>100000:raise DeleteError('历史备份数量超过安全清理范围，删除尚未开始。')
    return output


def make_plan(service,records):
    root=absolute(service.root);checked(root,root);selected=set(identities(record['id'] for record in records))
    checked(root/'.portable-vault',root,tree=True)
    store=service.store;all_records=store.all();all_ids={record['id'] for record in all_records}
    paths=[root/'windows.sqlite'];bins=[];prepared=[];catalogs=[];backup_records=[];bindings=[]
    backup_files=_files(root,selected,all_ids|selected)
    for path in backup_files:
        if path.name.endswith(('.sqlite','.sqlite.tmp')):paths.append(path)
    if (root/'prepared-sources.sqlite').exists():paths.append(root/'prepared-sources.sqlite')
    for path in paths:
        kind,items,links=_catalog(path,root,store)
        (catalogs if kind=='catalog' else prepared).append(relative(path,root))
        backup_records.extend(items);bindings.extend(links)
    for path in [*(root/name for name in _BIN_KINDS),*backup_files]:
        kind=_bin_kind(path.name)
        if not kind or not path.is_file():continue
        checked(path,root);value=_bin_value(path,root,kind)
        bins.append({'path':relative(path,root),'kind':kind,'owner':'data'})
    # Interrupted encrypted atomic writes can themselves contain a complete
    # recoverable old record and must be pruned too.
    for path in root.iterdir():
        kind=_bin_kind(path.name)
        if kind and path.is_file() and not any(item['path']==path.name for item in bins):
            checked(path,root);_bin_value(path,root,kind)
            bins.append({'path':path.name,'kind':kind,'owner':'data'})
    bootstrap=_bootstrap(root)
    if bootstrap is not None and bootstrap.exists():
        checked(bootstrap,bootstrap)
        for path in bootstrap.iterdir():
            if _bin_kind(path.name)=='selected' and path.is_file():
                checked(path,bootstrap);_bin_value(path,root,'selected')
                bins.append({'path':relative(path,bootstrap),'kind':'selected','owner':'bootstrap'})
    target_records=[item for item in backup_records if item['id'] in selected]
    other_records=[item for item in backup_records if item['id'] not in selected]
    source_ids=set().union(*(_sources(item) for item in target_records),set())
    other_sources=set().union(*(_sources(item) for item in other_records),set())
    bin_references=[]
    for item in bins:
        owner=root if item['owner']=='data' else bootstrap
        value=_bin_value(from_relative(item['path'],owner),root,item['kind'])
        source_ids.update(_bin_sources(value,item['kind'],selected))
        aliases={entry.get('alias') for entry in value if isinstance(entry,dict)} if item['kind']=='selected' else set()
        other_sources.update(_bin_sources(value,item['kind'],aliases-selected))
        bin_references.extend(_bin_references(value,item['kind'],selected,root))
    source_ids-=other_sources
    keys={key for key,identity in bindings if identity in selected}
    keys.update((item.get('_source') or {}).get('source_key') for item in target_records)
    keys.discard(None);keys.update(_source_key(value) for value in source_ids)
    shared_keys={key for key,identity in bindings if identity not in selected}
    keys-=shared_keys
    hashes={item.get('_runtime',{}).get('fingerprint_sha256') for item in target_records}
    other_hashes={item.get('_runtime',{}).get('fingerprint_sha256') for item in other_records}
    hashes={value for value in hashes if isinstance(value,str) and _HEX.fullmatch(value)}-other_hashes
    protections={_protection(item) for item in target_records}-{_protection(item) for item in other_records}
    protections.discard(None)
    references=_references(other_records)+bin_references
    targets=set();signature_paths={};work_owners={}
    for record in records:
        path=Path(record.get('_runtime',{}).get('profile_path',''))
        if path!=root/'profiles'/record['id'] or any(_related(path,value) for value in references):
            raise DeleteError('窗口资料目录的独占归属无法确认，未开始删除。')
        checked(path,root,tree=True);targets.add(relative(path,root))
        signature=Path(record.get('_runtime',{}).get('fingerprint_path',''))
        if signature.parent!=root/'fingerprints' or not _signature_name(signature.name,record['id']):
            raise DeleteError('窗口签名不在可认证的专属目录，未开始删除。')
        checked(signature,root)
        if signature.exists() and _digest(signature)!=record['_runtime'].get('fingerprint_sha256'):
            raise DeleteError('窗口签名与目录记录不一致，未开始删除。')
        extension=root/'extensions'/record['id']
        if not any(_related(extension,value) for value in references):
            checked(extension,root,tree=True);targets.add(relative(extension,root))
    fingerprint_root=root/'fingerprints'
    if fingerprint_root.exists():
        checked(fingerprint_root,root)
        for path in fingerprint_root.iterdir():
            if (any(_signature_name(path.name,identity) for identity in selected) and not any(_related(path,value) for value in references)
                    and not any(_signature_name(path.name,identity) for identity in all_ids-selected)):
                checked(path,root,tree=True)
                if not path.is_file():raise DeleteError('签名目录中存在未知目录，未开始删除。')
                targets.add(relative(path,root));signature_paths[relative(path,root)]=_digest(path)
    backup=root/'backups'
    if backup.exists():
        for path in backup.iterdir():
            if any(_profile_backup(path.name,identity) for identity in selected):
                if any(_related(path,value) for value in references):raise DeleteError('历史资料副本仍被其他窗口使用，未开始删除。')
                checked(path,root,tree=True);targets.add(relative(path,root))
    proxy=root/'proxy-runtime'
    if proxy.exists():
        checked(proxy,root)
        for path in proxy.iterdir():
            if any(_proxy_name(path.name,identity) for identity in selected):
                checked(path,root,tree=True)
                if not path.is_file():raise DeleteError('代理恢复文件的格式无法识别，未开始删除。')
                targets.add(relative(path,root))
    for path in backup_files:
        if path.parent.name!='signatures' or path.suffix not in ('.bin','.tmp'):continue
        checked(path,root)
        digest=_digest(path)
        if digest in other_hashes:continue
        own=digest in hashes
        if not own:
            try:protection=_protection({'_native':service.configuration.decode(path)})
            except Exception:raise DeleteError('历史匿名签名无法认证，删除尚未开始；未删除共享备份。') from None
            own=bool(protection and protection in protections)
        if own:
            targets.add(relative(path,root));signature_paths[relative(path,root)]=digest
    # Authenticated import intents may retain a prepared profile and signature.
    for db in catalogs:
        with closing(_database(from_relative(db,root),root,readonly=True)) as con:
            tables=_tables(con)
            if 'import_intents' not in tables:continue
            con.row_factory=sqlite3.Row
            for row in con.execute('SELECT * FROM import_intents'):
                if row['profile_id'] not in selected and row['source_key'] not in keys:continue
                item=dict(row);item['data']=store.unpack(item['data'])
                from sync_state import SyncState
                owner=SyncState.validate_intent(item)
                if not re.fullmatch('[0-9a-f]{32}',owner['work_id']):raise DeleteError('同步暂存目录身份无效，未开始删除。')
                work=root/'.sync-work'/owner['work_id'];checked(work,root,tree=True)
                if work.exists():
                    if any(_related(work,value) for value in references):raise DeleteError('同步暂存目录仍被其他窗口使用，未开始删除。')
                    marker=work/'.sync-owner.bin';checked(marker,root)
                    if store.unpack(marker.read_bytes())!={'format':1,'ownership':owner}:
                        raise DeleteError('同步暂存目录的归属不匹配，未开始删除。')
                    name=relative(work,root);targets.add(name);work_owners[name]=owner
    plan={'format':1,'identities':sorted(selected),'root':str(root),'source_ids':sorted(source_ids),
          'source_keys':sorted(keys),'targets':sorted(targets),'catalogs':catalogs,'prepared':prepared,
          'bins':bins,'signature_paths':signature_paths,'work_owners':work_owners}
    validate_plan(plan,root)
    return plan


def validate_plan(plan,root,*,trees=False):
    root=absolute(root)
    if not isinstance(plan,dict) or plan.get('format')!=1 or plan.get('root')!=str(root):
        raise DeleteError('删除恢复计划无法认证，已停止清理。')
    selected=identities(plan.get('identities',[]))
    if (any(not isinstance(plan.get(field),list) for field in ('targets','catalogs','prepared','bins')) or
            'windows.sqlite' not in plan['catalogs'] or
            any('profiles/'+identity not in plan['targets'] for identity in selected) or
            not isinstance(plan.get('signature_paths'),dict) or not isinstance(plan.get('work_owners'),dict)):
        raise DeleteError('删除恢复计划不完整，已停止清理。')
    for field,pattern in [('source_ids',_SOURCE),('source_keys',_HEX)]:
        if not isinstance(plan.get(field),list) or any(not isinstance(value,str) or not pattern.fullmatch(value) for value in plan[field]):
            raise DeleteError('删除恢复计划的身份无效，已停止清理。')
    for value in plan.get('targets',[]):
        path=from_relative(value,root);parts=path.relative_to(root).parts
        valid=(len(parts)==2 and parts[0] in ('profiles','extensions') and parts[1] in selected)
        valid=valid or (len(parts)==2 and parts[0]=='fingerprints' and any(_signature_name(parts[1],identity) for identity in selected))
        valid=valid or (len(parts)==2 and parts[0]=='backups' and any(_profile_backup(parts[1],identity) for identity in selected))
        valid=valid or (parts[0]=='backups' and len(parts)>=3 and parts[-2]=='signatures' and value in plan.get('signature_paths',{}))
        valid=valid or (len(parts)==2 and parts[0]=='.sync-work' and re.fullmatch('[0-9a-f]{32}',parts[1]) and value in plan.get('work_owners',{}))
        valid=valid or (len(parts)==2 and parts[0]=='proxy-runtime' and any(_proxy_name(parts[1],identity) for identity in selected))
        if not valid:raise DeleteError('删除恢复计划包含未获授权的目标，已停止清理。')
        checked(path,root,tree=trees)
    for value,digest in plan.get('signature_paths',{}).items():
        if value not in plan['targets'] or not isinstance(digest,str) or not _HEX.fullmatch(digest):
            raise DeleteError('删除恢复计划的签名证明无效，已停止清理。')
    for value in plan.get('catalogs',[])+plan.get('prepared',[]):
        path=from_relative(value,root)
        if value not in ('windows.sqlite','prepared-sources.sqlite') and not (value.startswith('backups/') and path.name.endswith(('.sqlite','.sqlite.tmp'))):
            raise DeleteError('删除恢复计划包含未知数据库，已停止清理。')
    for item in plan.get('bins',[]):
        owner=root if item.get('owner')=='data' else _bootstrap(root) if item.get('owner')=='bootstrap' else None
        if owner is None or _bin_kind(Path(item.get('path','')).name)!=item.get('kind'):
            raise DeleteError('删除恢复计划包含未知恢复文件，已停止清理。')
        path=from_relative(item['path'],owner)
        if item['owner']=='data' and path.parent!=root and not item['path'].startswith('backups/'):
            raise DeleteError('删除恢复文件不在受管目录，已停止清理。')
        if item['owner']=='bootstrap' and path.parent!=owner:raise DeleteError('旧恢复文件的归属无效，已停止清理。')


def _scrub(value,kind,plan):
    selected=set(plan['identities']);sources=set(plan['source_ids']);result=copy.deepcopy(value)
    if kind=='settings':result['windows']=[item for item in result['windows'] if item.get('alias') not in selected]
    elif kind=='runtime':
        for identity in selected:result.pop(identity,None)
    elif kind=='selected':
        result=[item for item in result if item.get('alias') not in selected]
    elif kind=='archive':
        result['items']={key:item for key,item in result['items'].items() if key.lower() not in sources}
    return result


def _in_clause(values):return ','.join('?' for _ in values)


def prune_database(path,root,store,plan,*,prepared=False):
    checked(path,root)
    selected=plan['identities'];keys=plan['source_keys'];sources=plan['source_ids']
    with closing(_database(path,root)) as con:
        con.execute('PRAGMA secure_delete=ON');con.execute('BEGIN IMMEDIATE');tables=_tables(con)
        if prepared:
            if sources:con.execute('DELETE FROM sources WHERE lower(source_id) IN ('+_in_clause(sources)+')',sources)
        else:
            con.execute('DELETE FROM profiles WHERE id IN ('+_in_clause(selected)+')',selected)
            if 'source_bindings' in tables:
                con.execute('DELETE FROM source_bindings WHERE profile_id IN ('+_in_clause(selected)+')',selected)
            if 'creation_items' in tables:
                creation_condition='profile_id IN ('+_in_clause(selected)+')'
                creation_values=selected
                if keys:
                    creation_condition+=' OR source_key IN ('+_in_clause(keys)+')'
                    creation_values=selected+keys
                jobs=[row[0] for row in con.execute('SELECT DISTINCT job_id FROM creation_items WHERE '+creation_condition,creation_values)]
                con.execute('DELETE FROM creation_items WHERE '+creation_condition,creation_values)
                if 'creation_jobs' in tables:
                    for job in jobs:
                        if not con.execute('SELECT 1 FROM creation_items WHERE job_id=? LIMIT 1',(job,)).fetchone():
                            con.execute('DELETE FROM creation_jobs WHERE job_id=?',(job,))
            if 'import_intents' in tables:
                condition='profile_id IN ('+_in_clause(selected)+')'
                if keys:condition+=' OR source_key IN ('+_in_clause(keys)+')'
                con.execute('DELETE FROM import_intents WHERE '+condition,selected+keys)
            if 'sync_items' in tables and keys:
                jobs=[row[0] for row in con.execute('SELECT DISTINCT job_id FROM sync_items WHERE source_key IN ('+_in_clause(keys)+')',keys)]
                con.execute('DELETE FROM sync_items WHERE source_key IN ('+_in_clause(keys)+')',keys)
                if 'sync_jobs' in tables:
                    for job in jobs:
                        counts=dict(con.execute('SELECT state,count(*) FROM sync_items WHERE job_id=? GROUP BY state',(job,)))
                        total=sum(counts.values())
                        if not total:con.execute('DELETE FROM sync_jobs WHERE job_id=?',(job,))
                        else:con.execute('UPDATE sync_jobs SET total=?,current=min(current,?),completed=?,skipped=?,failed=? WHERE job_id=?',
                                         (total,total,counts.get('completed',0),counts.get('skipped',0),counts.get('failed',0),job))
            for key,blob in con.execute('SELECT key,value FROM settings').fetchall():
                value=store.unpack(blob)
                if isinstance(value,dict) and isinstance(value.get('windows'),list):
                    clean=_scrub(value,'settings',plan)
                    if clean!=value:con.execute('UPDATE settings SET value=? WHERE key=?',(store.pack(clean),key))
        con.commit()


def compact(path,root):
    checked(path,root)
    with closing(_database(path,root)) as con:
        con.execute('PRAGMA secure_delete=ON')
        deadline=time.monotonic()+30
        con.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
        for vacuum in (False,True):
            if vacuum:con.execute('VACUUM')
            row=con.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
            if row is not None and row[0]:raise DeleteError('删除后的数据库仍被占用，存储清理尚未完成；重启或重试会继续。')
        if con.execute('PRAGMA freelist_count').fetchone()[0]:
            raise DeleteError('删除后的数据库整理尚未完成，重试会继续。')
    wal=Path(str(path)+'-wal')
    if wal.exists() and wal.stat().st_size:raise DeleteError('删除后的数据库日志仍被占用，重试会继续清理。')


def _require_cookie_seeds_closed(path,root):
    from browser_processes import profile_processes
    for profile in path.glob('cookie-seed-*/profile'):
        checked(profile,root,tree=True)
        if profile_processes(profile,require_inspectable=True):
            raise DeleteError('Cookie恢复验证仍在正常退出，暂存资料已保留，请稍后重试清理。')


def _remove_work(service,path,root,owner):
    checked(path,root,tree=True)
    if not path.exists():return
    _require_cookie_seeds_closed(path,root)
    marker=checked(path/'.sync-owner.bin',root)
    if not marker.exists():
        # Only an authenticated intent or deletion plan can reach here. A prior attempt
        # may have removed the final marker and stopped before the final rmdir.
        if any(path.iterdir()):raise DeleteError('非空同步暂存目录缺少归属凭据，清理尚未完成。')
        checked(path,root).rmdir();return
    def authenticate():
        checked(marker,root)
        if marker.stat().st_size>16384 or service.store.unpack(marker.read_bytes())!={'format':1,'ownership':owner}:
            raise DeleteError('同步暂存归属发生变化，清理尚未完成。')
    authenticate()
    for child in list(path.iterdir()):
        if child!=marker:remove(child,root)
    if any(child!=marker for child in path.iterdir()):raise DeleteError('同步暂存目录发生变化，清理尚未完成。')
    authenticate()
    remove(marker,root)
    checked(path,root).rmdir()


def execute_plan(service,plan):
    root=absolute(service.root);validate_plan(plan,root)
    # Recheck current and historical shared references before any deletion.
    others=[]
    for value in plan['catalogs']:
        _,records,_=_catalog(from_relative(value,root),root,service.store)
        others.extend(item for item in records if item['id'] not in plan['identities'])
    references=_references(others)
    bins=list(plan['bins'])
    # A failed operation can be resumed after a legacy recovery file or its
    # atomic temporary copy was written. Reidentify this bounded settings
    # family so a new shared reference is never missed by the old plan.
    all_ids={item['id'] for item in others}|set(plan['identities'])
    for path in [*root.iterdir(),*_files(root,set(plan['identities']),all_ids)]:
        if _bin_kind(path.name)!='settings' or not path.is_file():continue
        item={'path':relative(path,root),'kind':'settings','owner':'data'}
        if item not in bins:bins.append(item)
    for item in bins:
        owner=root if item['owner']=='data' else _bootstrap(root)
        path=from_relative(item['path'],owner)
        if path.exists():
            value=_bin_value(path,root,item['kind'])
            references.extend(_bin_references(value,item['kind'],set(plan['identities']),root))
    for value in plan['targets']:
        if any(_related(from_relative(value,root),reference) for reference in references):
            raise DeleteError('删除目标与其他窗口共享资料树，清理尚未完成。')
    for value in plan['targets']:
        path=from_relative(value,root)
        if path.is_dir():_require_cookie_seeds_closed(path,root)
        if value in plan['signature_paths'] and path.exists() and _digest(path)!=plan['signature_paths'][value]:
            raise DeleteError('删除期间历史签名发生变化，清理尚未完成。')
        owner=plan['work_owners'].get(value)
        if owner is not None:
            _remove_work(service,path,root,owner);continue
        remove(path,root)
    for item in bins:
        owner=root if item['owner']=='data' else _bootstrap(root)
        path=from_relative(item['path'],owner)
        if not path.exists():continue
        value=_bin_value(path,root,item['kind']);clean=_scrub(value,item['kind'],plan)
        if clean!=value:
            checked(path,owner);write_encrypted(path,clean,root=root)
    # The current catalog is last: its disappearance means every identified
    # filesystem copy and historical row has already been handled.
    for value in sorted(plan['catalogs'],key=lambda item:item=='windows.sqlite'):
        prune_database(from_relative(value,root),root,service.store,plan)
    for value in plan['prepared']:
        prune_database(from_relative(value,root),root,service.store,plan,prepared=True)
    for value in plan['catalogs']+plan['prepared']:compact(from_relative(value,root),root)
