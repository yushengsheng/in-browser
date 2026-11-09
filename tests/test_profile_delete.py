"""Synthetic vault-only permanent deletion, copy ownership and recovery checks."""
import copy
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))

from delete_paths import DeleteError,checked
import delete_paths
import delete_stores
from local_state import read_encrypted,write_encrypted
from portable_vault import PortableVault
import profile_delete
from sync_state import SyncState,WorkerLease
from window_store import WindowStore


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Fixture:
    def __init__(self,base,*,count=3):
        self.root=Path(base).resolve()/'data';self.root.mkdir(parents=True,exist_ok=True)
        PortableVault(self.root).initialize()
        write_encrypted(self.root/'portable-mode.bin',{'format':1,'state':'ready'},root=self.root)
        self.configuration=SimpleNamespace(decode=lambda path:json.loads(Path(path).read_bytes()))
        self.store=WindowStore(self.configuration,self.root);self.operations=threading.RLock()
        self.controller=SimpleNamespace(profiles={},state={},settings={'windows':[]},_status_cache={},
                                        _windowless_since={},_closing_workers=set(),lock=threading.RLock())
        proxy=self.root/'proxy-runtime';proxy.mkdir()
        self.proxy_runtime=SimpleNamespace(stop_if_unused=lambda identity:None,
            paths=lambda identity:(proxy/(identity+'.request'),proxy/(identity+'.state')))
        self.closed=[];self.records=[]
        for index in range(count):
            identity='synthetic-'+str(index);source=f'{index+1:032x}'
            profile=self.root/'profiles'/identity;(profile/'Default').mkdir(parents=True)
            (profile/'Default/Cookies').write_bytes(('secret-site-'+identity).encode())
            (profile/'Default/Preferences').write_text('{}',encoding='utf-8')
            native={'DataProtect':{'CipherKey':'synthetic-secret-'+identity},'name':identity}
            signature=self.root/'fingerprints'/(identity+'.bin');signature.parent.mkdir(exist_ok=True)
            signature.write_bytes(json.dumps(native).encode())
            key=hashlib.sha256(('bitbrowser-local-v1:'+source).encode()).hexdigest()
            record={'id':identity,'seq':index+1,'created_at':'synthetic','archived':index==0,'name':identity,
                    '_native':native,'_source':{'source_id':source,'source_key':key},
                    '_runtime':{'alias':identity,'profile_path':str(profile),'fingerprint_path':str(signature),
                                'fingerprint_sha256':digest(signature),'managed_extension':str(self.root/'extensions'/identity)}}
            self.store.put(record);self.records.append(record)
            with self.store.connect() as con:con.execute('INSERT INTO source_bindings VALUES (?,?,?)',(key,identity,'synthetic'))
            extension=self.root/'extensions'/identity;extension.mkdir(parents=True)
            (extension/'manifest.json').write_text('{}',encoding='ascii')
            self.controller.profiles[identity]=copy.deepcopy(record['_runtime'])
            self.controller.state[identity]={'pid':0};self.controller._status_cache[identity]='synthetic'
            self.controller.settings['windows'].append(copy.deepcopy(record['_runtime']))
            for path in self.proxy_runtime.paths(identity):write_encrypted(path,{'identity':identity},root=self.root)
        write_encrypted(self.root/'settings.bin',{'windows':copy.deepcopy(self.controller.settings['windows'])},root=self.root)
        write_encrypted(self.root/'runtime.bin',copy.deepcopy(self.controller.state),root=self.root)

    def close(self,identity):self.closed.append(identity)

    def mixed(self):
        backup=self.root/'backups'/'synthetic-mixed';backup.mkdir(parents=True)
        with self.store.connect() as source,closing(sqlite3.connect(backup/'renamed-catalog.sqlite')) as target:source.backup(target)
        signature=backup/'signatures';signature.mkdir()
        for index,record in enumerate(self.records,1):
            shutil.copyfile(record['_runtime']['fingerprint_path'],signature/('existing-'+str(index)+'.bin'))
        for name in ('settings.bin','runtime.bin'):shutil.copyfile(self.root/name,backup/name)
        archive={'format':1,'items':{record['_source']['source_id']:{'native':record['_native']} for record in self.records},'engines':{}}
        write_encrypted(self.root/'local-source-archive.bin',archive,root=self.root)
        shutil.copyfile(self.root/'local-source-archive.bin',backup/'local-source-archive.bin')
        from local_state import protect
        with closing(sqlite3.connect(self.root/'prepared-sources.sqlite')) as con,con:
            con.execute('CREATE TABLE sources(source_id TEXT PRIMARY KEY,payload BLOB NOT NULL)')
            for record in self.records:
                source=record['_source']['source_id']
                con.execute('INSERT INTO sources VALUES (?,?)',(source,protect(json.dumps({'format':1,'id':source,'native':record['_native']}).encode(),root=self.root)))
        return backup


class ProfileDeleteTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='profile-delete-synthetic-')
        self.addCleanup(temporary.cleanup);self.base=Path(temporary.name).resolve();self.service=Fixture(self.base)
        guard=patch.object(profile_delete,'profile_processes',return_value=[])
        guard.start();self.addCleanup(guard.stop)

    def delete(self,index=0):return profile_delete.delete_profile(self.service,self.service.records[index]['id'])

    def work(self,service=None):
        service=service or self.service;record=service.records[0];state=SyncState(service.store)
        intent=state.intent('1'*32,record['_source']['source_key'],record['id'],'2'*32)
        work=service.root/'.sync-work'/('2'*32);(work/'profile').mkdir(parents=True)
        (work/'profile/first').write_bytes(b'first-synthetic-secret');(work/'profile/second').write_bytes(b'second-synthetic-secret')
        marker=work/'.sync-owner.bin';owner={'format':1,'ownership':state.validate_intent(intent)}
        marker.write_bytes(service.store.pack(owner))
        return work,marker,owner

    def test_encrypted_catalog_and_every_identified_mixed_copy(self):
        service=self.service;record=service.records[0];other=service.records[1];backup=service.mixed()
        exclusive=service.root/'backups'/(record['id']+'-'+'a'*32);shutil.copytree(record['_runtime']['profile_path'],exclusive)
        copying=exclusive.with_name(exclusive.name+'.copying');shutil.copytree(exclusive,copying)
        fingerprints=service.root/'fingerprints'
        for name in (record['id']+'-'+'b'*32+'.bin',record['id']+'-local-'+'c'*32+'-moved-'+'d'*32+'.bin',record['id']+'-'+'e'*32+'.tmp'):
            (fingerprints/name).write_bytes(Path(record['_runtime']['fingerprint_path']).read_bytes())
        other_profile=Path(other['_runtime']['profile_path'])/'Default/Cookies';other_bytes=other_profile.read_bytes()
        with service.store.connect() as con:other_blob=con.execute('SELECT data FROM profiles WHERE id=?',(other['id'],)).fetchone()[0]
        self.assertEqual(self.delete(),{'deleted':True,'cleanup_complete':True})
        self.assertFalse(Path(record['_runtime']['profile_path']).exists());self.assertFalse(exclusive.exists());self.assertFalse(copying.exists())
        self.assertEqual(other_profile.read_bytes(),other_bytes)
        self.assertTrue(all(not delete_stores._signature_name(path.name,record['id']) for path in fingerprints.iterdir()))
        self.assertFalse((backup/'signatures/existing-1.bin').exists());self.assertTrue((backup/'signatures/existing-2.bin').exists())
        for path in (service.root/'windows.sqlite',backup/'renamed-catalog.sqlite'):
            with closing(sqlite3.connect(path)) as con:
                self.assertFalse(con.execute('SELECT 1 FROM profiles WHERE id=?',(record['id'],)).fetchone())
                self.assertEqual(con.execute('SELECT data FROM profiles WHERE id=?',(other['id'],)).fetchone()[0],other_blob)
                self.assertEqual(con.execute('PRAGMA freelist_count').fetchone()[0],0)
        for folder in (service.root,backup):
            self.assertNotIn(record['id'],read_encrypted(folder/'runtime.bin',root=service.root))
            self.assertTrue(all(item['alias']!=record['id'] for item in read_encrypted(folder/'settings.bin',root=service.root)['windows']))
            self.assertNotIn(record['_source']['source_id'],read_encrypted(folder/'local-source-archive.bin',root=service.root)['items'])
        with closing(sqlite3.connect(service.root/'prepared-sources.sqlite')) as con:
            self.assertEqual(con.execute('SELECT count(*) FROM sources').fetchone()[0],2)
        self.assertEqual(profile_delete.get_pending_ids(service.root),set())
        self.assertNotIn(record['id'],service.controller.profiles)
        self.assertTrue(all(not path.exists() for path in service.proxy_runtime.paths(record['id'])))

    def test_batch_scans_and_compacts_each_database_once(self):
        self.service.mixed()
        with patch.object(profile_delete,'make_plan',wraps=delete_stores.make_plan) as make,patch.object(delete_stores,'compact',wraps=delete_stores.compact) as compact:
            result=profile_delete.delete_profiles(self.service,[item['id'] for item in self.service.records[:2]])
        self.assertTrue(result['cleanup_complete']);self.assertEqual(make.call_count,1);self.assertEqual(compact.call_count,3)
        self.assertEqual(len(self.service.store.all()),1)

    def test_legacy_catalog_without_source_bindings_preserves_other_rows(self):
        service=self.service;record=service.records[0];other=service.records[1]
        backup=service.mixed();database=backup/'renamed-catalog.sqlite'
        with closing(sqlite3.connect(database)) as con,con:
            con.execute('DROP TABLE source_bindings')
            unchanged=con.execute('SELECT data FROM profiles WHERE id=?',(other['id'],)).fetchone()[0]
        self.assertTrue(self.delete()['cleanup_complete'])
        with closing(sqlite3.connect(database)) as con:
            self.assertFalse(con.execute('SELECT 1 FROM profiles WHERE id=?',(record['id'],)).fetchone())
            self.assertEqual(con.execute('SELECT data FROM profiles WHERE id=?',(other['id'],)).fetchone()[0],unchanged)
            self.assertEqual(con.execute('SELECT count(*) FROM profiles').fetchone()[0],2)

    def test_existing_malformed_binding_table_is_rejected(self):
        backup=self.service.mixed()
        with closing(sqlite3.connect(backup/'renamed-catalog.sqlite')) as con,con:
            con.execute('DROP TABLE source_bindings');con.execute('CREATE TABLE source_bindings(unrecognized TEXT)')
        with self.assertRaises(DeleteError):self.delete()
        self.assertEqual(len(self.service.store.all()),3)

    def test_similar_id_historical_signature_is_preserved(self):
        service=self.service;first=service.records[0];other=copy.deepcopy(service.records[1]);old=other['id']
        other['id']=first['id']+'-local-'+'a'*32;other['_runtime']['alias']=other['id']
        old_profile=Path(other['_runtime']['profile_path']);new_profile=old_profile.with_name(other['id']);old_profile.rename(new_profile)
        other['_runtime']['profile_path']=str(new_profile)
        with service.store.connect() as con:con.execute('DELETE FROM profiles WHERE id=?',(old,))
        service.store.put(other)
        historic=service.root/'fingerprints'/(other['id']+'-moved-'+'b'*32+'.bin');historic.write_bytes(b'unrelated-history')
        self.assertTrue(self.delete()['cleanup_complete']);self.assertEqual(historic.read_bytes(),b'unrelated-history')

    def test_normal_close_required_and_no_force(self):
        service=self.service;record=service.records[0]
        with patch.object(service,'close',side_effect=RuntimeError('synthetic')):
            with self.assertRaises(DeleteError):self.delete()
        self.assertTrue(Path(record['_runtime']['profile_path']).exists());self.assertEqual(len(service.store.all()),3)
        with patch.object(profile_delete,'profile_processes',return_value=[object()]):
            with self.assertRaises(DeleteError):self.delete()
        self.assertTrue(Path(record['_runtime']['profile_path']).exists())
        self.assertEqual(profile_delete.get_pending_ids(service.root),set())

    def test_worker_lease_refuses_active_sync(self):
        lease=WorkerLease(self.service.root);self.assertTrue(lease.acquire())
        try:
            with self.assertRaises(DeleteError):self.delete()
        finally:lease.release()
        self.assertEqual(len(self.service.store.all()),3)

    def test_catalog_busy_is_pending_partial_and_recoverable(self):
        service=self.service;record=service.records[0]
        reader=sqlite3.connect(service.store.db);reader.execute('BEGIN');reader.execute('SELECT * FROM profiles').fetchall()
        try:
            result=self.delete();self.assertTrue(result['deleted']);self.assertFalse(result['cleanup_complete'])
            self.assertEqual(profile_delete.get_pending_ids(service.root),{record['id']})
            encrypted=(service.root/profile_delete._PENDING).read_bytes();self.assertNotIn(record['id'].encode(),encrypted)
        finally:reader.rollback();reader.close()
        self.assertEqual(profile_delete.recover_pending_deletions(service),{'completed':1,'pending':0})
        self.assertFalse((service.root/profile_delete._PENDING).exists())

    def test_permission_failure_keeps_authenticated_recovery(self):
        service=self.service;record=service.records[0];actual=delete_stores.remove;calls=0
        def fail(path,root):
            nonlocal calls
            calls+=1
            if calls==2:raise PermissionError('synthetic')
            return actual(path,root)
        with patch.object(delete_stores,'remove',side_effect=fail):
            with self.assertRaises(DeleteError):self.delete()
        self.assertTrue(profile_delete.is_pending(service.root,record['id']))
        self.assertEqual(profile_delete.recover_pending_deletions(service),{'completed':1,'pending':0})
        self.assertEqual(len(service.store.all()),2)

    def test_crash_after_catalog_commit_resumes_from_encrypted_plan(self):
        service=self.service;record=service.records[0]
        with patch.object(delete_stores,'compact',side_effect=SystemExit(37)):
            with self.assertRaises(SystemExit):self.delete()
        self.assertEqual(profile_delete.get_pending_ids(service.root),{record['id']})
        self.assertEqual(profile_delete.recover_pending_deletions(service),{'completed':1,'pending':0})

    def test_unknown_mixed_backup_fails_before_deletion(self):
        backup=self.service.root/'backups'/'unrecognized';backup.mkdir(parents=True)
        with closing(sqlite3.connect(backup/'unknown.sqlite')) as con,con:con.execute('CREATE TABLE unrecognized(value TEXT)')
        with self.assertRaises(DeleteError):self.delete()
        self.assertTrue(Path(self.service.records[0]['_runtime']['profile_path']).exists())
        self.assertEqual(profile_delete.get_pending_ids(self.service.root),set())

    def test_current_unmanaged_or_changed_signature_is_rejected(self):
        service=self.service;record=copy.deepcopy(service.records[0]);signature=Path(record['_runtime']['fingerprint_path'])
        changed=signature.with_name('unrecognized-name.bin');shutil.copyfile(signature,changed)
        record['_runtime']['fingerprint_path']=str(changed);service.store.put(record)
        with self.assertRaises(DeleteError):self.delete()
        record['_runtime']['fingerprint_path']=str(signature);service.store.put(record);signature.write_bytes(b'changed')
        with self.assertRaises(DeleteError):self.delete()
        self.assertEqual(len(service.store.all()),3)

    def test_bad_ciphertext_plan_is_never_executed(self):
        (self.service.root/profile_delete._PENDING).write_bytes(b'not-authenticated')
        with self.assertRaises(DeleteError):profile_delete.get_pending_ids(self.service.root)
        with self.assertRaises(DeleteError):self.delete()
        self.assertEqual(len(self.service.store.all()),3)

    def test_authenticated_out_of_bounds_plan_is_rejected(self):
        plan=delete_stores.make_plan(self.service,[self.service.records[0]]);plan['token']='f'*32
        plan['targets'].append('../unrelated')
        write_encrypted(self.service.root/profile_delete._PENDING,{'format':1,'plans':[plan]},root=self.service.root)
        with self.assertRaises(DeleteError):profile_delete.recover_pending_deletions(self.service)
        self.assertEqual(len(self.service.store.all()),3)

    def test_symlink_and_parent_reparse_are_refused(self):
        record=self.service.records[0];profile=Path(record['_runtime']['profile_path']);outside=self.base/'outside';outside.mkdir();(outside/'keep').write_bytes(b'unrelated')
        try:(profile/'linked').symlink_to(outside,target_is_directory=True)
        except OSError:
            if os.name!='nt':self.skipTest('symlink unavailable')
            result=subprocess.run(['cmd','/c','mklink','/J',str(profile/'linked'),str(outside)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if result.returncode:self.skipTest('junction unavailable')
        try:
            with self.assertRaises(DeleteError):self.delete()
            self.assertEqual((outside/'keep').read_bytes(),b'unrelated')
        finally:
            link=profile/'linked'
            if link.is_symlink():link.unlink()
            elif link.exists():link.rmdir()

    def test_shared_extension_and_anonymous_signature_are_preserved(self):
        service=self.service;record=service.records[0];other=copy.deepcopy(service.records[1]);backup=service.mixed()
        other['_runtime']['managed_extension']=record['_runtime']['managed_extension'];other['_native']['DataProtect']=copy.deepcopy(record['_native']['DataProtect'])
        other['_runtime']['fingerprint_sha256']=record['_runtime']['fingerprint_sha256'];service.store.put(other)
        self.assertTrue(self.delete()['cleanup_complete'])
        self.assertTrue(Path(record['_runtime']['managed_extension']).is_dir())
        self.assertTrue((backup/'signatures/existing-1.bin').exists())

    def test_shared_extension_child_and_case_variant_preserve_whole_tree(self):
        for case_variant in (False,True):
            if case_variant and os.name!='nt':continue
            with self.subTest(case_variant=case_variant):
                service=Fixture(self.base/('shared-case-'+str(case_variant)));record=service.records[0];other=copy.deepcopy(service.records[1])
                extension=Path(record['_runtime']['managed_extension']);shared=extension/'shared';shared.mkdir()
                manifest=shared/'manifest.json';manifest.write_bytes(b'other-window-manifest')
                other['_runtime']['managed_extension']=str(shared).upper() if case_variant else str(shared);service.store.put(other)
                self.assertTrue(profile_delete.delete_profile(service,record['id'])['cleanup_complete'])
                self.assertEqual(manifest.read_bytes(),b'other-window-manifest')

    def test_shared_profile_or_backup_child_refuses_deletion_before_changes(self):
        for kind in ('profile','backup'):
            with self.subTest(kind=kind):
                service=Fixture(self.base/('shared-'+kind));record=service.records[0];other=copy.deepcopy(service.records[1])
                folder=Path(record['_runtime']['profile_path'])
                if kind=='backup':
                    backup=service.root/'backups'/(record['id']+'-'+'a'*32);shutil.copytree(folder,backup);folder=backup
                shared=folder/'shared';shared.mkdir();(shared/'keep').write_bytes(b'keep-shared-tree')
                other['_runtime']['managed_extension']=str(shared);service.store.put(other)
                with self.assertRaises(DeleteError):profile_delete.delete_profile(service,record['id'])
                self.assertEqual((shared/'keep').read_bytes(),b'keep-shared-tree')
                self.assertTrue(Path(record['_runtime']['profile_path']).is_dir());self.assertEqual(len(service.store.all()),3)

    def test_resume_rechecks_new_shared_descendant_reference(self):
        service=self.service;record=service.records[0];other=copy.deepcopy(service.records[1])
        plan=delete_stores.make_plan(service,[record]);plan['token']='f'*32
        profile_delete._write_pending(service.root,[plan])
        shared=Path(record['_runtime']['managed_extension'])/'shared';shared.mkdir();(shared/'manifest.json').write_bytes(b'keep')
        other['_runtime']['managed_extension']=str(shared);service.store.put(other)
        self.assertEqual(profile_delete.recover_pending_deletions(service),{'completed':0,'pending':1})
        self.assertEqual((shared/'manifest.json').read_bytes(),b'keep')
        self.assertTrue(Path(record['_runtime']['profile_path']).is_dir())

    def test_legacy_settings_shared_references_are_preserved_at_planning(self):
        for location in ('legacy-settings','temporary-settings'):
            for encoding in ('absolute','data','app'):
                with self.subTest(location=location,encoding=encoding):
                    service=Fixture(self.base/('settings-shared-'+location+'-'+encoding))
                    record=service.records[0];other=service.records[1]
                    extension=Path(record['_runtime']['managed_extension']);shared=extension/'shared';shared.mkdir()
                    manifest=shared/'manifest.json';manifest.write_bytes(b'historical-other-window-manifest')
                    raw=str(shared)
                    if encoding=='data':raw='@data/'+shared.relative_to(service.root).as_posix()
                    if encoding=='app':raw='@app/'+shared.relative_to(service.root.parent).as_posix()
                    backup=service.root/'backups'/'settings-only';backup.mkdir(parents=True)
                    name='settings.bin' if location=='legacy-settings' else 'settings.bin.synthetic.tmp'
                    path=backup/name
                    write_encrypted(path,{'windows':[{'alias':other['id'],'managed_extension':raw}]},root=service.root)
                    with patch.object(delete_stores,'APP_ROOT',service.root.parent):
                        self.assertTrue(profile_delete.delete_profile(service,record['id'])['cleanup_complete'])
                    self.assertEqual(manifest.read_bytes(),b'historical-other-window-manifest')
                    self.assertEqual(read_encrypted(path,root=service.root)['windows'][0]['managed_extension'],raw)

    def test_legacy_settings_shared_profile_child_refuses_before_deletion(self):
        service=self.service;record=service.records[0];other=service.records[1]
        backup=service.root/'backups'/'settings-only';backup.mkdir(parents=True)
        raw='@data/profiles/'+record['id']+'/Default'
        write_encrypted(backup/'settings.bin',{'windows':[{'alias':other['id'],'profile_path':raw}]},root=service.root)
        with self.assertRaises(DeleteError):self.delete()
        self.assertTrue(Path(record['_runtime']['profile_path']).is_dir());self.assertEqual(len(service.store.all()),3)

    def test_resume_rechecks_changed_or_new_temporary_settings_shared_reference(self):
        for new_temporary in (False,True):
            with self.subTest(new_temporary=new_temporary):
                service=Fixture(self.base/('settings-resume-'+str(new_temporary)));record=service.records[0];other=service.records[1]
                backup=service.root/'backups'/'settings-only';backup.mkdir(parents=True)
                path=backup/('settings.bin.new.tmp' if new_temporary else 'settings.bin')
                if not new_temporary:write_encrypted(path,{'windows':[]},root=service.root)
                plan=delete_stores.make_plan(service,[record]);plan['token']='f'*32;profile_delete._write_pending(service.root,[plan])
                shared=Path(record['_runtime']['managed_extension'])/'shared';shared.mkdir();(shared/'manifest.json').write_bytes(b'keep-new-reference')
                write_encrypted(path,{'windows':[{'alias':other['id'],'managed_extension':'@data/extensions/'+record['id']+'/shared'}]},root=service.root)
                self.assertEqual(profile_delete.recover_pending_deletions(service),{'completed':0,'pending':1})
                self.assertEqual((shared/'manifest.json').read_bytes(),b'keep-new-reference')
                self.assertTrue(Path(record['_runtime']['profile_path']).is_dir())
                write_encrypted(path,{'windows':[]},root=service.root)
                self.assertEqual(profile_delete.recover_pending_deletions(service),{'completed':1,'pending':0})

    def test_invalid_portable_settings_reference_is_rejected(self):
        backup=self.service.root/'backups'/'settings-only';backup.mkdir(parents=True)
        write_encrypted(backup/'settings.bin',{'windows':[{'alias':'other-history','managed_extension':'@data/../outside'}]},root=self.service.root)
        with self.assertRaises(DeleteError):self.delete()
        self.assertEqual(len(self.service.store.all()),3)

    def test_authenticated_intent_and_all_sync_candidates_are_removed(self):
        service=self.service;record=service.records[0];state=SyncState(service.store);key=record['_source']['source_key']
        state.create('synthetic-job',[{'source_key':key,'info':{'name':'synthetic secret'}},
                                     {'source_key':service.records[1]['_source']['source_key'],'info':{'name':'keep'}}])
        state.update('synthetic-job',state='interrupted')
        intent=state.intent('1'*32,key,record['id'],'2'*32,('synthetic-job',1))
        work=service.root/'.sync-work'/('2'*32);(work/'profile').mkdir(parents=True)
        (work/'profile/secret').write_bytes(b'target-secret')
        (work/'.sync-owner.bin').write_bytes(service.store.pack({'format':1,'ownership':state.validate_intent(intent)}))
        self.assertTrue(self.delete()['cleanup_complete']);self.assertFalse(work.exists())
        with service.store.connect() as con:
            self.assertEqual(con.execute('SELECT count(*) FROM import_intents').fetchone()[0],0)
            self.assertEqual(con.execute('SELECT count(*) FROM sync_items').fetchone()[0],1)
            self.assertEqual(con.execute('SELECT total FROM sync_jobs').fetchone()[0],1)

    def test_work_owner_survives_partial_child_rmtree_failure_and_crash(self):
        actual=delete_paths.shutil.rmtree
        for crash in (False,True):
            with self.subTest(crash=crash):
                service=Fixture(self.base/('work-failure-'+str(crash)));work,marker,_=self.work(service)
                def fail(path,*args,**kwargs):
                    if Path(path)==work/'profile':
                        (work/'profile/first').unlink()
                        if crash:raise SystemExit(37)
                        raise PermissionError('synthetic partial child removal')
                    return actual(path,*args,**kwargs)
                with patch.object(delete_paths.shutil,'rmtree',side_effect=fail):
                    with self.assertRaises(SystemExit if crash else DeleteError):
                        profile_delete.delete_profile(service,service.records[0]['id'])
                self.assertTrue(marker.exists());self.assertTrue((work/'profile/second').exists())
                self.assertEqual(profile_delete.recover_pending_deletions(service),{'completed':1,'pending':0})
                self.assertFalse(work.exists())

    def test_empty_work_tail_without_marker_recovers_after_final_rmdir_failure(self):
        work,marker,_=self.work();actual=Path.rmdir
        def fail(path):
            if path==work:raise PermissionError('synthetic final directory lock')
            return actual(path)
        with patch.object(Path,'rmdir',fail):
            with self.assertRaises(DeleteError):self.delete()
        self.assertTrue(work.is_dir());self.assertFalse(marker.exists());self.assertEqual(list(work.iterdir()),[])
        self.assertEqual(profile_delete.recover_pending_deletions(self.service),{'completed':1,'pending':0})
        self.assertFalse(work.exists())

    def test_nonempty_missing_or_changed_work_owner_remains_guarded(self):
        service=self.service;work,marker,owner=self.work()
        plan=delete_stores.make_plan(service,[service.records[0]]);plan['token']='f'*32;profile_delete._write_pending(service.root,[plan])
        marker.unlink()
        self.assertEqual(profile_delete.recover_pending_deletions(service),{'completed':0,'pending':1})
        self.assertTrue((work/'profile/first').exists())
        changed=copy.deepcopy(owner);changed['ownership']['work_id']='3'*32;marker.write_bytes(service.store.pack(changed))
        self.assertEqual(profile_delete.recover_pending_deletions(service),{'completed':0,'pending':1})
        self.assertTrue((work/'profile/first').exists())
        marker.write_bytes(service.store.pack(owner))
        self.assertEqual(profile_delete.recover_pending_deletions(service),{'completed':1,'pending':0})

    def test_interrupted_worker_and_settings_temporary_copies_are_pruned(self):
        service=self.service;record=service.records[0]
        request=service.proxy_runtime.paths(record['id'])[0]
        worker_temporary=request.with_name(request.name+'.synthetic.tmp');shutil.copyfile(request,worker_temporary)
        settings_temporary=service.root/'settings.bin.synthetic.tmp';shutil.copyfile(service.root/'settings.bin',settings_temporary)
        self.assertTrue(self.delete()['cleanup_complete']);self.assertFalse(worker_temporary.exists())
        self.assertTrue(all(item['alias']!=record['id'] for item in read_encrypted(settings_temporary,root=service.root)['windows']))

    def test_authenticated_pending_moves_with_complete_portable_folder(self):
        service=self.service;record=service.records[0]
        with patch.object(delete_stores,'compact',side_effect=SystemExit(37)):
            with self.assertRaises(SystemExit):self.delete()
        relocated=self.base/'relocated-data';shutil.copytree(service.root,relocated)
        proxy=relocated/'proxy-runtime'
        moved=SimpleNamespace(root=relocated,store=WindowStore(service.configuration,relocated),configuration=service.configuration,
                              operations=threading.RLock(),close=lambda identity:None,
                              proxy_runtime=SimpleNamespace(stop_if_unused=lambda identity:None,
                                  paths=lambda identity:(proxy/(identity+'.request'),proxy/(identity+'.state'))))
        self.assertEqual(profile_delete.get_pending_ids(relocated),{record['id']})
        self.assertEqual(profile_delete.recover_pending_deletions(moved),{'completed':1,'pending':0})
        self.assertTrue((service.root/profile_delete._PENDING).exists())
        self.assertTrue((relocated/'profiles'/service.records[1]['id']/'Default/Cookies').exists())

    def test_legacy_bootstrap_only_in_explicit_owned_location(self):
        app=self.base/'owned-app';data=app/'data';app.mkdir()
        service=Fixture(app);self.assertEqual(service.root,data)
        bootstrap=self.base/'analysis/private-bootstrap';bootstrap.mkdir(parents=True)
        values=[{'alias':record['id'],'info':{'id':record['_source']['source_id']}} for record in service.records]
        write_encrypted(bootstrap/'selected-settings.bin',values,root=service.root)
        with patch.object(delete_stores,'APP_ROOT',app):
            self.assertTrue(profile_delete.delete_profile(service,service.records[0]['id'])['cleanup_complete'])
        self.assertEqual(len(read_encrypted(bootstrap/'selected-settings.bin',root=service.root)),2)


if __name__=='__main__':unittest.main()
