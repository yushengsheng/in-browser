"""Synthetic-only import queue, identity, crash and commit-outcome checks."""
import copy
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

from local_state import LocalBrowserError
from sync_state import SyncState
from window_store import WindowStore
import window_sync
from window_sync import WindowSynchronizer,source_key


class PlainStore(WindowStore):
    def pack(self,value):return json.dumps(value,separators=(',',':')).encode()
    def unpack(self,value):return json.loads(value)


def record(identity,source_id,name='synthetic'):
    return {'id':identity,'seq':0,'name':name,'created_at':'synthetic','archived':False,
            '_source':{'source_id':source_id,'source_key':source_key(source_id),'provider':'bitbrowser-local-v1','imported_at':'synthetic'}}


def candidate(number,name='synthetic'):
    identity=f'{number:032x}'
    return {'source_id':identity,'source_key':source_key(identity),'profile_path':'synthetic',
            'info':{'id':identity,'name':name,'seq':1},'status':'ready','_snapshot':((1,2,3,4),),'_core_major':'148'}


class Provider:
    def __init__(self,items):self.items=items
    def discover(self):return copy.deepcopy(self.items)
    def revalidate(self,item):
        fresh=next((value for value in self.items if value['source_key']==item['source_key']),None)
        if fresh is None or item!=fresh:raise LocalBrowserError('合成来源已变化。')
        return copy.deepcopy(fresh)


def manifest(folder):
    return {str(path.relative_to(folder)):hashlib.sha256(path.read_bytes()).hexdigest()
            for path in folder.rglob('*') if path.is_file()}


def fixture(root,count=3,*,encrypted=False):
    root=Path(root).resolve();root.mkdir(parents=True,exist_ok=True)
    items=[]
    for number in range(1,count+1):
        item=candidate(number,'相同名称');source=root/'sources'/item['source_id']
        if not source.exists():
            (source/'Default').mkdir(parents=True)
            (source/'Default/Preferences').write_text('{}',encoding='utf-8')
            (source/'proof').write_text(item['source_id'],encoding='ascii')
        item['profile_path']=str(source);items.append(item)
    service=SimpleNamespace(root=root/'local',configuration=SimpleNamespace(independent=True,local_core=lambda core:None),
                            operations=threading.RLock(),_copy_profile=shutil.copytree,_manifest=manifest,
                            _sync=lambda value:None)
    service.root.mkdir(exist_ok=True)
    if encrypted:
        from portable_vault import PortableVault
        PortableVault(service.root).initialize()
    service.store=(WindowStore if encrypted else PlainStore)(service.configuration,service.root)
    with patch.object(window_sync,'APP_ROOT',root/'synthetic-app'):
        sync=WindowSynchronizer(service,Provider(items))
    sync._startup=lambda item:({'info':{'browserFingerPrint':{'coreVersion':'148'}}},{},b'synthetic-signature',{})
    def make_record(item,full,native,proxy,identity,final,config,source_manifest,notes,engine_path=None,*,fingerprint_hash=None):
        value=record(identity,item['source_id'],item['info']['name'])
        value.update(_source_manifest=source_manifest,_source_info={'id':item['source_id']},
                     _runtime={'profile_path':str(final),'fingerprint_path':str(config),'fingerprint_sha256':fingerprint_hash})
        return value
    sync._record=make_record
    return service,sync,items


def crash_fixture(root,stage):
    with patch.object(window_sync,'profile_processes',return_value=[]):
        service,sync,items=fixture(root,count=1)
        publish=sync._publish;commit=service.store.commit_import;copy_profile=service._copy_profile
        calls=0
        def copied(*args,**kwargs):
            result=copy_profile(*args,**kwargs)
            if stage=='copying':os._exit(37)
            return result
        def published(*args):
            nonlocal calls
            publish(*args);calls+=1
            if (stage=='profile_published' and calls==1) or (stage=='signature_published' and calls==2):os._exit(37)
        def committed(*args,**kwargs):
            commit(*args,**kwargs)
            if stage=='committed':os._exit(37)
        service._copy_profile=copied;sync._publish=published;service.store.commit_import=committed
        if stage=='prepared':sync._complete_intent=lambda intent:os._exit(37)
        job=sync.start([items[0]['source_key']]);sync.worker.join(20)
        raise AssertionError('Crash checkpoint was not reached')


class SyncReliabilityTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='sync-reliability-')
        self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve()
        guard=patch.object(window_sync,'profile_processes',return_value=[])
        guard.start();self.addCleanup(guard.stop)

    def wait(self,sync):
        sync.worker.join(30)
        self.assertFalse(sync.worker.is_alive())
        return sync.status(sync.active)

    def test_public_preview_is_read_only_and_start_requires_its_receipt(self):
        from api import dispatch
        service,sync,items=fixture(self.root,count=1)
        service.synchronizer=lambda:sync
        before=manifest(service.root)
        with patch.object(service,'_copy_profile',side_effect=AssertionError('Unexpected copy')):
            preview=dispatch(service,'sync_preview')['data']
            self.assertEqual(preview['counts']['ready'],1)
            self.assertEqual(preview['expires_in'],600)
            self.assertEqual(manifest(service.root),before)
            self.assertIsNone(sync.latest())
            for payload in ({},{'source_keys':[items[0]['source_key']]},
                            {'source_keys':[items[0]['source_key']],'preview_id':'wrong'}):
                self.assertFalse(dispatch(service,'sync_windows',payload)['ok'])
            self.assertIsNone(sync.latest())
            self.assertEqual(service.store.all(),[])

    def test_expired_or_replaced_preview_and_changed_source_refuse_before_job_creation(self):
        service,sync,items=fixture(self.root,count=1)
        keys=[items[0]['source_key']]
        first=sync.preview()['preview_id'];second=sync.preview()['preview_id']
        with self.assertRaises(LocalBrowserError):sync.start(keys,preview_id=first)
        with patch.object(window_sync.time,'monotonic',return_value=sync.preview_created+601):
            with self.assertRaises(LocalBrowserError):sync.start(keys,preview_id=second)
        for change in ('_snapshot','profile_path','info','status'):
            sync.provider=Provider(copy.deepcopy(items));preview=sync.preview()
            if change=='info':sync.provider.items[0]['info']['name']='changed'
            else:sync.provider.items[0][change]='changed'
            with self.assertRaises(LocalBrowserError):sync.start(keys,preview_id=preview['preview_id'])
            self.assertIsNone(sync.latest())
        sync.provider=Provider(copy.deepcopy(items));preview=sync.preview()
        service.store.commit_import(record('synthetic',items[0]['source_id']),keys[0])
        with self.assertRaises(LocalBrowserError):sync.start(keys,preview_id=preview['preview_id'])
        self.assertIsNone(sync.latest())

    def test_confirmed_start_is_idempotent_after_finish_and_rejects_changed_selection(self):
        service,sync,items=fixture(self.root,count=2)
        preview=sync.preview();keys=[items[0]['source_key']]
        job=sync.start(keys,preview_id=preview['preview_id']);status=self.wait(sync)
        self.assertEqual(status['completed'],1)
        self.assertEqual(sync.start(keys,preview_id=preview['preview_id']),job)
        with self.assertRaises(LocalBrowserError):sync.start([items[1]['source_key']],preview_id=preview['preview_id'])
        self.assertEqual(len(service.store.all()),1)
        next_preview=sync.preview()
        self.assertEqual(next_preview['counts']['ready'],1)
        sync.start([items[1]['source_key']],preview_id=next_preview['preview_id'])
        self.assertEqual(self.wait(sync)['completed'],1)

    def test_cancelled_confirmed_start_retry_preserves_cancelled_job(self):
        service,sync,items=fixture(self.root,count=1)
        preview=sync.preview();keys=[items[0]['source_key']]
        with patch.object(sync,'_launch',side_effect=lambda identity:setattr(sync,'active',identity)):
            job=sync.start(keys,preview_id=preview['preview_id'])
        sync.cancel(job['job_id']);sync._run(job['job_id'])
        self.assertEqual(sync.status(job['job_id'])['state'],'cancelled')
        self.assertEqual(sync.start(keys,preview_id=preview['preview_id']),job)
        self.assertEqual(service.store.all(),[])

    def test_failed_redetection_invalidates_previous_receipt(self):
        _,sync,items=fixture(self.root,count=1)
        preview=sync.preview()
        with patch.object(sync.provider,'discover',side_effect=LocalBrowserError('Synthetic unavailable')):
            with self.assertRaises(LocalBrowserError):sync.preview()
        with self.assertRaises(LocalBrowserError):sync.start([items[0]['source_key']],preview_id=preview['preview_id'])
        self.assertIsNone(sync.latest())

    def junction(self,link,target):
        if os.name=='nt':
            result=subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],
                                  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            self.assertEqual(result.returncode,0)
        else:link.symlink_to(target,target_is_directory=True)
        self.addCleanup(lambda:self.remove_junction(link))

    @staticmethod
    def remove_junction(link):
        if os.path.lexists(link) and (link.is_symlink() or getattr(link.lstat(),'st_file_attributes',0)&0x400):
            if os.name=='nt':link.rmdir()
            else:link.unlink()

    def test_10000_sources_use_9999_then_one_and_status_is_bounded(self):
        service,sync,_=fixture(self.root,count=0)
        items=[candidate(number,'same' if number%2 else 'another') for number in range(1,10001)]
        sync.provider=Provider(items);preview=sync.preview()
        self.assertEqual(preview['counts']['ready'],10000)
        with self.assertRaises(LocalBrowserError):sync.start([item['source_key'] for item in items])
        with patch.object(sync,'_launch',side_effect=lambda identity:setattr(sync,'active',identity)):
            job=sync.start([item['source_key'] for item in items[:9999]])
        sync.lease.release();state=sync.state
        self.assertEqual(state.status(job['job_id'])['total'],9999)
        # Complete this catalog-only stress fixture in one transaction; the actual
        # filesystem and per-window transaction paths are exercised separately.
        with service.store.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            for ordinal,item in enumerate(items[:9999],1):
                value=record('synthetic-'+str(ordinal),item['source_id'])
                WindowStore.validate_import_source(value,item['source_key'])
                con.execute('INSERT INTO profiles VALUES (?,?,?,?,?,?)',(value['id'],ordinal,'synthetic',None,0,service.store.pack(value)))
                con.execute('INSERT INTO source_bindings VALUES (?,?,?)',(item['source_key'],value['id'],'synthetic'))
                SyncState.complete_item(con,job['job_id'],ordinal,'completed','synthetic')
        state.update(job['job_id'],state='completed')
        status=state.status(job['job_id'])
        self.assertEqual((status['completed'],status['items_total'],len(status['items'])),(9999,9999,100))
        self.assertLess(len(json.dumps(status)),40000)
        seen=[];after=0
        while True:
            page=state.status(job['job_id'],after=after)
            if not page['items']:break
            seen.extend(item['source_key'] for item in page['items']);after=page['next_cursor']
        self.assertEqual(seen,[item['source_key'] for item in items[:9999]])
        self.assertEqual(len(set(seen)),9999)
        pending=list(state.pending(job['job_id']))
        self.assertEqual(pending,[])
        with patch.object(sync,'_launch',side_effect=lambda identity:setattr(sync,'active',identity)):
            remainder=sync.start([items[-1]['source_key']])
        sync.lease.release()
        service.store.commit_import(record('synthetic-10000',items[-1]['source_id']),items[-1]['source_key'])
        state.finish_item(remainder['job_id'],1,'completed','synthetic');state.update(remainder['job_id'],state='completed')
        bindings=service.store.source_bindings()
        self.assertEqual(len(bindings),10000)
        self.assertEqual(len(set(bindings.values())),10000)
        self.assertTrue(all(bindings[item['source_key']]=='synthetic-'+str(index) for index,item in enumerate(items,1)))

    def test_same_names_distinct_ids_and_repeated_id_do_not_cross(self):
        service,sync,items=fixture(self.root)
        sync.preview();sync.start([item['source_key'] for item in items]);status=self.wait(sync)
        self.assertEqual((status['completed'],status['failed']),(3,0))
        bindings=service.store.source_bindings();self.assertEqual(len(set(bindings.values())),3)
        for item in items:
            saved=service.store.get(bindings[item['source_key']])
            self.assertEqual((Path(saved['_runtime']['profile_path'])/'proof').read_text(),item['source_id'])
        changed=copy.deepcopy(items);changed[0]['info']['name']='renamed';sync.provider=Provider(changed)
        sync.preview();sync.start([item['source_key'] for item in changed]);status=self.wait(sync)
        self.assertEqual((status['completed'],status['skipped']),(0,3))
        self.assertEqual(service.store.source_bindings(),bindings)
        self.assertEqual(service.store.get(bindings[items[0]['source_key']])['name'],'相同名称')

    def test_preview_uses_one_binding_read_and_rejects_conflicting_duplicate(self):
        service,sync,items=fixture(self.root,count=1)
        conflict=copy.deepcopy(items[0]);conflict['profile_path']='different';conflict['info']['name']='different'
        sync.provider=Provider([items[0],conflict])
        with patch.object(service.store,'source_binding',side_effect=AssertionError('N queries')):
            result=sync.preview()
        self.assertEqual(len(result['items']),1)
        self.assertEqual(result['items'][0]['status'],'unsupported')
        sync.start([items[0]['source_key']]);status=self.wait(sync)
        self.assertEqual((status['skipped'],status['completed']),(1,0))
        self.assertEqual(service.store.source_bindings(),{})

    def test_source_identity_mismatch_rolls_back_and_concurrent_commit_is_unique(self):
        service,_,items=fixture(self.root,count=1);store=service.store;source_id=items[0]['source_id']
        wrong=record('wrong',source_id);wrong['_source_info']={'id':f'{99:032x}'}
        with self.assertRaises(LocalBrowserError):store.commit_import(wrong,source_key(source_id))
        self.assertEqual(store.all(),[])
        other=PlainStore(SimpleNamespace(),store.root);barrier=threading.Barrier(2);outcomes=[]
        def commit(target,identity):
            try:
                barrier.wait();target.commit_import(record(identity,source_id),source_key(source_id));outcomes.append('success')
            except LocalBrowserError:outcomes.append('duplicate')
        threads=[threading.Thread(target=commit,args=(target,identity)) for target,identity in ((store,'a'),(other,'b'))]
        for thread in threads:thread.start()
        for thread in threads:thread.join(10);self.assertFalse(thread.is_alive())
        self.assertCountEqual(outcomes,['success','duplicate'])
        self.assertEqual((len(store.all()),len(store.source_bindings())),(1,1))

    def test_binding_insert_failure_rolls_back_the_profile_and_group(self):
        service,_,items=fixture(self.root,count=1);store=service.store
        with store.connect() as con:
            con.execute("CREATE TRIGGER synthetic_binding_failure BEFORE INSERT ON source_bindings BEGIN SELECT RAISE(ABORT,'synthetic'); END")
        value=record('synthetic',items[0]['source_id']);value['group']='synthetic-group'
        with self.assertRaises(sqlite3.IntegrityError):store.commit_import(value,items[0]['source_key'])
        self.assertEqual(store.all(),[]);self.assertEqual(store.source_bindings(),{})
        self.assertEqual(store.setting('groups',[]),[])

    def test_queue_names_and_candidates_use_the_existing_directory_encryption(self):
        from portable_vault import PortableVault
        root=self.root/'encrypted';root.mkdir();PortableVault(root).initialize()
        store=WindowStore(SimpleNamespace(),root);state=SyncState(store)
        item=candidate(1,'synthetic-private-name');state.create('synthetic-job',[item])
        with store.connect() as con:
            name,stored=con.execute('SELECT name,candidate FROM sync_items').fetchone()
        self.assertNotIn(b'synthetic-private-name',name)
        self.assertNotIn(b'synthetic-private-name',stored)
        self.assertEqual(state.status('synthetic-job')['total'],1)
        restored=next(state.pending('synthetic-job'))[1]
        self.assertEqual(restored,item)

    def test_transaction_failure_and_uncertain_commit_recover_without_deleting(self):
        service,sync,items=fixture(self.root,count=1);key=items[0]['source_key']
        commit=service.store.commit_import
        with patch.object(service.store,'commit_import',side_effect=OSError('synthetic')):
            sync.preview();sync.start([key]);status=self.wait(sync)
        self.assertEqual(status['failed'],1);self.assertEqual(service.store.source_bindings(),{})
        self.assertEqual(len(list((service.root/'profiles').iterdir())),1)
        sync._recover_intents(key)
        self.assertIsNotNone(service.store.source_binding(key))
        self.assertEqual(len(list((service.root/'profiles').iterdir())),1)
        self.assertEqual(sync.status(sync.active)['completed'],1)
        self.assertEqual(sync.status(sync.active)['failed'],0)
        # A different source whose commit succeeded but whose caller lost its reply.
        service2,sync2,items2=fixture(self.root/'uncertain',count=1)
        original=service2.store.commit_import
        def uncertain(*args,**kwargs):original(*args,**kwargs);raise OSError('synthetic lost acknowledgement')
        with patch.object(service2.store,'commit_import',side_effect=uncertain):
            sync2.preview();sync2.start([items2[0]['source_key']]);status=self.wait(sync2)
        self.assertEqual((status['completed'],status['failed']),(1,0))
        saved=service2.store.get(service2.store.source_binding(items2[0]['source_key']))
        self.assertTrue(Path(saved['_runtime']['profile_path']).is_dir())
        self.assertEqual(list(sync2.state.intents()),[])

    def test_post_commit_runtime_and_cleanup_failures_are_warnings(self):
        service,sync,items=fixture(self.root,count=1)
        service._sync=lambda value:(_ for _ in ()).throw(OSError('synthetic'))
        with patch.object(sync,'_clean_work',side_effect=OSError('synthetic cleanup')):
            sync.preview();sync.start([items[0]['source_key']]);status=self.wait(sync)
        self.assertEqual((status['completed'],status['failed'],status['warnings_total']),(1,0,2))
        self.assertEqual(len(service.store.all()),1)
        service._sync=lambda value:None;sync._recover_intents()
        self.assertEqual(list(sync.state.intents()),[])

    def copying_work(self,folder):
        service,sync,items=fixture(folder,count=1,encrypted=True)
        intent=sync.state.intent('a'*32,items[0]['source_key'],'profile-'+'b'*32,'c'*32)
        work,_,_=sync._intent_paths(intent);work.mkdir(parents=True)
        marker=work/'.sync-owner.bin'
        marker.write_bytes(service.store.pack({'format':1,'ownership':sync.state.validate_intent(intent)}))
        (work/'profile').mkdir();(work/'profile/proof').write_bytes(b'synthetic')
        (work/'fingerprint.bin').write_bytes(b'synthetic-signature')
        return service,sync,intent,work,marker

    def test_copying_cleanup_keeps_owner_until_every_child_is_removed(self):
        actual=os.unlink
        for crash in (False,True):
            with self.subTest(crash=crash):
                _,sync,intent,work,marker=self.copying_work(self.root/str(crash))
                def fail(path,*args,**kwargs):
                    if Path(path).name=='fingerprint.bin':
                        if crash:raise SystemExit(37)
                        raise PermissionError('synthetic signature lock')
                    return actual(path,*args,**kwargs)
                with patch.object(os,'unlink',side_effect=fail):
                    with self.assertRaises(SystemExit if crash else PermissionError):sync._clean_work(intent)
                self.assertTrue(marker.is_file());self.assertTrue((work/'fingerprint.bin').is_file())
                sync._recover_intents(intent['source_key'])
                self.assertFalse(work.exists());self.assertEqual(list(sync.state.intents()),[])

    def test_copying_cleanup_recovers_empty_tail_after_final_rmdir_failure(self):
        _,sync,intent,work,marker=self.copying_work(self.root)
        actual=os.rmdir
        def fail(path,*args,**kwargs):
            if Path(path)==work:raise PermissionError('synthetic final directory lock')
            return actual(path,*args,**kwargs)
        with patch.object(os,'rmdir',side_effect=fail):
            with self.assertRaises(PermissionError):sync._clean_work(intent)
        self.assertTrue(work.is_dir());self.assertFalse(marker.exists());self.assertEqual(list(work.iterdir()),[])
        sync._recover_intents(intent['source_key'])
        self.assertFalse(work.exists());self.assertEqual(list(sync.state.intents()),[])

    def test_copying_cleanup_rejects_nonempty_missing_or_changed_owner(self):
        service,sync,intent,work,marker=self.copying_work(self.root)
        original=marker.read_bytes();marker.unlink()
        with self.assertRaises(LocalBrowserError):sync._recover_intents(intent['source_key'])
        changed=copy.deepcopy(service.store.unpack(original));changed['ownership']['work_id']='d'*32
        marker.write_bytes(service.store.pack(changed))
        with self.assertRaises(LocalBrowserError):sync._recover_intents(intent['source_key'])
        self.assertTrue((work/'profile/proof').is_file());self.assertTrue((work/'fingerprint.bin').is_file())
        marker.write_bytes(original);sync._recover_intents(intent['source_key'])
        self.assertFalse(work.exists());self.assertEqual(list(sync.state.intents()),[])

    def test_cancel_is_constant_size_and_stops_only_following_items(self):
        service,sync,items=fixture(self.root,count=3);entered=threading.Event();release=threading.Event()
        copy_profile=service._copy_profile
        def copying(*args):entered.set();release.wait(10);return copy_profile(*args)
        service._copy_profile=copying;sync.preview();job=sync.start([item['source_key'] for item in items])
        self.assertTrue(entered.wait(5));sync.cancel(job['job_id']);release.set()
        with patch.object(sync,'status',side_effect=AssertionError('Cancellation must not copy history')):
            sync.worker.join(20)
        status=sync.state.status(job['job_id'])
        self.assertEqual((status['state'],status['completed'],len(service.store.all())),('cancelled',1,1))

    def test_restart_marks_interrupted_and_can_resume_or_cancel(self):
        service,sync,items=fixture(self.root,count=3)
        job='synthetic-job';sync.state.create(job,items)
        sync.state.begin_item(job,1)
        with patch.object(window_sync,'APP_ROOT',self.root/'synthetic-app'):
            restarted=WindowSynchronizer(service,Provider(items))
        self.assertEqual(restarted.latest()['state'],'interrupted')
        restarted._startup=sync._startup;restarted._record=sync._record
        restarted.resume(job);status=self.wait(restarted)
        self.assertEqual((status['job_id'],status['completed'],status['failed']),(job,3,0))
        second='synthetic-cancel';restarted.state.create(second,items);restarted.state.interrupt_running()
        restarted.cancel(second);self.assertEqual(restarted.status(second)['state'],'cancelled')

    def test_terminal_status_cannot_start_a_second_worker_before_lease_release(self):
        service,sync,items=fixture(self.root,count=1);entered=threading.Event();release=threading.Event()
        update=sync._update
        def finishing(identity,**values):
            update(identity,**values)
            if values.get('state')=='completed':entered.set();release.wait(10)
        sync._update=finishing;sync.preview();job=sync.start([items[0]['source_key']])
        self.assertTrue(entered.wait(5))
        try:
            self.assertEqual(sync.start([items[0]['source_key']]),job)
            with patch.object(window_sync,'APP_ROOT',self.root/'synthetic-app'):
                second=WindowSynchronizer(service,Provider(items))
            second.preview()
            with self.assertRaises(LocalBrowserError):second.start([items[0]['source_key']])
        finally:release.set()
        status=self.wait(sync);self.assertEqual(status['completed'],1)

    def test_os_crash_at_each_publication_boundary_recovers_precisely(self):
        for stage in ('copying','prepared','profile_published','signature_published','committed'):
            with self.subTest(stage=stage):
                root=self.root/stage
                result=subprocess.run([sys.executable,'-B',str(Path(__file__).resolve()),'--crash-fixture',str(root),stage],
                                      stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
                self.assertEqual(result.returncode,37)
                service,sync,items=fixture(root,count=1)
                status=sync.latest();self.assertEqual(status['state'],'interrupted')
                if stage=='copying':
                    self.assertEqual(len(service.store.all()),0)
                    sync.resume(status['job_id']);status=self.wait(sync)
                self.assertEqual(len(service.store.all()),1)
                self.assertEqual(sync.status(status['job_id'])['completed'],1)
                saved=service.store.get(service.store.source_binding(items[0]['source_key']))
                self.assertEqual((Path(saved['_runtime']['profile_path'])/'proof').read_text(),items[0]['source_id'])
                self.assertEqual(list(sync.state.intents()),[])

    def test_unknown_directories_are_never_cleaned_and_mismatch_is_preserved(self):
        service,sync,_=fixture(self.root,count=0)
        unknown=service.root/'.sync-work'/'unknown';unknown.mkdir(parents=True)
        (unknown/'keep').write_text('keep')
        sync._recover_intents();self.assertTrue((unknown/'keep').is_file())
        root=self.root/'tampered'
        result=subprocess.run([sys.executable,'-B',str(Path(__file__).resolve()),'--crash-fixture',str(root),'profile_published'],
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        self.assertEqual(result.returncode,37)
        published=next((root/'local/profiles').iterdir());(published/'proof').write_text('tampered')
        service2,sync2,_=fixture(root,count=1)
        self.assertEqual(service2.store.all(),[])
        self.assertEqual((published/'proof').read_text(),'tampered')
        self.assertEqual(len(list(sync2.state.intents())),1)

    def test_preexisting_managed_parent_junctions_never_receive_profile_data(self):
        for parent in ('.sync-work','profiles','fingerprints'):
            with self.subTest(parent=parent):
                root=self.root/parent.replace('.','');service,sync,items=fixture(root,count=1,encrypted=True)
                external=root/'external';external.mkdir();self.junction(service.root/parent,external)
                before=manifest(Path(items[0]['profile_path']))
                with patch.object(service,'_copy_profile',wraps=service._copy_profile) as copied:
                    sync.preview();sync.start([items[0]['source_key']]);status=self.wait(sync)
                self.assertEqual((status['completed'],status['failed']),(0,1));copied.assert_not_called()
                self.assertEqual(list(external.iterdir()),[])
                self.assertEqual(service.store.source_bindings(),{})
                self.assertEqual(manifest(Path(items[0]['profile_path'])),before)

    def test_publication_rechecks_parents_after_mkdir_and_between_renames(self):
        for stage in ('mkdir','between-renames'):
            with self.subTest(stage=stage):
                root=self.root/stage;service,sync,items=fixture(root,count=1,encrypted=True)
                external=root/'external';external.mkdir();link=service.root/('profiles' if stage=='mkdir' else 'fingerprints')
                if stage=='mkdir':
                    original_mkdir=Path.mkdir
                    def mkdir(path,*args,**kwargs):
                        result=original_mkdir(path,*args,**kwargs)
                        if path==link and not os.path.islink(path) and not getattr(path.lstat(),'st_file_attributes',0)&0x400:
                            path.rmdir();self.junction(path,external)
                        return result
                    guard=patch.object(Path,'mkdir',new=mkdir)
                else:
                    publish=sync._publish;calls=[]
                    def published(source,target):
                        publish(source,target);calls.append(target)
                        if len(calls)==1:link.rmdir();self.junction(link,external)
                    guard=patch.object(sync,'_publish',side_effect=published)
                with guard:
                    sync.preview();sync.start([items[0]['source_key']]);status=self.wait(sync)
                self.assertEqual((status['completed'],status['failed']),(0,1))
                self.assertEqual(list(external.iterdir()),[])
                self.assertEqual(service.store.source_bindings(),{})
                self.remove_junction(link);sync._recover_intents()
                self.assertEqual(len(service.store.source_bindings()),1)

    def test_unauthenticated_copying_journal_never_claims_an_unknown_directory(self):
        service,sync,items=fixture(self.root,count=1,encrypted=True)
        unknown=service.root/'.sync-work'/('d'*32);unknown.mkdir(parents=True)
        (unknown/'keep').write_bytes(b'synthetic-unrelated')
        with service.store.connect() as con:
            con.execute('INSERT INTO import_intents(intent_id,source_key,profile_id,work_id,state) VALUES (?,?,?,?,?)',
                        ('a'*32,items[0]['source_key'],'profile-'+'b'*32,'d'*32,'copying'))
        sync._recover_intents()
        self.assertEqual((unknown/'keep').read_bytes(),b'synthetic-unrelated')
        self.assertEqual(len(list(sync.state.intents())),1)
        with self.assertRaises(LocalBrowserError):sync.state.get_intent('a'*32)

    def test_copying_journal_binds_every_identity_field_with_production_vault(self):
        changes={'intent_id':'f'*32,'source_key':source_key(f'{99:032x}'),'profile_id':'profile-'+'e'*32,
                 'work_id':'d'*32,'job_id':'different-job','ordinal':2}
        for field,value in changes.items():
            with self.subTest(field=field):
                service,sync,items=fixture(self.root/field,count=1,encrypted=True)
                intent=sync.state.intent('a'*32,items[0]['source_key'],'profile-'+'b'*32,'c'*32)
                work,_,_=sync._intent_paths(intent);work.mkdir(parents=True)
                (work/'.sync-owner.bin').write_bytes(service.store.pack({'format':1,'ownership':sync.state.validate_intent(intent)}))
                (work/'own').write_bytes(b'owned')
                unknown=work.parent/('d'*32);unknown.mkdir();(unknown/'keep').write_bytes(b'unrelated')
                with service.store.connect() as con:
                    original=con.execute('SELECT data FROM import_intents').fetchone()[0]
                    self.assertNotIn(('c'*32).encode(),original)
                    con.execute('UPDATE import_intents SET '+field+'=?',(value,))
                sync._recover_intents()
                self.assertEqual((work/'own').read_bytes(),b'owned')
                self.assertEqual((unknown/'keep').read_bytes(),b'unrelated')
                self.assertTrue(next(sync.state.intents())['_authentication_failed'])

    def test_prepared_journal_tamper_or_replay_cannot_delete_unrelated_work(self):
        for mutation in ('work_id','replay','ciphertext'):
            with self.subTest(mutation=mutation):
                service,sync,items=fixture(self.root/mutation,count=1,encrypted=True)
                with patch.object(sync,'_complete_intent',side_effect=LocalBrowserError('synthetic hold')):
                    sync.preview();sync.start([items[0]['source_key']]);status=self.wait(sync)
                self.assertEqual(status['failed'],1);intent=next(sync.state.intents())
                work,_,_=sync._intent_paths(intent)
                unknown=work.parent/('d'*32);unknown.mkdir();(unknown/'keep').write_bytes(b'unrelated')
                with service.store.connect() as con:
                    if mutation=='work_id':con.execute('UPDATE import_intents SET work_id=?',('d'*32,))
                    elif mutation=='replay':
                        data=con.execute('SELECT data FROM import_intents').fetchone()[0]
                        con.execute('INSERT INTO import_intents(intent_id,source_key,profile_id,work_id,state,data) VALUES (?,?,?,?,?,?)',
                                    ('a'*32,items[0]['source_key'],'profile-'+'b'*32,'d'*32,'prepared',data))
                        con.execute('DELETE FROM import_intents WHERE intent_id=?',(intent['intent_id'],))
                    else:
                        data=bytearray(con.execute('SELECT data FROM import_intents').fetchone()[0]);data[-1]^=1
                        con.execute('UPDATE import_intents SET data=?',(bytes(data),))
                sync._recover_intents()
                self.assertEqual((unknown/'keep').read_bytes(),b'unrelated')
                self.assertTrue((work/'profile/proof').is_file())
                self.assertEqual(service.store.source_bindings(),{})
                self.assertTrue(next(sync.state.intents())['_authentication_failed'])

    def test_preexisting_work_directory_is_not_owned_by_a_new_authenticated_intent(self):
        service,sync,items=fixture(self.root,count=1,encrypted=True)
        unknown=service.root/'.sync-work'/('c'*32);unknown.mkdir(parents=True);(unknown/'keep').write_bytes(b'unrelated')
        values=[SimpleNamespace(hex=value*32) for value in ('e','b','c','a')]
        with patch.object(window_sync.uuid,'uuid4',side_effect=values):
            sync.preview();sync.start([items[0]['source_key']]);status=self.wait(sync)
        self.assertEqual((status['completed'],status['failed']),(0,1))
        self.assertEqual((unknown/'keep').read_bytes(),b'unrelated')
        self.assertEqual(list(sync.state.intents()),[])
        # Even a trusted caller creating an authenticated row cannot claim an
        # existing directory without the marker written after exclusive mkdir.
        sync.state.intent('f'*32,items[0]['source_key'],'profile-'+'d'*32,'c'*32)
        sync._recover_intents()
        self.assertEqual((unknown/'keep').read_bytes(),b'unrelated')


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash-fixture':crash_fixture(sys.argv[2],sys.argv[3])
    else:unittest.main()
