"""Bounded parallel import tests using synthetic profiles and isolated databases."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
sys.path.insert(0,str(ROOT/'tests'))

from import_progress import emit, _observer
from local_state import LocalBrowserError
from sync_executor import run_bounded
from sync_state import SyncState, WorkerLease
from test_sync_reliability import fixture, Provider
import sync_executor
import window_sync
from window_sync import WindowSynchronizer


class SyncParallelTests(unittest.TestCase):
    def setUp(self):
        base=ROOT/'analysis/test-runs';base.mkdir(parents=True,exist_ok=True)
        # Validate cleanup at the actual test location before creating fixtures.
        with tempfile.TemporaryDirectory(prefix='sync-parallel-probe-',dir=base) as name:
            probe=Path(name).resolve()
            self.assertTrue(probe.is_relative_to(base.resolve()))
            (probe/'nested').mkdir();(probe/'nested/proof').write_bytes(b'synthetic')
        self.assertFalse(probe.exists())
        self.temporary=tempfile.TemporaryDirectory(prefix='sync-parallel-',dir=base)
        self.root=Path(self.temporary.name).resolve()
        (self.root/'owner.json').write_text(json.dumps({'pid':os.getpid(),'owner':'sync-parallel-synthetic'}))
        self.workers=[]
        self.addCleanup(self.cleanup)
        guard=patch.object(window_sync,'profile_processes',return_value=[])
        guard.start();self.addCleanup(guard.stop)

    def cleanup(self):
        for worker in self.workers:
            worker.join(15)
            self.assertFalse(worker.is_alive())
        self.assertTrue(self.root.is_relative_to((ROOT/'analysis/test-runs').resolve()))
        self.assertFalse(any(path.is_symlink() or getattr(path.lstat(),'st_file_attributes',0)&0x400
                             for path in (self.root,*self.root.rglob('*'))))
        self.temporary.cleanup()
        self.assertFalse(self.root.exists())

    def start(self,sync,items):
        sync.preview();job=sync.start([item['source_key'] for item in items])
        self.workers.append(sync.worker)
        return job['job_id']

    def wait(self,sync):
        sync.worker.join(25);self.assertFalse(sync.worker.is_alive())
        return sync.status(sync.active)

    def blocking_copy(self,service,sync,total=5):
        entered=threading.Event();release=threading.Event();lock=threading.Lock()
        actual=service._copy_profile;started=[]
        def copy(source,target):
            job,index=sync._job_item
            with lock:
                started.append((job,index))
                if len(started)==total:entered.set()
            emit('copying',done=index,total=100,unit='bytes')
            if not release.wait(15):raise RuntimeError('synthetic barrier timeout')
            return actual(source,target)
        service._copy_profile=copy
        self.addCleanup(release.set)
        return entered,release,started

    def extension_fixture(self,label):
        service,sync,items=fixture(self.root/label,count=2)
        original=self.root/label/'shared-extension';original.mkdir()
        (original/'manifest.json').write_text(json.dumps({'manifest_version':3,'name':'Synthetic shared extension','version':'1.0'}),encoding='utf-8')
        (original/'background.js').write_text('/* synthetic only */',encoding='utf-8')
        expected=service._manifest(original)
        digest=hashlib.sha256(json.dumps(expected,sort_keys=True).encode()).hexdigest()
        asset=service.root/'assets/extensions'/digest
        paths=[]
        for index,item in enumerate(items):
            source=Path(item['profile_path'])
            (source/'Default/Preferences').write_text(json.dumps({'extensions':{'settings':{
                'synthetic':{'state':1,'path':str(original)}}}}),encoding='utf-8')
            token=f'{index+1:032x}'
            intent=sync.state.intent(token,item['source_key'],'profile-'+token,token)
            work,final,_=sync._intent_paths(intent);work.mkdir(parents=True)
            (work/'.sync-owner.bin').write_bytes(service.store.pack({'format':1,'ownership':sync.state.validate_intent(intent)}))
            staged=work/'profile';service._copy_profile(source,staged)
            paths.append((source,staged,final))
        return service,sync,original,asset,expected,paths

    def test_two_items_share_one_verified_extension_publication(self):
        from profile_copy import copy_profile
        service,sync,original,asset,expected,paths=self.extension_fixture('shared-asset')
        entered=threading.Event();release=threading.Event();second_waiting=threading.Event()
        actual_lock=sync._asset_lock;counts_lock=threading.Lock();attempts=[];copies=[];verified=[]
        class ObservedLock:
            def __enter__(self):
                with counts_lock:
                    attempts.append(threading.get_ident())
                    if len(attempts)==2:second_waiting.set()
                actual_lock.acquire()
            def __exit__(self,*_):actual_lock.release()
        sync._asset_lock=ObservedLock()
        manifest=service._manifest
        def checked(folder):
            result=manifest(folder)
            if Path(folder)==asset:
                with counts_lock:verified.append(result)
            return result
        def copy(source,target):
            self.assertEqual((Path(source),Path(target)),(original,paths[0][1].parent/'extension-assets'/asset.name))
            with counts_lock:copies.append(Path(target))
            entered.set()
            if not release.wait(10):raise RuntimeError('synthetic asset publication timeout')
            return copy_profile(source,target)
        service._manifest=checked;service._copy_profile=copy
        with ThreadPoolExecutor(max_workers=2) as pool:
            first=pool.submit(sync._extensions,*paths[0])
            try:
                self.assertTrue(entered.wait(5))
                second=pool.submit(sync._extensions,*paths[1])
                self.assertTrue(second_waiting.wait(5))
                with counts_lock:self.assertEqual((len(copies),len(verified)),(1,0))
                self.assertFalse(first.done());self.assertFalse(second.done())
            finally:release.set()
            first.result(timeout=10);second.result(timeout=10)
        self.assertEqual((copies,verified),([paths[0][1].parent/'extension-assets'/asset.name],[expected,expected]))
        self.assertEqual(manifest(original),expected)
        self.assertEqual(manifest(asset),expected)
        self.assertFalse(asset.with_name(asset.name+'.copying').exists())
        for source,staged,_ in paths:
            preferences=json.loads((staged/'Default/Preferences').read_text(encoding='utf-8'))
            self.assertEqual(preferences['extensions']['settings']['synthetic']['path'],str(asset))
            self.assertEqual(json.loads((source/'Default/Preferences').read_text(encoding='utf-8'))['extensions']['settings']['synthetic']['path'],str(original))

    def test_extension_publication_failures_release_lock_and_keep_existing_asset(self):
        from profile_copy import copy_profile
        for failure in ('copy','verification','existing'):
            with self.subTest(failure=failure):
                service,sync,original,asset,expected,paths=self.extension_fixture(failure)
                manifest=service._manifest;copies=[];failed=False
                if failure=='existing':
                    asset.mkdir(parents=True);(asset/'keep').write_bytes(b'unknown existing asset')
                    existing=manifest(asset)
                def copy(source,target):
                    nonlocal failed
                    copies.append(Path(target))
                    if failure=='copy' and not failed:
                        failed=True;raise OSError('synthetic asset copy failure')
                    return copy_profile(source,target)
                def checked(folder):
                    nonlocal failed
                    if failure=='verification' and Path(folder)==asset and not failed:
                        failed=True;raise OSError('synthetic asset verification failure')
                    return manifest(folder)
                service._copy_profile=copy;service._manifest=checked
                error=LocalBrowserError if failure=='existing' else OSError
                with self.assertRaises(error):sync._extensions(*paths[0])
                acquired=sync._asset_lock.acquire(blocking=False)
                if acquired:sync._asset_lock.release()
                self.assertTrue(acquired)
                if failure=='existing':
                    with self.assertRaises(LocalBrowserError):sync._extensions(*paths[1])
                    self.assertEqual((copies,manifest(asset)),([],existing))
                else:
                    sync._extensions(*paths[1])
                    self.assertEqual(manifest(asset),expected)
                    self.assertEqual(len(copies),2 if failure=='copy' else 1)
                    preferences=json.loads((paths[1][1]/'Default/Preferences').read_text(encoding='utf-8'))
                    self.assertEqual(preferences['extensions']['settings']['synthetic']['path'],str(asset))
                self.assertFalse(asset.with_name(asset.name+'.copying').exists())

    def test_old_shared_extension_copying_residue_is_preserved_and_does_not_block(self):
        from profile_copy import copy_profile
        service,sync,original,asset,expected,paths=self.extension_fixture('old-extension-residue')
        stale=asset.with_name(asset.name+'.copying');stale.mkdir(parents=True)
        (stale/'keep').write_bytes(b'unclaimed previous copy')
        before=service._manifest(stale);source_before=service._manifest(paths[0][0])
        service._copy_profile=copy_profile
        sync._extensions(*paths[0])
        self.assertEqual(service._manifest(asset),expected)
        self.assertEqual(service._manifest(stale),before)
        self.assertEqual(service._manifest(original),expected)
        self.assertEqual(service._manifest(paths[0][0]),source_before)

    def test_extension_copy_interruption_is_recovered_with_its_authenticated_work(self):
        import profile_copy
        service,sync,original,asset,expected,paths=self.extension_fixture('extension-interruption')
        service._copy_profile=profile_copy.copy_profile
        item=sync.provider.items[0];source_before=service._manifest(paths[0][0])
        copy_tree=profile_copy._copy_tree
        def interrupted(source,temporary,inventory,total):
            if Path(source)==original:
                (temporary/'partial').write_bytes(b'interrupted synthetic copy')
                raise SystemExit(37)
            return copy_tree(source,temporary,inventory,total)
        with patch.object(profile_copy,'_copy_tree',side_effect=interrupted):
            with self.assertRaises(SystemExit):sync._import(item,lambda phase:None)
        intent=next(sync.state.intents(item['source_key']))
        work,_,_=sync._intent_paths(intent)
        pending=work/'extension-assets'/(asset.name+'.copying')
        self.assertTrue((pending/'partial').is_file())
        self.assertTrue((work/'.sync-owner.bin').is_file())
        self.assertFalse(asset.exists())
        self.assertFalse(asset.with_name(asset.name+'.copying').exists())
        with patch.object(window_sync,'APP_ROOT',self.root/'synthetic-app'):
            restarted=WindowSynchronizer(service,Provider(sync.provider.items))
        restarted._startup=sync._startup;restarted._record=sync._record
        self.assertFalse(work.exists());self.assertEqual(list(restarted.state.intents()),[])
        self.assertTrue(restarted._import(item,lambda phase:None))
        self.assertEqual(service._manifest(asset),expected)
        self.assertEqual(service._manifest(original),expected)
        self.assertEqual(service._manifest(paths[0][0]),source_before)
        self.assertEqual(len(service.store.all()),1)
        self.assertEqual(list(restarted.state.intents()),[])

    def test_existing_verified_extension_is_reused_without_copy_or_rewrite(self):
        service,sync,original,asset,expected,paths=self.extension_fixture('existing-extension')
        shutil.copytree(original,asset)
        stamps={path.relative_to(asset):(path.stat().st_ino,path.stat().st_size,path.stat().st_mtime_ns)
                for path in asset.rglob('*') if path.is_file()}
        with patch.object(service,'_copy_profile',side_effect=AssertionError('Existing asset must be reused')):
            sync._extensions(*paths[0])
        self.assertEqual(service._manifest(asset),expected)
        self.assertEqual({path.relative_to(asset):(path.stat().st_ino,path.stat().st_size,path.stat().st_mtime_ns)
                          for path in asset.rglob('*') if path.is_file()},stamps)

    def test_extension_staging_mismatch_is_rejected_before_shared_publication(self):
        from profile_copy import copy_profile
        service,sync,original,asset,expected,paths=self.extension_fixture('extension-staging-mismatch')
        def changed(source,target):
            result=copy_profile(source,target)
            (target/'background.js').write_bytes(b'changed synthetic copy')
            return result
        service._copy_profile=changed
        with self.assertRaises(LocalBrowserError):sync._extensions(*paths[0])
        self.assertFalse(asset.exists())
        self.assertEqual(service._manifest(original),expected)

    def test_extension_publication_race_rechecks_without_overwriting_shared_asset(self):
        from profile_copy import copy_profile
        for matching in (True,False):
            with self.subTest(matching=matching):
                service,sync,original,asset,expected,paths=self.extension_fixture('extension-race-'+str(matching))
                service._copy_profile=copy_profile;publish=sync._publish;existing={}
                def raced(source,target):
                    if matching:shutil.copytree(original,target)
                    else:
                        target.mkdir();(target/'keep').write_bytes(b'other publisher')
                    existing.update(service._manifest(target))
                    publish(source,target)
                with patch.object(sync,'_publish',side_effect=raced):
                    if matching:sync._extensions(*paths[0])
                    else:
                        with self.assertRaises(LocalBrowserError):sync._extensions(*paths[0])
                self.assertEqual(service._manifest(asset),existing)
                self.assertEqual(service._manifest(original),expected)
                self.assertTrue((paths[0][1].parent/'extension-assets'/asset.name).is_dir())

    def test_five_items_overlap_and_only_five_futures_are_submitted(self):
        from batch_operations import Operations
        service,sync,items=fixture(self.root,count=17)
        service.operations=Operations()
        entered,release,started=self.blocking_copy(service,sync)
        submitted=[]
        class CountingExecutor(ThreadPoolExecutor):
            def submit(self,*args,**kwargs):
                submitted.append(1)
                return super().submit(*args,**kwargs)
        with patch.object(sync_executor,'ThreadPoolExecutor',CountingExecutor):
            job=self.start(sync,items)
            try:
                self.assertTrue(entered.wait(10))
                self.assertEqual((len(started),len(submitted)),(5,5))
                status=sync.status(job)
                self.assertEqual(status['completed'],0)
                self.assertEqual([p['index'] for p in status['active_items']],[1,2,3,4,5])
                self.assertEqual([p['done'] for p in status['active_items']],[1,2,3,4,5])
                self.assertTrue(all(pair[0]==job for pair in started))
                self.assertFalse(service.operations.acquire(False))
            finally:release.set()
            status=self.wait(sync)
        self.assertEqual((status['completed'],status['failed'],len(submitted)),(17,0,17),sync.diagnostics[job])
        self.assertTrue(service.operations.acquire(False));service.operations.release()
        bindings=service.store.source_bindings()
        for item in items:
            saved=service.store.get(bindings[item['source_key']])
            self.assertEqual((Path(saved['_runtime']['profile_path'])/'proof').read_text(),item['source_id'])
        self.assertEqual(list(sync.state.intents()),[])
        self.assertIsNone(sync._job_item)
        self.assertEqual({entry['ordinal'] for entry in sync.diagnostics[job] if entry.get('kind')=='timing'},set(range(1,18)))

    def test_cancel_waits_for_five_executing_items_without_starting_remaining(self):
        service,sync,items=fixture(self.root,count=11)
        entered,release,started=self.blocking_copy(service,sync)
        job=self.start(sync,items)
        try:
            self.assertTrue(entered.wait(10));sync.cancel(job)
            self.assertTrue(sync.worker.is_alive())
            other=WorkerLease(service.root)
            self.assertFalse(other.acquire())
            self.assertEqual(len(started),5)
        finally:release.set()
        status=self.wait(sync)
        self.assertEqual((status['state'],status['completed'],status['failed']),('cancelled',5,0),status['items'])
        self.assertEqual(len(started),5)
        self.assertEqual(len(list(sync.state.pending(job))),6)
        self.assertEqual(status['active_items'],[])
        self.assertTrue(other.acquire());other.release()

    def test_mixed_failures_keep_independent_context_counts_and_diagnostics(self):
        service,sync,items=fixture(self.root,count=10)
        actual=service._copy_profile
        def copy(source,target):
            _,index=sync._job_item
            self.assertEqual(Path(source).name,items[index-1]['source_id'])
            if index==3:raise LocalBrowserError('合成可读失败。')
            if index==4:raise OSError('synthetic private exception must stay local')
            return actual(source,target)
        service._copy_profile=copy
        job=self.start(sync,items);status=self.wait(sync)
        self.assertEqual((status['completed'],status['failed'],status['items_total']),(8,2,10))
        self.assertEqual({item['index'] for item in status['items'] if item['status']=='failed'},{3,4})
        self.assertNotIn('private exception',json.dumps(sync.diagnostics[job]))
        self.assertEqual(len(service.store.source_bindings()),8)

    def test_result_cursor_returns_late_lower_ordinals_and_recovered_results(self):
        _,sync,items=fixture(self.root,count=3)
        state=sync.state;state.create('cursor-job',items)
        state.finish_item('cursor-job',3,'completed','synthetic')
        page=state.status('cursor-job',after=0)
        self.assertEqual(([item['index'] for item in page['items']],page['next_cursor']),([3],1))
        state.finish_item('cursor-job',1,'failed','synthetic')
        page=state.status('cursor-job',after=page['next_cursor'])
        self.assertEqual(([item['index'] for item in page['items']],page['next_cursor']),([1],2))
        state.finish_item('cursor-job',2,'completed','synthetic')
        state.finish_item('cursor-job',1,'completed','synthetic recovered')
        state.finish_item('cursor-job',1,'completed','synthetic duplicate')
        page=state.status('cursor-job',after=2)
        self.assertEqual(([item['index'] for item in page['items']],page['next_cursor']),([2,1],4))
        self.assertEqual((page['completed'],page['failed'],page['items_total']),(3,0,3))

    def test_old_queue_schema_migrates_without_losing_previous_cursor(self):
        service,sync,items=fixture(self.root,count=2)
        with service.store.connect() as con:
            con.execute('DROP TABLE sync_items');con.execute('DROP TABLE sync_jobs')
            con.execute('CREATE TABLE sync_jobs(job_id TEXT PRIMARY KEY,created_at TEXT NOT NULL,state TEXT NOT NULL,'
                        'phase TEXT NOT NULL,current INTEGER NOT NULL,total INTEGER NOT NULL,completed INTEGER NOT NULL DEFAULT 0,'
                        'skipped INTEGER NOT NULL DEFAULT 0,failed INTEGER NOT NULL DEFAULT 0,cancel_requested INTEGER NOT NULL DEFAULT 0,'
                        'message TEXT,warnings_total INTEGER NOT NULL DEFAULT 0)')
            con.execute('CREATE TABLE sync_items(job_id TEXT NOT NULL,ordinal INTEGER NOT NULL,source_key TEXT NOT NULL,'
                        'name BLOB NOT NULL,candidate BLOB NOT NULL,state TEXT NOT NULL DEFAULT \'pending\',message TEXT,'
                        'PRIMARY KEY(job_id,ordinal),UNIQUE(job_id,source_key))')
            con.execute("INSERT INTO sync_jobs(job_id,created_at,state,phase,current,total,completed) VALUES('old-job','synthetic','running','checking',2,2,1)")
            for index,item in enumerate(items,1):
                con.execute('INSERT INTO sync_items VALUES(?,?,?,?,?,?,?)',('old-job',index,item['source_key'],service.store.pack('synthetic'),
                    service.store.pack(item),'completed' if index==2 else 'pending','synthetic'))
        state=SyncState(service.store)
        page=state.status('old-job',after=0)
        self.assertEqual(([item['index'] for item in page['items']],page['next_cursor']),([2],2))
        state.finish_item('old-job',1,'completed','synthetic')
        page=state.status('old-job',after=2)
        self.assertEqual(([item['index'] for item in page['items']],page['next_cursor']),([1],3))
        self.assertEqual((page['completed'],page['items_total']),(2,2))

    def test_restart_recovers_multiple_authenticated_prepared_items(self):
        service,sync,items=fixture(self.root,count=5)
        job='interrupted-parallel';sync.state.create(job,items)
        sync._prepare_roots()
        def prepare(index,item):
            sync.state.begin_item(job,index)
            token=sync._item_context.set((job,index))
            try:
                with self.assertRaises(OSError):sync._import(item,lambda phase:None)
            finally:sync._item_context.reset(token)
        with patch.object(sync,'_complete_intent',side_effect=OSError('synthetic before commit')):
            run_bounded(enumerate(items,1),prepare,lambda:False)
        self.assertEqual(len(list(sync.state.intents())),5)
        self.assertEqual(sync.state.status(job)['completed'],0)
        with patch.object(window_sync,'APP_ROOT',self.root/'synthetic-app'):
            restarted=WindowSynchronizer(service,Provider(items))
        status=restarted.latest()
        self.assertEqual((status['state'],status['completed'],status['failed']),('interrupted',5,0))
        self.assertEqual(list(restarted.state.intents()),[])
        self.assertEqual(len(service.store.source_bindings()),5)
        restarted._startup=sync._startup;restarted._record=sync._record
        restarted.resume(job);self.workers.append(restarted.worker)
        self.assertEqual(self.wait(restarted)['completed'],5)
        self.assertEqual(len(service.store.all()),5)

    def test_parallel_uncertain_commit_readback_never_duplicates_or_deletes(self):
        service,sync,items=fixture(self.root,count=9)
        actual=service.store.commit_import
        def commit(*args,**kwargs):
            actual(*args,**kwargs)
            raise OSError('synthetic lost acknowledgement')
        with patch.object(service.store,'commit_import',side_effect=commit):
            self.start(sync,items);status=self.wait(sync)
        self.assertEqual((status['completed'],status['failed']),(9,0))
        self.assertEqual(len(service.store.source_bindings()),9)
        self.assertEqual(list(sync.state.intents()),[])
        self.assertEqual(len(list((service.root/'profiles').iterdir())),9)

    def test_late_progress_from_finished_item_cannot_change_another_item(self):
        service,sync,items=fixture(self.root,count=2)
        actual=service._copy_profile;entered=threading.Event();release=threading.Event()
        callbacks={};lock=threading.Lock();finished=threading.Event()
        complete=sync.state.finish_item
        def copy(source,target):
            _,index=sync._job_item
            with lock:
                callbacks[index]=_observer.get()
                if len(callbacks)==2:entered.set()
            emit('copying',done=index,total=100,unit='bytes')
            if index==2:
                if not release.wait(15):raise RuntimeError('synthetic barrier timeout')
            elif not entered.wait(15):raise RuntimeError('synthetic barrier timeout')
            return actual(source,target)
        def finish(job,index,*args):
            complete(job,index,*args)
            if index==1:finished.set()
        service._copy_profile=copy;sync.state.finish_item=finish
        job=self.start(sync,items)
        try:
            self.assertTrue(entered.wait(10));self.assertTrue(finished.wait(10))
            callbacks[1]('copying',done=99,total=100,unit='bytes')
            active=sync.status(job)['active_items']
            self.assertEqual([(p['index'],p['done']) for p in active],[(2,2)])
        finally:release.set()
        self.assertEqual(self.wait(sync)['completed'],2)

    def test_cancelled_item_cannot_be_claimed_by_a_late_future(self):
        _,sync,items=fixture(self.root,count=1)
        sync.state.create('cancelled-claim',items);sync.state.cancel('cancelled-claim')
        with patch.object(sync,'_import',side_effect=AssertionError('must not start')):
            sync._run_item('cancelled-claim',1,items[0])
        self.assertEqual(len(list(sync.state.pending('cancelled-claim'))),1)
        self.assertIsNone(sync._job_item)

    def test_persistence_failure_drains_executing_items_before_interrupt_and_resume(self):
        service,sync,items=fixture(self.root,count=10)
        entered=threading.Event();release_first=threading.Event();release=threading.Event()
        failed=threading.Event();lock=threading.Lock();started=[]
        actual_copy=service._copy_profile;actual_finish=sync.state.finish_item
        def copy(source,target):
            _,index=sync._job_item
            with lock:
                started.append(index)
                if len(started)==5:entered.set()
            if not (release_first if index==1 else release).wait(15):raise RuntimeError('synthetic barrier timeout')
            return actual_copy(source,target)
        def finish(job,index,*args):
            if index==1:failed.set();raise OSError('synthetic persistence failure')
            return actual_finish(job,index,*args)
        service._copy_profile=copy
        with patch.object(sync.state,'finish_item',side_effect=finish):
            job=self.start(sync,items)
            try:
                self.assertTrue(entered.wait(10));release_first.set()
                self.assertTrue(failed.wait(10))
                self.assertTrue(sync.worker.is_alive())
                self.assertEqual(len(started),5)
                other=WorkerLease(service.root);self.assertFalse(other.acquire())
            finally:release.set();release_first.set()
            status=self.wait(sync)
        self.assertEqual((status['state'],status['completed']),('interrupted',5))
        self.assertEqual(len(list(sync.state.pending(job))),5)
        service._copy_profile=actual_copy
        sync.resume(job);self.workers.append(sync.worker)
        self.assertEqual(self.wait(sync)['completed'],10)


if __name__=='__main__':unittest.main(verbosity=2)
