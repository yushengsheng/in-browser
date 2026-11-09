"""Synthetic-only bridge, pending guards and deletion/sync integration checks."""
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
sys.path.insert(0,str(ROOT/'tests'))

from api import dispatch
from local_state import LocalBrowserError
from manager_service import ManagerService
from sync_state import SyncState
from test_profile_delete import Fixture
from window_sync import WindowSynchronizer


class DeleteBridgeTests(unittest.TestCase):
    def test_single_and_batch_require_explicit_complete_receipt(self):
        service=Mock()
        service.delete.return_value={'deleted':True,'cleanup_complete':True}
        service.delete_many.return_value=service.delete.return_value
        self.assertTrue(dispatch(service,'delete',{'id':'synthetic'})['data']['cleanup_complete'])
        reply=dispatch(service,'batch',{'action':'delete','ids':['a','a','b']})
        self.assertEqual(reply['data']['completed'],2)
        self.assertEqual([item['id'] for item in reply['data']['results']],['a','b'])
        service.delete_many.assert_called_once_with(['a','b'])
        service.delete_many.return_value={'deleted':True,'cleanup_complete':False}
        result=dispatch(service,'batch',{'action':'delete','ids':['a','b']})['data']
        self.assertEqual(result['completed'],0)
        self.assertEqual(len(result['errors']),2)
        self.assertTrue(all(item['data']['deleted'] for item in result['results']))

    def test_delete_errors_never_claim_all_data_preserved_or_expose_raw_error(self):
        service=Mock()
        for error in (RuntimeError('synthetic-private-detail'),LocalBrowserError('删除尚未完成。')):
            service.delete.side_effect=service.delete_many.side_effect=error
            for action,payload in [('delete',{'id':'a'}),('batch',{'action':'delete','ids':['a','b']})]:
                result=dispatch(service,action,payload)
                self.assertNotIn('synthetic-private-detail',str(result))
                self.assertNotIn('原有资料和配置已保留',str(result))
                if action=='batch':
                    self.assertEqual(result['data']['completed'],0)
                    self.assertEqual(len(result['data']['results']),2)
                    self.assertTrue(all(not item['ok'] for item in result['data']['results']))
                else:self.assertFalse(result['ok'])

    def test_other_batch_contract_and_hundred_item_limit_unchanged(self):
        service=Mock()
        service.request.return_value={'ok':True,'data':{}}
        result=dispatch(service,'batch',{'action':'close','ids':['a','a','b']})['data']
        self.assertEqual(result,{'completed':2,'errors':[]})
        service.delete_many.return_value={'deleted':True,'cleanup_complete':True}
        result=dispatch(service,'batch',{'action':'delete','ids':[str(index) for index in range(101)]})['data']
        self.assertEqual(result['completed'],100)
        self.assertEqual(len(service.delete_many.call_args.args[0]),100)


class PendingIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='delete-integration-synthetic-')
        self.addCleanup(temporary.cleanup)
        self.fixture=Fixture(temporary.name)

    def manager(self):
        service=ManagerService.__new__(ManagerService)
        service.root=self.fixture.root;service.operations=threading.RLock()
        service.store=Mock();service.controller=Mock()
        return service

    def test_pending_actions_block_under_operations_lock_before_read_or_launch(self):
        service=self.manager()
        def pending(root,identity):
            self.assertTrue(service.operations._is_owned())
            return True
        with patch('profile_delete.is_pending',side_effect=pending):
            calls=[lambda:service.open('synthetic'),lambda:service.save({'id':'synthetic'}),
                   lambda:service.archive('synthetic'),lambda:service.archive('synthetic',True),
                   lambda:service.detail('synthetic'),lambda:service.activate('synthetic')]
            for call in calls:
                with self.assertRaises(LocalBrowserError):call()
        service.store.get.assert_not_called();service.controller.open.assert_not_called()
        service.controller.activate.assert_not_called()

    def test_pending_status_is_visible_and_ordinary_record_contract_is_unchanged(self):
        service=self.manager()
        records=[{'id':identity,'fingerprint':{},'tags':[],'_runtime':{'fingerprint_path':'synthetic-missing'}} for identity in ('a','b')]
        service.store=self.fixture.store
        service.store.all=Mock(return_value=records)
        service.controller.statuses.return_value={'a':'未打开','b':'未打开'}
        with patch('profile_delete.get_pending_ids',return_value={'a'}):
            for rows in (service.listing()['profiles'],service.statuses()['profiles']):
                self.assertEqual(rows[0]['config_status'],'delete_pending')
                self.assertTrue(rows[0]['delete_pending'])
                self.assertNotIn('delete_pending',rows[1])

    def test_sync_constructor_does_not_republish_pending_deletion(self):
        with patch('profile_delete.get_pending_ids',return_value={'synthetic-0'}), \
                patch.object(WindowSynchronizer,'_recover_intents') as recover, \
                patch.object(WindowSynchronizer,'_bind_legacy') as bind:
            sync=WindowSynchronizer(self.fixture,Mock())
            recover.assert_not_called();bind.assert_not_called()
            sync._launch=Mock()
            for call in (lambda:sync.start([]),lambda:sync.resume('synthetic-job')):
                with self.assertRaises(LocalBrowserError):call()
            sync._launch.assert_not_called()

    def test_sync_rechecks_after_obtaining_worker_lease(self):
        with patch.object(WindowSynchronizer,'_recover_intents'),patch.object(WindowSynchronizer,'_bind_legacy'):
            sync=WindowSynchronizer(self.fixture,Mock())
        sync.candidates={'synthetic':{'status':'ready'}};sync._launch=Mock()
        with patch('profile_delete.get_pending_ids',side_effect=[set(),{'synthetic-0'}]):
            with self.assertRaises(LocalBrowserError):sync.start([])
        self.assertIsNone(sync.lease.handle);sync._launch.assert_not_called()
        with patch('profile_delete.get_pending_ids',side_effect=[set(),{'synthetic-0'}]):
            with self.assertRaises(LocalBrowserError):sync.resume('synthetic-job')
        self.assertIsNone(sync.lease.handle)

    def test_relocation_skips_pending_missing_configuration(self):
        import portable_paths
        from local_state import write_encrypted
        root=self.fixture.root
        write_encrypted(root/'portable-mode.bin',{'format':1,'state':'ready'},root=root)
        record=self.fixture.records[0]
        record['_portable_app']='synthetic-previous-app'
        service=SimpleNamespace(root=root,store=Mock(),_closed=Mock())
        service.store.all.return_value=[record]
        with patch('profile_delete.get_pending_ids',return_value={record['id']}):
            portable_paths.relocate(service)
        service._closed.assert_not_called();service.store.put.assert_not_called()

    def test_manager_attempts_startup_recovery_and_preserves_failure_for_guard(self):
        fixture=self.fixture
        with patch('manager_service.WindowStore',return_value=fixture.store), \
                patch('manager_service.EngineStore'),patch('portable_paths.relocate'), \
                patch('manager_service.BrowserController',return_value=fixture.controller), \
                patch('manager_service.ProxyRuntime',return_value=fixture.proxy_runtime), \
                patch('profile_delete.recover_pending_deletions',side_effect=LocalBrowserError('删除尚未完成。')) as recover:
            service=ManagerService(fixture.root,configuration=fixture.configuration)
        recover.assert_called_once_with(service)
        self.assertIsNotNone(service.controller)

    def test_remaining_sync_progress_survives_deleted_ordinal_gaps(self):
        store=self.fixture.store;state=SyncState(store)
        state.create('synthetic-job',[{'source_key':str(index),'info':{}} for index in range(4)])
        with store.connect() as con:
            con.execute('DELETE FROM sync_items WHERE job_id=? AND ordinal IN (1,3)',('synthetic-job',))
            con.execute('UPDATE sync_jobs SET total=2 WHERE job_id=?',('synthetic-job',))
        state.begin_item('synthetic-job',4)
        self.assertEqual(state.status('synthetic-job')['current'],2)

    def test_missing_sync_task_is_null_only_when_explicitly_requested(self):
        state=SyncState(self.fixture.store)
        self.assertIsNone(state.status('synthetic-missing',missing_ok=True))
        with self.assertRaises(LocalBrowserError):state.status('synthetic-missing')
        service=Mock()
        service.synchronizer.return_value.status.return_value=None
        self.assertEqual(dispatch(service,'sync_status',{'job_id':'synthetic-missing','missing_ok':True}),{'ok':True,'data':None})
        service.synchronizer.return_value.status.assert_called_once_with('synthetic-missing',after=None,missing_ok=True)


if __name__=='__main__':unittest.main(verbosity=2)
