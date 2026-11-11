"""Display caching and SQLite durability checks use synthetic temporary catalogs."""
import copy
from contextlib import closing,contextmanager
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))

from local_state import LocalBrowserError
from portable_vault import PortableVault
from portable_paths import _RUNTIME_PATHS
import window_store
from window_store import WindowStore


class StatusProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='status-projection-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        PortableVault(self.root).initialize()
        self.store=WindowStore(SimpleNamespace(),self.root)

    def record(self,index=1,**changes):
        value={'id':f'synthetic-{index}','seq':index,'created_at':'synthetic',
               'last_opened_at':None,'archived':False,'config_status':'ready',
               'name':'synthetic private label','password':'synthetic private value',
               '_native':{'large':'unused'*100},'fingerprint':{'unused':'synthetic'},
               '_runtime':{'fingerprint_path':str(self.root/f'fingerprint-{index}.bin'),
                           'signature_provider':'local-v1','unused':'synthetic private runtime'}}
        value.update(changes)
        return value

    @staticmethod
    def projection(value):
        return {'id':value['id'],'last_opened_at':value.get('last_opened_at'),
                'config_status':value.get('config_status','ready'),
                '_runtime':{'fingerprint_path':value['_runtime']['fingerprint_path'],
                            'signature_provider':value['_runtime'].get('signature_provider','vendor')}}

    def test_unchanged_rows_reuse_only_display_fields_and_return_copies(self):
        record=self.record();self.store.put(record)
        with patch.object(self.store,'_unpack_encoded',wraps=self.store._unpack_encoded) as unpack:
            first=self.store.status_rows()
            self.assertEqual(unpack.call_count,1)
            first[0]['_runtime']['fingerprint_path']='changed by caller'
            self.assertEqual(self.store.status_rows(),[self.projection(record)])
            self.assertEqual(unpack.call_count,1)
        self.assertEqual(list(self.store._status_cache.values()),[self.projection(record)])
        self.assertTrue(all(isinstance(key,bytes) and len(key)==32 for key in self.store._status_cache))

    def test_slow_status_decoding_does_not_block_catalog_writes(self):
        record=self.record();self.store.put(record)
        entered=threading.Event();release=threading.Event();saved=threading.Event()
        errors=[];observed=[];decode=self.store._unpack_encoded
        def slow_decode(blob):
            value=decode(blob);entered.set()
            if not release.wait(5):raise RuntimeError('Synthetic decoding gate timed out')
            return value
        def read_status():
            try:observed.extend(self.store.status_rows())
            except Exception as error:errors.append(type(error).__name__)
        def write_record():
            try:
                updated=copy.deepcopy(record);updated['last_opened_at']='updated'
                self.store.put(updated);saved.set()
            except Exception as error:errors.append(type(error).__name__)
        with patch.object(self.store,'_unpack_encoded',side_effect=slow_decode):
            reader=threading.Thread(target=read_status,daemon=True)
            writer=threading.Thread(target=write_record,daemon=True)
            reader.start()
            try:
                self.assertTrue(entered.wait(2))
                writer.start()
                self.assertTrue(saved.wait(2),'Status decoding blocked a catalog write')
            finally:
                release.set();reader.join(5)
                if writer.ident is not None:writer.join(5)
        self.assertFalse(reader.is_alive() or writer.is_alive())
        self.assertFalse(errors)
        self.assertIsNone(observed[0]['last_opened_at'])
        self.assertEqual(self.store.status_rows()[0]['last_opened_at'],'updated')

    def test_external_changes_add_delete_and_renewal_are_visible(self):
        original=self.record();self.store.put(original);self.store.status_rows()
        updated=copy.deepcopy(original)
        updated.update(last_opened_at='later',config_status='changed',archived=True)
        updated['_runtime']['fingerprint_path']=str(self.root/'renewed.bin')
        added=self.record(2)
        with closing(sqlite3.connect(self.store.db)) as con,con:
            con.execute('UPDATE profiles SET data=? WHERE id=?',(self.store.pack(updated),original['id']))
            con.execute('INSERT INTO profiles VALUES (?,?,?,?,?,?)',
                        (added['id'],2,'synthetic',None,0,self.store.pack(added)))
        self.assertEqual(self.store.status_rows(),[self.projection(updated),self.projection(added)])
        with closing(sqlite3.connect(self.store.db)) as con,con:
            con.execute('DELETE FROM profiles WHERE id=?',(original['id'],))
        self.assertEqual(self.store.status_rows(),[self.projection(added)])
        self.assertEqual(len(self.store._status_cache),1)

    def test_index_columns_do_not_override_authenticated_inner_fields(self):
        first=self.record();second=self.record(2)
        self.store.put(first);self.store.put(second);self.store.status_rows()
        with closing(sqlite3.connect(self.store.db)) as con,con:
            con.execute('UPDATE profiles SET id=?,seq=?,last_opened_at=?,archived=1 WHERE id=?',
                        ('outer-only',3,'outer-only',first['id']))
        self.assertEqual(self.store.status_rows(),[self.projection(second),self.projection(first)])
        self.assertEqual(self.store.status_rows(),[self.projection(row) for row in self.store.all()])

    def test_corrupted_ciphertext_never_uses_previous_display_value(self):
        record=self.record();self.store.put(record);self.store.status_rows()
        with closing(sqlite3.connect(self.store.db)) as con,con:
            blob=con.execute('SELECT data FROM profiles').fetchone()[0]
            damaged=blob[:-1]+bytes([blob[-1]^1])
            con.execute('UPDATE profiles SET data=?',(damaged,))
        with self.assertRaises(LocalBrowserError):self.store.status_rows()
        self.assertEqual(self.store._status_cache,{})

    def test_changed_valid_vault_cannot_authorize_previously_cached_rows(self):
        self.store.put(self.record());self.store.status_rows()
        other=self.root/'other';other.mkdir()
        replacement=PortableVault(other);replacement.initialize()
        current=PortableVault(self.root)
        current.key_path.write_bytes(replacement.key_path.read_bytes())
        current.marker_path.write_bytes(replacement.marker_path.read_bytes())
        with self.assertRaises(LocalBrowserError):self.store.status_rows()
        self.assertEqual(self.store._status_cache,{})

    def test_missing_vault_is_checked_even_for_a_cache_hit(self):
        self.store.put(self.record());self.store.status_rows()
        PortableVault(self.root).key_path.unlink()
        with self.assertRaises(LocalBrowserError):self.store.status_rows()
        self.assertEqual(self.store._status_cache,{})

    def test_database_replacement_reauthenticates_identical_ciphertext(self):
        record=self.record();self.store.put(record);self.store.status_rows()
        replacement=self.root/'replacement.sqlite'
        with closing(sqlite3.connect(self.store.db)) as source,closing(sqlite3.connect(replacement)) as target:
            source.backup(target)
        os.replace(replacement,self.store.db)
        with patch.object(self.store,'_unpack_encoded',wraps=self.store._unpack_encoded) as unpack:
            self.assertEqual(self.store.status_rows(),[self.projection(record)])
            self.assertEqual(unpack.call_count,1)

    def test_cache_is_bounded_without_full_scan_eviction_thrashing(self):
        for index in range(1,5):self.store.put(self.record(index))
        with patch.object(window_store,'_STATUS_CACHE_LIMIT',2):
            self.assertEqual(len(self.store.status_rows()),4)
            self.assertEqual(len(self.store._status_cache),2)
            with patch.object(self.store,'_unpack_encoded',wraps=self.store._unpack_encoded) as unpack:
                self.assertEqual(len(self.store.status_rows()),4)
                self.assertEqual(unpack.call_count,2)
            self.assertEqual(len(self.store._status_cache),2)

    def test_oversized_and_nonscalar_projection_values_are_not_cached(self):
        for value in ('x'*(window_store._STATUS_CACHE_MAX_CHARS+1),{'unexpected':['synthetic']}):
            record=self.record(config_status=value);self.store.put(record)
            with patch.object(self.store,'_unpack_encoded',wraps=self.store._unpack_encoded) as unpack:
                self.assertEqual(self.store.status_rows(),[self.projection(record)])
                self.assertEqual(self.store.status_rows(),[self.projection(record)])
                self.assertEqual(unpack.call_count,2)
            self.assertEqual(self.store._status_cache,{})

    def test_legacy_rows_always_reauthenticate(self):
        record=self.record();self.store.put(record)
        with self.store.connect() as con:con.execute('UPDATE profiles SET data=?',(b'synthetic-legacy-envelope',))
        with patch.object(self.store,'_unpack_encoded',side_effect=lambda _:copy.deepcopy(record)) as unpack:
            self.assertEqual(self.store.status_rows(),[self.projection(record)])
            self.assertEqual(self.store.status_rows(),[self.projection(record)])
            self.assertEqual(unpack.call_count,2)
        self.assertEqual(self.store._status_cache,{})

    def test_get_and_all_never_use_the_display_cache(self):
        record=self.record();self.store.put(record);self.store.status_rows()
        with patch.object(self.store,'unpack',wraps=self.store.unpack) as unpack:
            self.assertEqual(self.store.get(record['id']),record)
            self.assertEqual(self.store.all(),[record])
            self.assertEqual(unpack.call_count,2)

    def test_cached_encoded_paths_recheck_every_managed_runtime_field(self):
        original_resolve=Path.resolve
        managed=self.root/'configs/value.bin'
        outside=self.root.parent/'synthetic-outside/value.bin'
        def changed_path(path,*args,**kwargs):
            return outside if path==managed else original_resolve(path,*args,**kwargs)
        for field in _RUNTIME_PATHS:
            with self.subTest(field=field):
                record=self.record();record['_runtime'][field]='@data/configs/value.bin'
                self.store.put(record)
                before=self.store.status_rows()
                cached=next(iter(self.store._status_cache.values()))
                self.assertEqual(cached['_runtime'][field],'@data/configs/value.bin')
                with patch.object(Path,'resolve',autospec=True,side_effect=changed_path):
                    with self.assertRaises(LocalBrowserError):self.store.all()
                    with self.assertRaises(LocalBrowserError):self.store.status_rows()
                self.assertEqual(self.store._status_cache,{})
                self.assertEqual(self.store.status_rows(),before)

    def test_absolute_external_paths_keep_existing_compatibility(self):
        record=self.record()
        for field in _RUNTIME_PATHS:record['_runtime'][field]=str(self.root.parent/'synthetic-external'/field)
        self.store.put(record)
        with patch.object(self.store,'_unpack_encoded',wraps=self.store._unpack_encoded) as unpack:
            self.assertEqual(self.store.status_rows(),[self.projection(record)])
            self.assertEqual(self.store.status_rows(),[self.projection(record)])
            self.assertEqual(unpack.call_count,1)

    def test_other_managed_paths_keep_original_rejection(self):
        for field in ('download_dir','browser_path'):
            with self.subTest(field=field):
                record=self.record(_runtime=None)
                record[field]='@data/../synthetic-outside'
                self.store.put(record)
                with self.assertRaises(LocalBrowserError):self.store.all()
                with self.assertRaises(LocalBrowserError):self.store.status_rows()
                self.assertEqual(self.store._status_cache,{})

    @contextmanager
    def junction(self,link,target):
        result=subprocess.run(['cmd','/d','/c','mklink','/J',str(link),str(target)],
                              capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=10)
        created=result.returncode==0
        try:
            self.assertTrue(created,'Synthetic junction creation failed')
            yield
        finally:
            # Remove only this junction before either synthetic temporary tree is cleaned.
            if created:os.rmdir(link)

    @unittest.skipUnless(os.name=='nt','Windows junction fixture')
    def test_real_junction_replacement_rejects_cached_paths_and_recovers(self):
        with tempfile.TemporaryDirectory(prefix='status-outside-') as directory:
            outside=Path(directory);sentinel=outside/'sentinel';sentinel.write_bytes(b'synthetic')
            link=self.root/'configs';link.mkdir()
            for field in _RUNTIME_PATHS:
                with self.subTest(field=field):
                    record=self.record();record['_runtime'][field]='@data/configs/value.bin'
                    self.store.put(record);before=self.store.status_rows()
                    link.rmdir()
                    with self.junction(link,outside):
                        with self.assertRaises(LocalBrowserError):self.store.all()
                        with self.assertRaises(LocalBrowserError):self.store.status_rows()
                    self.assertEqual(sentinel.read_bytes(),b'synthetic')
                    link.mkdir()
                    self.assertEqual(self.store.status_rows(),before)


class SQLiteConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='catalog-connection-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        PortableVault(self.root).initialize()

    def test_wal_is_set_once_and_full_timeout_remain_per_connection(self):
        statements=[];connect=sqlite3.connect
        def traced(*args,**kwargs):
            con=connect(*args,**kwargs);con.set_trace_callback(statements.append)
            return con
        with patch.object(window_store.sqlite3,'connect',side_effect=traced):
            store=WindowStore(SimpleNamespace(),self.root)
            self.assertEqual(statements.count('PRAGMA journal_mode=WAL'),1)
            statements.clear()
            for _ in range(3):
                with store.connect() as con:
                    self.assertEqual(con.execute('PRAGMA synchronous').fetchone()[0],2)
                    self.assertEqual(con.execute('PRAGMA busy_timeout').fetchone()[0],5000)
            self.assertEqual(statements.count('PRAGMA journal_mode=WAL'),0)
            self.assertEqual(statements.count('PRAGMA synchronous=FULL'),3)
            self.assertEqual(statements.count('PRAGMA journal_mode'),3)

    def test_external_mode_change_and_replacement_enable_wal_again(self):
        store=WindowStore(SimpleNamespace(),self.root)
        with closing(sqlite3.connect(store.db)) as con:
            self.assertEqual(con.execute('PRAGMA journal_mode=DELETE').fetchone()[0],'delete')
        with store.connect() as con:self.assertEqual(con.execute('PRAGMA journal_mode').fetchone()[0],'wal')
        replacement=self.root/'replacement.sqlite'
        with closing(sqlite3.connect(replacement)) as con,con:con.execute('CREATE TABLE synthetic(value INTEGER)')
        os.replace(replacement,store.db)
        with store.connect() as con:
            self.assertEqual(con.execute('PRAGMA journal_mode').fetchone()[0],'wal')
            self.assertEqual(con.execute('PRAGMA synchronous').fetchone()[0],2)

    def test_failure_rolls_back_and_closes_connection(self):
        store=WindowStore(SimpleNamespace(),self.root)
        with self.assertRaisesRegex(RuntimeError,'synthetic failure'):
            with store.connect() as failed:
                failed.execute('INSERT INTO settings VALUES (?,?)',('synthetic',b'synthetic'))
                raise RuntimeError('synthetic failure')
        with self.assertRaises(sqlite3.ProgrammingError):failed.execute('SELECT 1')
        with store.connect() as con:
            self.assertIsNone(con.execute('SELECT value FROM settings WHERE key=?',('synthetic',)).fetchone())

    def test_unavailable_wal_fails_closed_and_releases_connection(self):
        store=WindowStore(SimpleNamespace(),self.root)
        con=Mock();con.execute.return_value.fetchone.return_value=('delete',)
        with patch.object(window_store.sqlite3,'connect',return_value=con):
            with self.assertRaises(LocalBrowserError):
                with store.connect():pass
        con.rollback.assert_called_once();con.close.assert_called_once()


if __name__=='__main__':
    unittest.main(verbosity=2)
