"""Startup Cookie restore boundaries; no accounts, browsers or external requests."""
import copy
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from import_cookies import source_cookies,_merge_database,prepare_existing,materialize,_expiry_candidates,_update_expiry,_session_rows,_CHROME_EPOCH_US
from local_state import LocalBrowserError


class ImportCookieTests(unittest.TestCase):
    def cookie(self,**values):
        return {'name':'session','value':'synthetic','domain':'.example.invalid','path':'/','secure':True,'httpOnly':True,**values}

    def test_source_aliases_flags_and_same_site(self):
        value=source_cookies({'cookie':json.dumps([self.cookie(expirationDate=2000000000,sameSite='no_restriction',hostOnly=True)])},now=1000000000)[0]
        self.assertEqual(value['domain'],'example.invalid');self.assertEqual(value['expires'],2000000000)
        self.assertEqual(value['sameSite'],'None');self.assertTrue(value['httpOnly'])
        host=source_cookies({'cookie':[self.cookie(name='__Host-fixture',path='/wrong',secure=False)]})[0]
        self.assertEqual((host['domain'],host['path'],host['secure']),('example.invalid','/',True))

    def test_explicit_future_expiry_wins_over_session_flag_without_extending_deadlines(self):
        cookies=source_cookies({'cookie':[self.cookie(expires=500),self.cookie(name='session2',session=True,expires=2000000000)]},now=1000)
        self.assertEqual(len(cookies),1);self.assertEqual(cookies[0]['expires'],2000000000)
        sessions=source_cookies({'cookie':[self.cookie(session=True),self.cookie(name='without-expiry',session=True,expires=-1)]},now=1000)
        self.assertEqual(len(sessions),2);self.assertTrue(all('expires' not in cookie for cookie in sessions))
        self.assertEqual(source_cookies({'cookie':[self.cookie(session=True,expires=500)]},now=1000),[])
        ms=source_cookies({'cookie':[self.cookie(expires=2000000000000)]},now=1000)[0]
        self.assertEqual(ms['expires'],2000000000)
        dated=source_cookies({'cookie':[self.cookie(expires='2033-05-18T03:33:20Z')]},now=1000)[0]
        self.assertEqual(dated['expires'],2000000000)
        fractional=source_cookies({'cookie':[self.cookie(session=True,expires=2000000000.987654)]},now=1000)[0]
        self.assertEqual(fractional['expires'],2000000000)
        fractional_ms=source_cookies({'cookie':[self.cookie(session=True,expires=2000000000987)]},now=1000)[0]
        self.assertEqual(fractional_ms['expires'],2000000000)
        session=source_cookies({'cookie':[self.cookie(expires='-1',domain='.EXAMPLE.INVALID')]},now=1000)[0]
        self.assertNotIn('expires',session);self.assertEqual(session['domain'],'.example.invalid')

    def test_invalid_or_oversized_input_is_not_silently_ignored(self):
        for value in ('not json',{},[self.cookie(expires=float('nan'))],[self.cookie(domain='evil.invalid\r\n')],
                      [self.cookie(path='relative')],[self.cookie(sameSite='invalid')],' '*2000001):
            with self.subTest(kind=type(value).__name__),self.assertRaises((ValueError,TypeError)):
                source_cookies({'cookie':value})

    def database(self,path,rows):
        con=sqlite3.connect(path)
        con.execute('CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,encrypted_value BLOB,expires_utc INTEGER,has_expires INTEGER,is_persistent INTEGER,UNIQUE(host_key,name,path))')
        con.executemany('INSERT INTO cookies VALUES(?,?,?,?,?,?,?)',rows);con.commit();con.close()

    def test_merge_preserves_unrelated_rows_and_session_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'source';target=root/'target'
            self.database(source,[('example.invalid','session','/',b'native-encrypted',100,1,1)])
            self.database(target,[('example.invalid','session','/',b'old',99,1,1),('other.invalid','keep','/',b'unchanged',200,1,1)])
            self.assertEqual(_merge_database(source,target,{('example.invalid','session','/','',False)},1),1)
            con=sqlite3.connect(target);rows=con.execute('SELECT encrypted_value,expires_utc,has_expires,is_persistent FROM cookies ORDER BY host_key').fetchall();con.close()
            self.assertEqual(rows,[(b'native-encrypted',0,0,0),(b'unchanged',200,1,1)])

    def test_count_or_schema_failure_happens_without_overwriting_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'source';target=root/'target'
            self.database(source,[('example.invalid','session','/',b'new',100,1,1)]);self.database(target,[])
            before=target.read_bytes()
            with self.assertRaises(ValueError):_merge_database(source,target,set(),2)
            self.assertEqual(target.read_bytes(),before)
            con=sqlite3.connect(target);con.execute('ALTER TABLE cookies ADD COLUMN incompatible INTEGER');con.close();before=target.read_bytes()
            with self.assertRaises(ValueError):_merge_database(source,target,set(),1)
            self.assertEqual(target.read_bytes(),before)

    def test_transaction_failure_keeps_existing_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'source';target=root/'target'
            self.database(source,[('example.invalid','session','/',b'new',100,1,1)]);self.database(target,[('example.invalid','session','/',b'old',99,1,1)])
            con=sqlite3.connect(target);con.execute("CREATE TRIGGER block_restore BEFORE INSERT ON cookies BEGIN SELECT RAISE(ABORT,'fixture'); END");con.close()
            with self.assertRaises(sqlite3.IntegrityError):_merge_database(source,target,set(),1)
            con=sqlite3.connect(target);self.assertEqual(con.execute('SELECT encrypted_value FROM cookies').fetchone()[0],b'old');con.close()

    def test_partitioned_session_does_not_change_another_partition_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'source';target=root/'target'
            for path in (source,target):
                con=sqlite3.connect(path)
                con.execute('CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,encrypted_value BLOB,expires_utc INTEGER,has_expires INTEGER,is_persistent INTEGER,top_frame_site_key TEXT,has_cross_site_ancestor INTEGER,UNIQUE(host_key,name,path,top_frame_site_key,has_cross_site_ancestor))')
                if path==source:con.executemany('INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?)',[
                    ('example.invalid','session','/',b'one',100,1,1,'https://first.invalid',0),
                    ('example.invalid','session','/',b'two',200,1,1,'https://second.invalid',1)])
                con.commit();con.close()
            _merge_database(source,target,{('example.invalid','session','/','https://first.invalid',False)},2)
            con=sqlite3.connect(target);self.assertEqual(con.execute('SELECT expires_utc,is_persistent FROM cookies ORDER BY top_frame_site_key').fetchall(),[(0,0),(200,1)]);con.close()

    def test_locally_created_or_completed_import_never_replays_source_cookies(self):
        for record in ({'created_locally':True},{'_source_info':{'cookie':'invalid'},'_startup_cookies':{'format':1,'expiry_revision':2}}):
            self.assertIs(prepare_existing(None,record),record)
        self.assertFalse(materialize(None,{'created_locally':True},None))
        self.assertFalse(materialize(None,{'_source_info':{'cookie':'invalid'},'_startup_cookies':{'format':1}},None))

    def test_unpartitioned_session_with_ancestor_bit_keeps_session_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'source';target=root/'target'
            con=sqlite3.connect(source)
            con.execute('CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,encrypted_value BLOB,expires_utc INTEGER,has_expires INTEGER,is_persistent INTEGER,top_frame_site_key TEXT,has_cross_site_ancestor INTEGER,UNIQUE(host_key,name,path,top_frame_site_key,has_cross_site_ancestor))')
            con.execute('INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?)',('example.invalid','session','/',b'native',100,1,1,'',1))
            con.commit();con.close()
            _merge_database(source,target,{('example.invalid','session','/','',False)},1)
            con=sqlite3.connect(target)
            self.assertEqual(con.execute('SELECT expires_utc,has_expires,is_persistent,has_cross_site_ancestor FROM cookies').fetchone(),(0,0,0,1))
            con.close()

    def test_explicit_user_cookies_take_precedence_without_profile_writes(self):
        record={'_source_info':{'cookie':json.dumps([self.cookie()])},'_cookie_pending':True,'cookie_text':'fixture'}
        service=SimpleNamespace(store=SimpleNamespace(put=Mock()),_sync=Mock())
        original=copy.deepcopy(record);updated=prepare_existing(service,record)
        self.assertEqual(original,record);self.assertTrue(updated['_startup_cookies']['user_cookie_override'])
        service.store.put.assert_called_once()

    def test_interrupted_live_seed_prevents_its_owned_work_from_being_deleted(self):
        from delete_stores import _remove_work
        from delete_paths import DeleteError
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();work=root/'work';seed=work/'cookie-seed-fixture/profile';seed.mkdir(parents=True)
            marker=work/'.sync-owner.bin';marker.write_bytes(b'synthetic')
            evidence=seed/'keep';evidence.write_bytes(b'synthetic')
            service=SimpleNamespace(store=SimpleNamespace(unpack=lambda value:{'format':1,'ownership':{}}))
            with patch('browser_processes.profile_processes',return_value=[object()]):
                with self.assertRaises(DeleteError):_remove_work(service,work,root,{})
            self.assertTrue(marker.exists());self.assertTrue(evidence.exists())
            with patch('browser_processes.profile_processes',return_value=[]):_remove_work(service,work,root,{})
            self.assertFalse(work.exists())


class ExpiryRepairTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self.temp=tempfile.TemporaryDirectory(prefix='cookie-expiry-repair-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.profile=self.root/'profiles/fixture'
        self.database=self.profile/'Default/Network/Cookies';self.database.parent.mkdir(parents=True)
        (self.profile/'Local State').write_text('{"os_crypt":{"synthetic":true}}',encoding='utf-8')
        self.key=bytes(range(32));self.cipher=AESGCM(self.key)
        self.deadline=time.time()+86400*500;self.native_cap=time.time()+86400*300
        self.cookie={'domain':'.example.invalid','name':'session','path':'/','value':'fixture-value',
            'secure':True,'httpOnly':True,'session':True,'expires':self.deadline}
        self.record={'id':'fixture','_source_info':{'cookie':[copy.deepcopy(self.cookie)]},
            '_startup_cookies':{'format':1,'count':1},'_runtime':{'profile_path':str(self.profile),'core_major':'148'},
            '_native':{'DataProtect':{'synthetic':True}},'_continuity':{'synthetic':True},
            '_portable_crypt':{'format':1,'key':base64.b64encode(self.key).decode(),'key_id':hashlib.sha256(self.key).hexdigest()}}
        self.service=SimpleNamespace(root=self.root,_closed=Mock(),_sync=Mock(),store=SimpleNamespace(put=Mock()))
        self.service._copy_profile=Mock(side_effect=lambda source,target:shutil.copytree(source,target))
        con=sqlite3.connect(self.database)
        con.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT)');con.execute("INSERT INTO meta VALUES('version','24')")
        con.execute('CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,value TEXT,encrypted_value BLOB,expires_utc INTEGER,has_expires INTEGER,is_persistent INTEGER,is_secure INTEGER,is_httponly INTEGER,top_frame_site_key TEXT,has_cross_site_ancestor INTEGER,UNIQUE(host_key,name,path,top_frame_site_key,has_cross_site_ancestor))')
        con.commit();con.close()
        self.ciphers={};self.add_row(self.cookie)
        self.response=[{**copy.deepcopy(self.cookie),'expires':self.deadline}]
        self.opens=0;self.reads=0;self.on_close=None;self.fail_open=False;self.last_set=None
        owner=self
        class Controller:
            def __init__(self,_root,settings):
                runtime=settings['windows'][0];self.profiles={runtime['alias']:runtime}
                owner.seed_profile=Path(runtime['profile_path'])
                owner.assertEqual(runtime['account_password'],'');owner.assertEqual(runtime['account_username'],'')
                owner.assertEqual(runtime['initial_urls'],[])
            def open(self,*_,**options):
                owner.opens+=1
                owner.assertTrue(options['offline_test']);owner.assertTrue(options['background_probe'])
                owner.assertEqual(options['extra_urls'],['about:blank'])
                if owner.fail_open:raise ValueError('synthetic unavailable engine')
            def endpoint(self,*_):return 'synthetic'
            def close(self,*_):
                if owner.on_close:owner.on_close()
        class Connection:
            def __init__(self,*_):pass
            def __enter__(self):
                con=sqlite3.connect(owner.seed_profile/'Default/Network/Cookies')
                rows=con.execute('SELECT name,encrypted_value,has_expires,is_persistent FROM cookies').fetchall();con.close()
                owner.assertEqual(len(rows),len(owner.response))
                for name,cipher,has_expires,persistent in rows:
                    owner.assertTrue(cipher==owner.ciphers[name]);owner.assertEqual((has_expires,persistent),(1,1))
                return self
            def __exit__(self,*_):return False
            def call(self,method,params=None):
                if method=='Storage.getCookies':owner.reads+=1;return {'cookies':copy.deepcopy(owner.response)}
                if method=='Storage.setCookies':
                    owner.last_set=copy.deepcopy(params)
                    owner.response=[{**cookie,'expires':min(cookie['expires'],owner.native_cap)} for cookie in params['cookies']]
                    return {}
                raise AssertionError('unexpected synthetic method')
        for target,replacement in [('import_cookies.BrowserController',Controller),('import_cookies.CDP',Connection),
                ('import_cookies.profile_processes',lambda *a,**k:[])]:
            mocked=patch(target,replacement);mocked.start();self.addCleanup(mocked.stop)

    def add_row(self,cookie,*,value=None,opaque=False,partition='',ancestor=0):
        clear=(b'native protected layer' if opaque else hashlib.sha256(cookie['domain'].encode()).digest()+
            (cookie['value'] if value is None else value).encode())
        nonce=os.urandom(12);encrypted=b'v10'+nonce+self.cipher.encrypt(nonce,clear,None)
        con=sqlite3.connect(self.database)
        con.execute('INSERT OR REPLACE INTO cookies VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
            (cookie['domain'],cookie['name'],cookie['path'],'',encrypted,0,0,0,int(cookie['secure']),int(cookie['httpOnly']),partition,ancestor))
        con.commit();con.close();self.ciphers[cookie['name']]=encrypted
        return encrypted

    def rows(self):
        con=sqlite3.connect(self.database)
        try:return con.execute('SELECT name,encrypted_value,expires_utc,has_expires,is_persistent FROM cookies ORDER BY name').fetchall()
        finally:con.close()

    def legacy_database(self,value):
        nonce=os.urandom(12);encrypted=b'v10'+nonce+self.cipher.encrypt(nonce,value.encode(),None)
        con=sqlite3.connect(self.database)
        con.execute('DROP TABLE cookies');con.execute("UPDATE meta SET value='23' WHERE key='version'")
        con.execute('CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,value TEXT,encrypted_value BLOB,expires_utc INTEGER,has_expires INTEGER,is_persistent INTEGER,is_secure INTEGER,is_httponly INTEGER,UNIQUE(host_key,name,path))')
        con.execute('INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?,?)',
            (self.cookie['domain'],self.cookie['name'],self.cookie['path'],'',encrypted,0,0,0,1,1))
        con.commit();con.close();self.ciphers[self.cookie['name']]=encrypted
        return encrypted

    def test_legacy_schema_without_host_hash_repairs_only_matching_current_value(self):
        encrypted=self.legacy_database(self.cookie['value'])
        updated=prepare_existing(self.service,self.record)
        self.assertEqual(updated['_startup_cookies']['expiry_repaired'],1)
        self.assertEqual(self.opens,1);self.assertTrue(self.rows()[0][1]==encrypted)
        self.assertEqual(self.rows()[0][3:],(1,1))

    def test_legacy_schema_changed_value_and_absent_partition_never_replay(self):
        for changed in (True,False):
            with self.subTest(changed=changed):
                self.legacy_database('new-current-value' if changed else self.cookie['value'])
                record=copy.deepcopy(self.record)
                if not changed:record['_source_info']['cookie'][0]['partitionKey']={'topLevelSite':'https://first.invalid'}
                before=self.rows();updated=prepare_existing(self.service,record)
                self.assertEqual(self.rows(),before);self.assertEqual(updated['_startup_cookies']['expiry_repaired'],0)
        self.assertEqual(self.opens,0);self.service._copy_profile.assert_not_called()

    def test_matching_value_repairs_only_expiry_with_native_cap_and_keeps_backup(self):
        unrelated={**self.cookie,'name':'unrelated','value':'keep'};self.add_row(unrelated)
        before=copy.deepcopy(self.record);encrypted=self.ciphers[self.cookie['name']]
        updated=prepare_existing(self.service,self.record)
        row=next(row for row in self.rows() if row[0]==self.cookie['name'])
        self.assertTrue(row[1]==encrypted)
        self.assertEqual(row[2:],(int(self.native_cap*1_000_000)+_CHROME_EPOCH_US,1,1))
        self.assertEqual(updated['_startup_cookies']['expiry_revision'],2)
        self.assertEqual(updated['_startup_cookies']['expiry_repaired'],1)
        self.assertEqual(self.record,before);self.assertEqual(updated['_native'],before['_native'])
        self.assertEqual(updated['_continuity'],before['_continuity'])
        keep=next(row for row in self.rows() if row[0]=='unrelated')
        self.assertEqual(keep[2:],(0,0,0));self.assertTrue(keep[1]==self.ciphers['unrelated'])
        backups=list((self.root/'backups').iterdir());self.assertEqual(len(backups),1)
        self.assertTrue((backups[0]/'Default/Network/Cookies').is_file())
        self.assertEqual(list(backups[0].glob('cookie-seed-*')),[])
        self.assertIs(prepare_existing(None,updated),updated);self.assertEqual(self.opens,1)

    def test_dataprotect_opaque_value_requires_native_authentication_before_repair(self):
        encrypted=self.add_row(self.cookie,opaque=True)
        updated=prepare_existing(self.service,self.record)
        self.assertEqual(self.opens,1);self.assertEqual(self.reads,2)
        self.assertEqual(updated['_startup_cookies']['expiry_repaired'],1)
        self.assertTrue(self.rows()[0][1]==encrypted)

    def test_changed_current_value_is_never_replayed_and_skips_native_probe(self):
        self.add_row(self.cookie,value='new-current-value');before=self.rows()
        updated=prepare_existing(self.service,self.record)
        self.assertEqual(self.rows(),before);self.assertEqual(self.opens,0)
        self.assertEqual(updated['_startup_cookies']['expiry_repaired'],0)
        self.service._copy_profile.assert_not_called()

    def test_changed_native_value_is_never_overwritten_when_protection_is_opaque(self):
        self.add_row(self.cookie,opaque=True);self.response[0]['value']='new-current-value';before=self.rows()
        updated=prepare_existing(self.service,self.record)
        self.assertEqual(self.rows(),before);self.assertIsNone(self.last_set)
        self.assertEqual(updated['_startup_cookies']['expiry_repaired'],0)

    def test_expired_snapshot_or_partition_mismatch_only_upgrades_revision(self):
        for expired in (True,False):
            with self.subTest(expired=expired):
                record=copy.deepcopy(self.record)
                if expired:record['_source_info']['cookie'][0]['expires']=time.time()-1
                else:record['_source_info']['cookie'][0]['partitionKey']={'topLevelSite':'https://other.invalid','hasCrossSiteAncestor':True}
                before=self.rows();updated=prepare_existing(self.service,record)
                self.assertEqual(self.rows(),before);self.assertEqual(updated['_startup_cookies']['expiry_revision'],2)
                self.assertEqual(updated['_startup_cookies']['expiry_repaired'],0)
        self.assertEqual(self.opens,0);self.service._copy_profile.assert_not_called()

    def test_security_flags_must_match_before_any_repair(self):
        before=self.rows()
        for key in ('secure','httpOnly'):
            record=copy.deepcopy(self.record);record['_source_info']['cookie'][0][key]=False
            updated=prepare_existing(self.service,record)
            self.assertEqual(updated['_startup_cookies']['expiry_repaired'],0)
            self.assertEqual(self.rows(),before)
        self.assertEqual(self.opens,0);self.service._copy_profile.assert_not_called()

    def test_matching_partition_repairs_only_the_identical_partition_and_ancestor(self):
        original_cipher=self.ciphers[self.cookie['name']]
        partition={'topLevelSite':'https://first.invalid','hasCrossSiteAncestor':True}
        self.cookie['partitionKey']=partition
        self.record['_source_info']['cookie']=[copy.deepcopy(self.cookie)]
        self.response=[copy.deepcopy(self.cookie)]
        matching_cipher=self.add_row(self.cookie,partition=partition['topLevelSite'],ancestor=1)
        updated=prepare_existing(self.service,self.record)
        self.assertEqual(updated['_startup_cookies']['expiry_repaired'],1)
        con=sqlite3.connect(self.database)
        rows=con.execute('SELECT top_frame_site_key,has_cross_site_ancestor,encrypted_value,has_expires,is_persistent FROM cookies ORDER BY top_frame_site_key').fetchall();con.close()
        self.assertEqual(rows[0][:2],('',0));self.assertEqual(rows[0][3:],(0,0));self.assertTrue(rows[0][2]==original_cipher)
        self.assertEqual(rows[1][:2],(partition['topLevelSite'],1));self.assertEqual(rows[1][3:],(1,1));self.assertTrue(rows[1][2]==matching_cipher)

    def test_wrong_oscrypt_key_or_unknown_encrypted_scheme_never_guesses(self):
        before=self.rows();wrong=bytes(reversed(range(32)));record=copy.deepcopy(self.record)
        record['_portable_crypt']={'format':1,'key':base64.b64encode(wrong).decode(),'key_id':hashlib.sha256(wrong).hexdigest()}
        with self.assertRaises(LocalBrowserError):prepare_existing(self.service,record)
        self.assertEqual(self.rows(),before);self.assertEqual(self.opens,0)
        con=sqlite3.connect(self.database);con.execute('UPDATE cookies SET encrypted_value=?',(b'v20'+bytes(40),));con.commit();con.close()
        before=self.rows()
        with self.assertRaises(LocalBrowserError):prepare_existing(self.service,self.record)
        self.assertEqual(self.rows(),before);self.assertEqual(self.opens,0)

    def test_native_unavailable_keeps_old_marker_and_database_unchanged(self):
        self.fail_open=True;before=self.rows();original=copy.deepcopy(self.record)
        with self.assertRaises(LocalBrowserError):prepare_existing(self.service,self.record)
        self.assertEqual(self.rows(),before);self.assertEqual(self.record,original)
        self.service.store.put.assert_not_called()
        self.assertTrue((self.root/'backups').is_dir())

    def test_row_changed_after_native_authentication_cannot_receive_old_expiry(self):
        def change():self.add_row(self.cookie,value='rotated-during-verification')
        self.on_close=change
        with self.assertRaises(LocalBrowserError):prepare_existing(self.service,self.record)
        row=self.rows()[0];self.assertEqual(row[2:],(0,0,0))
        self.assertTrue(row[1]==self.ciphers[self.cookie['name']]);self.service.store.put.assert_not_called()

    def test_transaction_failure_rolls_back_all_metadata_without_replaying_values(self):
        second={**self.cookie,'name':'second'};self.add_row(second)
        self.record['_source_info']['cookie'].append(second)
        con=sqlite3.connect(self.database)
        con.execute("CREATE TRIGGER block_expiry BEFORE UPDATE ON cookies WHEN NEW.name='second' BEGIN SELECT RAISE(ABORT,'fixture'); END")
        con.commit();con.close();before=self.rows()
        with patch('import_cookies._native_expiry',side_effect=lambda *args:args[4]):
            with self.assertRaises(LocalBrowserError):prepare_existing(self.service,self.record)
        self.assertEqual(self.rows(),before);self.service.store.put.assert_not_called()

    def test_marker_commit_failure_is_idempotent_after_metadata_commit(self):
        self.service.store.put.side_effect=OSError('synthetic marker failure')
        with self.assertRaises(OSError):prepare_existing(self.service,self.record)
        first=self.rows();self.assertEqual(first[0][3:],(1,1));self.assertEqual(self.opens,1)
        self.service.store.put.side_effect=None
        updated=prepare_existing(self.service,self.record)
        self.assertEqual(self.rows(),first);self.assertEqual(self.opens,1)
        self.assertEqual(updated['_startup_cookies']['expiry_revision'],2)
        self.assertEqual(len(list((self.root/'backups').iterdir())),1)

    def test_native_expiry_never_exceeds_the_original_source_deadline(self):
        self.native_cap=self.deadline+86400
        prepare_existing(self.service,self.record)
        self.assertEqual(self.rows()[0][2],int(self.deadline)*1_000_000+_CHROME_EPOCH_US)

    def test_fresh_empty_materialization_marks_revision_two(self):
        record=copy.deepcopy(self.record);record.pop('_startup_cookies');record['_source_info']['cookie']=[]
        self.assertTrue(materialize(self.service,record,self.profile))
        self.assertEqual(record['_startup_cookies'],{'format':1,'expiry_revision':2,'count':0})


if __name__=='__main__':unittest.main(verbosity=2)
