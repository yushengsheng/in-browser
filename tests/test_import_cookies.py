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

    def test_normalized_cookie_duplicates_merge_only_equivalent_records(self):
        first=self.cookie(hostOnly=True)
        equivalent={**first,'domain':'example.invalid'}
        self.assertEqual(len(source_cookies({'cookie':[first,equivalent]})),1)
        host=self.cookie(name='__Host-fixture',path='/ignored')
        self.assertEqual(len(source_cookies({'cookie':[host,{**host,'path':'/'}]})),1)
        partition={'topLevelSite':'https://first.invalid'}
        first=self.cookie(partitionKey=partition)
        equivalent={**first,'partitionKey':{**partition,'hasCrossSiteAncestor':False}}
        self.assertEqual(len(source_cookies({'cookie':[first,equivalent]})),1)
        distinct={**first,'partitionKey':{**partition,'hasCrossSiteAncestor':True}}
        self.assertEqual(len(source_cookies({'cookie':[first,distinct]})),2)

    def test_conflicting_normalized_cookie_duplicates_are_rejected(self):
        first=self.cookie(hostOnly=True)
        for change in ({'value':'different'},{'expires':2000000000},{'secure':False},{'httpOnly':False}):
            with self.subTest(field=next(iter(change))),self.assertRaises(ValueError):
                source_cookies({'cookie':[first,{**first,'domain':'example.invalid',**change}]},now=1000)

    @staticmethod
    def metadata(con,version=24):
        con.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT)')
        con.executemany('INSERT INTO meta VALUES(?,?)',[('version',str(version)),('last_compatible_version',str(version))])

    def database(self,path,rows):
        con=sqlite3.connect(path)
        self.metadata(con)
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

    def test_same_columns_with_incompatible_meta_or_indexes_are_rejected(self):
        changes=("UPDATE meta SET value='23' WHERE key='version'",
                 "UPDATE meta SET value='23' WHERE key='last_compatible_version'",
                 "DELETE FROM meta WHERE key='version'",
                 'CREATE UNIQUE INDEX different_identity ON cookies(host_key,name)',
                 'CREATE UNIQUE INDEX different_collation ON cookies(host_key COLLATE NOCASE,name,path)')
        for change in changes:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve();source=root/'source';target=root/'target'
                self.database(source,[('example.invalid','session','/',b'new',100,1,1)])
                self.database(target,[('example.invalid','session','/',b'old',99,1,1)])
                con=sqlite3.connect(target);con.execute(change);con.commit();con.close()
                before=target.read_bytes()
                with self.assertRaises(ValueError):_merge_database(source,target,set(),1)
                self.assertEqual(target.read_bytes(),before)

    def test_same_columns_with_incompatible_partition_uniqueness_never_drop_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'source';target=root/'target'
            for database in (source,target):
                con=sqlite3.connect(database);self.metadata(con)
                unique='host_key,name,path,top_frame_site_key' if database==source else 'host_key,name,path'
                con.execute('CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,encrypted_value BLOB,expires_utc INTEGER,has_expires INTEGER,is_persistent INTEGER,top_frame_site_key TEXT,UNIQUE('+unique+'))')
                if database==source:
                    con.executemany('INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?)',[
                        ('example.invalid','session','/',b'first',100,1,1,'https://first.invalid'),
                        ('example.invalid','session','/',b'second',200,1,1,'https://second.invalid')])
                con.commit();con.close()
            before=target.read_bytes()
            with self.assertRaises(ValueError):_merge_database(source,target,set(),2)
            self.assertEqual(target.read_bytes(),before)

    def test_partitioned_session_does_not_change_another_partition_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'source';target=root/'target'
            for path in (source,target):
                con=sqlite3.connect(path)
                self.metadata(con)
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
            self.metadata(con)
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


class PartitionConflictTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from local_state import _dpapi_protect
        temporary=tempfile.TemporaryDirectory(prefix='partition-conflict-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.profile=self.root/'profile'
        self.database=self.profile/'Default/Network/Cookies';self.database.parent.mkdir(parents=True)
        self.key=bytes(range(32));self.cipher=AESGCM(self.key);self.expiry=int(time.time())+7200
        state={'os_crypt':{'encrypted_key':base64.b64encode(b'DPAPI'+_dpapi_protect(self.key)).decode()}}
        (self.profile/'Local State').write_text(json.dumps(state),encoding='utf-8')
        self.snapshots=[{'domain':'example.invalid','name':'session','path':'/','value':value,
                         'secure':True,'httpOnly':True,'sameSite':'Lax','expires':self.expiry}
                        for value in ('synthetic-first','synthetic-second')]
        self.actual=[{**cookie,'session':False,'partitionKey':{'topLevelSite':site,'hasCrossSiteAncestor':bool(index)}}
                     for index,(cookie,site) in enumerate(zip(self.snapshots,('https://first.invalid','https://second.invalid')))]
        self.write_database(self.database,self.actual)
        self.record={'_source_info':{'cookie':copy.deepcopy(self.snapshots)},
                     '_runtime':{'alias':'synthetic','core_major':'148','profile_path':str(self.profile)},
                     '_portable_crypt':{'format':1,'key':base64.b64encode(self.key).decode(),'key_id':hashlib.sha256(self.key).hexdigest()}}
        self.service=SimpleNamespace(root=self.root);self.controllers=[];self.native_transform=lambda values:values
        process=patch('import_cookies.profile_processes',return_value=[]);process.start();self.addCleanup(process.stop)
        controller=patch('import_cookies.BrowserController',side_effect=self.controller);controller.start();self.addCleanup(controller.stop)
        cdp=patch('import_cookies.CDP',side_effect=self.connection);cdp.start();self.addCleanup(cdp.stop)

    def write_database(self,path,cookies):
        path.parent.mkdir(parents=True,exist_ok=True)
        con=sqlite3.connect(path)
        try:
            ImportCookieTests.metadata(con)
            con.execute('CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,top_frame_site_key TEXT,has_cross_site_ancestor INTEGER,encrypted_value BLOB,expires_utc INTEGER,has_expires INTEGER,is_persistent INTEGER,is_secure INTEGER,is_httponly INTEGER,samesite INTEGER,UNIQUE(host_key,name,path,top_frame_site_key,has_cross_site_ancestor))')
            for index,cookie in enumerate(cookies):
                nonce=bytes([index+1])*12
                encrypted=b'v10'+nonce+self.cipher.encrypt(nonce,hashlib.sha256(cookie['domain'].encode()).digest()+cookie['value'].encode(),None)
                key=cookie.get('partitionKey') or {}
                con.execute('INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                    (cookie['domain'],cookie['name'],cookie['path'],key.get('topLevelSite',''),int(key.get('hasCrossSiteAncestor',False)),encrypted,
                     int(cookie['expires'])*1_000_000+_CHROME_EPOCH_US,1,1,int(cookie['secure']),int(cookie['httpOnly']),1))
            con.commit()
        finally:con.close()

    def controller(self,root,*,settings):
        runtime=settings['windows'][0]
        controller=Mock();controller.profiles={runtime['alias']:runtime};controller.pending=[]
        controller.endpoint.return_value='synthetic-endpoint'
        def close(_):
            if controller.pending:
                self.write_database(Path(runtime['profile_path'])/'Default/Network/Cookies',controller.pending)
                controller.pending=[]
        controller.close.side_effect=close
        self.controllers.append(controller);return controller

    def connection(self,*args,**kwargs):
        controller=self.controllers[-1];connection=Mock()
        def call(method,params=None):
            if method=='Storage.setCookies':controller.pending=copy.deepcopy(params['cookies']);return {}
            values=controller.pending or self.actual
            return {'cookies':self.native_transform(copy.deepcopy(values))}
        connection.call.side_effect=call
        context=Mock();context.__enter__=Mock(return_value=connection);context.__exit__=Mock(return_value=False)
        return context

    def rows(self):
        con=sqlite3.connect(self.database)
        try:return con.execute('SELECT rowid,* FROM cookies ORDER BY rowid').fetchall()
        finally:con.close()

    def update(self,sql):
        con=sqlite3.connect(self.database)
        try:con.execute(sql);con.commit()
        finally:con.close()

    def rejected(self):
        before=self.rows()
        with self.assertRaises(LocalBrowserError):materialize(self.service,self.record,self.profile)
        self.assertEqual(self.rows(),before);self.assertNotIn('_startup_cookies',self.record)
        self.assertFalse(list(self.root.glob('cookie-seed-*')))

    def test_persistent_partition_conflict_preserves_original_rows_and_marks_proof(self):
        before=self.database.read_bytes()
        self.assertTrue(materialize(self.service,self.record,self.profile))
        self.assertEqual(self.database.read_bytes(),before)
        self.assertEqual(self.record['_startup_cookies']['preserved_partition_cookies'],2)
        self.assertEqual(self.record['_startup_cookies']['count'],0)
        self.assertEqual(len(self.controllers),1)
        self.assertFalse(list(self.root.glob('cookie-seed-*')))
        self.assertFalse(materialize(self.service,self.record,self.profile))
        self.assertEqual(len(self.controllers),1)

    def test_normal_cookie_merge_keeps_proven_partition_rows_unchanged(self):
        before=self.rows()
        ordinary={**self.snapshots[0],'name':'ordinary','value':'synthetic-extra'}
        self.record['_source_info']['cookie'].append(ordinary)
        self.assertTrue(materialize(self.service,self.record,self.profile))
        self.assertEqual(self.rows()[:2],before)
        self.assertEqual(len(self.rows()),3);self.assertEqual(len(self.controllers),2)
        self.assertEqual(self.record['_startup_cookies']['count'],1)

    def test_ordinary_snapshot_does_not_start_partition_proof(self):
        self.record['_source_info']['cookie']=[{**self.snapshots[0],'name':'ordinary'}]
        with patch('import_cookies._preserve_partition_conflicts') as proof:
            self.assertTrue(materialize(self.service,self.record,self.profile))
            proof.assert_not_called()
        self.assertEqual(len(self.controllers),1)

    def test_unsupported_or_overlapping_snapshot_conflicts_are_rejected(self):
        original=copy.deepcopy(self.record)
        for change in ({'session':True},{'partitionKey':{'topLevelSite':'https://first.invalid'}},
                       {'partitionKeyOpaque':True},{'expires':-1}):
            with self.subTest(field=next(iter(change))):
                self.record=copy.deepcopy(original)
                for cookie in self.record['_source_info']['cookie']:cookie.update(change)
                self.rejected()
        self.record=copy.deepcopy(original)
        self.record['_source_info']['cookie'].append({**self.snapshots[0],
            'partitionKey':{'topLevelSite':'https://first.invalid','hasCrossSiteAncestor':False}})
        self.rejected()
        self.assertEqual(len(self.controllers),0)

    def test_missing_extra_unpartitioned_or_nonpersistent_native_rows_are_rejected(self):
        original=self.database.read_bytes()
        changes=("DELETE FROM cookies WHERE rowid=2",
                 "UPDATE cookies SET top_frame_site_key='' WHERE rowid=2",
                 "UPDATE cookies SET expires_utc=1 WHERE rowid=2",
                 "UPDATE cookies SET is_persistent=0,has_expires=0,expires_utc=0 WHERE rowid=2",
                 "INSERT INTO cookies SELECT host_key,name,path,'https://extra.invalid',has_cross_site_ancestor,encrypted_value,expires_utc,has_expires,is_persistent,is_secure,is_httponly,samesite FROM cookies WHERE rowid=1")
        for sql in changes:
            with self.subTest(case=sql.split()[0]):
                self.database.write_bytes(original);self.update(sql);self.rejected()
        self.assertEqual(len(self.controllers),0)

    def test_native_value_flags_same_site_partition_or_missing_cookie_mismatch_rejects(self):
        changes=({'value':'different'},{'secure':False},{'httpOnly':False},{'sameSite':'Strict'},
                 {'partitionKeyOpaque':True},{'session':True},{'expires':float('nan')},
                 {'partitionKey':{'topLevelSite':'https://first.invalid'}},
                 {'partitionKey':{'topLevelSite':'https://other.invalid','hasCrossSiteAncestor':False}})
        for change in changes:
            with self.subTest(field=next(iter(change))):
                self.native_transform=lambda values,change=change:[{**values[0],**change},values[1]]
                self.rejected()
        self.native_transform=lambda values:values[:1];self.rejected()

    def test_duplicate_values_do_not_make_an_ambiguous_matching_proof(self):
        cookies=self.record['_source_info']['cookie'];cookies[1]['value']=cookies[0]['value'];cookies[1]['httpOnly']=False
        self.rejected();self.assertEqual(len(self.controllers),0)
        many=[{**self.snapshots[0],'value':'synthetic-'+str(index)} for index in range(10000)]
        conflicts=[];dumps=json.dumps
        with patch('import_cookies.json.dumps',wraps=dumps) as signatures:
            self.assertEqual(source_cookies({'cookie':many},_conflicts=conflicts),[])
        self.assertEqual(signatures.call_count,len(many))
        self.assertEqual(len(conflicts),1);self.assertEqual(len(conflicts[0]),len(many))

    def test_wrong_key_or_unknown_cipher_never_reaches_native_probe(self):
        original=self.database.read_bytes()
        for encrypted in (b'v20'+b'x'*40,b'v10'+b'x'*40):
            con=sqlite3.connect(self.database)
            try:con.execute('UPDATE cookies SET encrypted_value=? WHERE rowid=2',(encrypted,));con.commit()
            finally:con.close()
            self.rejected();self.database.write_bytes(original)
        wrong=bytes(reversed(self.key))
        self.record['_portable_crypt']={'format':1,'key':base64.b64encode(wrong).decode(),'key_id':hashlib.sha256(wrong).hexdigest()}
        self.rejected()
        self.assertEqual(len(self.controllers),0)

    def test_native_timeout_cleans_proof_and_never_marks_success(self):
        def timeout(_):raise TimeoutError()
        self.native_transform=timeout;self.rejected()

    def test_row_change_during_native_proof_is_rejected(self):
        def changed(values):
            self.update('UPDATE cookies SET is_httponly=0 WHERE rowid=2')
            return values
        self.native_transform=changed
        with self.assertRaises(LocalBrowserError):materialize(self.service,self.record,self.profile)
        self.assertNotIn('_startup_cookies',self.record)
        self.assertFalse(list(self.root.glob('cookie-seed-*')))

    def test_corrupt_database_or_changed_state_never_marks_a_proof(self):
        original=self.database.read_bytes();self.database.write_bytes(b'synthetic-invalid-sqlite')
        with self.assertRaises(LocalBrowserError):materialize(self.service,self.record,self.profile)
        self.assertEqual(self.database.read_bytes(),b'synthetic-invalid-sqlite')
        self.assertNotIn('_startup_cookies',self.record);self.assertEqual(len(self.controllers),0)
        self.database.write_bytes(original)
        def changed(values):
            state=self.profile/'Local State';state.write_bytes(state.read_bytes()+b' ')
            return values
        self.native_transform=changed
        with self.assertRaises(LocalBrowserError):materialize(self.service,self.record,self.profile)
        self.assertEqual(self.database.read_bytes(),original)
        self.assertNotIn('_startup_cookies',self.record)
        self.assertFalse(list(self.root.glob('cookie-seed-*')))

    def test_merge_trigger_touching_preserved_rows_rolls_back_all_writes(self):
        self.update("CREATE TRIGGER tamper AFTER INSERT ON cookies WHEN NEW.name='ordinary' BEGIN UPDATE cookies SET is_httponly=0 WHERE name='session'; END")
        self.record['_source_info']['cookie'].append({**self.snapshots[0],'name':'ordinary','value':'synthetic-extra'})
        self.rejected()
        self.assertEqual(len(self.rows()),2);self.assertEqual(len(self.controllers),2)


if __name__=='__main__':unittest.main(verbosity=2)
