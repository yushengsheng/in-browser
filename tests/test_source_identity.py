"""Read-only bounded prepared-source identities over synthetic browser files."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import local_source
from local_source import profile_identity
from local_state import LocalBrowserError

A='1'*32


class SourceIdentityTests(unittest.TestCase):
    def setUp(self):
        base=ROOT/'analysis/test-runs';base.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='source-identity-probe-',dir=base) as name:
            probe=Path(name).resolve();self.assertTrue(probe.is_relative_to(base.resolve()))
            (probe/'nested').mkdir();(probe/'nested/proof').write_bytes(b'synthetic')
        self.assertFalse(probe.exists())
        self.temporary=tempfile.TemporaryDirectory(prefix='source-identity-',dir=base)
        self.base=Path(self.temporary.name).resolve();self.addCleanup(self.cleanup)
        (self.base/'owner.json').write_text(json.dumps({'pid':os.getpid(),'owner':'source-identity-synthetic'}))
        self.profiles=self.base/'profiles';self.folder=self.profiles/A
        (self.folder/'Default/Network').mkdir(parents=True)
        (self.folder/'Default/Sessions').mkdir()
        for relative in ('Local State','Default/Preferences','Last Version'):
            (self.folder/relative).write_bytes(b'synthetic')
        self.configuration=SimpleNamespace(vendor_data=self.base/'missing-vendor',
            source_archive=lambda:{'profile_root':str(self.profiles)})

    def cleanup(self):
        self.assertTrue(self.base.is_relative_to((ROOT/'analysis/test-runs').resolve()))
        self.assertFalse(any(path.is_symlink() or getattr(path.lstat(),'st_file_attributes',0)&0x400
                             for path in (self.base,*self.base.rglob('*'))))
        self.temporary.cleanup();self.assertFalse(self.base.exists())

    def identity(self):return profile_identity(self.configuration,A)

    def write(self,relative,value):
        path=self.folder/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value)
        return path

    def rewrite_same_size(self,path,value):
        previous=path.stat();self.assertEqual(previous.st_size,len(value))
        path.write_bytes(value);os.utime(path,ns=(previous.st_atime_ns,previous.st_mtime_ns))

    def test_cookie_password_sidecars_and_tabgroups_bind_content_and_missing_state(self):
        relatives=[database+suffix for database in local_source._PROFILE_DATABASES for suffix in ('','-wal','-shm','-journal')]
        relatives.append('Default/~TabGroups')
        for relative in relatives:self.write(relative,b'old bytes')
        previous=self.identity()
        self.assertEqual(len(previous['files']),5)
        for relative in relatives:
            with self.subTest(relative=relative):
                path=self.folder/relative
                self.rewrite_same_size(path,b'new bytes')
                current=self.identity()
                self.assertNotEqual(previous,current)
                self.assertEqual(current['critical']['files'][relative]['sha256'],hashlib.sha256(b'new bytes').hexdigest())
                path.unlink();missing=self.identity()
                self.assertIsNone(missing['critical']['files'][relative])
                self.assertNotEqual(current,missing)
                previous=missing

    def test_sessions_bind_creation_removal_and_content_without_using_directory_mtime(self):
        directory=self.folder/'Default/Sessions';before=self.identity();stamp=directory.stat()
        for name in ('Session_1','Tabs_2'):
            path=self.write('Default/Sessions/'+name,b'old session')
            os.utime(directory,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
            current=self.identity();self.assertNotEqual(before,current)
            relative='Default/Sessions/'+name
            self.assertIn(relative,current['critical']['files'])
            self.rewrite_same_size(path,b'new session')
            rewritten=self.identity();self.assertNotEqual(current,rewritten)
            self.assertEqual(rewritten['critical']['files'][relative]['sha256'],hashlib.sha256(b'new session').hexdigest())
            path.unlink();removed=self.identity()
            self.assertNotIn(relative,removed['critical']['files']);self.assertNotEqual(rewritten,removed)

    def test_sqlite_wal_changes_invalidate_preparation_without_opening_database(self):
        path=self.folder/'Default/Network/Cookies';con=sqlite3.connect(path)
        try:
            con.execute('CREATE TABLE cookies(value TEXT)');con.commit()
            con.execute('PRAGMA journal_mode=WAL');con.execute('PRAGMA wal_autocheckpoint=0')
            con.execute("INSERT INTO cookies VALUES('old value')");con.commit()
            main=hashlib.sha256(path.read_bytes()).digest();before=self.identity()
            con.execute("UPDATE cookies SET value='new value'");con.commit()
            snapshot={p.name:hashlib.sha256(p.read_bytes()).digest() for p in path.parent.iterdir()}
            with patch('sqlite3.connect',side_effect=AssertionError('Identity must not connect source SQLite')):
                after=self.identity()
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(),main)
            self.assertNotEqual(before,after)
            self.assertEqual(snapshot,{p.name:hashlib.sha256(p.read_bytes()).digest() for p in path.parent.iterdir()})
        finally:con.close()

    def test_copy_or_move_does_not_reuse_another_location_identity(self):
        self.write('Default/Network/Cookies',b'synthetic cookie')
        before=self.identity();copied=self.base/'copied-profiles';shutil.copytree(self.profiles,copied)
        config=SimpleNamespace(vendor_data=self.base/'missing-vendor',source_archive=lambda:{'profile_root':str(copied)})
        copied_identity=profile_identity(config,A)
        self.assertNotEqual(before['path'],copied_identity['path']);self.assertNotEqual(before,copied_identity)
        moved=self.base/'moved-profiles'
        self.assertTrue(copied.resolve().is_relative_to(self.base))
        self.assertTrue(moved.resolve().is_relative_to(self.base))
        copied.rename(moved)
        config.source_archive=lambda:{'profile_root':str(moved)}
        self.assertNotEqual(copied_identity,profile_identity(config,A))

    def test_change_between_hash_rounds_is_rejected_even_when_metadata_is_unchanged(self):
        path=self.write('Default/Network/Cookies',b'old bytes');actual=local_source._profile_digest
        inventory=local_source._profile_inventory(self.profiles,self.folder,local_source.time.monotonic()+20)
        changed=[]
        def digest(target,expected,deadline):
            if target==path:expected=local_source._profile_stamp(target.lstat())
            value=actual(target,expected,deadline)
            if target==path and not changed:
                self.rewrite_same_size(path,b'new bytes');changed.append(True)
            return value
        # Keep inventory stamps fixed to establish that both content rounds,
        # independently of directory/file timestamps, must agree.
        with patch.object(local_source,'_profile_inventory',return_value=inventory),\
                patch.object(local_source,'_profile_digest',side_effect=digest),self.assertRaises(LocalBrowserError):
            self.identity()

    def test_old_prepared_identity_without_critical_binding_is_stale(self):
        from configuration import Configuration
        current=self.identity();old={key:copy.deepcopy(current[key]) for key in ('path','files')}
        saved={'profile_identity':old,'native_source':{'synthetic':True}}
        self.configuration.prepared_sources=lambda:SimpleNamespace(get=lambda _:saved)
        with patch.object(local_source,'source_signature_identity',return_value={'synthetic':True}):
            self.assertFalse(Configuration.source_prepared_for_profile(self.configuration,A))
            saved['profile_identity']=current
            self.assertTrue(Configuration.source_prepared_for_profile(self.configuration,A))

    def test_bounds_reject_before_reading_oversized_groups_and_directory_counts(self):
        first=self.write('Default/Network/Cookies',b'12345')
        second=self.write('Default/Login Data',b'12345')
        with patch.object(local_source,'_PROFILE_DATABASE_BYTES',8),\
                patch.object(local_source,'_profile_digest',side_effect=AssertionError('No oversized read')),self.assertRaises(LocalBrowserError):
            self.identity()
        first.unlink();second.unlink()
        self.write('Default/Sessions/Session_1',b'12345');self.write('Default/Sessions/Tabs_1',b'12345')
        with patch.object(local_source,'_PROFILE_SESSION_BYTES',8),self.assertRaises(LocalBrowserError):self.identity()
        with patch.object(local_source,'_PROFILE_SESSION_FILE_BYTES',4),self.assertRaises(LocalBrowserError):self.identity()
        with patch.object(local_source,'_PROFILE_SESSION_ENTRIES',1),self.assertRaises(LocalBrowserError):self.identity()
        with patch.object(local_source,'_PROFILE_IDENTITY_FILES',3),self.assertRaises(LocalBrowserError):self.identity()
        with patch.object(local_source.time,'monotonic',side_effect=[0,21]),self.assertRaises(LocalBrowserError):self.identity()

    def test_only_fixed_paths_and_one_session_directory_are_read(self):
        ignored=self.write('Default/IndexedDB/example/large-ignored-file',b'old bytes')
        before=self.identity();actual=os.scandir;scanned=[]
        def scan(path):
            scanned.append(Path(path))
            self.assertEqual(Path(path),self.folder/'Default/Sessions')
            return actual(path)
        self.rewrite_same_size(ignored,b'new bytes')
        with patch.object(local_source.os,'scandir',side_effect=scan),\
                patch.object(Path,'rglob',side_effect=AssertionError('No full profile scan')):
            self.assertEqual(before,self.identity())
        self.assertEqual(len(scanned),3)

    def junction(self,link,target):
        if os.name=='nt':
            result=subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,timeout=10,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            self.assertEqual(result.returncode,0)
            self.addCleanup(lambda:link.rmdir() if os.path.lexists(link) else None)
        else:
            link.symlink_to(target,target_is_directory=True)
            self.addCleanup(lambda:link.unlink() if os.path.lexists(link) else None)

    def test_directory_links_are_rejected_even_for_missing_optional_files(self):
        for relative in ('Default/Network','Default/Sessions'):
            with self.subTest(relative=relative):
                path=self.folder/relative;path.rmdir();external=self.base/('external-'+path.name);external.mkdir()
                self.junction(path,external)
                with self.assertRaises(LocalBrowserError):self.identity()
                if os.name=='nt':path.rmdir()
                else:path.unlink()
                path.mkdir()

    def test_matching_session_links_or_non_regular_files_are_rejected(self):
        external=self.base/'external-session';external.mkdir()
        self.junction(self.folder/'Default/Sessions/Session_1',external)
        with self.assertRaises(LocalBrowserError):self.identity()

    def test_cookie_link_attributes_and_unreadable_content_are_rejected(self):
        path=self.write('Default/Network/Cookies',b'synthetic cookie');actual_stat=Path.lstat
        def linked(target,*args,**kwargs):
            value=actual_stat(target,*args,**kwargs)
            if target==path:
                return SimpleNamespace(st_mode=stat.S_IFREG,st_file_attributes=0x400)
            return value
        with patch.object(Path,'lstat',new=linked),self.assertRaises(LocalBrowserError):self.identity()
        actual_open=Path.open
        def unreadable(target,*args,**kwargs):
            if target==path:raise PermissionError('synthetic exception must stay local')
            return actual_open(target,*args,**kwargs)
        with patch.object(Path,'open',new=unreadable),self.assertRaises(LocalBrowserError) as caught:self.identity()
        self.assertNotIn('synthetic exception',str(caught.exception))

    def test_session_directory_file_limit_is_bounded_at_existing_policy(self):
        for number in range(local_source._PROFILE_SESSION_ENTRIES):
            self.write('Default/Sessions/Session_'+str(number),b'')
        value=self.identity()
        sessions=[name for name in value['critical']['files'] if name.startswith('Default/Sessions/')]
        self.assertEqual(len(sessions),1024)
        self.write('Default/Sessions/Tabs_extra',b'')
        with self.assertRaises(LocalBrowserError):self.identity()


if __name__=='__main__':unittest.main(verbosity=2)
