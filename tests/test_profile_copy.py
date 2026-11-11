"""Synthetic profile copying contracts; never uses account profiles or browsers."""
from collections import Counter
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
import profile_copy
from import_progress import observe
from local_state import LocalBrowserError


class ProfileCopyTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='profile-copy-test-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.source=self.root/'source';self.target=self.root/'target'
        self.source.mkdir()
        (self.source/'a').write_bytes(b'a'*4096);(self.source/'b').write_bytes(b'b'*8192)
        self.sleep=patch.object(profile_copy.time,'sleep');self.sleep.start();self.addCleanup(self.sleep.stop)

    def assert_unpublished(self):
        self.assertFalse(self.target.exists())
        self.assertFalse(self.target.with_name(self.target.name+'.copying').exists())

    def test_complete_manifest_hidden_empty_metadata_and_actual_byte_progress(self):
        empty=self.source/'.hidden/empty';empty.mkdir(parents=True)
        hidden=self.source/'.hidden/value';hidden.write_bytes(b'hidden')
        os.utime(hidden,ns=(1234567890000000000,1234567890000000000))
        os.utime(empty,ns=(1234567890000000000,1234567890000000000))
        total=sum(path.stat().st_size for path in self.source.rglob('*') if path.is_file())
        events=[]
        with observe(lambda phase,**values:events.append((phase,values))):
            result=profile_copy.copy_profile(self.source,self.target)
        self.assertEqual(result,profile_copy.manifest(self.source))
        self.assertEqual(result,profile_copy.manifest(self.target))
        self.assertTrue((self.target/'.hidden/empty').is_dir())
        self.assertEqual((self.target/'.hidden/value').stat().st_mtime_ns,hidden.stat().st_mtime_ns)
        self.assertEqual((self.target/'.hidden/empty').stat().st_mtime_ns,empty.stat().st_mtime_ns)
        self.assertEqual({phase for phase,_ in events},{'inventory','source_hash','copying','source_verify','copy_verify'})
        for phase in ('source_hash','copying','source_verify','copy_verify'):
            values=[value for name,value in events if name==phase]
            self.assertEqual(values[0]['done'],0)
            self.assertEqual(values[-1],dict(done=total,total=total,unit='bytes'))
            self.assertEqual([value['done'] for value in values],sorted(value['done'] for value in values))
        self.assertTrue(all(set(value)=={'done','total','unit'} for _,value in events))

    def test_permission_retry_only_recopies_failed_file(self):
        original=shutil.copy2;calls=Counter();progress=[]
        def copy(source,target,**kwargs):
            calls[Path(source).name]+=1
            if Path(source).name=='b' and calls['b']==1:
                Path(target).write_bytes(b'partial')
                raise PermissionError('synthetic failure')
            return original(source,target,**kwargs)
        with patch.object(profile_copy.shutil,'copy2',side_effect=copy),observe(lambda phase,**values:progress.append((phase,values))):
            profile_copy.copy_profile(self.source,self.target)
        self.assertEqual(calls,{'a':1,'b':2})
        self.assertEqual([value['done'] for phase,value in progress if phase=='copying'],[0,4096,12288])

    def test_exhausted_retry_removes_only_unpublished_copy(self):
        before=profile_copy.manifest(self.source);original=shutil.copy2;calls=Counter()
        def copy(source,target,**kwargs):
            calls[Path(source).name]+=1
            if Path(source).name=='b':raise PermissionError('synthetic failure')
            return original(source,target,**kwargs)
        with patch.object(profile_copy.shutil,'copy2',side_effect=copy),self.assertRaises(PermissionError):
            profile_copy.copy_profile(self.source,self.target)
        self.assertEqual(calls,{'a':1,'b':3});self.assert_unpublished()
        self.assertEqual(before,profile_copy.manifest(self.source))

    def test_same_length_source_content_change_is_rejected_even_with_restored_time(self):
        original=shutil.copy2
        def copy(source,target,**kwargs):
            result=original(source,target,**kwargs)
            if Path(source).name=='b':
                changed=self.source/'a';info=changed.stat();changed.write_bytes(b'x'*info.st_size)
                os.utime(changed,ns=(info.st_atime_ns,info.st_mtime_ns))
            return result
        with patch.object(profile_copy.shutil,'copy2',side_effect=copy),self.assertRaises(LocalBrowserError):
            profile_copy.copy_profile(self.source,self.target)
        self.assert_unpublished()

    def test_source_new_file_and_empty_directory_change_are_rejected(self):
        original=shutil.copy2
        for directory in (False,True):
            added=self.source/'new-entry'
            def copy(source,target,**kwargs):
                result=original(source,target,**kwargs)
                if Path(source).name=='b':
                    if directory:added.mkdir()
                    else:added.write_bytes(b'new')
                return result
            with self.subTest(directory=directory),patch.object(profile_copy.shutil,'copy2',side_effect=copy),self.assertRaises(LocalBrowserError):
                profile_copy.copy_profile(self.source,self.target)
            self.assert_unpublished()
            if directory:added.rmdir()
            else:added.unlink()

    def test_corrupt_destination_is_rejected_by_content_digest(self):
        original=shutil.copy2
        def copy(source,target,**kwargs):
            result=original(source,target,**kwargs)
            if Path(source).name=='b':Path(target).write_bytes(b'x'*8192)
            return result
        with patch.object(profile_copy.shutil,'copy2',side_effect=copy),self.assertRaises(LocalBrowserError):
            profile_copy.copy_profile(self.source,self.target)
        self.assert_unpublished()

    def test_existing_target_and_existing_temporary_are_never_modified(self):
        for folder in (self.target,self.target.with_name(self.target.name+'.copying')):
            with self.subTest(temporary=folder!=self.target):
                folder.mkdir();(folder/'keep').write_bytes(b'keep')
                with self.assertRaises(LocalBrowserError):profile_copy.copy_profile(self.source,self.target)
                self.assertEqual((folder/'keep').read_bytes(),b'keep')
                shutil.rmtree(folder)

    def test_target_appearing_before_publish_is_never_overwritten(self):
        def progress(phase,**values):
            if phase=='copy_verify' and not self.target.exists():
                self.target.mkdir();(self.target/'keep').write_bytes(b'keep')
        with observe(progress),self.assertRaises(LocalBrowserError):profile_copy.copy_profile(self.source,self.target)
        self.assertEqual((self.target/'keep').read_bytes(),b'keep')
        self.assertFalse(self.target.with_name(self.target.name+'.copying').exists())

    def test_directory_permission_error_is_retried_without_recopying_files(self):
        (self.source/'nested').mkdir();(self.source/'nested/value').write_bytes(b'value')
        original=os.makedirs;calls=Counter()
        def mkdir(path,*args,**kwargs):
            path=Path(path)
            if path.name=='nested' and path.parent.name.endswith('.copying'):
                calls['nested']+=1
                if calls['nested']==1:raise PermissionError('synthetic failure')
            return original(path,*args,**kwargs)
        with patch.object(os,'makedirs',mkdir),patch.object(profile_copy.shutil,'copy2',wraps=shutil.copy2) as copied:
            profile_copy.copy_profile(self.source,self.target)
        self.assertEqual(calls['nested'],2);self.assertEqual(copied.call_count,3)

    def test_readonly_partial_copy_is_cleaned_on_failure(self):
        original=shutil.copy2
        def copy(source,target,**kwargs):
            if Path(source).name=='b':raise PermissionError('synthetic failure')
            result=original(source,target,**kwargs);Path(target).chmod(stat.S_IREAD)
            return result
        with patch.object(profile_copy.shutil,'copy2',side_effect=copy),self.assertRaises(PermissionError):
            profile_copy.copy_profile(self.source,self.target)
        self.assert_unpublished()

    def test_directory_link_is_rejected_without_reading_external_tree(self):
        external=self.root/'external';external.mkdir();(external/'keep').write_bytes(b'keep')
        link=self.source/'link'
        if os.name=='nt':
            result=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(link),str(external)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            self.assertEqual(result.returncode,0)
        else:link.symlink_to(external,target_is_directory=True)
        try:
            with self.assertRaises(LocalBrowserError):profile_copy.copy_profile(self.source,self.target)
            with self.assertRaises(LocalBrowserError):profile_copy.manifest(self.source)
            self.assert_unpublished();self.assertEqual((external/'keep').read_bytes(),b'keep')
        finally:
            if os.name=='nt':link.rmdir()
            else:link.unlink()

    @unittest.skipUnless(os.name=='nt','Windows hidden file attributes')
    def test_windows_hidden_directory_and_file_attributes_are_retained(self):
        import ctypes
        from ctypes import wintypes
        folder=self.source/'hidden';folder.mkdir();file=folder/'value';file.write_bytes(b'value')
        setter=ctypes.WinDLL('kernel32',use_last_error=True).SetFileAttributesW
        setter.argtypes=(wintypes.LPCWSTR,wintypes.DWORD);setter.restype=wintypes.BOOL
        for path in (folder,file):self.assertTrue(setter(str(path),path.stat().st_file_attributes|0x2))
        profile_copy.copy_profile(self.source,self.target)
        self.assertTrue((self.target/'hidden').stat().st_file_attributes&0x2)
        self.assertTrue((self.target/'hidden/value').stat().st_file_attributes&0x2)

    @unittest.skipUnless(os.name=='nt','Windows executable suffix stat modes')
    def test_windows_executable_suffixes_and_readonly_files_copy_and_hash(self):
        for index,suffix in enumerate(('.exe','.EXE','.com','.bat','.cmd')):
            (self.source/('value'+str(index)+suffix)).write_bytes(b'synthetic executable contents')
        readonly=self.source/'readonly.exe';readonly.write_bytes(b'readonly contents')
        readonly.chmod(stat.S_IREAD)
        before=profile_copy.manifest(self.source)
        copied=profile_copy.copy_profile(self.source,self.target)
        self.assertEqual(copied,before)
        self.assertEqual(profile_copy.manifest(self.source),before)
        self.assertEqual(profile_copy.manifest(self.target),before)
        self.assertFalse((self.target/readonly.name).stat().st_mode&stat.S_IWRITE)

    @unittest.skipUnless(os.name=='nt','Windows readonly file attributes')
    def test_windows_readonly_change_during_copy_is_still_rejected(self):
        executable=self.source/'value.exe';executable.write_bytes(b'synthetic contents')
        changed=False
        def progress(phase,**values):
            nonlocal changed
            if phase=='source_hash' and not changed:
                executable.chmod(stat.S_IREAD);changed=True
        with observe(progress),self.assertRaises(LocalBrowserError):
            profile_copy.copy_profile(self.source,self.target)
        self.assertTrue(changed);self.assert_unpublished()

    def test_profile_copy_inside_source_is_rejected_before_writing(self):
        with self.assertRaises(LocalBrowserError):profile_copy.copy_profile(self.source,self.source/'nested')
        self.assertFalse((self.source/'nested').exists())

    def test_replaced_target_boundary_never_writes_or_deletes_external_data(self):
        external=self.root/'external';external.mkdir();(external/'keep').write_bytes(b'keep')
        temporary=self.target.with_name(self.target.name+'.copying');moved=self.root/'owned-copy'
        changed=False
        def progress(phase,**values):
            nonlocal changed
            if phase!='copying' or not values.get('done') or changed:return
            changed=True;temporary.rename(moved)
            if os.name=='nt':
                result=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(temporary),str(external)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                self.assertEqual(result.returncode,0)
            else:temporary.symlink_to(external,target_is_directory=True)
        try:
            with observe(progress),self.assertRaises(LocalBrowserError):profile_copy.copy_profile(self.source,self.target)
            self.assertTrue(changed);self.assertFalse(self.target.exists())
            self.assertEqual(sorted(path.name for path in external.iterdir()),['keep'])
            self.assertEqual((external/'keep').read_bytes(),b'keep')
        finally:
            if os.path.lexists(temporary):
                if os.name=='nt':temporary.rmdir()
                else:temporary.unlink()


if __name__=='__main__':unittest.main(verbosity=2)
