"""Group updates against an in-memory synthetic catalog, without app initialization."""
import json
from pathlib import Path
import sqlite3
import sys
import threading
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from manager_service import ManagerService


class GroupOperations(unittest.TestCase):
    def setUp(self):
        self.database=sqlite3.connect(':memory:')
        self.addCleanup(self.database.close)
        self.database.executescript('CREATE TABLE profiles(id TEXT PRIMARY KEY,data TEXT);'
                                   'CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);')
        self.database.executemany('INSERT INTO profiles VALUES (?,?)',
            [(name,json.dumps({'id':name,'group':group}))
             for name,group in (('selected','Old'),('unrelated','Keep'),('empty',''))])
        self.database.commit()
        self.service=ManagerService.__new__(ManagerService)
        self.service.operations=threading.RLock()
        self.service.store=SimpleNamespace(lock=threading.RLock(),connect=lambda:self.database,
                                           pack=json.dumps,unpack=json.loads)

    def group(self,identity):
        return json.loads(self.database.execute(
            'SELECT data FROM profiles WHERE id=?',(identity,)).fetchone()[0])['group']

    def test_long_or_padded_rename_preserves_membership_at_the_same_name_limit(self):
        for name in ('  New  ','Z'*101,'😀'*101):
            with self.subTest(kind=len(name)):
                self.database.execute('UPDATE profiles SET data=? WHERE id=?',
                    (json.dumps({'id':'selected','group':'Old'}),'selected'))
                self.database.commit()
                result=self.service.groups_save({'groups':[name,'Keep'],'renames':{'Old':name}})
                expected=name.strip()[:100]
                self.assertEqual(result['groups'],[expected,'Keep'])
                self.assertEqual(self.group('selected'),expected)
                self.assertEqual(self.group('unrelated'),'Keep')
                self.assertEqual(self.group('empty'),'')

    def test_deleted_groups_clear_membership_but_keep_other_groups(self):
        self.service.groups_save({'groups':['Keep'],'renames':{}})
        self.assertEqual(self.group('selected'),'')
        self.assertEqual(self.group('unrelated'),'Keep')

    def test_rename_to_existing_group_merges_without_losing_membership(self):
        result=self.service.groups_save({'groups':['Keep','Keep'],'renames':{'Old':'Keep'}})
        self.assertEqual(result['groups'],['Keep'])
        self.assertEqual(self.group('selected'),'Keep')
        self.assertEqual(self.group('unrelated'),'Keep')


if __name__=='__main__':
    unittest.main()
