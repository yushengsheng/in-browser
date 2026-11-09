"""Synthetic migration/path/legacy tests; no real browser or private data."""
import copy
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'app'))
from local_state import LocalBrowserError,read_encrypted,write_encrypted,protect
from window_store import WindowStore
from portable_vault import PortableVault,is_portable
from portable_paths import encode_record,decode_record,decode_path
from portable_migration import migrate


def main():
    report={'success':False,'checks':{}}
    def check(name,value):
        report['checks'][name]=bool(value)
        if not value:raise AssertionError(name)
    with tempfile.TemporaryDirectory(prefix='portable-state-') as tmp:
        root=Path(tmp).resolve()/'first';root.mkdir();config=SimpleNamespace(independent=True)
        store=WindowStore(config,root)
        write_encrypted(root/'independent-mode.bin',{'format':1})
        write_encrypted(root/'configuration-context.bin',{'fixture':'private'})
        profile=root/'profiles/fixture';profile.mkdir(parents=True)
        record={'id':'fixture','seq':1,'created_at':'fixture','last_opened_at':None,'archived':False,'_native':{'DataProtect':{'CipherKey':'synthetic-only'}},
                '_runtime':{'profile_path':str(profile),'fingerprint_path':str(root/'fingerprints/fixture.bin'),'core_path':str(ROOT/'app/local-engines/fixture/BitBrowser.exe')}}
        store.put(record)
        service=SimpleNamespace(root=root,store=store,configuration=config,operations=threading.RLock(),_closed=lambda _:None,_sync=lambda _:None)
        with patch('portable_browser.capture_profile',return_value={'format':1,'key':'synthetic-only','key_id':'fixture'}):result=migrate(service)
        check('explicit_migration_completes',result['windows']==1 and result['backup_created'])
        with store.connect() as con:
            packed=con.execute('SELECT data FROM profiles').fetchone()[0]
            check('catalog_uses_folder_encryption',is_portable(packed))
            check('catalog_paths_are_relative',json.loads(protect(packed,decrypt=True,root=root))['_runtime']['profile_path'].startswith('@data/'))
        with patch('local_state._dpapi_protect',side_effect=AssertionError('Original Windows user unavailable')):
            check('all_current_bins_read_without_dpapi',read_encrypted(root/'configuration-context.bin')['fixture']=='private')
            check('catalog_read_without_dpapi',store.all()[0]['id']=='fixture')
            check('repeat_migration_is_local',migrate(service)['already_portable'])
        moved=Path(tmp).resolve()/'different-directory';shutil.copytree(root,moved)
        with patch('local_state._dpapi_protect',side_effect=AssertionError('Original Windows user unavailable')):
            moved_store=WindowStore(config,moved)
            check('copied_catalog_rebases_data_paths',moved_store.all()[0]['_runtime']['profile_path']==str(moved/'profiles/fixture'))
            check('copied_folder_decrypts',read_encrypted(moved/'configuration-context.bin')['fixture']=='private')
        for value in ['@data/../outside','@app/C:/outside','@data/dir\\..\\outside']:
            try:decode_path(value,root)
            except LocalBrowserError:pass
            else:raise AssertionError('unsafe path accepted')
        check('relative_traversal_rejected',True)
        keydir=moved/'.portable-vault';shutil.rmtree(keydir)
        try:read_encrypted(moved/'portable-mode.bin')
        except LocalBrowserError:pass
        else:raise AssertionError('missing key accepted')
        check('deleted_folder_key_never_regenerated',not keydir.exists())
        backups=list((root/'backups').glob('before-portable-*'))
        check('original_dpapi_backup_retained',len(backups)==1 and (backups[0]/'windows.sqlite').is_file())
        report['success']=all(report['checks'].values())
    print(json.dumps(report))


if __name__=='__main__':main()
