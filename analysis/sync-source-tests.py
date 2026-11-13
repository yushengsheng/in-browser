"""Bounded provider contract checks; no source browser is started or modified."""
import copy
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'app'))
from bit_source import BitSource
import bit_source
from browser_core import LocalBrowserError
from configuration import Configuration
from browser_processes import profile_processes


def fixture_tests():
    with tempfile.TemporaryDirectory(prefix='sync-source-fixture-', dir=ROOT/'analysis') as temporary:
        data=Path(temporary);cache=data/'profiles';cache.mkdir()
        identity='a'*32;orphan='b'*32
        for name in [identity,orphan]:
            folder=cache/name;(folder/'Default').mkdir(parents=True)
            (folder/'Default/Preferences').write_text('{}')
            (folder/'Local State').write_text('{}')
            (folder/'Last Version').write_text('148.0.7778.289')
        (cache/'not-a-source-window').mkdir()
        con=sqlite3.connect(data/'db.sqlite')
        con.executescript('CREATE TABLE global_configs(config_name TEXT,config_value TEXT); CREATE TABLE chrome_versions(chrome TEXT,version TEXT);')
        con.executemany('INSERT INTO global_configs VALUES(?,?)',[('browser_cache_dir',str(cache)),('server_port','54345.0')])
        con.execute('INSERT INTO chrome_versions VALUES(?,?)',('148','win148.26.17'));con.commit();con.close()
        core=data/'Chrome-bin/148/win148.26.17/BitBrowser.exe';core.parent.mkdir(parents=True);core.write_bytes(b'fixture')
        detail={'id':identity,'coreProduct':'chrome','browserFingerPrint':{'coreVersion':'148'},'browserTags':[]}
        startup=copy.deepcopy(detail);startup['browserFingerPrint']['extendOptions']={'DataProtect':{'CipherKey':'fixture-only','Areas':{}}}
        queried=[]
        def source_detail(value):
            queried.append(value)
            return copy.deepcopy(detail) if value==identity else None
        source=BitSource(SimpleNamespace(vendor_data=data,source_detail=source_detail,source_settings=lambda _:copy.deepcopy(startup)))
        results=[]
        def probe(path):
            try:return bool(bit_source.profile_processes(path,require_inspectable=True)),False
            except LocalBrowserError:return False,True
        process_snapshot=lambda:SimpleNamespace(occupied=lambda path:probe(path)[0],uncertain=lambda path:probe(path)[1])
        with patch('bit_source.profile_processes',lambda _,**kw:[]),patch('bit_source.executable_major',lambda _:'148'),patch('bit_source.ProfileProcessSnapshot',side_effect=process_snapshot):
            candidates=source.discover()
            assert len(candidates)==2 and [c['status'] for c in candidates]==['ready','missing_data'];results.append('local-only and orphan preservation')
            assert set(queried)=={identity,orphan};results.append('only local directory identities queried directly')
            first=candidates[0]
            assert len(first['source_key'])==64 and source.discover()[0]['source_key']==first['source_key'];results.append('stable opaque identity')
            assert source.startup(first)['core_path']==core and source.startup(first)['signed_path'] is None;results.append('installed build mapping and full startup')
            startup['browserFingerPrint']['extendOptions']=json.dumps(startup['browserFingerPrint']['extendOptions'])
            assert isinstance(source.startup(first)['info']['browserFingerPrint']['extendOptions'],dict)
            startup['browserFingerPrint']['extendOptions']=json.loads(startup['browserFingerPrint']['extendOptions'])
            results.append('JSON extension normalized')
            detail['remark']='edited fixture'
            try:source.revalidate(first)
            except LocalBrowserError:pass
            else:raise AssertionError('metadata edit accepted')
            detail.pop('remark');results.append('metadata-only edit rejected')
            with patch('bit_source.profile_processes',lambda _,**kw:[object()]):
                assert source.discover()[0]['status']=='source_open'
                try:source.revalidate(first)
                except LocalBrowserError:pass
                else:raise AssertionError('active source accepted')
            results.append('exact profile process rejected')
            with patch('bit_source.profile_processes',side_effect=LocalBrowserError('fixture process visibility unavailable')):
                assert all(c['status']=='unsupported' for c in source.discover())
            results.append('uninspectable source process fails closed per item')
            (cache/identity/'Default/Preferences').write_text('{"fixture":true}')
            try:source.revalidate(first)
            except LocalBrowserError:pass
            else:raise AssertionError('changed source accepted')
            results.append('changed source rejected')
            current=source.discover()[0]
            startup['browserFingerPrint']['extendOptions']=None
            try:source.startup(current)
            except LocalBrowserError:pass
            else:raise AssertionError('missing protection accepted')
            results.append('missing DataProtect rejected')
            escaped=dict(current,source_id='../'+identity)
            try:source.revalidate(escaped)
            except LocalBrowserError:pass
            else:raise AssertionError('escape accepted')
            results.append('source traversal rejected')
            with patch('bit_source._reparse',lambda p:p==cache/identity):
                assert source.discover()[0]['status']=='unsupported'
            results.append('source reparse rejected')
            with patch.object(source.configuration,'source_detail',side_effect=LocalBrowserError('fixture authorization unavailable')):
                unavailable=source.discover()
                assert len(unavailable)==2 and all(c['status']=='missing_data' and c['reason']=='fixture authorization unavailable' for c in unavailable)
                try:source.revalidate(current)
                except LocalBrowserError:pass
                else:raise AssertionError('unreadable metadata accepted')
                with patch('bit_source.profile_processes',lambda _,**kw:[object()]):
                    assert all(c['status']=='source_open' for c in source.discover())
            results.append('unavailable metadata preserves candidates and rejects import')
            (data/'config.json').write_text('not valid LocalAPI config')
            con=sqlite3.connect(data/'db.sqlite');con.execute("UPDATE global_configs SET config_value='disabled' WHERE config_name='server_port'");con.commit();con.close()
            assert source._settings()==cache and source.discover()[0]['status']=='ready'
            results.append('LocalAPI port authentication and config are not dependencies')
            (cache/identity/'Last Version').unlink()
            queried.clear();assert source.discover()[0]['status']=='missing_data' and identity not in queried
            results.append('incomplete local profile never queried or accepted')
        print(json.dumps({'fixture_checks_passed':results},ensure_ascii=False))


def direct_request_tests():
    config=Configuration.__new__(Configuration)
    config.main='line1:{client:`https://client.invalid`,web:`https://web.invalid`,webapi:`https://api.invalid`'
    config.authorization=lambda:{'app_token':'fixture-only'}
    captured=[]
    class Opener:
        def open(self,request,timeout):
            captured.append(request)
            assert timeout==20
            return io.BytesIO(b'{"code":20000,"result":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}')
    with patch('configuration.build_opener',lambda *args:Opener()):
        config.source_detail('a'*32);config.source_settings('a'*32)
    assert [r.full_url for r in captured]==['https://client.invalid/v1/browserInfos/'+'a'*32,'https://client.invalid/v1/browserInfos/getApi/'+'a'*32]
    assert all(r.get_header('Authorization')=='Bearer fixture-only' and r.get_method()=='GET' for r in captured)
    with patch('configuration.build_opener',side_effect=OSError('fixture sensitive server message')):
        try:config.source_detail('a'*32)
        except LocalBrowserError as error:
            assert 'fixture' not in str(error) and '无需启动' in str(error)
        else:raise AssertionError('request failure accepted')
    for args in [['--user-data-dir=fixture-profile'],['--user-data-dir','"fixture-profile"']]:
        process=SimpleNamespace(pid=101,info={'pid':101,'name':'BitBrowser.exe','cmdline':args,'exe':'BitBrowser.exe','create_time':100})
        process.as_dict=lambda attrs:{name:process.info.get(name) for name in attrs}
        with patch('browser_processes.psutil.process_iter',return_value=[process]),patch('browser_processes.psutil.Process',return_value=process):
            assert profile_processes(Path('fixture-profile'),require_inspectable=True)==[process]
            assert profile_processes(Path('fixture-profile-other'),require_inspectable=True)==[]
    process=SimpleNamespace(pid=101,info={'name':'BitBrowser.exe','cmdline':None,'exe':None})
    process.as_dict=lambda attrs:{name:process.info.get(name) for name in attrs}
    with patch('browser_processes.psutil.process_iter',return_value=[process]):
        assert profile_processes(Path('fixture-profile'))==[]
        try:profile_processes(Path('fixture-profile'),require_inspectable=True)
        except LocalBrowserError:pass
        else:raise AssertionError('unknown engine activity accepted')
    print(json.dumps({'direct_request_and_process_checks_passed':True}))


def smoke():
    source=BitSource(Configuration())
    rows=source.discover()
    print(json.dumps({'read_only_original_smoke':True,'local_candidates':len(rows),'status_counts':{s:sum(x['status']==s for x in rows) for s in ['ready','source_open','missing_data','unsupported']},'ready_core_majors':sorted({x['_core_major'] for x in rows if x['status']=='ready'})},ensure_ascii=False))


if __name__=='__main__':
    fixture_tests()
    direct_request_tests()
    if '--smoke' in sys.argv:smoke()
