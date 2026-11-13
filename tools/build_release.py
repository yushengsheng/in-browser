"""Build an allowlisted source tree or an empty Windows distribution.

Private data, credentials, local signing deployments, shortcuts and historical
reports never enter either output. A runtime build contains the original 148
engine; other supported engines are deployed when importing their sources.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import zipfile
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parent))
from overlay_layout import PACKAGE_DIRECTORY, MARKER, LAUNCHER, launcher_bytes

ROOT=Path(__file__).resolve().parents[1]
FIXTURES=('portable-vault-tests.py','portable-browser-tests.py','portable-state-tests.py',
    'signature-guard-tests.py','local-engine-tests.py','local-signer-tests.py','sync-source-tests.py',
    'fingerprint-continuity-tests.py','conservative-policy-tests.py','proxy-runtime-protocol-tests.py',
    'browser-proxy-boundary-regression.py')
TOP=('README.md','AGENTS.md','本地浏览器说明.md','开发说明.md','启动本地浏览器.cmd','VERSION',
     'requirements.txt','THIRD_PARTY_NOTICES.md','.gitignore')
RUNTIME_EXECUTABLES=('python/python.exe','python/pythonw.exe','node/node.exe','webview2/msedgewebview2.exe')
UPDATE_POLICY={'format':1,'data_format':1,'from_versions':{
    '0.2.7':'d2d219a3fa3006b062e3dae84e40555c69ef6d438de71cf79f379e3b7cfd7429'}}


def ordinary(path):
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise ValueError('Special path')
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):raise ValueError('Special file')


def source_files(root=ROOT):
    files=[root/name for name in TOP]
    files.extend(p for p in (root/'app').iterdir() if p.suffix in ('.py','.pyw','.js') and p.is_file())
    files.extend(root/'app/ui'/name for name in ('app.js','index.html','style.css','README.md'))
    files.extend(root/'app/resources'/name for name in ('electron-main.js','crypto.worker.js','defaults.json','signature-verification-public.der','creation-catalog.json','pythonnet.config'))
    for directory in ('docs','tests','tools','.github'):
        for path in (root/directory).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix in ('.py','.pyw','.js','.cjs','.json','.md','.html','.css','.yml','.yaml','.sha256','.svg','.png','.ico'):
                files.append(path)
    files.extend(root/'analysis'/name for name in FIXTURES)
    for path in files:
        if not path.is_file():raise FileNotFoundError(path.name)
        for part in (path,*path.parents):
            if part==root.parent:break
            ordinary(part)
    return sorted(set(files))


def copy_tree(source,destination):
    for path in sorted(source.rglob('*')):
        ordinary(path)
        if '__pycache__' in path.parts or path.suffix in ('.pyc','.log'):continue
        target=destination/path.relative_to(source)
        if path.is_dir():target.mkdir(parents=True,exist_ok=True)
        else:target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)


def write_manifest(directory,name):
    files={}
    for path in sorted(directory.rglob('*')):
        ordinary(path)
        first=path.relative_to(directory).parts[0].casefold()
        if first==PACKAGE_DIRECTORY or first.startswith('.program-update-backup-'):
            raise ValueError('Reserved program namespace')
        if path.is_file() and path!=directory/name:
            digest=hashlib.sha256()
            with path.open('rb') as stream:
                while block:=stream.read(1024*1024):digest.update(block)
            files[path.relative_to(directory).as_posix()]={'bytes':path.stat().st_size,'sha256':digest.hexdigest()}
    (directory/name).write_text(json.dumps({'algorithm':'SHA256','files':files},indent=2),'utf-8')
    return len(files)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--runtime-from',type=Path)
    parser.add_argument('--zip',action='store_true');args=parser.parse_args()
    target=args.output.absolute()
    try:
        if target.exists() or target.is_symlink():raise ValueError('Output must be new')
        if target==ROOT or ROOT.is_relative_to(target):raise ValueError('Invalid output')
        for parent in target.parents:
            if parent.exists():ordinary(parent)
        archive_path=target.parent/(target.name+'.zip')
        if args.zip and (archive_path.exists() or archive_path.is_symlink()):raise ValueError('Archive must be new')
        version_path=ROOT/'VERSION'
        ordinary(version_path)
        if version_path.stat().st_size>128:raise ValueError('Invalid version')
        version=version_path.read_text('utf-8-sig').strip()
        if re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',version) is None:
            raise ValueError('Invalid version')
        runtime=args.runtime_from.resolve() if args.runtime_from else None
        if runtime:
            if not runtime.is_dir() or any(not (runtime/name).is_file() for name in RUNTIME_EXECUTABLES):
                raise ValueError('Runtime missing')
            ordinary(runtime)
            for name in RUNTIME_EXECUTABLES:
                ordinary((runtime/name).parent);ordinary(runtime/name)
        overlay=bool(runtime)
        package_id=uuid.uuid4().hex if overlay else None
        program=target/PACKAGE_DIRECTORY/package_id if overlay else target
        program.mkdir(parents=True)
        for source in source_files():
            path=program/source.relative_to(ROOT);path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,path)
        # A generated release marker; source checkouts intentionally omit it.
        (program/'update-policy.json').write_text(json.dumps(UPDATE_POLICY,sort_keys=True,indent=2)+'\n','utf-8')
        if overlay:
            launcher=launcher_bytes(package_id)
            (target/LAUNCHER).write_bytes(launcher)
            (program/LAUNCHER).write_bytes(launcher)
            (program/MARKER).write_text(json.dumps({'format':1,'package_id':package_id},sort_keys=True)+'\n','utf-8')
        if runtime:
            copy_tree(runtime,program/'runtime')
            # The default CLR domain reads the executable's config before Python.NET loads.
            for name in ('python.exe.config','pythonw.exe.config'):
                shutil.copy2(ROOT/'app/resources/pythonnet.config',program/'runtime/python'/name)
            write_manifest(program/'runtime','manifest.sha256.json')
            copy_tree(ROOT/'app/engines/148',program/'app/engines/148')
        count=write_manifest(program,'release-manifest.json')
        if args.zip:
            with zipfile.ZipFile(archive_path,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
                for path in sorted(target.rglob('*')):
                    ordinary(path)
                    archive.write(path,path.relative_to(target).as_posix())
        report={'success':True,'files':count,'contains_user_data':False,'runtime_included':bool(args.runtime_from),
                'version':version,'layout':'overlay' if overlay else 'flat'}
        if overlay:report['package_id']=package_id
        print(json.dumps(report));return 0
    except Exception as exc:
        print(json.dumps({'success':False,'error_type':type(exc).__name__}));return 1


if __name__=='__main__':raise SystemExit(main())
