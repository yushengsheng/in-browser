"""Build an allowlisted source tree or an empty Windows distribution.

Private data, credentials, local signing deployments, shortcuts and historical
reports never enter either output. A runtime build contains the original 148
engine; other supported engines are deployed when importing their sources.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
FIXTURES=('portable-vault-tests.py','portable-browser-tests.py','portable-state-tests.py',
    'signature-guard-tests.py','local-engine-tests.py','local-signer-tests.py','sync-source-tests.py',
    'fingerprint-continuity-tests.py','conservative-policy-tests.py','proxy-runtime-protocol-tests.py')
TOP=('README.md','AGENTS.md','本地浏览器说明.md','开发说明.md','启动本地浏览器.cmd','VERSION',
     'requirements.txt','THIRD_PARTY_NOTICES.md','.gitignore')


def ordinary(path):
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:raise ValueError('Special path')
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):raise ValueError('Special file')


def source_files(root=ROOT):
    files=[root/name for name in TOP]
    files.extend(p for p in (root/'app').iterdir() if p.suffix in ('.py','.pyw','.js') and p.is_file())
    files.extend(root/'app/ui'/name for name in ('app.js','index.html','style.css','README.md'))
    files.extend(root/'app/resources'/name for name in ('electron-main.js','crypto.worker.js','defaults.json','signature-verification-public.der','creation-catalog.json'))
    for directory in ('docs','tests','tools','.github'):
        for path in (root/directory).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix in ('.py','.pyw','.js','.json','.md','.html','.css','.yml','.yaml','.sha256','.svg','.png','.ico'):
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
        target.mkdir(parents=True)
        for source in source_files():
            path=target/source.relative_to(ROOT);path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,path)
        if args.runtime_from:
            runtime=args.runtime_from.resolve();ordinary(runtime)
            if not (runtime/'python/python.exe').is_file():raise ValueError('Runtime missing')
            copy_tree(runtime,target/'runtime');write_manifest(target/'runtime','manifest.sha256.json')
            copy_tree(ROOT/'app/engines/148',target/'app/engines/148')
        count=write_manifest(target,'release-manifest.json')
        if args.zip:
            with zipfile.ZipFile(target.with_suffix('.zip'),'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
                for path in sorted(target.rglob('*')):
                    if path.is_file():archive.write(path,path.relative_to(target).as_posix())
        print(json.dumps({'success':True,'files':count,'contains_user_data':False,'runtime_included':bool(args.runtime_from)}));return 0
    except Exception as exc:
        print(json.dumps({'success':False,'error_type':type(exc).__name__}));return 1


if __name__=='__main__':raise SystemExit(main())
