#!/usr/bin/env python3
"""Run historical tests in a separate source view, never hydrate the checkout.

Legacy SQL comes from the immutable public source commit. Current implementation
and tests are overlaid, while the compact installer is omitted in this explicitly
legacy-only view. Fresh baseline validation has its own PostgreSQL proof runner.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
SOURCE='db5e64b566712e5213424db5e166775d9a15a7be'
PREFIXES=tuple('migrations/postgres/'+lane+'/' for lane in ['identity','control-api','policy'])
BASE='migrations/postgres/baseline-v1/'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory',type=Path,required=True)
    p.add_argument('--store-dir',type=Path)
    p.add_argument('--command',nargs=argparse.REMAINDER,required=True)
    args=p.parse_args();view=args.directory.resolve()
    if view.exists():raise ValueError('Historical test directory must not exist')
    subprocess.run(['git','-C',str(ROOT),'worktree','add','--detach',str(view),SOURCE],check=True)
    files=set()
    for options in [[],['--others','--exclude-standard']]:
        files.update(subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z',*options]).decode().split('\0'))
    for name in sorted(files):
        if not name or name.startswith(PREFIXES):continue
        if name.startswith(BASE) and name!=BASE+'legacy-package.json':continue
        source=ROOT/name;target=view/name
        if source.is_file():
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
        elif target.is_file():target.unlink()
    record=json.loads((ROOT/(BASE+'legacy-package.json')).read_text())
    for name,item in record['files'].items():
        if not name.startswith('migrations/'):continue
        if hashlib.sha256((view/name).read_bytes()).hexdigest()!=item['sha256']:
            raise ValueError('Historical test fixture source drift: '+name)
    (view/'LEGACY_TEST_VIEW.json').write_text(json.dumps({'source_commit':SOURCE,'historical_only':True})+'\n')
    environment={**os.environ,'OPENPC_CONTROL_LEGACY_TEST_VIEW':'1'}
    if (ROOT/'node_modules').exists():
        command=['pnpm','install','--offline','--frozen-lockfile','--ignore-scripts','--strict-peer-dependencies']
        if args.store_dir:command+=['--store-dir',str(args.store_dir.resolve())]
        subprocess.run(command,cwd=view,env=environment,check=True)
    print('Historical SQL verified; running current code in',view,flush=True)
    raise SystemExit(subprocess.run(args.command,cwd=view,env=environment).returncode)


if __name__=='__main__':main()
