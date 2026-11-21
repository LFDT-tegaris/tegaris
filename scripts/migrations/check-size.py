#!/usr/bin/env python3
"""Measure the actual source checkout and enforce the 25 MB migration budget."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
SOURCE='db5e64b566712e5213424db5e166775d9a15a7be'


def main():
    before={}
    for line in subprocess.check_output(['git','-C',str(ROOT),'ls-tree','-r','-l',SOURCE],text=True).splitlines():
        meta,path=line.split('\t',1);fields=meta.split()
        if fields[1]=='blob':before[path]=int(fields[3])
    files=set()
    for options in [[],['--others','--exclude-standard']]:
        files.update(subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z',*options]).decode().split('\0'))
    after={name:(ROOT/name).stat().st_size for name in files if name and (ROOT/name).is_file()}
    migration_before=sum(size for name,size in before.items() if name.startswith('migrations/'))
    migration_after=sum(size for name,size in after.items() if name.startswith('migrations/'))
    baseline=ROOT/'migrations/postgres/baseline-v1'
    manifest=json.loads((baseline/'baseline.json').read_text())
    for name,expected in manifest['files'].items():
        if hashlib.sha256((baseline/name).read_bytes()).hexdigest()!=expected:raise ValueError('Baseline asset drift: '+name)
    legacy=json.loads((baseline/'legacy-package.json').read_text())
    anchors={'identity':'0245_runtime_profile_approval_resume.sql','control-api':'0208_public_operations_source_v1.sql',
             'policy':'0014_module_installation_direct_assignment_epoch.sql'}
    for lane,name in anchors.items():
        directory=ROOT/'migrations/postgres'/lane
        if sorted(path.name for path in directory.glob('*.sql'))!=[name]:
            raise ValueError('Unqualified post-baseline SQL in '+lane+': include a versioned installer/upgrade change')
        for path in directory.rglob('*'):
            if not path.is_file() or path.suffix not in {'.sql','.json'} or str(path.relative_to(ROOT)) not in legacy['files']:continue
            if hashlib.sha256(path.read_bytes()).hexdigest()!=legacy['files'][str(path.relative_to(ROOT))]['sha256']:
                raise ValueError('Immutable generation anchor or metadata changed: '+str(path.relative_to(ROOT)))
    report={'reference_commit':SOURCE,'before':{'source_bytes':sum(before.values()),'migration_bytes':migration_before,'source_files':len(before)},
            'after':{'source_bytes':sum(after.values()),'migration_bytes':migration_after,'source_files':len(after)},
            'reduction':{'source_bytes':sum(before.values())-sum(after.values()),'migration_bytes':migration_before-migration_after},
            'migration_budget_bytes':25_000_000,'within_budget':migration_after<=25_000_000}
    print(json.dumps(report,indent=2))
    if not report['within_budget']:raise SystemExit('Migration source exceeds the reviewed 25 MB budget')


if __name__=='__main__':main()
