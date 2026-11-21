#!/usr/bin/env python3
"""Restore a checksum-pinned control backup into a verified empty target only.

Use the original initdb bootstrap role name in the new target cluster. Does not
drop databases, overwrite application objects, start services or fetch packages.
The existing PostgreSQL clients and Python 3.11+ are sufficient.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
from baseline import BASE,assets


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--sha256',required=True)
    args=parser.parse_args()
    if not re.fullmatch('[0-9a-f]{64}',args.sha256):raise ValueError('A trusted backup SHA256 is required')
    with args.archive.open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=args.sha256:raise ValueError('Backup SHA256 mismatch')
    assets()
    if os.environ.get('PGDATABASE')!='openpc_control':raise ValueError('Explicit PGDATABASE=openpc_control is required')
    listing=subprocess.check_output(['pg_restore','--list',str(args.archive)],text=True)
    entries=listing.splitlines();excluded=[];retained=[]
    for line in entries:
        if re.match(r'^\d+; \d+ \d+ EXTENSION - pgcrypto(?:\s|$)',line):excluded.append(line)
        else:retained.append(line)
    if len(excluded)!=1:raise ValueError('Backup must contain exactly the qualified pgcrypto extension entry')
    # Preflight and preparation are atomic; unknown/populated targets stop before
    # the first persistent change. The archive itself restores in one transaction.
    subprocess.run(['psql','-X','-q','-v','ON_ERROR_STOP=1','-f',str(BASE/'prepare-restore.sql')],check=True)
    with tempfile.TemporaryDirectory(prefix='tegaris-restore-toc-') as scratch:
        toc=Path(scratch)/'restore.list';toc.write_text('\n'.join(retained)+'\n')
        subprocess.run(['pg_restore','--exit-on-error','--single-transaction','--use-list',str(toc),
                        '--dbname','openpc_control',str(args.archive)],check=True)
    subprocess.run(['psql','-X','-q','-v','ON_ERROR_STOP=1','-f',str(BASE/'restore.sql')],check=True)
    print('TEGARIS_BASELINE_RESTORE|PASS')


if __name__=='__main__':main()
