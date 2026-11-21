#!/usr/bin/env python3
"""Build or verify the immutable, offline legacy migration package.

No network operations, database access, or Git mutations. The checked-in manifest
is the trust anchor; an archive's own manifest is never trusted independently.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / 'migrations/postgres/baseline-v1/legacy-package.json'
SOURCE = 'db5e64b566712e5213424db5e166775d9a15a7be'
PATHS = ['migrations', 'deploy/compose/local/migrate.sh', 'LICENSE']


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build(output, manifest=MANIFEST):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError('Refusing to overwrite an existing package')
    files = {}
    process = subprocess.Popen(['git', '-C', str(ROOT), 'archive', SOURCE, *PATHS], stdout=subprocess.PIPE)
    try:
        with output.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w|', format=tarfile.USTAR_FORMAT) as target:
                with tarfile.open(fileobj=process.stdout, mode='r|') as source:
                    for entry in source:
                        if entry.isdir():
                            continue
                        if not entry.isfile():
                            raise ValueError('Legacy source must contain regular files only')
                        data = source.extractfile(entry).read()
                        files[entry.name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                        item = tarfile.TarInfo(entry.name)
                        item.size, item.mode, item.mtime = len(data), entry.mode, 0
                        target.addfile(item, io.BytesIO(data))
        if process.wait() != 0:
            raise ValueError('Git source archive failed')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    record = {'format': 1, 'source_commit': SOURCE, 'archive': output.name,
              'archive_bytes': output.stat().st_size, 'archive_sha256': digest(output),
              'uncompressed_bytes': sum(f['bytes'] for f in files.values()), 'files': files}
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return record


def verify(archive, manifest=MANIFEST, destination=None):
    record = json.loads(Path(manifest).read_text())
    if record['format'] != 1 or record['source_commit'] != SOURCE:
        raise ValueError('Unsupported legacy source identity')
    if Path(archive).stat().st_size != record['archive_bytes'] or digest(archive) != record['archive_sha256']:
        raise ValueError('Legacy archive digest mismatch')
    # Validate all members before exposing any extracted package to callers.
    members = set()
    destination = Path(destination) if destination else None
    if destination and destination.exists():
        raise ValueError('Extraction destination must not exist')
    parent = destination.parent if destination else None
    with tempfile.TemporaryDirectory(prefix='legacy-verified-', dir=parent) as scratch:
        scratch = Path(scratch)
        with tarfile.open(archive, 'r:gz') as source:
            for item in source:
                name = PurePosixPath(item.name)
                if (not item.isfile() or name.is_absolute() or '..' in name.parts
                        or str(name) != item.name or item.name in members
                        or item.name not in record['files']):
                    raise ValueError('Unexpected or unsafe legacy archive member')
                expected = record['files'][item.name]
                if item.size != expected['bytes']:
                    raise ValueError('Legacy member size mismatch')
                data = source.extractfile(item).read()
                if hashlib.sha256(data).hexdigest() != expected['sha256']:
                    raise ValueError('Legacy member checksum mismatch')
                members.add(item.name)
                if destination:
                    path = scratch / item.name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                    path.chmod(item.mode & 0o755)
        if members != set(record['files']):
            raise ValueError('Legacy package is incomplete')
        if destination:
            scratch.rename(destination)
            # TemporaryDirectory cleanup tolerates a directory renamed away.
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    pack = sub.add_parser('build')
    pack.add_argument('--output', required=True)
    pack.add_argument('--manifest', default=MANIFEST, help='Write the reproduced manifest separately when verifying reproducibility')
    unpack = sub.add_parser('verify')
    unpack.add_argument('--archive', required=True)
    unpack.add_argument('--destination')
    args = parser.parse_args()
    record = build(args.output, manifest=Path(args.manifest)) if args.command == 'build' else verify(args.archive, destination=args.destination)
    print(json.dumps({k: record[k] for k in ['source_commit', 'archive_bytes', 'archive_sha256', 'uncompressed_bytes']}))


if __name__ == '__main__':
    main()
