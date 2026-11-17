"""Validate an owned reboot archive before Docker's exact, non-following tar copy.

No extraction to the host, new network, volume allocation, or product execution.
The runtime owner supplies exclusive locks, target ownership and empty-mount checks.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile


def source_identity(path, source):
    path = Path(path)
    assert path.is_absolute() and path.resolve() == path
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    assert info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
    assert 1024 <= info.st_size <= 65 * 1024 * 1024
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    fields = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    assert fields(os.fstat(source.fileno())) == fields(info)
    return fields(info)


def source_digest(source):
    source.seek(0)
    digest = 'sha256:' + hashlib.file_digest(source, 'sha256').hexdigest()
    source.seek(0)
    return digest


def inspect_archive(path, identity, source):
    info = source_identity(path, source)
    rows, owner = {}, None
    digest = source_digest(source)
    with tarfile.open(fileobj=source, mode='r:') as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            if name == '.':
                name = ''
            assert not name.startswith('/') and '\\' not in name
            assert all(part not in ('', '.', '..') for part in name.split('/')) if name else member.isdir()
            assert str(PurePosixPath(name)) == name if name else True
            assert name not in rows and len(rows) < 1024
            assert member.isfile() or member.isdir()
            assert member.uid == 65532 and member.gid == 65532
            assert member.mode == (0o700 if member.isdir() else 0o600)
            assert member.size >= 0 and member.size <= 64 * 1024 * 1024
            row = dict(type='directory' if member.isdir() else 'file', mode=member.mode,
                       uid=member.uid, gid=member.gid, size=member.size if member.isfile() else 0)
            if member.isfile():
                data = archive.extractfile(member).read()
                assert len(data) == member.size
                row['digest'] = hashlib.sha256(data).hexdigest()
                if name == '.openpc-enospc-owner':
                    assert len(data) <= 512
                    owner = json.loads(data)
            rows[name] = row
    assert '' in rows and rows['']['type'] == 'directory'
    assert sum(row['size'] for row in rows.values()) <= 64 * 1024 * 1024
    assert owner == identity
    for name in rows:
        if name:
            parent = str(PurePosixPath(name).parent)
            assert rows['' if parent == '.' else parent]['type'] == 'directory'
    assert source_identity(path, source) == info
    return {'archiveDigest': digest, 'entries': rows}


def run_archive(action, archive, identity, rest):
    # Validation and Docker stdin share one non-following descriptor. A pathname
    # replacement must never redirect the bytes copied into the retained volume.
    with os.fdopen(os.open(archive, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        info = source_identity(archive, source)
        result = inspect_archive(archive, identity, source)
        if action == 'copy':
            keeper, expected = rest
            assert len(keeper) == 64 and all(c in '0123456789abcdef' for c in keeper)
            assert result['archiveDigest'] == expected
            assert source_identity(archive, source) == info
            assert source_digest(source) == expected
            assert source_identity(archive, source) == info
            subprocess.run(['docker', 'cp', '-a', '-', keeper + ':/openpc-spool-enospc'],
                           stdin=source, check=True, stdout=subprocess.DEVNULL)
            assert source_identity(archive, source) == info
            assert inspect_archive(archive, identity, source) == result
        else:
            assert action == 'inspect' and not rest
        return result


if __name__ == '__main__':
    action, archive, encoded_identity, *rest = sys.argv[1:]
    result = run_archive(action, archive, json.loads(encoded_identity), rest)
    print(json.dumps(result, separators=(',', ':')))
