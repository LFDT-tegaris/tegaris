#!/usr/bin/env python3
"""Print bounded, redacted PostgreSQL error classes from an owned test log."""
import os
from pathlib import Path
import re
import stat
import sys


def summarize(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                return []
            source.seek(max(0, info.st_size - 32768))
            content = source.read(32768).decode('utf8', errors='replace')
    except OSError:
        return []
    result = []
    for line in content.splitlines():
        match = re.search(r'\b(ERROR|FATAL):\s*(.*)', line)
        if not match:
            continue
        kind, message = match.groups()
        if re.search(r'password|secret|token|private.?key|credential', message, re.I):
            message = 'sensitive diagnostic redacted'
        else:
            message = re.sub(r"'[^']*'|\"[^\"]*\"", '<value>', message)
            message = re.sub(r'https?://\S+|\b\S+@\S+\b|/[A-Za-z0-9_./-]+', '<location>', message)
            message = re.sub(r'\b[A-Za-z0-9_+/=-]{32,}\b', '<opaque>', message)
            message = ''.join(c if 32 <= ord(c) < 127 else '?' for c in message)
        value = kind + ': ' + message[:200]
        if value not in result:
            result.append(value)
        if len(result) == 10:
            break
    return result


if __name__ == '__main__':
    for value in summarize(Path(sys.argv[1])):
        print('ISOLATED_MIGRATION_ERROR|' + value)
