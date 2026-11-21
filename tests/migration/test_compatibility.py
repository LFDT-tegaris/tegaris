"""Adversarial offline-package verification tests; no database or daemon needed."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('compatibility',ROOT/'scripts/migrations/compatibility.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def package(self,entries,expected=None):
        archive=self.root/'package.tar.gz'; files={}
        with tarfile.open(archive,'w:gz') as target:
            for name,data,kind in entries:
                entry=tarfile.TarInfo(name);entry.type=kind;entry.mode=0o644
                if kind==tarfile.REGTYPE:
                    entry.size=len(data);target.addfile(entry,io.BytesIO(data))
                else:
                    entry.linkname='/tmp/outside-package';target.addfile(entry)
                files[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        manifest=self.root/'manifest.json'
        manifest.write_text(json.dumps({'format':1,'source_commit':module.SOURCE,'archive_bytes':archive.stat().st_size,
                                       'archive_sha256':module.digest(archive),'files':files if expected is None else expected}))
        return archive,manifest

    def test_exact_package_extracts_only_after_verification(self):
        a,m=self.package([('migrations/postgres/identity/0000.sql',b'SELECT 1;',tarfile.REGTYPE)])
        module.verify(a,m,self.root/'verified')
        self.assertEqual((self.root/'verified/migrations/postgres/identity/0000.sql').read_bytes(),b'SELECT 1;')

    def test_archive_byte_tampering_is_rejected(self):
        a,m=self.package([('safe.sql',b'SELECT 1;',tarfile.REGTYPE)])
        with a.open('ab') as f:f.write(b'tampered')
        with self.assertRaisesRegex(ValueError,'digest'):module.verify(a,m,self.root/'verified')
        self.assertFalse((self.root/'verified').exists())

    def test_member_checksum_mismatch_exposes_nothing(self):
        a,m=self.package([('safe.sql',b'SELECT 1;',tarfile.REGTYPE)],{'safe.sql':{'bytes':9,'sha256':'0'*64}})
        with self.assertRaisesRegex(ValueError,'checksum'):module.verify(a,m,self.root/'verified')
        self.assertFalse((self.root/'verified').exists())

    def test_missing_member_exposes_nothing(self):
        a,m=self.package([],{'missing.sql':{'bytes':1,'sha256':'0'*64}})
        with self.assertRaisesRegex(ValueError,'incomplete'):module.verify(a,m,self.root/'verified')

    def test_duplicate_members_are_rejected(self):
        a,m=self.package([('safe.sql',b'one',tarfile.REGTYPE),('safe.sql',b'one',tarfile.REGTYPE)])
        with self.assertRaisesRegex(ValueError,'unsafe'):module.verify(a,m,self.root/'verified')

    def test_parent_traversal_is_rejected(self):
        a,m=self.package([('../outside.sql',b'one',tarfile.REGTYPE)])
        with self.assertRaisesRegex(ValueError,'unsafe'):module.verify(a,m,self.root/'verified')

    def test_absolute_paths_are_rejected(self):
        a,m=self.package([('/outside.sql',b'one',tarfile.REGTYPE)])
        with self.assertRaisesRegex(ValueError,'unsafe'):module.verify(a,m,self.root/'verified')

    def test_symlink_is_rejected(self):
        a,m=self.package([('link',b'',tarfile.SYMTYPE)])
        with self.assertRaisesRegex(ValueError,'unsafe'):module.verify(a,m,self.root/'verified')

    def test_existing_destination_is_preserved(self):
        a,m=self.package([('safe.sql',b'one',tarfile.REGTYPE)])
        dest=self.root/'verified';dest.mkdir();(dest/'existing').write_text('preserve')
        with self.assertRaisesRegex(ValueError,'must not exist'):module.verify(a,m,dest)
        self.assertEqual((dest/'existing').read_text(),'preserve')


if __name__=='__main__':unittest.main()
