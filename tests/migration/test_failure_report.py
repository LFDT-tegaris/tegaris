"""Failure reporting must not publish fixture secrets or unowned file content."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('failure_report', Path(__file__).resolve().parents[2] / 'scripts/migrations/report-failure.py')
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class FailureReport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def log(self, value):
        path = self.root / 'migration.log'
        path.write_text(value)
        return path

    def test_error_class_omits_log_path_and_context(self):
        self.assertEqual(report.summarize(self.log('psql:/fixture/example/install.sql:22: ERROR: out of shared memory\nDETAIL: private row\nCONTEXT: private statement\n')), ['ERROR: out of shared memory'])

    def test_sensitive_messages_are_suppressed(self):
        for word in ['password', 'secret', 'token', 'private_key', 'credential']:
            self.assertEqual(report.summarize(self.log('ERROR: ' + word + ' fixture-sensitive-value\n')), ['ERROR: sensitive diagnostic redacted'])

    def test_values_and_locations_are_redacted(self):
        values = ['quoted-sensitive', 'a' * 64, 'https://example.test/private', 'actor@example.test']
        result = report.summarize(self.log(f'ERROR: value \'{values[0]}\' {values[1]} {values[2]} {values[3]}\n'))
        self.assertEqual(len(result), 1)
        for value in values:
            self.assertNotIn(value, result[0])

    def test_only_bounded_deduplicated_errors_are_emitted(self):
        result = report.summarize(self.log('\n'.join(f'ERROR: code {n}\nERROR: code {n}' for n in range(40))))
        self.assertEqual(len(result), 10)
        self.assertEqual(result[0], 'ERROR: code 0')

    def test_symlinks_and_hardlinks_are_not_read(self):
        source = self.log('ERROR: should not be read')
        link = self.root / 'alias'; link.symlink_to(source)
        self.assertEqual(report.summarize(link), [])
        hard = self.root / 'hard'; hard.hardlink_to(source)
        self.assertEqual(report.summarize(hard), [])

    def test_missing_log_is_not_an_error(self):
        self.assertEqual(report.summarize(self.root / 'missing'), [])

    def test_large_log_reads_only_a_bounded_tail(self):
        self.assertEqual(report.summarize(self.log('x' * 100000 + '\nERROR: final cause\n')), ['ERROR: final cause'])
