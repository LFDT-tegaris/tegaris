"""Exercise contributor documentation checks against complete temporary roots."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name('check-docs.py')
SPEC = importlib.util.spec_from_file_location('check_docs', SCRIPT)
docs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(docs)


class DocumentationChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        for name in docs.DOCUMENTS:
            self.write(name, '# Guide\n')

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def test_missing_required_documents_and_titles_are_still_rejected(self):
        (self.root / 'SECURITY.md').unlink()
        self.write('README.md', 'No title\n')
        self.assertEqual(docs.check(self.root), [
            'README.md: missing document title',
            'SECURITY.md: required document is missing',
        ])

    def test_cross_document_same_document_and_encoded_sections(self):
        self.write('README.md', '# Guide\n[Access](docs/README.md#account--workspace)\n'
                   '[This section](#guide)\n[Encoded](docs/README.md#caf%C3%A9)\n')
        self.write('docs/README.md', '# Guide\n## Account & workspace\n## Café\n')
        self.assertEqual(docs.check(self.root), [])
        self.write('README.md', '# Guide\n[Changed section](docs/README.md#old-title)\n')
        self.assertEqual(docs.check(self.root), [
            'README.md: missing Markdown section: docs/README.md#old-title',
        ])

    def test_duplicate_heading_collisions_and_custom_anchors(self):
        self.write('README.md', '# Guide\n## Repeat\n## Repeat-1\n## Repeat\n'
                   '<a name="Repeat"></a>\n<a id="custom-point"></a>\n'
                   '[Repeated](#repeat-2)\n[Custom](#custom-point)\n[Named](#Repeat)\n')
        self.assertEqual(docs.check(self.root), [])
        self.write('README.md', '# Guide\n## Repeat\n## Repeat\n[Missing](#repeat-2)\n')
        self.assertEqual(docs.check(self.root), [
            'README.md: missing Markdown section: #repeat-2',
        ])

    def test_headings_use_rendered_content_and_preserve_identifiers(self):
        self.write('README.md', '# Guide\n## Review **policy** and `target_id`\n'
                   '## A [useful](https://example.org) _reference_\n'
                   'Setext section\n--------------\n'
                   '[Policy](#review-policy-and-target_id)\n'
                   '[Reference](#a-useful-reference)\n[Setext](#setext-section)\n')
        self.assertEqual(docs.check(self.root), [])

    def test_examples_and_comments_cannot_supply_a_missing_section(self):
        self.write('README.md', '# Guide\n````markdown\n```\n## Fake\n'
                   '[Example](missing.md)\n```\n````\n'
                   '~~~markdown\n## Also fake\n~~~\n'
                   '<!--\n## Hidden\n[Hidden](missing.md)\n-->\n'
                   '[First](#fake)\n[Second](#also-fake)\n[Third](#hidden)\n')
        self.assertEqual(docs.check(self.root), [
            'README.md: missing Markdown section: #fake',
            'README.md: missing Markdown section: #also-fake',
            'README.md: missing Markdown section: #hidden',
        ])

    def test_root_relative_paths_and_repository_boundary(self):
        self.write('README.md', '# Guide\n[Guide](/docs/README.md#guide)\n'
                   '[Escape](../outside.md#guide)\n')
        self.assertEqual(docs.check(self.root), [
            'README.md: link leaves the repository: ../outside.md#guide',
        ])

    def test_reference_links_are_checked_and_source_line_links_are_preserved(self):
        self.write('example.rs', '// Example\n')
        self.write('README.md', '# Guide\n[External](https://example.org/#external)\n'
                   '[Source](example.rs#L1)\n[Guide][guide]\n'
                   '[guide]: docs/README.md#missing\n')
        self.assertEqual(docs.check(self.root), [
            'README.md: missing Markdown section: docs/README.md#missing',
        ])

    def test_cli_fails_for_a_broken_section_then_passes_the_complete_root(self):
        self.write('README.md', '# Guide\n[Section](#missing)\n')
        result = subprocess.run([sys.executable, str(SCRIPT), '--root', str(self.root)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn('missing Markdown section: #missing', result.stderr)
        self.write('README.md', '# Guide\n[Section](#guide)\n')
        result = subprocess.run([sys.executable, str(SCRIPT), '--root', str(self.root)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn(f'Checked {len(docs.DOCUMENTS)} documents', result.stdout)


if __name__ == '__main__':
    unittest.main()
