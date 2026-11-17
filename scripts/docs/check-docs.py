#!/usr/bin/env python3
"""Check required contributor documentation and repository-relative links."""

import argparse
from html import unescape
from pathlib import Path
import re
import sys
import unicodedata
from urllib.parse import unquote, urlsplit


DOCUMENTS = (
    'README.md', 'ONBOARDING.md', 'CONTRIBUTING.md', 'CONTRIBUTION_PROPOSAL.md', 'SECURITY.md',
    'GOVERNANCE.md', 'MAINTAINERS.md', 'CODE_OF_CONDUCT.md', 'ROADMAP.md',
    'RELEASE.md', 'CHANGELOG.md', 'ADOPTERS.md', 'SUPPORT.md', 'docs/README.md',
    'docs/getting-started.md', 'docs/development/README.md',
    'docs/development/integration.md', 'docs/development/proposals.md',
    'docs/development/hosted-demo.md',
    'docs/reference/interfaces.md', 'docs/user-guide/README.md',
    'docs/user-guide/troubleshooting.md', 'docs/user-guide/contract-interactions.md',
    'docs/security/privacy-model.md',
    'docs/releases/README.md', 'docs/releases/v0.9.0.md',
    'docs/architecture.md', 'LICENSES/README.md',
    'docs/development/testing.md', 'docs/operations/README.md',
    'docs/operations/certificates.md', 'docs/operations/modules.md',
    'docs/operations/installation-source.md',
    'docs/evaluation/README.md', 'docs/reference/configuration.md',
    'docs/reference/glossary.md',
    'apps/admin-cli/README.md', 'deploy/compose/local/README.md',
    'deploy/compose/local/secrets/README.md',
    'services/multi-rpc/tests/fixtures/README.md',
    'policies/modules/README.md', 'policies/modules/source/README.md',
    'apps/admin-web/README.md',
)
INLINE_LINK = re.compile(r'!?\[[^\]\n]*\]\(([^)\n]+)\)')
REFERENCE_LINK = re.compile(r'^\s*\[[^\]]+\]:\s*(\S+)', re.MULTILINE)
FENCE = re.compile(r'^ {0,3}(`{3,}|~{3,})(.*)$')
HEADING = re.compile(r'^ {0,3}#{1,6}[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*$')
CUSTOM_ANCHOR = re.compile(
    r'<a\b[^>]*\b(?:id|name)\s*=\s*["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE,
)


def prose_only(text):
    """Exclude fenced examples and HTML comments from link/heading checks."""
    lines = []
    fence = None
    for line in text.splitlines():
        marker = FENCE.match(line)
        if fence is None:
            if marker:
                fence = marker.group(1)
                lines.append('')
            else:
                lines.append(line)
        elif (marker and marker.group(1)[0] == fence[0]
              and len(marker.group(1)) >= len(fence)
              and not marker.group(2).strip()):
            fence = None
            lines.append('')
    return re.sub(r'<!--.*?-->', '', '\n'.join(lines), flags=re.DOTALL)


def heading_slug(heading):
    """GitHub-style anchors for the headings used by the contributor guides."""
    heading = re.sub(r'<[^>]+>', '', heading)
    heading = re.sub(r'!?\[([^\]\n]*)\]\([^)]+\)', r'\1', heading)
    heading = re.sub(r'`+([^`]+)`+', r'\1', heading)
    heading = re.sub(r'(\*{1,3}|_{1,3}|~~)(?=\S)(.*?\S)\1', r'\2', heading)
    heading = unescape(heading).strip().lower()
    return ''.join(
        '-' if char == ' ' else char
        for char in heading
        if char in ' _-' or unicodedata.category(char)[0] in 'LMN'
    )


def markdown_anchors(text):
    prose = prose_only(text)
    generated = set()
    previous = ''
    for line in prose.splitlines():
        heading = HEADING.match(line)
        title = heading.group(1) if heading else None
        if title is None and previous and re.fullmatch(r' {0,3}(?:=+|-+)[ \t]*', line):
            title = previous.strip()
        if title is not None:
            base = heading_slug(title)
            anchor = base
            suffix = 0
            while anchor in generated:
                suffix += 1
                anchor = f'{base}-{suffix}'
            generated.add(anchor)
        previous = line if line.strip() and not heading else ''
    # Custom anchors do not participate in heading suffix allocation.
    return generated | {unescape(value) for value in CUSTOM_ANCHOR.findall(prose)}


def check(root):
    errors = []
    anchor_cache = {}
    for name in DOCUMENTS:
        source = root / name
        if not source.is_file():
            errors.append(f'{name}: required document is missing')
            continue
        text = source.read_text(encoding='utf-8')
        if not text.startswith('# '):
            errors.append(f'{name}: missing document title')
        prose = prose_only(text)
        links = INLINE_LINK.findall(prose) + REFERENCE_LINK.findall(prose)
        for raw in links:
            target = raw.strip().split(' "', 1)[0].strip('<>')
            parts = urlsplit(target)
            if parts.scheme or parts.netloc:
                continue
            if not parts.path:
                path = source
            elif parts.path.startswith('/'):
                path = (root / unquote(parts.path).lstrip('/')).resolve()
            else:
                path = (source.parent / unquote(parts.path)).resolve()
            if not path.is_relative_to(root):
                errors.append(f'{name}: link leaves the repository: {target}')
            elif not path.exists():
                errors.append(f'{name}: missing link target: {target}')
            elif parts.fragment and path.is_file() and path.suffix.lower() in ('.md', '.markdown'):
                if path not in anchor_cache:
                    anchor_cache[path] = markdown_anchors(path.read_text(encoding='utf-8'))
                if unquote(parts.fragment) not in anchor_cache[path]:
                    errors.append(f'{name}: missing Markdown section: {target}')
    return errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    errors = check(args.root.resolve())
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        raise SystemExit(1)
    print(f'Checked {len(DOCUMENTS)} documents, local link targets and Markdown sections.')
