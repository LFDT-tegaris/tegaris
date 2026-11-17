import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { ModuleRecordSummary } from './module-record-summary';

afterEach(cleanup);

it('shows the proposed release and fingerprint without inventing installation or runtime authority', () => {
  render(
    <ModuleRecordSummary
      kind="module-registration"
      title="Review this change"
      review
      value={{
        name: 'pc.config.assets',
        semanticVersion: '1.0.0',
        supportProfile: 'R1',
        manifestDigest: `sha256:${'a'.repeat(64)}`,
        reason: 'Enable configuration management for the private evaluation.',
        signingKey: 'private-key-material',
        arbitraryField: 'unexpected-source-material',
      }}
    />,
  );
  expect(screen.getByText('pc.config.assets')).toBeVisible();
  expect(screen.getByText('1.0.0')).toBeVisible();
  expect(screen.getByText('Release fingerprint')).toBeVisible();
  expect(screen.queryByText(/private-key-material|unexpected-source-material/)).toBeNull();
  expect(screen.queryByText(/Installed|Active|Completed/)).toBeNull();
});

it('binds a lifecycle review to the exact resource and expected revision without an inferred module name', () => {
  render(
    <ModuleRecordSummary
      kind="module-enable"
      title="Change under review"
      review
      value={{ targetRef: 'urn:openpc:resource:original-module', expectedRevision: '2' }}
    />,
  );
  expect(screen.getByText('Module reference').nextElementSibling).toHaveTextContent(
    'urn:openpc:resource:original-module',
  );
  expect(screen.getByText('Expected revision').nextElementSibling).toHaveTextContent('2');
  expect(screen.queryByText('Module status')).toBeNull();
});

it.each([
  ['REGISTERED', 'Registered'],
  ['INSTALLED', 'Installed'],
  ['ACTIVE', 'Active'],
  ['NEW_STATE', 'Status not reported'],
])('uses recorded %s state and revision independently from operation success', (state, label) => {
  render(
    <ModuleRecordSummary
      kind="module-install"
      title="Recorded outcome"
      value={{
        name: 'pc.config.assets',
        semanticVersion: '1.0.0',
        state,
        revision: '2',
        updatedAt: '2026-10-11T18:05:39.700000Z',
      }}
    />,
  );
  expect(screen.getByText(label)).toBeVisible();
  expect(screen.getByText('Record revision').nextElementSibling).toHaveTextContent('2');
  expect(screen.getByText('Updated at').nextElementSibling).toHaveTextContent(
    '11 Oct 2026, 18:05 UTC',
  );
  expect(screen.getByText('Runtime access is governed separately.')).toBeVisible();
});
