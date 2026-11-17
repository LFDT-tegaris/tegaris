import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import type { ModuleSlotAnchors, ModuleUiContribution } from '@openpc/ui-extensions';
import type { ModuleExtensionSnapshot } from '../../lib/module-extensions';
import { ModuleExtensionSlot, type BundledModulePresentation } from './module-extension-slots';

// Isolated renderer contracts; lifetime teardown is exercised in the sibling
// boundary suite. None of these fixtures constitutes admitted production UI.
const state = vi.hoisted(() => ({ snapshot: undefined as ModuleExtensionSnapshot | undefined }));
vi.mock('./module-extension-boundary', () => ({
  useModuleExtensionLifetime: () => ({ snapshot: state.snapshot }),
  ModuleContributionBoundary: ({ children }: { children: ReactNode }) => children,
}));
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
const anchors: ModuleSlotAnchors = {
  'UISLOT-NAV-PRIMARY': ['DEST-HOME'],
  'UISLOT-ROUTE-CONTENT': ['ROUTE-MODULE-LIFECYCLE'],
  'UISLOT-OBJECT-ACTION': ['VIEW-MODULE_LIFECYCLE'],
  'UISLOT-DETAIL-PANEL': ['VIEW-MODULE_LIFECYCLE'],
  'UISLOT-DASHBOARD-CARD': ['DASHBOARD-EXAMPLE'],
  'UISLOT-SETTINGS-SECTION': ['ROUTE-CONFIG-IMPORT-EXPORT-SETTINGS'],
};
const contribution = (changes: Partial<ModuleUiContribution> = {}): ModuleUiContribution => ({
  contributionId: 'UICONTRIB-EXAMPLE',
  slotId: 'UISLOT-ROUTE-CONTENT',
  kind: 'REGISTERED_VIEW',
  phase: 'AFTER_DOMAIN_CONTENT',
  anchor: 'ROUTE-MODULE-LIFECYCLE',
  priority: 100,
  capabilityRequirements: ['CAP-EXAMPLE'],
  routeBehavior: 'NO_ROUTE',
  actionIntents: [],
  dataQueries: [],
  viewOrFormId: 'VIEW-MODULE_LIFECYCLE',
  versionRange: '>=1.0.0 <2.0.0',
  accessibilityMetadataId: 'A11Y-EXAMPLE',
  localizationNamespace: 'openpc.example',
  unloadBehavior: 'UNMOUNT_CANCEL_CLEAR_REAUTHORIZE',
  ...changes,
});
function setup(contributions: ModuleUiContribution[]) {
  const digest = `sha256:${'a'.repeat(64)}`;
  state.snapshot = {
    kind: 'MODULE_EXTENSIONS',
    query: { routeId: 'ROUTE-MODULE-LIFECYCLE' },
    binding: {
      actorKey: digest,
      observationKey: digest,
      participantId: '018f0000-0000-7000-8000-000000000001',
      privacyDomainId: '018f0000-0000-7000-8000-000000000002',
    },
    entries: contributions.map((value) => ({
      moduleId: 'pc.example',
      moduleRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000003',
      moduleVersion: '1.0.0',
      moduleDigest: digest,
      moduleRevision: '3',
      uiManifestDigest: digest,
      contribution: value,
    })),
  };
  return contributions.map(
    (value) =>
      ({
        moduleId: 'pc.example',
        moduleVersion: '1.0.0',
        moduleDigest: digest,
        uiManifestDigest: digest,
        contributionId: value.contributionId,
        slotId: value.slotId,
        viewOrFormId: value.viewOrFormId,
        label: `Module ${value.contributionId}`,
        component: () => <button type="button">Registered content {value.contributionId}</button>,
      }) satisfies BundledModulePresentation,
  );
}
it.each([
  ['UISLOT-NAV-PRIMARY', 'NAV_LINK', 'AFTER_SEALED_PRIMARY', 'DEST-HOME'],
  ['UISLOT-ROUTE-CONTENT', 'REGISTERED_VIEW', 'BEFORE_DOMAIN_CONTENT', 'ROUTE-MODULE-LIFECYCLE'],
  ['UISLOT-OBJECT-ACTION', 'OBJECT_ACTION', 'SECONDARY', 'VIEW-MODULE_LIFECYCLE'],
  ['UISLOT-DETAIL-PANEL', 'DETAIL_PANEL', 'PRIMARY', 'VIEW-MODULE_LIFECYCLE'],
  ['UISLOT-DASHBOARD-CARD', 'DASHBOARD_CARD', 'PRIMARY', 'DASHBOARD-EXAMPLE'],
  [
    'UISLOT-SETTINGS-SECTION',
    'REGISTERED_FORM',
    'DOMAIN_SECTION',
    'ROUTE-CONFIG-IMPORT-EXPORT-SETTINGS',
  ],
] as const)('renders only the bound %s position', (slotId, kind, phase, anchor) => {
  const presentations = setup([contribution({ slotId, kind, phase, anchor })]);
  render(
    <>
      <p>Sealed safety</p>
      <ModuleExtensionSlot
        slot={slotId}
        anchor={anchor}
        anchors={anchors}
        presentations={presentations}
      />
    </>,
  );
  expect(screen.getByRole('region', { name: 'Module UICONTRIB-EXAMPLE' })).toBeVisible();
  expect(
    screen.getByRole('button', { name: 'Registered content UICONTRIB-EXAMPLE' }),
  ).toBeVisible();
  expect(screen.getByText('Sealed safety')).toBeVisible();
});
it('isolates render failure and preserves sibling and sealed safety UI', () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  const presentations: BundledModulePresentation[] = setup([
    contribution(),
    contribution({ contributionId: 'UICONTRIB-SAFE' }),
  ]);
  presentations[0] = {
    ...presentations[0]!,
    component: () => {
      throw new Error('private error detail must not render');
    },
  };
  render(
    <>
      <p>Sealed safety</p>
      <ModuleExtensionSlot
        slot="UISLOT-ROUTE-CONTENT"
        anchor="ROUTE-MODULE-LIFECYCLE"
        anchors={anchors}
        presentations={presentations}
      />
    </>,
  );
  expect(screen.getByRole('status')).toHaveTextContent('This module contribution is unavailable.');
  expect(screen.getByText('Sealed safety')).toBeVisible();
  expect(screen.getByRole('button')).toHaveTextContent('UICONTRIB-SAFE');
  expect(screen.queryByText('private error detail must not render')).toBeNull();
});
it('does not load absent, duplicate or mismatched compile-time bindings', () => {
  const presentations = setup([contribution()]);
  const { rerender } = render(
    <ModuleExtensionSlot
      slot="UISLOT-ROUTE-CONTENT"
      anchor="ROUTE-MODULE-LIFECYCLE"
      anchors={anchors}
      presentations={[]}
    />,
  );
  expect(screen.queryByRole('button')).toBeNull();
  rerender(
    <ModuleExtensionSlot
      slot="UISLOT-ROUTE-CONTENT"
      anchor="ROUTE-MODULE-LIFECYCLE"
      anchors={anchors}
      presentations={[...presentations, ...presentations]}
    />,
  );
  expect(screen.queryByRole('button')).toBeNull();
  rerender(
    <ModuleExtensionSlot
      slot="UISLOT-ROUTE-CONTENT"
      anchor="ROUTE-MODULE-LIFECYCLE"
      anchors={anchors}
      presentations={[{ ...presentations[0]!, viewOrFormId: 'FORM-FOREIGN' }]}
    />,
  );
  expect(screen.queryByRole('button')).toBeNull();
});
it('rejects malformed ordering and never renders a contribution at another anchor', () => {
  const presentations = setup([contribution()]);
  const { rerender } = render(
    <ModuleExtensionSlot
      slot="UISLOT-DETAIL-PANEL"
      anchor="VIEW-MODULE_LIFECYCLE"
      anchors={anchors}
      presentations={presentations}
    />,
  );
  expect(screen.queryByRole('button')).toBeNull();
  state.snapshot!.entries.push(state.snapshot!.entries[0]!);
  rerender(
    <ModuleExtensionSlot
      slot="UISLOT-ROUTE-CONTENT"
      anchor="ROUTE-MODULE-LIFECYCLE"
      anchors={anchors}
      presentations={presentations}
    />,
  );
  expect(screen.getByRole('status')).toHaveTextContent('ordering is unavailable');
  expect(screen.queryByRole('button')).toBeNull();
});
it.each([
  { moduleId: 'pc.foreign' },
  { moduleVersion: '2.0.0' },
  { moduleDigest: `sha256:${'b'.repeat(64)}` },
  { uiManifestDigest: `sha256:${'b'.repeat(64)}` },
])('rejects a reused contribution ID from a different compiled binding %j', (change) => {
  const presentations = setup([contribution()]);
  render(
    <ModuleExtensionSlot
      slot="UISLOT-ROUTE-CONTENT"
      anchor="ROUTE-MODULE-LIFECYCLE"
      anchors={anchors}
      presentations={[{ ...presentations[0]!, ...change }]}
    />,
  );
  expect(screen.queryByRole('button')).toBeNull();
  expect(screen.getByRole('status')).toHaveTextContent('could not be loaded');
});
