import { expect, it } from 'vitest';

import {
  registeredContributions,
  assertModuleSlot,
  orderModuleContributions,
  moduleUiContributionSchema,
  extensionSlots,
  type ModuleSlotAnchors,
  type ModuleUiContribution,
} from './registry';

it('does not let extension state create a visible contribution without server registration', () => {
  const contributions = [
    {
      extensionId: 'pc.example',
      slot: 'UISLOT-NAV-PRIMARY' as const,
      label: 'Example',
      href: '/example',
    },
  ];
  expect(registeredContributions(contributions, [])).toEqual([]);
  expect(registeredContributions(contributions, ['pc.example'])).toEqual(contributions);
});

// Presentation-only data; these tests do not admit a module or grant authority.
const contribution = (changes: Partial<ModuleUiContribution> = {}): ModuleUiContribution => ({
  contributionId: 'UICONTRIB-EXAMPLE',
  slotId: 'UISLOT-ROUTE-CONTENT',
  kind: 'REGISTERED_VIEW',
  phase: 'AFTER_DOMAIN_CONTENT',
  anchor: 'ROUTE-MODULE-LIFECYCLE',
  priority: 100,
  capabilityRequirements: ['CAP-EXAMPLE'],
  routeBehavior: 'REGISTERED_CHILD_ROUTE',
  actionIntents: [],
  dataQueries: ['getUiModuleLifecycle'],
  viewOrFormId: 'VIEW-MODULE_LIFECYCLE',
  versionRange: '>=1.0.0 <2.0.0',
  accessibilityMetadataId: 'A11Y-EXAMPLE',
  localizationNamespace: 'openpc.example',
  unloadBehavior: 'UNMOUNT_CANCEL_CLEAR_REAUTHORIZE',
  ...changes,
});
const anchors: ModuleSlotAnchors = {
  'UISLOT-NAV-PRIMARY': ['DEST-HOME', 'DEST-GOVERN'],
  'UISLOT-ROUTE-CONTENT': ['ROUTE-MODULE-LIFECYCLE', 'ROUTE-SECOND'],
  'UISLOT-OBJECT-ACTION': ['VIEW-MODULE_LIFECYCLE'],
  'UISLOT-DETAIL-PANEL': ['VIEW-MODULE_LIFECYCLE'],
  'UISLOT-DASHBOARD-CARD': ['DASHBOARD-EXAMPLE'],
  'UISLOT-SETTINGS-SECTION': ['ROUTE-CONFIG-IMPORT-EXPORT-SETTINGS'],
};
it.each([
  ['UISLOT-NAV-PRIMARY', 'NAV_LINK', 'AFTER_SEALED_PRIMARY', 'DEST-HOME'],
  ['UISLOT-ROUTE-CONTENT', 'REGISTERED_VIEW', 'BEFORE_DOMAIN_CONTENT', 'ROUTE-MODULE-LIFECYCLE'],
  ['UISLOT-OBJECT-ACTION', 'OBJECT_ACTION', 'OVERFLOW', 'VIEW-MODULE_LIFECYCLE'],
  ['UISLOT-DETAIL-PANEL', 'DETAIL_PANEL', 'PRIMARY', 'VIEW-MODULE_LIFECYCLE'],
  ['UISLOT-DASHBOARD-CARD', 'DASHBOARD_CARD', 'SECONDARY', 'DASHBOARD-EXAMPLE'],
  [
    'UISLOT-SETTINGS-SECTION',
    'REGISTERED_FORM',
    'DOMAIN_SECTION',
    'ROUTE-CONFIG-IMPORT-EXPORT-SETTINGS',
  ],
] as const)(
  'supports the registered %s position without granting visibility',
  (slotId, kind, phase, anchor) => {
    const value = contribution({ slotId, kind, phase, anchor });
    expect(() => assertModuleSlot(value)).not.toThrow();
    expect(
      orderModuleContributions([{ moduleId: 'pc.example', contribution: value }], anchors),
    ).toHaveLength(1);
  },
);
it('sorts by phase then anchor then priority then exact module and contribution identity', () => {
  const entry = (
    moduleId: string,
    contributionId: string,
    changes: Partial<ModuleUiContribution> = {},
  ) => ({ moduleId, contribution: contribution({ contributionId, ...changes }) });
  const items = [
    entry('pc.zz', 'UICONTRIB-Z'),
    entry('pc.aa', 'UICONTRIB-B'),
    entry('pc.aa', 'UICONTRIB-A'),
    entry('pc.xx', 'UICONTRIB-LOW', { priority: 0 }),
    entry('pc.xx', 'UICONTRIB-EARLY', {
      phase: 'BEFORE_DOMAIN_CONTENT',
      anchor: 'ROUTE-SECOND',
      priority: 1000,
    }),
  ];
  expect(
    orderModuleContributions(items, anchors).map((item) => item.contribution.contributionId),
  ).toEqual(['UICONTRIB-EARLY', 'UICONTRIB-LOW', 'UICONTRIB-A', 'UICONTRIB-B', 'UICONTRIB-Z']);
  expect(items[0]!.moduleId).toBe('pc.zz');
});
it('rejects duplicate IDs/anchors, unknown anchors/cycles and mismatched slot kinds', () => {
  const entry = { moduleId: 'pc.example', contribution: contribution() };
  expect(() => orderModuleContributions([entry, entry], anchors)).toThrow('PC-MODULE-7001');
  expect(() =>
    orderModuleContributions([entry], {
      ...anchors,
      'UISLOT-ROUTE-CONTENT': ['ROUTE-MODULE-LIFECYCLE', 'ROUTE-MODULE-LIFECYCLE'],
    }),
  ).toThrow('PC-MODULE-7001');
  expect(() =>
    orderModuleContributions(
      [{ ...entry, contribution: contribution({ anchor: 'UICONTRIB-EXAMPLE' }) }],
      anchors,
    ),
  ).toThrow('PC-MODULE-7001');
  for (const slotId of extensionSlots.filter((slot) => slot !== 'UISLOT-ROUTE-CONTENT'))
    expect(() => assertModuleSlot(contribution({ slotId }))).toThrow('PC-MODULE-7002');
  expect(() =>
    assertModuleSlot(
      contribution({
        slotId: 'UISLOT-NAV-PRIMARY',
        kind: 'NAV_LINK',
        phase: 'AFTER_SEALED_PRIMARY',
        anchor: 'https://evil.invalid',
      }),
    ),
  ).toThrow('PC-MODULE-7002');
});
it.each([
  { priority: -1 },
  { priority: 1001 },
  { priority: 0.5 },
  { remoteScript: 'https://evil.invalid/a.js' },
  { unloadBehavior: 'KEEP_CACHED' },
  { capabilityRequirements: ['CAP-X', 'CAP-X'] },
  { dataQueries: ['fetchAnything', 'fetchAnything'] },
])('keeps contribution input closed: %j', (change) => {
  expect(moduleUiContributionSchema.safeParse({ ...contribution(), ...change }).success).toBe(
    false,
  );
});
