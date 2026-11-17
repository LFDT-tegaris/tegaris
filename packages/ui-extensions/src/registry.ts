import { z } from 'zod';

export const extensionSlots = [
  'UISLOT-NAV-PRIMARY',
  'UISLOT-ROUTE-CONTENT',
  'UISLOT-OBJECT-ACTION',
  'UISLOT-DETAIL-PANEL',
  'UISLOT-DASHBOARD-CARD',
  'UISLOT-SETTINGS-SECTION',
] as const;

export type ExtensionSlot = (typeof extensionSlots)[number];

export const extensionContributionSchema = z
  .object({
    extensionId: z.string().regex(/^[a-z0-9][a-z0-9.-]{0,127}$/),
    slot: z.enum(extensionSlots),
    label: z.string().min(1).max(160),
    href: z.string().startsWith('/').optional(),
  })
  .strict();

export type ExtensionContribution = z.infer<typeof extensionContributionSchema>;

/**
 * Extensions provide presentation only. The server's current snapshot remains
 * the sole authority for route, object, field, and action visibility.
 */
export function registeredContributions(
  contributions: readonly ExtensionContribution[],
  allowedExtensionIds: readonly string[],
): readonly ExtensionContribution[] {
  const allowed = new Set(allowedExtensionIds);
  return contributions.filter((contribution) => allowed.has(contribution.extensionId));
}

/** Presentation contract. Parsing and ordering do not admit a module or authorize access. */
export const moduleUiContributionSchema = z.strictObject({
  contributionId: z.string().regex(/^UICONTRIB-[A-Z0-9_-]+$/u),
  slotId: z.enum(extensionSlots),
  kind: z.enum([
    'NAV_LINK',
    'REGISTERED_VIEW',
    'REGISTERED_FORM',
    'OBJECT_ACTION',
    'DETAIL_PANEL',
    'DASHBOARD_CARD',
  ]),
  phase: z.enum([
    'AFTER_SEALED_PRIMARY',
    'BEFORE_DOMAIN_CONTENT',
    'AFTER_DOMAIN_CONTENT',
    'PRIMARY',
    'SECONDARY',
    'OVERFLOW',
    'DOMAIN_SECTION',
  ]),
  anchor: z.string().min(1),
  priority: z.number().int().min(0).max(1000),
  capabilityRequirements: z.array(z.string().regex(/^CAP-/u)).refine(unique),
  routeBehavior: z.enum(['NO_ROUTE', 'REGISTERED_CHILD_ROUTE', 'REGISTERED_LINK_ONLY']),
  actionIntents: z.array(z.string().regex(/^ACT-/u)).refine(unique),
  dataQueries: z.array(z.string().regex(/^[a-z][A-Za-z0-9]+$/u)).refine(unique),
  viewOrFormId: z
    .string()
    .regex(/^(VIEW|FORM)-/u)
    .nullable(),
  versionRange: z.string().min(5),
  accessibilityMetadataId: z.string().regex(/^A11Y-/u),
  localizationNamespace: z.string().min(3),
  unloadBehavior: z.literal('UNMOUNT_CANCEL_CLEAR_REAUTHORIZE'),
});
function unique(values: readonly string[]) {
  return new Set(values).size === values.length;
}
export type ModuleUiContribution = z.infer<typeof moduleUiContributionSchema>;
export const moduleSlotRules = {
  'UISLOT-NAV-PRIMARY': { kinds: ['NAV_LINK'], phases: ['AFTER_SEALED_PRIMARY'] },
  'UISLOT-ROUTE-CONTENT': {
    kinds: ['REGISTERED_VIEW', 'REGISTERED_FORM'],
    phases: ['BEFORE_DOMAIN_CONTENT', 'AFTER_DOMAIN_CONTENT'],
  },
  'UISLOT-OBJECT-ACTION': { kinds: ['OBJECT_ACTION'], phases: ['SECONDARY', 'OVERFLOW'] },
  'UISLOT-DETAIL-PANEL': { kinds: ['DETAIL_PANEL'], phases: ['PRIMARY', 'SECONDARY'] },
  'UISLOT-DASHBOARD-CARD': { kinds: ['DASHBOARD_CARD'], phases: ['PRIMARY', 'SECONDARY'] },
  'UISLOT-SETTINGS-SECTION': { kinds: ['REGISTERED_FORM'], phases: ['DOMAIN_SECTION'] },
} as const;

export class ModuleContributionError extends Error {
  constructor(readonly code: 'PC-MODULE-7001' | 'PC-MODULE-7002') {
    super(code);
  }
}
export interface ModuleContributionEntry {
  readonly moduleId: string;
  readonly contribution: ModuleUiContribution;
}
/** Shell-owned registered anchors, never supplied by a contribution/request. */
export type ModuleSlotAnchors = Readonly<Record<ExtensionSlot, readonly string[]>>;

export function assertModuleSlot(contribution: ModuleUiContribution): void {
  const parsed = moduleUiContributionSchema.safeParse(contribution);
  if (!parsed.success) throw new ModuleContributionError('PC-MODULE-7002');
  const rules = moduleSlotRules[parsed.data.slotId];
  if (
    !(rules.kinds as readonly string[]).includes(parsed.data.kind) ||
    !(rules.phases as readonly string[]).includes(parsed.data.phase)
  )
    throw new ModuleContributionError('PC-MODULE-7002');
  if (
    parsed.data.slotId === 'UISLOT-NAV-PRIMARY' &&
    !['DEST-HOME', 'DEST-GOVERN', 'DEST-CONFIGURE', 'DEST-OPERATE', 'DEST-DEVELOP'].includes(
      parsed.data.anchor,
    )
  )
    throw new ModuleContributionError('PC-MODULE-7002');
  if (
    parsed.data.slotId === 'UISLOT-SETTINGS-SECTION' &&
    parsed.data.anchor !== 'ROUTE-CONFIG-IMPORT-EXPORT-SETTINGS'
  )
    throw new ModuleContributionError('PC-MODULE-7002');
}

/** Deterministic ordering by phase, anchor, priority, module and contribution.
 * Unknown anchors (including contribution-to-contribution cycles) fail closed.
 * This does not select enabled modules or grant route/object/field/action access. */
export function orderModuleContributions<T extends ModuleContributionEntry>(
  entries: readonly T[],
  anchors: ModuleSlotAnchors,
): readonly T[] {
  for (const slot of extensionSlots)
    if (!Array.isArray(anchors[slot]) || !unique(anchors[slot]))
      throw new ModuleContributionError('PC-MODULE-7001');
  const identities = new Set<string>();
  for (const entry of entries) {
    if (!/^pc\.[a-z0-9.-]+$/u.test(entry.moduleId))
      throw new ModuleContributionError('PC-MODULE-7002');
    assertModuleSlot(entry.contribution);
    if (
      identities.has(entry.contribution.contributionId) ||
      !anchors[entry.contribution.slotId].includes(entry.contribution.anchor)
    )
      throw new ModuleContributionError('PC-MODULE-7001');
    identities.add(entry.contribution.contributionId);
  }
  const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  return [...entries].sort((a, b) => {
    const x = a.contribution,
      y = b.contribution;
    if (x.slotId !== y.slotId)
      return extensionSlots.indexOf(x.slotId) - extensionSlots.indexOf(y.slotId);
    const phases: readonly string[] = moduleSlotRules[x.slotId].phases;
    return (
      phases.indexOf(x.phase) - phases.indexOf(y.phase) ||
      anchors[x.slotId].indexOf(x.anchor) - anchors[y.slotId].indexOf(y.anchor) ||
      x.priority - y.priority ||
      cmp(a.moduleId, b.moduleId) ||
      cmp(x.contributionId, y.contributionId)
    );
  });
}
