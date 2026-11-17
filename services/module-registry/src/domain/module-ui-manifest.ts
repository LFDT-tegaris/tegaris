import { z } from 'zod';
import {
  assertModuleUiReleaseSignature,
  moduleUiCoseContext,
  moduleUiRegisteredSchemaDigest,
} from './module-ui-signing.js';
import type { ModuleReleasePublisherBinding } from '../module-release-catalog.js';
import {
  assertModuleSlot,
  moduleUiContributionSchema,
} from '../../../../packages/ui-extensions/src/registry.js';

export const moduleUiSignatureContext = moduleUiCoseContext;
export const moduleUiSchemaDigest = moduleUiRegisteredSchemaDigest;
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const semver = z
  .string()
  .regex(
    /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u,
  );
const range = z
  .string()
  .regex(/^(?:\^|~|>=|>|<=|<)?[0-9]+\.[0-9]+\.[0-9]+(?: [<>=~^]+[0-9]+\.[0-9]+\.[0-9]+)*$/u);
const strings = (pattern: RegExp) =>
  z.array(z.string().regex(pattern)).refine((v) => new Set(v).size === v.length);
const positive = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const truthStates = [
  'SUCCESS',
  'AUTHORIZED_EMPTY',
  'DENIED',
  'LOADING',
  'UNKNOWN',
  'UNAVAILABLE',
  'STALE',
  'REORG',
  'PARTIAL',
  'CONFLICTING',
  'DEGRADED',
  'FAILED',
  'RETRY_ELIGIBLE',
  'FAILOVER_ELIGIBLE',
  'WRITE_AMBIGUITY',
  'RECOVERY',
  'ROLLBACK',
  'RETIREMENT',
  'UNINSTALL',
  'DECOMMISSION',
] as const;
export const moduleUiTestKinds = [
  'UNIT',
  'SCHEMA',
  'ACCESSIBILITY_AUTOMATED',
  'KEYBOARD_E2E',
  'SCREEN_READER_MANUAL',
  'RESPONSIVE',
  'LOCALIZATION',
  'FAILURE_ISOLATION',
  'BACKEND_REAUTHORIZATION',
  'ANTI_LEAKAGE',
  'MIGRATION',
  'UNINSTALL',
] as const;

/** ModuleUiManifestV1 document shape. Evidence identifiers describe
 * obligations, not proof that certification, budgets or admission passed. */
export const moduleUiManifestSchema = z.strictObject({
  schemaVersion: z.literal('1.0'),
  manifestId: z
    .string()
    .regex(
      /^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    ),
  moduleId: z.string().regex(/^pc\.[a-z0-9.-]+$/u),
  moduleVersion: semver,
  moduleDigest: digest,
  publisherKeyId: digest,
  shellRange: range,
  designSystemRange: range,
  capabilities: strings(/^CAP-[A-Z0-9_-]+$/u),
  contributions: z.array(moduleUiContributionSchema).min(1),
  resourceBudget: z.strictObject({
    bundleBytes: positive,
    initialRenderMs: positive,
    interactionMs: positive,
    memoryBytes: positive,
    networkRequests: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    policy: z.literal('EXACT_QUALIFIED_PROFILE_NO_SLA_CLAIM'),
  }),
  telemetry: z.strictObject({
    namespace: z.string().regex(/^ui\.module\.[a-z0-9._-]+$/u),
    allowedDimensions: z
      .array(
        z.enum([
          'moduleId',
          'moduleVersion',
          'contributionId',
          'slotId',
          'routeId',
          'truthState',
          'stableProblemCode',
          'durationBucket',
        ]),
      )
      .refine((v) => new Set(v).size === v.length),
    payloadCapture: z.literal(false),
    highCardinalityActorLabels: z.literal(false),
  }),
  failure: z.strictObject({
    render: z.literal('ISOLATE_CONTRIBUTION'),
    load: z.literal('OMIT_AND_RECORD'),
    query: z.literal('TYPED_NO_FALLBACK'),
    mutation: z.literal('NO_AUTO_RETRY'),
    budget: z.literal('DISABLE_CONTRIBUTION'),
    safetyUi: z.literal('PRESERVE'),
  }),
  accessibility: z.strictObject({
    nameKey: z.string().min(3),
    landmarkPolicy: z.enum(['NONE', 'LABELLED_REGION', 'COMPLEMENTARY']),
    keyboardPatternIds: strings(/^A11Y-/u).refine((v) => v.length > 0),
    truthStates: z
      .array(z.enum(truthStates))
      .refine((v) => JSON.stringify(v) === JSON.stringify(truthStates)),
    responsiveProfiles: z.tuple([
      z.literal('MOBILE'),
      z.literal('TABLET'),
      z.literal('DESKTOP'),
      z.literal('WIDE'),
    ]),
    manualEvidenceIds: strings(/^EVIDENCE-/u).refine((v) => v.length > 0),
  }),
  localization: z.strictObject({
    namespace: z.string().regex(/^[a-z][a-z0-9.-]+$/u),
    builtInLocale: z.literal('en'),
    resourceDigests: z
      .record(z.string().regex(/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/u), digest)
      .refine((v) => Object.keys(v).length > 0),
    missingKey: z.literal('FAIL_CONTRIBUTION_CERTIFICATION'),
    richText: z.literal('ALLOWLISTED_STRUCTURED_TOKENS_NO_HTML'),
  }),
  tests: z
    .array(
      z.strictObject({
        testId: z.string().regex(/^TEST-/u),
        kind: z.enum(moduleUiTestKinds),
        evidenceId: z.string().regex(/^EVIDENCE-/u),
      }),
    )
    .min(1),
  migration: z.strictObject({
    fromRanges: z.array(z.string().min(5)).refine((v) => new Set(v).size === v.length),
    stateSchemaVersion: semver,
    migrationIds: strings(/^MIG-/u),
    rollbackId: z.string().regex(/^ROLLBACK-/u),
    oneActiveVersion: z.literal(true),
  }),
  uninstall: z.strictObject({
    disableFirst: z.literal(true),
    removeContributions: z.literal(true),
    clearState: z.literal(true),
    savedViews: z.literal('DROP_MODULE_FIELDS_AND_FILTERS'),
    localization: z.literal('REMOVE_NAMESPACE_AFTER_UNMOUNT'),
    evidenceReceipt: z.literal('REQUIRED'),
  }),
  signature: z.strictObject({
    encoding: z.literal('PC-CBOR-1'),
    algorithm: z.literal('ES256'),
    schemaId: z.literal(23001),
    schemaVersion: z.literal('1.0.0'),
    schemaDigest: z.literal(moduleUiSchemaDigest),
    purpose: z.literal('openpc:module-ui-manifest:v1'),
    coseSign1: z.string().min(1),
  }),
});
export type ModuleUiManifest = z.infer<typeof moduleUiManifestSchema>;
export class ModuleUiManifestError extends Error {
  constructor(readonly code: 'PC-MODULE-7002' | 'PC-MODULE-7008' = 'PC-MODULE-7002') {
    super(code);
  }
}

export function parseModuleUiManifest(value: unknown): ModuleUiManifest {
  const parsed = moduleUiManifestSchema.safeParse(value);
  if (!parsed.success) throw new ModuleUiManifestError();
  const manifest = parsed.data;
  const ids = new Set<string>();
  for (const contribution of manifest.contributions) {
    assertModuleSlot(contribution);
    if (
      ids.has(contribution.contributionId) ||
      contribution.localizationNamespace !== manifest.localization.namespace ||
      contribution.capabilityRequirements.some(
        (capability) => !manifest.capabilities.includes(capability),
      )
    )
      throw new ModuleUiManifestError();
    ids.add(contribution.contributionId);
  }
  return manifest;
}

/** Complete document validation plus canonical final-payload/release signature
 * binding. Deployment composition supplies the publisher binding, never a
 * browser key or an unrelated signed buffer. This remains void: compile-time
 * bundle certification and live module/context admission are separate gates. */
export function assertModuleUiEnvelopeSignature(
  document: unknown,
  binding: ModuleReleasePublisherBinding,
): void {
  const manifest = parseModuleUiManifest(document);
  try {
    assertModuleUiReleaseSignature(manifest, binding);
  } catch {
    throw new ModuleUiManifestError('PC-MODULE-7008');
  }
}
