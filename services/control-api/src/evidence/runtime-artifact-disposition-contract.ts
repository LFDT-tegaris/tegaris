import { z } from 'zod';
import { participantUrnSchema, resourceUrnSchema } from '../configuration/resource-contracts.js';
import { runtimeArtifactDeletionSelection } from './runtime-artifact-deletion-contracts.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);

/** Exact governed intent. The enclosed deletion observation creates neither
 * native custody nor deletion authority; each has its own result and owner. */
export const runtimeArtifactDispositionSelection = z.strictObject({
  version: z.literal('OPENPC_RUNTIME_ARTIFACT_SOURCE_DISPOSITION_V1'),
  sourceOwnerId: z.uuidv7(),
  sourceRootDigest: digest,
  archivePendingDigest: digest,
  observation: runtimeArtifactDeletionSelection,
});
export type RuntimeArtifactDispositionSelection = z.infer<
  typeof runtimeArtifactDispositionSelection
>;

export const disposeRuntimeArtifactSource = z.strictObject({
  participantId: participantUrnSchema,
  selection: runtimeArtifactDispositionSelection,
  actionIntentId: z.literal('ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1'),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
});

export const runtimeArtifactDispositionPlanInput = z.strictObject({
  runtimeConfigurationInputId: resourceUrnSchema,
  retentionPolicyId: resourceUrnSchema,
});
export const runtimeArtifactDispositionPlan = z.strictObject({
  selection: runtimeArtifactDispositionSelection.nullable(),
  blockers: z.array(z.string().regex(/^[A-Z][A-Z0-9_]*$/u)).max(32),
  nativeCustody: z.literal('REQUIRED_AFTER_COMMITTED_ADMISSION'),
  authority: z.literal('NONE'),
});

export const runtimeArtifactDispositionView = z.strictObject({
  dispositionId: resourceUrnSchema,
  participantId: participantUrnSchema,
  privacyDomainId: z.uuidv7(),
  sourceOwnerId: z.uuidv7(),
  runtimeConfigurationInputId: resourceUrnSchema,
  configurationDigest: digest,
  selectionDigest: digest,
  operationId: z.uuidv7(),
  revision: z.literal('1'),
  admittedAt: z.iso.datetime({ precision: 6 }),
  admissionReceiptDigest: digest,
  newUseState: z.literal('DENIED'),
  nativeState: z.enum(['PENDING', 'DENIED']),
  nativeDenialDigest: digest.nullable(),
  physicalState: z.enum(['NOT_ESTABLISHED', 'RETIRED']),
});
