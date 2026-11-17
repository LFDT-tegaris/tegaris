import { z } from 'zod';
import { participantUrnSchema, resourceUrnSchema } from '../configuration/resource-contracts.js';
import { sha256 } from '../configuration/digest.js';
import { digest, evidenceScope, sequence } from './segment.js';
import { deleteLocalEvidence, evidenceDeletionCursor } from './deletion-contracts.js';
import {
  runtimeArtifactArchiveIdentity,
  runtimeArtifactManifestRecordId,
} from './runtime-artifact-archive-contract.js';

// This is an exact selection of native bytes and retained archive observations.
// Parsing it never establishes reference disposition, eligibility or authority.
const sinkReceipt = z.strictObject({
  sinkId: evidenceScope.shape.streamId,
  checkpointDigest: digest,
  receiptDigest: digest,
  acknowledgedAtMicros: sequence,
});
const archiveSegment = z.strictObject({
  // Evidence custody uses random UUIDs; these are archive identities, not
  // configuration resource IDs. Preserve the segment owner's UUID contract.
  segmentId: z.uuid(),
  objectDigest: digest,
  firstSequence: sequence,
  throughSequence: sequence,
  sinkReceipts: z.array(sinkReceipt).min(1).max(8),
});
export const runtimeArtifactDeletionSelection = z
  .strictObject({
    version: z.literal('OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1'),
    participantId: participantUrnSchema,
    privacyDomainId: z.uuidv7(),
    retentionPolicyId: resourceUrnSchema,
    policyDigest: digest,
    targetDatabase: z.literal('openpc_control'),
    dataClass: z.literal('RUNTIME_ARTIFACT'),
    deletionMode: z.literal('ROW_DELETE'),
    source: runtimeArtifactArchiveIdentity,
    streamId: evidenceScope.shape.streamId,
    manifestRecordId: z.string().regex(/^runtime-artifact:[0-9a-f]{64}:manifest$/u),
    manifestDigest: digest,
    archiveSegments: z.array(archiveSegment).min(1).max(65),
    referenceObservationDigest: digest,
    eligibleAfterMicros: sequence,
    priorCursor: evidenceDeletionCursor.nullable(),
  })
  .superRefine((value, context) => {
    const identityDigest = sha256({
      domain: 'pc.runtime-artifact.archive-identity.v1',
      identity: value.source,
    });
    const segments = value.archiveSegments;
    if (
      value.participantId !== `urn:openpc:participant:${value.source.participantId}` ||
      value.privacyDomainId !== value.source.privacyDomainId ||
      value.manifestRecordId !== runtimeArtifactManifestRecordId(identityDigest) ||
      new Set(segments.map((segment) => segment.segmentId)).size !== segments.length ||
      segments.some(
        (segment, index) =>
          BigInt(segment.firstSequence) < 1n ||
          BigInt(segment.throughSequence) < BigInt(segment.firstSequence) ||
          (index > 0 &&
            BigInt(segment.firstSequence) <= BigInt(segments[index - 1]!.throughSequence)) ||
          new Set(segment.sinkReceipts.map((receipt) => receipt.sinkId)).size !==
            segment.sinkReceipts.length,
      )
    )
      context.addIssue({
        code: 'custom',
        message: 'Runtime artifact selection binding is invalid.',
      });
  });
export type RuntimeArtifactDeletionSelection = z.infer<typeof runtimeArtifactDeletionSelection>;
// A physical batch binds its immediate successor even when that input is still
// ineligible. A later caller cannot skip it or substitute a new business key.
export const runtimeArtifactRetirementTarget = z.strictObject({
  runtimeConfigurationInputId: z.uuidv7(),
  configurationDigest: digest,
  beforeDigest: digest,
});
export const runtimeArtifactRetirementSelection = runtimeArtifactDeletionSelection
  .safeExtend({
    disposition: z.strictObject({
      dispositionId: z.uuidv7(),
      operationId: z.uuidv7(),
      receiptDigest: digest,
      nativeDenialDigest: digest,
      sourceOwnerId: z.uuidv7(),
      sourceRootDigest: digest,
    }),
    nextInput: runtimeArtifactRetirementTarget.nullable(),
  })
  .superRefine((value, context) => {
    if (
      value.nextInput &&
      value.nextInput.runtimeConfigurationInputId <= value.source.runtimeConfigurationInputId
    )
      context.addIssue({
        code: 'custom',
        message: 'Runtime retirement must preserve primary-key order.',
      });
  });
export const deleteRuntimeArtifactBatch = deleteLocalEvidence.extend({
  selection: runtimeArtifactRetirementSelection,
});
export const runtimeArtifactDeletionBlocker = z.enum([
  'NO_ACTIVE_POLICY',
  'UNSUPPORTED_MODE',
  'RETENTION_NOT_ELAPSED',
  'ACTIVE_HOLD',
  'SINK_QUORUM',
  'INCOMPLETE_CHECKPOINT',
  'SELECTED_INPUT',
  'ACTIVE_CONFIGURATION',
  'REFERENCES',
  'UNKNOWN_EFFECT',
  'INCOMPLETE_REFERENCE_COVERAGE',
  'SOURCE_REDELIVERY_UNPROVEN',
  'RUNTIME_CUSTODY_UNPROVEN',
  'BACKUP_RESTORE_UNPROVEN',
  'GOVERNED_DISPOSITION_REQUIRED',
  'STALE_SELECTION',
  'ALREADY_DELETED',
]);

export const runtimeArtifactRetirementPlanInput = z.strictObject({
  retentionPolicyId: resourceUrnSchema,
  previousDeletionJobId: resourceUrnSchema.nullable(),
});
export const runtimeArtifactRetirementPlan = z.strictObject({
  selection: runtimeArtifactRetirementSelection.nullable(),
  beforeDigest: digest.nullable(),
  eligible: z.boolean(),
  blockers: z.array(runtimeArtifactDeletionBlocker).max(32),
  continuationState: z.enum(['READY', 'BLOCKED', 'COMPLETE', 'ADVANCED']),
  nextDeletionJobId: resourceUrnSchema.nullable(),
  authority: z.literal('NONE'),
});
