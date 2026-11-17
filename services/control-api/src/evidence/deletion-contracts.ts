import { z } from 'zod';
import { participantUrnSchema, resourceUrnSchema } from '../configuration/resource-contracts.js';
import { digest, evidenceScope, sequence } from './segment.js';

export const evidenceDeletionCursor = z.strictObject({
  deletionJobId: resourceUrnSchema,
  receiptDigest: digest,
});

export const evidenceDeletionRejection = z.strictObject({
  evidenceId: resourceUrnSchema,
  commandId: z.uuidv7(),
  attemptId: z.uuidv7(),
  receiptDigest: digest,
  candidateDigest: digest,
  authorizationEvidenceDigest: digest,
  externalAttemptState: z.literal('NOT_STARTED'),
  sourceFormat: z.literal('PC-DEPLOYMENT-RESERVATION-REJECTION-1'),
});
export const evidenceDeletionRejections = z
  .array(evidenceDeletionRejection)
  .min(1)
  .max(128)
  .refine(
    (items) =>
      new Set(items.map((item) => item.evidenceId)).size === items.length &&
      items.every((item, index) => index === 0 || item.commandId > items[index - 1]!.commandId),
    'Rejection sources must be distinct and in command order.',
  );

/** Public locators/digests of an already governed normalized RPC retirement.
 * This is historical proof, never authority to execute or replay the RPC. */
export const evidenceDeletionRpcRetirement = z.strictObject({
  evidenceId: resourceUrnSchema,
  recordId: z
    .string()
    .regex(/^rpc:[0-9a-f]{64}:[1-9][0-9]{0,19}$/u)
    .refine((value) => {
      const sequence = value.split(':')[2];
      return (
        sequence !== undefined &&
        /^[1-9][0-9]{0,19}$/u.test(sequence) &&
        BigInt(sequence) <= 18446744073709551615n
      );
    }, 'RPC sequence must fit u64.'),
  sourceReceiptDigest: digest,
  retirementJobId: resourceUrnSchema,
  retirementReceiptDigest: digest,
  retirementDigest: digest,
});
export const evidenceDeletionRpcRetirements = z
  .array(evidenceDeletionRpcRetirement)
  .min(1)
  .max(128)
  .refine(
    (items) =>
      new Set(items.map((item) => item.evidenceId)).size === items.length &&
      items.every((item, index) => index === 0 || item.recordId > items[index - 1]!.recordId),
    'RPC retirement sources must be distinct and in canonical record-ID order.',
  );

export function evidenceDeletionSourceCardinality(value: {
  recordCount: number;
  sourceRejections?: readonly { evidenceId: string }[];
  sourceRpcRetirements?: readonly { evidenceId: string }[];
}) {
  const sources = [...(value.sourceRejections ?? []), ...(value.sourceRpcRetirements ?? [])];
  return (
    sources.length <= value.recordCount &&
    new Set(sources.map((item) => item.evidenceId)).size === sources.length
  );
}

// One initial batch owns one complete immutable ciphertext object (at most 128
// records). Its metadata and other storage locations have separate lifetimes.
export const localEvidenceDeletionSelection = z
  .strictObject({
    version: z.literal('OPENPC_LOCAL_EVIDENCE_DELETION_V1'),
    evidenceId: resourceUrnSchema,
    participantId: participantUrnSchema,
    privacyDomainId: z.uuid(),
    retentionPolicyId: resourceUrnSchema,
    policyDigest: digest,
    targetDatabase: z.literal('openpc_control'),
    dataClass: z.literal('AUDIT_EVIDENCE'),
    deletionMode: z.literal('ROW_DELETE'),
    streamId: evidenceScope.shape.streamId,
    segmentId: z.uuid(),
    firstSequence: sequence,
    throughSequence: sequence,
    objectDigest: digest,
    ciphertextBytes: z.number().int().min(1).max(2097152),
    recordCount: z.number().int().min(1).max(128),
    // Absent for historical authentication/business-only selections. The
    // existing signed eligibility digest binds this complete additive field.
    sourceRejections: evidenceDeletionRejections.optional(),
    sourceRpcRetirements: evidenceDeletionRpcRetirements.optional(),
    eligibleAfterMicros: z.string().regex(/^(?:0|[1-9][0-9]{0,24})$/u),
    sinkReceipts: z
      .array(
        z.strictObject({
          sinkId: z.string().min(1).max(160),
          checkpointDigest: digest,
          receiptDigest: digest,
          acknowledgedAtMicros: sequence,
        }),
      )
      .max(8),
    priorCursor: z.null(),
  })
  .superRefine((value, context) => {
    if (
      BigInt(value.firstSequence) < 1n ||
      !evidenceDeletionSourceCardinality(value) ||
      BigInt(value.throughSequence) - BigInt(value.firstSequence) + 1n !== BigInt(value.recordCount)
    )
      context.addIssue({
        code: 'custom',
        message: 'The complete object range must match its exact record count.',
      });
    if (
      new Set(value.sinkReceipts.map((receipt) => receipt.sinkId)).size !==
      value.sinkReceipts.length
    )
      context.addIssue({ code: 'custom', message: 'Sink receipts must name distinct sinks.' });
  });
export const localEvidenceDeletionPlan = z.strictObject({
  evidenceId: resourceUrnSchema,
  localPayload: z.enum(['RETAINED', 'DELETED']),
  eligible: z.boolean(),
  blockers: z.array(
    z.enum([
      'NO_ACTIVE_POLICY',
      'UNSUPPORTED_MODE',
      'RETENTION_NOT_ELAPSED',
      'ACTIVE_HOLD',
      'SINK_QUORUM',
      'INCOMPLETE_CHECKPOINT',
      'UNSUPPORTED_SOURCE',
      'REFERENCES',
      'ALREADY_DELETED',
    ]),
  ),
  selection: localEvidenceDeletionSelection.nullable(),
  beforeDigest: digest.nullable(),
});
export const deleteLocalEvidence = z.strictObject({
  participantId: participantUrnSchema,
  selection: localEvidenceDeletionSelection,
  beforeDigest: digest,
  actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
});
export const evidenceDeletionView = z.strictObject({
  deletionJobId: resourceUrnSchema,
  participantId: participantUrnSchema,
  selection: localEvidenceDeletionSelection,
  state: z.literal('SUCCEEDED'),
  revision: z.literal('1'),
  operationId: z.uuidv7(),
  attemptId: z.uuidv7(),
  externalAttemptState: z.literal('NOT_STARTED'),
  deletedCount: z.literal('1'),
  deletedBytes: sequence,
  retainedAliasCount: z.literal('0'),
  beforeDigest: digest,
  afterDigest: digest,
  receiptDigest: digest,
  startedAt: z.iso.datetime({ precision: 6 }),
  completedAt: z.iso.datetime({ precision: 6 }),
  createdAt: z.iso.datetime({ precision: 6 }),
  updatedAt: z.iso.datetime({ precision: 6 }),
});
