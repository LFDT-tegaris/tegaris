import { z } from 'zod';
import { participantUrnSchema, resourceUrnSchema } from '../configuration/resource-contracts.js';
import { protectedProofSource } from './protected-contracts.js';
import { digest } from './segment.js';
import {
  evidenceDeletionCursor,
  localEvidenceDeletionPlan,
  deleteLocalEvidence,
} from './deletion-contracts.js';

export const rawProofDeletionTarget = z.strictObject({
  objectRef: resourceUrnSchema,
  objectVersion: z.literal('1'),
  objectDigest: digest,
  payloadDigest: digest,
  ciphertextBytes: z.number().int().min(17).max(65552),
  beforeDigest: digest,
});
export const rawProofDeletionSelection = z
  .strictObject({
    version: z.literal('OPENPC_RAW_PROOF_DELETION_BATCH_V1'),
    participantId: participantUrnSchema,
    privacyDomainId: z.uuid(),
    retentionPolicyId: resourceUrnSchema,
    policyDigest: digest,
    targetDatabase: z.literal('openpc_control'),
    dataClass: z.literal('RAW_SOURCE_BODY'),
    deletionMode: z.literal('ROW_DELETE'),
    objectRef: resourceUrnSchema,
    objectVersion: z.literal('1'),
    objectDigest: digest,
    payloadDigest: digest,
    ciphertextBytes: z.number().int().min(17).max(65552),
    source: protectedProofSource,
    eligibleAfterMicros: z.string().regex(/^(?:0|[1-9][0-9]{0,24})$/u),
    sinkReceipts: z
      .array(
        z.strictObject({
          sinkId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
          checkpointDigest: digest,
          receiptDigest: digest,
          acknowledgedAtMicros: z.string().regex(/^(?:0|[1-9][0-9]{0,19})$/u),
        }),
      )
      .max(8),
    priorCursor: evidenceDeletionCursor.nullable(),
    targets: z.array(rawProofDeletionTarget).min(1).max(16),
    batchIndex: z.number().int().min(0).max(15),
  })
  .superRefine((value, context) => {
    const target = value.targets[value.batchIndex];
    if (
      !target ||
      (value.batchIndex === 0) !== (value.priorCursor === null) ||
      value.targets.some(
        (item, index) => index > 0 && item.objectRef <= value.targets[index - 1]!.objectRef,
      ) ||
      new Set(value.sinkReceipts.map((item) => item.sinkId)).size !== value.sinkReceipts.length ||
      (target &&
        Object.entries(target).some(
          ([key, field]) => key !== 'beforeDigest' && value[key as keyof typeof value] !== field,
        ))
    )
      context.addIssue({
        code: 'custom',
        message: 'Invalid exact raw-proof deletion continuation.',
      });
  });
export const deleteRawProofBatch = deleteLocalEvidence.extend({
  selection: rawProofDeletionSelection,
});
export const rawProofDeletionPlan = z.strictObject({
  objectRef: resourceUrnSchema,
  localPayload: z.enum(['RETAINED', 'DELETED']),
  eligible: z.boolean(),
  blockers: z.array(
    z.enum([...localEvidenceDeletionPlan.shape.blockers.element.options, 'STALE_SELECTION']),
  ),
  selection: rawProofDeletionSelection.nullable(),
  beforeDigest: digest.nullable(),
  continuationState: z.enum(['READY', 'BLOCKED', 'COMPLETE', 'ADVANCED']),
  nextDeletionJobId: resourceUrnSchema.nullable(),
});
