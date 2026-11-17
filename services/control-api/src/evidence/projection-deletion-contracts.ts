import { z } from 'zod';
import { participantUrnSchema, resourceUrnSchema } from '../configuration/resource-contracts.js';
import { digest, evidenceScope, sequence } from './segment.js';
import {
  deleteLocalEvidence,
  evidenceDeletionCursor,
  localEvidenceDeletionPlan,
} from './deletion-contracts.js';

export const projectionDataClass = z.enum(['NORMALIZED_JSON_PROJECTION', 'SEARCH_PROJECTION']);
export const rpcRetirementWitness = z.strictObject({
  identityDigest: digest,
  terminalEvidenceId: resourceUrnSchema,
  terminalRecordId: z.string().min(1).max(320),
  terminalSequence: sequence,
  terminalSourceDigest: digest,
  terminalProjectionDigest: digest,
  terminalOccurredAtNs: sequence,
  terminalPhase: z.enum(['INTERRUPTED', 'COMMITTED', 'RELEASED', 'SOURCE_READ_RELEASED']),
  terminalEffect: z.enum(['DENY_TERMINAL', 'AUTHORIZED_EMPTY', 'WITHHOLD_STALE']).nullable(),
  terminalDecisionDigest: digest.nullable(),
  sourceScopeDigest: digest.nullable(),
  authorityBindingDigest: digest.nullable(),
});
export const projectionDeletionTarget = z.strictObject({
  evidenceId: resourceUrnSchema,
  recordId: z.string().min(1).max(320),
  projectionDigest: digest,
  projectionBytes: z.number().int().min(1).max(16384),
  sourceReceiptDigest: digest,
  beforeDigest: digest,
});
export const projectionDeletionSelection = z
  .strictObject({
    version: z.literal('OPENPC_PROJECTION_DELETION_BATCH_V1'),
    participantId: participantUrnSchema,
    privacyDomainId: z.uuid(),
    retentionPolicyId: resourceUrnSchema,
    policyDigest: digest,
    targetDatabase: z.literal('openpc_control'),
    dataClass: projectionDataClass,
    deletionMode: z.literal('PROJECTION_DELETE'),
    sourceKind: z.enum([
      'AUTHENTICATION_CATALOGUE',
      'RETENTION_POLICY_CATALOGUE',
      'RPC_RETIRED_CATALOGUE',
      'RPC_PRE_ADMISSION_DENIAL',
      'RPC_CLOSED_TRANSITION',
      'FACT_PROVENANCE',
      'DEPLOYMENT_PROVENANCE',
    ]),
    // Additive: historical denial/search receipts preserve their exact bytes.
    rpcClosure: rpcRetirementWitness
      .extend({
        archive: z.strictObject({
          segmentId: z.uuid(),
          objectDigest: digest,
          sinkReceipts: localEvidenceDeletionPlan.shape.selection.unwrap().shape.sinkReceipts,
        }),
      })
      .optional(),
    streamId: evidenceScope.shape.streamId,
    segmentId: z.uuid(),
    sequence,
    evidenceId: resourceUrnSchema,
    recordId: projectionDeletionTarget.shape.recordId,
    projectionDigest: digest,
    projectionBytes: projectionDeletionTarget.shape.projectionBytes,
    sourceReceiptDigest: digest,
    archiveObjectDigest: digest,
    eligibleAfterMicros: z.string().regex(/^(?:0|[1-9][0-9]{0,24})$/u),
    sinkReceipts: localEvidenceDeletionPlan.shape.selection.unwrap().shape.sinkReceipts,
    priorCursor: evidenceDeletionCursor.nullable(),
    targets: z.array(projectionDeletionTarget).min(1).max(16),
    batchIndex: z.number().int().min(0).max(15),
  })
  .superRefine((value, context) => {
    const target = value.targets[value.batchIndex];
    if (
      !target ||
      (value.dataClass === 'SEARCH_PROJECTION') !==
        [
          'AUTHENTICATION_CATALOGUE',
          'RETENTION_POLICY_CATALOGUE',
          'RPC_RETIRED_CATALOGUE',
        ].includes(value.sourceKind) ||
      (value.sourceKind === 'RPC_CLOSED_TRANSITION') !== (value.rpcClosure !== undefined) ||
      (value.rpcClosure !== undefined &&
        (BigInt(value.rpcClosure.terminalSequence) < BigInt(value.sequence) ||
          (value.rpcClosure.terminalPhase === 'COMMITTED') !==
            (value.rpcClosure.terminalEffect !== null) ||
          ['COMMITTED', 'RELEASED'].includes(value.rpcClosure.terminalPhase) !==
            (value.rpcClosure.terminalDecisionDigest !== null) ||
          (value.rpcClosure.terminalPhase === 'SOURCE_READ_RELEASED') !==
            (value.rpcClosure.sourceScopeDigest !== null) ||
          (value.rpcClosure.terminalPhase === 'SOURCE_READ_RELEASED') !==
            (value.rpcClosure.authorityBindingDigest !== null) ||
          new Set(value.rpcClosure.archive.sinkReceipts.map((item) => item.sinkId)).size !==
            value.rpcClosure.archive.sinkReceipts.length)) ||
      (value.batchIndex === 0) !== (value.priorCursor === null) ||
      value.targets.some(
        (item, index) => index > 0 && item.recordId <= value.targets[index - 1]!.recordId,
      ) ||
      new Set(value.targets.map((item) => item.evidenceId)).size !== value.targets.length ||
      new Set(value.sinkReceipts.map((item) => item.sinkId)).size !== value.sinkReceipts.length ||
      (target &&
        Object.entries(target).some(
          ([key, field]) => key !== 'beforeDigest' && value[key as keyof typeof value] !== field,
        ))
    )
      context.addIssue({
        code: 'custom',
        message: 'Invalid class-specific projection continuation.',
      });
  });
export const deleteProjectionBatch = deleteLocalEvidence.extend({
  selection: projectionDeletionSelection,
});
export const projectionDeletionPlan = z
  .strictObject({
    evidenceId: resourceUrnSchema,
    dataClass: projectionDataClass,
    projectionState: z.enum(['RETAINED', 'RETIRED', 'UNAVAILABLE']),
    eligible: z.boolean(),
    blockers: z.array(
      z.enum([
        ...localEvidenceDeletionPlan.shape.blockers.element.options,
        'STALE_SELECTION',
        'UNRESOLVED_TRANSITION',
        'UNRESOLVED_OPERATION',
        'WRITE_AMBIGUITY',
        'REORG_FENCED',
      ]),
    ),
    selection: projectionDeletionSelection.nullable(),
    beforeDigest: digest.nullable(),
    continuationState: z.enum(['READY', 'BLOCKED', 'COMPLETE', 'ADVANCED']),
    nextDeletionJobId: resourceUrnSchema.nullable(),
  })
  .superRefine((value, context) => {
    if (
      value.selection &&
      (value.selection.dataClass !== value.dataClass ||
        value.selection.evidenceId !== value.evidenceId)
    )
      context.addIssue({
        code: 'custom',
        message: 'Projection plan does not match its selected class and record.',
      });
  });
