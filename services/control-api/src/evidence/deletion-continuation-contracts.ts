import { runtimeArtifactRetirementSelection } from './runtime-artifact-deletion-contracts.js';
import { z } from 'zod';
import { resourceUrnSchema } from '../configuration/resource-contracts.js';
import {
  deleteLocalEvidence,
  evidenceDeletionView,
  localEvidenceDeletionPlan,
  localEvidenceDeletionSelection,
  evidenceDeletionCursor,
  evidenceDeletionSourceCardinality,
} from './deletion-contracts.js';
import { digest } from './segment.js';
import { projectionDeletionSelection } from './projection-deletion-contracts.js';
import { rawProofDeletionSelection } from './raw-deletion-contracts.js';

// A signed batch commits one object and the immutable ordered remaining target
// set. The receipt locator is resolved against durable, scoped signed state;
// possessing it never supplies authority to execute the next batch.
export { evidenceDeletionCursor } from './deletion-contracts.js';
export const evidenceDeletionTarget = z.strictObject({
  evidenceId: localEvidenceDeletionSelection.shape.evidenceId,
  segmentId: localEvidenceDeletionSelection.shape.segmentId,
  firstSequence: localEvidenceDeletionSelection.shape.firstSequence,
  throughSequence: localEvidenceDeletionSelection.shape.throughSequence,
  objectDigest: localEvidenceDeletionSelection.shape.objectDigest,
  ciphertextBytes: localEvidenceDeletionSelection.shape.ciphertextBytes,
  recordCount: localEvidenceDeletionSelection.shape.recordCount,
  beforeDigest: digest,
});
export const evidenceDeletionBatchSelection = z
  .strictObject({
    ...localEvidenceDeletionSelection.shape,
    version: z.literal('OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1'),
    priorCursor: evidenceDeletionCursor.nullable(),
    targets: z.array(evidenceDeletionTarget).min(1).max(16),
    batchIndex: z.number().int().min(0).max(15),
  })
  .superRefine((value, context) => {
    const target = value.targets[value.batchIndex];
    if (
      !target ||
      !evidenceDeletionSourceCardinality(value) ||
      new Set(value.sinkReceipts.map((receipt) => receipt.sinkId)).size !==
        value.sinkReceipts.length ||
      (value.batchIndex === 0) !== (value.priorCursor === null) ||
      value.targets.some(
        (item, index) => index > 0 && item.segmentId <= value.targets[index - 1]!.segmentId,
      ) ||
      new Set(value.targets.map((item) => item.evidenceId)).size !== value.targets.length ||
      value.targets.some(
        (item) =>
          BigInt(item.firstSequence) < 1n ||
          BigInt(item.throughSequence) - BigInt(item.firstSequence) + 1n !==
            BigInt(item.recordCount),
      ) ||
      (target &&
        Object.entries(target).some(
          ([key, field]) => key !== 'beforeDigest' && value[key as keyof typeof value] !== field,
        ))
    )
      context.addIssue({ code: 'custom', message: 'Invalid ordered deletion continuation.' });
  });
export const deleteLocalEvidenceBatch = deleteLocalEvidence.extend({
  selection: evidenceDeletionBatchSelection,
});
export const evidenceDeletionBatchPlan = localEvidenceDeletionPlan.extend({
  selection: evidenceDeletionBatchSelection.nullable(),
  blockers: z.array(
    z.enum([...localEvidenceDeletionPlan.shape.blockers.element.options, 'STALE_SELECTION']),
  ),
  continuationState: z.enum(['READY', 'BLOCKED', 'COMPLETE', 'ADVANCED']),
  nextDeletionJobId: resourceUrnSchema.nullable(),
});

export const evidenceDeletionResultView = evidenceDeletionView.extend({
  selection: z.union([
    localEvidenceDeletionSelection,
    evidenceDeletionBatchSelection,
    rawProofDeletionSelection,
    projectionDeletionSelection,
    runtimeArtifactRetirementSelection,
  ]),
});
