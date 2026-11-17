import { z } from 'zod';
import { digest, evidenceClass, evidenceScope, sequence } from './segment.js';
import { participantUrnSchema, resourceUrnSchema } from '../configuration/resource-contracts.js';

const timestamp = z.iso.datetime({ precision: 6 });
const action = z.strictObject({
  actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
});

/** Typed query-digest, range and redaction request. */
export const evidenceExportRange = z
  .strictObject({
    streamId: evidenceScope.shape.streamId,
    fromSequence: sequence,
    throughSequence: sequence,
    redactionProfileId: z.literal('pc.evidence.minimized-audit.v1'),
  })
  .refine(
    (value) =>
      BigInt(value.fromSequence) > 0n &&
      BigInt(value.throughSequence) >= BigInt(value.fromSequence) &&
      BigInt(value.throughSequence) - BigInt(value.fromSequence) < 128n,
  );

export const createEvidenceExportFromSelection = action.extend({
  participantId: participantUrnSchema,
  selection: evidenceExportRange,
});

// A request cannot submit a sink acknowledgement, prior progress, or an output.
// The legacy digest input resolves only a stored, exactly scoped selection.
export const createEvidenceExportRequest = action.extend({
  participantId: participantUrnSchema,
  requestDigest: digest,
  checkpoint: z.literal('0'),
  outputDigest: z.null(),
});
export const updateEvidenceExportRequest = action.extend({
  expectedRevision: sequence,
  replacementDigest: digest,
});
export const startEvidenceExportRequest = action.extend({
  targetRef: resourceUrnSchema,
  expectedRevision: sequence,
  inputDigest: digest,
});

/** Immutable selection of original receipt identities; never raw protected payload. */
export const selectedEvidenceRecord = z.strictObject({
  evidenceId: resourceUrnSchema,
  sourceRecordId: z.string().min(1).max(160),
  segmentId: z.uuid(),
  objectDigest: digest,
  sequence,
  evidenceClass,
  recordDigest: digest,
  occurredAt: timestamp,
});
export const evidenceExportSelection = z.strictObject({
  version: z.literal('OPENPC_EVIDENCE_EXPORT_SELECTION_V1'),
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  range: evidenceExportRange,
  records: z.array(selectedEvidenceRecord).min(1).max(128),
});
export type EvidenceExportSelection = z.infer<typeof evidenceExportSelection>;
export type EvidenceExportRange = z.infer<typeof evidenceExportRange>;

/** Discover an export range from a record the caller may already read. */
export const evidenceRecordExportRange = z.strictObject({
  evidenceId: resourceUrnSchema,
  recordDigest: digest,
  range: evidenceExportRange,
});

export const evidenceExportSelectionView = z.strictObject({
  requestDigest: digest,
  range: evidenceExportRange,
  records: z
    .array(
      selectedEvidenceRecord.omit({ sourceRecordId: true, segmentId: true, objectDigest: true }),
    )
    .min(1)
    .max(128),
});

export const evidenceExportView = z.strictObject({
  evidenceExportId: resourceUrnSchema,
  participantId: participantUrnSchema,
  requestDigest: digest,
  checkpoint: sequence,
  state: z.enum(['REQUESTED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'BACKLOGGED']),
  outputDigest: digest.nullable(),
  revision: sequence,
  createdAt: timestamp,
  updatedAt: timestamp,
});
