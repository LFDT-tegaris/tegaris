import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { participantUrnSchema, resourceUrnSchema } from '../configuration/resource-contracts.js';
import { evidenceExportRange, type EvidenceExportSelection } from './export-contracts.js';
import { digest, evidenceClass, sequence, EvidenceCustodyError } from './segment.js';

// An explicit allowlist: no original receipt bytes, keys, authentication claims,
// internal source identifiers or unfiltered event payloads can enter an export.
export const evidenceExportArtifact = z
  .strictObject({
    version: z.literal('OPENPC_EVIDENCE_REDACTED_EXPORT_V1'),
    evidenceExportId: resourceUrnSchema,
    participantId: participantUrnSchema,
    privacyDomainId: z.string().regex(/^urn:openpc:privacy-domain:/u),
    requestDigest: digest,
    range: evidenceExportRange,
    sinkId: z.string().min(1).max(160),
    assurance: z.enum(['LOCAL_FSYNC_READBACK', 'REMOTE_INTERFACE_VERIFIED']),
    providerQualification: z.literal('NOT_ESTABLISHED').optional(),
    records: z
      .array(
        z.strictObject({
          evidenceId: resourceUrnSchema,
          sequence,
          evidenceClass,
          recordDigest: digest,
          occurredAt: z.iso.datetime({ precision: 6 }),
          segmentDigest: digest,
          checkpointDigest: digest,
        }),
      )
      .min(1)
      .max(128),
  })
  .refine(
    (value) =>
      (value.assurance === 'REMOTE_INTERFACE_VERIFIED') ===
      (value.providerQualification === 'NOT_ESTABLISHED'),
  );

export const evidenceExportDownload = z.strictObject({
  outputDigest: digest,
  artifact: evidenceExportArtifact,
});

export function buildEvidenceExportArtifact(
  evidenceExportId: string,
  selection: EvidenceExportSelection,
  sinkId: string,
  checkpoints: ReadonlyMap<string, string>,
  assurance: 'LOCAL_FSYNC_READBACK' | 'REMOTE_INTERFACE_VERIFIED' = 'LOCAL_FSYNC_READBACK',
) {
  const artifact = evidenceExportArtifact.parse({
    version: 'OPENPC_EVIDENCE_REDACTED_EXPORT_V1',
    evidenceExportId: `urn:openpc:resource:${evidenceExportId}`,
    participantId: `urn:openpc:participant:${selection.participantId}`,
    privacyDomainId: `urn:openpc:privacy-domain:${selection.privacyDomainId}`,
    requestDigest: sha256(selection),
    range: selection.range,
    sinkId,
    assurance,
    ...(assurance === 'REMOTE_INTERFACE_VERIFIED'
      ? { providerQualification: 'NOT_ESTABLISHED' }
      : {}),
    records: selection.records.map((record) => {
      const checkpointDigest = checkpoints.get(record.segmentId);
      if (!checkpointDigest) throw new EvidenceCustodyError('UNAVAILABLE');
      return {
        evidenceId: record.evidenceId,
        sequence: record.sequence,
        evidenceClass: record.evidenceClass,
        recordDigest: record.recordDigest,
        occurredAt: record.occurredAt,
        segmentDigest: record.objectDigest,
        checkpointDigest,
      };
    }),
  });
  const bytes = Buffer.from(canonicalJson(artifact));
  return { artifact, bytes, outputDigest: sha256(bytes) };
}
