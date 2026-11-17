import type { PoolClient } from 'pg';
import { z } from 'zod';
import { encodeEvidenceExportCompletedData } from '@openpc/security-kernel';
import { sha256 } from '../configuration/digest.js';
import {
  evidenceScope,
  sequence,
  digest,
  EvidenceCustodyError,
  type EvidenceScope,
} from './segment.js';

const completionSource = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  streamId: evidenceScope.shape.streamId,
  evidenceExportId: z.uuidv7(),
  startOperationId: z.uuidv7(),
  causationId: z.uuidv7(),
  requestDigest: digest,
  checkpoint: sequence,
  outputDigest: digest,
  recordCount: sequence,
});
export type EvidenceExportCompletionSource = z.infer<typeof completionSource>;

/** Actual immutable output and original governed start only. This is source
 * provenance, not current workload/signing authorization or outbox admission.
 * The caller retains its scoped transaction and lifecycle fence through commit. */
export async function readEvidenceExportCompletionSource(
  client: Pick<PoolClient, 'query'>,
  scope: EvidenceScope,
  evidenceExportId: string,
) {
  const selected = await client.query<{ source: unknown }>(
    'select openpc.evidence_export_completion_source($1::uuid) source',
    [evidenceExportId],
  );
  const parsed = completionSource.safeParse(selected.rows[0]?.source);
  if (
    selected.rowCount !== 1 ||
    !parsed.success ||
    parsed.data.evidenceExportId !== evidenceExportId ||
    parsed.data.participantId !== scope.participantId ||
    parsed.data.privacyDomainId !== scope.privacyDomainId ||
    parsed.data.streamId !== scope.streamId
  )
    throw new EvidenceCustodyError('INTEGRITY');
  const source = parsed.data;
  const data = encodeEvidenceExportCompletedData({
    evidenceExportId: source.evidenceExportId,
    checkpoint: source.checkpoint,
    outputDigest: source.outputDigest,
    recordCount: source.recordCount,
  });
  return { source, data, dataDigest: sha256(data) };
}
