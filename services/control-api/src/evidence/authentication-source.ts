import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { digest, EvidenceCustodyError, type EvidenceScope, type SourceReceipt } from './segment.js';

const receiptFields = {
  version: z.literal('OPENPC_AUTHENTICATION_OCCURRENCE_V1'),
  occurrenceId: z.uuidv7(),
  participantId: z.uuid(),
  privacyDomainId: z.uuid().nullable(),
  principalId: z.uuid(),
  operationId: z.uuidv7(),
  sourceId: z.uuidv7(),
  credentialDigest: digest,
  proofDigest: digest,
  occurredAt: z.iso.datetime({ precision: 6 }),
  authorityEffect: z.literal('NONE'),
  integrity: z.literal('CONTROL_DATABASE_IMMUTABLE'),
};
export const authenticationReceiptSchema = z.union([
  z.strictObject({
    ...receiptFields,
    method: z.enum(['OIDC_CODE_PKCE_S256', 'WEBAUTHN_ASSERTION']),
    contextMode: z.enum(['PLATFORM', 'PARTICIPANT']),
    sessionBindingDigest: digest,
  }),
  z.strictObject({
    ...receiptFields,
    method: z.literal('TLS13_MTLS'),
    contextMode: z.literal('WORKLOAD'),
    transportBindingDigest: digest,
  }),
]);

/** Identity's immutable commit is the source. Its integrity classification is
 * retained exactly; database custody is not presented as a provider signature.
 */
export async function readAuthenticationEvidenceSources(
  client: PoolClient,
  scope: EvidenceScope,
): Promise<SourceReceipt[]> {
  const rows = await client.query<{ id: string; receipt: Buffer; receiptDigest: Buffer }>(
    `select occurrence_id::text id,receipt,receipt_digest as "receiptDigest"
     from control.authentication_occurrence a where a.participant_id=$1 and a.privacy_domain_id=$2
      and not exists(select 1 from control.evidence_catalogue c where c.participant_id=a.participant_id
       and c.privacy_domain_id=a.privacy_domain_id and c.stream_id=$3 and c.record_id=a.occurrence_id::text)
      and not exists(select 1 from control.evidence_projection_retirement r where r.participant_id=a.participant_id
       and r.privacy_domain_id=a.privacy_domain_id and r.stream_id=$3 and r.record_id=a.occurrence_id::text and r.data_class='SEARCH_PROJECTION')
     order by occurred_at,occurrence_id limit 8`,
    [scope.participantId, scope.privacyDomainId, scope.streamId],
  );
  return rows.rows.map((row) => {
    const receipt = verifyAuthenticationSource(row, scope);
    return {
      recordId: row.id,
      evidenceClass: 'AUTHENTICATION',
      sourceFormat: receipt.version,
      occurredAt: receipt.occurredAt,
      receiptDigest: sha256(row.receipt),
      receiptBase64: row.receipt.toString('base64'),
    };
  });
}

export interface AuthenticationSourceRow {
  id: string;
  receipt: Buffer;
  receiptDigest: Buffer;
}
export function verifyAuthenticationSource(
  row: AuthenticationSourceRow,
  scope: Pick<EvidenceScope, 'participantId' | 'privacyDomainId'>,
) {
  try {
    const receipt = authenticationReceiptSchema.parse(JSON.parse(row.receipt.toString('utf8')));
    const receiptDigest = sha256(row.receipt);
    if (
      receipt.occurrenceId !== row.id ||
      receipt.participantId !== scope.participantId ||
      receipt.privacyDomainId !== scope.privacyDomainId ||
      receiptDigest !== `sha256:${row.receiptDigest.toString('hex')}` ||
      !Buffer.from(canonicalJson(receipt)).equals(row.receipt)
    )
      throw new EvidenceCustodyError('INTEGRITY');
    return receipt;
  } catch {
    throw new EvidenceCustodyError('INTEGRITY');
  }
}
