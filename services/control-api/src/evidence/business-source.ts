import type { PoolClient } from 'pg';
import {
  admittedReceiptSchemaVersion,
  decodeAdmittedReceipt,
  verifyAdmittedReceiptCose,
} from '@openpc/security-kernel';
import { sha256 } from '../configuration/digest.js';
import { EvidenceCustodyError, type EvidenceScope, type SourceReceipt } from './segment.js';

export interface BusinessSourceRow {
  evidenceId: string;
  receiptId: string;
  operationId: string;
  payload: Buffer;
  payloadDigest: Buffer;
  coseSign1: Buffer;
  publicKey: Buffer;
  trustDigest: Buffer;
  trustPreimage: Buffer;
  signerId: string;
  recordedAtNs: string;
  evidenceFormat: string;
}

export const businessSourceSelect = `select e.evidence_record_id::text as "evidenceId",a.receipt_id::text as "receiptId",
      a.operation_id::text as "operationId",a.receipt_cbor as payload,a.receipt_digest as "payloadDigest",
      a.cose_sign1 as "coseSign1",a.signer_id as "signerId",k.public_key_spki_der as "publicKey",
      k.trust_digest as "trustDigest",k.trust_preimage as "trustPreimage",a.recorded_at_ns::text as "recordedAtNs",
      e.evidence_format as "evidenceFormat"
     from control.evidence_record e join control.audit_occurrence a
      on a.participant_id=e.participant_id and a.privacy_domain_id=e.privacy_domain_id
       and a.receipt_id=e.receipt_id and a.receipt_digest=e.receipt_digest
     join control.business_signing_key k on k.participant_id=a.participant_id and k.privacy_domain_id=a.privacy_domain_id
      and k.signer_id=a.signer_id and k.trust_digest=a.signer_trust_snapshot_digest
     where e.participant_id=$1 and e.privacy_domain_id=$2
      and e.evidence_role='BUSINESS_TRANSITION_RECEIPT' and e.custody='CONTROL_STORE'
`;

/**
 * Read the authoritative committed occurrence and retained signing trust, not
 * an outbox delivery status or a caller's claim of success. Historical receipt
 * verification does not require today's key to remain authorized for new work.
 */
export async function readBusinessEvidenceSources(
  client: PoolClient,
  scope: EvidenceScope,
  limit = 8,
): Promise<SourceReceipt[]> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 8) throw new EvidenceCustodyError('INVALID');
  const result = await client.query<BusinessSourceRow>(
    `${businessSourceSelect}
      and not exists(select 1 from control.evidence_catalogue c where c.participant_id=e.participant_id
       and c.privacy_domain_id=e.privacy_domain_id and c.stream_id=$3 and c.record_id=e.evidence_record_id::text)
      and not exists(select 1 from control.evidence_projection_retirement r where r.participant_id=e.participant_id
       and r.privacy_domain_id=e.privacy_domain_id and r.stream_id=$3 and r.record_id=e.evidence_record_id::text
       and r.data_class='SEARCH_PROJECTION')
     order by a.recorded_at_ns,e.evidence_record_id limit $4`,
    [scope.participantId, scope.privacyDomainId, scope.streamId, limit],
  );
  return result.rows.map((row) => {
    const receipt = verifyBusinessSource(row, scope);
    return {
      recordId: row.evidenceId,
      evidenceClass: 'BUSINESS_TRANSITION',
      sourceFormat: row.evidenceFormat,
      occurredAt: businessOccurrenceTime(receipt.recordedAtNs),
      receiptDigest: sha256(row.coseSign1),
      receiptBase64: row.coseSign1.toString('base64'),
    };
  });
}

export function businessOccurrenceTime(ns: bigint) {
  return new Date(Number(ns / 1000000n))
    .toISOString()
    .replace(/\.\d{3}Z$/u, `.${String((ns / 1000n) % 1000000n).padStart(6, '0')}Z`);
}
export function verifyBusinessSource(
  row: BusinessSourceRow,
  scope: Pick<EvidenceScope, 'participantId' | 'privacyDomainId'>,
) {
  try {
    const receipt = decodeAdmittedReceipt(row.payload);
    const version = admittedReceiptSchemaVersion(receipt);
    if (
      receipt.receiptId !== row.receiptId ||
      receipt.operationId !== row.operationId ||
      receipt.participantId !== scope.participantId ||
      receipt.privacyDomainId !== scope.privacyDomainId ||
      receipt.recordedAtNs !== BigInt(row.recordedAtNs) ||
      receipt.signerId !== row.signerId ||
      !receipt.signerTrustSnapshotDigest.equals(row.trustDigest) ||
      sha256(row.trustPreimage) !== `sha256:${row.trustDigest.toString('hex')}` ||
      sha256(row.publicKey) !== row.signerId ||
      sha256(row.payload) !== `sha256:${row.payloadDigest.toString('hex')}` ||
      row.evidenceFormat !== `COSE_SIGN1_24001_${version}_338` ||
      !verifyAdmittedReceiptCose(row.publicKey, row.payload, row.coseSign1)
    )
      throw new EvidenceCustodyError('INTEGRITY');
    return receipt;
  } catch {
    throw new EvidenceCustodyError('INTEGRITY');
  }
}
