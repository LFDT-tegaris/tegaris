import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  admittedReceiptSchemaVersion,
  businessSigningSchemaVersion,
  businessSigningTrustDigest,
  encodeAdmittedReceipt,
  BusinessSigningTrustError,
  type BusinessSigningTrust,
  type BusinessTransitionReceipt,
} from '@openpc/security-kernel';
import { uuidBytes } from '../../../../packages/security-kernel/src/business-transition/payload.js';

/** Exclude the derived receipt ID itself, while binding every other exact payload field. */
export function receiptSigningAttemptId(receipt: BusinessTransitionReceipt): string {
  const context = encodeAdmittedReceipt({ ...receipt, receiptId: receipt.operationId });
  const digest = createHash('sha256')
    .update('pc.control.receipt-signing-attempt.v1\0')
    .update(context)
    .digest();
  const bytes = uuidBytes(receipt.operationId);
  digest.copy(bytes, 6, 0, 10);
  bytes[6] = (bytes[6]! & 15) | 0x70;
  bytes[8] = (bytes[8]! & 63) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
/** Called before provider invocation, with the caller's authority, aggregate and signing locks still held. */
export async function reserveReceiptSigningAttempt(
  client: PoolClient,
  receipt: BusinessTransitionReceipt,
  trust: BusinessSigningTrust,
  reservationKind: 'ORDINARY_ATOMIC' | 'LIFECYCLE_DURABLE',
): Promise<{ selectionVersion: string; admissionVersion: string; fenceGeneration: string }> {
  const payload = encodeAdmittedReceipt(receipt);
  const version = admittedReceiptSchemaVersion(receipt);
  if (
    receipt.receiptId !== receiptSigningAttemptId(receipt) ||
    businessSigningSchemaVersion(trust) !== version ||
    receipt.signerId !== trust.signerId ||
    !receipt.signerTrustSnapshotDigest.equals(businessSigningTrustDigest(trust))
  )
    throw new Error('Signing attempt receipt/trust binding mismatch');
  const selected = await client.query<{
    selectionVersion: string;
    admissionVersion: string;
    fenceGeneration: string;
    nowNs: string;
  }>(
    `select row_version::text as "selectionVersion",admission_version::text as "admissionVersion",fence_generation::text as "fenceGeneration",
   (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text as "nowNs"
   from control.business_signing_selection where participant_id=$1 and privacy_domain_id=$2 and environment_id=$3
   and profile_digest=$4 and signer_id=$5 and fenced_operation_id is null for share`,
    [
      receipt.participantId,
      receipt.privacyDomainId,
      receipt.environmentId,
      receipt.transitionProfileDigest,
      receipt.signerId,
    ],
  );
  if (selected.rowCount !== 1 || selected.rows[0] === undefined)
    throw new BusinessSigningTrustError();
  // Run after the selection lock has been acquired, with a fresh statement snapshot.
  const admitted = await client.query<{ open: boolean }>(
    'select openpc.signing_admission_open($1,$2,$3,$4) as open',
    [receipt.participantId, receipt.privacyDomainId, receipt.signerId, receipt.operationId],
  );
  if (admitted.rows[0]?.open !== true) throw new BusinessSigningTrustError();
  const row = selected.rows[0];
  await client.query(
    `insert into control.receipt_signing_attempt(attempt_id,participant_id,privacy_domain_id,operation_id,reservation_kind,
  signer_id,signer_trust_digest,key_epoch,selection_version,admission_version,fence_generation,profile_digest,schema_version,payload_cbor,payload_digest,reserved_at_ns)
  values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
    [
      receipt.receiptId,
      receipt.participantId,
      receipt.privacyDomainId,
      receipt.operationId,
      reservationKind,
      receipt.signerId,
      receipt.signerTrustSnapshotDigest,
      trust.keyEpoch.toString(),
      row.selectionVersion,
      row.admissionVersion,
      row.fenceGeneration,
      receipt.transitionProfileDigest,
      version,
      payload,
      createHash('sha256').update(payload).digest(),
      row.nowNs,
    ],
  );
  return row;
}
