import type { PoolClient } from 'pg';
import {
  decodeAdmittedReceipt,
  verifyAdmittedReceiptCose,
  type BusinessTransitionReceipt,
} from '@openpc/security-kernel';
import {
  validateBusinessProviderObservation,
  type BusinessProviderObservation,
  type BusinessProviderRequest,
} from '../domain/business-signing-provider.js';
import { SigningRotationError } from '../domain/signing-rotation.js';
import { persistBusinessReceipt } from './business-receipt-store.js';
import type { SigningRotationPartition } from './signing-rotation-store.js';

export interface ObservedSigningAttestation {
  receipt: BusinessTransitionReceipt;
  payload: Buffer;
  coseSign1: Buffer;
  beforeStatePreimage: Buffer;
  afterStatePreimage: Buffer;
  authoritySnapshot: Buffer;
  evidenceRecordId: string;
  eventPayloads: ReadonlyMap<string, Buffer>;
}

/** Read the one retained signature against immutable admitted public trust, never provider-supplied trust. */
export async function observedSigningAttestation(
  client: PoolClient,
  scope: SigningRotationPartition,
  operationId: string,
  revision: string,
): Promise<ObservedSigningAttestation> {
  const found = await client.query<{
    payload: Buffer;
    beforeStatePreimage: Buffer;
    afterStatePreimage: Buffer;
    authoritySnapshot: Buffer;
    evidenceRecordId: string;
    eventId: string | null;
    eventPayload: Buffer | null;
    request: BusinessProviderRequest;
    observation: BusinessProviderObservation;
    publicKey: Buffer;
  }>(
    `select a.receipt_cbor as payload,a.before_state_preimage as "beforeStatePreimage",a.after_state_preimage as "afterStatePreimage",
    a.authority_snapshot as "authoritySnapshot",a.evidence_record_id::text as "evidenceRecordId",a.event_id::text as "eventId",a.event_payload as "eventPayload",
    p.request,p.observation,k.public_key_spki_der as "publicKey"
    from control.signing_rotation_attestation a join control.signing_provider_attempt p using(attempt_id)
    join control.business_signing_key k on k.participant_id=a.participant_id and k.privacy_domain_id=a.privacy_domain_id
     and k.signer_id=a.signer_id and k.trust_digest=a.signer_trust_digest
    where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3 and a.from_revision=$4
     and p.state='OBSERVED' and p.request->>'method'='SIGN_RECEIPT'`,
    [scope.participantId, scope.privacyDomainId, operationId, revision],
  );
  const row = found.rows[0];
  if (found.rowCount !== 1 || !row) throw new SigningRotationError('AMBIGUOUS');
  validateBusinessProviderObservation(row.request, row.observation);
  const receipt = decodeAdmittedReceipt(row.payload);
  const coseSign1 = Buffer.from(row.observation.resultHex ?? '', 'hex');
  if (
    row.observation.outcome !== 'SUCCEEDED' ||
    row.observation.descriptor?.publicKeySpkiHex !== row.publicKey.toString('hex') ||
    !verifyAdmittedReceiptCose(row.publicKey, row.payload, coseSign1)
  )
    throw new SigningRotationError('PROVIDER_REJECTED');
  return {
    ...row,
    receipt,
    coseSign1,
    eventPayloads:
      row.eventId && row.eventPayload ? new Map([[row.eventId, row.eventPayload]]) : new Map(),
  };
}

/** The state/history transition, sequence, occurrence, custody and operation all share this commit. */
export async function persistSigningAttestation(
  client: PoolClient,
  attestation: ObservedSigningAttestation,
): Promise<void> {
  const receipt = attestation.receipt;
  if (receipt.outboxEvents.length === 1) {
    const event = receipt.outboxEvents[0]!;
    const head = await client.query<{ sequence: string }>(
      `insert into control.business_outbox_head
      (participant_id,privacy_domain_id,sequence_namespace,aggregate_type,aggregate_id,last_sequence)
      values($1,$2,'CONTROL_BUSINESS_TRANSITION_V1','signing-key-rotation',$3,1)
      on conflict(participant_id,privacy_domain_id,sequence_namespace,aggregate_type,aggregate_id)
      do update set last_sequence=control.business_outbox_head.last_sequence+1,updated_at=clock_timestamp()
      returning last_sequence::text as sequence`,
      [receipt.participantId, receipt.privacyDomainId, receipt.aggregateId],
    );
    if (head.rowCount !== 1 || BigInt(head.rows[0]!.sequence) !== event.aggregateSequence)
      throw new SigningRotationError('CONFLICT');
  }
  await persistBusinessReceipt(client, attestation);
}
