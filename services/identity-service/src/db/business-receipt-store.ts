import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  encodeReceiptStructure,
  encodeReceiptStructureV2,
  type BusinessTransitionReceipt,
} from '@openpc/security-kernel';
import { localOperationId } from '../domain/local-operation-id.js';
import { validateSigningRotationReceipt } from '../domain/signing-rotation-receipt.js';

/** Shared immutable receipt/custody/outbox storage, inside the owning business transaction. */
export async function persistBusinessReceipt(
  client: PoolClient,
  input: {
    receipt: BusinessTransitionReceipt;
    payload: Buffer;
    coseSign1: Buffer;
    beforeStatePreimage: Buffer;
    afterStatePreimage: Buffer;
    authoritySnapshot: Buffer;
    evidenceRecordId?: string;
    eventPayloads: ReadonlyMap<string, Buffer>;
  },
): Promise<void> {
  const r = input.receipt;
  const lifecycle = r.aggregateType === 'signing-key-rotation';
  if (lifecycle)
    validateSigningRotationReceipt(r, input.beforeStatePreimage, input.afterStatePreimage);
  if (
    !(lifecycle ? encodeReceiptStructureV2(r) : encodeReceiptStructure(r)).equals(input.payload) ||
    input.eventPayloads.size !== r.outboxEvents.length
  )
    throw new Error('Receipt storage binding mismatch');
  for (const event of r.outboxEvents) {
    const payload = input.eventPayloads.get(event.eventId);
    if (
      payload === undefined ||
      !createHash('sha256').update(payload).digest().equals(event.payloadDigest)
    )
      throw new Error('Event storage binding mismatch');
  }
  const receiptDigest = createHash('sha256').update(input.payload).digest();
  const record = {
    receipt_id: r.receiptId,
    participant_id: r.participantId,
    privacy_domain_id: r.privacyDomainId,
    operation_id: r.operationId,
    idempotency_record_id: r.idempotencyRecordId,
    schema_definition_digest: r.schemaDefinitionDigest,
    profile_id: r.transitionProfileId,
    profile_version: r.transitionProfileVersion,
    profile_digest: r.transitionProfileDigest,
    environment_id: r.environmentId,
    action_intent_id: r.actionIntentId,
    catalog_operation_id: r.catalogOperationId,
    aggregate_type: r.aggregateType,
    aggregate_id: r.aggregateId,
    actor_key_digest: r.actorKeyDigest,
    pre_commit_authority_digest: r.preCommitAuthorityDigest,
    action_intent_digest: r.actionIntentDigest,
    candidate_digest: r.candidateDigest,
    request_digest: r.requestDigest,
    before_existence: r.before.existence,
    before_revision: r.before.revision.toString(),
    before_state_digest: r.before.stateDigest,
    before_state_preimage: input.beforeStatePreimage,
    after_existence: r.after.existence,
    after_revision: r.after.revision.toString(),
    after_state_digest: r.after.stateDigest,
    after_state_preimage: input.afterStatePreimage,
    authority_snapshot: input.authoritySnapshot,
    transition_kind: r.transitionKind,
    recorded_at_ns: r.recordedAtNs.toString(),
    signer_id: r.signerId,
    signer_trust_snapshot_digest: r.signerTrustSnapshotDigest,
    receipt_cbor: input.payload,
    receipt_digest: receiptDigest,
    cose_sign1: input.coseSign1,
  };
  await client.query(
    `insert into control.audit_occurrence(${Object.keys(record).join(',')}) values(${Object.keys(
      record,
    )
      .map((_, i) => `$${i + 1}`)
      .join(',')})`,
    Object.values(record),
  );
  await client.query(
    `insert into control.evidence_record(evidence_record_id,participant_id,privacy_domain_id,receipt_id,receipt_digest,
    evidence_role,evidence_format,custody,sink_quorum,recorded_at_ns)
    values($1,$2,$3,$4,$5,'BUSINESS_TRANSITION_RECEIPT',$7,'CONTROL_STORE',0,$6)`,
    [
      input.evidenceRecordId ?? localOperationId(),
      r.participantId,
      r.privacyDomainId,
      r.receiptId,
      receiptDigest,
      r.recordedAtNs.toString(),
      lifecycle ? 'COSE_SIGN1_24001_2_338' : 'COSE_SIGN1_24001_1_338',
    ],
  );
  for (const event of r.outboxEvents) {
    const payload = input.eventPayloads.get(event.eventId);
    if (
      payload === undefined ||
      !createHash('sha256').update(payload).digest().equals(event.payloadDigest)
    )
      throw new Error('Event storage binding mismatch');
    const seconds = event.occurredAtNs / 1000000000n;
    const micros = (event.occurredAtNs % 1000000000n) / 1000n;
    const occurredAt =
      new Date(Number(seconds) * 1000).toISOString().slice(0, 19) +
      '.' +
      micros.toString().padStart(6, '0') +
      'Z';
    await client.query(
      `insert into control.outbox_event(participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
      business_sequence,payload_cbor,payload_digest,cose_sign1,occurred_at,proof_kind,sequence_namespace,receipt_id,data_schema_uri,source,subject,correlation_id,causation_id,authority_generation)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,null,$10,'BUSINESS_RECEIPT_REFERENCE','CONTROL_BUSINESS_TRANSITION_V1',$11,$12,$13,$14,$15,$16,$17)`,
      [
        r.participantId,
        r.privacyDomainId,
        event.eventId,
        event.eventType,
        r.aggregateType,
        r.aggregateId,
        event.aggregateSequence.toString(),
        payload,
        event.payloadDigest,
        occurredAt,
        r.receiptId,
        event.dataSchemaUri,
        event.source,
        event.subject,
        event.correlationId,
        event.causationId ?? null,
        event.authorityGeneration ?? null,
      ],
    );
  }
}
