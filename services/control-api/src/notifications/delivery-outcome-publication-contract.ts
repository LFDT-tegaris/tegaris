import { encodeCanonicalCbor } from '@openpc/security-kernel';
import type { CborValue } from '../../../../packages/security-kernel/src/canonical-cbor.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  encodeNotificationDeliveryOutcomeTransition,
  proposeNotificationDeliveryOutcome,
  NotificationDeliveryOutcomeError,
} from './delivery-outcome-contract.js';
import { notificationOutcomeFinalEffects } from './delivery-outcome-state.js';

export const notificationCompletionProof = 'NOTIFICATION_DELIVERY_COMPLETION_REFERENCE';
export const notificationCompletionNamespace = 'NOTIFICATION_DELIVERY_COMPLETED_V1';
export const notificationOutcomeEvidenceFormat = 'COSE_SIGN1_24029_1_366';
/** Closed reference recipe, NOT another receipt or producer admission. The event
 * id is the signed receipt id; correlation is the outcome operation; causation
 * is the original delivery-request event. Sequence one is terminal per occurrence.
 * DATA uses canonical CBOR {0: occurrence URN,1: state,2: count U64,3: gateway COSE
 * digest H32}. Its digest is derived only after full native result verification.
 * Canonical shared outbox registration must admit this exact reference family. */
export function notificationOutcomePublication(value: unknown) {
  const encoded = encodeNotificationDeliveryOutcomeTransition(value);
  const t = encoded.transition,
    r = t.receipt;
  const proposal = proposeNotificationDeliveryOutcome(t.input);
  const effects = notificationOutcomeFinalEffects(t);
  let event = null;
  if (effects.completionData) {
    const data = effects.completionData;
    const payload = encodeCanonicalCbor(
      new Map<number, CborValue>([
        [0, data.notificationOccurrenceId],
        [1, data.state],
        [2, BigInt(data.attemptCount)],
        [3, Buffer.from(data.deliveryReceiptDigest.slice(7), 'hex')],
      ]),
    );
    const envelope = immutableJsonCopy({
      specversion: '1.0',
      id: r.receiptId,
      source: 'urn:openpc:service:LS-NOTIFICATION',
      type: 'io.openpc.notification.delivery.completed.v1',
      subject: data.notificationOccurrenceId,
      time: new Date(r.recordedAtMs).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z'),
      datacontenttype: 'application/json',
      dataschema:
        'https://schemas.openpc.local/event-payloads.schema.json#/$defs/NotificationDeliveryCompleted',
      participantid: `urn:openpc:participant:${r.participantId}`,
      privacydomainid: `urn:openpc:privacy-domain:${r.privacyDomainId}`,
      correlationid: r.operationId,
      causationid: proposal.original.source.eventId,
      sequence: '1',
      datadigest: sha256(payload),
      data,
    });
    event = {
      envelope,
      proofKind: notificationCompletionProof,
      sequenceNamespace: notificationCompletionNamespace,
      get payloadCbor() {
        return Buffer.from(payload);
      },
      get payloadDigest() {
        return Buffer.from(sha256(payload).slice(7), 'hex');
      },
    };
  }
  return Object.freeze({
    encoded,
    proposal,
    event,
    failureWork: effects.failureWork,
  });
}
export type NotificationOutcomePublication = ReturnType<typeof notificationOutcomePublication>;
export interface NotificationCompletionRow {
  participant_id: string;
  privacy_domain_id: string;
  event_id: string;
  event_type: string;
  aggregate_type: string;
  aggregate_id: string;
  aggregate_sequence: string | null;
  business_sequence: string | null;
  proof_kind: string;
  sequence_namespace: string;
  receipt_id: string | null;
  data_schema_uri: string | null;
  source: string | null;
  subject: string | null;
  correlation_id: string | null;
  causation_id: string | null;
  authority_generation: Buffer | null;
  payload_cbor: Buffer;
  payload_digest: Buffer;
  cose_sign1: Buffer | null;
  webauthn_assertion_binding_digest: Buffer | null;
  occurred_at_ms: string;
}
/** Exact outbox row, including excluded authorization/legacy fields. A stored row
 * is not evidence of the independently required Control Work consumer effect. */
export function assertNotificationCompletionRow(
  value: NotificationOutcomePublication,
  row: NotificationCompletionRow | null,
) {
  const e = value.event,
    r = value.encoded.transition.receipt;
  if (!e) {
    if (row !== null) throw new NotificationDeliveryOutcomeError();
    return;
  }
  if (!row) throw new NotificationDeliveryOutcomeError();
  const { payload_cbor, payload_digest, ...metadata } = row;
  const expected = {
    participant_id: r.participantId,
    privacy_domain_id: r.privacyDomainId,
    event_id: e.envelope.id,
    event_type: e.envelope.type,
    aggregate_type: 'notification-occurrence',
    aggregate_id: r.notificationOccurrenceId,
    aggregate_sequence: null,
    business_sequence: '1',
    proof_kind: e.proofKind,
    sequence_namespace: e.sequenceNamespace,
    receipt_id: null,
    data_schema_uri: e.envelope.dataschema,
    source: e.envelope.source,
    subject: e.envelope.subject,
    correlation_id: r.operationId,
    causation_id: e.envelope.causationid,
    authority_generation: null,
    cose_sign1: null,
    webauthn_assertion_binding_digest: null,
    occurred_at_ms: String(r.recordedAtMs),
  };
  if (
    canonicalJson(metadata) !== canonicalJson(expected) ||
    !Buffer.isBuffer(payload_cbor) ||
    !payload_cbor.equals(e.payloadCbor) ||
    !Buffer.isBuffer(payload_digest) ||
    !payload_digest.equals(e.payloadDigest)
  )
    throw new NotificationDeliveryOutcomeError();
}
