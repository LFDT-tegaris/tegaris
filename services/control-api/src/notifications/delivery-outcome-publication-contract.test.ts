import { it, expect } from 'vitest';
import { notificationSignedOutcomeSample } from '../../../../tests/integration/identity/notification-delivery-outcome-cases.js';
import {
  notificationOutcomePublication,
  assertNotificationCompletionRow,
  type NotificationCompletionRow,
} from './delivery-outcome-publication-contract.js';
function sample(
  outcome: 'DELIVERED' | 'PERMANENT_FAILURE' | 'AMBIGUOUS' | 'RETRYABLE_NO_EFFECT' = 'DELIVERED',
) {
  const f = notificationSignedOutcomeSample(outcome),
    p = notificationOutcomePublication(f.value),
    r = f.value.receipt,
    e = p.event;
  const row: NotificationCompletionRow | null = e
    ? {
        participant_id: r.participantId,
        privacy_domain_id: r.privacyDomainId,
        event_id: r.receiptId,
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
        payload_cbor: e.payloadCbor,
        payload_digest: e.payloadDigest,
        cose_sign1: null,
        webauthn_assertion_binding_digest: null,
        occurred_at_ms: String(r.recordedAtMs),
      }
    : null;
  return { f, p, row };
}
it.each(['DELIVERED', 'PERMANENT_FAILURE'] as const)(
  'binds exact terminal %s event and source-owned failure data',
  (outcome) => {
    const { f, p, row } = sample(outcome);
    expect(() => assertNotificationCompletionRow(p, row)).not.toThrow();
    expect(p.event!.envelope.id).toBe(f.value.receipt.receiptId);
    expect(p.event!.envelope.correlationid).toBe(f.value.receipt.operationId);
    expect(p.event!.envelope.causationid).toBe(f.f.original.source.eventId);
    expect(p.event!.envelope.data.deliveryReceiptDigest).toBe(f.value.receipt.gatewayCoseDigest);
    expect(p.event!.envelope.data.attemptCount).toBe(String(f.value.receipt.attemptCount));
    expect(p.failureWork?.workItemId ?? null).toBe(
      outcome === 'PERMANENT_FAILURE' ? f.value.receipt.receiptId : null,
    );
    const bytes = p.event!.payloadCbor;
    bytes.fill(0);
    expect(p.event!.payloadCbor).not.toEqual(bytes);
  },
);
it.each(['AMBIGUOUS', 'RETRYABLE_NO_EFFECT'] as const)(
  'does not invent completion or work for %s',
  (outcome) => {
    const { p } = sample(outcome);
    expect(p.event).toBeNull();
    expect(p.failureWork).toBeNull();
    expect(() => assertNotificationCompletionRow(p, null)).not.toThrow();
    expect(() => assertNotificationCompletionRow(p, sample().row)).toThrow();
  },
);
it.each([
  'participant_id',
  'privacy_domain_id',
  'event_id',
  'event_type',
  'aggregate_type',
  'aggregate_id',
  'aggregate_sequence',
  'business_sequence',
  'proof_kind',
  'sequence_namespace',
  'receipt_id',
  'data_schema_uri',
  'source',
  'subject',
  'correlation_id',
  'causation_id',
  'authority_generation',
  'cose_sign1',
  'webauthn_assertion_binding_digest',
  'occurred_at_ms',
  'payload_cbor',
  'payload_digest',
] as const)('rejects detached completion %s', (field) => {
  const { p, row } = sample();
  const altered = { ...row! };
  Object.assign(altered, {
    [field]: Buffer.isBuffer(altered[field]) ? Buffer.from('bad') : 'different',
  });
  expect(() => assertNotificationCompletionRow(p, altered)).toThrow();
});
it('requires actual native signatures rather than structurally correct completion data', () => {
  const { f } = sample();
  expect(() => notificationOutcomePublication({ ...f.value, coseHex: '00' })).toThrow();
  expect(() =>
    notificationOutcomePublication({
      ...f.value,
      receipt: { ...f.value.receipt, afterDeliveryState: 'FAILED' },
    }),
  ).toThrow();
  expect(() => assertNotificationCompletionRow(sample().p, null)).toThrow();
});
