import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { notificationDeliverySigningSample } from '../../../../tests/integration/identity/notification-delivery-signing-cases.js';
import { decodeNotificationSigningRecord } from './delivery-signing-state.js';
function stored() {
  const { signing, observe } = notificationDeliverySigningSample(),
    bytes = Buffer.from(canonicalJson(signing));
  return {
    signing,
    observe,
    q: {
      source: structuredClone(signing.deliveryPreparation.source),
      operationId: signing.request.operationId,
      signerInstallationDigest: signing.request.signerInstallationDigest,
    },
    row: {
      preparation_bytes: bytes,
      preparation_digest: sha256(bytes),
      state: 'PREPARED',
      dispatch_token: null as string | null,
      observation_bytes: null as Buffer | null,
      observation_digest: null as string | null,
    },
  };
}
it('retains exact originals after dispatch and observation without refreshing receipt lifetime', () => {
  const { q, row, observe } = stored();
  const prepared = decodeNotificationSigningRecord(row, q);
  row.state = 'DISPATCHED';
  row.dispatch_token = '01900000-0000-7000-8000-000000000099';
  expect(decodeNotificationSigningRecord(row, q).preparation).toEqual(prepared.preparation);
  row.state = 'OBSERVED';
  row.observation_bytes = Buffer.from(canonicalJson(observe()));
  row.observation_digest = sha256(row.observation_bytes);
  expect(decodeNotificationSigningRecord(row, q).observation?.outcome).toBe('SIGNED');
});
it.each([
  'wrong-operation',
  'wrong-source',
  'missing-token',
  'premature-observation',
  'missing-observation',
  'changed-bytes',
] as const)('fails closed on persisted %s', (kind) => {
  const { q, row, observe } = stored();
  if (kind === 'wrong-operation') q.operationId = q.source.eventId;
  if (kind === 'wrong-source') q.source.eventId = q.source.notificationOccurrenceId;
  if (kind === 'missing-token') row.state = 'DISPATCHED';
  if (kind === 'premature-observation') {
    row.observation_bytes = Buffer.from(canonicalJson(observe()));
    row.observation_digest = sha256(row.observation_bytes);
  }
  if (kind === 'missing-observation') {
    row.state = 'OBSERVED';
    row.dispatch_token = q.operationId;
  }
  if (kind === 'changed-bytes') row.preparation_bytes = Buffer.from('{}');
  expect(() => decodeNotificationSigningRecord(row, q)).toThrow();
});
it('composes genuine current-generation, custody, TLS and same-client owners; historical attachment has no new effect admission', () => {
  const src = readFileSync(new URL('./delivery-signing-state.ts', import.meta.url), 'utf8');
  for (const text of [
    'withNotificationWorkerPeer',
    'withCurrentNotificationReceiptSigner',
    'current_notification_delivery_limit',
    'gate.withDeliveryCurrent',
    'assertNotificationDeliveryPayloadReference',
    'currentNotificationChannel',
    'for update',
    'authorityValidUntilMs',
    "state='PREPARED'",
    "state='DISPATCHED'",
  ])
    expect(src).toContain(text);
  const attach = src.slice(src.indexOf('export async function attachNotification'));
  expect(attach).toContain('withNotificationSigningHistory');
  expect(attach).not.toContain('withCurrentNotificationSigning');
  expect(src).not.toMatch(/\.perform\(|\.deliver\(|signNotificationClaim\(/u);
});
