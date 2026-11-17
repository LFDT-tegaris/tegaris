import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  encodeNotificationDeliveryRequestedData,
  evidenceKeyId,
  signNotificationClaim,
  type NotificationWorkerProfileClaims,
  type NotificationOccurrenceReceiptClaims,
  type NotificationDeliveryRequestedReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { validateNotificationOccurrencePreparation } from './occurrence-contract.js';
import type { NotificationPayloadReferenceGate } from './payload-reference.js';
import type { NotificationWorkerAdmission } from '../../../identity-service/src/domain/notification-worker.js';
import { readPublishedNotificationDeliveryRequest } from './delivery-source.js';
import {
  readNotificationOccurrence,
  markNotificationOccurrenceUnknown,
  dispatchNotificationOccurrence,
  observeNotificationOccurrence,
  readNotificationOccurrencePublication,
  publishNotificationOccurrence,
} from './occurrence-state.js';
const admissionCheck = vi.hoisted(() => vi.fn());
// Unit-only admission double. Real TLS/Identity/SQL acceptance belongs to the
// joined integration helper and cannot be inferred from these state tests.
vi.mock('../../../identity-service/src/domain/notification-worker.js', () => ({
  assertNotificationWorkerAdmission: admissionCheck,
  assertNotificationDeliveryWorkerAdmission: admissionCheck,
}));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = (s: string) => sha256(s);
const signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const key = signer.privateKey.export({ format: 'der', type: 'pkcs8' });
const spki = signer.publicKey.export({ format: 'der', type: 'spki' });
const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
  format: 'der',
  type: 'spki',
});
const input = {
  worker: {
    participantId: id(1),
    privacyDomainId: id(2),
    installationDigest: hash('installation'),
  },
  source: {
    scope: { participantId: id(1), privacyDomainId: id(2), streamId: 'CONTROL-BUSINESS' },
    evidenceExportId: id(3),
    eventId: id(4),
  },
  keyPreparationId: id(5),
};
function fixtures() {
  const profile: NotificationWorkerProfileClaims = {
    environmentId: 'local-notification',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(6),
    revision: '1',
    validFromMs: 100,
    validUntilMs: 200,
    sourceId: id(7),
    serviceId: 'LS-NOTIFICATION',
    processRole: 'ROLE-NOTIFICATION-WORKER',
    subscriptionId: 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1',
    principalId: id(8),
    workloadCredentialId: id(9),
    workloadEpoch: '1',
    workloadId: 'notification-worker',
    producerTrustDigest: hash('producer'),
    routingProfileDigest: hash('routing'),
    kmsInstallationDigest: hash('kms'),
    receiptSignerSpki: spki.toString('hex'),
    issuerKeyId: evidenceKeyId(issuer),
  };
  const claims: NotificationOccurrenceReceiptClaims = {
    environmentId: profile.environmentId,
    participantId: id(1),
    privacyDomainId: id(2),
    receiptId: id(10),
    operationId: id(11),
    notificationId: id(12),
    notificationOccurrenceId: id(13),
    payloadObjectId: id(14),
    keyPreparationId: id(5),
    sourceEventId: id(4),
    sourceDataDigest: hash('data'),
    sourceReceiptDigest: hash('source-receipt'),
    routingProfileDigest: hash('routing'),
    workerProfileDigest: hash('profile'),
    authoritySnapshotDigest: hash('authority'),
    custodyDigest: hash('custody'),
    endpointId: id(15),
    endpointRevision: '1',
    templateDigest: hash('template'),
    payloadDigest: hash('payload'),
    encryptedObjectDigest: hash('cipher'),
    keyId: hash('key'),
    recordedAtMs: 150,
    signerKeyId: evidenceKeyId(spki),
  };
  const signed = signNotificationClaim('NotificationOccurrenceReceiptV1', key, spki, claims);
  const occurrence = validateNotificationOccurrencePreparation({
    schema: 'pc.notification.occurrence-preparation.v1',
    preparationId: id(16),
    family: 'NotificationOccurrenceReceiptV1',
    input,
    workerProfile: profile,
    workerProfileDigest: claims.workerProfileDigest,
    workerAuthorityDigest: claims.authoritySnapshotDigest,
    payloadHex: signed.payload.toString('hex'),
  });
  const controlProfile: NotificationWorkerProfileClaims = {
    ...profile,
    profileId: id(17),
    principalId: id(18),
    workloadCredentialId: id(19),
    serviceId: 'LS-CONTROL-WORK',
    processRole: 'ROLE-CONTROL-WORKER',
    subscriptionId: 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1',
    workloadId: 'control-worker',
    sourceId: id(20),
  };
  const { notificationOccurrenceId, endpointId, templateDigest, payloadDigest } = claims;
  const request: NotificationDeliveryRequestedReceiptClaims = {
    ...claims,
    receiptId: id(21),
    operationId: id(22),
    workerProfileDigest: hash('control-profile'),
    authoritySnapshotDigest: hash('control-authority'),
    occurrenceReceiptDigest: sha256(signed.payload),
    eventId: id(23),
    sourceId: controlProfile.sourceId,
    sequence: '1',
    dataDigest: sha256(
      encodeNotificationDeliveryRequestedData({
        notificationOccurrenceId,
        endpointId,
        templateDigest,
        payloadDigest,
      }),
    ),
  };
  const deliverySigned = signNotificationClaim(
    'NotificationDeliveryRequestedReceiptV1',
    key,
    spki,
    request,
  );
  const delivery = validateNotificationOccurrencePreparation({
    ...occurrence,
    preparationId: id(24),
    family: 'NotificationDeliveryRequestedReceiptV1',
    input: {
      ...input,
      worker: { ...input.worker, installationDigest: hash('control-installation') },
    },
    workerProfile: controlProfile,
    workerProfileDigest: request.workerProfileDigest,
    workerAuthorityDigest: request.authoritySnapshotDigest,
    payloadHex: deliverySigned.payload.toString('hex'),
  });
  return { claims, profile, occurrence, signed, request, delivery, deliverySigned };
}

function database(state = 'OBSERVED') {
  const f = fixtures();
  const controls = { affected: 1 };
  const row = {
    preparation_bytes: Buffer.from(canonicalJson(f.occurrence)),
    preparation_digest: sha256(f.occurrence),
    state,
    receipt_payload: state === 'OBSERVED' ? f.signed.payload : null,
    receipt_digest: state === 'OBSERVED' ? sha256(f.signed.payload) : null,
    cose_sign1: state === 'OBSERVED' ? f.signed.cose : null,
  };
  const query = vi.fn(async (sql: string) => {
    if (sql.startsWith('select p.preparation_bytes')) return { rowCount: 1, rows: [row] };
    if (sql.startsWith('update ') && sql.includes("set state='UNKNOWN'")) {
      if (controls.affected === 1) row.state = 'UNKNOWN';
      return { rowCount: controls.affected, rows: [] };
    }
    throw new Error('Unexpected unit SQL');
  });
  const client = { query } as unknown as PoolClient;
  const admission = { installation: { profile: f.profile } } as NotificationWorkerAdmission;
  admissionCheck.mockImplementation((supplied: unknown, connection: unknown) => {
    if (supplied !== admission || connection !== client) throw new Error('Expired admission');
  });
  return {
    f,
    row,
    controls,
    query,
    client,
    admission,
    selector: { worker: input.worker, preparationId: f.occurrence.preparationId },
  };
}

it('delivery source requires the exact signed published original and detached readback', async () => {
  const f = fixtures();
  const row = {
    preparation_id: f.delivery.preparationId,
    preparation_bytes: Buffer.from(canonicalJson(f.delivery)),
    preparation_digest: sha256(f.delivery),
    operation_id: f.request.operationId,
    receipt_payload: f.deliverySigned.payload,
    receipt_digest: sha256(f.deliverySigned.payload),
    cose_sign1: f.deliverySigned.cose,
  };
  let publicationRows = 1;
  const query = vi.fn(async (sql: string) => {
    if (sql.includes('openpc.assert_request_context'))
      return { rowCount: 1, rows: [{ allowed: true }] };
    if (sql.includes('select p.preparation_id')) return { rowCount: 1, rows: [row] };
    if (sql.includes('check_notification_delivery_requested_event'))
      return { rowCount: publicationRows, rows: [] };
    if (sql.startsWith('savepoint ') || sql.startsWith('release savepoint '))
      return { rowCount: null, rows: [] };
    throw new Error('Unexpected unit SQL');
  });
  const client = { query } as unknown as PoolClient;
  const admission = { installation: { profile: f.profile } } as NotificationWorkerAdmission;
  admissionCheck.mockImplementation((actual: unknown) => {
    if (actual !== admission) throw new Error('Not admitted');
  });
  const selector = {
    worker: input.worker,
    notificationOccurrenceId: f.request.notificationOccurrenceId,
    eventId: f.request.eventId,
  };
  const result = await readPublishedNotificationDeliveryRequest(client, admission, selector);
  expect(result.claims).toEqual(f.request);
  result.receiptPayload.fill(0);
  expect(
    (await readPublishedNotificationDeliveryRequest(client, admission, selector)).receiptPayload,
  ).toEqual(f.deliverySigned.payload);
  for (const invalid of [
    { ...selector, eventId: id(98) },
    { ...selector, notificationOccurrenceId: id(99) },
    { ...selector, ready: true },
  ])
    await expect(
      readPublishedNotificationDeliveryRequest(client, admission, invalid),
    ).rejects.toThrow('source unavailable');
  publicationRows = 0;
  await expect(
    readPublishedNotificationDeliveryRequest(client, admission, selector),
  ).rejects.toThrow('source unavailable');
  publicationRows = 1;
  row.cose_sign1 = Buffer.from(row.cose_sign1);
  row.cose_sign1[row.cose_sign1.length - 1] = row.cose_sign1[row.cose_sign1.length - 1]! ^ 1;
  await expect(
    readPublishedNotificationDeliveryRequest(client, admission, selector),
  ).rejects.toThrow('source unavailable');
  query.mockClear();
  await expect(
    readPublishedNotificationDeliveryRequest(client, {} as NotificationWorkerAdmission, selector),
  ).rejects.toThrow('source unavailable');
  expect(query).not.toHaveBeenCalled();
});
it('reads exact immutable proof with detached buffers and no effects', async () => {
  const d = database();
  const first = await readNotificationOccurrence(d.client, d.admission, d.selector);
  expect(first.cose).toEqual(d.f.signed.cose);
  first.cose!.fill(0);
  expect((await readNotificationOccurrence(d.client, d.admission, d.selector)).cose).toEqual(
    d.f.signed.cose,
  );
  expect(d.query.mock.calls.every(([sql]) => sql.startsWith('select '))).toBe(true);
});
it('denies fabricated or stale admission before SQL', async () => {
  const d = database();
  await expect(
    readNotificationOccurrence(d.client, {} as NotificationWorkerAdmission, d.selector),
  ).rejects.toThrow('Expired admission');
  expect(d.query).not.toHaveBeenCalled();
});
it.each(['PREPARED', 'DISPATCHED', 'UNKNOWN'])(
  'rejects a proof row paired with %s',
  async (state) => {
    const d = database();
    d.row.state = state;
    await expect(readNotificationOccurrence(d.client, d.admission, d.selector)).rejects.toThrow(
      'INTEGRITY',
    );
  },
);
it('denies missing proof for OBSERVED and altered retained bytes', async () => {
  const d = database('UNKNOWN');
  d.row.state = 'OBSERVED';
  await expect(readNotificationOccurrence(d.client, d.admission, d.selector)).rejects.toThrow(
    'INTEGRITY',
  );
  const next = database();
  next.row.preparation_bytes[0] = 0;
  await expect(
    readNotificationOccurrence(next.client, next.admission, next.selector),
  ).rejects.toThrow('INTEGRITY');
});
it.each(['DISPATCHED', 'UNKNOWN', 'OBSERVED'])(
  'does not dispatch another attempt from %s',
  async (state) => {
    const d = database(state);
    await expect(dispatchNotificationOccurrence(d.client, d.admission, d.selector)).rejects.toThrow(
      'UNKNOWN',
    );
    expect(d.query).toHaveBeenCalledTimes(1);
  },
);
it('retains uncertainty with the original identity and makes UNKNOWN replay effect-free', async () => {
  const d = database('DISPATCHED');
  expect((await markNotificationOccurrenceUnknown(d.client, d.admission, d.selector)).state).toBe(
    'UNKNOWN',
  );
  const mutations = d.query.mock.calls.filter(([sql]) => sql.startsWith('update ')).length;
  expect(
    (await markNotificationOccurrenceUnknown(d.client, d.admission, d.selector)).preparation,
  ).toEqual(d.f.occurrence);
  expect(d.query.mock.calls.filter(([sql]) => sql.startsWith('update '))).toHaveLength(mutations);
});
it('accepts only the exact first observation on replay', async () => {
  const d = database();
  expect(
    (await observeNotificationOccurrence(d.client, d.admission, d.selector, d.f.signed.cose)).cose,
  ).toEqual(d.f.signed.cose);
  const again = signNotificationClaim('NotificationOccurrenceReceiptV1', key, spki, d.f.claims);
  if (!again.cose.equals(d.f.signed.cose))
    await expect(
      observeNotificationOccurrence(d.client, d.admission, d.selector, again.cose),
    ).rejects.toThrow('CONFLICT');
  const changed = signNotificationClaim('NotificationOccurrenceReceiptV1', key, spki, {
    ...d.f.claims,
    sourceDataDigest: hash('changed'),
  });
  await expect(
    observeNotificationOccurrence(d.client, d.admission, d.selector, changed.cose),
  ).rejects.toThrow('INTEGRITY');
  expect(d.query.mock.calls.every(([sql]) => sql.startsWith('select '))).toBe(true);
});

it('refuses new dispatch or observation under a replaced authority snapshot', async () => {
  const d = database('PREPARED');
  await expect(dispatchNotificationOccurrence(d.client, d.admission, d.selector)).rejects.toThrow(
    'CONFLICT',
  );
  expect(d.query).toHaveBeenCalledTimes(1);
  const unknown = database('UNKNOWN');
  await expect(
    observeNotificationOccurrence(
      unknown.client,
      unknown.admission,
      unknown.selector,
      unknown.f.signed.cose,
    ),
  ).rejects.toThrow('CONFLICT');
  expect(unknown.query).toHaveBeenCalledTimes(1);
});

it('does not report a transition when its conditional update lost the race', async () => {
  const d = database('DISPATCHED');
  d.controls.affected = 0;
  await expect(
    markNotificationOccurrenceUnknown(d.client, d.admission, d.selector),
  ).rejects.toThrow('CONFLICT');
  expect(d.query).toHaveBeenCalledTimes(2);
  expect(d.row.state).toBe('DISPATCHED');
});

function publicationDatabase() {
  const f = fixtures();
  const row = (p: typeof f.occurrence, s: typeof f.signed) => ({
    preparation_bytes: Buffer.from(canonicalJson(p)),
    preparation_digest: sha256(p),
    state: 'OBSERVED',
    receipt_payload: s.payload,
    receipt_digest: sha256(s.payload),
    cose_sign1: s.cose,
  });
  const controls = { published: false, partial: false };
  const query = vi.fn(async (sql: string) => {
    if (sql.startsWith('select p.preparation_bytes'))
      return {
        rowCount: 1,
        rows: [
          sql.includes("p.family='NotificationOccurrenceReceiptV1'")
            ? row(f.occurrence, f.signed)
            : row(f.delivery, f.deliverySigned),
        ],
      };
    if (sql.startsWith('select openpc.check_notification_delivery_requested_event'))
      return { rowCount: controls.published ? 1 : 0, rows: [] };
    if (sql.startsWith('select 1 from control.notification where'))
      return { rowCount: controls.partial ? 1 : 0, rows: [] };
    throw new Error('Unexpected publication SQL');
  });
  const client = { query } as unknown as PoolClient;
  const admission = {
    installation: { profile: f.delivery.workerProfile },
    authorityDigest: f.request.authoritySnapshotDigest,
  } as NotificationWorkerAdmission;
  admissionCheck.mockImplementation((supplied: unknown, connection: unknown) => {
    if (supplied !== admission || connection !== client) throw new Error('Expired admission');
  });
  return {
    f,
    controls,
    query,
    client,
    admission,
    selector: { worker: f.delivery.input.worker, preparationId: f.delivery.preparationId },
  };
}
it('reconciles publication from retained originals without current-key calls or writes', async () => {
  const d = publicationDatabase();
  expect(
    (await readNotificationOccurrencePublication(d.client, d.admission, d.selector)).state,
  ).toBe('UNPUBLISHED');
  d.controls.published = true;
  const result = await readNotificationOccurrencePublication(d.client, d.admission, d.selector);
  expect(result.state).toBe('PUBLISHED');
  expect(result.event.id).toBe(d.f.request.eventId);
  expect(d.query.mock.calls.every(([sql]) => sql.startsWith('select '))).toBe(true);
});
it('fails closed on partial effects instead of completing or replacing an original', async () => {
  const d = publicationDatabase();
  d.controls.partial = true;
  await expect(
    readNotificationOccurrencePublication(d.client, d.admission, d.selector),
  ).rejects.toThrow('INTEGRITY');
});
it('does not cross the current-key gate under a changed worker authority', async () => {
  const d = publicationDatabase();
  const withCurrent = vi.fn();
  Object.assign(d.admission, { authorityDigest: hash('changed') });
  await expect(
    publishNotificationOccurrence(d.client, d.admission, d.selector, {
      withCurrent,
    } as unknown as NotificationPayloadReferenceGate),
  ).rejects.toThrow('CONFLICT');
  expect(withCurrent).not.toHaveBeenCalled();
});
it('keeps all effects absent when the actual current-key gate denies', async () => {
  const d = publicationDatabase();
  const withCurrent = vi.fn().mockRejectedValue(new Error('current key denied'));
  await expect(
    publishNotificationOccurrence(d.client, d.admission, d.selector, {
      withCurrent,
    } as unknown as NotificationPayloadReferenceGate),
  ).rejects.toThrow('current key denied');
  expect(withCurrent.mock.calls[0]!.slice(0, 3)).toEqual([
    d.client,
    d.admission,
    { worker: d.selector.worker, keyPreparationId: d.f.request.keyPreparationId },
  ]);
  expect(d.query.mock.calls.every(([sql]) => sql.startsWith('select '))).toBe(true);
});
it('rejects copied custody metadata from a fabricated gate before any publication query', async () => {
  const d = publicationDatabase();
  const withCurrent = vi.fn(
    async (_c: unknown, _a: unknown, _q: unknown, run: (r: unknown) => Promise<unknown>) =>
      run({ custodyDigest: d.f.request.custodyDigest }),
  );
  await expect(
    publishNotificationOccurrence(d.client, d.admission, d.selector, {
      withCurrent,
    } as unknown as NotificationPayloadReferenceGate),
  ).rejects.toThrow('Notification payload reference unavailable');
  expect(d.query.mock.calls).toHaveLength(2);
});
