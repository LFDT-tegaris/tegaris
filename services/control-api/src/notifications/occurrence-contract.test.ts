import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  encodeNotificationClaim,
  encodeNotificationDeliveryRequestedData,
  evidenceKeyId,
  signNotificationClaim,
  type NotificationWorkerProfileClaims,
  type NotificationOccurrenceReceiptClaims,
  type NotificationDeliveryRequestedReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { matchNotificationEventEnvelope } from './event-input.js';
import {
  assertNotificationOccurrencePair,
  constructNotificationDeliveryRequestedEvent,
  bindNotificationDeliveryRequestedEvent,
  decodeNotificationOccurrencePreparation,
  notificationOccurrencePrepareInput,
  notificationOccurrenceReferences,
  parseNotificationOccurrence,
  validateNotificationOccurrencePreparation,
  verifyNotificationOccurrenceObservation,
} from './occurrence-contract.js';
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
it('preserves canonical original receipts and separates the two service roles', () => {
  const f = fixtures();
  expect(
    assertNotificationOccurrencePair(f.occurrence, f.signed.cose, f.delivery, f.deliverySigned.cose)
      .occurrence.claims,
  ).toEqual(f.claims);
  const bytes = Buffer.from(canonicalJson(f.occurrence));
  expect(decodeNotificationOccurrencePreparation(bytes, sha256(bytes))).toEqual(f.occurrence);
  expect(verifyNotificationOccurrenceObservation(f.occurrence, f.signed.cose).cose).not.toBe(
    f.signed.cose,
  );
});
it('rejects caller authority and foreign scope before any admission', () => {
  for (const value of [
    { ...input, ready: true },
    { ...input, claims: {} },
    { ...input, source: { ...input.source, payloadHex: '00' } },
    { ...input, keyPreparationId: 'urn:openpc:resource:' + id(5) },
  ])
    expect(() => parseNotificationOccurrence(notificationOccurrencePrepareInput, value)).toThrow(
      'INVALID',
    );
  const f = fixtures();
  expect(() =>
    validateNotificationOccurrencePreparation({
      ...f.occurrence,
      input: { ...input, worker: { ...input.worker, privacyDomainId: id(99) } },
    }),
  ).toThrow('INTEGRITY');
});
it('projects only exact scoped resource namespaces', () => {
  expect(
    notificationOccurrenceReferences({
      notificationId: id(12),
      notificationOccurrenceId: id(13),
      payloadObjectId: id(14),
    }),
  ).toEqual({
    notificationRef: 'urn:openpc:resource:' + id(12),
    occurrenceRef: 'urn:openpc:notification-occurrence:' + id(13),
    payloadObjectRef: 'urn:openpc:resource:' + id(14),
  });
  expect(() =>
    notificationOccurrenceReferences({
      notificationId: 'urn:openpc:resource:' + id(12),
      notificationOccurrenceId: id(13),
      payloadObjectId: id(14),
    }),
  ).toThrow();
});
it('denies copied worker roles, authority, identity and expiry at original preparation', () => {
  const f = fixtures();
  for (const patch of [
    {
      workerProfile: {
        ...f.profile,
        serviceId: 'LS-CONTROL-WORK',
        processRole: 'ROLE-CONTROL-WORKER',
        subscriptionId: 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1',
      },
    },
    { workerProfile: { ...f.profile, validUntilMs: 150 } },
    { workerProfile: { ...f.profile, validFromMs: 151 } },
    { workerProfile: { ...f.profile, privacyDomainId: id(99) } },
    { workerProfileDigest: hash('other') },
    { workerAuthorityDigest: hash('other') },
  ])
    expect(() => validateNotificationOccurrencePreparation({ ...f.occurrence, ...patch })).toThrow(
      'INTEGRITY',
    );
});
it('denies original signed bytes altered under the same event identity', () => {
  const f = fixtures();
  const copied = signNotificationClaim('NotificationOccurrenceReceiptV1', key, spki, {
    ...f.claims,
    sourceDataDigest: hash('other'),
  });
  expect(() => verifyNotificationOccurrenceObservation(f.occurrence, copied.cose)).toThrow(
    'INTEGRITY',
  );
  const broken = Buffer.from(f.signed.cose);
  broken[broken.length - 1] = broken[broken.length - 1]! ^ 1;
  expect(() => verifyNotificationOccurrenceObservation(f.occurrence, broken)).toThrow('INTEGRITY');
  const bytes = Buffer.from(canonicalJson(f.occurrence) + ' ');
  expect(() => decodeNotificationOccurrencePreparation(bytes, sha256(bytes))).toThrow('INTEGRITY');
  expect(() =>
    decodeNotificationOccurrencePreparation(
      Buffer.from(canonicalJson(f.occurrence)),
      hash('other'),
    ),
  ).toThrow('INTEGRITY');
});
it('denies independently signed rebinding of every shared source and custody field', () => {
  const f = fixtures();
  for (const field of [
    'notificationId',
    'notificationOccurrenceId',
    'payloadObjectId',
    'keyPreparationId',
    'sourceEventId',
    'sourceDataDigest',
    'sourceReceiptDigest',
    'routingProfileDigest',
    'custodyDigest',
    'endpointId',
    'endpointRevision',
    'templateDigest',
    'payloadDigest',
    'encryptedObjectDigest',
    'keyId',
  ] as const) {
    const request = {
      ...f.request,
      [field]:
        field.endsWith('Id') && field !== 'keyId'
          ? id(99)
          : field === 'endpointRevision'
            ? '2'
            : hash('other'),
    };
    const { notificationOccurrenceId, endpointId, templateDigest, payloadDigest } = request;
    request.dataDigest = sha256(
      encodeNotificationDeliveryRequestedData({
        notificationOccurrenceId,
        endpointId,
        templateDigest,
        payloadDigest,
      }),
    );
    const signed = signNotificationClaim(
      'NotificationDeliveryRequestedReceiptV1',
      key,
      spki,
      request,
    );
    expect(
      () =>
        assertNotificationOccurrencePair(
          f.occurrence,
          f.signed.cose,
          { ...f.delivery, payloadHex: signed.payload.toString('hex') },
          signed.cose,
        ),
      field,
    ).toThrow('INTEGRITY');
  }
});
it('retains original proof buffers when caller mutates returned values', () => {
  const f = fixtures();
  const first = verifyNotificationOccurrenceObservation(f.occurrence, f.signed.cose);
  first.payload.fill(0);
  first.cose.fill(0);
  first.claims.keyId = hash('mutated');
  expect(verifyNotificationOccurrenceObservation(f.occurrence, f.signed.cose).claims).toEqual(
    f.claims,
  );
});
it('keeps operation and receipt identities separate across the two signed stages', () => {
  const f = fixtures();
  for (const patch of [
    { operationId: f.claims.operationId },
    { receiptId: f.claims.receiptId },
    { occurrenceReceiptDigest: hash('other') },
    { recordedAtMs: 149 },
  ]) {
    const claims = { ...f.request, ...patch };
    const signed = signNotificationClaim(
      'NotificationDeliveryRequestedReceiptV1',
      key,
      spki,
      claims,
    );
    expect(() =>
      assertNotificationOccurrencePair(
        f.occurrence,
        f.signed.cose,
        {
          ...f.delivery,
          payloadHex: encodeNotificationClaim(
            'NotificationDeliveryRequestedReceiptV1',
            claims,
          ).toString('hex'),
        },
        signed.cose,
      ),
    ).toThrow('INTEGRITY');
  }
});

it('constructs the registered delivery event from both original proofs and interoperates with the event consumer', () => {
  const f = fixtures();
  const result = constructNotificationDeliveryRequestedEvent(
    f.occurrence,
    f.signed.cose,
    f.delivery,
    f.deliverySigned.cose,
  );
  expect(result.envelope).toMatchObject({
    id: f.request.eventId,
    source: `urn:openpc:service:${f.request.sourceId}`,
    type: 'io.openpc.notification.delivery.requested.v1',
    subject: `urn:openpc:notification-occurrence:${f.request.notificationOccurrenceId}`,
    participantid: `urn:openpc:participant:${f.request.participantId}`,
    privacydomainid: `urn:openpc:privacy-domain:${f.request.privacyDomainId}`,
    correlationid: f.request.operationId,
    causationid: f.request.sourceEventId,
    sequence: '1',
    datadigest: f.request.dataDigest,
    data: {
      notificationOccurrenceId: `urn:openpc:notification-occurrence:${f.request.notificationOccurrenceId}`,
      endpointId: `urn:openpc:resource:${f.request.endpointId}`,
      templateDigest: f.request.templateDigest,
      payloadDigest: f.request.payloadDigest,
    },
  });
  expect(result.payloadDigest.toString('hex')).toBe(f.request.dataDigest.slice(7));
  expect(sha256(result.payloadCbor)).toBe(f.request.dataDigest);
  expect(result.receiptPayload).toEqual(f.deliverySigned.payload);
  expect(result.receiptCose).toEqual(f.deliverySigned.cose);
  expect(
    matchNotificationEventEnvelope(result.envelope, {
      participantId: f.request.participantId,
      privacyDomainId: f.request.privacyDomainId,
      source: result.envelope.source,
      partition: result.envelope.data.notificationOccurrenceId,
      sequence: '1',
      dataDigest: f.request.dataDigest,
    }),
  ).toEqual(result.envelope);
  expect(
    bindNotificationDeliveryRequestedEvent(
      result.envelope,
      f.occurrence,
      f.signed.cose,
      f.delivery,
      f.deliverySigned.cose,
    ),
  ).toEqual(result);
});
it('rejects scope, identity, ordering, digest and optional-extension substitutions under the original event ID', () => {
  const f = fixtures();
  const original = constructNotificationDeliveryRequestedEvent(
    f.occurrence,
    f.signed.cose,
    f.delivery,
    f.deliverySigned.cose,
  );
  for (const patch of [
    { participantid: `urn:openpc:participant:${id(99)}` },
    { privacydomainid: `urn:openpc:privacy-domain:${id(99)}` },
    { source: `urn:openpc:service:${id(99)}` },
    { subject: `urn:openpc:resource:${f.request.notificationOccurrenceId}` },
    { correlationid: id(99) },
    { causationid: id(99) },
    { sequence: '0' },
    { sequence: '2' },
    { sequence: '01' },
    { datadigest: hash('different-data') },
    { authoritygeneration: hash('extra-authority') },
    { ready: true },
    { data: { ...original.envelope.data, payloadDigest: hash('different-payload') } },
    {
      data: {
        ...original.envelope.data,
        notificationOccurrenceId: `urn:openpc:resource:${f.request.notificationOccurrenceId}`,
      },
    },
    {
      data: {
        ...original.envelope.data,
        endpointId: `urn:openpc:notification-occurrence:${f.request.endpointId}`,
      },
    },
    { data: { ...original.envelope.data, ready: true } },
  ])
    expect(() =>
      bindNotificationDeliveryRequestedEvent(
        { ...original.envelope, ...patch },
        f.occurrence,
        f.signed.cose,
        f.delivery,
        f.deliverySigned.cose,
      ),
    ).toThrow('INTEGRITY');
  const missing = { ...original.envelope };
  delete (missing as { datadigest?: string }).datadigest;
  expect(() =>
    bindNotificationDeliveryRequestedEvent(
      missing,
      f.occurrence,
      f.signed.cose,
      f.delivery,
      f.deliverySigned.cose,
    ),
  ).toThrow('INTEGRITY');
});
it('rejects a copied delivery proof or source pair before constructing any event', () => {
  const f = fixtures();
  expect(() =>
    constructNotificationDeliveryRequestedEvent(
      f.occurrence,
      f.signed.cose,
      f.delivery,
      f.signed.cose,
    ),
  ).toThrow('INTEGRITY');
  expect(() =>
    constructNotificationDeliveryRequestedEvent(
      f.occurrence,
      f.signed.cose,
      {
        ...f.delivery,
        input: {
          ...f.delivery.input,
          source: { ...f.delivery.input.source, evidenceExportId: id(99) },
        },
      },
      f.deliverySigned.cose,
    ),
  ).toThrow('INTEGRITY');
});
it('keeps event DATA bytes and proof buffers independent of callers', () => {
  const f = fixtures();
  const make = () =>
    constructNotificationDeliveryRequestedEvent(
      f.occurrence,
      f.signed.cose,
      f.delivery,
      f.deliverySigned.cose,
    );
  const first = make(),
    second = make();
  first.payloadCbor.fill(0);
  first.payloadDigest.fill(0);
  first.receiptPayload.fill(0);
  first.receiptCose.fill(0);
  first.envelope.data.endpointId = `urn:openpc:resource:${id(99)}`;
  expect(make()).toEqual(second);
  expect(f.deliverySigned.payload).toEqual(second.receiptPayload);
  expect(f.deliverySigned.cose).toEqual(second.receiptCose);
});
