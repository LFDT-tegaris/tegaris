import { businessTransitionProfileForOperation } from '../business-transition/profiles.js';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { evidenceKeyId } from '../business-transition/cose.js';
import { decodeCbor, encodeCbor } from '../canonical-cbor.js';
import {
  encodeNotificationClaim,
  decodeNotificationClaim,
  signNotificationClaim,
  verifyNotificationClaim,
  encodeNotificationDeliveryRequestedData,
  type NotificationWorkerProfileClaims,
  type NotificationDeliveryCancellationReceiptClaims,
  type NotificationDeliveryOutcomeReceiptClaims,
  type NotificationOccurrenceReceiptClaims,
  type NotificationDeliveryRequestedReceiptClaims,
} from './codec.js';
import {
  verifyInstalledNotificationWorkerProfile,
  verifyNotificationWorkerReceipt,
  verifyNotificationDeliveryCancellationReceipt,
  verifyNotificationDeliveryOutcomeReceipt,
  assertNotificationDeliveryRequestOriginal,
  notificationDeliveryRequestedEnvelope,
  type InstalledNotificationWorkerProfile,
} from './worker-contract.js';
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const h = (n: number) => digest(Buffer.from(String(n)));
const keys = () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: pair.publicKey.export({ format: 'der', type: 'spki' }),
  };
};
const issuer = keys(),
  signer = keys(),
  transport = keys();
function profile(control = false): NotificationWorkerProfileClaims {
  return {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(control ? 4 : 3),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 10000,
    sourceId: id(5),
    serviceId: control ? 'LS-CONTROL-WORK' : 'LS-NOTIFICATION',
    processRole: control ? 'ROLE-CONTROL-WORKER' : 'ROLE-NOTIFICATION-WORKER',
    subscriptionId: control
      ? 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1'
      : 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1',
    principalId: id(6),
    workloadCredentialId: id(7),
    workloadEpoch: '1',
    workloadId: 'urn:openpc:workload:test',
    producerTrustDigest: h(1),
    routingProfileDigest: h(2),
    kmsInstallationDigest: h(3),
    receiptSignerSpki: signer.spki.toString('hex'),
    issuerKeyId: evidenceKeyId(issuer.spki),
  };
}
function installed(p = profile()) {
  const signed = signNotificationClaim(
    'NotificationWorkerProfileV1',
    issuer.privateKey,
    issuer.spki,
    p,
  );
  const pins: InstalledNotificationWorkerProfile = {
    issuerSpki: issuer.spki,
    signedProfileDigest: digest(signed.cose),
    environmentId: p.environmentId,
    participantId: p.participantId,
    privacyDomainId: p.privacyDomainId,
    profileId: p.profileId,
    revision: p.revision,
    serviceId: p.serviceId,
    processRole: p.processRole,
    subscriptionId: p.subscriptionId,
    principalId: p.principalId,
    workloadCredentialId: p.workloadCredentialId,
    workloadEpoch: p.workloadEpoch,
    workloadId: p.workloadId,
    workloadKeyDigest: evidenceKeyId(transport.spki),
  };
  return { p, pins, ...signed };
}
function occurrence(
  p: NotificationWorkerProfileClaims,
  workerProfileDigest: string,
): NotificationOccurrenceReceiptClaims {
  return {
    environmentId: p.environmentId,
    participantId: p.participantId,
    privacyDomainId: p.privacyDomainId,
    receiptId: id(10),
    operationId: id(11),
    notificationId: id(12),
    notificationOccurrenceId: id(13),
    payloadObjectId: id(14),
    keyPreparationId: id(15),
    sourceEventId: id(16),
    sourceDataDigest: h(4),
    sourceReceiptDigest: h(5),
    routingProfileDigest: p.routingProfileDigest,
    workerProfileDigest,
    authoritySnapshotDigest: h(6),
    custodyDigest: h(7),
    endpointId: id(17),
    endpointRevision: '2',
    templateDigest: h(8),
    payloadDigest: h(9),
    encryptedObjectDigest: h(10),
    keyId: h(11),
    recordedAtMs: 2000,
    signerKeyId: evidenceKeyId(signer.spki),
  };
}
function request(
  original: NotificationOccurrenceReceiptClaims,
  workerProfileDigest: string,
): NotificationDeliveryRequestedReceiptClaims {
  const { notificationOccurrenceId, endpointId, templateDigest, payloadDigest } = original;
  return {
    ...original,
    receiptId: id(20),
    operationId: id(21),
    workerProfileDigest,
    recordedAtMs: 3000,
    occurrenceReceiptDigest: digest(
      encodeNotificationClaim('NotificationOccurrenceReceiptV1', original),
    ),
    eventId: id(22),
    sourceId: id(5),
    sequence: '1',
    dataDigest: digest(
      encodeNotificationDeliveryRequestedData({
        notificationOccurrenceId,
        endpointId,
        templateDigest,
        payloadDigest,
      }),
    ),
  };
}
it('verifies independently pinned profiles for each exact registered service/role/subscription pair', () => {
  for (const p of [
    profile(),
    profile(true),
    { ...profile(), subscriptionId: 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1' as const },
  ]) {
    const i = installed(p);
    expect(verifyInstalledNotificationWorkerProfile(i.pins, i.payload, i.cose, 2000)).toEqual(p);
  }
  for (const patch of [
    { processRole: 'ROLE-CONTROL-WORKER' },
    { serviceId: 'LS-CONTROL-WORK' },
    { subscriptionId: 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1' },
    { receiptSignerSpki: issuer.spki.toString('hex') },
    { validUntilMs: 1000 },
    { workloadEpoch: '0' },
    { workloadId: ' role ' },
    { ready: true },
  ])
    expect(() =>
      encodeNotificationClaim('NotificationWorkerProfileV1', {
        ...profile(),
        ...patch,
      } as NotificationWorkerProfileClaims),
    ).toThrow();
});
it('denies foreign, stale, mismatched or conflated initial trust independently of valid signatures', () => {
  const i = installed();
  for (const patch of [
    { signedProfileDigest: h(20) },
    { issuerSpki: signer.spki },
    { participantId: id(90) },
    { privacyDomainId: id(90) },
    { profileId: id(90) },
    { revision: '2' },
    { principalId: id(90) },
    { workloadCredentialId: id(90) },
    { workloadEpoch: '2' },
    { workloadId: 'other' },
    { workloadKeyDigest: evidenceKeyId(signer.spki) },
    { workloadKeyDigest: evidenceKeyId(issuer.spki) },
    { workloadKeyDigest: 'alias' },
  ])
    expect(() =>
      verifyInstalledNotificationWorkerProfile({ ...i.pins, ...patch }, i.payload, i.cose, 2000),
    ).toThrow();
  for (const now of [999, 10000, NaN, Infinity, -0, -1, 1.5])
    expect(() =>
      verifyInstalledNotificationWorkerProfile(i.pins, i.payload, i.cose, now),
    ).toThrow();
});
it('binds each receipt to its own worker family and exact retained prepared payload', () => {
  const n = installed(),
    c = installed(profile(true));
  const o = occurrence(n.p, n.pins.signedProfileDigest),
    r = request(o, c.pins.signedProfileDigest);
  for (const [family, claims, owner] of [
    ['NotificationOccurrenceReceiptV1', o, n],
    ['NotificationDeliveryRequestedReceiptV1', r, c],
  ] as const) {
    const signed = signNotificationClaim(family, signer.privateKey, signer.spki, claims);
    expect(
      verifyNotificationWorkerReceipt(
        family,
        owner.p,
        owner.pins.signedProfileDigest,
        claims,
        signed.payload,
        signed.cose,
      ),
    ).toEqual(claims);
    const other = owner === n ? c : n;
    expect(() =>
      verifyNotificationWorkerReceipt(
        family,
        other.p,
        owner.pins.signedProfileDigest,
        claims,
        signed.payload,
        signed.cose,
      ),
    ).toThrow();
    expect(() =>
      verifyNotificationWorkerReceipt(family, owner.p, h(99), claims, signed.payload, signed.cose),
    ).toThrow();
    for (const patch of [
      { custodyDigest: h(99) },
      { notificationOccurrenceId: id(99) },
      { endpointRevision: '3' },
      { workerProfileDigest: h(99) },
      { authoritySnapshotDigest: h(99) },
      { recordedAtMs: 10000 },
    ])
      expect(() =>
        verifyNotificationWorkerReceipt(
          family,
          owner.p,
          owner.pins.signedProfileDigest,
          { ...claims, ...patch },
          signed.payload,
          signed.cose,
        ),
      ).toThrow();
  }
  const oSigned = signNotificationClaim(
    'NotificationOccurrenceReceiptV1',
    signer.privateKey,
    signer.spki,
    o,
  );
  expect(() =>
    verifyNotificationClaim(
      'NotificationDeliveryRequestedReceiptV1',
      signer.spki,
      oSigned.payload,
      oSigned.cose,
    ),
  ).toThrow();
  expect(() =>
    verifyNotificationWorkerReceipt(
      'NotificationOccurrenceReceiptV1',
      { ...n.p, subscriptionId: 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1' },
      n.pins.signedProfileDigest,
      o,
      oSigned.payload,
      oSigned.cose,
    ),
  ).toThrow();
});
it('request publication references the exact earlier occurrence while retaining separate operation and receipt identities', () => {
  const n = installed(),
    c = installed(profile(true)),
    o = occurrence(n.p, n.pins.signedProfileDigest),
    r = request(o, c.pins.signedProfileDigest);
  expect(() => assertNotificationDeliveryRequestOriginal(r, o)).not.toThrow();
  for (const patch of [
    { receiptId: o.receiptId },
    { operationId: o.operationId },
    { recordedAtMs: 1999 },
    { keyPreparationId: id(90) },
    { payloadObjectId: id(90) },
    { sourceReceiptDigest: h(90) },
    { sourceEventId: id(90) },
    { encryptedObjectDigest: h(90) },
    { keyId: h(90) },
    { occurrenceReceiptDigest: h(90) },
    { notificationId: id(90) },
  ])
    expect(() => assertNotificationDeliveryRequestOriginal({ ...r, ...patch }, o)).toThrow();
  expect(() =>
    encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', { ...r, sequence: '2' }),
  ).toThrow();
  expect(() =>
    encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', {
      ...r,
      recordedAtMs: 253402300800000,
    }),
  ).toThrow();
  expect(() =>
    encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', {
      ...r,
      payloadDigest: h(91),
    }),
  ).toThrow();
  expect(() =>
    encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', {
      ...r,
      sourceId: 'urn:openpc:service:' + r.sourceId,
    }),
  ).toThrow();
  expect(notificationDeliveryRequestedEnvelope(r)).toMatchObject({
    id: r.eventId,
    source: `urn:openpc:service:${r.sourceId}`,
    subject: `urn:openpc:notification-occurrence:${r.notificationOccurrenceId}`,
    time: '1970-01-01T00:00:03.000000Z',
    correlationid: r.operationId,
    causationid: r.sourceEventId,
    sequence: '1',
    data: {
      notificationOccurrenceId: `urn:openpc:notification-occurrence:${r.notificationOccurrenceId}`,
      endpointId: `urn:openpc:resource:${r.endpointId}`,
      templateDigest: r.templateDigest,
      payloadDigest: r.payloadDigest,
    },
  });
});
it('rejects malformed and cross-purpose wire, wrong signer, aliases, unknown fields and trailing bytes', () => {
  const i = installed(),
    o = occurrence(i.p, i.pins.signedProfileDigest),
    r = request(o, h(40));
  for (const [family, claims] of [
    ['NotificationWorkerProfileV1', i.p],
    ['NotificationOccurrenceReceiptV1', o],
    ['NotificationDeliveryRequestedReceiptV1', r],
  ] as const) {
    const payload = encodeNotificationClaim(family, claims);
    expect(decodeNotificationClaim(family, payload)).toEqual(claims);
    expect(() =>
      decodeNotificationClaim(family, Buffer.concat([payload, Buffer.from([0])])),
    ).toThrow();
    const untrusted = { ...claims, readiness: true };
    expect(() => encodeNotificationClaim(family, untrusted)).toThrow();
    const map = decodeCbor(payload);
    if (!(map instanceof Map)) throw new Error('map');
    map.set(0, Buffer.alloc(32));
    expect(() => decodeNotificationClaim(family, encodeCbor(map))).toThrow();
  }
  const signed = signNotificationClaim(
    'NotificationOccurrenceReceiptV1',
    signer.privateKey,
    signer.spki,
    o,
  );
  expect(() =>
    verifyNotificationClaim(
      'NotificationOccurrenceReceiptV1',
      issuer.spki,
      signed.payload,
      signed.cose,
    ),
  ).toThrow();
  const corrupted = Buffer.from(signed.cose);
  corrupted[corrupted.length - 1]! ^= 1;
  expect(() =>
    verifyNotificationClaim(
      'NotificationOccurrenceReceiptV1',
      signer.spki,
      signed.payload,
      corrupted,
    ),
  ).toThrow();
  const data = {
    notificationOccurrenceId: o.notificationOccurrenceId,
    endpointId: o.endpointId,
    templateDigest: o.templateDigest,
    payloadDigest: o.payloadDigest,
  };
  expect(() =>
    encodeNotificationDeliveryRequestedData({
      ...data,
      endpointId: `urn:openpc:resource:${o.endpointId}`,
    }),
  ).toThrow();
  expect(() =>
    encodeNotificationDeliveryRequestedData({ ...data, plaintext: 'secret' } as typeof data),
  ).toThrow();
});

function startedFixture() {
  const worker = {
    ...profile(),
    subscriptionId: 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1' as const,
  };
  const requested = request(occurrence(profile(), h(50)), h(51));
  const started: import('./codec.js').NotificationDeliveryStartedReceiptClaims = {
    environmentId: worker.environmentId,
    participantId: worker.participantId,
    privacyDomainId: worker.privacyDomainId,
    receiptId: id(30),
    operationId: id(31),
    attemptId: id(32),
    notificationOccurrenceId: requested.notificationOccurrenceId,
    payloadObjectId: requested.payloadObjectId,
    keyPreparationId: requested.keyPreparationId,
    sourceEventId: requested.eventId,
    sourceDataDigest: requested.dataDigest,
    sourceReceiptDigest: digest(
      encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', requested),
    ),
    routingProfileDigest: worker.routingProfileDigest,
    workerProfileDigest: h(52),
    authoritySnapshotDigest: h(53),
    endpointId: requested.endpointId,
    endpointRevision: requested.endpointRevision,
    templateDigest: requested.templateDigest,
    payloadDigest: requested.payloadDigest,
    encryptedObjectDigest: requested.encryptedObjectDigest,
    keyId: requested.keyId,
    signedChannelProfileDigest: h(54),
    attemptDigest: h(55),
    contextDigest: h(56),
    attemptNumber: 1,
    startedAtMs: 4000,
    deadlineAtMs: 5000,
    deliveryRevision: '1',
    beforeStateDigest: h(57),
    afterStateDigest: h(58),
    signerKeyId: evidenceKeyId(signer.spki),
  };
  return { worker, requested, started };
}
it('binds STARTED to the exact delivery subscriber and original published request without widening publisher roles', async () => {
  const { verifyNotificationDeliveryStartedReceipt, assertNotificationDeliveryStartOriginal } =
    await import('./worker-contract.js');
  const { worker, requested, started } = startedFixture();
  const signed = signNotificationClaim(
    'NotificationDeliveryStartedReceiptV1',
    signer.privateKey,
    signer.spki,
    started,
  );
  expect(
    verifyNotificationDeliveryStartedReceipt(
      worker,
      started.workerProfileDigest,
      started,
      signed.payload,
      signed.cose,
    ),
  ).toEqual(started);
  expect(() => assertNotificationDeliveryStartOriginal(started, requested)).not.toThrow();
  for (const wrong of [
    profile(),
    profile(true),
    { ...worker, processRole: 'ROLE-CONTROL-WORKER' as const },
    { ...worker, participantId: id(90) },
    { ...worker, privacyDomainId: id(90) },
    { ...worker, routingProfileDigest: h(90) },
    { ...worker, validFromMs: 4001 },
    { ...worker, validUntilMs: 4999 },
    { ...worker, receiptSignerSpki: keys().spki.toString('hex') },
  ])
    expect(() =>
      verifyNotificationDeliveryStartedReceipt(
        wrong,
        started.workerProfileDigest,
        started,
        signed.payload,
        signed.cose,
      ),
    ).toThrow();
  expect(() =>
    verifyNotificationDeliveryStartedReceipt(worker, h(90), started, signed.payload, signed.cose),
  ).toThrow();
  expect(() =>
    verifyNotificationWorkerReceipt(
      'NotificationOccurrenceReceiptV1',
      worker,
      h(50),
      occurrence(worker, h(50)),
      signed.payload,
      signed.cose,
    ),
  ).toThrow();
  expect(() =>
    verifyNotificationClaim(
      'NotificationDeliveryReceiptV1',
      signer.spki,
      signed.payload,
      signed.cose,
    ),
  ).toThrow();
});
it('rejects changed START operation, original source, payload, endpoint and framing without accepting matching caller labels', async () => {
  const { verifyNotificationDeliveryStartedReceipt, assertNotificationDeliveryStartOriginal } =
    await import('./worker-contract.js');
  const { worker, requested, started } = startedFixture();
  const signed = signNotificationClaim(
    'NotificationDeliveryStartedReceiptV1',
    signer.privateKey,
    signer.spki,
    started,
  );
  for (const [name, original] of Object.entries(started)) {
    const replacement =
      typeof original === 'number'
        ? original + 1
        : original.startsWith('sha256:')
          ? h(91)
          : original.includes('-7000-')
            ? id(91)
            : original === '1'
              ? '2'
              : 'different';
    expect(
      () =>
        verifyNotificationDeliveryStartedReceipt(
          worker,
          started.workerProfileDigest,
          { ...started, [name]: replacement },
          signed.payload,
          signed.cose,
        ),
      name,
    ).toThrow();
  }
  for (const change of [
    { sourceEventId: id(90) },
    { sourceDataDigest: h(90) },
    { sourceReceiptDigest: h(90) },
    { operationId: requested.operationId },
    { receiptId: requested.receiptId },
    { payloadObjectId: id(90) },
    { endpointRevision: '3' },
    { encryptedObjectDigest: h(90) },
    { keyId: h(90) },
    { startedAtMs: 2999 },
  ])
    expect(() =>
      assertNotificationDeliveryStartOriginal({ ...started, ...change }, requested),
    ).toThrow();
  for (const change of [
    { attemptNumber: 0 },
    { attemptNumber: 7 },
    { deadlineAtMs: 4000 },
    { deadlineAtMs: 34001 },
    { deliveryRevision: '18446744073709551615' },
    { beforeStateDigest: started.afterStateDigest },
    { ready: true },
  ])
    expect(() =>
      encodeNotificationClaim('NotificationDeliveryStartedReceiptV1', { ...started, ...change }),
    ).toThrow();
  const map = decodeCbor(signed.payload) as Map<number, import('../canonical-cbor.js').CborValue>;
  map.set(999, 1);
  expect(() =>
    decodeNotificationClaim('NotificationDeliveryStartedReceiptV1', encodeCbor(map)),
  ).toThrow();
  expect(() =>
    decodeNotificationClaim(
      'NotificationDeliveryStartedReceiptV1',
      Buffer.concat([signed.payload, Buffer.from([0])]),
    ),
  ).toThrow();
  const tampered = Buffer.from(signed.cose);
  tampered[tampered.length - 1]! ^= 1;
  expect(() =>
    verifyNotificationDeliveryStartedReceipt(
      worker,
      started.workerProfileDigest,
      started,
      signed.payload,
      tampered,
    ),
  ).toThrow();
});

function cancellationFixture(): NotificationDeliveryCancellationReceiptClaims {
  const { worker, started } = startedFixture();
  return {
    environmentId: worker.environmentId,
    participantId: worker.participantId,
    privacyDomainId: worker.privacyDomainId,
    receiptId: id(80),
    operationId: id(81),
    notificationOccurrenceId: started.notificationOccurrenceId,
    payloadDigest: started.payloadDigest,
    sourceEventId: started.sourceEventId,
    sourceReceiptDigest: started.sourceReceiptDigest,
    workerProfileDigest: started.workerProfileDigest,
    routingProfileDigest: worker.routingProfileDigest,
    authoritySnapshotDigest: h(82),
    endpointId: started.endpointId,
    endpointRevision: '2',
    causeOperationId: id(83),
    causeAction: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
    causeProfileDigest: businessTransitionProfileForOperation(
      'CFG-OP-UPDATE-NOTIFICATION-ENDPOINT',
    )!.profileDigest,
    causeReceiptDigest: h(84),
    causeBeforeStateDigest: h(85),
    causeAfterStateDigest: h(86),
    causeEndpointRevision: '3',
    deliveryRevision: '2',
    beforeStateDigest: h(87),
    afterStateDigest: h(88),
    beforeDeliveryState: 'PENDING',
    afterDeliveryState: 'CANCELLED',
    attemptCount: 0,
    disposition: 'CANCELLED_BEFORE_START',
    recordedAtMs: 4000,
    signerKeyId: evidenceKeyId(signer.spki),
  };
}
it('cancellation receipts retain pre-start, no-effect retry and unresolved-original dispositions under a separate purpose', () => {
  const { worker } = startedFixture();
  const base = cancellationFixture();
  for (const transition of [
    {},
    { beforeDeliveryState: 'RETRY_WAIT', attemptCount: 1, disposition: 'PREVENT_LATER_ATTEMPTS' },
    {
      beforeDeliveryState: 'STARTED',
      afterDeliveryState: 'STARTED',
      attemptCount: 1,
      disposition: 'RECONCILE_ORIGINAL',
    },
    {
      beforeDeliveryState: 'AMBIGUOUS',
      afterDeliveryState: 'AMBIGUOUS',
      attemptCount: 6,
      disposition: 'RECONCILE_ORIGINAL',
    },
  ]) {
    const claims = { ...base, ...transition } as NotificationDeliveryCancellationReceiptClaims;
    const signed = signNotificationClaim(
      'NotificationDeliveryCancellationReceiptV1',
      signer.privateKey,
      signer.spki,
      claims,
    );
    expect(
      verifyNotificationDeliveryCancellationReceipt(
        worker,
        claims.workerProfileDigest,
        claims,
        signed.payload,
        signed.cose,
      ),
    ).toEqual(claims);
    expect(() =>
      verifyNotificationClaim(
        'NotificationDeliveryStartedReceiptV1',
        signer.spki,
        signed.payload,
        signed.cose,
      ),
    ).toThrow();
    for (const change of [
      { causeOperationId: id(90) },
      { causeReceiptDigest: h(91) },
      { causeBeforeStateDigest: h(92) },
      { endpointId: id(93) },
      { participantId: id(94) },
      { sourceReceiptDigest: h(95) },
    ])
      expect(() =>
        verifyNotificationDeliveryCancellationReceipt(
          worker,
          claims.workerProfileDigest,
          { ...claims, ...change },
          signed.payload,
          signed.cose,
        ),
      ).toThrow();
    for (const invalid of [
      profile(),
      profile(true),
      { ...worker, receiptSignerSpki: issuer.spki.toString('hex') },
      { ...worker, validUntilMs: 4000 },
    ])
      expect(() =>
        verifyNotificationDeliveryCancellationReceipt(
          invalid,
          claims.workerProfileDigest,
          claims,
          signed.payload,
          signed.cose,
        ),
      ).toThrow();
  }
});
it('cancellation wire rejects ACK, borrowed operation, skipped revisions, fabricated no-effect and terminal-state rewrites', () => {
  const p = cancellationFixture();
  for (const change of [
    { causeAction: 'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1' },
    { causeProfileDigest: h(99) },
    { operationId: p.causeOperationId },
    { causeEndpointRevision: '4' },
    { deliveryRevision: '18446744073709551615' },
    { beforeStateDigest: p.afterStateDigest },
    { causeBeforeStateDigest: p.causeAfterStateDigest },
    { attemptCount: 1 },
    { attemptCount: 7 },
    { beforeDeliveryState: 'DELIVERED' },
    { beforeDeliveryState: 'STARTED', attemptCount: 1 },
    { beforeDeliveryState: 'AMBIGUOUS', attemptCount: 1, disposition: 'RECONCILE_ORIGINAL' },
    { disposition: 'PREVENT_LATER_ATTEMPTS' },
    { afterDeliveryState: 'STARTED' },
    { noEffect: true },
  ])
    expect(() =>
      encodeNotificationClaim('NotificationDeliveryCancellationReceiptV1', {
        ...p,
        ...change,
      } as NotificationDeliveryCancellationReceiptClaims),
    ).toThrow();
});

function outcomeFixture(): NotificationDeliveryOutcomeReceiptClaims {
  const { started } = startedFixture();
  return {
    environmentId: started.environmentId,
    participantId: started.participantId,
    privacyDomainId: started.privacyDomainId,
    receiptId: id(101),
    operationId: id(102),
    notificationOccurrenceId: started.notificationOccurrenceId,
    attemptId: started.attemptId,
    startOperationId: started.operationId,
    startReceiptDigest: h(103),
    dispatchClaimDigest: h(104),
    sourceReceiptDigest: started.sourceReceiptDigest,
    workerProfileDigest: started.workerProfileDigest,
    routingProfileDigest: started.routingProfileDigest,
    authoritySnapshotDigest: h(105),
    endpointId: started.endpointId,
    endpointRevision: started.endpointRevision,
    payloadDigest: started.payloadDigest,
    gatewayReceiptId: id(106),
    gatewayReceiptDigest: h(107),
    gatewayCoseDigest: h(108),
    observationDigest: h(109),
    deliveryRevision: '2',
    beforeStateDigest: h(110),
    afterStateDigest: h(111),
    outcome: 'DELIVERED',
    beforeDeliveryState: 'STARTED',
    afterDeliveryState: 'DELIVERED',
    attemptCount: 1,
    attemptLimit: 6,
    nextAttemptAtMs: 0,
    cancelRequested: 'NO',
    observedAtMs: 4500,
    recordedAtMs: 5000,
    signerKeyId: started.signerKeyId,
  };
}
it('separates original gateway truth from the Control outcome signature and exact state/cancellation binding', () => {
  const { worker } = startedFixture();
  const base = outcomeFixture();
  const transitions: Partial<NotificationDeliveryOutcomeReceiptClaims>[] = [
    {},
    { cancelRequested: 'YES' },
    {
      outcome: 'AMBIGUOUS',
      afterDeliveryState: 'AMBIGUOUS',
      beforeDeliveryState: 'AMBIGUOUS',
      cancelRequested: 'YES',
    },
    { outcome: 'PERMANENT_FAILURE', afterDeliveryState: 'FAILED' },
    { outcome: 'RETRYABLE_NO_EFFECT', afterDeliveryState: 'CANCELLED', cancelRequested: 'YES' },
    { outcome: 'RETRYABLE_NO_EFFECT', afterDeliveryState: 'FAILED', attemptLimit: 0 },
    { outcome: 'RETRYABLE_NO_EFFECT', afterDeliveryState: 'FAILED', attemptCount: 6 },
    ...[5000, 30000, 120000, 600000, 1800000].map((delay, n) => ({
      outcome: 'RETRYABLE_NO_EFFECT' as const,
      afterDeliveryState: 'RETRY_WAIT' as const,
      attemptCount: n + 1,
      nextAttemptAtMs: base.observedAtMs + delay,
    })),
  ];
  for (const patch of transitions) {
    const claims = { ...base, ...patch };
    const signed = signNotificationClaim(
      'NotificationDeliveryOutcomeReceiptV1',
      signer.privateKey,
      signer.spki,
      claims,
    );
    expect(
      verifyNotificationDeliveryOutcomeReceipt(
        worker,
        claims.workerProfileDigest,
        claims,
        signed.payload,
        signed.cose,
      ),
    ).toEqual(claims);
    for (const family of [
      'NotificationDeliveryReceiptV1',
      'NotificationDeliveryStartedReceiptV1',
      'NotificationDeliveryCancellationReceiptV1',
    ] as const)
      expect(() =>
        verifyNotificationClaim(family, signer.spki, signed.payload, signed.cose),
      ).toThrow();
    for (const key of [
      'startReceiptDigest',
      'dispatchClaimDigest',
      'gatewayReceiptDigest',
      'gatewayCoseDigest',
      'observationDigest',
      'beforeStateDigest',
      'afterStateDigest',
    ] as const)
      expect(() =>
        verifyNotificationDeliveryOutcomeReceipt(
          worker,
          claims.workerProfileDigest,
          { ...claims, [key]: h(150) },
          signed.payload,
          signed.cose,
        ),
      ).toThrow();
  }
  const signed = signNotificationClaim(
    'NotificationDeliveryOutcomeReceiptV1',
    signer.privateKey,
    signer.spki,
    base,
  );
  for (const wrong of [
    profile(),
    profile(true),
    { ...worker, privacyDomainId: id(150) },
    { ...worker, validUntilMs: base.recordedAtMs },
    { ...worker, receiptSignerSpki: keys().spki.toString('hex') },
  ])
    expect(() =>
      verifyNotificationDeliveryOutcomeReceipt(
        wrong,
        base.workerProfileDigest,
        base,
        signed.payload,
        signed.cose,
      ),
    ).toThrow();
});
it('rejects forged outcome transitions, retry schedule resets and effect/cancellation confusion', () => {
  const base = outcomeFixture();
  for (const patch of [
    { outcome: 'ABSENT' },
    { afterDeliveryState: 'CANCELLED', cancelRequested: 'YES' },
    { attemptCount: 0 },
    { attemptCount: 7 },
    { attemptLimit: 7 },
    { beforeDeliveryState: 'PENDING' },
    { nextAttemptAtMs: 9500 },
    { recordedAtMs: base.observedAtMs - 1 },
    { deliveryRevision: '18446744073709551615' },
    { beforeStateDigest: base.afterStateDigest },
    { receiptId: base.gatewayReceiptId },
    { operationId: base.startOperationId },
    { outcome: 'RETRYABLE_NO_EFFECT', afterDeliveryState: 'RETRY_WAIT', nextAttemptAtMs: 9499 },
    {
      outcome: 'RETRYABLE_NO_EFFECT',
      afterDeliveryState: 'RETRY_WAIT',
      nextAttemptAtMs: 9500,
      cancelRequested: 'YES',
    },
    { outcome: 'AMBIGUOUS', afterDeliveryState: 'CANCELLED', cancelRequested: 'YES' },
  ])
    expect(() =>
      encodeNotificationClaim('NotificationDeliveryOutcomeReceiptV1', {
        ...base,
        ...patch,
      } as NotificationDeliveryOutcomeReceiptClaims),
    ).toThrow();
});
