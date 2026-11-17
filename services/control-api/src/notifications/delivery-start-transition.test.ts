import { generateKeyPairSync } from 'node:crypto';
import { afterEach, expect, it, vi } from 'vitest';
import {
  encodeNotificationClaim,
  encodeNotificationDeliveryRequestedData,
  evidenceKeyId,
  signNotificationClaim,
  type NotificationWorkerProfileClaims,
  type NotificationDeliveryRequestedReceiptClaims,
  type NotificationDeliveryStartedReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  notificationIdempotencyDigest,
  notificationScopeDigest,
  verifyInstalledNotificationChannel,
  type AdapterCallContextV1,
  type NotificationDeliveryAttemptBinding,
  type NotificationGatewayTransportV1,
} from './gateway-contracts.js';
import { initialDeliverySnapshot, planNotificationDelivery } from './delivery-policy.js';
import { notificationDeliveryStateDigest } from './delivery-start-contract.js';
import { validateNotificationWorkerInstallation } from './worker-installation-contract.js';
import {
  validateNotificationDeliveryStartTransition,
  encodeNotificationDeliveryStartTransition,
  decodeNotificationDeliveryStartTransition,
  NotificationDeliveryStartTransitionError,
} from './delivery-start-transition.js';
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = (n: number) => sha256(String(n));
function fixture() {
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const issuerSpki = issuer.publicKey.export({ type: 'spki', format: 'der' });
  const signerSpki = signer.publicKey.export({ type: 'spki', format: 'der' });
  const transport: NotificationGatewayTransportV1 = {
    protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
    channel: 'WEBHOOK',
    destinationRef: `urn:openpc:resource:${id(4)}`,
    credentialRef: `urn:openpc:resource:${id(5)}`,
    endpoint: 'https://gateway.test/',
    addresses: ['127.0.0.1'],
    serverSpkiDigest: h(1),
    requestTimeoutMs: 1000,
    maxPayloadBytes: 1024,
  };
  const profile = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(3),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 10000,
    transportProfileDigest: sha256(transport),
    receiptSignerSpki: signerSpki.toString('hex'),
    issuerKeyId: evidenceKeyId(issuerSpki),
  };
  const signed = signNotificationClaim(
    'NotificationChannelProfileV1',
    issuer.privateKey.export({ type: 'pkcs8', format: 'der' }),
    issuerSpki,
    profile,
  );
  const channel = verifyInstalledNotificationChannel(
    {
      environmentId: 'test',
      participantId: id(1),
      privacyDomainId: id(2),
      signedProfileDigest: sha256(signed.cose),
      issuerSpkiHex: issuerSpki.toString('hex'),
    },
    { transport, payloadHex: signed.payload.toString('hex'), coseHex: signed.cose.toString('hex') },
  );
  const source: NotificationDeliveryRequestedReceiptClaims = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    receiptId: id(10),
    operationId: id(11),
    notificationId: id(12),
    notificationOccurrenceId: id(13),
    payloadObjectId: id(14),
    keyPreparationId: id(15),
    sourceEventId: id(16),
    sourceDataDigest: h(2),
    sourceReceiptDigest: h(3),
    routingProfileDigest: h(4),
    workerProfileDigest: h(5),
    authoritySnapshotDigest: h(6),
    custodyDigest: h(7),
    endpointId: id(17),
    endpointRevision: '1',
    templateDigest: h(8),
    payloadDigest: h(9),
    encryptedObjectDigest: h(10),
    keyId: h(11),
    recordedAtMs: 2000,
    signerKeyId: evidenceKeyId(signerSpki),
    occurrenceReceiptDigest: h(12),
    eventId: id(18),
    sourceId: id(19),
    sequence: '1',
    dataDigest: '',
  };
  source.dataDigest = sha256(
    encodeNotificationDeliveryRequestedData({
      notificationOccurrenceId: source.notificationOccurrenceId,
      endpointId: source.endpointId,
      templateDigest: source.templateDigest,
      payloadDigest: source.payloadDigest,
    }),
  );
  const attempt: NotificationDeliveryAttemptBinding = {
    version: 'NotificationDeliveryAttemptV1',
    participantId: id(1),
    privacyDomainId: id(2),
    notificationOccurrenceId: `urn:openpc:resource:${source.notificationOccurrenceId}`,
    endpointId: `urn:openpc:resource:${source.endpointId}`,
    endpointRevision: '1',
    channel: transport.channel,
    destinationRef: transport.destinationRef,
    credentialRef: transport.credentialRef,
    channelProfileDigest: channel.signedProfileDigest,
    templateDigest: source.templateDigest,
    payloadDigest: source.payloadDigest,
    payloadBytes: 100,
    attemptId: id(20),
    attemptNumber: 1,
    startedAtMs: 3000,
    deadlineAtMs: 4000,
  };
  const context: AdapterCallContextV1 = {
    authorizationDigest: h(13),
    profileDigest: channel.signedProfileDigest,
    authorizationContextId: id(21),
    authorizationContextEpoch: 1,
    accessClassIds: ['ACCESS-NOTIFICATION'],
    scopeDigest: notificationScopeDigest(attempt),
    deadlineAt: new Date(4000).toISOString(),
    idempotencyDigest: notificationIdempotencyDigest(attempt),
    occurrenceId: source.notificationOccurrenceId,
    auditCorrelationId: id(22),
    cancellation: {
      mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION',
      occurrenceId: source.notificationOccurrenceId,
    },
    reconciliation: { mode: 'EXACT_OCCURRENCE', occurrenceId: source.notificationOccurrenceId },
  };
  const before = initialDeliverySnapshot(
    {
      participantId: id(1),
      privacyDomainId: id(2),
      notificationOccurrenceId: source.notificationOccurrenceId,
      payloadDigest: source.payloadDigest,
    },
    6,
    2000,
  );
  const after = planNotificationDelivery(before, 6, 3000).next;
  const receipt: NotificationDeliveryStartedReceiptClaims = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    receiptId: id(23),
    operationId: context.auditCorrelationId,
    attemptId: attempt.attemptId,
    notificationOccurrenceId: source.notificationOccurrenceId,
    payloadObjectId: source.payloadObjectId,
    keyPreparationId: source.keyPreparationId,
    sourceEventId: source.eventId,
    sourceDataDigest: source.dataDigest,
    sourceReceiptDigest: sha256(
      encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', source),
    ),
    routingProfileDigest: source.routingProfileDigest,
    workerProfileDigest: h(14),
    authoritySnapshotDigest: context.authorizationDigest,
    endpointId: source.endpointId,
    endpointRevision: source.endpointRevision,
    templateDigest: source.templateDigest,
    payloadDigest: source.payloadDigest,
    encryptedObjectDigest: source.encryptedObjectDigest,
    keyId: source.keyId,
    signedChannelProfileDigest: channel.signedProfileDigest,
    attemptDigest: sha256(attempt),
    contextDigest: sha256(context),
    attemptNumber: 1,
    startedAtMs: 3000,
    deadlineAtMs: 4000,
    deliveryRevision: '1',
    beforeStateDigest: notificationDeliveryStateDigest(before, '1'),
    afterStateDigest: notificationDeliveryStateDigest(after, '2'),
    signerKeyId: evidenceKeyId(signerSpki),
  };
  const workerProfile: NotificationWorkerProfileClaims = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(30),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 10000,
    sourceId: id(31),
    serviceId: 'LS-NOTIFICATION',
    processRole: 'ROLE-NOTIFICATION-WORKER',
    subscriptionId: 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1',
    principalId: id(32),
    workloadCredentialId: id(33),
    workloadEpoch: '1',
    workloadId: 'urn:openpc:workload:notification',
    producerTrustDigest: h(15),
    routingProfileDigest: source.routingProfileDigest,
    kmsInstallationDigest: h(16),
    receiptSignerSpki: signerSpki.toString('hex'),
    issuerKeyId: evidenceKeyId(issuerSpki),
  };
  const workerSigned = signNotificationClaim(
    'NotificationWorkerProfileV1',
    issuer.privateKey.export({ type: 'pkcs8', format: 'der' }),
    issuerSpki,
    workerProfile,
  );
  const workerInstallation = {
    pins: {
      issuerSpkiHex: issuerSpki.toString('hex'),
      signedProfileDigest: sha256(workerSigned.cose),
      environmentId: workerProfile.environmentId,
      participantId: workerProfile.participantId,
      privacyDomainId: workerProfile.privacyDomainId,
      profileId: workerProfile.profileId,
      revision: workerProfile.revision,
      serviceId: workerProfile.serviceId,
      processRole: workerProfile.processRole,
      subscriptionId: workerProfile.subscriptionId,
      principalId: workerProfile.principalId,
      workloadCredentialId: workerProfile.workloadCredentialId,
      workloadEpoch: workerProfile.workloadEpoch,
      workloadId: workerProfile.workloadId,
      workloadKeyDigest: h(17),
    },
    signed: {
      payloadHex: workerSigned.payload.toString('hex'),
      coseHex: workerSigned.cose.toString('hex'),
    },
    installationReference: 'local-notification-delivery-worker',
  };
  receipt.workerProfileDigest = workerInstallation.pins.signedProfileDigest;
  function sign(claims: NotificationDeliveryStartedReceiptClaims) {
    const wire = signNotificationClaim(
      'NotificationDeliveryStartedReceiptV1',
      signer.privateKey.export({ type: 'pkcs8', format: 'der' }),
      signerSpki,
      claims,
    );
    return { payloadHex: wire.payload.toString('hex'), coseHex: wire.cose.toString('hex') };
  }
  const value = {
    schema: 'pc.notification.delivery-start-transition.v1' as const,
    sourceOperationId: source.operationId,
    workerInstallation,
    workerInstallationDigest: validateNotificationWorkerInstallation(workerInstallation, 3000)
      .installationDigest,
    workerAuthorityDigest: receipt.authoritySnapshotDigest,
    receipt,
    source,
    channel,
    attempt,
    context,
    before,
    after,
    configuredLimit: 6,
    ...sign(receipt),
  };
  return { value, sign, issuer, issuerSpki, workerProfile };
}
afterEach(() => vi.useRealTimers());

it('retains the exact signed STARTED proof, closed JSON and declared persistence bytes', () => {
  const { value } = fixture();
  const prior = structuredClone(value);
  const encoded = encodeNotificationDeliveryStartTransition(value);
  expect(encoded.transition).toEqual(prior);
  expect(encoded.transitionBytes).toEqual(Buffer.from(canonicalJson(prior)));
  expect(encoded.transitionDigest).toBe(sha256(encoded.transitionBytes));
  expect(encoded.receiptPayload).toEqual(Buffer.from(prior.payloadHex, 'hex'));
  expect(encoded.coseSign1).toEqual(Buffer.from(prior.coseHex, 'hex'));
  expect(encoded.receiptDigest).toBe(sha256(encoded.receiptPayload));
  expect(
    decodeNotificationDeliveryStartTransition(encoded.transitionBytes, encoded.transitionDigest),
  ).toEqual(prior);
  expect(value).toEqual(prior);
});

it('detaches every mutable input and returned buffer before persistence can await', async () => {
  const { value } = fixture();
  const original = structuredClone(value);
  const encoded = encodeNotificationDeliveryStartTransition(value);
  value.before.attemptLimit = 0;
  value.workerInstallation.pins.principalId = id(99);
  value.context.accessClassIds.push('ACCESS-OTHER');
  value.payloadHex = '00';
  encoded.transitionBytes.fill(0);
  encoded.receiptPayload.fill(0);
  encoded.coseSign1.fill(0);
  await Promise.resolve();
  expect(encoded.transition).toEqual(original);
  expect(Object.isFrozen(encoded)).toBe(true);
  for (const v of [
    encoded.transition,
    encoded.transition.before,
    encoded.transition.workerInstallation.pins,
    encoded.transition.context.accessClassIds,
    encoded.transition.channel.transport.addresses,
  ]) {
    expect(Object.isFrozen(v)).toBe(true);
  }
  const wire = encoded.transitionBytes;
  const decoded = decodeNotificationDeliveryStartTransition(wire, encoded.transitionDigest);
  wire.fill(0);
  expect(decoded).toEqual(original);
  expect(encoded.receiptPayload.toString('hex')).toBe(original.payloadHex);
  expect(encoded.coseSign1.toString('hex')).toBe(original.coseHex);
});

it('reads original history after profile expiry without refreshing or signing authority', () => {
  const { value } = fixture();
  const encoded = encodeNotificationDeliveryStartTransition(value);
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2099-01-01T00:00:00Z'));
  expect(
    decodeNotificationDeliveryStartTransition(encoded.transitionBytes, encoded.transitionDigest),
  ).toEqual(value);
});

type FixtureValue = ReturnType<typeof fixture>['value'];
const mutations: [string, (v: FixtureValue) => void][] = [
  [
    'source operation',
    (v) => {
      v.sourceOperationId = id(99);
    },
  ],
  [
    'original source',
    (v) => {
      v.source.operationId = id(99);
      v.sourceOperationId = id(99);
    },
  ],
  [
    'source event',
    (v) => {
      v.source.eventId = id(99);
    },
  ],
  [
    'source wire namespace',
    (v) => {
      v.source.notificationOccurrenceId = `urn:openpc:resource:${id(13)}`;
    },
  ],
  [
    'source signer',
    (v) => {
      v.source.signerKeyId = h(99);
    },
  ],
  [
    'installation digest',
    (v) => {
      v.workerInstallationDigest = h(99);
    },
  ],
  [
    'worker actor',
    (v) => {
      v.workerInstallation.pins.principalId = id(99);
    },
  ],
  [
    'worker credential',
    (v) => {
      v.workerInstallation.pins.workloadCredentialId = id(99);
    },
  ],
  [
    'worker epoch',
    (v) => {
      v.workerInstallation.pins.workloadEpoch = '2';
    },
  ],
  [
    'worker role',
    (v) => {
      v.workerInstallation.pins.processRole = 'ROLE-CONTROL-WORKER';
    },
  ],
  [
    'publisher subscription',
    (v) => {
      v.workerInstallation.pins.subscriptionId = 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1';
    },
  ],
  [
    'worker scope',
    (v) => {
      v.workerInstallation.pins.privacyDomainId = id(99);
    },
  ],
  [
    'worker authority',
    (v) => {
      v.workerAuthorityDigest = h(99);
    },
  ],
  [
    'worker profile',
    (v) => {
      v.receipt.workerProfileDigest = h(99);
    },
  ],
  [
    'operation',
    (v) => {
      v.receipt.operationId = id(99);
    },
  ],
  [
    'receipt identity',
    (v) => {
      v.receipt.receiptId = id(99);
    },
  ],
  [
    'receipt scope',
    (v) => {
      v.receipt.participantId = id(99);
    },
  ],
  [
    'receipt revision',
    (v) => {
      v.receipt.deliveryRevision = '2';
    },
  ],
  [
    'revision overflow',
    (v) => {
      v.receipt.deliveryRevision = '18446744073709551615';
    },
  ],
  [
    'channel profile',
    (v) => {
      v.channel = { ...v.channel, signedProfileDigest: h(99) };
    },
  ],
  [
    'channel transport',
    (v) => {
      v.channel = structuredClone(v.channel);
      v.channel.transport.endpoint = 'https://other.test/';
    },
  ],
  [
    'attempt identity',
    (v) => {
      v.attempt.attemptId = id(99);
    },
  ],
  [
    'attempt number',
    (v) => {
      v.attempt.attemptNumber = 2;
    },
  ],
  [
    'attempt scope',
    (v) => {
      v.attempt.privacyDomainId = id(99);
    },
  ],
  [
    'attempt bytes',
    (v) => {
      v.attempt.payloadBytes = 101;
    },
  ],
  [
    'attempt endpoint',
    (v) => {
      v.attempt.endpointRevision = '2';
    },
  ],
  [
    'context authority',
    (v) => {
      v.context.authorizationDigest = h(99);
    },
  ],
  [
    'context identity',
    (v) => {
      v.context.authorizationContextId = id(99);
    },
  ],
  [
    'context scope',
    (v) => {
      v.context.scopeDigest = h(99);
    },
  ],
  [
    'before state',
    (v) => {
      v.before.cancelRequested = true;
    },
  ],
  [
    'after state',
    (v) => {
      v.after.attemptLimit = 5;
    },
  ],
  [
    'lower configured limit',
    (v) => {
      v.configuredLimit = 5;
    },
  ],
  [
    'zero configured limit',
    (v) => {
      v.configuredLimit = 0;
    },
  ],
  [
    'invalid configured limit',
    (v) => {
      v.configuredLimit = 101;
    },
  ],
  [
    'fractional configured limit',
    (v) => {
      v.configuredLimit = 5.5;
    },
  ],
  [
    'original payload',
    (v) => {
      v.payloadHex = '00' + v.payloadHex.slice(2);
    },
  ],
  [
    'original signature',
    (v) => {
      v.coseHex = v.coseHex.slice(0, -2) + (v.coseHex.endsWith('00') ? '01' : '00');
    },
  ],
];
it.each(mutations)('rejects changed %s', (_name, mutate) => {
  const { value } = fixture();
  mutate(value);
  expect(() => validateNotificationDeliveryStartTransition(value)).toThrow(
    NotificationDeliveryStartTransitionError,
  );
});

it('rejects an otherwise valid foreign signature over identical claims', () => {
  const { value } = fixture();
  const foreign = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = foreign.publicKey.export({ type: 'spki', format: 'der' });
  const receipt = { ...value.receipt, signerKeyId: evidenceKeyId(spki) };
  const signed = signNotificationClaim(
    'NotificationDeliveryStartedReceiptV1',
    foreign.privateKey.export({ type: 'pkcs8', format: 'der' }),
    spki,
    receipt,
  );
  expect(() =>
    validateNotificationDeliveryStartTransition({
      ...value,
      receipt,
      payloadHex: signed.payload.toString('hex'),
      coseHex: signed.cose.toString('hex'),
    }),
  ).toThrow(NotificationDeliveryStartTransitionError);
});

it('rejects changed worker pins even with a recomputed installation digest', () => {
  const { value } = fixture();
  value.workerInstallation.pins.principalId = id(99);
  value.workerInstallationDigest = sha256(value.workerInstallation);
  expect(() => validateNotificationDeliveryStartTransition(value)).toThrow(
    NotificationDeliveryStartTransitionError,
  );
});

it('rejects a signed STARTED receipt whose original state/authority/source join is inconsistent', () => {
  const { value, sign } = fixture();
  for (const mutate of [
    (v: FixtureValue) => {
      v.receipt.operationId = v.source.operationId;
    },
    (v: FixtureValue) => {
      v.receipt.sourceEventId = id(99);
    },
    (v: FixtureValue) => {
      v.receipt.authoritySnapshotDigest = h(99);
      v.workerAuthorityDigest = h(99);
    },
    (v: FixtureValue) => {
      v.receipt.deliveryRevision = '2';
    },
    (v: FixtureValue) => {
      v.before.cancelRequested = true;
      v.receipt.beforeStateDigest = notificationDeliveryStateDigest(v.before, '1');
    },
    (v: FixtureValue) => {
      v.after.attemptLimit = 5;
      v.receipt.afterStateDigest = notificationDeliveryStateDigest(v.after, '2');
    },
    (v: FixtureValue) => {
      v.receipt.deadlineAtMs = 10001;
    },
  ]) {
    const changed = structuredClone(value);
    mutate(changed);
    Object.assign(changed, sign(changed.receipt));
    expect(() => validateNotificationDeliveryStartTransition(changed)).toThrow(
      NotificationDeliveryStartTransitionError,
    );
  }
});

it('requires the exact delivery role even when a different profile is legitimately signed', () => {
  const { value, sign, issuer, issuerSpki, workerProfile } = fixture();
  workerProfile.subscriptionId = 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1';
  const signed = signNotificationClaim(
    'NotificationWorkerProfileV1',
    issuer.privateKey.export({ type: 'pkcs8', format: 'der' }),
    issuerSpki,
    workerProfile,
  );
  value.workerInstallation.signed = {
    payloadHex: signed.payload.toString('hex'),
    coseHex: signed.cose.toString('hex'),
  };
  value.workerInstallation.pins.subscriptionId = workerProfile.subscriptionId;
  value.workerInstallation.pins.signedProfileDigest = sha256(signed.cose);
  value.workerInstallationDigest = sha256(value.workerInstallation);
  value.receipt.workerProfileDigest = sha256(signed.cose);
  Object.assign(value, sign(value.receipt));
  expect(() => validateNotificationDeliveryStartTransition(value)).toThrow(
    NotificationDeliveryStartTransitionError,
  );
});

it('accepts the canonical reduced retry limit and noninitial revision without resetting attempts', () => {
  const { value, sign } = fixture();
  value.before = {
    ...value.before,
    state: 'RETRY_WAIT',
    attemptCount: 1,
    lastStartedAtMs: 2000,
    nextAttemptAtMs: 7000,
  };
  value.configuredLimit = 2;
  value.attempt = { ...value.attempt, attemptNumber: 2, startedAtMs: 7000, deadlineAtMs: 8000 };
  value.context.deadlineAt = new Date(8000).toISOString();
  value.after = planNotificationDelivery(value.before, 2, 7000).next;
  value.receipt = {
    ...value.receipt,
    attemptNumber: 2,
    startedAtMs: 7000,
    deadlineAtMs: 8000,
    deliveryRevision: '9',
    beforeStateDigest: notificationDeliveryStateDigest(value.before, '9'),
    afterStateDigest: notificationDeliveryStateDigest(value.after, '10'),
    attemptDigest: sha256(value.attempt),
    contextDigest: sha256(value.context),
  };
  Object.assign(value, sign(value.receipt));
  expect(validateNotificationDeliveryStartTransition(value)).toEqual(value);
  value.configuredLimit = 1;
  expect(() => validateNotificationDeliveryStartTransition(value)).toThrow(
    NotificationDeliveryStartTransitionError,
  );
});

it('rejects extra fields throughout the closed representation', () => {
  const { value } = fixture();
  for (const select of [
    (v: FixtureValue) => v,
    (v: FixtureValue) => v.receipt,
    (v: FixtureValue) => v.source,
    (v: FixtureValue) => v.workerInstallation,
    (v: FixtureValue) => v.workerInstallation.pins,
    (v: FixtureValue) => v.workerInstallation.signed,
    (v: FixtureValue) => v.channel,
    (v: FixtureValue) => v.channel.claims,
    (v: FixtureValue) => v.channel.transport,
    (v: FixtureValue) => v.attempt,
    (v: FixtureValue) => v.context,
    (v: FixtureValue) => v.context.cancellation,
    (v: FixtureValue) => v.before,
    (v: FixtureValue) => v.after,
  ]) {
    const changed = structuredClone(value);
    Object.assign(select(changed), { extra: true });
    expect(() => validateNotificationDeliveryStartTransition(changed)).toThrow(
      NotificationDeliveryStartTransitionError,
    );
  }
});

it('rejects prototypes, accessors, symbols, hidden members and sparse arrays without invoking getters', () => {
  const { value } = fixture();
  let calls = 0;
  const cases = [
    Object.assign(Object.create({ inherited: true }), value),
    { ...value, before: new Date() },
    { ...value, configuredLimit: NaN },
    { ...value, configuredLimit: -0 },
    { ...value, extra: undefined },
    { ...value, [Symbol('hidden')]: true },
    Object.defineProperty({ ...value }, 'hidden', { value: true }),
    Object.defineProperty({ ...value }, 'before', {
      enumerable: true,
      get() {
        calls++;
        return value.before;
      },
    }),
    { ...value, context: { ...value.context, accessClassIds: new Array(1) } },
  ];
  for (const malformed of cases)
    expect(() => validateNotificationDeliveryStartTransition(malformed)).toThrow(
      NotificationDeliveryStartTransitionError,
    );
  expect(calls).toBe(0);
});

it('enforces wire lengths, hex spelling and total transition size before accepting data', () => {
  const { value } = fixture();
  for (const wire of [
    { payloadHex: '' },
    { payloadHex: 'a' },
    { payloadHex: value.payloadHex.toUpperCase() },
    { payloadHex: '00'.repeat(65537) },
    { coseHex: '00'.repeat(64) },
    { coseHex: '00'.repeat(131073) },
  ])
    expect(() => validateNotificationDeliveryStartTransition({ ...value, ...wire })).toThrow(
      NotificationDeliveryStartTransitionError,
    );
  for (const bytes of [Buffer.alloc(0), Buffer.alloc(262145), new Uint8Array([1]), null]) {
    expect(() => decodeNotificationDeliveryStartTransition(bytes as Buffer, h(99))).toThrow(
      NotificationDeliveryStartTransitionError,
    );
  }
});

it('rejects noncanonical JSON, duplicate keys and malformed UTF-8 even with recomputed digests', () => {
  const { value } = fixture();
  const canonical = Buffer.from(canonicalJson(value));
  const variants = [
    Buffer.from(JSON.stringify(value)),
    Buffer.concat([Buffer.from(' '), canonical]),
    Buffer.from(
      canonical
        .toString()
        .replace('"configuredLimit":6', '"configuredLimit":6,"configuredLimit":6'),
    ),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), canonical]),
    Buffer.concat([canonical, Buffer.from([0xff])]),
    Buffer.from('{"__proto__":{"polluted":true}}'),
  ];
  for (const bytes of variants)
    expect(() => decodeNotificationDeliveryStartTransition(bytes, sha256(bytes))).toThrow(
      NotificationDeliveryStartTransitionError,
    );
});

it('pins exact historical input with the durable digest, including semantically equivalent limits', () => {
  const { value } = fixture();
  const encoded = encodeNotificationDeliveryStartTransition(value);
  const changed = Buffer.from(canonicalJson({ ...value, configuredLimit: 7 }));
  // Both values cap at six; only the original durable digest establishes which
  // historical configuration was recorded. Neither is current admission.
  expect(() =>
    decodeNotificationDeliveryStartTransition(changed, encoded.transitionDigest),
  ).toThrow(NotificationDeliveryStartTransitionError);
  expect(() => decodeNotificationDeliveryStartTransition(encoded.transitionBytes, h(99))).toThrow(
    NotificationDeliveryStartTransitionError,
  );
});
