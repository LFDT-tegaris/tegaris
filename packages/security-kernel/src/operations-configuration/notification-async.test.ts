import { createHash, generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { decodeCbor, encodeCbor } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { signConsumerCose } from '../fact-consumer/cose-framing.js';
import {
  decodeNotificationAsync,
  encodeNotificationAsync,
  notificationAsyncProfiles,
  verifyNotificationAsyncEnvelope,
  verifyNotificationAsyncPair,
  verifyNotificationAsyncInstalledPair,
  type NotificationAsyncInputClaims,
  type NotificationAsyncCapacityClaims,
  type NotificationAsyncEnvelope,
} from './notification-async.js';
import {
  encodeProviderRetryQualification,
  providerRetryQualificationProfiles,
  qualificationCanonicalJson,
  verifyProviderRetryAuthority,
  type QualificationAuthorityEnvelope,
  type QualificationRoot,
} from './provider-retry-qualification.js';
const key = () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: pair.publicKey.export({ format: 'der', type: 'spki' }),
  };
};
const inputKey = key(),
  receiptKey = key();
const digest = (value: string | Buffer) =>
  `sha256:${createHash('sha256').update(value).digest('hex')}`;
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
function input(): NotificationAsyncInputClaims {
  return {
    authorityId: 'local-authority',
    environmentId: 'local-test',
    profile: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    task: 'ASYNC-NOTIFICATION',
    generationId: id(3),
    configurationDigest: digest('configuration'),
    configurationSchemaDigest: digest('schema'),
    namedProfileDigest: digest('profile'),
    buildDigest: digest('build'),
    sourceTreeDigest: digest('source'),
    workloadIdentityDigest: digest('workload'),
    environmentIdentityDigest: digest('environment'),
    storeProfileDigest: digest('store'),
    gatewayProfileDigest: digest('gateway'),
    ratePolicyDigest: digest('rate'),
    inputId: id(4),
    slot: 'QINPUT-ASYNC-NOTIFICATION',
    concurrency: 2,
    batchSize: 3,
    leaseMs: 10000,
    heartbeatMs: 4000,
    attemptTimeoutMs: 1000,
    retryDelaysMs: [10, 20, 30, 40, 50],
    domainDeadlineMs: 20000,
    queueItems: 20,
    queueBytes: 20000,
    maximumQueueAgeMs: 20000,
    maximumPayloadBytes: 1000,
    dispatchRatePerSecond: 3,
    issuerKeyId: evidenceKeyId(inputKey.spki),
    issuerEpoch: '1',
    validFromMs: 1000,
    validUntilMs: 100000,
  };
}
function capacity(v = input()): NotificationAsyncCapacityClaims {
  return {
    authorityId: v.authorityId,
    environmentId: v.environmentId,
    profile: v.profile,
    participantId: v.participantId,
    privacyDomainId: v.privacyDomainId,
    task: v.task,
    generationId: v.generationId,
    configurationDigest: v.configurationDigest,
    configurationSchemaDigest: v.configurationSchemaDigest,
    namedProfileDigest: v.namedProfileDigest,
    buildDigest: v.buildDigest,
    sourceTreeDigest: v.sourceTreeDigest,
    workloadIdentityDigest: v.workloadIdentityDigest,
    environmentIdentityDigest: v.environmentIdentityDigest,
    storeProfileDigest: v.storeProfileDigest,
    gatewayProfileDigest: v.gatewayProfileDigest,
    ratePolicyDigest: v.ratePolicyDigest,
    issuerEpoch: v.issuerEpoch,
    receiptId: id(5),
    inputPayloadDigest: digest(encodeNotificationAsync('input', v)),
    runId: id(6),
    harnessDigest: digest('harness'),
    rawEvidenceDigest: digest('raw'),
    originalSignedOutcomesDigest: digest('originals'),
    normalizedResultsDigest: digest('results'),
    reviewerAttestationDigest: digest('review'),
    subjectAuthorPrincipalId: id(7),
    harnessAuthorPrincipalId: id(8),
    reviewerPrincipalId: id(9),
    signerPrincipalId: id(10),
    measuredConcurrency: v.concurrency,
    measuredBatchSize: v.batchSize,
    measuredQueueItems: v.queueItems,
    measuredQueueBytes: v.queueBytes,
    measuredMaximumPayloadBytes: v.maximumPayloadBytes,
    measuredDispatchRatePerSecond: v.dispatchRatePerSecond,
    observedMaximumQueueAgeMs: v.maximumQueueAgeMs,
    observedMaximumAttemptDurationMs: v.attemptTimeoutMs,
    runStartedAtMs: v.validFromMs,
    runCompletedAtMs: 2000,
    keysetPayloadDigest: digest('keyset'),
    revocationPayloadDigest: digest('revocations'),
    issuerKeyId: evidenceKeyId(receiptKey.spki),
    issuedAtMs: 3000,
    expiresAtMs: v.validUntilMs,
  };
}
function signed(
  family: 'input' | 'capacity',
  claims: NotificationAsyncInputClaims | NotificationAsyncCapacityClaims,
): NotificationAsyncEnvelope {
  const k = family === 'input' ? inputKey : receiptKey;
  const payload = encodeNotificationAsync(family, claims);
  return {
    payload,
    cose: signConsumerCose(notificationAsyncProfiles[family], k.privateKey, k.spki, payload),
  };
}
it('keeps intended async values and authentic measured receipts distinct without current authority', () => {
  const i = input(),
    c = capacity(i),
    a = signed('input', i),
    b = signed('capacity', c);
  expect(decodeNotificationAsync('input', a.payload)).toEqual(i);
  const original = verifyNotificationAsyncPair(inputKey.spki, a, receiptKey.spki, b);
  expect(original).toEqual({ input: i, capacity: c });
  expect(Object.isFrozen(original.input.retryDelaysMs)).toBe(true);
  expect(original).not.toHaveProperty('current');
  expect(original).not.toHaveProperty('ready');
  expect(() => verifyNotificationAsyncEnvelope('capacity', inputKey.spki, a)).toThrow();
  expect(() => verifyNotificationAsyncEnvelope('input', receiptKey.spki, a)).toThrow();
  expect(notificationAsyncProfiles.input.schemaId).toBe(24032);
  expect(notificationAsyncProfiles.capacity.schemaId).toBe(24033);
});
it('rejects missing, coercible, unbounded and deadline-unsafe intended inputs before allocation', () => {
  const i = input();
  for (const patch of [
    { concurrency: 0 },
    { concurrency: true },
    { batchSize: 1.2 },
    { queueBytes: '20000' },
    { queueItems: 2 },
    { heartbeatMs: 5000 },
    { leaseMs: 0 },
    { retryDelaysMs: [1, 2, 3, 4] },
    { retryDelaysMs: [1, 2, 3, 4, 5, 6] },
    { retryDelaysMs: [1, 2, 3, 4, -1] },
    { attemptTimeoutMs: 4000 },
    { domainDeadlineMs: Number.MAX_SAFE_INTEGER },
    { maximumPayloadBytes: 30000 },
    { validUntilMs: 1000 },
    { slot: 'provider.read_retry_limit' },
    { ready: true },
  ])
    expect(() =>
      encodeNotificationAsync('input', { ...i, ...patch } as NotificationAsyncInputClaims),
    ).toThrow();
  let read = 0;
  const getter = { ...i };
  Object.defineProperty(getter, 'concurrency', {
    enumerable: true,
    get() {
      read++;
      return 2;
    },
  });
  expect(() => encodeNotificationAsync('input', getter)).toThrow();
  expect(read).toBe(0);
  const sparse = [10, 20, 30, 40, 50];
  Reflect.deleteProperty(sparse, '2');
  expect(() =>
    encodeNotificationAsync('input', {
      ...i,
      retryDelaysMs: sparse,
    } as unknown as NotificationAsyncInputClaims),
  ).toThrow();
});
it('rejects malformed maps, definition changes, trailing bytes and purpose substitution', () => {
  const bytes = encodeNotificationAsync('input', input());
  expect(() =>
    decodeNotificationAsync('input', Buffer.concat([bytes, Buffer.from([0])])),
  ).toThrow();
  expect(() => decodeNotificationAsync('input', Buffer.alloc(65537))).toThrow();
  const decoded = decodeCbor(bytes) as Map<number, import('../canonical-cbor.js').CborValue>;
  decoded.set(0, Buffer.alloc(32));
  expect(() => decodeNotificationAsync('input', encodeCbor(decoded))).toThrow();
  const envelope = signed('input', input());
  const modified = Buffer.from(envelope.cose);
  modified[modified.length - 1]! ^= 1;
  expect(() =>
    verifyNotificationAsyncEnvelope('input', inputKey.spki, { ...envelope, cose: modified }),
  ).toThrow();
});
it('binds original run, scope, generation, input, actual capacity and independent reviewer fields', () => {
  const i = input(),
    c = capacity(i),
    a = signed('input', i);
  for (const patch of [
    { environmentId: 'other-env' },
    { generationId: id(11) },
    { configurationDigest: digest('other') },
    { inputPayloadDigest: digest('other') },
    { measuredConcurrency: 1 },
    { measuredQueueItems: 10 },
    { measuredQueueBytes: 10000 },
    { measuredDispatchRatePerSecond: 1 },
    { observedMaximumQueueAgeMs: 20001 },
    { observedMaximumAttemptDurationMs: 1001 },
    { expiresAtMs: 100001 },
    { runStartedAtMs: 999 },
  ])
    expect(() =>
      verifyNotificationAsyncPair(
        inputKey.spki,
        a,
        receiptKey.spki,
        signed('capacity', { ...c, ...patch }),
      ),
    ).toThrow();
  for (const patch of [
    { reviewerPrincipalId: c.subjectAuthorPrincipalId },
    { reviewerPrincipalId: c.harnessAuthorPrincipalId },
    { signerPrincipalId: c.subjectAuthorPrincipalId },
    { runCompletedAtMs: 1000 },
    { issuedAtMs: 1500 },
    { expiresAtMs: 3000 },
  ])
    expect(() => encodeNotificationAsync('capacity', { ...c, ...patch })).toThrow();
});

// Actual root-signed cryptographic adapter corpus only. These software keys and
// declared principals do not establish installed execution or reviewer custody.
const asyncAuthorityRootKey = key();
function authoritySnapshot(
  change: (
    keys: Array<Record<string, unknown>>,
    revoked: Array<Record<string, unknown>>,
  ) => void = () => {},
) {
  const rootKey = asyncAuthorityRootKey;
  const root: QualificationRoot = {
    authorityId: 'local-authority',
    rootKeyId: evidenceKeyId(rootKey.spki),
    rootEpoch: '1',
    rootSpki: rootKey.spki,
    policySigner: 'OFFLINE_TRUST_ROOT',
    validFromMs: 0,
    validUntilMs: 200000,
  };
  const keys: Array<Record<string, unknown>> = [
    [inputKey, 'pc.cose.operations-notification-async-input.v1'],
    [receiptKey, 'pc.cose.operations-notification-async-capacity-receipt.v1'],
  ].map(([material, purpose]) => {
    const k = material as ReturnType<typeof key>;
    return {
      keyId: evidenceKeyId(k.spki),
      epoch: 1,
      state: 'ACTIVE',
      purpose,
      nonExportable: true,
      backend: 'HSM',
      publicKeySpkiHex: k.spki.toString('hex'),
      validFromMs: 0,
      validUntilMs: 150000,
    };
  });
  const revoked: Array<Record<string, unknown>> = [];
  change(keys, revoked);
  keys.sort(
    (a, b) => String(a.keyId).localeCompare(String(b.keyId)) || Number(a.epoch) - Number(b.epoch),
  );
  const revocationDocument = Buffer.from(
    qualificationCanonicalJson({
      schemaVersion: '1.0',
      authorityId: root.authorityId,
      revocations: revoked,
    }),
  );
  const revocationPayload = encodeProviderRetryQualification('revocations', {
    authorityId: root.authorityId,
    snapshotId: id(30),
    sequence: '1',
    revocationDocumentDigest: digest(revocationDocument),
    rootKeyId: root.rootKeyId,
    rootEpoch: '1',
    issuedAtMs: 500,
    validUntilMs: 200000,
  });
  const keysetDocument = Buffer.from(
    qualificationCanonicalJson({
      schemaVersion: '1.0',
      authorityId: root.authorityId,
      policySigner: root.policySigner,
      keys,
      issuedAt: new Date(500).toISOString(),
      signatureEnvelope: {
        format: 'COSE_Sign1',
        algorithm: 'ES256',
        curve: 'P-256',
        hash: 'SHA-256',
        canonicalization: 'PC-CBOR-1',
      },
    }),
  );
  const keysetPayload = encodeProviderRetryQualification('keyset', {
    authorityId: root.authorityId,
    keysetId: id(31),
    sequence: '1',
    keysetDocumentDigest: digest(keysetDocument),
    revocationPayloadDigest: digest(revocationPayload),
    policySigner: root.policySigner,
    rootKeyId: root.rootKeyId,
    rootEpoch: '1',
    issuedAtMs: 500,
    validUntilMs: 200000,
  });
  const bundle: QualificationAuthorityEnvelope = {
    keyset: {
      payload: keysetPayload,
      cose: signConsumerCose(
        providerRetryQualificationProfiles.keyset,
        rootKey.privateKey,
        rootKey.spki,
        keysetPayload,
      ),
      document: keysetDocument,
    },
    revocations: {
      payload: revocationPayload,
      cose: signConsumerCose(
        providerRetryQualificationProfiles.revocations,
        rootKey.privateKey,
        rootKey.spki,
        revocationPayload,
      ),
      document: revocationDocument,
    },
  };
  return { root, bundle, state: verifyProviderRetryAuthority(root, bundle, 4000) };
}
it('authenticates distinct installed issuance/current keys but grants no execution or reviewer authority', () => {
  const issued = authoritySnapshot(),
    i = input(),
    c = {
      ...capacity(i),
      keysetPayloadDigest: issued.state.keysetDigest,
      revocationPayloadDigest: issued.state.revocationsDigest,
    };
  const original = { input: signed('input', i), capacity: signed('capacity', c) };
  const verify = (current = issued.state, now = 4000) =>
    verifyNotificationAsyncInstalledPair(
      original.input,
      original.capacity,
      issued.state,
      current,
      now,
    );
  expect(verify()).toEqual({ input: i, capacity: c });
  expect(verify()).not.toHaveProperty('admitted');
  expect(() => verify(issued.state, 100000)).toThrow();
  for (const state of ['SUSPENDED', 'REVOKED', 'DRAFT'])
    expect(() =>
      verify(
        authoritySnapshot((keys) => {
          keys[0]!.state = state;
        }).state,
      ),
    ).toThrow();
  expect(
    verify(
      authoritySnapshot((keys) => {
        for (const k of keys) k.state = 'RETIRED';
      }).state,
    ),
  ).toEqual({ input: i, capacity: c });
  expect(() =>
    verify(
      authoritySnapshot((keys) => {
        keys[0]!.epoch = 2;
      }).state,
    ),
  ).toThrow();
  expect(() =>
    verify(
      authoritySnapshot((keys) => {
        keys[0]!.purpose = 'pc.cose.operations-qualification-input.v1';
      }).state,
    ),
  ).toThrow();
  expect(() =>
    verifyNotificationAsyncInstalledPair(
      original.input,
      original.capacity,
      authoritySnapshot((keys) => {
        keys[0]!.epoch = 2;
      }).state,
      issued.state,
      4000,
    ),
  ).toThrow();
  for (const patch of [
    { authorityId: 'other-authority' },
    { issuerEpoch: '2' },
    { signerPrincipalId: i.participantId, subjectAuthorPrincipalId: i.participantId },
  ])
    expect(() =>
      verifyNotificationAsyncInstalledPair(
        original.input,
        signed('capacity', { ...c, ...patch }),
        issued.state,
        issued.state,
        4000,
      ),
    ).toThrow();
  const revoked = authoritySnapshot((_keys, entries) => {
    entries.push({
      schemaVersion: '1.0',
      authorityId: issued.root.authorityId,
      keyId: evidenceKeyId(inputKey.spki),
      keyEpoch: 1,
      state: 'REVOKED',
      effectiveAt: new Date(4000).toISOString(),
      receiptEffect: 'INVALIDATE_RECEIPTS_COVERED_BY_REVOKED_KEY_EPOCH',
      evidenceRetention: 'PRESERVE_NEVER_DELETE_OR_RESIGN',
      signatureEnvelope: {
        format: 'COSE_Sign1',
        algorithm: 'ES256',
        curve: 'P-256',
        hash: 'SHA-256',
        canonicalization: 'PC-CBOR-1',
      },
    });
  }).state;
  expect(verify(revoked, 3999)).toEqual({ input: i, capacity: c });
  expect(() => verify(revoked, 4000)).toThrow();
  expect(() =>
    verifyProviderRetryAuthority({ ...issued.root, rootEpoch: '2' }, issued.bundle, 4000),
  ).toThrow();
  expect(() =>
    verifyProviderRetryAuthority({ ...issued.root, rootSpki: key().spki }, issued.bundle, 4000),
  ).toThrow();
});
