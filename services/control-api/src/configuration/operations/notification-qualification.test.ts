import { generateKeyPairSync, sign } from 'node:crypto';
import { expect, it } from 'vitest';
import { TLSSocket } from 'node:tls';
import { Socket } from 'node:net';
import { verifyConditionCases } from '../../../../identity-service/src/db/function-grants.js';
import {
  canonical,
  digest,
  document,
  inputClaims,
  qualificationInstallationSchema,
  qualificationOriginRequestSchema,
  qualificationRunRequestSchema,
  qualificationRecordSchema,
  verifyQualificationOrigin,
  qualificationCases,
  type QualificationOriginal,
  type QualificationRecordKind,
} from './notification-qualification-contract.js';
import { normalizeNotificationQualification } from './notification-qualification-review.js';
import { createNotificationQualificationPeer } from '../../../../identity-service/src/domain/notification-qualification-peer.js';
const id = (n: number) => `019a0000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const h = (s: string) => digest(Buffer.from(s));
const peer = (n: number) => ({
  principalId: id(n),
  credentialId: id(n + 20),
  participantEpoch: '1',
  principalEpoch: '1',
  credentialEpoch: '1',
  workloadId: `qualification-${n}`,
  keyDigest: h(`key${n}`),
  certificateDigest: h(`certificate${n}`),
});
/** Pure codec/normalizer corpus only: never a database origin, run, native
 * admission or signed capacity. External key exercises only its protocol. */
function fixture() {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = key.publicKey.export({ type: 'spki', format: 'der' });
  const input = inputClaims({
    authorityId: 'local-authority',
    environmentId: 'local-test',
    profile: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    task: 'ASYNC-NOTIFICATION',
    generationId: id(3),
    configurationDigest: h('configuration'),
    configurationSchemaDigest: h('schema'),
    namedProfileDigest: h('profile'),
    buildDigest: h('build'),
    sourceTreeDigest: h('source'),
    workloadIdentityDigest: h('workload'),
    environmentIdentityDigest: h('environment'),
    storeProfileDigest: h('store'),
    gatewayProfileDigest: h('gateway'),
    ratePolicyDigest: h('rate'),
    inputId: id(4),
    slot: 'QINPUT-ASYNC-NOTIFICATION',
    concurrency: 1,
    batchSize: 1,
    leaseMs: 1000,
    heartbeatMs: 100,
    attemptTimeoutMs: 1000,
    retryDelaysMs: [0, 0, 0, 0, 0],
    domainDeadlineMs: 10000,
    queueItems: 1,
    queueBytes: 20,
    maximumQueueAgeMs: 10000,
    maximumPayloadBytes: 10,
    dispatchRatePerSecond: 1,
    issuerKeyId: h('issuer'),
    issuerEpoch: '1',
    validFromMs: 0,
    validUntilMs: 100000,
  });
  const pins = qualificationInstallationSchema.parse({
    schemaVersion: 1,
    participantId: id(1),
    privacyDomainId: id(2),
    installationId: id(5),
    environmentId: 'local-test',
    operationsInstallationDigest: h('installation'),
    rootPrincipalId: id(6),
    subjectAuthor: peer(7),
    harnessAuthor: peer(8),
    executor: peer(9),
    reviewer: peer(10),
    signer: peer(11),
    builder: {
      providerId: 'external-build-fixture',
      keyId: digest(publicKey),
      publicKeySpkiHex: publicKey.toString('hex'),
    },
    subjectOriginId: id(40),
    harnessOriginId: id(41),
    executorDeploymentId: id(42),
    reviewerDeploymentId: id(43),
    storeIdentityDigest: h('store'),
    gatewayIdentityDigest: h('gateway'),
    capacityIssuer: { keyId: h('capacity'), epoch: '1' },
    input,
    maximumRunMs: 20000,
    maximumSamples: 100,
    maximumSources: 100,
    maximumEvidenceBytes: 16777216,
    validFromMs: 0,
    validUntilMs: 100000,
  });
  const origin = qualificationOriginRequestSchema.parse({
    schemaVersion: 1,
    mode: 'NEW_AUTHENTICATED_ORIGIN',
    originId: pins.subjectOriginId,
    installationId: pins.installationId,
    installationDigest: document(pins).digest,
    participantId: pins.participantId,
    privacyDomainId: pins.privacyDomainId,
    environmentId: pins.environmentId,
    kind: 'SUBJECT',
    author: pins.subjectAuthor,
    operationId: id(44),
    sourceDigest: input.sourceTreeDigest,
    buildDigest: input.buildDigest,
    issuedAtMs: 100,
    deadlineAtMs: 1000,
  });
  const signOrigin = (value: unknown) =>
    sign(
      'sha256',
      Buffer.concat([
        Buffer.from('pc.external.notification-build-origin.v1\0'),
        Buffer.from(canonical(value)),
      ]),
      { key: key.privateKey, dsaEncoding: 'ieee-p1363' },
    ).toString('hex');
  const request = qualificationRunRequestSchema.parse({
    schemaVersion: 1,
    purpose: 'QUALIFICATION_RUN',
    participantId: pins.participantId,
    privacyDomainId: pins.privacyDomainId,
    installationId: pins.installationId,
    runId: id(45),
    operationId: id(46),
    installationDigest: document(pins).digest,
    subjectOriginDigest: h('subject-original'),
    harnessOriginDigest: h('harness-original'),
    inputPayloadHex: '00',
    inputPayloadDigest: h('input'),
    executor: pins.executor,
    reservedAtMs: 100,
    deadlineAtMs: 50000,
  });
  const original: QualificationOriginal = { request, records: [] };
  const add = (kind: QualificationRecordKind, value: unknown, key = 'original') => {
    const record = qualificationRecordSchema.parse({
        schemaVersion: 1,
        runId: request.runId,
        kind,
        key,
        operationId: id(47),
        recordedAtMs: 600,
        value,
      }),
      d = document(record);
    (original.records as { record: typeof record; bytes: Buffer; digest: string }[]).push({
      record,
      bytes: d.bytes,
      digest: d.digest,
    });
    return d.digest;
  };
  const sources = qualificationCases.map((_, i) => id(50 + i));
  sources.forEach((eventId) => add('SOURCE', { eventId }, eventId));
  const cases = qualificationCases.map((caseId, i) => ({
    caseId,
    status: 'PASS',
    reason: 'COMPLETE',
    sourceEventIds: [sources[i]!],
  }));
  const raw = {
    startedAtMs: 200,
    completedAtMs: 600,
    samples: [
      {
        atMs: 300,
        sourceEventIds: sources,
        activeLeases: 2,
        batchSize: 2,
        queueItems: 2,
        queueBytes: 40,
        maximumPayloadBytes: 12,
        maximumQueueAgeMs: 100,
        dispatched: 2,
      },
    ],
    cases,
    unresolvedAttempts: 0,
  };
  const outcomes = {
    outcomes: [
      {
        eventId: sources[0],
        attemptId: id(60),
        operationId: id(61),
        publishedAtMs: 200,
        startedAtMs: 300,
        completedAtMs: 500,
        startPayloadHex: '01',
        startCoseHex: '02',
        outcomePayloadHex: '03',
        outcomeCoseHex: '04',
        transitionHex: '05',
        transitionDigest: h('transition'),
      },
    ],
  };
  const rawDigest = add('RAW', raw),
    outcomesDigest = add('OUTCOMES', outcomes);
  add('RESULT', {
    rawEvidenceDigest: rawDigest,
    originalSignedOutcomesDigest: outcomesDigest,
    completedAtMs: 600,
  });
  return { pins, origin, signOrigin, original, raw, outcomes, add };
}
it('accepts exact external new-origin signature and rejects substitution', () => {
  const f = fixture(),
    signature = f.signOrigin(f.origin);
  expect(verifyQualificationOrigin(f.origin, signature, f.pins)).toEqual(f.origin);
  for (const change of [
    { originId: id(90) },
    { kind: 'HARNESS' },
    { sourceDigest: h('substituted') },
    { author: f.pins.executor },
    { environmentId: 'another-env' },
    { installationDigest: h('other') },
  ])
    expect(() =>
      verifyQualificationOrigin({ ...f.origin, ...change } as typeof f.origin, signature, f.pins),
    ).toThrow();
  expect(() => verifyQualificationOrigin(f.origin, '00'.repeat(64), f.pins)).toThrow();
});
it.each(['subjectAuthor', 'harnessAuthor', 'executor', 'signer'] as const)(
  'rejects reviewer overlap with %s',
  (field) => {
    const { pins } = fixture();
    expect(() =>
      qualificationInstallationSchema.parse({ ...pins, reviewer: pins[field] }),
    ).toThrow();
  },
);
it.each([
  { maximumRunMs: Infinity },
  { maximumSources: 0 },
  { maximumSamples: 4097 },
  { validUntilMs: 0 },
  { input: {} },
  { capacityIssuer: { keyId: 'invented', epoch: '1' } },
])('rejects malformed installation %j', (change) => {
  const { pins } = fixture();
  expect(() => qualificationInstallationSchema.parse({ ...pins, ...change })).toThrow();
});
it('derives measurements from raw samples/outcomes rather than requested bounds', () => {
  const f = fixture(),
    n = normalizeNotificationQualification(f.original, f.pins);
  expect(n.status).toBe('PASS');
  expect(n.measurements).toEqual({
    measuredConcurrency: 2,
    measuredBatchSize: 2,
    measuredQueueItems: 2,
    measuredQueueBytes: 40,
    measuredMaximumPayloadBytes: 12,
    measuredDispatchRatePerSecond: 2,
    observedMaximumQueueAgeMs: 100,
    observedMaximumAttemptDurationMs: 200,
  });
  const higher = { ...f.pins, input: { ...inputClaims(f.pins.input), concurrency: 3 } };
  expect(normalizeNotificationQualification(f.original, higher).status).toBe('FAIL');
});
it.each(['FAIL', 'BLOCKED', 'UNKNOWN'] as const)(
  'never hides original %s behind passing siblings',
  (status) => {
    const f = fixture();
    const raw = f.original.records.find((r) => r.record.kind === 'RAW')!;
    const changed = structuredClone(raw.record.value) as typeof f.raw;
    changed.cases[1]!.status = status;
    raw.record.value = changed;
    expect(normalizeNotificationQualification(f.original, f.pins).status).toBe(status);
  },
);
it('retains unresolved effects as unsigned UNKNOWN and rejects missing/grafted artifacts', () => {
  const f = fixture(),
    raw = f.original.records.find((r) => r.record.kind === 'RAW')!;
  raw.record.value = { ...f.raw, unresolvedAttempts: 1 };
  expect(normalizeNotificationQualification(f.original, f.pins).status).toBe('UNKNOWN');
  expect(() =>
    normalizeNotificationQualification(
      { ...f.original, records: f.original.records.filter((r) => r.record.kind !== 'OUTCOMES') },
      f.pins,
    ),
  ).toThrow();
  const out = f.original.records.find((r) => r.record.kind === 'OUTCOMES')!;
  out.record.value = { outcomes: [{ ...f.outcomes.outcomes[0], eventId: id(99) }] };
  expect(() => normalizeNotificationQualification(f.original, f.pins)).toThrow();
});
it('rejects sample time reversal, duplicate outcome identity and nonnumeric coercion', () => {
  for (const mutate of [
    (f: ReturnType<typeof fixture>) => ({
      ...f.raw,
      samples: [{ ...f.raw.samples[0], atMs: 999 }],
    }),
    (f: ReturnType<typeof fixture>) => ({
      ...f.raw,
      samples: [{ ...f.raw.samples[0], queueBytes: '40' }],
    }),
  ]) {
    const f = fixture();
    f.original.records.find((r) => r.record.kind === 'RAW')!.record.value = mutate(f);
    expect(() => normalizeNotificationQualification(f.original, f.pins)).toThrow();
  }
  const f = fixture();
  f.original.records.find((r) => r.record.kind === 'OUTCOMES')!.record.value = {
    outcomes: [f.outcomes.outcomes[0], f.outcomes.outcomes[0]],
  };
  expect(() => normalizeNotificationQualification(f.original, f.pins)).toThrow();
});
it('keeps disconnected transport from invoking any native owner or store', async () => {
  const socket = new TLSSocket(new Socket());
  const owner = createNotificationQualificationPeer({
    ownerPool: undefined,
    kernel: undefined,
    nativeExecution: undefined,
  } as unknown as Parameters<typeof createNotificationQualificationPeer>[0]);
  const { pins } = fixture();
  try {
    await expect(
      owner.reserve(socket, {
        participantId: pins.participantId,
        privacyDomainId: pins.privacyDomainId,
        installationId: pins.installationId,
        runId: id(99),
      }),
    ).rejects.toThrow();
  } finally {
    socket.destroy();
  }
});
it('preflights SQL condition syntax; this does not claim PostgreSQL execution', async () => {
  const { notificationQualificationGuardsSql } = await import(
    new URL('./notification-qualification-guards.mjs', import.meta.url).href
  );
  expect(() => verifyConditionCases(notificationQualificationGuardsSql)).not.toThrow();
  expect(notificationQualificationGuardsSql).not.toContain('CREATE ROLE');
});

it('rejects missing cases, reused business sources and empty passing cases', () => {
  for (const mode of ['missing', 'reused', 'empty'] as const) {
    const f = fixture();
    const raw = structuredClone(f.raw);
    if (mode === 'missing') raw.cases.pop();
    if (mode === 'reused') raw.cases[1]!.sourceEventIds = [...raw.cases[0]!.sourceEventIds];
    if (mode === 'empty') raw.cases[0]!.sourceEventIds = [];
    f.original.records.find((r) => r.record.kind === 'RAW')!.record.value = raw;
    expect(() => normalizeNotificationQualification(f.original, f.pins)).toThrow();
  }
});
