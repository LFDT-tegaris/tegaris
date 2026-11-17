import { getEventListeners } from 'node:events';
import { validateNotificationCompletionDispositionSignerInstallation } from '../../../control-api/src/notifications/completion-disposition-signer.js';
import { request as httpsRequest } from 'node:https';
import { canonicalJson } from '../../../control-api/src/configuration/digest.js';
import {
  completionDispositionInputFixture,
  completionWorkerFixture,
  completionTestId,
} from '../../../../tests/integration/identity/notification-completion-disposition-cases.js';
import { validateNotificationCompletionWorkerOriginal } from '../../../control-api/src/notifications/completion-worker-installation-contract.js';
import { buildNotificationCompletionDispositionSigning } from '../../../control-api/src/notifications/completion-disposition-state.js';
import {
  validateNotificationCompletionDispositionRequest,
  createNotificationCompletionDispositionRequest,
  type NotificationCompletionDispositionRequest,
} from './notification-completion-disposition-provider.js';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it, vi } from 'vitest';
import { encodeNotificationClaim } from '@openpc/security-kernel';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import {
  notificationReceiptProviderSample,
  notificationCancellationReceiptProviderSample,
  notificationOutcomeReceiptProviderSample,
  createNotificationReceiptProviderFixture,
  notificationFixtureSpki,
  type NotificationReceiptFixtureFault,
  type NotificationCompletionFixtureBoundary,
} from '../../../../tests/integration/identity/notification-receipt-provider-fixture.js';
import {
  createNotificationReceiptRequest,
  NotificationReceiptProviderUnknown,
  type NotificationReceiptProviderTrust,
} from './notification-receipt-provider.js';
import {
  createHttpNotificationReceiptProvider,
  createHttpNotificationCancellationReceiptProvider,
  createHttpNotificationOutcomeReceiptProvider,
  createHttpNotificationCompletionDispositionProvider,
} from './http-notification-receipt-provider.js';
import { createNotificationCancellationReceiptRequest } from './notification-cancellation-receipt-provider.js';
import { createNotificationOutcomeReceiptRequest } from './notification-outcome-receipt-provider.js';

it.each([
  createHttpNotificationReceiptProvider,
  createHttpNotificationCancellationReceiptProvider,
  createHttpNotificationOutcomeReceiptProvider,
  createHttpNotificationCompletionDispositionProvider,
])('preserves the notification public error family after transport extraction (%#)', (factory) => {
  expect(() =>
    (factory as (input: unknown) => unknown)({
      trust: null,
      certificate: Buffer.alloc(0),
      privateKey: Buffer.alloc(0),
      trustCa: Buffer.alloc(0),
    }),
  ).toThrow(NotificationReceiptProviderUnknown);
});

async function tlsFixture() {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent) throw new Error('Owned OPENPC_TEST_TMP_ROOT required');
  const root = await mkdtemp(join(parent, 'notification-receipt-tls-'));
  const openssl = (args: string[]) => execFileSync('openssl', args, { cwd: root, stdio: 'ignore' });
  openssl([
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-keyout',
    'ca.key',
    '-out',
    'ca.crt',
    '-days',
    '1',
    '-subj',
    '/CN=Notification-receipt-test-CA',
  ]);
  const certificate = async (name: string, serial: number, usage: string, san: string) => {
    openssl([
      'req',
      '-new',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      name + '.key',
      '-out',
      name + '.csr',
      '-subj',
      '/CN=' + name,
    ]);
    await writeFile(
      join(root, name + '.ext'),
      `subjectAltName=${san}\nextendedKeyUsage=${usage}\nkeyUsage=digitalSignature\n`,
      { mode: 0o600 },
    );
    openssl([
      'x509',
      '-req',
      '-in',
      name + '.csr',
      '-CA',
      'ca.crt',
      '-CAkey',
      'ca.key',
      '-set_serial',
      String(serial),
      '-days',
      '1',
      '-extfile',
      name + '.ext',
      '-out',
      name + '.crt',
    ]);
    return {
      certificate: await readFile(join(root, name + '.crt')),
      privateKey: await readFile(join(root, name + '.key')),
    };
  };
  const server = await certificate('server', 1, 'serverAuth', 'IP:127.0.0.1');
  const worker = await certificate(
    'worker',
    2,
    'clientAuth',
    'URI:urn:openpc:test:notification-worker',
  );
  const foreign = await certificate(
    'foreign',
    3,
    'clientAuth',
    'URI:urn:openpc:test:foreign-worker',
  );
  return { root, server, worker, foreign, ca: await readFile(join(root, 'ca.crt')) };
}
it('real mTLS native provider preserves one original across lost response/restart/expiry and makes lookup observation-only', async () => {
  const tls = await tlsFixture();
  const sample = notificationReceiptProviderSample({
    workerSpki: notificationFixtureSpki(tls.worker.certificate),
    providerSpki: notificationFixtureSpki(tls.server.certificate),
  });
  const config = {
    directory: join(tls.root, 'state'),
    trust: sample.trust,
    signerPrivateKey: sample.signerPrivateKey,
    ...tls.server,
    trustCa: tls.ca,
  };
  let server = await createNotificationReceiptProviderFixture(config);
  let client = createHttpNotificationReceiptProvider({
    trust: server.trust,
    ...tls.worker,
    trustCa: tls.ca,
    timeoutMs: 500,
  });
  const make = (trust: NotificationReceiptProviderTrust, n: number) =>
    createNotificationReceiptRequest(trust, {
      deliveryPreparationDigest: sample.request.deliveryPreparationDigest,
      payloadHex: encodeNotificationClaim('NotificationDeliveryStartedReceiptV1', {
        ...sample.claims,
        receiptId: `01990000-0000-7000-8000-${String(n).padStart(12, '0')}`,
        operationId: `01990000-0000-7000-8000-${String(n + 1).padStart(12, '0')}`,
        attemptId: `01990000-0000-7000-8000-${String(n + 2).padStart(12, '0')}`,
      }).toString('hex'),
    });
  try {
    const request = make(server.trust, 20),
      absent = make(server.trust, 30);
    expect(await client.lookup(absent)).toBeUndefined();
    expect(server.counters()).toEqual({ performs: 0, lookups: 1, signatures: 0 });
    server.setFault('LOSE_RESPONSE');
    await expect(client.perform(request)).rejects.toThrow(
      'Notification receipt signing outcome requires reconciliation',
    );
    expect(server.counters()).toEqual({ performs: 1, lookups: 1, signatures: 1 });
    server.setFault('NONE');
    const first = await client.lookup(request);
    expect(first?.outcome).toBe('SIGNED');
    expect(server.counters().performs).toBe(1);
    expect(await client.lookup(request, first)).toEqual(first);
    const port = Number(new URL(server.origin).port),
      trust = server.trust;
    client.close();
    await server.close();
    server = await createNotificationReceiptProviderFixture({ ...config, trust, port });
    client = createHttpNotificationReceiptProvider({
      trust,
      ...tls.worker,
      trustCa: tls.ca,
      timeoutMs: 500,
    });
    expect(await client.lookup(request, first)).toEqual(first);
    expect(server.counters()).toEqual({ performs: 0, lookups: 1, signatures: 0 });
    const clock = vi.spyOn(Date, 'now').mockReturnValue(sample.claims.deadlineAtMs + 1);
    try {
      expect(await client.lookup(request, first)).toEqual(first);
      await expect(client.perform(request)).rejects.toThrow();
    } finally {
      clock.mockRestore();
    }
    expect(server.counters().performs).toBe(0);
    await server.revoke();
    const rejected = await client.perform(absent);
    expect(rejected).toMatchObject({ outcome: 'REJECTED', reason: 'REVOKED', coseHex: null });
    expect(await client.lookup(request, first)).toEqual(first);
    expect(server.counters().signatures).toBe(0);
    const same = await client.lookup(absent, rejected);
    expect(same).toEqual(rejected);
    const altered = { ...request, deliveryPreparationDigest: sha256('other') };
    await expect(client.lookup(altered)).rejects.toThrow();
    expect(server.counters().performs).toBe(1);
    client.close();
    await expect(client.lookup(request)).rejects.toThrow();
  } finally {
    client.close();
    await server.close();
    sample.signerPrivateKey.fill(0);
    await rm(tls.root, { recursive: true, force: true });
  }
}, 20000);
it('bounds response frames/deadlines, refuses wrong TLS/client identity and redacts every failure without retry', async () => {
  const tls = await tlsFixture();
  const sample = notificationReceiptProviderSample({
    workerSpki: notificationFixtureSpki(tls.worker.certificate),
    providerSpki: notificationFixtureSpki(tls.server.certificate),
  });
  const server = await createNotificationReceiptProviderFixture({
    directory: join(tls.root, 'state'),
    trust: sample.trust,
    signerPrivateKey: sample.signerPrivateKey,
    ...tls.server,
    trustCa: tls.ca,
  });
  const client = createHttpNotificationReceiptProvider({
    trust: server.trust,
    ...tls.worker,
    trustCa: tls.ca,
    timeoutMs: 150,
  });
  const request = createNotificationReceiptRequest(server.trust, {
    payloadHex: sample.request.payloadHex,
    deliveryPreparationDigest: sample.request.deliveryPreparationDigest,
  });
  try {
    const wrongTrust = {
      ...server.trust,
      signer: { ...server.trust.signer, providerTlsSpkiDigest: sha256('wrong TLS pin') },
    };
    const wrongPin = createHttpNotificationReceiptProvider({
      trust: wrongTrust,
      ...tls.worker,
      trustCa: tls.ca,
      timeoutMs: 150,
    });
    try {
      await expect(
        wrongPin.lookup(
          createNotificationReceiptRequest(wrongTrust, {
            payloadHex: request.payloadHex,
            deliveryPreparationDigest: request.deliveryPreparationDigest,
          }),
        ),
      ).rejects.toThrow('Notification receipt signing outcome requires reconciliation');
    } finally {
      wrongPin.close();
    }
    expect(server.counters()).toEqual({ performs: 0, lookups: 0, signatures: 0 });
    expect(() =>
      createHttpNotificationReceiptProvider({
        trust: server.trust,
        ...tls.foreign,
        trustCa: tls.ca,
      }),
    ).toThrow('Notification receipt signing outcome requires reconciliation');
    const foreignSample = notificationReceiptProviderSample({
      workerSpki: notificationFixtureSpki(tls.foreign.certificate),
      providerSpki: notificationFixtureSpki(tls.server.certificate),
      origin: server.origin,
    });
    const foreignClient = createHttpNotificationReceiptProvider({
      trust: foreignSample.trust,
      ...tls.foreign,
      trustCa: tls.ca,
      timeoutMs: 150,
    });
    try {
      await expect(foreignClient.lookup(foreignSample.request)).rejects.toThrow();
    } finally {
      foreignClient.close();
      foreignSample.signerPrivateKey.fill(0);
    }
    expect(server.counters().lookups).toBe(0);
    for (const fault of [
      'TIMEOUT',
      'OVERSIZED',
      'BAD_JSON',
      'DUPLICATE_KEY',
      'WRONG_REQUEST',
      'INVALID_SIGNATURE',
      'WRONG_CONTENT_TYPE',
      'REDIRECT',
      'TRUNCATED',
    ] satisfies NotificationReceiptFixtureFault[]) {
      server.setFault(fault);
      const before = server.counters().performs;
      await expect(client.perform(request)).rejects.toThrow(
        'Notification receipt signing outcome requires reconciliation',
      );
      expect(server.counters().performs).toBe(before + 1);
    }
    // Explicit repeated calls here test the external fixture's original-result
    // retention. They are not an allowed production retry policy.
    expect(server.counters().signatures).toBe(1);
    server.setFault('NONE');
    const observed = await client.lookup(request);
    expect(observed?.outcome).toBe('SIGNED');
    expect(server.counters().signatures).toBe(1);
    for (const config of [
      { timeoutMs: 0 },
      { timeoutMs: 10001 },
      { privateKey: Buffer.from('PRIVATE_CANARY') },
      { trustCa: Buffer.alloc(0) },
    ])
      expect(() =>
        createHttpNotificationReceiptProvider({
          trust: server.trust,
          ...tls.worker,
          trustCa: tls.ca,
          ...config,
        }),
      ).toThrow('Notification receipt signing outcome requires reconciliation');
  } finally {
    client.close();
    await server.close();
    sample.signerPrivateKey.fill(0);
    await rm(tls.root, { recursive: true, force: true });
  }
}, 20000);

it('cancellation uses distinct mTLS protocol and preserves its exact original through lost response and provider restart', async () => {
  const tls = await tlsFixture();
  const sample = notificationCancellationReceiptProviderSample({
    workerSpki: notificationFixtureSpki(tls.worker.certificate),
    providerSpki: notificationFixtureSpki(tls.server.certificate),
  });
  const config = {
    directory: join(tls.root, 'cancellation'),
    trust: sample.trust,
    signerPrivateKey: sample.original.signerPrivateKey,
    ...tls.server,
    trustCa: tls.ca,
  };
  let server = await createNotificationReceiptProviderFixture(config);
  let client = createHttpNotificationCancellationReceiptProvider({
    trust: server.trust,
    ...tls.worker,
    trustCa: tls.ca,
    timeoutMs: 500,
  });
  try {
    const request = createNotificationCancellationReceiptRequest(server.trust, {
      payloadHex: sample.request.payloadHex,
      cancellationPreparationDigest: sample.request.cancellationPreparationDigest,
    });
    expect(() =>
      createHttpNotificationReceiptProvider({
        trust: server.trust,
        ...tls.worker,
        trustCa: tls.ca,
      }),
    ).toThrow();
    expect(await client.lookup(request)).toBeUndefined();
    server.setFault('LOSE_RESPONSE');
    await expect(client.perform(request)).rejects.toThrow();
    expect(server.counters()).toEqual({ performs: 1, lookups: 1, signatures: 1 });
    server.setFault('NONE');
    const first = await client.lookup(request);
    expect(first?.outcome).toBe('SIGNED');
    expect(await client.lookup(request, first)).toEqual(first);
    const port = Number(new URL(server.origin).port),
      trust = server.trust;
    client.close();
    await server.close();
    server = await createNotificationReceiptProviderFixture({ ...config, trust, port });
    client = createHttpNotificationCancellationReceiptProvider({
      trust,
      ...tls.worker,
      trustCa: tls.ca,
      timeoutMs: 500,
    });
    expect(await client.lookup(request, first)).toEqual(first);
    const clock = vi.spyOn(Date, 'now').mockReturnValue(sample.bound.notAfterMs + 1);
    try {
      expect(await client.lookup(request, first)).toEqual(first);
      await expect(client.perform(request)).rejects.toThrow();
    } finally {
      clock.mockRestore();
    }
    expect(server.counters().performs).toBe(0);
    expect(server.counters().signatures).toBe(0);
    await expect(
      client.lookup({ ...request, cancellationPreparationDigest: sha256('different') }),
    ).rejects.toThrow();
  } finally {
    client.close();
    await server.close();
    await rm(tls.root, { recursive: true, force: true });
  }
});

it('outcome uses distinct mTLS protocol and preserves its exact original through lost response and provider restart', async () => {
  const tls = await tlsFixture();
  const sample = notificationOutcomeReceiptProviderSample({
    workerSpki: notificationFixtureSpki(tls.worker.certificate),
    providerSpki: notificationFixtureSpki(tls.server.certificate),
  });
  const config = {
    directory: join(tls.root, 'outcome'),
    trust: sample.trust,
    signerPrivateKey: sample.original.signerPrivateKey,
    ...tls.server,
    trustCa: tls.ca,
  };
  let server = await createNotificationReceiptProviderFixture(config);
  let client = createHttpNotificationOutcomeReceiptProvider({
    trust: server.trust,
    ...tls.worker,
    trustCa: tls.ca,
    timeoutMs: 500,
  });
  try {
    const request = createNotificationOutcomeReceiptRequest(server.trust, {
      payloadHex: sample.request.payloadHex,
      outcomePreparationDigest: sample.request.outcomePreparationDigest,
    });
    expect(() =>
      createHttpNotificationReceiptProvider({
        trust: server.trust,
        ...tls.worker,
        trustCa: tls.ca,
      }),
    ).toThrow();
    expect(() =>
      createHttpNotificationCancellationReceiptProvider({
        trust: server.trust,
        ...tls.worker,
        trustCa: tls.ca,
      }),
    ).toThrow();
    expect(await client.lookup(request)).toBeUndefined();
    server.setFault('LOSE_RESPONSE');
    await expect(client.perform(request)).rejects.toThrow();
    expect(server.counters()).toEqual({ performs: 1, lookups: 1, signatures: 1 });
    server.setFault('NONE');
    const first = await client.lookup(request);
    expect(first?.outcome).toBe('SIGNED');
    expect(await client.lookup(request, first)).toEqual(first);
    const port = Number(new URL(server.origin).port),
      trust = server.trust;
    client.close();
    await server.close();
    server = await createNotificationReceiptProviderFixture({ ...config, trust, port });
    client = createHttpNotificationOutcomeReceiptProvider({
      trust,
      ...tls.worker,
      trustCa: tls.ca,
      timeoutMs: 500,
    });
    expect(await client.lookup(request, first)).toEqual(first);
    const clock = vi.spyOn(Date, 'now').mockReturnValue(sample.bound.notAfterMs + 1);
    try {
      expect(await client.lookup(request, first)).toEqual(first);
      await expect(client.perform(request)).rejects.toThrow();
    } finally {
      clock.mockRestore();
    }
    expect(server.counters().performs).toBe(0);
    expect(server.counters().signatures).toBe(0);
    await expect(
      client.lookup({ ...request, outcomePreparationDigest: sha256('different') }),
    ).rejects.toThrow();
  } finally {
    client.close();
    await server.close();
    await rm(tls.root, { recursive: true, force: true });
  }
});

function completionTlsSample(tls: Awaited<ReturnType<typeof tlsFixture>>, origin: string) {
  const f = completionDispositionInputFixture(),
    now = Date.now() - 100;
  const current = completionWorkerFixture({
    validFromMs: now - 1000,
    validUntilMs: now + 60000,
    workloadKeyDigest: sha256(notificationFixtureSpki(tls.worker.certificate)),
  });
  const worker = validateNotificationCompletionWorkerOriginal(current.installation);
  const signer = {
    ...f.signer,
    workerInstallationDigest: worker.installationDigest,
    workerProfileDigest: worker.input.pins.signedProfileDigest,
    workerIssuerSpkiHex: worker.input.pins.issuerSpkiHex,
    providerOrigin: origin,
    providerTlsSpkiDigest: sha256(notificationFixtureSpki(tls.server.certificate)),
    validFromNs: String(BigInt(now - 1000) * 1000000n),
    validUntilNs: String(BigInt(now + 60000) * 1000000n),
  };
  const journal = {
    ...f.input.journal,
    initialWorker: worker.input,
    attempts: [
      {
        ...f.input.journal.attempts[0]!,
        workerInstallationDigest: worker.installationDigest,
        claimedAtMs: now,
        leaseUntilMs: now + 30000,
        finishedAtMs: now + 1,
      },
    ],
  };
  const before = {
    schema: 'pc.notification.completion-disposition-state.v1',
    journal,
    disposition: null,
  };
  const after = {
    ...before,
    disposition: 'ADMITTED',
    receiptId: f.input.metadata.receiptId,
    operationId: f.input.metadata.operationId,
    workItemKind: 'NONE',
    workItemId: f.input.metadata.receiptId,
    cursorMode: 'ADVANCE',
  };
  const prepared = buildNotificationCompletionDispositionSigning({
    ...f.input,
    journal,
    workerInstallation: worker.input,
    signerInstallation: signer,
    metadata: {
      ...f.input.metadata,
      recordedAtMs: now + 2,
      beforeStateDigest: sha256(before),
      afterStateDigest: sha256(after),
    },
  });
  const successor = completionWorkerFixture({
    validFromMs: now - 1000,
    validUntilMs: now + 120000,
    profileId: completionTestId(61),
    workloadCredentialId: completionTestId(62),
    workloadEpoch: '2',
    workloadKeyDigest: sha256(notificationFixtureSpki(tls.foreign.certificate)),
  });
  return {
    trust: { signer, worker: worker.input },
    request: prepared.request,
    key: f.key,
    successor: successor.installation,
  };
}
/** Compose the existing durable external fixture; no additional provider server. */
async function completionTlsPeer(tls: Awaited<ReturnType<typeof tlsFixture>>) {
  const original = completionTlsSample(tls, 'https://127.0.0.1:4433');
  const config = {
    directory: join(tls.root, 'completion-state'),
    trust: original.trust,
    completionLookupWorkers: [original.successor],
    signerPrivateKey: original.key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    ...tls.server,
    trustCa: tls.ca,
  };
  let server = await createNotificationReceiptProviderFixture(config);
  const trust = server.trust;
  const claims = validateNotificationCompletionDispositionRequest(
    original.request,
    original.trust,
  ).claims;
  const request = createNotificationCompletionDispositionRequest(trust, {
    payloadHex: encodeNotificationClaim('NotificationCompletionDispositionReceiptV1', {
      ...claims,
      signerInstallationDigest: validateNotificationCompletionDispositionSignerInstallation(
        trust.signer,
      ).digest,
    }).toString('hex'),
    dispositionPreparationDigest: original.request.dispositionPreparationDigest,
  });
  const prior = { performs: 0, lookups: 0, signatures: 0 };
  return {
    sample: { ...original, trust, request },
    origin: server.origin,
    directory: config.directory,
    setFault: (fault: NotificationReceiptFixtureFault) => server.setFault(fault),
    counts() {
      const current = server.counters();
      return {
        performs: prior.performs + current.performs,
        lookups: prior.lookups + current.lookups,
        signatures: prior.signatures + current.signatures,
      };
    },
    currentCounts: () => server.counters(),
    hold: (point: NotificationCompletionFixtureBoundary) => server.holdCompletion(point),
    withdrawSuccessor: () =>
      server.withdrawCompletionWorker(
        validateNotificationCompletionWorkerOriginal(original.successor).installationDigest,
      ),
    withdrawOriginal: () =>
      server.withdrawCompletionWorker(
        validateNotificationCompletionWorkerOriginal(trust.worker).installationDigest,
      ),
    revokeSigner: () => server.revoke(),
    async restart() {
      const current = server.counters();
      prior.performs += current.performs;
      prior.lookups += current.lookups;
      prior.signatures += current.signatures;
      const port = Number(new URL(server.origin).port);
      await server.close();
      server = await createNotificationReceiptProviderFixture({ ...config, trust, port });
    },
    close: () => server.close(),
  };
}
/** Deliberately bypass the client validator to exercise the external peer boundary. */
async function completionRawPost(
  tls: Awaited<ReturnType<typeof tlsFixture>>,
  origin: string,
  body: unknown,
  lookup: boolean,
  successor = false,
) {
  const peer = successor ? tls.foreign : tls.worker;
  const bytes = Buffer.from(canonicalJson(body));
  return new Promise<number>((resolve, reject) => {
    const req = httpsRequest(
      new URL(
        `/v1/notification-completion-disposition-receipts/${lookup ? 'lookup' : 'perform'}`,
        origin,
      ),
      {
        method: 'POST',
        cert: peer.certificate,
        key: peer.privateKey,
        ca: tls.ca,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        agent: false,
        headers: { 'content-type': 'application/json', 'content-length': bytes.length },
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode ?? 0));
      },
    );
    req.setTimeout(1000, () => req.destroy(new Error('Test peer deadline')));
    req.on('error', reject);
    req.end(bytes);
  });
}
it('completion disposition uses current successor TLS for original lookup after signing loss, historical expiry and provider restart without re-signing', async () => {
  const tls = await tlsFixture(),
    peer = await completionTlsPeer(tls),
    s = peer.sample;
  const config = {
    trust: s.trust,
    transportWorker: s.trust.worker,
    ...tls.worker,
    trustCa: tls.ca,
    timeoutMs: 200,
  };
  let client = createHttpNotificationCompletionDispositionProvider(config);
  try {
    expect(await client.lookup(s.request)).toBeUndefined();
    expect(peer.counts()).toEqual({ performs: 0, lookups: 1, signatures: 0 });
    peer.setFault('LOSE_RESPONSE');
    await expect(client.perform(s.request)).rejects.toThrow(
      'Notification receipt signing outcome requires reconciliation',
    );
    expect(peer.counts()).toEqual({ performs: 1, lookups: 1, signatures: 1 });
    peer.setFault('ABSENT');
    expect(await client.lookup(s.request)).toBeUndefined();
    expect(peer.counts()).toEqual({ performs: 1, lookups: 2, signatures: 1 });
    peer.setFault('NONE');
    const first = await client.lookup(s.request);
    expect(first?.outcome).toBe('SIGNED');
    const originalBytes = await readFile(
      join(peer.directory, `${s.request.signingAttemptId}.json`),
    );
    await peer.withdrawOriginal();
    await expect(client.lookup(s.request, first)).rejects.toThrow();
    expect(await completionRawPost(tls, peer.origin, s.request, false, true)).toBe(403);
    client.close();
    await peer.restart();
    expect(peer.currentCounts()).toEqual({ performs: 0, lookups: 0, signatures: 0 });
    expect(await readFile(join(peer.directory, `${s.request.signingAttemptId}.json`))).toEqual(
      originalBytes,
    );
    expect(await completionRawPost(tls, peer.origin, s.request, false)).toBe(403);
    client = createHttpNotificationCompletionDispositionProvider({
      ...config,
      transportWorker: s.successor,
      ...tls.foreign,
    });
    expect(await client.lookup(s.request, first)).toEqual(first);
    await peer.revokeSigner();
    expect(await client.lookup(s.request, first)).toEqual(first);
    await expect(client.perform(s.request)).rejects.toThrow();
    expect(peer.counts().performs).toBe(1);
    const clock = vi
      .spyOn(Date, 'now')
      .mockReturnValue(Number(BigInt(s.trust.signer.validUntilNs) / 1000000n) + 1);
    try {
      expect(await client.lookup(s.request, first)).toEqual(first);
      await expect(client.perform(s.request)).rejects.toThrow();
      expect(() => createHttpNotificationCompletionDispositionProvider(config)).toThrow();
    } finally {
      clock.mockRestore();
    }
    const expiredSuccessor = vi
      .spyOn(Date, 'now')
      .mockReturnValue(
        validateNotificationCompletionWorkerOriginal(s.successor).profile.validUntilMs + 1,
      );
    try {
      const bound = validateNotificationCompletionDispositionRequest(s.request, s.trust);
      const before = peer.counts();
      expect(
        await completionRawPost(
          tls,
          peer.origin,
          {
            originalRequest: s.request,
            requestDigest: bound.requestDigest,
          },
          true,
          true,
        ),
      ).toBe(403);
      expect(peer.counts()).toEqual(before);
    } finally {
      expiredSuccessor.mockRestore();
    }
    const changed = { ...s.request, dispositionPreparationDigest: sha256('changed') };
    await expect(client.lookup(changed)).rejects.toThrow();
    peer.setFault('ABSENT');
    await expect(client.lookup(s.request, first)).rejects.toThrow();
    peer.setFault('NONE');
    expect(await client.lookup(s.request, first)).toEqual(first);
    expect(await readFile(join(peer.directory, `${s.request.signingAttemptId}.json`))).toEqual(
      originalBytes,
    );
    const absent: NotificationCompletionDispositionRequest = {
      ...s.request,
      signingAttemptId: completionTestId(99),
    };
    await expect(client.lookup(absent)).rejects.toThrow(); // Request/payload binding prevents invented lookup identities.
    expect(peer.counts().signatures).toBe(1);
    expect(peer.counts().performs).toBe(1);
    client.close();
    await expect(client.lookup(s.request)).rejects.toThrow();
  } finally {
    client.close();
    await peer.close();
    await rm(tls.root, { recursive: true, force: true });
  }
}, 20000);
it('completion disposition rejects TLS/scope/purpose/key substitutions, bounded malformed responses and timeout without retry', async () => {
  const tls = await tlsFixture(),
    peer = await completionTlsPeer(tls),
    s = peer.sample;
  const config = {
    trust: s.trust,
    transportWorker: s.trust.worker,
    ...tls.worker,
    trustCa: tls.ca,
    timeoutMs: 1000,
  };
  const client = createHttpNotificationCompletionDispositionProvider(config);
  try {
    expect(() =>
      createHttpNotificationCompletionDispositionProvider({ ...config, ...tls.foreign }),
    ).toThrow();
    const foreign = completionWorkerFixture({
      validFromMs: Date.now() - 1000,
      validUntilMs: Date.now() + 60000,
      privacyDomainId: completionTestId(80),
      workloadKeyDigest: s.successor.pins.workloadKeyDigest,
    });
    expect(() =>
      createHttpNotificationCompletionDispositionProvider({
        ...config,
        transportWorker: foreign.installation,
        ...tls.foreign,
      }),
    ).toThrow();
    expect(() =>
      createHttpNotificationCompletionDispositionProvider({
        ...config,
        trust: {
          ...s.trust,
          signer: {
            ...s.trust.signer,
            purpose: 'pc.cose.notification-delivery-outcome-receipt.v1',
          },
        },
      }),
    ).toThrow();
    expect(() =>
      createHttpNotificationCompletionDispositionProvider({
        ...config,
        trust: {
          ...s.trust,
          signer: {
            ...s.trust.signer,
            providerTlsSpkiDigest: sha256(Buffer.from(s.trust.signer.publicKeySpkiHex, 'hex')),
          },
        },
      }),
    ).toThrow();
    const wrongTrust = {
      ...s.trust,
      signer: { ...s.trust.signer, providerTlsSpkiDigest: sha256('wrong-pin') },
    };
    const wrongSigner = validateNotificationCompletionDispositionSignerInstallation(
      wrongTrust.signer,
    );
    const claims = validateNotificationCompletionDispositionRequest(s.request, s.trust).claims;
    const wrongRequest = createNotificationCompletionDispositionRequest(wrongTrust, {
      payloadHex: encodeNotificationClaim('NotificationCompletionDispositionReceiptV1', {
        ...claims,
        signerInstallationDigest: wrongSigner.digest,
      }).toString('hex'),
      dispositionPreparationDigest: s.request.dispositionPreparationDigest,
    });
    const wrongPin = createHttpNotificationCompletionDispositionProvider({
      ...config,
      trust: wrongTrust,
    });
    try {
      await expect(wrongPin.lookup(wrongRequest)).rejects.toThrow();
    } finally {
      wrongPin.close();
    }
    const wrongCa = createHttpNotificationCompletionDispositionProvider({
      ...config,
      trustCa: tls.foreign.certificate,
    });
    try {
      await expect(wrongCa.lookup(s.request)).rejects.toThrow();
    } finally {
      wrongCa.close();
    }
    expect(peer.counts()).toEqual({ performs: 0, lookups: 0, signatures: 0 });
    for (const changed of [
      { ...s.request, privacyDomainId: completionTestId(80) },
      { ...s.request, purpose: 'pc.cose.notification-delivery-outcome-receipt.v1' },
      { ...s.request, signerKeyId: sha256('foreign-signer') },
    ])
      expect(await completionRawPost(tls, peer.origin, changed, false)).toBe(403);
    expect(await completionRawPost(tls, peer.origin, s.request, false, true)).toBe(403);
    const first = await client.perform(s.request);
    expect(first.outcome).toBe('SIGNED');
    const conflicting = {
      ...s.request,
      dispositionPreparationDigest: sha256('conflicting-intent'),
    };
    expect(await completionRawPost(tls, peer.origin, conflicting, false)).toBe(403);
    expect(peer.counts()).toEqual({ performs: 2, lookups: 0, signatures: 1 });
    for (const fault of [
      'TIMEOUT',
      'BAD_JSON',
      'DUPLICATE_KEY',
      'WRONG_REQUEST',
      'INVALID_SIGNATURE',
      'OVERSIZED',
      'REDIRECT',
      'WRONG_CONTENT_TYPE',
      'TRUNCATED',
    ] as const) {
      peer.setFault(fault);
      const before = peer.counts().lookups;
      await expect(client.lookup(s.request, first)).rejects.toThrow(
        'Notification receipt signing outcome requires reconciliation',
      );
      expect(peer.counts().lookups).toBe(before + 1);
      expect(peer.counts().performs).toBe(2);
      expect(peer.counts().signatures).toBe(1);
    }
    peer.setFault('NONE');
    expect(await client.lookup(s.request, first)).toEqual(first);
    for (const extra of [
      { timeoutMs: 0 },
      { timeoutMs: 10001 },
      { privateKey: Buffer.from('PRIVATE_CANARY') },
      { trustCa: Buffer.alloc(0) },
    ])
      expect(() =>
        createHttpNotificationCompletionDispositionProvider({ ...config, ...extra }),
      ).toThrow();
  } finally {
    client.close();
    await peer.close();
    await rm(tls.root, { recursive: true, force: true });
  }
}, 20000);
it('completion external fixture rejects untrusted, foreign and ambiguous successor installations before listening', async () => {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent) throw new Error('Owned OPENPC_TEST_TMP_ROOT required');
  const directory = await mkdtemp(join(parent, 'completion-fixture-installation-'));
  const f = completionDispositionInputFixture();
  const worker = validateNotificationCompletionWorkerOriginal(f.input.workerInstallation).input;
  const config = {
    directory,
    trust: { signer: f.signer, worker },
    signerPrivateKey: f.key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    certificate: Buffer.alloc(0),
    privateKey: Buffer.alloc(0),
    trustCa: Buffer.alloc(0),
  };
  try {
    await expect(
      createNotificationReceiptProviderFixture({ ...config, completionLookupWorkers: [worker] }),
    ).rejects.toThrow('Ambiguous completion lookup installation');
    await expect(
      createNotificationReceiptProviderFixture({
        ...config,
        completionLookupWorkers: [{ ...worker, signed: { ...worker.signed, coseHex: '00' } }],
      }),
    ).rejects.toThrow('Notification completion worker admission unavailable');
    for (const overrides of [
      { participantId: completionTestId(90) },
      { privacyDomainId: completionTestId(91) },
      { environmentId: 'foreign' },
      { producerTrustDigest: sha256('foreign-producer') },
    ]) {
      const foreign = completionWorkerFixture(overrides).installation;
      await expect(
        createNotificationReceiptProviderFixture({ ...config, completionLookupWorkers: [foreign] }),
      ).rejects.toThrow('Invalid completion lookup installation');
    }
  } finally {
    config.signerPrivateKey.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});

it.each(['BODY', 'SIGN', 'PERSISTED', 'LOOKUP'] as const)(
  'completion provider orders %s use against withdrawal and retains the admitted original',
  async (boundary) => {
    const tls = await tlsFixture(),
      peer = await completionTlsPeer(tls),
      s = peer.sample;
    const client = createHttpNotificationCompletionDispositionProvider({
      trust: s.trust,
      transportWorker: s.successor,
      ...tls.foreign,
      trustCa: tls.ca,
      timeoutMs: 500,
    });
    const lookup = boundary === 'LOOKUP';
    const requestDigest = validateNotificationCompletionDispositionRequest(
      s.request,
      s.trust,
    ).requestDigest;
    const body = lookup ? { originalRequest: s.request, requestDigest } : s.request;
    let firstBytes: Buffer | undefined;
    if (lookup) {
      expect(await completionRawPost(tls, peer.origin, s.request, false)).toBe(200);
      firstBytes = await readFile(join(peer.directory, `${s.request.signingAttemptId}.json`));
    }
    const hold = peer.hold(boundary);
    const pending = completionRawPost(tls, peer.origin, body, lookup, lookup);
    let withdrawal: Promise<void> | undefined;
    try {
      await hold.reached;
      let settled = false;
      withdrawal = (lookup ? peer.withdrawSuccessor() : peer.withdrawOriginal()).then(() => {
        settled = true;
      });
      // This second actual request reaches the now-closed admission. Its denial
      // cannot release or replace the first admitted use or its durable result.
      expect(await completionRawPost(tls, peer.origin, body, lookup, lookup)).toBe(403);
      if (boundary === 'BODY') {
        await withdrawal;
        expect(settled).toBe(true);
      } else expect(settled).toBe(false);
      hold.release();
      expect(await pending).toBe(boundary === 'BODY' ? 403 : 200);
      await withdrawal;
      expect(await completionRawPost(tls, peer.origin, body, lookup, lookup)).toBe(403);
      expect(peer.counts().signatures).toBe(boundary === 'BODY' ? 0 : 1);
      if (!lookup) {
        const observed = await client.lookup(s.request);
        expect(observed?.outcome).toBe(boundary === 'BODY' ? undefined : 'SIGNED');
        if (observed) {
          const stored = await readFile(join(peer.directory, `${s.request.signingAttemptId}.json`));
          await peer.restart();
          expect(await client.lookup(s.request, observed)).toEqual(observed);
          expect(
            await readFile(join(peer.directory, `${s.request.signingAttemptId}.json`)),
          ).toEqual(stored);
        }
      } else {
        expect(await readFile(join(peer.directory, `${s.request.signingAttemptId}.json`))).toEqual(
          firstBytes,
        );
      }
    } finally {
      hold.release();
      await Promise.allSettled([pending, ...(withdrawal ? [withdrawal] : [])]);
      client.close();
      await peer.close();
      await rm(tls.root, { recursive: true, force: true });
    }
  },
  20000,
);
it.each(['BODY', 'SIGN', 'PERSISTED', 'LOOKUP'] as const)(
  'completion provider rechecks expiry after awaited %s boundary without losing signed originals',
  async (boundary) => {
    const tls = await tlsFixture(),
      peer = await completionTlsPeer(tls),
      s = peer.sample;
    const lookup = boundary === 'LOOKUP';
    const bound = validateNotificationCompletionDispositionRequest(s.request, s.trust);
    const body = lookup
      ? { originalRequest: s.request, requestDigest: bound.requestDigest }
      : s.request;
    let firstBytes: Buffer | undefined;
    if (lookup) {
      expect(await completionRawPost(tls, peer.origin, s.request, false)).toBe(200);
      firstBytes = await readFile(join(peer.directory, `${s.request.signingAttemptId}.json`));
    }
    const hold = peer.hold(boundary);
    const pending = completionRawPost(tls, peer.origin, body, lookup, lookup);
    let clock: ReturnType<typeof vi.spyOn> | undefined;
    try {
      await hold.reached;
      const worker = validateNotificationCompletionWorkerOriginal(
        lookup ? s.successor : s.trust.worker,
      );
      clock = vi.spyOn(Date, 'now').mockReturnValue(worker.profile.validUntilMs + 1);
      hold.release();
      expect(await pending).toBe(403);
      const signed = boundary === 'PERSISTED' || lookup;
      expect(peer.counts().signatures).toBe(signed ? 1 : 0);
      if (lookup) {
        expect(await readFile(join(peer.directory, `${s.request.signingAttemptId}.json`))).toEqual(
          firstBytes,
        );
      } else {
        // The successor remains current while original authority has expired.
        const client = createHttpNotificationCompletionDispositionProvider({
          trust: s.trust,
          transportWorker: s.successor,
          ...tls.foreign,
          trustCa: tls.ca,
          timeoutMs: 500,
        });
        try {
          const observed = await client.lookup(s.request);
          expect(observed?.outcome).toBe(signed ? 'SIGNED' : undefined);
          if (observed) {
            const bytes = await readFile(
              join(peer.directory, `${s.request.signingAttemptId}.json`),
            );
            await peer.restart();
            expect(await client.lookup(s.request, observed)).toEqual(observed);
            expect(
              await readFile(join(peer.directory, `${s.request.signingAttemptId}.json`)),
            ).toEqual(bytes);
          }
        } finally {
          client.close();
        }
      }
      expect(peer.counts().signatures).toBe(signed ? 1 : 0);
    } finally {
      hold.release();
      await Promise.allSettled([pending]);
      clock?.mockRestore();
      await peer.close();
      await rm(tls.root, { recursive: true, force: true });
    }
  },
  20000,
);

// External TLS cancellation proof only; internal dispatch/SQL authority is not simulated.
it('STARTED abort closes active and queued requests, preserving only original lookup', async () => {
  const tls = await tlsFixture();
  const sample = notificationReceiptProviderSample({
    workerSpki: notificationFixtureSpki(tls.worker.certificate),
    providerSpki: notificationFixtureSpki(tls.server.certificate),
  });
  const server = await createNotificationReceiptProviderFixture({
    directory: join(tls.root, 'abort'),
    trust: sample.trust,
    signerPrivateKey: sample.signerPrivateKey,
    ...tls.server,
    trustCa: tls.ca,
  });
  const controller = new AbortController();
  const options = { trust: server.trust, ...tls.worker, trustCa: tls.ca, timeoutMs: 5000 };
  const client = createHttpNotificationReceiptProvider({ ...options, signal: controller.signal });
  const request = createNotificationReceiptRequest(server.trust, {
    payloadHex: sample.request.payloadHex,
    deliveryPreparationDigest: sample.request.deliveryPreparationDigest,
  });
  let fresh: ReturnType<typeof createHttpNotificationReceiptProvider> | undefined;
  try {
    const early = new AbortController();
    early.abort();
    expect(() =>
      createHttpNotificationReceiptProvider({ ...options, signal: early.signal }),
    ).toThrow();
    expect(server.counters()).toEqual({ performs: 0, lookups: 0, signatures: 0 });
    server.setFault('TIMEOUT');
    const first = client.perform(request).then(
      () => 'unexpected-success',
      () => 'unknown',
    );
    await vi.waitFor(() => expect(server.counters().signatures).toBe(1));
    const queued = client.lookup(request).then(
      () => 'unexpected-success',
      () => 'unknown',
    );
    controller.abort();
    client.close();
    controller.abort();
    client.close();
    expect(await Promise.all([first, queued])).toEqual(['unknown', 'unknown']);
    expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
    expect(server.counters()).toEqual({ performs: 1, lookups: 0, signatures: 1 });
    await expect(client.lookup(request)).rejects.toThrow();
    server.setFault('NONE');
    fresh = createHttpNotificationReceiptProvider(options);
    const original = await fresh.lookup(request);
    expect(original?.outcome).toBe('SIGNED');
    expect(await fresh.lookup(request, original!)).toEqual(original);
    expect(server.counters()).toEqual({ performs: 1, lookups: 2, signatures: 1 });
  } finally {
    client.close();
    fresh?.close();
    await server.close();
    sample.signerPrivateKey.fill(0);
    await rm(tls.root, { recursive: true, force: true });
  }
}, 15000);

// External TLS cancellation proof only; internal dispatch/SQL authority is not simulated.
it('CANCELLATION abort closes active and queued requests, preserving only original lookup', async () => {
  const tls = await tlsFixture();
  const sample = notificationCancellationReceiptProviderSample({
    workerSpki: notificationFixtureSpki(tls.worker.certificate),
    providerSpki: notificationFixtureSpki(tls.server.certificate),
  });
  const server = await createNotificationReceiptProviderFixture({
    directory: join(tls.root, 'abort'),
    trust: sample.trust,
    signerPrivateKey: sample.original.signerPrivateKey,
    ...tls.server,
    trustCa: tls.ca,
  });
  const controller = new AbortController();
  const options = { trust: server.trust, ...tls.worker, trustCa: tls.ca, timeoutMs: 5000 };
  const client = createHttpNotificationCancellationReceiptProvider({
    ...options,
    signal: controller.signal,
  });
  const request = createNotificationCancellationReceiptRequest(server.trust, {
    payloadHex: sample.request.payloadHex,
    cancellationPreparationDigest: sample.request.cancellationPreparationDigest,
  });
  let fresh: ReturnType<typeof createHttpNotificationCancellationReceiptProvider> | undefined;
  try {
    const early = new AbortController();
    early.abort();
    expect(() =>
      createHttpNotificationCancellationReceiptProvider({ ...options, signal: early.signal }),
    ).toThrow();
    expect(server.counters()).toEqual({ performs: 0, lookups: 0, signatures: 0 });
    server.setFault('TIMEOUT');
    const first = client.perform(request).then(
      () => 'unexpected-success',
      () => 'unknown',
    );
    await vi.waitFor(() => expect(server.counters().signatures).toBe(1));
    const queued = client.lookup(request).then(
      () => 'unexpected-success',
      () => 'unknown',
    );
    controller.abort();
    client.close();
    controller.abort();
    client.close();
    expect(await Promise.all([first, queued])).toEqual(['unknown', 'unknown']);
    expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
    expect(server.counters()).toEqual({ performs: 1, lookups: 0, signatures: 1 });
    await expect(client.lookup(request)).rejects.toThrow();
    server.setFault('NONE');
    fresh = createHttpNotificationCancellationReceiptProvider(options);
    const original = await fresh.lookup(request);
    expect(original?.outcome).toBe('SIGNED');
    expect(await fresh.lookup(request, original!)).toEqual(original);
    expect(server.counters()).toEqual({ performs: 1, lookups: 2, signatures: 1 });
  } finally {
    client.close();
    fresh?.close();
    await server.close();
    sample.original.signerPrivateKey.fill(0);
    await rm(tls.root, { recursive: true, force: true });
  }
}, 15000);

// External TLS cancellation proof only; internal dispatch/SQL authority is not simulated.
it('OUTCOME abort closes active and queued requests, preserving only original lookup', async () => {
  const tls = await tlsFixture();
  const sample = notificationOutcomeReceiptProviderSample({
    workerSpki: notificationFixtureSpki(tls.worker.certificate),
    providerSpki: notificationFixtureSpki(tls.server.certificate),
  });
  const server = await createNotificationReceiptProviderFixture({
    directory: join(tls.root, 'abort'),
    trust: sample.trust,
    signerPrivateKey: sample.original.signerPrivateKey,
    ...tls.server,
    trustCa: tls.ca,
  });
  const controller = new AbortController();
  const options = { trust: server.trust, ...tls.worker, trustCa: tls.ca, timeoutMs: 5000 };
  const client = createHttpNotificationOutcomeReceiptProvider({
    ...options,
    signal: controller.signal,
  });
  const request = createNotificationOutcomeReceiptRequest(server.trust, {
    payloadHex: sample.request.payloadHex,
    outcomePreparationDigest: sample.request.outcomePreparationDigest,
  });
  let fresh: ReturnType<typeof createHttpNotificationOutcomeReceiptProvider> | undefined;
  try {
    const early = new AbortController();
    early.abort();
    expect(() =>
      createHttpNotificationOutcomeReceiptProvider({ ...options, signal: early.signal }),
    ).toThrow();
    expect(server.counters()).toEqual({ performs: 0, lookups: 0, signatures: 0 });
    server.setFault('TIMEOUT');
    const first = client.perform(request).then(
      () => 'unexpected-success',
      () => 'unknown',
    );
    await vi.waitFor(() => expect(server.counters().signatures).toBe(1));
    const queued = client.lookup(request).then(
      () => 'unexpected-success',
      () => 'unknown',
    );
    controller.abort();
    client.close();
    controller.abort();
    client.close();
    expect(await Promise.all([first, queued])).toEqual(['unknown', 'unknown']);
    expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
    expect(server.counters()).toEqual({ performs: 1, lookups: 0, signatures: 1 });
    await expect(client.lookup(request)).rejects.toThrow();
    server.setFault('NONE');
    fresh = createHttpNotificationOutcomeReceiptProvider(options);
    const original = await fresh.lookup(request);
    expect(original?.outcome).toBe('SIGNED');
    expect(await fresh.lookup(request, original!)).toEqual(original);
    expect(server.counters()).toEqual({ performs: 1, lookups: 2, signatures: 1 });
  } finally {
    client.close();
    fresh?.close();
    await server.close();
    sample.original.signerPrivateKey.fill(0);
    await rm(tls.root, { recursive: true, force: true });
  }
}, 15000);

it.each(['abort', 'close'] as const)(
  'completion %s after durable signature rejects late response and queued I/O; restart only looks up original',
  async (stop) => {
    const tls = await tlsFixture(),
      peer = await completionTlsPeer(tls),
      controller = new AbortController();
    const options = {
      trust: peer.sample.trust,
      transportWorker: peer.sample.trust.worker,
      ...tls.worker,
      trustCa: tls.ca,
      timeoutMs: 5000,
    };
    const client = createHttpNotificationCompletionDispositionProvider({
      ...options,
      signal: controller.signal,
    });
    const hold = peer.hold('PERSISTED');
    let fresh: ReturnType<typeof createHttpNotificationCompletionDispositionProvider> | undefined;
    try {
      const early = new AbortController();
      early.abort();
      expect(() =>
        createHttpNotificationCompletionDispositionProvider({ ...options, signal: early.signal }),
      ).toThrow();
      expect(peer.counts()).toEqual({ performs: 0, lookups: 0, signatures: 0 });
      const first = client.perform(peer.sample.request).then(
        () => 'unexpected-success',
        () => 'unknown',
      );
      await hold.reached;
      const queued = client.lookup(peer.sample.request).then(
        () => 'unexpected-success',
        () => 'unknown',
      );
      if (stop === 'abort') controller.abort();
      else client.close();
      client.close();
      controller.abort();
      expect(await Promise.all([first, queued])).toEqual(['unknown', 'unknown']);
      expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
      hold.release();
      expect(peer.counts()).toEqual({ performs: 1, lookups: 0, signatures: 1 });
      await expect(client.lookup(peer.sample.request)).rejects.toThrow();
      await peer.restart();
      fresh = createHttpNotificationCompletionDispositionProvider(options);
      const original = await fresh.lookup(peer.sample.request);
      expect(original?.outcome).toBe('SIGNED');
      expect(await fresh.lookup(peer.sample.request, original!)).toEqual(original);
      expect(peer.counts()).toEqual({ performs: 1, lookups: 2, signatures: 1 });
    } finally {
      hold.release();
      client.close();
      fresh?.close();
      await peer.close();
      await rm(tls.root, { recursive: true, force: true });
    }
  },
  15000,
);
