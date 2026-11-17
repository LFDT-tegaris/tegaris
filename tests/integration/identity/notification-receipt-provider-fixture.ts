import { notificationCompletionDispositionSigningPurpose } from '../../../services/control-api/src/notifications/completion-disposition-signer.js';
import {
  validateNotificationCompletionWorkerOriginal,
  validateNotificationCompletionWorkerInstallation,
} from '../../../services/control-api/src/notifications/completion-worker-installation-contract.js';
import {
  validateNotificationCompletionDispositionRequest,
  validateNotificationCompletionDispositionObservation,
  type NotificationCompletionDispositionProviderTrust,
} from '../../../services/identity-service/src/domain/notification-completion-disposition-provider.js';
import { createServer } from 'node:https';
import { performance } from 'node:perf_hooks';
import type { TLSSocket } from 'node:tls';
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdir, open, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import {
  businessTransitionProfileForOperation,
  type NotificationDeliveryCancellationReceiptClaims,
  type NotificationDeliveryOutcomeReceiptClaims,
  evidenceKeyId,
  signNotificationClaim,
  encodeNotificationClaim,
  type NotificationWorkerProfileClaims,
  type NotificationDeliveryStartedReceiptClaims,
} from '../../../packages/security-kernel/src/index.js';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { validateNotificationWorkerInstallation } from '../../../services/control-api/src/notifications/worker-installation-contract.js';
import {
  notificationReceiptSigningPurpose,
  notificationCancellationSigningPurpose,
  notificationOutcomeSigningPurpose,
  type NotificationReceiptSignerInstallation,
} from '../../../services/control-api/src/notifications/receipt-signer-installation.js';
import {
  createNotificationReceiptRequest,
  validateNotificationReceiptRequest,
  validateNotificationReceiptObservation,
  type NotificationReceiptProviderTrust,
  type NotificationReceiptProviderObservation,
} from '../../../services/identity-service/src/domain/notification-receipt-provider.js';

import {
  createNotificationCancellationReceiptRequest,
  validateNotificationCancellationReceiptRequest,
  validateNotificationCancellationReceiptObservation,
} from '../../../services/identity-service/src/domain/notification-cancellation-receipt-provider.js';

import {
  createNotificationOutcomeReceiptRequest,
  validateNotificationOutcomeReceiptRequest,
  validateNotificationOutcomeReceiptObservation,
} from '../../../services/identity-service/src/domain/notification-outcome-receipt-provider.js';

const id = (n: number) => `01990000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = (s: string) => sha256(Buffer.from(s));
const pair = () => {
  const p = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    spki: p.publicKey.export({ type: 'spki', format: 'der' }),
    key: p.privateKey.export({ type: 'pkcs8', format: 'der' }),
  };
};
/** Cryptographic component fixture only, never a real Identity admission or a
 * seeded delivery. The genuine PostgreSQL journey must use its own installed
 * worker and durable native preparation. Private keys belong to external fixture. */
export function notificationReceiptProviderSample(
  input: { workerSpki?: Buffer; providerSpki?: Buffer; origin?: string; nowMs?: number } = {},
) {
  const now = input.nowMs ?? Date.now(),
    issuer = pair(),
    signer = pair(),
    workload = input.workerSpki ?? pair().spki,
    provider = input.providerSpki ?? pair().spki;
  const profile: NotificationWorkerProfileClaims = {
    environmentId: 'local',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(3),
    revision: '1',
    validFromMs: now - 1000,
    validUntilMs: now + 600000,
    sourceId: id(4),
    serviceId: 'LS-NOTIFICATION',
    processRole: 'ROLE-NOTIFICATION-WORKER',
    subscriptionId: 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1',
    principalId: id(5),
    workloadCredentialId: id(6),
    workloadEpoch: '1',
    workloadId: 'native-notification-worker',
    producerTrustDigest: hash('producer'),
    routingProfileDigest: hash('routing'),
    kmsInstallationDigest: hash('kms'),
    receiptSignerSpki: signer.spki.toString('hex'),
    issuerKeyId: evidenceKeyId(issuer.spki),
  };
  const signed = signNotificationClaim(
    'NotificationWorkerProfileV1',
    issuer.key,
    issuer.spki,
    profile,
  );
  issuer.key.fill(0);
  const worker = {
    pins: {
      issuerSpkiHex: issuer.spki.toString('hex'),
      signedProfileDigest: sha256(signed.cose),
      environmentId: profile.environmentId,
      participantId: profile.participantId,
      privacyDomainId: profile.privacyDomainId,
      profileId: profile.profileId,
      revision: profile.revision,
      serviceId: profile.serviceId,
      processRole: profile.processRole,
      subscriptionId: profile.subscriptionId,
      principalId: profile.principalId,
      workloadCredentialId: profile.workloadCredentialId,
      workloadEpoch: profile.workloadEpoch,
      workloadId: profile.workloadId,
      workloadKeyDigest: evidenceKeyId(workload),
    },
    signed: { payloadHex: signed.payload.toString('hex'), coseHex: signed.cose.toString('hex') },
    installationReference: 'external-fixture-component-profile',
  };
  const installed = validateNotificationWorkerInstallation(worker, now);
  const pins: NotificationReceiptSignerInstallation = {
    owner: 'LS-NOTIFICATION',
    purpose: notificationReceiptSigningPurpose,
    environmentId: profile.environmentId,
    participantId: profile.participantId,
    privacyDomainId: profile.privacyDomainId,
    installationId: id(7),
    workerInstallationDigest: installed.installationDigest,
    workerProfileDigest: worker.pins.signedProfileDigest,
    workerIssuerSpkiHex: worker.pins.issuerSpkiHex,
    principalId: profile.principalId,
    workloadCredentialId: profile.workloadCredentialId,
    workloadEpoch: profile.workloadEpoch,
    workloadId: profile.workloadId,
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://test-notification/receipt#v1',
    secretVersion: 'v1',
    publicKeySpkiHex: signer.spki.toString('hex'),
    keyEpoch: '1',
    providerId: 'notification-test',
    providerOrigin: input.origin ?? 'https://localhost:4433',
    providerTlsSpkiDigest: evidenceKeyId(provider),
    validFromNs: (BigInt(now - 1000) * 1000000n).toString(),
    validUntilNs: (BigInt(now + 600000) * 1000000n).toString(),
    installationReference: 'external-fixture-component-signer',
  };
  const claims: NotificationDeliveryStartedReceiptClaims = {
    environmentId: profile.environmentId,
    participantId: profile.participantId,
    privacyDomainId: profile.privacyDomainId,
    receiptId: id(10),
    operationId: id(11),
    attemptId: id(12),
    notificationOccurrenceId: id(13),
    payloadObjectId: id(14),
    keyPreparationId: id(15),
    sourceEventId: id(16),
    sourceDataDigest: hash('source-data'),
    sourceReceiptDigest: hash('source-receipt'),
    routingProfileDigest: profile.routingProfileDigest,
    workerProfileDigest: worker.pins.signedProfileDigest,
    authoritySnapshotDigest: hash('authority'),
    endpointId: id(17),
    endpointRevision: '1',
    templateDigest: hash('template'),
    payloadDigest: hash('payload'),
    encryptedObjectDigest: hash('ciphertext'),
    keyId: hash('notification-payload-key'),
    signedChannelProfileDigest: hash('channel'),
    attemptDigest: hash('attempt'),
    contextDigest: hash('context'),
    attemptNumber: 1,
    startedAtMs: now,
    deadlineAtMs: now + 30000,
    deliveryRevision: '1',
    beforeStateDigest: hash('before'),
    afterStateDigest: hash('after'),
    signerKeyId: evidenceKeyId(signer.spki),
  };
  const trust = { signer: pins, worker };
  const request = createNotificationReceiptRequest(trust, {
    payloadHex: encodeNotificationClaim('NotificationDeliveryStartedReceiptV1', claims).toString(
      'hex',
    ),
    deliveryPreparationDigest: hash('original-preparation'),
  });
  return { trust, profile, claims, request, signerPrivateKey: signer.key };
}
export type NotificationReceiptFixtureFault =
  | 'NONE'
  | 'ABSENT'
  | 'LOSE_RESPONSE'
  | 'TIMEOUT'
  | 'OVERSIZED'
  | 'BAD_JSON'
  | 'DUPLICATE_KEY'
  | 'WRONG_REQUEST'
  | 'INVALID_SIGNATURE'
  | 'WRONG_CONTENT_TYPE'
  | 'REDIRECT'
  | 'TRUNCATED';
export type NotificationCompletionFixtureBoundary = 'BODY' | 'SIGN' | 'LOOKUP' | 'PERSISTED';
/** Only the external provider is simulated. Actual TLS peers and canonical native
 * signatures are used; original results/revocation are fsynced and survive a
 * fixture restart. This is not OpenPC dispatch/Identity/PG acceptance. */
export async function createNotificationReceiptProviderFixture<
  T extends NotificationReceiptProviderTrust | NotificationCompletionDispositionProviderTrust,
>(config: {
  directory: string;
  trust: T;
  /** External provider installation allow-list, never internal Identity admission. */
  completionLookupWorkers?: readonly unknown[];
  signerPrivateKey: Buffer;
  certificate: Buffer;
  privateKey: Buffer;
  trustCa: Buffer;
  port?: number;
}) {
  let trust = config.trust;
  const legacyTrust = () => trust as NotificationReceiptProviderTrust;
  const completion = z
    .object({ purpose: z.literal(notificationCompletionDispositionSigningPurpose) })
    .safeParse(trust.signer).success;
  if (!completion && config.completionLookupWorkers !== undefined)
    throw new Error('Invalid fixture family');
  const originalWorker = completion
    ? validateNotificationCompletionWorkerOriginal(trust.worker)
    : undefined;
  const lookupWorkers = completion
    ? [
        originalWorker!,
        ...(config.completionLookupWorkers ?? []).map(validateNotificationCompletionWorkerOriginal),
      ]
    : [];
  for (const worker of lookupWorkers) {
    const p = worker.profile,
      original = originalWorker!.profile;
    if (
      p.environmentId !== original.environmentId ||
      p.participantId !== original.participantId ||
      p.privacyDomainId !== original.privacyDomainId ||
      p.producerTrustDigest !== original.producerTrustDigest
    )
      throw new Error('Invalid completion lookup installation');
  }
  if (new Set(lookupWorkers.map((w) => w.profile.workloadKeyDigest)).size !== lookupWorkers.length)
    throw new Error('Ambiguous completion lookup installation');
  const cancellation = legacyTrust().signer.purpose === notificationCancellationSigningPurpose;
  const outcome = legacyTrust().signer.purpose === notificationOutcomeSigningPurpose;
  const path = completion
    ? '/v1/notification-completion-disposition-receipts'
    : outcome
      ? '/v1/notification-outcome-receipts'
      : cancellation
        ? '/v1/notification-cancellation-receipts'
        : '/v1/notification-receipts';
  const validateRequest = (value: unknown) => {
    if (completion) return validateNotificationCompletionDispositionRequest(value, trust);
    if (outcome) return validateNotificationOutcomeReceiptRequest(value, legacyTrust());
    if (cancellation) return validateNotificationCancellationReceiptRequest(value, legacyTrust());
    const original = validateNotificationReceiptRequest(value, legacyTrust());
    return {
      ...original,
      notBeforeMs: original.claims.startedAtMs,
      notAfterMs: original.claims.deadlineAtMs,
    };
  };
  const validateObservation = (original: unknown, observed: unknown) => {
    if (completion)
      return validateNotificationCompletionDispositionObservation(
        validateNotificationCompletionDispositionRequest(original, trust).request,
        observed,
        trust,
      );
    if (outcome)
      return validateNotificationOutcomeReceiptObservation(
        validateNotificationOutcomeReceiptRequest(original, legacyTrust()).request,
        observed,
        legacyTrust(),
      );
    if (cancellation)
      return validateNotificationCancellationReceiptObservation(
        validateNotificationCancellationReceiptRequest(original, legacyTrust()).request,
        observed,
        legacyTrust(),
      );
    return validateNotificationReceiptObservation(
      validateNotificationReceiptRequest(original, legacyTrust()).request,
      observed,
      legacyTrust(),
    );
  };
  await mkdir(config.directory, { recursive: true, mode: 0o700 });
  let fault: NotificationReceiptFixtureFault = 'NONE',
    performs = 0,
    lookups = 0,
    signatures = 0;
  const inflight = new Map<string, Promise<unknown>>();
  // External provider-local admission fence only. Withdrawal closes new uses
  // synchronously and cannot acknowledge until every admitted use has settled.
  // Keep the fence until actual settlement, including filesystem uncertainty;
  // an empty signing-only inflight map does not establish safe withdrawal.
  const completionUses = new Map<
    string,
    { closing: boolean; uses: Set<Promise<void>>; withdrawal: Promise<void> | undefined }
  >(
    lookupWorkers.map((w) => [
      w.installationDigest,
      {
        closing: false,
        uses: new Set<Promise<void>>(),
        withdrawal: undefined as Promise<void> | undefined,
      },
    ]),
  );
  const holds = new Map<
    NotificationCompletionFixtureBoundary,
    {
      entered: () => void;
      resumed: Promise<void>;
    }
  >();
  const useTimeoutMs = 1500;
  async function boundedCompletion<T>(pending: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        pending,
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error('Completion provider use unresolved')),
            useTimeoutMs,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }
  async function completionBoundary(point: NotificationCompletionFixtureBoundary) {
    const hold = holds.get(point);
    if (!hold) return;
    holds.delete(point);
    hold.entered();
    await boundedCompletion(hold.resumed);
  }
  async function admitCompletionUse(
    worker: NonNullable<typeof originalWorker>,
    live: () => boolean,
  ) {
    const state = completionUses.get(worker.installationDigest)!;
    if (state.closing) throw new Error('Completion worker withdrawn');
    const withdrawn = await existing(`withdrawn-${worker.installationDigest.slice(7)}`);
    if (state.closing || withdrawn || !live()) throw new Error('Completion worker withdrawn');
    validateNotificationCompletionWorkerInstallation(worker.input, Date.now());
    let release!: () => void;
    const done = new Promise<void>((resolve) => {
      release = resolve;
    });
    state.uses.add(done);
    const deadline = performance.now() + useTimeoutMs;
    return {
      confirm() {
        if (!live() || performance.now() >= deadline)
          throw new Error('Completion provider use unresolved');
        validateNotificationCompletionWorkerInstallation(worker.input, Date.now());
      },
      release() {
        state.uses.delete(done);
        release();
      },
    };
  }

  async function existing(name: string) {
    try {
      return await readFile(join(config.directory, name));
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw e;
    }
  }
  async function persist(name: string, bytes: Buffer) {
    const file = await open(join(config.directory, name), 'wx', 0o600);
    try {
      await file.writeFile(bytes);
      await file.sync();
    } finally {
      await file.close();
    }
    const dir = await open(config.directory, 'r');
    try {
      await dir.sync();
    } finally {
      await dir.close();
    }
  }
  const server = createServer(
    {
      cert: config.certificate,
      key: config.privateKey,
      ca: config.trustCa,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    },
    async (req, res) => {
      let use: Awaited<ReturnType<typeof admitCompletionUse>> | undefined;
      // Body parsing is outside admission and cannot hold withdrawal open.
      const requestTimer = completion
        ? setTimeout(() => req.destroy(), useTimeoutMs * 2)
        : undefined;
      try {
        const socket = req.socket as TLSSocket,
          peer = socket.getPeerCertificate();
        if (
          !socket.authorized ||
          !peer.raw ||
          req.method !== 'POST' ||
          ![`${path}/perform`, `${path}/lookup`].includes(req.url ?? '')
        )
          throw new Error();
        const peerKey = evidenceKeyId(
          new X509Certificate(peer.raw).publicKey.export({ type: 'spki', format: 'der' }),
        );
        const lookup = req.url!.endsWith('/lookup');
        const worker = completion
          ? lookupWorkers.find((w) => w.profile.workloadKeyDigest === peerKey)
          : undefined;
        if (completion) {
          if (
            !worker ||
            (!lookup && worker.installationDigest !== originalWorker!.installationDigest)
          )
            throw new Error();
          validateNotificationCompletionWorkerInstallation(worker.input, Date.now());
          await completionBoundary('BODY');
        } else if (peerKey !== legacyTrust().worker.pins.workloadKeyDigest) throw new Error();
        let length = 0;
        const chunks: Buffer[] = [];
        for await (const chunk of req) {
          const b = Buffer.from(chunk as Buffer);
          length += b.length;
          if (length > 196608) throw new Error();
          chunks.push(b);
        }
        const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)),
          body: unknown = JSON.parse(text);
        if (canonicalJson(body) !== text) throw new Error();
        const envelope = lookup
          ? z
              .strictObject({
                originalRequest: z.unknown(),
                requestDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
              })
              .parse(body)
          : undefined;
        const valid = validateRequest(lookup ? envelope!.originalRequest : body),
          r = valid.request;
        if (lookup && envelope!.requestDigest !== valid.requestDigest) throw new Error();
        if (worker)
          use = await admitCompletionUse(
            worker,
            () => !socket.destroyed && socket.authorized && socket.getProtocol() === 'TLSv1.3',
          );
        const file = `${r.signingAttemptId}.json`;
        const perform = async () => {
          const prior = await existing(file);
          use?.confirm();
          if (prior) {
            const p = JSON.parse(prior.toString('utf8')) as {
              request: unknown;
              observation: unknown;
            };
            if (canonicalJson(p.request) !== canonicalJson(r)) throw new Error();
            return validateObservation(r, p.observation);
          }
          const revoked = await existing('revoked');
          if (completion) await completionBoundary('SIGN');
          use?.confirm();
          const now = Date.now();
          let observation: NotificationReceiptProviderObservation;
          if (revoked || now < valid.notBeforeMs || now >= valid.notAfterMs) {
            observation = {
              schemaVersion: 1,
              providerId: r.providerId,
              signingAttemptId: r.signingAttemptId,
              requestDigest: valid.requestDigest,
              recordedAtMs: now,
              outcome: 'REJECTED',
              reason: revoked ? 'REVOKED' : 'EXPIRED',
              coseHex: null,
            };
          } else {
            const signed = signNotificationClaim(
              completion
                ? 'NotificationCompletionDispositionReceiptV1'
                : outcome
                  ? 'NotificationDeliveryOutcomeReceiptV1'
                  : cancellation
                    ? 'NotificationDeliveryCancellationReceiptV1'
                    : 'NotificationDeliveryStartedReceiptV1',
              config.signerPrivateKey,
              Buffer.from(legacyTrust().signer.publicKeySpkiHex, 'hex'),
              valid.claims,
            );
            signatures++;
            observation = {
              schemaVersion: 1,
              providerId: r.providerId,
              signingAttemptId: r.signingAttemptId,
              requestDigest: valid.requestDigest,
              recordedAtMs: now,
              outcome: 'SIGNED',
              reason: null,
              coseHex: signed.cose.toString('hex'),
            };
          }
          validateObservation(r, observation);
          await persist(file, Buffer.from(canonicalJson({ request: r, observation })));
          if (completion) await completionBoundary('PERSISTED');
          use?.confirm();
          return observation;
        };
        let output: unknown;
        if (lookup) {
          lookups++;
          const prior = await existing(file);
          if (completion) await completionBoundary('LOOKUP');
          use?.confirm();
          if (!prior || fault === 'ABSENT')
            output = {
              state: 'ABSENT',
              signingAttemptId: r.signingAttemptId,
              requestDigest: valid.requestDigest,
            };
          else {
            const p = JSON.parse(prior.toString('utf8')) as {
              request: unknown;
              observation: unknown;
            };
            if (canonicalJson(p.request) !== canonicalJson(r)) throw new Error();
            output = {
              state: 'OBSERVED',
              observation: validateObservation(r, p.observation),
            };
          }
        } else {
          performs++;
          const earlier = inflight.get(file);
          if (earlier) await earlier;
          const pending = perform();
          inflight.set(file, pending);
          try {
            output = await pending;
          } finally {
            if (inflight.get(file) === pending) inflight.delete(file);
          }
        }
        use?.confirm();
        const mode = fault;
        if (mode === 'LOSE_RESPONSE') {
          req.socket.destroy();
          return;
        }
        if (mode === 'TIMEOUT') {
          return;
        } // Client's total deadline ends this socket.
        if (mode === 'REDIRECT') {
          res.writeHead(307, { location: 'https://invalid.example/' }).end();
          return;
        }
        if (mode === 'WRONG_REQUEST' || mode === 'INVALID_SIGNATURE') {
          const changed =
            mode === 'WRONG_REQUEST' ? { requestDigest: hash('wrong') } : { coseHex: '00' };
          if (!lookup) output = { ...(output as object), ...changed };
          else if ((output as { state: string }).state === 'OBSERVED')
            output = {
              state: 'OBSERVED',
              observation: { ...(output as { observation: object }).observation, ...changed },
            };
        }
        const encoded =
          mode === 'OVERSIZED'
            ? 'x'.repeat(196609)
            : mode === 'BAD_JSON'
              ? 'PRIVATE_CANARY'
              : mode === 'DUPLICATE_KEY'
                ? '{"state":"ABSENT","state":"OBSERVED"}'
                : canonicalJson(output);
        res.writeHead(200, {
          'content-type': mode === 'WRONG_CONTENT_TYPE' ? 'text/plain' : 'application/json',
          'content-length': Buffer.byteLength(encoded) + (mode === 'TRUNCATED' ? 5 : 0),
        });
        if (completion)
          await boundedCompletion(new Promise<void>((resolve) => res.end(encoded, resolve)));
        else res.end(encoded);
      } catch {
        if (res.headersSent) req.socket.destroy();
        else {
          res.writeHead(403, { 'content-type': 'application/json' });
          res.end('{"code":"UNAVAILABLE"}');
        }
      } finally {
        clearTimeout(requestTimer);
        use?.release();
      }
    },
  );
  server.on('tlsClientError', () => {});
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port ?? 0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Fixture listener unavailable');
  const origin = `https://127.0.0.1:${address.port}`;
  trust = { ...trust, signer: { ...legacyTrust().signer, providerOrigin: origin } } as T;
  return {
    origin,
    trust,
    setFault(value: NotificationReceiptFixtureFault) {
      fault = value;
    },
    counters() {
      return { performs, lookups, signatures };
    },
    holdCompletion(point: NotificationCompletionFixtureBoundary) {
      if (!completion || holds.has(point)) throw new Error('Invalid completion hold');
      let entered!: () => void, release!: () => void;
      const reached = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const resumed = new Promise<void>((resolve) => {
        release = resolve;
      });
      holds.set(point, { entered, resumed });
      return { reached: boundedCompletion(reached), release };
    },
    async withdrawCompletionWorker(installationDigest: string) {
      const state = completionUses.get(installationDigest);
      if (!completion || !state) throw new Error('Unknown completion worker');
      if (!state.withdrawal) {
        state.closing = true;
        const admitted = [...state.uses];
        state.withdrawal = boundedCompletion(
          (async () => {
            const name = `withdrawn-${installationDigest.slice(7)}`;
            if (!(await existing(name))) await persist(name, Buffer.from('withdrawn'));
            await Promise.all(admitted);
          })(),
        );
      }
      // A timeout or persistence failure remains explicit uncertainty. Keep the
      // closed fence and rejected result; never report successful withdrawal.
      await state.withdrawal;
    },
    async revoke() {
      if (!(await existing('revoked'))) await persist('revoked', Buffer.from('revoked'));
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((e) => (e ? reject(e) : resolve())),
      );
    },
  };
}
export const notificationFixtureSpki = (certificate: Buffer) =>
  new X509Certificate(certificate).publicKey.export({ format: 'der', type: 'spki' });
export const notificationFixtureDigest = (bytes: Buffer) =>
  'sha256:' + createHash('sha256').update(bytes).digest('hex');

/** Prepared real-Identity/PG corpus for the canonical fixture. The supplied
 * withAdmission must traverse its existing genuine mTLS listener/Identity owner;
 * no fabricated admission, profile or intermediate business state is accepted.
 * This helper is not executed by the provider's cryptographic component tests. */
export async function assertNotificationReceiptSignerInstallationCases(input: {
  installation: NotificationReceiptSignerInstallation;
  installer<T>(run: (client: import('pg').PoolClient) => Promise<T>): Promise<T>;
  withAdmission<T>(
    run: (
      client: import('pg').PoolClient,
      admission: import('../../../services/identity-service/src/domain/notification-worker.js').NotificationWorkerAdmission,
    ) => Promise<T>,
  ): Promise<T>;
  assertWorkerWithdrawalBlocked(): Promise<void>;
}) {
  const { expect } = await import('vitest');
  const { assertNotificationDeliveryResultAuthority, withNotificationDeliveryResultAuthority } =
    await import('../../../services/control-api/src/notifications/delivery-result-admission.js');
  const {
    installInitialNotificationReceiptSigner,
    installInitialNotificationCancellationSigner,
    installInitialNotificationOutcomeSigner,
    validateNotificationOutcomeSignerInstallation,
    notificationOutcomeSigningPurpose,
    withCurrentNotificationOutcomeSigner,
    assertNotificationOutcomeSigner,
    validateNotificationCancellationSignerInstallation,
    notificationCancellationSigningPurpose,
    withCurrentNotificationCancellationSigner,
    assertNotificationCancellationSigner,
    withCurrentNotificationReceiptSigner,
    withdrawNotificationReceiptSigner,
    assertNotificationReceiptSigner,
    validateNotificationReceiptSignerInstallation,
    NotificationReceiptSignerError,
  } =
    await import('../../../services/control-api/src/notifications/receipt-signer-installation.js');
  const installed = validateNotificationReceiptSignerInstallation(input.installation),
    p = installed.pins;
  const selector = {
    worker: {
      participantId: p.participantId,
      privacyDomainId: p.privacyDomainId,
      installationDigest: p.workerInstallationDigest,
    },
    signerInstallationDigest: installed.digest,
  };
  expect(
    await input.installer((client) => installInitialNotificationReceiptSigner(client, p)),
  ).toBe(installed.digest);
  expect(
    await input.installer((client) => installInitialNotificationReceiptSigner(client, p)),
  ).toBe(installed.digest);
  await expect(
    input.installer((client) =>
      installInitialNotificationReceiptSigner(client, { ...p, keyEpoch: '2' }),
    ),
  ).rejects.toThrow();
  const outcome = validateNotificationOutcomeSignerInstallation({
    ...p,
    installationId: id(99032),
    purpose: notificationOutcomeSigningPurpose,
  });
  const outcomeSelector = { ...selector, signerInstallationDigest: outcome.digest };
  expect(
    await input.installer((client) =>
      installInitialNotificationOutcomeSigner(client, outcome.pins),
    ),
  ).toBe(outcome.digest);
  expect(
    await input.installer((client) =>
      installInitialNotificationOutcomeSigner(client, outcome.pins),
    ),
  ).toBe(outcome.digest);
  await input.withAdmission(async (client, admission) => {
    let escaped:
      | import('../../../services/control-api/src/notifications/receipt-signer-installation.js').NotificationReceiptSigner
      | undefined;
    await withNotificationDeliveryResultAuthority(
      client,
      admission,
      outcomeSelector,
      async (signer) => {
        escaped = signer;
        assertNotificationOutcomeSigner(signer, client, outcomeSelector);
        expect(
          (await client.query('select openpc.current_action_intent_id() action')).rows[0]?.action,
        ).toBe('ACT-EVIDENCE_EXPORT_RECORDS-V1');
        // Receipt proposal only: no delivery/signing attempt or business result
        // is seeded. This exercises the real peer/signer authority intersection.
        await client.query('select openpc.assert_notification_outcome_signing_owner()');
        await client.query('select openpc.assert_notification_outcome_publication_owner()');
        const signingPrivileges = await client.query(
          `select has_table_privilege(current_user,'control.notification_delivery_outcome_signing','INSERT') can_insert,
            has_table_privilege(current_user,'control.notification_delivery_outcome_signing','UPDATE') can_update,
            has_table_privilege(current_user,'control.notification_delivery_outcome_signing','DELETE') can_delete,
            has_table_privilege(current_user,'control.notification_delivery_outcome','INSERT') can_publish,
            has_table_privilege(current_user,'control.notification_delivery_observation','INSERT') can_observe`,
        );
        expect(signingPrivileges.rows).toEqual([
          {
            can_insert: true,
            can_update: true,
            can_delete: false,
            can_publish: true,
            can_observe: true,
          },
        ]);
        const w = admission.installation.profile;
        const receipt: NotificationDeliveryOutcomeReceiptClaims = {
          environmentId: w.environmentId,
          participantId: w.participantId,
          privacyDomainId: w.privacyDomainId,
          receiptId: id(99101),
          operationId: id(99102),
          notificationOccurrenceId: id(99103),
          attemptId: id(99104),
          startOperationId: id(99105),
          startReceiptDigest: hash('started'),
          dispatchClaimDigest: hash('dispatch'),
          sourceReceiptDigest: hash('source'),
          workerProfileDigest: admission.installation.input.pins.signedProfileDigest,
          routingProfileDigest: w.routingProfileDigest,
          authoritySnapshotDigest: admission.authorityDigest,
          endpointId: id(99106),
          endpointRevision: '1',
          payloadDigest: hash('payload'),
          gatewayReceiptId: id(99107),
          gatewayReceiptDigest: hash('gateway'),
          gatewayCoseDigest: hash('cose'),
          observationDigest: hash('observation'),
          deliveryRevision: '2',
          beforeStateDigest: hash('before'),
          afterStateDigest: hash('after'),
          outcome: 'PERMANENT_FAILURE',
          beforeDeliveryState: 'STARTED',
          afterDeliveryState: 'FAILED',
          attemptCount: 1,
          attemptLimit: 6,
          nextAttemptAtMs: 0,
          cancelRequested: 'NO',
          observedAtMs: Date.now(),
          recordedAtMs: Date.now(),
          signerKeyId: signer.signerKeyId,
        };
        expect(
          assertNotificationDeliveryResultAuthority(
            client,
            admission,
            signer,
            outcomeSelector,
            receipt,
          ),
        ).toEqual(receipt);
        for (const patch of [
          { authoritySnapshotDigest: hash('caller-authority') },
          { participantId: id(99108) },
          { privacyDomainId: id(99109) },
          { workerProfileDigest: hash('other-worker') },
          { signerKeyId: hash('other-key') },
          { routingProfileDigest: hash('other-route') },
          { recordedAtMs: w.validUntilMs },
        ])
          expect(() =>
            assertNotificationDeliveryResultAuthority(client, admission, signer, outcomeSelector, {
              ...receipt,
              ...patch,
            }),
          ).toThrow();
        expect(() =>
          assertNotificationDeliveryResultAuthority(
            client,
            { ...admission },
            signer,
            outcomeSelector,
            receipt,
          ),
        ).toThrow();
        expect(() =>
          assertNotificationDeliveryResultAuthority(
            client,
            admission,
            { ...signer },
            outcomeSelector,
            receipt,
          ),
        ).toThrow();
        expect(() => assertNotificationReceiptSigner(signer, client, outcomeSelector)).toThrow();
        expect(() =>
          assertNotificationCancellationSigner(signer, client, outcomeSelector),
        ).toThrow();
        expect(() =>
          assertNotificationOutcomeSigner({ ...signer }, client, outcomeSelector),
        ).toThrow();
      },
    );
    expect(() => assertNotificationOutcomeSigner(escaped!, client, outcomeSelector)).toThrow();
    const action = async () =>
      (await client.query('select openpc.current_action_intent_id() action')).rows[0]?.action;
    expect(await action()).toBe('ACT-POLICY_READ_EFFECTIVE_ACCESS-V1');
    await client.query("select set_config('openpc.result_admission_test','before',true)");
    await expect(
      withNotificationDeliveryResultAuthority(client, admission, outcomeSelector, async () => {
        await client.query("select set_config('openpc.result_admission_test','changed',true)");
        throw new Error('bounded callback failure');
      }),
    ).rejects.toThrow();
    expect(await action()).toBe('ACT-POLICY_READ_EFFECTIVE_ACCESS-V1');
    expect(
      (await client.query("select current_setting('openpc.result_admission_test') value")).rows[0]
        ?.value,
    ).toBe('before');
    // A database error leaves the savepoint aborted; the owning rollback must
    // recover both context and transaction before another independent operation.
    await expect(
      withNotificationDeliveryResultAuthority(client, admission, outcomeSelector, async () => {
        await client.query('select 1/0');
      }),
    ).rejects.toThrow();
    expect(await action()).toBe('ACT-POLICY_READ_EFFECTIVE_ACCESS-V1');
    let wrong = 0;
    await expect(
      withNotificationDeliveryResultAuthority(
        client,
        { ...admission },
        outcomeSelector,
        async () => {
          wrong++;
        },
      ),
    ).rejects.toThrow();
    await expect(
      withNotificationDeliveryResultAuthority(client, admission, selector, async () => {
        wrong++;
      }),
    ).rejects.toThrow();
    await expect(
      withCurrentNotificationReceiptSigner(client, admission, outcomeSelector, async () => {
        wrong++;
      }),
    ).rejects.toThrow();
    await expect(
      withCurrentNotificationCancellationSigner(client, admission, outcomeSelector, async () => {
        wrong++;
      }),
    ).rejects.toThrow();
    await expect(
      withCurrentNotificationOutcomeSigner(client, admission, selector, async () => {
        wrong++;
      }),
    ).rejects.toThrow();
    expect(wrong).toBe(0);
  });
  await input.installer((client) => withdrawNotificationReceiptSigner(client, outcomeSelector));
  await expect(
    input.withAdmission((client, admission) =>
      withCurrentNotificationOutcomeSigner(client, admission, outcomeSelector, async () => {}),
    ),
  ).rejects.toThrow();
  await expect(
    input.installer((client) => installInitialNotificationOutcomeSigner(client, outcome.pins)),
  ).rejects.toThrow();
  // Distinct initial purpose grants coexist for the same real installed worker.
  // Neither a STARTED grant nor a copied live capability authorizes cancellation.
  const cancellation = validateNotificationCancellationSignerInstallation({
    ...p,
    installationId: id(99031),
    purpose: notificationCancellationSigningPurpose,
  });
  const cancelSelector = { ...selector, signerInstallationDigest: cancellation.digest };
  expect(
    await input.installer((client) =>
      installInitialNotificationCancellationSigner(client, cancellation.pins),
    ),
  ).toBe(cancellation.digest);
  expect(
    await input.installer((client) =>
      installInitialNotificationCancellationSigner(client, cancellation.pins),
    ),
  ).toBe(cancellation.digest);
  await expect(
    input.installer((client) => installInitialNotificationReceiptSigner(client, cancellation.pins)),
  ).rejects.toThrow();
  await input.withAdmission(async (client, admission) => {
    let escaped:
      | import('../../../services/control-api/src/notifications/receipt-signer-installation.js').NotificationReceiptSigner
      | undefined;
    await withCurrentNotificationCancellationSigner(
      client,
      admission,
      cancelSelector,
      async (signer) => {
        escaped = signer;
        assertNotificationCancellationSigner(signer, client, cancelSelector);
        expect(() => assertNotificationReceiptSigner(signer, client, cancelSelector)).toThrow();
        expect(() =>
          assertNotificationCancellationSigner({ ...signer }, client, cancelSelector),
        ).toThrow();
      },
    );
    expect(() => assertNotificationCancellationSigner(escaped!, client, cancelSelector)).toThrow();
    let wrongPurposeCalls = 0;
    await expect(
      withCurrentNotificationReceiptSigner(client, admission, cancelSelector, async () => {
        wrongPurposeCalls++;
      }),
    ).rejects.toThrow();
    await expect(
      withCurrentNotificationCancellationSigner(client, admission, selector, async () => {
        wrongPurposeCalls++;
      }),
    ).rejects.toThrow();
    expect(wrongPurposeCalls).toBe(0);
  });
  await input.installer((client) => withdrawNotificationReceiptSigner(client, cancelSelector));
  await expect(
    input.withAdmission((client, admission) =>
      withCurrentNotificationCancellationSigner(client, admission, cancelSelector, async () => {}),
    ),
  ).rejects.toThrow();
  await expect(
    input.installer((client) =>
      installInitialNotificationCancellationSigner(client, cancellation.pins),
    ),
  ).rejects.toThrow();
  await input.withAdmission(async (client, admission) => {
    await client.query("select set_config('openpc.test_receipt_signer_probe','0',true)");
    let escaped:
      | import('../../../services/control-api/src/notifications/receipt-signer-installation.js').NotificationReceiptSigner
      | undefined;
    await withCurrentNotificationReceiptSigner(client, admission, selector, async (signer) => {
      escaped = signer;
      assertNotificationReceiptSigner(signer, client, selector);
      expect(() => assertNotificationReceiptSigner({ ...signer }, client, selector)).toThrow();
      expect(() =>
        assertNotificationReceiptSigner(signer, {} as import('pg').PoolClient, selector),
      ).toThrow();
      expect(() =>
        assertNotificationReceiptSigner(signer, client, {
          ...selector,
          signerInstallationDigest: sha256('other'),
        }),
      ).toThrow();
    });
    expect(() => assertNotificationReceiptSigner(escaped!, client, selector)).toThrow();
    let entered = false;
    await expect(
      withCurrentNotificationReceiptSigner(client, admission, selector, async () => {
        entered = true;
        await client.query("select set_config('openpc.test_receipt_signer_probe','1',true)");
        throw new Error('PRIVATE_CANARY');
      }),
    ).rejects.toThrow('Notification receipt signer unavailable');
    expect(entered).toBe(true);
    expect(
      (await client.query("select current_setting('openpc.test_receipt_signer_probe') value"))
        .rows[0]?.value,
    ).toBe('0');
  });
  let entered!: () => void, release!: () => void;
  const arrival = new Promise<void>((resolve) => {
      entered = resolve;
    }),
    held = new Promise<void>((resolve) => {
      release = resolve;
    });
  const pending = input.withAdmission((client, admission) =>
    withCurrentNotificationReceiptSigner(client, admission, selector, async () => {
      entered();
      await held;
    }),
  );
  try {
    await Promise.race([
      arrival,
      pending.then(() => {
        throw new Error('Signer callback not entered');
      }),
    ]);
    await input.installer(async (client) => {
      await client.query('select openpc.assert_request_context(true)');
      expect((await client.query('select current_user role')).rows).toEqual([
        { role: 'openpc_control_owner' },
      ]);
      expect(
        (
          await client.query(
            "select pg_try_advisory_xact_lock(hashtextextended('notification-receipt-signer:'||$1::text||':'||$2::text,0)) allowed",
            [p.participantId, p.privacyDomainId],
          )
        ).rows,
      ).toEqual([{ allowed: false }]);
      await expect(withdrawNotificationReceiptSigner(client, selector)).rejects.toBeInstanceOf(
        NotificationReceiptSignerError,
      );
      const row = await client.query(
        'select state,trust_bytes from control.notification_receipt_signer_installation where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3 and worker_installation_digest=$4',
        [p.participantId, p.privacyDomainId, installed.digest, p.workerInstallationDigest],
      );
      expect(row.rows).toEqual([{ state: 'ACTIVE', trust_bytes: installed.bytes }]);
    });
    await input.assertWorkerWithdrawalBlocked();
  } finally {
    release();
  }
  await pending;
  await input.installer((client) => withdrawNotificationReceiptSigner(client, selector));
  let calls = 0;
  await expect(
    input.withAdmission((client, admission) =>
      withCurrentNotificationReceiptSigner(client, admission, selector, async () => {
        calls++;
      }),
    ),
  ).rejects.toThrow();
  expect(calls).toBe(0);
  await expect(
    input.installer((client) => installInitialNotificationReceiptSigner(client, p)),
  ).rejects.toThrow();
}

export function notificationCancellationReceiptProviderSample(
  input: Parameters<typeof notificationReceiptProviderSample>[0] = {},
) {
  const original = notificationReceiptProviderSample(input);
  const trust: NotificationReceiptProviderTrust = {
    ...original.trust,
    signer: { ...original.trust.signer, purpose: notificationCancellationSigningPurpose },
  };
  const s = original.claims;
  const claims: NotificationDeliveryCancellationReceiptClaims = {
    environmentId: s.environmentId,
    participantId: s.participantId,
    privacyDomainId: s.privacyDomainId,
    receiptId: id(81),
    operationId: id(82),
    notificationOccurrenceId: s.notificationOccurrenceId,
    payloadDigest: s.payloadDigest,
    sourceEventId: s.sourceEventId,
    sourceReceiptDigest: s.sourceReceiptDigest,
    workerProfileDigest: s.workerProfileDigest,
    routingProfileDigest: s.routingProfileDigest,
    authoritySnapshotDigest: sha256('cancel-authority'),
    endpointId: s.endpointId,
    endpointRevision: '2',
    causeOperationId: id(83),
    causeAction: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
    causeProfileDigest: businessTransitionProfileForOperation(
      'CFG-OP-UPDATE-NOTIFICATION-ENDPOINT',
    )!.profileDigest,
    causeReceiptDigest: sha256('original-cause-receipt'),
    causeBeforeStateDigest: sha256('endpoint-before'),
    causeAfterStateDigest: sha256('endpoint-after'),
    causeEndpointRevision: '3',
    deliveryRevision: '1',
    beforeStateDigest: sha256('delivery-before'),
    afterStateDigest: sha256('delivery-after'),
    beforeDeliveryState: 'PENDING',
    afterDeliveryState: 'CANCELLED',
    attemptCount: 0,
    disposition: 'CANCELLED_BEFORE_START',
    recordedAtMs: s.startedAtMs,
    signerKeyId: s.signerKeyId,
  };
  const request = createNotificationCancellationReceiptRequest(trust, {
    payloadHex: encodeNotificationClaim(
      'NotificationDeliveryCancellationReceiptV1',
      claims,
    ).toString('hex'),
    cancellationPreparationDigest: sha256('retained-preparation'),
  });
  const bound = validateNotificationCancellationReceiptRequest(request, trust);
  const sign = () =>
    signNotificationClaim(
      'NotificationDeliveryCancellationReceiptV1',
      original.signerPrivateKey,
      Buffer.from(trust.signer.publicKeySpkiHex, 'hex'),
      claims,
    );
  const observation = {
    schemaVersion: 1 as const,
    providerId: request.providerId,
    signingAttemptId: request.signingAttemptId,
    requestDigest: bound.requestDigest,
    recordedAtMs: claims.recordedAtMs,
    outcome: 'SIGNED' as const,
    reason: null,
    coseHex: sign().cose.toString('hex'),
  };
  return { original, trust, claims, request, bound, observation, sign };
}

export function notificationOutcomeReceiptProviderSample(
  input: Parameters<typeof notificationReceiptProviderSample>[0] = {},
) {
  const original = notificationReceiptProviderSample(input);
  const trust: NotificationReceiptProviderTrust = {
    ...original.trust,
    signer: { ...original.trust.signer, purpose: notificationOutcomeSigningPurpose },
  };
  const s = original.claims;
  const claims: NotificationDeliveryOutcomeReceiptClaims = {
    environmentId: s.environmentId,
    participantId: s.participantId,
    privacyDomainId: s.privacyDomainId,
    receiptId: id(101),
    operationId: id(102),
    notificationOccurrenceId: s.notificationOccurrenceId,
    attemptId: s.attemptId,
    startOperationId: s.operationId,
    startReceiptDigest: hash('original-started-receipt'),
    dispatchClaimDigest: hash('original-dispatch-claim'),
    sourceReceiptDigest: s.sourceReceiptDigest,
    workerProfileDigest: s.workerProfileDigest,
    routingProfileDigest: s.routingProfileDigest,
    authoritySnapshotDigest: hash('outcome-authority'),
    endpointId: s.endpointId,
    endpointRevision: s.endpointRevision,
    payloadDigest: s.payloadDigest,
    gatewayReceiptId: id(106),
    gatewayReceiptDigest: hash('gateway-payload'),
    gatewayCoseDigest: hash('gateway-cose'),
    observationDigest: hash('original-gateway-observation'),
    deliveryRevision: '2',
    beforeStateDigest: hash('delivery-before'),
    afterStateDigest: hash('delivery-after'),
    outcome: 'DELIVERED',
    beforeDeliveryState: 'STARTED',
    afterDeliveryState: 'DELIVERED',
    attemptCount: 1,
    attemptLimit: 6,
    nextAttemptAtMs: 0,
    cancelRequested: 'NO',
    observedAtMs: s.startedAtMs,
    recordedAtMs: s.startedAtMs,
    signerKeyId: s.signerKeyId,
  };
  const request = createNotificationOutcomeReceiptRequest(trust, {
    payloadHex: encodeNotificationClaim('NotificationDeliveryOutcomeReceiptV1', claims).toString(
      'hex',
    ),
    outcomePreparationDigest: sha256('retained-preparation'),
  });
  const bound = validateNotificationOutcomeReceiptRequest(request, trust);
  const sign = () =>
    signNotificationClaim(
      'NotificationDeliveryOutcomeReceiptV1',
      original.signerPrivateKey,
      Buffer.from(trust.signer.publicKeySpkiHex, 'hex'),
      claims,
    );
  const observation = {
    schemaVersion: 1 as const,
    providerId: request.providerId,
    signingAttemptId: request.signingAttemptId,
    requestDigest: bound.requestDigest,
    recordedAtMs: claims.recordedAtMs,
    outcome: 'SIGNED' as const,
    reason: null,
    coseHex: sign().cose.toString('hex'),
  };
  return { original, trust, claims, request, bound, observation, sign };
}
