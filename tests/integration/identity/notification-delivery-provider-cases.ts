import { generateKeyPairSync } from 'node:crypto';
import {
  encodeNotificationClaim,
  encodeNotificationDeliveryRequestedData,
  evidenceKeyId,
  signNotificationClaim,
  type NotificationWorkerProfileClaims,
  type NotificationDeliveryRequestedReceiptClaims,
  type NotificationDeliveryStartedReceiptClaims,
} from '../../../packages/security-kernel/src/index.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import {
  notificationIdempotencyDigest,
  notificationScopeDigest,
  verifyInstalledNotificationChannel,
  type AdapterCallContextV1,
  type NotificationDeliveryAttemptBinding,
  type NotificationGatewayTransportV1,
} from '../../../services/control-api/src/notifications/gateway-contracts.js';
import {
  initialDeliverySnapshot,
  planNotificationDelivery,
} from '../../../services/control-api/src/notifications/delivery-policy.js';
import { notificationDeliveryStateDigest } from '../../../services/control-api/src/notifications/delivery-start-contract.js';
import { validateNotificationWorkerInstallation } from '../../../services/control-api/src/notifications/worker-installation-contract.js';
import { validateNotificationDeliveryStartTransition } from '../../../services/control-api/src/notifications/delivery-start-transition.js';
/** Cryptographic/external-transport component fixture only. Synthetic signed
 * STARTED is not an internal durable claim, Identity admission or payload grant. */
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = (n: number) => sha256(String(n));
export function notificationDeliveryProviderSample(
  options: {
    endpoint?: string;
    serverSpkiDigest?: string;
    channel?: NotificationGatewayTransportV1['channel'];
    nowMs?: number;
  } = {},
) {
  const now = options.nowMs ?? Date.now();
  const payload = Buffer.from('{"message":"ready"}');
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const issuerSpki = issuer.publicKey.export({ type: 'spki', format: 'der' });
  const signerSpki = signer.publicKey.export({ type: 'spki', format: 'der' });
  const transport: NotificationGatewayTransportV1 = {
    protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1',
    channel: options.channel ?? 'WEBHOOK',
    destinationRef: `urn:openpc:resource:${id(4)}`,
    credentialRef: `urn:openpc:resource:${id(5)}`,
    endpoint: options.endpoint ?? 'https://gateway.test/',
    addresses: ['127.0.0.1'],
    serverSpkiDigest: options.serverSpkiDigest ?? h(1),
    requestTimeoutMs: 10000,
    maxPayloadBytes: 1024,
  };
  const profile = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(3),
    revision: '1',
    validFromMs: now - 1000,
    validUntilMs: now + 600000,
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
    payloadDigest: sha256(payload),
    encryptedObjectDigest: h(10),
    keyId: h(11),
    recordedAtMs: now - 1,
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
    payloadBytes: payload.length,
    attemptId: id(20),
    attemptNumber: 1,
    startedAtMs: now,
    deadlineAtMs: now + 10000,
  };
  const context: AdapterCallContextV1 = {
    authorizationDigest: h(13),
    profileDigest: channel.signedProfileDigest,
    authorizationContextId: id(21),
    authorizationContextEpoch: 1,
    accessClassIds: ['ACCESS-NOTIFICATION'],
    scopeDigest: notificationScopeDigest(attempt),
    deadlineAt: new Date(now + 10000).toISOString(),
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
    now - 1,
  );
  const after = planNotificationDelivery(before, 6, now).next;
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
    startedAtMs: now,
    deadlineAtMs: now + 10000,
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
    validFromMs: now - 1000,
    validUntilMs: now + 600000,
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
    workerInstallationDigest: validateNotificationWorkerInstallation(workerInstallation, now)
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
  return {
    original: validateNotificationDeliveryStartTransition(value),
    payload,
    issuerSpki,
    issuerPrivateKey: issuer.privateKey.export({ type: 'pkcs8', format: 'der' }),
    signerSpki,
    signerPrivateKey: signer.privateKey.export({ type: 'pkcs8', format: 'der' }),
  };
}

import { createPrivateKey, X509Certificate } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { join } from 'node:path';
import {
  encodeCbor,
  type CborValue,
} from '../../../packages/security-kernel/src/canonical-cbor.js';
import {
  decodeNotificationCredentialMaterial,
  notificationCredentialEncoding,
} from '../../../services/identity-service/src/domain/notification-credential-material.js';
import { createNotificationGatewayAdapter } from '../../../services/control-api/src/notifications/gateway-adapter.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';

type GatewayFixture = {
  port: number;
  setFault(value: 'NORMAL' | 'LOST_ACK' | 'STALL' | 'REDIRECT' | 'FORGED' | 'UNSIGNED'): void;
  stats(): {
    calls: number;
    readbacks: number;
    delivered: number;
    receipts: number;
    sockets: number;
  };
  close(): Promise<void>;
};
async function vacantPort() {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  if (!address || typeof address === 'string') throw new Error('Fixture port unavailable');
  return address.port;
}
/** Real pinned mTLS plus existing authenticated external gateway journal. This
 * exercises the lower transport directly, NOT a fabricated recipient lease or
 * a successful internal dispatch. Genuine-lease joined cases are separate below. */
export async function createNotificationDeliveryExternalFixture(
  channel: NotificationGatewayTransportV1['channel'],
) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent) throw new Error('Owned OPENPC_TEST_TMP_ROOT required');
  const root = await mkdtemp(join(parent, 'notification-delivery-provider-'));
  let peer: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>> | undefined;
  let gateway: GatewayFixture | undefined;
  let sample: ReturnType<typeof notificationDeliveryProviderSample> | undefined;
  let materialBytes: Buffer | undefined;
  try {
    peer = await runtimeSnapshotTlsFixture('urn:openpc:test:notification-delivery-component');
    const port = await vacantPort(),
      serverCertificate = new X509Certificate(peer.server.certificate);
    sample = notificationDeliveryProviderSample({
      channel,
      endpoint: `https://127.0.0.1:${port}/`,
      serverSpkiDigest: sha256(serverCertificate.publicKey.export({ type: 'spki', format: 'der' })),
    });
    const privateDer = createPrivateKey(peer.privateKey).export({ type: 'pkcs8', format: 'der' }),
      ca = new X509Certificate(peer.server.ca);
    try {
      materialBytes = encodeCbor(
        new Map<number, CborValue>([
          [0, notificationCredentialEncoding],
          [1, privateDer],
          [2, [peer.parsed.raw]],
          [3, [ca.raw]],
        ]),
      );
    } finally {
      privateDer.fill(0);
    }
    const material = decodeNotificationCredentialMaterial(materialBytes);
    const module: Record<string, unknown> = await import(
      new URL('../local-runtime/notification-gateway-fixture.mjs', import.meta.url).href
    );
    if (typeof module.createNotificationGatewayFixture !== 'function')
      throw new Error('Missing existing gateway fixture');
    const config = {
      tls: { key: peer.server.privateKey, cert: peer.server.certificate, ca: peer.server.ca },
      installed: sample.original.channel,
      signerPrivateKey: sample.signerPrivateKey,
      signerSpki: sample.signerSpki,
      clientSpkiDigest: sha256(peer.parsed.publicKey.export({ type: 'spki', format: 'der' })),
      journalPath: join(root, 'gateway.jsonl'),
      port,
    };
    const create = module.createNotificationGatewayFixture as (
      value: typeof config,
    ) => Promise<GatewayFixture>;
    gateway = await create(config);
    const original = sample.original,
      payload = sample.payload;
    const provider = (
      window: { signal: AbortSignal; timeoutMs: number },
      fingerprint = material.clientCertificateFingerprint,
    ) =>
      createNotificationGatewayAdapter(
        original.channel,
        original.channel,
        material.secureContext,
        window,
        fingerprint,
      );
    return {
      original,
      payload,
      materialBytes,
      material,
      provider,
      stats: () => gateway!.stats(),
      setFault: (fault: Parameters<GatewayFixture['setFault']>[0]) => gateway!.setFault(fault),
      async restart() {
        await gateway!.close();
        gateway = undefined;
        gateway = await create(config);
      },
      async close() {
        try {
          await gateway?.close();
        } finally {
          sample!.payload.fill(0);
          sample!.issuerPrivateKey.fill(0);
          sample!.signerPrivateKey.fill(0);
          materialBytes?.fill(0);
          peer!.privateKey.fill(0);
          peer!.server.privateKey.fill(0);
          await peer!.close();
          await rm(root, { recursive: true, force: true });
        }
      },
    };
  } catch (error) {
    try {
      await gateway?.close();
    } finally {
      sample?.payload.fill(0);
      sample?.issuerPrivateKey.fill(0);
      sample?.signerPrivateKey.fill(0);
      materialBytes?.fill(0);
      if (peer) {
        peer.privateKey.fill(0);
        peer.server.privateKey.fill(0);
        await peer.close();
      }
      await rm(root, { recursive: true, force: true });
    }
    throw error;
  }
}

import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../services/identity-service/src/domain/identity-kernel.js';
import {
  withNotificationSecretRecipient,
  assertNotificationCredentialLease,
  type NotificationSecretRequest,
} from '../../../services/identity-service/src/domain/notification-secret-recipient.js';
import type { NotificationCredentialProvider } from '../../../services/identity-service/src/domain/notification-credential-material.js';
import {
  deliverNotificationProvider,
  reconcileNotificationProvider,
  type NotificationDeliveryProviderInput,
} from '../../../services/control-api/src/notifications/delivery-provider.js';
import type { NotificationDeliveryReceiptV1 } from '../../../services/control-api/src/notifications/gateway-contracts.js';

/** Existing real Identity/PG/TLS recipient entrypoint only. The canonical fixture
 * owns its scoped source, installed endpoint/credential and external provider.
 * No callback manufactures a lease or grants dispatch/material authority. */
export interface NotificationDeliveryRecipientCase {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  request: NotificationSecretRequest;
  credentialProvider: NotificationCredentialProvider;
  /** Actual immutable signed STARTED readback from the canonical durable owner. */
  original: NotificationDeliveryProviderInput['original'];
  current: NotificationDeliveryProviderInput['current'];
  gatewayStats(): { calls: number; readbacks: number };
}
/** Prepared real-owner no-effect checks, safe before delivery root composition.
 * Requires an actual durable STARTED source and real current recipient; missing
 * dependencies stay BLOCKED at fixture admission, never synthetic positive state. */
export async function assertNotificationDeliveryProviderRejections(
  input: NotificationDeliveryRecipientCase,
) {
  const { expect } = await import('vitest'),
    before = input.gatewayStats();
  await withNotificationSecretRecipient(
    input.pool,
    input.kernel,
    input.socket,
    input.request,
    input.credentialProvider,
    async (lease) => {
      const args: NotificationDeliveryProviderInput = {
        original: input.original,
        current: input.current,
        credential: lease.credential,
        lease,
        window: { signal: new AbortController().signal, timeoutMs: 1000 },
      };
      const bytes = Buffer.from(lease.bytes),
        bad = Buffer.alloc(0);
      try {
        await expect(deliverNotificationProvider(args, bad)).rejects.toThrow();
        await expect(
          reconcileNotificationProvider({ ...args, lease: { ...lease } }),
        ).rejects.toThrow();
        const controller = new AbortController();
        controller.abort();
        await expect(
          reconcileNotificationProvider({
            ...args,
            window: { signal: controller.signal, timeoutMs: 1000 },
          }),
        ).rejects.toThrow();
        await expect(
          reconcileNotificationProvider({
            ...args,
            credential: {
              ...lease.credential,
              epoch: (BigInt(lease.credential.epoch) + 1n).toString(),
            },
          }),
        ).rejects.toThrow();
        await expect(
          reconcileNotificationProvider({
            ...args,
            current: {
              ...input.current,
              transport: {
                ...input.current.transport,
                serverSpkiDigest: sha256('wrong-transport'),
              },
            },
          }),
        ).rejects.toThrow();
        expect(lease.bytes).toEqual(bytes);
      } finally {
        bytes.fill(0);
      }
      assertNotificationCredentialLease(lease, lease.credential, sha256(input.current.transport));
    },
  );
  expect(input.gatewayStats()).toEqual(before);
}
/** Prepared original lookup suffix only. The canonical caller must supply the
 * first persisted authenticated gateway receipt after a genuine claimed send.
 * This helper never acquires plaintext, submits delivery or invents the missing
 * dispatch/material owner. Renewed lookup authority may outlive original expiry. */
export async function assertNotificationDeliveryProviderOriginalReadback(
  input: NotificationDeliveryRecipientCase,
  first: NotificationDeliveryReceiptV1,
) {
  const { expect } = await import('vitest'),
    before = input.gatewayStats();
  const result = await withNotificationSecretRecipient(
    input.pool,
    input.kernel,
    input.socket,
    input.request,
    input.credentialProvider,
    (lease) =>
      reconcileNotificationProvider(
        {
          original: input.original,
          current: input.current,
          credential: lease.credential,
          lease,
          window: { signal: new AbortController().signal, timeoutMs: 5000 },
        },
        first,
      ),
  );
  expect(result).toEqual(first);
  expect(input.gatewayStats().calls).toBe(before.calls);
  expect(input.gatewayStats().readbacks - before.readbacks).toBe(1);
  return result;
}
