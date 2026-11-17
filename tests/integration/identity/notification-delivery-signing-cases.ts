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
import { notificationReceiptSigningPurpose } from '../../../services/control-api/src/notifications/receipt-signer-installation.js';
import { buildNotificationDeliverySigning } from '../../../services/control-api/src/notifications/delivery-signing-contract.js';
import type {
  NotificationReceiptProviderObservation,
  NotificationReceiptProviderTrust,
} from '../../../services/identity-service/src/domain/notification-receipt-provider.js';
/** Pure cryptographic component corpus. It grants no Identity, configuration,
 * payload custody or database authority and never seeds an accepted journey. */
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = (n: number) => sha256(String(n));
export function notificationDeliverySigningSample() {
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
    authorizationContextId: id(33),
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

  const worker = validateNotificationWorkerInstallation(workerInstallation, 3000);
  const trust: NotificationReceiptProviderTrust = {
    worker: workerInstallation,
    signer: {
      owner: 'LS-NOTIFICATION' as const,
      purpose: notificationReceiptSigningPurpose,
      environmentId: 'test',
      participantId: id(1),
      privacyDomainId: id(2),
      installationId: id(40),
      workerInstallationDigest: worker.installationDigest,
      workerProfileDigest: workerInstallation.pins.signedProfileDigest,
      workerIssuerSpkiHex: workerInstallation.pins.issuerSpkiHex,
      principalId: workerProfile.principalId,
      workloadCredentialId: workerProfile.workloadCredentialId,
      workloadEpoch: '1',
      workloadId: workerProfile.workloadId,
      secretClass: 'SECRET-SIGNING-KEY' as const,
      secretReference: 'secret://notification-test/receipt#v1',
      secretVersion: 'v1',
      publicKeySpkiHex: signerSpki.toString('hex'),
      keyEpoch: '1',
      providerId: 'notification-test',
      providerOrigin: 'https://127.0.0.1:4433',
      providerTlsSpkiDigest: h(20),
      validFromNs: '1000000000',
      validUntilNs: '10000000000',
      installationReference: 'component-only',
    },
  };
  const preparation = {
    schema: 'pc.notification.delivery-preparation.v1',
    operationId: receipt.operationId,
    source: {
      worker: {
        participantId: id(1),
        privacyDomainId: id(2),
        installationDigest: worker.installationDigest,
      },
      notificationOccurrenceId: source.notificationOccurrenceId,
      eventId: source.eventId,
    },
    sourceOperationId: source.operationId,
    sourceReceiptDigest: receipt.sourceReceiptDigest,
    workerCredentialId: workerProfile.workloadCredentialId,
    workerEpoch: '1',
    authorityDigest: receipt.authoritySnapshotDigest,
    authorityValidUntilMs: 9000,
    generationId: id(41),
    effectiveDigest: h(21),
    configuredLimit: 6,
    before: {
      ...before,
      revision: '1',
      deliveryRequestEventId: source.eventId,
      deliveryRequestOperationId: source.operationId,
      budgetEnvironmentId: 'test',
      budgetGenerationId: id(41),
      budgetEffectiveDigest: h(21),
      budgetConfiguredLimit: 6,
      budgetWorkerInstallationDigest: worker.installationDigest,
    },
    plannedAfter: after,
    beforeStateDigest: receipt.beforeStateDigest,
    plannedAfterStateDigest: receipt.afterStateDigest,
    channel,
    attempt,
    context,
    attemptDigest: receipt.attemptDigest,
    contextDigest: receipt.contextDigest,
  };
  const signing = buildNotificationDeliverySigning({
    deliveryPreparation: preparation,
    sourceClaims: source,
    trust,
    receiptId: receipt.receiptId,
  });
  const observe = (): NotificationReceiptProviderObservation => ({
    schemaVersion: 1,
    providerId: signing.request.providerId,
    signingAttemptId: signing.request.signingAttemptId,
    requestDigest: signing.requestDigest,
    recordedAtMs: 3500,
    outcome: 'SIGNED',
    reason: null,
    coseHex: sign(receipt).coseHex,
  });
  return { signing, observe };
}

import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../services/identity-service/src/domain/identity-kernel.js';
import type { NotificationPayloadReferenceGate } from '../../../services/control-api/src/notifications/payload-reference.js';
import type { NotificationDeliverySigningSelector } from '../../../services/control-api/src/notifications/delivery-signing-contract.js';
import { notificationSigningTransition } from '../../../services/control-api/src/notifications/delivery-signing-contract.js';
import { prepareNotificationDelivery } from '../../../services/control-api/src/notifications/delivery-start-preparation.js';
import {
  prepareNotificationDeliverySigning,
  claimNotificationDeliverySigning,
  withCurrentNotificationSigning,
  withNotificationSigningHistory,
  readNotificationSigningRecord,
} from '../../../services/control-api/src/notifications/delivery-signing-state.js';
import { NotificationDeliverySigningRuntime } from '../../../services/control-api/src/notifications/delivery-signing-runtime.js';
import {
  publishNotificationDeliveryStart,
  readNotificationDeliveryStart,
} from '../../../services/control-api/src/notifications/delivery-start-atomic.js';
import { encodeNotificationDeliveryStartTransition } from '../../../services/control-api/src/notifications/delivery-start-transition.js';

/** Canonical real PostgreSQL/Identity/TLS fixture inputs, never fake admissions.
 * source must already have been created through the supported publication owner.
 * Each case uses an independent business source and real configured generation.
 * The fixture controls only external provider faults and genuine withdrawal/
 * configuration/cancellation owners. It must not seed intermediate business rows.
 * Missing current generation is a BLOCKED prerequisite, not test success. */
export interface NotificationSigningJourneyFixture {
  pool: Pool;
  kernel: IdentityKernel;
  gate: NotificationPayloadReferenceGate;
  source: NotificationDeliverySigningSelector['source'];
  signerInstallationDigest: string;
  transport: ConstructorParameters<typeof NotificationDeliverySigningRuntime>[3];
  withPeer<T>(run: (socket: TLSSocket) => Promise<T>): Promise<T>;
  counters(): { performs: number; lookups: number; signatures: number; gatewayCalls: number };
  setProviderFault(fault: 'NONE' | 'LOSE_RESPONSE'): void;
  /** Counters remain cumulative across this external fixture restart. */
  restartProvider(): Promise<void>;
  revokeProvider(): Promise<void>;
  invalidate(
    kind: 'SIGNER' | 'CANCEL' | 'EXPIRE' | 'ZERO_CAP' | 'DECREASED_CAP' | 'STATE_CHANGE',
  ): Promise<void>;
}
export class NotificationSigningPrerequisiteBlocked extends Error {
  constructor() {
    super('BLOCKED: genuine notification preparation/current-generation prerequisite unavailable');
  }
}
async function prepareReal(f: NotificationSigningJourneyFixture) {
  let preparation: Awaited<ReturnType<typeof prepareNotificationDelivery>>;
  try {
    preparation = await f.withPeer((socket) =>
      prepareNotificationDelivery(f.pool, f.kernel, socket, f.source),
    );
  } catch {
    throw new NotificationSigningPrerequisiteBlocked();
  }
  const selector = {
    source: preparation.source,
    operationId: preparation.operationId,
    signerInstallationDigest: f.signerInstallationDigest,
  };
  const original = await f.withPeer((socket) =>
    prepareNotificationDeliverySigning(f.pool, f.kernel, socket, f.gate, selector),
  );
  return {
    selector,
    original,
    runtime: new NotificationDeliverySigningRuntime(f.pool, f.kernel, f.gate, f.transport),
  };
}
const readSigning = (
  f: NotificationSigningJourneyFixture,
  q: NotificationDeliverySigningSelector,
) =>
  f.withPeer((socket) =>
    withNotificationSigningHistory(f.pool, f.kernel, socket, q, (client, selector) =>
      readNotificationSigningRecord(client, selector),
    ),
  );

/** Runs a real concurrent claim/sign/start/restart-readback path. No internal
 * success mocks: all product calls reach supplied real Pool, kernel and TLS. */
export async function assertNotificationSigningAtomicJourney(f: NotificationSigningJourneyFixture) {
  const { expect } = await import('vitest'),
    before = f.counters(),
    { selector, original, runtime } = await prepareReal(f);
  const results = await Promise.all(
    [0, 1].map(() => f.withPeer((socket) => runtime.dispatchOnce(socket, selector))),
  );
  const retained = await f.withPeer((socket) => runtime.reconcile(socket, selector));
  expect(results.some((r) => r.state === 'OBSERVED')).toBe(true);
  expect(retained.state).toBe('OBSERVED');
  expect(f.counters().performs - before.performs).toBe(1);
  expect(f.counters().signatures - before.signatures).toBe(1);
  const after = await readSigning(f, selector);
  expect(after?.preparation).toEqual(original.preparation);
  expect(after?.state).toBe('OBSERVED');
  const starts = await Promise.all(
    [0, 1].map(() =>
      f.withPeer((socket) =>
        publishNotificationDeliveryStart(f.pool, f.kernel, socket, f.gate, selector),
      ),
    ),
  );
  expect(starts[0]).toEqual(starts[1]);
  expect(starts[0]?.receipt.attemptId).toBe(original.preparation.request.deliveryAttemptId);
  const restarted = new NotificationDeliverySigningRuntime(f.pool, f.kernel, f.gate, f.transport);
  expect((await f.withPeer((socket) => restarted.reconcile(socket, selector))).state).toBe(
    'OBSERVED',
  );
  expect(
    await f.withPeer((socket) => readNotificationDeliveryStart(f.pool, f.kernel, socket, selector)),
  ).toEqual(starts[0]);
  expect(f.counters().performs - before.performs).toBe(1);
  expect(f.counters().gatewayCalls).toBe(before.gatewayCalls);
  return { selector, transition: starts[0] };
}

/** Durable DISPATCHED with no perform models process loss immediately after
 * claim commit. ABSENT/restarts remain lookup-only and never invent an effect. */
export async function assertNotificationSigningAbsentRecovery(
  f: NotificationSigningJourneyFixture,
) {
  const { expect } = await import('vitest'),
    before = f.counters(),
    { selector, original, runtime } = await prepareReal(f);
  const claimed = await f.withPeer((socket) =>
    claimNotificationDeliverySigning(f.pool, f.kernel, socket, f.gate, selector),
  );
  expect(claimed.claimed).toBe(true);
  expect(await f.withPeer((socket) => runtime.reconcile(socket, selector))).toMatchObject({
    state: 'UNKNOWN',
  });
  await f.restartProvider();
  const restarted = new NotificationDeliverySigningRuntime(f.pool, f.kernel, f.gate, f.transport);
  expect(await f.withPeer((socket) => restarted.dispatchOnce(socket, selector))).toMatchObject({
    state: 'UNKNOWN',
  });
  expect((await readSigning(f, selector))?.preparation).toEqual(original.preparation);
  expect((await readSigning(f, selector))?.state).toBe('DISPATCHED');
  expect(f.counters().performs).toBe(before.performs);
  expect(f.counters().signatures).toBe(before.signatures);
  expect(f.counters().gatewayCalls).toBe(before.gatewayCalls);
  expect(
    await f.withPeer((socket) => readNotificationDeliveryStart(f.pool, f.kernel, socket, selector)),
  ).toBeNull();
}

/** Lost response followed by real signer withdrawal retains and authenticates
 * original provider observation while fresh STARTED remains prohibited. */
export async function assertNotificationSigningLostResponse(f: NotificationSigningJourneyFixture) {
  const { expect } = await import('vitest'),
    before = f.counters(),
    { selector, original, runtime } = await prepareReal(f);
  f.setProviderFault('LOSE_RESPONSE');
  expect(await f.withPeer((socket) => runtime.dispatchOnce(socket, selector))).toMatchObject({
    state: 'UNKNOWN',
  });
  expect(f.counters().performs - before.performs).toBe(1);
  expect((await readSigning(f, selector))?.state).toBe('DISPATCHED');
  f.setProviderFault('NONE');
  await f.restartProvider();
  await f.invalidate('SIGNER');
  const recovered = await f.withPeer((socket) =>
    new NotificationDeliverySigningRuntime(f.pool, f.kernel, f.gate, f.transport).reconcile(
      socket,
      selector,
    ),
  );
  expect(recovered.state).toBe('OBSERVED');
  expect((await readSigning(f, selector))?.preparation).toEqual(original.preparation);
  await expect(
    f.withPeer((socket) =>
      publishNotificationDeliveryStart(f.pool, f.kernel, socket, f.gate, selector),
    ),
  ).rejects.toThrow();
  expect(
    await f.withPeer((socket) => readNotificationDeliveryStart(f.pool, f.kernel, socket, selector)),
  ).toBeNull();
  expect(f.counters().performs - before.performs).toBe(1);
  expect(f.counters().signatures - before.signatures).toBe(1);
  expect(f.counters().gatewayCalls).toBe(before.gatewayCalls);
}

export async function assertNotificationSigningInvalidation(
  f: NotificationSigningJourneyFixture,
  kind: Parameters<NotificationSigningJourneyFixture['invalidate']>[0],
  phase: 'BEFORE_DISPATCH' | 'AFTER_OBSERVATION',
) {
  const { expect } = await import('vitest'),
    before = f.counters(),
    { selector, original, runtime } = await prepareReal(f);
  if (phase === 'AFTER_OBSERVATION')
    expect((await f.withPeer((socket) => runtime.dispatchOnce(socket, selector))).state).toBe(
      'OBSERVED',
    );
  await f.invalidate(kind);
  if (phase === 'BEFORE_DISPATCH')
    expect((await f.withPeer((socket) => runtime.dispatchOnce(socket, selector))).state).toBe(
      'UNKNOWN',
    );
  await expect(
    f.withPeer((socket) =>
      publishNotificationDeliveryStart(f.pool, f.kernel, socket, f.gate, selector),
    ),
  ).rejects.toThrow();
  expect(
    await f.withPeer((socket) => readNotificationDeliveryStart(f.pool, f.kernel, socket, selector)),
  ).toBeNull();
  const saved = await readSigning(f, selector);
  expect(saved?.preparation).toEqual(original.preparation);
  expect(saved?.state).toBe(phase === 'BEFORE_DISPATCH' ? 'PREPARED' : 'OBSERVED');
  expect(f.counters().performs - before.performs).toBe(phase === 'BEFORE_DISPATCH' ? 0 : 1);
  expect(f.counters().gatewayCalls).toBe(before.gatewayCalls);
}

/** Negative SQL admission corpus only. It deliberately omits one member of the
 * real atomic write under the actual current owner; every transaction must fail
 * and leave all four owners unchanged. These are not seeded successful states. */
export async function assertNotificationStartPartialRollback(
  f: NotificationSigningJourneyFixture,
  omit: 'START' | 'ATTEMPT' | 'PROJECTION' | 'INTENT',
) {
  const { expect } = await import('vitest'),
    before = f.counters(),
    { selector, runtime } = await prepareReal(f);
  expect((await f.withPeer((socket) => runtime.dispatchOnce(socket, selector))).state).toBe(
    'OBSERVED',
  );
  await expect(
    f.withPeer((socket) =>
      withCurrentNotificationSigning(
        f.pool,
        f.kernel,
        socket,
        f.gate,
        selector,
        async (client, q, p) => {
          const signing = await readNotificationSigningRecord(client, q, true);
          if (!signing?.observation) throw new Error('Missing original observation');
          const transition = notificationSigningTransition(
              signing.preparation,
              signing.observation,
            ),
            e = encodeNotificationDeliveryStartTransition(transition),
            r = transition.receipt;
          if (omit !== 'START')
            await client.query(
              `insert into control.notification_delivery_start(participant_id,privacy_domain_id,operation_id,receipt_id,attempt_id,notification_occurrence_id,payload_digest,delivery_revision,source_operation_id,worker_installation_digest,transition,transition_bytes,transition_digest,receipt_payload,receipt_digest,cose_sign1) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
              [
                r.participantId,
                r.privacyDomainId,
                r.operationId,
                r.receiptId,
                r.attemptId,
                r.notificationOccurrenceId,
                r.payloadDigest,
                r.deliveryRevision,
                p.sourceOperationId,
                p.source.worker.installationDigest,
                transition,
                e.transitionBytes,
                e.transitionDigest,
                e.receiptPayload,
                e.receiptDigest,
                e.coseSign1,
              ],
            );
          if (omit !== 'ATTEMPT')
            await client.query(
              `insert into control.notification_delivery_attempt(participant_id,privacy_domain_id,attempt_id,notification_occurrence_id,payload_digest,attempt_number,started_at_ms,worker_credential_id,worker_credential_epoch,start_operation_id) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
              [
                r.participantId,
                r.privacyDomainId,
                r.attemptId,
                r.notificationOccurrenceId,
                r.payloadDigest,
                r.attemptNumber,
                r.startedAtMs,
                p.workerCredentialId,
                p.workerEpoch,
                r.operationId,
              ],
            );
          if (omit !== 'PROJECTION')
            await client.query(
              `update control.notification_delivery set state='STARTED',attempt_count=$4,last_started_at_ms=$5,next_attempt_at_ms=null,revision=revision+1 where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3`,
              [
                r.participantId,
                r.privacyDomainId,
                r.notificationOccurrenceId,
                r.attemptNumber,
                r.startedAtMs,
              ],
            );
          if (omit !== 'INTENT')
            await client.query(
              `insert into control.notification_delivery_dispatch_intent(participant_id,privacy_domain_id,operation_id,attempt_id,notification_occurrence_id,payload_digest,delivery_revision,receipt_digest) values($1,$2,$3,$4,$5,$6,$7,$8)`,
              [
                r.participantId,
                r.privacyDomainId,
                r.operationId,
                r.attemptId,
                r.notificationOccurrenceId,
                r.payloadDigest,
                (BigInt(r.deliveryRevision) + 1n).toString(),
                e.receiptDigest,
              ],
            );
          // Intentionally allow COMMIT: deferred completeness must reject partial joins.
        },
      ),
    ),
  ).rejects.toThrow();
  expect(
    await f.withPeer((socket) => readNotificationDeliveryStart(f.pool, f.kernel, socket, selector)),
  ).toBeNull();
  await f.withPeer((socket) =>
    withNotificationSigningHistory(f.pool, f.kernel, socket, selector, async (client, q) => {
      for (const table of [
        'notification_delivery_start',
        'notification_delivery_attempt',
        'notification_delivery_dispatch_intent',
      ]) {
        const col =
          table === 'notification_delivery_attempt' ? 'start_operation_id' : 'operation_id';
        expect(
          (
            await client.query(
              `select 1 from control.${table} where participant_id=$1 and privacy_domain_id=$2 and ${col}=$3`,
              [q.source.worker.participantId, q.source.worker.privacyDomainId, q.operationId],
            )
          ).rowCount,
        ).toBe(0);
      }
      const p = (await readNotificationSigningRecord(client, q))!.preparation.deliveryPreparation;
      const d = await client.query(
        'select state,attempt_count,revision::text from control.notification_delivery where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3',
        [
          q.source.worker.participantId,
          q.source.worker.privacyDomainId,
          q.source.notificationOccurrenceId,
        ],
      );
      expect(d.rows[0]).toEqual({
        state: p.before.state,
        attempt_count: p.before.attemptCount,
        revision: p.before.revision,
      });
    }),
  );
  expect(f.counters().gatewayCalls).toBe(before.gatewayCalls);
}

/** External signer refusal is an immutable observed result. Reconciliation and
 * repeated dispatch cannot turn it into a fresh signing attempt or STARTED. */
export async function assertNotificationSigningRejected(f: NotificationSigningJourneyFixture) {
  const { expect } = await import('vitest');
  const before = f.counters();
  const { selector, original, runtime } = await prepareReal(f);
  await f.revokeProvider();
  const result = await f.withPeer((socket) => runtime.dispatchOnce(socket, selector));
  expect(result.state).toBe('OBSERVED');
  const saved = await readSigning(f, selector);
  expect(saved?.observation?.outcome).toBe('REJECTED');
  expect(saved?.observation?.reason).toBe('REVOKED');
  expect(saved?.preparation).toEqual(original.preparation);
  expect(await f.withPeer((socket) => runtime.dispatchOnce(socket, selector))).toEqual(result);
  await expect(
    f.withPeer((socket) =>
      publishNotificationDeliveryStart(f.pool, f.kernel, socket, f.gate, selector),
    ),
  ).rejects.toThrow();
  expect(
    await f.withPeer((socket) => readNotificationDeliveryStart(f.pool, f.kernel, socket, selector)),
  ).toBeNull();
  expect(f.counters().performs - before.performs).toBe(1);
  expect(f.counters().signatures).toBe(before.signatures);
  expect(f.counters().gatewayCalls).toBe(before.gatewayCalls);
}
