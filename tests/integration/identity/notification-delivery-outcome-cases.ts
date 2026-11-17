import {
  prepareNotificationOutcomeSigning,
  readNotificationOutcomeSigning,
} from '../../../services/control-api/src/notifications/delivery-outcome-state.js';
import { NotificationOutcomeSigningRecovery } from '../../../services/control-api/src/notifications/delivery-outcome-runtime.js';
import assert from 'node:assert/strict';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationDeliveryReceiptClaims,
} from '../../../packages/security-kernel/src/index.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { notificationDeliveryProviderSample } from './notification-delivery-provider-cases.js';
import { notificationDeliveryStateDigest } from '../../../services/control-api/src/notifications/delivery-start-contract.js';
import { validateNotificationDeliveryStartTransition } from '../../../services/control-api/src/notifications/delivery-start-transition.js';
import { verifyNotificationReceipt } from '../../../services/control-api/src/notifications/gateway-contracts.js';
import {
  encodeNotificationOutcomeObservation,
  notificationDeliveryOutcomeClaims,
  encodeNotificationDeliveryOutcomeTransition,
} from '../../../services/control-api/src/notifications/delivery-outcome-contract.js';
import { validateNotificationWorkerInstallation } from '../../../services/control-api/src/notifications/worker-installation-contract.js';
import {
  notificationOutcomeSigningPurpose,
  validateNotificationOutcomeSignerInstallation,
  type NotificationReceiptSignerInstallation,
} from '../../../services/control-api/src/notifications/receipt-signer-installation.js';
import { inspectNotificationDeliveryOutcome } from '../../../services/control-api/src/notifications/delivery-outcome-runtime.js';
import type {
  NotificationOutcomeObservationRow,
  NotificationSignedOutcomeRow,
} from '../../../services/control-api/src/notifications/delivery-outcome-state.js';
import {
  buildNotificationOutcomeSigning,
  type NotificationOutcomeSigningRow,
} from '../../../services/control-api/src/notifications/delivery-outcome-state.js';
import { canonicalJson } from '../../../services/control-api/src/configuration/digest.js';

/** Native protocol/row-codec fixture only; never a committed signing claim. */
export function notificationOutcomeSigningSample() {
  const f = notificationSignedOutcomeSample();
  const preparation = buildNotificationOutcomeSigning({
    input: f.value.input,
    workerInstallation: f.value.workerInstallation,
    signerInstallation: f.value.signerInstallation,
    metadata: f.value.metadata,
  });
  const bytes = Buffer.from(canonicalJson(preparation));
  const selector = {
    original: {
      source: {
        worker: {
          participantId: f.value.receipt.participantId,
          privacyDomainId: f.value.receipt.privacyDomainId,
          installationDigest: f.f.original.workerInstallationDigest,
        },
        notificationOccurrenceId: f.value.receipt.notificationOccurrenceId,
        eventId: f.f.original.source.eventId,
      },
      operationId: f.value.receipt.startOperationId,
      signerInstallationDigest: sha256('component-original-start-signer'),
    },
    operationId: f.value.receipt.operationId,
    worker: {
      participantId: f.value.receipt.participantId,
      privacyDomainId: f.value.receipt.privacyDomainId,
      installationDigest: f.f.original.workerInstallationDigest,
    },
    signerInstallationDigest: preparation.request.signerInstallationDigest,
  };
  const observation = {
    schemaVersion: 1 as const,
    providerId: preparation.request.providerId,
    signingAttemptId: preparation.request.signingAttemptId,
    requestDigest: preparation.requestDigest,
    recordedAtMs: f.value.metadata.recordedAtMs,
    outcome: 'SIGNED' as const,
    reason: null,
    coseHex: f.value.coseHex,
  };
  const row: NotificationOutcomeSigningRow = {
    preparation_bytes: bytes,
    preparation_digest: sha256(bytes),
    state: 'DISPATCHED',
    dispatch_token: 'ef'.repeat(32),
    dispatched_at_ms: String(f.value.metadata.recordedAtMs),
    observation_bytes: null,
    observation_digest: null,
  };
  return { f, preparation, selector, observation, row };
}

/** Cryptographic contract fixture only. Synthetic STARTED/claim/projection are
 * never inserted into PostgreSQL and establish no internal acceptance. */
export function notificationOutcomeSample(attemptNumber = 1) {
  const f = notificationDeliveryProviderSample({ nowMs: 1800000000000 });
  const original = structuredClone(f.original);
  if (attemptNumber > 1) {
    original.before = {
      ...original.before,
      state: 'RETRY_WAIT',
      attemptCount: attemptNumber - 1,
      lastStartedAtMs: original.attempt.startedAtMs - 10000,
    };
    original.after.attemptCount = attemptNumber;
    original.attempt.attemptNumber = attemptNumber;
    original.receipt.attemptNumber = attemptNumber;
    original.receipt.attemptDigest = sha256(original.attempt);
    original.receipt.beforeStateDigest = notificationDeliveryStateDigest(original.before, '1');
    original.receipt.afterStateDigest = notificationDeliveryStateDigest(original.after, '2');
    const signed = signNotificationClaim(
      'NotificationDeliveryStartedReceiptV1',
      f.signerPrivateKey,
      f.signerSpki,
      original.receipt,
    );
    original.payloadHex = signed.payload.toString('hex');
    original.coseHex = signed.cose.toString('hex');
  }
  const checked = validateNotificationDeliveryStartTransition(original);
  const claim = {
    state: 'CLAIMED' as const,
    claimToken: 'ab'.repeat(32),
    claimedAtMs: checked.attempt.startedAtMs + 1,
  };
  function observation(
    outcome: NotificationDeliveryReceiptClaims['outcome'] = 'DELIVERED',
    observedAtMs = claim.claimedAtMs + 1,
  ) {
    const claims: NotificationDeliveryReceiptClaims = {
      environmentId: checked.receipt.environmentId,
      participantId: checked.receipt.participantId,
      privacyDomainId: checked.receipt.privacyDomainId,
      receiptId: '01900000-0000-7000-8000-000000000080',
      signedProfileDigest: checked.channel.signedProfileDigest,
      attemptDigest: sha256(checked.attempt),
      contextDigest: sha256(checked.context),
      outcome,
      observedAtMs,
      signerKeyId: evidenceKeyId(f.signerSpki),
    };
    const signed = signNotificationClaim(
      'NotificationDeliveryReceiptV1',
      f.signerPrivateKey,
      f.signerSpki,
      claims,
    );
    return verifyNotificationReceipt(checked.channel, checked.attempt, checked.context, {
      payloadHex: signed.payload.toString('hex'),
      coseHex: signed.cose.toString('hex'),
    });
  }
  const first = observation();
  const binding = { original: checked, claim, observation: first };
  const encoded = encodeNotificationOutcomeObservation(binding);
  const row: NotificationOutcomeObservationRow = {
    participant_id: checked.receipt.participantId,
    privacy_domain_id: checked.receipt.privacyDomainId,
    observation_id: first.claims.receiptId,
    attempt_id: checked.receipt.attemptId,
    start_operation_id: checked.receipt.operationId,
    dispatch_claim_token: claim.claimToken,
    operation_id: '01900000-0000-7000-8000-000000000081',
    outcome: first.claims.outcome,
    observed_at_ms: String(first.claims.observedAtMs),
    observation_bytes: encoded.observationBytes,
    observation_digest: encoded.observationDigest,
  };
  return {
    ...f,
    original: checked,
    claim,
    observation,
    binding,
    row,
    current: { snapshot: checked.after, revision: '2' },
  };
}

/** Canonical crypto fixture only; never a real signer admission/PG publication. */
export function notificationSignedOutcomeSample(
  outcome: NotificationDeliveryReceiptClaims['outcome'] = 'DELIVERED',
  attemptNumber = 1,
) {
  const f = notificationOutcomeSample(attemptNumber),
    observation = f.observation(outcome);
  const input = {
    observation: { ...f.binding, observation },
    current: f.current,
    configuredLimit: 6,
  };
  const metadata = {
    operationId: f.row.operation_id,
    receiptId: '01900000-0000-7000-8000-000000000082',
    recordedAtMs: observation.claims.observedAtMs + 1,
    authoritySnapshotDigest: sha256('component-outcome-admission'),
  };
  const workerInstallation = f.original.workerInstallation;
  const worker = validateNotificationWorkerInstallation(workerInstallation, metadata.recordedAtMs),
    p = worker.profile;
  const signerInstallation: NotificationReceiptSignerInstallation = {
    owner: 'LS-NOTIFICATION',
    purpose: notificationOutcomeSigningPurpose,
    environmentId: p.environmentId,
    participantId: p.participantId,
    privacyDomainId: p.privacyDomainId,
    installationId: '01900000-0000-7000-8000-000000000083',
    workerInstallationDigest: worker.installationDigest,
    workerProfileDigest: worker.input.pins.signedProfileDigest,
    workerIssuerSpkiHex: worker.input.pins.issuerSpkiHex,
    principalId: p.principalId,
    workloadCredentialId: p.workloadCredentialId,
    workloadEpoch: p.workloadEpoch,
    workloadId: p.workloadId,
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://test-notification/outcome#v1',
    secretVersion: 'v1',
    publicKeySpkiHex: p.receiptSignerSpki,
    keyEpoch: '1',
    providerId: 'notification-test',
    providerOrigin: 'https://localhost:4433',
    providerTlsSpkiDigest: sha256('component-public-outcome-tls'),
    validFromNs: (BigInt(p.validFromMs) * 1000000n).toString(),
    validUntilNs: (BigInt(p.validUntilMs) * 1000000n).toString(),
    installationReference: 'component-outcome-signer',
  };
  const receipt = notificationDeliveryOutcomeClaims({
    input,
    metadata,
    workerInstallation,
    signerInstallation,
  });
  const signed = signNotificationClaim(
    'NotificationDeliveryOutcomeReceiptV1',
    f.signerPrivateKey,
    f.signerSpki,
    receipt,
  );
  const value = {
    schema: 'pc.notification.delivery-outcome-transition.v1' as const,
    input,
    metadata,
    workerInstallation,
    signerInstallation,
    receipt,
    payloadHex: signed.payload.toString('hex'),
    coseHex: signed.cose.toString('hex'),
  };
  const encoded = encodeNotificationDeliveryOutcomeTransition(value),
    native = encodeNotificationOutcomeObservation(input.observation);
  const firstRow = {
    ...f.row,
    outcome,
    observed_at_ms: String(observation.claims.observedAtMs),
    observation_bytes: native.observationBytes,
    observation_digest: native.observationDigest,
  };
  const row: NotificationSignedOutcomeRow = {
    participant_id: receipt.participantId,
    privacy_domain_id: receipt.privacyDomainId,
    operation_id: receipt.operationId,
    receipt_id: receipt.receiptId,
    attempt_id: receipt.attemptId,
    start_operation_id: receipt.startOperationId,
    notification_occurrence_id: receipt.notificationOccurrenceId,
    payload_digest: receipt.payloadDigest,
    worker_installation_digest: validateNotificationWorkerInstallation(
      workerInstallation,
      receipt.recordedAtMs,
    ).installationDigest,
    delivery_revision: receipt.deliveryRevision,
    signer_installation_digest:
      validateNotificationOutcomeSignerInstallation(signerInstallation).digest,
    transition_bytes: encoded.transitionBytes,
    transition_digest: encoded.transitionDigest,
    receipt_payload: encoded.receiptPayload,
    receipt_digest: encoded.receiptDigest,
    cose_sign1: encoded.coseSign1,
  };
  return { f, value, encoded, firstRow, row };
}

/** Connected read-only seam for the existing PG/TLS journey. Caller supplies a
 * genuine supported STARTED/CLAIMED journey and native external receipt. This
 * invokes the real owner, never inserts trust/business intermediates or reports
 * signed outcome/final atomic completion. Missing schema/admission fails closed. */
export async function inspectOriginalNotificationOutcome(
  args: Parameters<typeof inspectNotificationDeliveryOutcome>,
  expectedOriginalOperationId: string | null,
) {
  const first = await inspectNotificationDeliveryOutcome(...args);
  const again = await inspectNotificationDeliveryOutcome(...args);
  // The surrounding existing journey owns isolated state. Read-only inspection
  // cannot consume a claim, create an outcome, advance a retry or mint work.
  assert.deepEqual(again, first);
  if (expectedOriginalOperationId !== null) {
    assert.equal(first.state, 'ORIGINAL_OBSERVATION');
    if (first.state !== 'ORIGINAL_OBSERVATION') throw new Error('Missing original observation');
    assert.equal(first.operationId, expectedOriginalOperationId);
    assert.deepEqual(first.observation, args[4]);
  } else {
    assert.equal(first.state, 'UNPUBLISHED_PROPOSAL');
    if (first.state !== 'UNPUBLISHED_PROPOSAL') throw new Error('Unexpected retained operation');
    const { proposal } = first;
    assert.deepEqual(proposal.observation, args[4]);
    assert.equal(proposal.after.snapshot.attemptCount, proposal.before.snapshot.attemptCount);
    assert.equal(proposal.claim.state, 'CLAIMED');
    assert.equal(proposal.failureWorkRequired, proposal.after.snapshot.state === 'FAILED');
  }
  return first;
}

/** Joined acceptance helper for the existing real PostgreSQL/TLS driver. Inputs
 * must come from its public STARTED/dispatch and native gateway owners. This
 * performs real durable preparation/claim/lookup/attachment and never seeds an
 * internal decision or substitutes a mock admission. It is not final publication.
 * The driver must retain provider call counts and its clean/restart/fault cases. */
export async function exerciseNotificationOutcomeSigning(
  args: Parameters<typeof prepareNotificationOutcomeSigning>,
  transport: ConstructorParameters<typeof NotificationOutcomeSigningRecovery>[2],
) {
  const [pool, kernel, socket] = args;
  const prepared = await prepareNotificationOutcomeSigning(...args);
  assert.equal(prepared.record.state, 'PREPARED');
  assert.deepEqual(await prepareNotificationOutcomeSigning(...args), prepared);
  const runtime = new NotificationOutcomeSigningRecovery(pool, kernel, transport);
  const concurrent = await Promise.all([
    runtime.dispatchOnce(socket, prepared.selector),
    runtime.dispatchOnce(socket, prepared.selector),
  ]);
  assert.ok(
    concurrent.some((r) => r.state === 'OBSERVED'),
    'No real signing observation retained',
  );
  const recovered = await runtime.reconcile(socket, prepared.selector);
  assert.equal(recovered.state, 'OBSERVED');
  if (recovered.state !== 'OBSERVED') throw new Error('Missing original signing observation');
  assert.deepEqual(recovered.record.preparation, prepared.record.preparation);
  assert.deepEqual(await runtime.dispatchOnce(socket, prepared.selector), recovered);
  assert.deepEqual(
    await readNotificationOutcomeSigning(pool, kernel, socket, prepared.selector),
    recovered.record,
  );
  const restarted = new NotificationOutcomeSigningRecovery(pool, kernel, transport);
  assert.deepEqual(await restarted.reconcile(socket, prepared.selector), recovered);
  assert.ok(recovered.record.observation);
  return { prepared, recovered };
}

/** Existing caller supplies real TLS callbacks and the already-owned external
 * providers. These callbacks carry sockets, never fabricated Identity grants. */
export interface NotificationProducerJourneyInput {
  pool: import('pg').Pool;
  kernel: import('../../../services/identity-service/src/domain/identity-kernel.js').IdentityKernel;
  vaultDirectory: string;
  kmsTls: import('../../../services/control-api/src/evidence/kms-runtime.js').EvidenceKmsTlsMaterial;
  source: import('../../../services/control-api/src/notifications/delivery-source.js').NotificationDeliverySourceSelector;
  startSignerInstallationDigest: string;
  outcomeSignerInstallationDigest: string;
  transport: ConstructorParameters<typeof NotificationOutcomeSigningRecovery>[2];
  credentialProvider: import('../../../services/identity-service/src/domain/notification-credential-material.js').NotificationCredentialProvider;
  withDeliveryPeer<T>(run: (socket: import('node:tls').TLSSocket) => Promise<T>): Promise<T>;
  withRecipientPeer<T>(run: (socket: import('node:tls').TLSSocket) => Promise<T>): Promise<T>;
}

export class NotificationProducerPrerequisiteBlocked extends Error {
  constructor(readonly prerequisite: 'OPERATIONS_GENERATION' | 'ZERO_CAPACITY' | 'ASYNC_OWNER') {
    super(`BLOCKED_NOTIFICATION_PRODUCER_${prerequisite}`);
  }
}

/** Query the authoritative owner using the original source's environment. Only
 * its explicit unavailable-generation result is a prerequisite; syntax, grants,
 * missing functions and other product failures must remain failures. */
export async function requireNotificationProducerGeneration(
  input: Pick<NotificationProducerJourneyInput, 'pool' | 'kernel' | 'source' | 'withDeliveryPeer'>,
) {
  const { withNotificationDeliveryRequest } =
    await import('../../../services/control-api/src/notifications/delivery-admission.js');
  const { withCurrentNotificationAsync, NotificationAsyncOwnerUnavailable } =
    await import('../../../services/control-api/src/notifications/async-admission.js');
  // The outer owner intentionally maps errors to its safe public error. Preserve
  // the actual SQL prerequisite classification inside that authenticated scope.
  let blocked: NotificationProducerPrerequisiteBlocked | undefined;
  try {
    return await input.withDeliveryPeer((socket) =>
      withNotificationDeliveryRequest(
        input.pool,
        input.kernel,
        socket,
        input.source,
        async (client, _admission, source) => {
          try {
            const result = await client.query<{
              generation_id: string;
              effective_digest: string;
              configured_limit: number;
            }>('select * from openpc.current_notification_delivery_limit($1)', [
              source.claims.environmentId,
            ]);
            assert.equal(result.rowCount, 1);
            const configuration = result.rows[0]!;
            assert.match(configuration.generation_id, /^[0-9a-f-]{36}$/u);
            assert.match(configuration.effective_digest, /^sha256:[0-9a-f]{64}$/u);
            assert.ok(
              Number.isInteger(configuration.configured_limit) &&
                configuration.configured_limit >= 0 &&
                configuration.configured_limit <= 100,
            );
            if (configuration.configured_limit === 0)
              throw new NotificationProducerPrerequisiteBlocked('ZERO_CAPACITY');
            const context = await client.query<{ request_id: string }>(
              "select current_setting('openpc.operation_id',true) request_id",
            );
            assert.equal(context.rowCount, 1);
            const requestId = context.rows[0]!.request_id;
            assert.match(requestId, /^[0-9a-f-]{36}$/u);
            await withCurrentNotificationAsync(
              client,
              {
                participantId: input.source.worker.participantId,
                privacyDomainId: input.source.worker.privacyDomainId,
                environmentId: source.claims.environmentId,
                generationId: configuration.generation_id,
                requestId,
                workerInstallationDigest: input.source.worker.installationDigest,
              },
              async (currentClient, admitted) => {
                assert.equal(currentClient, client);
                assert.equal(admitted.committedGenerationDigest, configuration.effective_digest);
              },
            );
            return { environmentId: source.claims.environmentId, ...configuration };
          } catch (error) {
            if (error instanceof NotificationAsyncOwnerUnavailable)
              blocked = new NotificationProducerPrerequisiteBlocked('ASYNC_OWNER');
            else if (error instanceof NotificationProducerPrerequisiteBlocked) blocked = error;
            else if (
              (error as { code?: string; message?: string }).code === 'P0001' &&
              (error as Error).message === 'OPS_CONFIG_UNREADY'
            )
              blocked = new NotificationProducerPrerequisiteBlocked('OPERATIONS_GENERATION');
            throw error;
          }
        },
      ),
    );
  } catch (error) {
    throw blocked ?? error;
  }
}

/** Exercise the actual product composition from a published occurrence. All
 * peers, provider credentials, SQL owners and signed results remain real. An
 * ambiguous first attempt uses only retained lookup, never another start. */
export async function exerciseNotificationDeliveryProducer(
  input: NotificationProducerJourneyInput,
) {
  await requireNotificationProducerGeneration(input);
  const { NotificationDeliveryRuntime, NotificationDeliveryRuntimeError } =
    await import('../../../services/control-api/src/notifications/delivery-runtime.js');
  const runtime = new NotificationDeliveryRuntime({
    pool: input.pool,
    kernel: input.kernel,
    vaultDirectory: input.vaultDirectory,
    kmsTls: input.kmsTls,
    signerTls: input.transport,
    signers: {
      start: input.startSignerInstallationDigest,
      outcome: input.outcomeSignerInstallationDigest,
    },
    credentialProvider: input.credentialProvider,
  });
  const withPeers = <T>(
    run: (
      peers: import('../../../services/control-api/src/notifications/delivery-runtime.js').NotificationDeliveryPeers,
    ) => Promise<T>,
  ) =>
    input.withDeliveryPeer((delivery) =>
      input.withRecipientPeer((recipient) => run({ delivery, recipient })),
    );
  try {
    let result:
      Awaited<ReturnType<typeof runtime.start>> | Awaited<ReturnType<typeof runtime.lookup>>;
    try {
      result = await withPeers((peers) => runtime.start(peers, input.source));
    } catch (error) {
      if (
        !(error instanceof NotificationDeliveryRuntimeError) ||
        error.code !== 'UNKNOWN' ||
        !error.original
      )
        throw error;
      result = await withPeers((peers) => runtime.lookup(peers, error.original));
    }
    assert.equal(
      result.state,
      'PUBLISHED',
      'Original delivery remains unresolved; no resubmission or fabricated completion',
    );
    if (result.state !== 'PUBLISHED') throw new Error('Notification delivery original unresolved');
    const published = result.publication;
    assert.ok(published.event, 'Only an actual terminal producer event can enter completion');
    assert.equal(published.event.envelope.type, 'io.openpc.notification.delivery.completed.v1');
    const lookup = await withPeers((peers) => runtime.lookup(peers, result.original));
    assert.equal(lookup.state, 'PUBLISHED');
    if (lookup.state !== 'PUBLISHED') throw new Error('Notification delivery readback unavailable');
    assert.deepEqual(lookup.publication.encoded, published.encoded);
    const repeated = await withPeers((peers) => runtime.start(peers, input.source));
    assert.equal(
      repeated.state,
      'ORIGINAL',
      'Retained preparation must not allocate another effect',
    );
    return { published, eventId: published.event.envelope.id, original: result.original };
  } finally {
    await runtime.close();
  }
}

/** External receipt providers and initial signer trust, using the real installed
 * delivery worker. No preparation, dispatch, observation or result is seeded. */
export async function createNotificationProducerSigners(input: {
  owner: import('pg').Pool;
  workerInstallation: unknown;
  signerPrivateKey: Buffer;
  directory: string;
  tls: {
    certificate: Buffer;
    privateKey: Buffer;
    server: { certificate: Buffer; privateKey: Buffer; ca: Buffer };
  };
}) {
  const { join } = await import('node:path');
  const { localOperationId: id } =
    await import('../../../services/identity-service/src/domain/local-operation-id.js');
  const { runScopedTransaction } =
    await import('../../../services/identity-service/src/db/scoped-transaction.js');
  const {
    notificationReceiptSigningPurpose,
    installInitialNotificationReceiptSigner,
    installInitialNotificationOutcomeSigner,
  } =
    await import('../../../services/control-api/src/notifications/receipt-signer-installation.js');
  const { createNotificationReceiptProviderFixture, notificationFixtureSpki } =
    await import('./notification-receipt-provider-fixture.js');
  const worker = validateNotificationWorkerInstallation(input.workerInstallation, Date.now()),
    p = worker.profile;
  const providers: Awaited<ReturnType<typeof createNotificationReceiptProviderFixture>>[] = [];
  const close = async () => {
    const results = await Promise.allSettled(
      providers.splice(0).map((provider) => provider.close()),
    );
    const errors = results.flatMap((result) =>
      result.status === 'rejected' ? [result.reason] : [],
    );
    if (errors.length) throw new AggregateError(errors, 'Producer signer cleanup failed');
  };
  try {
    const installed = [];
    for (const purpose of [
      notificationReceiptSigningPurpose,
      notificationOutcomeSigningPurpose,
    ] as const) {
      const pins: NotificationReceiptSignerInstallation = {
        owner: 'LS-NOTIFICATION',
        purpose,
        environmentId: p.environmentId,
        participantId: p.participantId,
        privacyDomainId: p.privacyDomainId,
        installationId: id(),
        workerInstallationDigest: worker.installationDigest,
        workerProfileDigest: worker.input.pins.signedProfileDigest,
        workerIssuerSpkiHex: worker.input.pins.issuerSpkiHex,
        principalId: p.principalId,
        workloadCredentialId: p.workloadCredentialId,
        workloadEpoch: p.workloadEpoch,
        workloadId: p.workloadId,
        secretClass: 'SECRET-SIGNING-KEY',
        secretReference: 'secret://local/producer-journey#1',
        secretVersion: '1',
        publicKeySpkiHex: p.receiptSignerSpki,
        keyEpoch: '1',
        providerId: 'producer-journey',
        providerOrigin: 'https://127.0.0.1:443',
        providerTlsSpkiDigest: sha256(notificationFixtureSpki(input.tls.server.certificate)),
        validFromNs: String(BigInt(p.validFromMs) * 1000000n),
        validUntilNs: String(BigInt(p.validUntilMs) * 1000000n),
        installationReference: 'producer-journey-initial-trust',
      };
      const provider = await createNotificationReceiptProviderFixture({
        directory: join(
          input.directory,
          purpose === notificationReceiptSigningPurpose ? 'start' : 'outcome',
        ),
        trust: { signer: pins, worker: worker.input },
        signerPrivateKey: input.signerPrivateKey,
        certificate: input.tls.server.certificate,
        privateKey: input.tls.server.privateKey,
        trustCa: input.tls.server.ca,
      });
      providers.push(provider);
      installed.push(
        await runScopedTransaction(
          input.owner,
          {
            participantId: p.participantId,
            privacyDomainId: p.privacyDomainId,
            actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
          },
          id,
          (client) =>
            purpose === notificationReceiptSigningPurpose
              ? installInitialNotificationReceiptSigner(client, provider.trust.signer)
              : installInitialNotificationOutcomeSigner(client, provider.trust.signer),
        ),
      );
    }
    return {
      startSignerInstallationDigest: installed[0]!,
      outcomeSignerInstallationDigest: installed[1]!,
      providers,
      transport: {
        certificate: input.tls.certificate,
        privateKey: input.tls.privateKey,
        trustCa: input.tls.server.ca,
      },
      close,
    };
  } catch (error) {
    try {
      await close();
    } catch (cleanup) {
      throw new AggregateError([error, cleanup], 'Producer signer setup failed');
    }
    throw error;
  }
}
