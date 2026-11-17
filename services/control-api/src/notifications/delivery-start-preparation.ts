import type { NotificationOutcomeSigningSelector } from './delivery-outcome-state.js';
import {
  withNotificationWorkerLease,
  notificationWorkerLeaseSelector,
  type NotificationWorkerLeaseSelector,
} from './async-worker-state.js';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import {
  decodeNotificationClaim,
  encodeNotificationClaim,
  type NotificationChannelProfileClaims,
} from '@openpc/security-kernel';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import {
  assertNotificationDeliveryWorkerAdmission,
  type NotificationWorkerAdmission,
  notificationDeliveryWorkerContextIdentity,
} from '../../../identity-service/src/domain/notification-worker.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { assertAdapterCallContext } from '../contracts/privacy-explorer-adapter.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { decodeNotificationKeyPreparation } from '../evidence/notification-key-contracts.js';
import {
  withNotificationDeliveryConfiguration,
  withNotificationDeliveryRequest,
} from './delivery-admission.js';
import {
  notificationDeliverySourceSelector,
  readPublishedNotificationDeliveryRequest,
  type NotificationDeliverySourceSelector,
} from './delivery-source.js';
import { withCurrentNotificationRouting } from './routing-installation.js';
import { readPublishedNotificationSource } from './published-source.js';
import { renderEvidenceExportNotification } from './template-renderer.js';
import { notificationDeliverySnapshot, planNotificationDelivery } from './delivery-policy.js';
import { notificationDeliveryBudgetRecord } from './delivery-start-state.js';
import { notificationDeliveryStateDigest } from './delivery-start-contract.js';
import {
  notificationDeliveryAttemptBinding,
  notificationGatewayTransport,
  notificationIdempotencyDigest,
  notificationScopeDigest,
} from './gateway-contracts.js';
import { assertNotificationPreparedContext } from './delivery-adapter-context.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const time = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const record = z.strictObject({
  schema: z.literal('pc.notification.delivery-preparation.v1'),
  operationId: z.uuidv7(),
  source: notificationDeliverySourceSelector,
  sourceOperationId: z.uuidv7(),
  sourceReceiptDigest: digest,
  workerCredentialId: z.uuidv7(),
  workerEpoch: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  authorityDigest: digest,
  authorityValidUntilMs: time,
  generationId: z.uuidv7(),
  effectiveDigest: digest,
  configuredLimit: z.number().int().min(0).max(100),
  before: notificationDeliveryBudgetRecord,
  plannedAfter: notificationDeliverySnapshot,
  beforeStateDigest: digest,
  plannedAfterStateDigest: digest,
  channel: z.strictObject({
    claims: z.unknown(),
    transport: notificationGatewayTransport,
    signedProfileDigest: digest,
  }),
  attempt: notificationDeliveryAttemptBinding,
  context: z.unknown(),
  attemptDigest: digest,
  contextDigest: digest,
});
export class NotificationDeliveryPreparationError extends Error {
  constructor() {
    super('Notification delivery preparation unavailable');
  }
}

function deliverySnapshot(value: z.infer<typeof notificationDeliveryBudgetRecord>) {
  return notificationDeliverySnapshot.parse({
    participantId: value.participantId,
    privacyDomainId: value.privacyDomainId,
    notificationOccurrenceId: value.notificationOccurrenceId,
    payloadDigest: value.payloadDigest,
    state: value.state,
    attemptCount: value.attemptCount,
    attemptLimit: value.attemptLimit,
    nextAttemptAtMs: value.nextAttemptAtMs,
    lastStartedAtMs: value.lastStartedAtMs,
    cancelRequested: value.cancelRequested,
  });
}
/** Pure selection only. A new ordinal requires durable progress of the original;
 * revision/cap changes, expiry, cancellation and UNKNOWN cannot manufacture it. */
export function notificationPreparationDisposition(
  original: NotificationDeliveryPreparation,
  current: z.infer<typeof notificationDeliveryBudgetRecord>,
): 'ORIGINAL' | 'NEXT' {
  const before = notificationDeliveryBudgetRecord.parse(current);
  if (
    before.participantId !== original.before.participantId ||
    before.privacyDomainId !== original.before.privacyDomainId ||
    before.notificationOccurrenceId !== original.before.notificationOccurrenceId ||
    before.payloadDigest !== original.before.payloadDigest
  )
    throw new NotificationDeliveryPreparationError();
  if (
    before.state !== 'RETRY_WAIT' ||
    before.cancelRequested ||
    before.attemptCount < original.attempt.attemptNumber
  )
    return 'ORIGINAL';
  if (
    before.attemptCount !== original.attempt.attemptNumber ||
    before.lastStartedAtMs !== original.attempt.startedAtMs ||
    BigInt(before.revision) <= BigInt(original.before.revision)
  )
    throw new NotificationDeliveryPreparationError();
  return 'NEXT';
}

/** Exact historical bytes; no TLS, live eligibility, signer or gateway authority. */
export function validateNotificationDeliveryPreparation(value: unknown) {
  try {
    const p = record.parse(immutableJsonCopy(value));
    const claims = decodeNotificationClaim(
      'NotificationChannelProfileV1',
      encodeNotificationClaim(
        'NotificationChannelProfileV1',
        p.channel.claims as NotificationChannelProfileClaims,
      ),
    );
    if (canonicalJson(claims) !== canonicalJson(p.channel.claims)) throw new Error();
    const channel = { ...p.channel, claims };
    const context = assertAdapterCallContext(p.context);
    const { revision, deliveryRequestEventId, deliveryRequestOperationId, budgetEnvironmentId } =
      p.before;
    const snapshot = deliverySnapshot(p.before);
    const plan = planNotificationDelivery(snapshot, p.configuredLimit, p.attempt.startedAtMs);
    assertNotificationPreparedContext({
      operationId: p.operationId,
      sourceOperationId: p.sourceOperationId,
      occurrenceId: p.source.notificationOccurrenceId,
      workerCredentialId: p.workerCredentialId,
      workerEpoch: p.workerEpoch,
      authorityDigest: p.authorityDigest,
      validUntilMs: p.authorityValidUntilMs,
      channel,
      attempt: p.attempt,
      context,
    });
    if (
      plan.action !== 'START' ||
      canonicalJson(plan.next) !== canonicalJson(p.plannedAfter) ||
      p.before.attemptLimit > Math.min(p.configuredLimit, 6) ||
      p.source.worker.participantId !== snapshot.participantId ||
      p.source.worker.privacyDomainId !== snapshot.privacyDomainId ||
      p.source.notificationOccurrenceId !== snapshot.notificationOccurrenceId ||
      deliveryRequestEventId !== p.source.eventId ||
      deliveryRequestOperationId !== p.sourceOperationId ||
      budgetEnvironmentId !== claims.environmentId ||
      p.attempt.participantId !== snapshot.participantId ||
      p.attempt.privacyDomainId !== snapshot.privacyDomainId ||
      p.attempt.payloadDigest !== snapshot.payloadDigest ||
      p.attempt.attemptNumber !== plan.next.attemptCount ||
      claims.transportProfileDigest !== sha256(channel.transport) ||
      p.attemptDigest !== sha256(p.attempt) ||
      p.contextDigest !== sha256(context) ||
      p.beforeStateDigest !== notificationDeliveryStateDigest(snapshot, revision) ||
      p.plannedAfterStateDigest !==
        notificationDeliveryStateDigest(plan.next, (BigInt(revision) + 1n).toString())
    )
      throw new Error();
    const result = immutableJsonCopy({ ...p, channel, context });
    if (Buffer.byteLength(canonicalJson(result)) > 262144) throw new Error();
    return result;
  } catch {
    throw new NotificationDeliveryPreparationError();
  }
}
export type NotificationDeliveryPreparation = ReturnType<
  typeof validateNotificationDeliveryPreparation
>;
export function decodeNotificationDeliveryPreparation(bytes: Buffer, expectedDigest: string) {
  try {
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length < 1 ||
      bytes.length > 262144 ||
      sha256(bytes) !== digest.parse(expectedDigest)
    )
      throw new Error();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const p = validateNotificationDeliveryPreparation(JSON.parse(text));
    if (canonicalJson(p) !== text) throw new Error();
    return p;
  } catch {
    throw new NotificationDeliveryPreparationError();
  }
}
async function prior(client: PoolClient, input: NotificationDeliverySourceSelector) {
  const rows = await client.query<{ preparation_bytes: Buffer; preparation_digest: string }>(
    `select preparation_bytes,preparation_digest from control.notification_delivery_preparation
     where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3
     order by attempt_number desc limit 1`,
    [input.worker.participantId, input.worker.privacyDomainId, input.notificationOccurrenceId],
  );
  if (!rows.rowCount) return null;
  const p = decodeNotificationDeliveryPreparation(
    rows.rows[0]!.preparation_bytes,
    rows.rows[0]!.preparation_digest,
  );
  if (
    p.source.eventId !== input.eventId ||
    p.source.notificationOccurrenceId !== input.notificationOccurrenceId ||
    p.source.worker.participantId !== input.worker.participantId ||
    p.source.worker.privacyDomainId !== input.worker.privacyDomainId
  )
    throw new NotificationDeliveryPreparationError();
  return p;
}
const deliveryProjection = `participant_id::text as "participantId",privacy_domain_id::text as "privacyDomainId",
 notification_occurrence_id::text as "notificationOccurrenceId",payload_digest as "payloadDigest",state,
 attempt_count as "attemptCount",attempt_limit as "attemptLimit",next_attempt_at_ms::float8 as "nextAttemptAtMs",
 last_started_at_ms::float8 as "lastStartedAtMs",cancel_requested as "cancelRequested",revision::text,
 delivery_request_event_id::text as "deliveryRequestEventId",delivery_request_operation_id::text as "deliveryRequestOperationId",
 budget_environment_id as "budgetEnvironmentId",budget_generation_id::text as "budgetGenerationId",
 budget_effective_digest as "budgetEffectiveDigest",budget_configured_limit as "budgetConfiguredLimit",
 budget_worker_installation_digest as "budgetWorkerInstallationDigest"`;

/** Source-only historical readback remains available after original deadline or
 * generation expiry. Current worker/source admission is mandatory; no attempt is
 * re-admitted or refreshed and no bytes confer later dispatch rights. */
export async function readNotificationDeliveryPreparation(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  try {
    const input = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
    return await withNotificationDeliveryRequest(
      pool,
      kernel,
      socket,
      input,
      async (client, admission) => {
        assertNotificationDeliveryWorkerAdmission(admission, client, input.worker);
        return prior(client, input);
      },
    );
  } catch {
    throw new NotificationDeliveryPreparationError();
  }
}

/** Shared actual source/template/body owner. Consumers get its measured size,
 * never plaintext or a caller-supplied length. SQL independently derives the
 * same original bytes through the owning renderer before consumption. */
export async function withNotificationDeliveryPayloadSize<T>(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
  operation: (binding: {
    payloadBytes: number;
    route: Parameters<Parameters<typeof withCurrentNotificationRouting>[2]>[0];
  }) => Promise<T>,
) {
  const input = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
  assertNotificationDeliveryWorkerAdmission(admission, client, input.worker);
  const source = await readPublishedNotificationDeliveryRequest(client, admission, input);
  const p = source.claims;
  const keys = [p.participantId, p.privacyDomainId, p.notificationOccurrenceId];
  const keyRows = await client.query<{
    preparation_bytes: Buffer;
    preparation_digest: string;
  }>(
    `select k.preparation_bytes,k.preparation_digest from control.notification_occurrence o
         join control.notification_key_preparation k on k.participant_id=o.participant_id and k.privacy_domain_id=o.privacy_domain_id
          and k.payload_object_id=o.payload_object_id and k.occurrence_id=o.notification_occurrence_id
         where o.participant_id=$1 and o.privacy_domain_id=$2 and o.notification_occurrence_id=$3`,
    keys,
  );
  if (keyRows.rowCount !== 1) throw new Error();
  const key = decodeNotificationKeyPreparation(
    keyRows.rows[0]!.preparation_bytes,
    keyRows.rows[0]!.preparation_digest,
  );
  if (
    key.occurrenceId !== p.notificationOccurrenceId ||
    key.objectIntent.payloadDigest !== p.payloadDigest ||
    key.objectIntent.templateDigest !== p.templateDigest ||
    key.input.routing.signedProfileDigest !== p.routingProfileDigest ||
    key.input.producerTrustDigest !== admission.installation.profile.producerTrustDigest ||
    key.input.kmsInstallationDigest !== admission.installation.profile.kmsInstallationDigest
  )
    throw new Error();
  const published = await readPublishedNotificationSource(client, {
    scope: key.input.scope,
    evidenceExportId: key.input.evidenceExportId,
    eventId: key.sourceEventId,
  });
  if (
    published.claims.dataDigest !== key.sourceDataDigest ||
    sha256(published.payload) !== key.sourceReceiptDigest
  )
    throw new Error();
  // Current routing acquires Identity/channel/endpoint fences in its existing
  // order, validates exact verification and rechecks after this callback.
  return withCurrentNotificationRouting(
    client,
    {
      participantId: p.participantId,
      privacyDomainId: p.privacyDomainId,
      ...key.input.routing,
      producerTrustDigest: key.input.producerTrustDigest,
    },
    async (route) => {
      if (
        route.installationDigest !== key.routingInstallationDigest ||
        route.endpoint.endpointId !== p.endpointId ||
        route.endpoint.revision !== p.endpointRevision ||
        route.route.claims.environmentId !== p.environmentId ||
        route.route.claims.templateDigest !== p.templateDigest
      )
        throw new Error();
      // Only derive the original length/digest from the admitted deterministic
      // template. No encrypted payload, key material or plaintext is released.
      const rendered = renderEvidenceExportNotification(route.input, published.envelope.data);
      let payloadBytes: number;
      try {
        if (rendered.payloadDigest !== p.payloadDigest) throw new Error();
        payloadBytes = rendered.bytes.length;
      } finally {
        rendered.bytes.fill(0);
      }

      const size = await client.query<{ bytes: number }>(
        'select openpc.read_notification_delivery_payload_size($1,$2) bytes',
        [input.eventId, input.worker.installationDigest],
      );
      if (size.rowCount !== 1 || size.rows[0]!.bytes !== payloadBytes)
        throw new NotificationDeliveryPreparationError();
      return operation({ route, payloadBytes });
    },
  );
}

/** The sole reservation entrypoint. All caller input is a source selector. A
 * committed original wins on replay, including stale/expired originals. New
 * reservations require the real current configuration/endpoint/source owners.
 * No signer, payload consumer, network callback or caller-ready DTO is accepted. */
async function prepareNotificationDeliveryCore(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
  retry?: NotificationOutcomeSigningSelector,
  allocated?: { value: boolean },
): Promise<NotificationDeliveryPreparation> {
  try {
    const input = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
    return await withNotificationDeliveryConfiguration(
      pool,
      kernel,
      socket,
      input,
      async (client, admission, _source, configuration) => {
        const execute = async () => {
          assertNotificationDeliveryWorkerAdmission(admission, client, input.worker);
          await client.query('select openpc.assert_notification_delivery_preparation_owner()');
          const source = await readPublishedNotificationDeliveryRequest(client, admission, input);
          // Lifecycle exclusion serializes absent rows and preserves the original on
          // an uncertain COMMIT reply. No retry allocates another operation/attempt.
          const original = await prior(client, input);
          if (retry && (!original || canonicalJson(retry.original.source) !== canonicalJson(input)))
            throw new NotificationDeliveryPreparationError();
          if (retry && original && original.operationId !== retry.original.operationId)
            return original;
          if (original) {
            const current = await client.query(
              `select ${deliveryProjection} from control.notification_delivery where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3`,
              [
                input.worker.participantId,
                input.worker.privacyDomainId,
                input.notificationOccurrenceId,
              ],
            );
            if (current.rowCount !== 1) throw new Error();
            if (notificationPreparationDisposition(original, current.rows[0]) === 'ORIGINAL')
              return original;
          }
          const p = source.claims;
          const keys = [p.participantId, p.privacyDomainId, p.notificationOccurrenceId];
          return withNotificationDeliveryPayloadSize(
            client,
            admission,
            input,
            async ({ route, payloadBytes }) => {
              const selected = await client.query(
                `select ${deliveryProjection} from control.notification_delivery where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3 for update`,
                keys,
              );
              if (selected.rowCount !== 1) throw new Error();
              const before = notificationDeliveryBudgetRecord.parse(selected.rows[0]);
              if (lease && before.state === 'RETRY_WAIT' && !retry)
                throw new NotificationDeliveryPreparationError();
              if (retry) {
                const { readNotificationOutcomePublicationInTransaction } =
                  await import('./delivery-outcome-publication.js');
                const { validateNotificationRetryLineage } =
                  await import('./delivery-cancellation-contract.js');
                const published = await readNotificationOutcomePublicationInTransaction(
                  client,
                  retry,
                );
                if (
                  !published ||
                  !original ||
                  published.proposal.original.receipt.operationId !== original.operationId
                )
                  throw new NotificationDeliveryPreparationError();
                validateNotificationRetryLineage(
                  published.encoded.transition,
                  before,
                  published.proposal.original,
                  published.proposal.claim,
                );
              }
              if (
                before.payloadDigest !== p.payloadDigest ||
                before.deliveryRequestEventId !== p.eventId ||
                before.deliveryRequestOperationId !== p.operationId ||
                before.budgetEnvironmentId !== p.environmentId ||
                before.attemptLimit > Math.min(configuration.configured_limit, 6)
              )
                throw new Error();
              const clock = await client.query<{ now_ms: string; valid_until_ms: string }>(
                `select floor(extract(epoch from clock_timestamp())*1000)::text now_ms,
           floor(extract(epoch from min(valid_until))*1000)::text valid_until_ms from control.credential
           where participant_id=$1 and credential_id=any($2::uuid[]) and state='ACTIVE' and kind='WORKLOAD_MTLS'
           having count(*)=cardinality($2::uuid[])`,
                [
                  p.participantId,
                  [
                    ...new Set([
                      admission.installation.profile.workloadCredentialId,
                      route.channel.installation.workloadCredentialId,
                    ]),
                  ],
                ],
              );
              if (clock.rowCount !== 1) throw new Error();
              const now = time.parse(Number(clock.rows[0]!.now_ms));
              const validUntilMs = time.parse(
                Math.min(
                  Number(clock.rows[0]!.valid_until_ms),
                  admission.installation.profile.validUntilMs,
                  route.channel.channel.claims.validUntilMs,
                  route.channel.credential.validUntilMs,
                  route.route.claims.validUntilMs,
                ),
              );
              const { revision } = before;
              const snapshot = deliverySnapshot(before);
              const plan = planNotificationDelivery(snapshot, configuration.configured_limit, now);
              if (plan.action !== 'START') throw new Error();
              const operationId = localOperationId();
              const attempt = notificationDeliveryAttemptBinding.parse({
                version: 'NotificationDeliveryAttemptV1',
                participantId: p.participantId,
                privacyDomainId: p.privacyDomainId,
                notificationOccurrenceId: `urn:openpc:resource:${p.notificationOccurrenceId}`,
                endpointId: `urn:openpc:resource:${p.endpointId}`,
                endpointRevision: p.endpointRevision,
                channel: route.endpoint.channel,
                destinationRef: route.endpoint.destinationRef,
                credentialRef: route.endpoint.credentialRef,
                channelProfileDigest: route.channel.channel.signedProfileDigest,
                templateDigest: p.templateDigest,
                payloadDigest: p.payloadDigest,
                payloadBytes,
                attemptId: localOperationId(),
                attemptNumber: plan.next.attemptCount,
                startedAtMs: now,
                deadlineAtMs: Math.min(
                  now + route.channel.channel.transport.requestTimeoutMs,
                  validUntilMs,
                ),
              });
              const identity = notificationDeliveryWorkerContextIdentity(
                admission,
                client,
                input.worker,
              );
              const context = assertAdapterCallContext({
                ...identity,
                accessClassIds: [...identity.accessClassIds],
                profileDigest: attempt.channelProfileDigest,
                scopeDigest: notificationScopeDigest(attempt),
                idempotencyDigest: notificationIdempotencyDigest(attempt),
                deadlineAt: new Date(attempt.deadlineAtMs).toISOString(),
                occurrenceId: p.notificationOccurrenceId,
                auditCorrelationId: operationId,
                cancellation: {
                  mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION',
                  occurrenceId: p.notificationOccurrenceId,
                },
                reconciliation: {
                  mode: 'EXACT_OCCURRENCE',
                  occurrenceId: p.notificationOccurrenceId,
                },
              });
              const prepared = validateNotificationDeliveryPreparation({
                schema: 'pc.notification.delivery-preparation.v1',
                operationId,
                source: input,
                sourceOperationId: p.operationId,
                sourceReceiptDigest: source.sourceReceiptDigest,
                workerCredentialId: identity.authorizationContextId,
                workerEpoch: admission.installation.profile.workloadEpoch,
                authorityDigest: identity.authorizationDigest,
                authorityValidUntilMs: validUntilMs,
                generationId: configuration.generation_id,
                effectiveDigest: configuration.effective_digest,
                configuredLimit: configuration.configured_limit,
                before,
                plannedAfter: plan.next,
                beforeStateDigest: notificationDeliveryStateDigest(snapshot, revision),
                plannedAfterStateDigest: notificationDeliveryStateDigest(
                  plan.next,
                  (BigInt(revision) + 1n).toString(),
                ),
                channel: route.channel.channel,
                attempt,
                context,
                attemptDigest: sha256(attempt),
                contextDigest: sha256(context),
              });
              const bytes = Buffer.from(canonicalJson(prepared));
              const inserted = await client.query(
                `insert into control.notification_delivery_preparation
          (participant_id,privacy_domain_id,operation_id,attempt_id,notification_occurrence_id,delivery_revision,attempt_number,
           source_operation_id,source_event_id,worker_installation_digest,preparation,preparation_bytes,preparation_digest)
          values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) returning preparation_bytes,preparation_digest`,
                [
                  p.participantId,
                  p.privacyDomainId,
                  operationId,
                  attempt.attemptId,
                  p.notificationOccurrenceId,
                  revision,
                  attempt.attemptNumber,
                  p.operationId,
                  p.eventId,
                  input.worker.installationDigest,
                  prepared,
                  bytes,
                  sha256(bytes),
                ],
              );
              if (inserted.rowCount !== 1) throw new Error();
              if (allocated) allocated.value = true;
              return decodeNotificationDeliveryPreparation(
                inserted.rows[0].preparation_bytes,
                inserted.rows[0].preparation_digest,
              );
            },
          );
        };
        return lease === undefined
          ? execute()
          : withNotificationWorkerLease(client, input, lease, 'PREPARE', async () => {
              return execute();
            });
      },
    );
  } catch {
    throw new NotificationDeliveryPreparationError();
  }
}

export function prepareNotificationDelivery(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  lease?: NotificationWorkerLeaseSelector,
) {
  return prepareNotificationDeliveryCore(pool, kernel, socket, value, lease);
}

/** Leased production entry; original API remains available to existing owners. */
export function prepareNotificationDeliveryLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  return prepareNotificationDelivery(
    pool,
    kernel,
    socket,
    value,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
  );
}

/** Explicit retry selects the already-published original no-effect outcome. The
 * same locked budget and original publication are checked before allocating a
 * next ordinal; replay after a newer preparation returns that original. */
export async function prepareNotificationRetryDeliveryLeased(
  lease: unknown,
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const { notificationOutcomeSigningSelector } = await import('./delivery-outcome-state.js');
  const retry = notificationOutcomeSigningSelector.parse(immutableJsonCopy(value));
  const allocated = { value: false };
  const preparation = await prepareNotificationDeliveryCore(
    pool,
    kernel,
    socket,
    retry.original.source,
    notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
    retry,
    allocated,
  );
  return { state: allocated.value ? ('PREPARED' as const) : ('ORIGINAL' as const), preparation };
}
