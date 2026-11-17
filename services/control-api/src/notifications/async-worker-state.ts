import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import {
  type NotificationWorkerAdmission,
  withNotificationDeliveryWorkerPeer,
} from '../../../identity-service/src/domain/notification-worker.js';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { withCurrentNotificationAsync, type CurrentNotificationAsync } from './async-admission.js';
import {
  notificationDeliverySourceSelector,
  type NotificationDeliverySourceSelector,
  readHistoricalNotificationDeliveryRequest,
  type PublishedNotificationDeliveryRequest,
} from './delivery-source.js';
import {
  assertNotificationWorkerSchedule,
  notificationWorkDeadline,
  notificationLeaseDeadline,
  notificationQueueAdmission,
} from './async-worker-policy.js';
import {
  withNotificationDeliveryConfiguration,
  type NotificationDeliveryConfiguration,
} from './delivery-admission.js';
import type { NotificationDeliveryOriginal } from './delivery-runtime.js';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';

const epoch = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((n) => BigInt(n) <= 18446744073709551615n);
export const notificationWorkerLeaseSelector = z.strictObject({
  eventId: z.uuidv7(),
  ownerId: z.string().min(1).max(256),
  epoch,
});
/** Selects an original lease. Its fields never confer authority. */
export type NotificationWorkerLeaseSelector = z.infer<typeof notificationWorkerLeaseSelector>;
export type NotificationWorkerEffectPhase =
  | 'PREPARE'
  | 'SIGN'
  | 'STARTED'
  | 'GATEWAY'
  | 'MATERIAL'
  | 'OUTCOME'
  | 'CANCEL'
  | 'RECOVERY_PUBLICATION';
export class NotificationAsyncWorkerError extends Error {
  constructor(
    readonly code: 'INPUT' | 'LEASE' | 'EXPIRED' | 'BUSY' | 'PROOF_OWNER_UNBOUND' | 'UNKNOWN',
  ) {
    super(`Notification async worker ${code}`);
  }
}
export interface NotificationWorkerLeaseWindow {
  readonly validUntilMs: number;
  readonly heartbeatMs: number;
  readonly ownerId: string;
  readonly epoch: string;
}
/** Cancellation budget derived from an acknowledged real owner admission. It
 * cannot renew a signed request or authorize anything on its own. */
export function notificationWorkerLeaseSignal(
  window: NotificationWorkerLeaseWindow,
  parent?: AbortSignal,
) {
  if (!Number.isSafeInteger(window.validUntilMs) || window.validUntilMs < 0)
    throw new NotificationAsyncWorkerError('INPUT');
  const remaining = window.validUntilMs - Date.now();
  const deadline =
    remaining <= 0 ? AbortSignal.abort() : AbortSignal.timeout(Math.min(remaining, 2147483647));
  return parent ? AbortSignal.any([parent, deadline]) : deadline;
}
interface WorkRow {
  event_id: string;
  notification_occurrence_id: string;
  environment_id: string;
  generation_id: string;
  worker_installation_digest: string;
  input_payload_digest: string;
  capacity_payload_digest: string;
  lease_owner: string | null;
  lease_epoch: string;
  lease_until_ms: string | null;
  deadline_at_ms: string;
  state: string;
  charged: boolean;
  effect_uncertain: boolean;
}
const columns = `event_id::text,notification_occurrence_id::text,environment_id,generation_id::text,
 worker_installation_digest,input_payload_digest,capacity_payload_digest,
 lease_owner::text,lease_epoch::text,lease_until_ms::text,deadline_at_ms::text,state,charged,effect_uncertain`;
function safeTime(value: string) {
  if (!/^(0|[1-9][0-9]*)$/u.test(value) || BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER))
    throw new NotificationAsyncWorkerError('INPUT');
  return Number(value);
}
async function transaction(client: PoolClient, source: NotificationDeliverySourceSelector) {
  const result = await client.query<{
    participant: string;
    privacy: string;
    request: string;
    tx: string;
    backend: number;
    role: string;
    isolation: string;
    rls: string;
    action: string;
  }>(`select openpc.current_participant_id()::text participant,openpc.current_privacy_domain_id()::text privacy,
    openpc.current_operation_id()::text request,pg_current_xact_id()::text tx,pg_backend_pid() backend,current_user role,
    current_setting('transaction_isolation') isolation,current_setting('row_security') rls,openpc.current_action_intent_id() action`);
  const row = result.rows[0];
  if (
    result.rowCount !== 1 ||
    !row ||
    row.participant !== source.worker.participantId ||
    row.privacy !== source.worker.privacyDomainId ||
    row.isolation !== 'read committed' ||
    row.rls !== 'on' ||
    row.action !== 'ACT-EVIDENCE_EXPORT_RECORDS-V1' ||
    !z.uuidv7().safeParse(row.request).success
  )
    throw new NotificationAsyncWorkerError('LEASE');
  return row;
}
async function currentNative<T>(
  client: PoolClient,
  source: NotificationDeliverySourceSelector,
  work: WorkRow,
  consume: (current: CurrentNotificationAsync, nowMs: number) => Promise<T>,
) {
  const tx = await transaction(client, source);
  const current = await client.query<{ generation_id: string; effective_digest: string }>(
    'select * from openpc.current_notification_delivery_limit($1)',
    [work.environment_id],
  );
  if (current.rowCount !== 1 || current.rows[0]!.generation_id !== work.generation_id)
    throw new NotificationAsyncWorkerError('LEASE');
  return withCurrentNotificationAsync(
    client,
    {
      participantId: source.worker.participantId,
      privacyDomainId: source.worker.privacyDomainId,
      requestId: tx.request,
      environmentId: work.environment_id,
      generationId: work.generation_id,
      workerInstallationDigest: source.worker.installationDigest,
    },
    async (same, admitted) => {
      if (same !== client) throw new NotificationAsyncWorkerError('LEASE');
      assertNotificationWorkerSchedule(admitted.input);
      if (
        admitted.original.consumer.stage !== 'EFFECTIVE' ||
        admitted.original.inputPayloadDigest !== work.input_payload_digest ||
        admitted.original.capacityPayloadDigest !== work.capacity_payload_digest ||
        admitted.committedGenerationDigest !== current.rows[0]!.effective_digest ||
        admitted.input.environmentId !== work.environment_id ||
        admitted.input.generationId !== work.generation_id
      )
        throw new NotificationAsyncWorkerError('LEASE');
      const clock = await client.query<{ now: string }>(
        'select floor(extract(epoch from clock_timestamp())*1000)::text now',
      );
      const result = await consume(admitted, safeTime(clock.rows[0]!.now));
      const after = await transaction(client, source);
      if (
        after.tx !== tx.tx ||
        after.backend !== tx.backend ||
        after.request !== tx.request ||
        after.role !== tx.role
      )
        throw new NotificationAsyncWorkerError('LEASE');
      return result;
    },
  );
}
async function readLease(
  client: PoolClient,
  source: NotificationDeliverySourceSelector,
  selector: NotificationWorkerLeaseSelector,
) {
  const result = await client.query<WorkRow>(
    `select ${columns} from control.notification_async_work
    where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
    [source.worker.participantId, source.worker.privacyDomainId, selector.eventId],
  );
  const work = result.rows[0];
  if (
    result.rowCount !== 1 ||
    !work ||
    work.notification_occurrence_id !== source.notificationOccurrenceId ||
    work.event_id !== source.eventId ||
    work.worker_installation_digest !== source.worker.installationDigest ||
    work.lease_owner !== selector.ownerId ||
    work.lease_epoch !== selector.epoch ||
    !work.charged ||
    !['LEASED', 'RECONCILING'].includes(work.state)
  )
    throw new NotificationAsyncWorkerError('LEASE');
  const proof = await client.query(
    `select openpc.check_notification_async_work_proof(w.event_id,w.revision)
   from control.notification_async_work w where participant_id=$1 and privacy_domain_id=$2 and event_id=$3
   and lease_owner=$4 and lease_epoch=$5`,
    [
      source.worker.participantId,
      source.worker.privacyDomainId,
      source.eventId,
      selector.ownerId,
      selector.epoch,
    ],
  );
  if (proof.rowCount !== 1) throw new NotificationAsyncWorkerError('LEASE');
  return work;
}

/** Additional exclusion INSIDE the existing real effect transaction. No Pool,
 * verifier callback or synthetic admission is accepted. The shared effect fence
 * blocks takeover, not same-epoch heartbeat: no work-row SHARE/UPDATE lock is
 * held over provider I/O. The existing owner's transaction lifetime is unchanged.
 * Historical read/reconcile/observation attachment must not call this function. */
export async function withNotificationWorkerLease<T>(
  client: PoolClient,
  sourceValue: unknown,
  selectorValue: unknown,
  phase: NotificationWorkerEffectPhase,
  consume: (window: NotificationWorkerLeaseWindow) => Promise<T>,
): Promise<T> {
  const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(sourceValue));
  const selector = notificationWorkerLeaseSelector.parse(immutableJsonCopy(selectorValue));
  const original = await readLease(client, source, selector);
  return currentNative(client, source, original, async (admitted) => {
    await client.query('select openpc.assert_notification_async_worker_owner()');
    const lock = await client.query<{ acquired: boolean }>(
      'select pg_try_advisory_xact_lock_shared(hashtextextended($1,0)) acquired',
      [
        `notification-work-effect:${source.worker.participantId}:${source.worker.privacyDomainId}:${selector.eventId}`,
      ],
    );
    if (lock.rows[0]?.acquired !== true) throw new NotificationAsyncWorkerError('BUSY');
    const check = async () => {
      const work = await readLease(client, source, selector);
      const clock = await client.query<{ now: string }>(
        'select floor(extract(epoch from clock_timestamp())*1000)::text now',
      );
      const observedNow = safeTime(clock.rows[0]!.now);
      const until = Math.min(
        safeTime(work.lease_until_ms ?? '0'),
        safeTime(work.deadline_at_ms),
        admitted.input.validUntilMs,
        admitted.capacity.expiresAtMs,
        observedNow + admitted.input.attemptTimeoutMs,
      );
      if (
        admitted.original.consumer.processInstanceId !== work.lease_owner ||
        work.input_payload_digest !== original.input_payload_digest ||
        work.capacity_payload_digest !== original.capacity_payload_digest ||
        work.generation_id !== original.generation_id ||
        work.environment_id !== original.environment_id ||
        (work.state === 'RECONCILING' &&
          phase !== 'RECOVERY_PUBLICATION' &&
          phase !== 'OUTCOME' &&
          phase !== 'CANCEL')
      )
        throw new NotificationAsyncWorkerError('LEASE');
      if (safeTime(clock.rows[0]!.now) >= until) throw new NotificationAsyncWorkerError('EXPIRED');
      // The immutable preparation owner measured the original rendered body.
      // Recheck its verified bytes against current native input before and after
      // each effect; neither the receipt envelope nor a caller length is used.
      const preparations = await client.query<{
        preparation_bytes: Buffer;
        preparation_digest: string;
      }>(
        `select preparation_bytes,preparation_digest from control.notification_delivery_preparation
         where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3
         order by attempt_number desc limit 1`,
        [
          source.worker.participantId,
          source.worker.privacyDomainId,
          source.notificationOccurrenceId,
        ],
      );
      if (preparations.rowCount === 1) {
        const { decodeNotificationDeliveryPreparation } =
          await import('./delivery-start-preparation.js');
        const p = decodeNotificationDeliveryPreparation(
          preparations.rows[0]!.preparation_bytes,
          preparations.rows[0]!.preparation_digest,
        );
        if (
          p.source.eventId !== source.eventId ||
          p.attempt.payloadBytes > admitted.input.maximumPayloadBytes
        )
          throw new NotificationAsyncWorkerError('INPUT');
      } else if (phase !== 'PREPARE' && phase !== 'CANCEL' && phase !== 'RECOVERY_PUBLICATION') {
        throw new NotificationAsyncWorkerError('INPUT');
      }

      return {
        validUntilMs: until,
        heartbeatMs: admitted.input.heartbeatMs,
        ownerId: work.lease_owner!,
        epoch: work.lease_epoch,
      };
    };
    const window = await check();
    if (phase === 'GATEWAY') {
      const rate = await client.query<{ acquired: boolean }>(
        'select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired',
        [
          `notification-dispatch-rate:${source.worker.participantId}:${source.worker.privacyDomainId}:${original.environment_id}`,
        ],
      );
      if (rate.rows[0]?.acquired !== true) throw new NotificationAsyncWorkerError('BUSY');
      const used = await client.query<{ count: string }>(
        `select count(*)::text count
        from control.notification_delivery_dispatch_intent i join control.notification_delivery d
        using(participant_id,privacy_domain_id,notification_occurrence_id)
        where i.participant_id=$1 and i.privacy_domain_id=$2 and d.budget_environment_id=$3
        and i.state='CLAIMED' and i.claimed_at_ms>floor(extract(epoch from clock_timestamp())*1000)-1000`,
        [source.worker.participantId, source.worker.privacyDomainId, original.environment_id],
      );
      if (BigInt(used.rows[0]!.count) >= BigInt(admitted.input.dispatchRatePerSecond))
        throw new NotificationAsyncWorkerError('BUSY');
    }
    const result = await consume(window);
    await check();
    return result;
  });
}

export interface NotificationAsyncWorkRecord {
  readonly source: NotificationDeliverySourceSelector;
  readonly state: string;
  readonly reason: string | null;
  readonly revision: string;
  readonly proofEventId: string;
  readonly deadlineAtMs: number;
  readonly nextAtMs: number | null;
  readonly lease: NotificationWorkerLeaseSelector | null;
  readonly leaseUntilMs: number | null;
  readonly charged: boolean;
  readonly effectUncertain: boolean;
  readonly original: NotificationDeliveryOriginal;
}
interface FullWorkRow extends WorkRow {
  reason: string | null;
  revision: string;
  transition_event_id: string;
  next_at_ms: string | null;
  original: unknown;
}
const fullColumns =
  columns + ',reason,revision::text,transition_event_id::text,next_at_ms::text,original';
const args = (source: NotificationDeliverySourceSelector) => [
  source.worker.participantId,
  source.worker.privacyDomainId,
  source.eventId,
];
async function exclusive(client: PoolClient, name: string) {
  const lock = await client.query<{ acquired: boolean }>(
    'select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired',
    [name],
  );
  if (lock.rows[0]?.acquired !== true) throw new NotificationAsyncWorkerError('BUSY');
}
/** Current worker authentication plus immutable historical source custody. This
 * wrapper cannot grant dispatch authority and performs no external effect. */
async function withHistoricalSource<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  source: NotificationDeliverySourceSelector,
  use: (
    client: PoolClient,
    worker: NotificationWorkerAdmission,
    published: PublishedNotificationDeliveryRequest,
  ) => Promise<T>,
) {
  return withNotificationDeliveryWorkerPeer(
    pool,
    kernel,
    socket,
    source.worker,
    async (client, worker) => {
      await client.query(
        "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
      );
      try {
        await lockEvidenceLifecycle(
          client,
          source.worker.participantId,
          source.worker.privacyDomainId,
        );
        const published = await readHistoricalNotificationDeliveryRequest(client, worker, source);
        return await use(client, worker, published);
      } finally {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        );
      }
    },
  );
}

/** Short scheduler admission through real Identity, original publication,
 * generation and native custody. No external provider callback is exposed. */
async function scheduler<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  source: NotificationDeliverySourceSelector,
  use: (
    client: PoolClient,
    admitted: CurrentNotificationAsync,
    now: number,
    worker: NotificationWorkerAdmission,
  ) => Promise<T>,
  historical = false,
) {
  const consume = async (
    client: PoolClient,
    _worker: NotificationWorkerAdmission,
    published: PublishedNotificationDeliveryRequest,
    configuration: NotificationDeliveryConfiguration,
  ) => {
    const tx = await transaction(client, source);
    return withCurrentNotificationAsync(
      client,
      {
        participantId: source.worker.participantId,
        privacyDomainId: source.worker.privacyDomainId,
        environmentId: published.claims.environmentId,
        generationId: configuration.generation_id,
        requestId: tx.request,
        workerInstallationDigest: source.worker.installationDigest,
      },
      async (same, admitted) => {
        if (
          same !== client ||
          admitted.original.consumer.stage !== 'EFFECTIVE' ||
          admitted.committedGenerationDigest !== configuration.effective_digest ||
          admitted.input.environmentId !== published.claims.environmentId ||
          admitted.input.generationId !== configuration.generation_id
        )
          throw new NotificationAsyncWorkerError('LEASE');
        assertNotificationWorkerSchedule(admitted.input);
        await client.query('select openpc.assert_notification_async_worker_owner()');
        const clock = await client.query<{ now: string }>(
          'select floor(extract(epoch from clock_timestamp())*1000)::text now',
        );
        const result = await use(client, admitted, safeTime(clock.rows[0]!.now), _worker);
        const after = await transaction(client, source);
        if (
          after.tx !== tx.tx ||
          after.backend !== tx.backend ||
          after.request !== tx.request ||
          after.role !== tx.role
        )
          throw new NotificationAsyncWorkerError('LEASE');
        return result;
      },
    );
  };
  if (!historical)
    return withNotificationDeliveryConfiguration(pool, kernel, socket, source, consume);
  return withHistoricalSource(pool, kernel, socket, source, async (client, worker, published) => {
    const configuration = await client.query<NotificationDeliveryConfiguration>(
      'select * from openpc.current_notification_delivery_limit($1)',
      [published.claims.environmentId],
    );
    if (configuration.rowCount !== 1) throw new NotificationAsyncWorkerError('LEASE');
    return consume(client, worker, published, configuration.rows[0]!);
  });
}
function compatible(
  row: WorkRow,
  admitted: CurrentNotificationAsync,
  source: NotificationDeliverySourceSelector,
) {
  if (
    row.event_id !== source.eventId ||
    row.notification_occurrence_id !== source.notificationOccurrenceId ||
    row.worker_installation_digest !== source.worker.installationDigest ||
    row.environment_id !== admitted.input.environmentId ||
    row.generation_id !== admitted.input.generationId ||
    row.input_payload_digest !== admitted.original.inputPayloadDigest ||
    row.capacity_payload_digest !== admitted.original.capacityPayloadDigest
  )
    throw new NotificationAsyncWorkerError('LEASE');
}
/** Discover selectors only from durable internal owners after a crash. Those
 * selectors are subsequently verified by original signer/outcome readers. */
async function original(
  client: PoolClient,
  source: NotificationDeliverySourceSelector,
): Promise<NotificationDeliveryOriginal> {
  const latest = await client.query<{
    operation_id: string;
    signer_installation_digest: string | null;
  }>(
    `
 select p.operation_id::text,s.signer_installation_digest from control.notification_delivery_preparation p
 left join control.notification_delivery_signing s using(participant_id,privacy_domain_id,operation_id)
 where p.participant_id=$1 and p.privacy_domain_id=$2 and p.notification_occurrence_id=$3
 order by p.attempt_number desc limit 1`,
    [source.worker.participantId, source.worker.privacyDomainId, source.notificationOccurrenceId],
  );
  const row = latest.rows[0];
  if (!row?.signer_installation_digest) return { source };
  const start = {
    source,
    operationId: row.operation_id,
    signerInstallationDigest: row.signer_installation_digest,
  };
  const results = await client.query<{ operation_id: string; signer_installation_digest: string }>(
    `
 select operation_id::text,signer_installation_digest from control.notification_delivery_outcome_signing
 where participant_id=$1 and privacy_domain_id=$2 and start_operation_id=$3`,
    [source.worker.participantId, source.worker.privacyDomainId, start.operationId],
  );
  if (results.rowCount! > 1) throw new NotificationAsyncWorkerError('UNKNOWN');
  const outcome = results.rows[0];
  return outcome
    ? {
        source,
        start,
        outcome: {
          original: start,
          worker: source.worker,
          operationId: outcome.operation_id,
          signerInstallationDigest: outcome.signer_installation_digest,
        },
      }
    : { source, start };
}
async function record(
  client: PoolClient,
  source: NotificationDeliverySourceSelector,
  row: FullWorkRow,
): Promise<NotificationAsyncWorkRecord> {
  if (
    row.event_id !== source.eventId ||
    row.notification_occurrence_id !== source.notificationOccurrenceId
  )
    throw new NotificationAsyncWorkerError('UNKNOWN');
  const retainedSource: NotificationDeliverySourceSelector = {
    ...source,
    worker: { ...source.worker, installationDigest: row.worker_installation_digest },
  };
  await client.query('select openpc.check_notification_async_work_proof($1,$2)', [
    source.eventId,
    row.revision,
  ]);
  return immutableJsonCopy({
    source: retainedSource,
    state: row.state,
    reason: row.reason,
    revision: row.revision,
    proofEventId: row.transition_event_id,
    deadlineAtMs: safeTime(row.deadline_at_ms),
    nextAtMs: row.next_at_ms === null ? null : safeTime(row.next_at_ms),
    lease:
      row.lease_owner === null
        ? null
        : { eventId: source.eventId, ownerId: row.lease_owner, epoch: row.lease_epoch },
    leaseUntilMs: row.lease_until_ms === null ? null : safeTime(row.lease_until_ms),
    charged: row.charged,
    effectUncertain: row.effect_uncertain,
    original: await original(client, retainedSource),
  });
}
export async function readNotificationAsyncWork(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
  return withHistoricalSource(pool, kernel, socket, source, async (client) => {
    const rows = await client.query<FullWorkRow>(
      `select ${fullColumns} from control.notification_async_work where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
      args(source),
    );
    if (rows.rowCount === 0) return null;
    if (rows.rowCount !== 1) throw new NotificationAsyncWorkerError('UNKNOWN');
    return record(client, source, rows.rows[0]!);
  });
}
/** Atomic source-custody enqueue; retained original is returned without changing
 * its domain deadline. Queue bytes measure the receipt envelope; maximum payload
 * bytes independently bound the actual deterministic delivery body. */
export async function enqueueNotificationAsyncWork(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
  return scheduler(
    pool,
    kernel,
    socket,
    source,
    async (client, admitted, now, worker) => {
      const scope = args(source),
        input = admitted.input;
      await exclusive(
        client,
        `notification-work-capacity:${scope[0]}:${scope[1]}:${input.environmentId}`,
      );
      const existing = await client.query<FullWorkRow>(
        `select ${fullColumns} from control.notification_async_work where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
        scope,
      );
      if (existing.rowCount === 1) return record(client, source, existing.rows[0]!);
      const events = await client.query<{
        bytes: string;
        digest: string;
        published: string;
        partition: string;
        sequence: string;
      }>(
        `
   select octet_length(payload_cbor)::text bytes,'sha256:'||encode(payload_digest,'hex') digest,
   floor(extract(epoch from occurred_at)*1000)::text published,aggregate_type||':'||aggregate_id::text partition,business_sequence::text sequence
   from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
        scope,
      );
      if (events.rowCount !== 1) throw new NotificationAsyncWorkerError('INPUT');
      const event = events.rows[0]!,
        deadline = notificationWorkDeadline(input, safeTime(event.published));
      // The SQL owner rederives denial from original custody under fences. A
      // caught application error cannot create a disposition. Native qualification
      // remains mandatory for this bookkeeping-only branch and its proof event.
      const disposition = await client.query<{ reason: string | null }>(
        'select openpc.notification_async_initial_disposition($1,$2,$3) reason',
        [source.eventId, source.worker.installationDigest, deadline],
      );
      if (disposition.rowCount !== 1) throw new NotificationAsyncWorkerError('UNKNOWN');
      const reason = disposition.rows[0]!.reason;
      const insert = async (initialReason: string | null) => {
        const rows = await client.query<FullWorkRow>(
          `insert into control.notification_async_work
   (participant_id,privacy_domain_id,event_id,notification_occurrence_id,environment_id,generation_id,worker_installation_digest,input_payload_digest,capacity_payload_digest,
    partition,sequence,payload_bytes,source_digest,published_at_ms,deadline_at_ms,state,lease_epoch,charged,effect_uncertain,revision,transition_event_id,reason)
   values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,0,false,false,1,$17,$18) returning ${fullColumns}`,
          [
            ...scope,
            source.notificationOccurrenceId,
            input.environmentId,
            input.generationId,
            source.worker.installationDigest,
            admitted.original.inputPayloadDigest,
            admitted.original.capacityPayloadDigest,
            event.partition,
            event.sequence,
            event.bytes,
            event.digest,
            event.published,
            deadline,
            initialReason === null ? 'PENDING' : 'QUARANTINED',
            localOperationId(),
            initialReason,
          ],
        );
        return record(client, source, rows.rows[0]!);
      };
      if (reason !== null) return insert(reason);
      if (deadline <= now) throw new NotificationAsyncWorkerError('EXPIRED');
      const totals = await client.query<{ items: string; bytes: string }>(
        `select count(*)::text items,coalesce(sum(payload_bytes),0)::text bytes
   from control.notification_async_work where participant_id=$1 and privacy_domain_id=$2 and environment_id=$3 and state not in ('DONE','CANCELLED')
   and not (state='QUARANTINED' and revision=1 and lease_epoch=0 and not charged and not effect_uncertain
    and reason in ('INITIAL_DOMAIN_DEADLINE','INITIAL_SOURCE_WITHDRAWN'))`,
        [scope[0], scope[1], input.environmentId],
      );
      const { withNotificationDeliveryPayloadSize } =
        await import('./delivery-start-preparation.js');
      return withNotificationDeliveryPayloadSize(
        client,
        worker,
        source,
        async ({ payloadBytes }) => {
          if (
            notificationQueueAdmission(
              input,
              { items: safeTime(totals.rows[0]!.items), bytes: safeTime(totals.rows[0]!.bytes) },
              { payloadBytes, envelopeBytes: safeTime(event.bytes) },
            ) !== 'ADMIT'
          )
            throw new NotificationAsyncWorkerError('BUSY');
          return insert(null);
        },
      );
    },
    true,
  );
}
const preEffectPhase = z.enum([
  'UNPREPARED',
  'PREPARED',
  'SIGNING_PREPARED',
  'STALE_PREPARED',
  'HANDED_OFF',
]);
async function inspectPreEffect(client: PoolClient, source: NotificationDeliverySourceSelector) {
  const rows = await client.query<{ phase: unknown }>(
    'select openpc.notification_async_pre_effect_phase($1) phase',
    [source.eventId],
  );
  if (rows.rowCount !== 1) throw new NotificationAsyncWorkerError('UNKNOWN');
  return preEffectPhase.parse(rows.rows[0]!.phase);
}
/** Re-entry is allowed only from actual fenced, never-handed-off originals.
 * The result is a selector, not a portable capability: every subsequent owner
 * rechecks the current lease and its own original before any mutation or I/O. */
export async function inspectNotificationPreEffectResume(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  leaseValue: unknown,
) {
  const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(value)),
    lease = notificationWorkerLeaseSelector.parse(immutableJsonCopy(leaseValue));
  return scheduler(pool, kernel, socket, source, async (client, admitted, now) => {
    const row = await readLease(client, source, lease);
    compatible(row, admitted, source);
    if (
      row.state !== 'LEASED' ||
      lease.ownerId !== admitted.original.consumer.processInstanceId ||
      Math.min(
        safeTime(row.lease_until_ms ?? '0'),
        safeTime(row.deadline_at_ms),
        admitted.input.validUntilMs,
        admitted.capacity.expiresAtMs,
      ) <= now
    )
      throw new NotificationAsyncWorkerError('LEASE');
    await exclusive(
      client,
      `notification-work-effect:${source.worker.participantId}:${source.worker.privacyDomainId}:${source.eventId}`,
    );
    const phase = await inspectPreEffect(client, source);
    if (phase === 'HANDED_OFF' || phase === 'STALE_PREPARED')
      throw new NotificationAsyncWorkerError('LEASE');
    if (phase === 'UNPREPARED') return { phase, operationId: null };
    const rows = await client.query<{ preparation_bytes: Buffer; preparation_digest: string }>(
      `select preparation_bytes,preparation_digest
   from control.notification_delivery_preparation where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3
   order by attempt_number desc limit 1`,
      [source.worker.participantId, source.worker.privacyDomainId, source.notificationOccurrenceId],
    );
    if (rows.rowCount !== 1) throw new NotificationAsyncWorkerError('UNKNOWN');
    const { decodeNotificationDeliveryPreparation } =
      await import('./delivery-start-preparation.js');
    const prepared = decodeNotificationDeliveryPreparation(
      rows.rows[0]!.preparation_bytes,
      rows.rows[0]!.preparation_digest,
    );
    if (
      prepared.source.eventId !== source.eventId ||
      prepared.source.notificationOccurrenceId !== source.notificationOccurrenceId
    )
      throw new NotificationAsyncWorkerError('UNKNOWN');
    return { phase, operationId: prepared.operationId };
  });
}
/** Batch claims share one authenticated operation context. Each transition has
 * its own (scope,event,revision) proof identity; no context swapping per row. */
export async function claimNotificationAsyncBatch(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
) {
  const anchor = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
  return scheduler(pool, kernel, socket, anchor, async (client, admitted, now) => {
    const input = admitted.input,
      scope = [anchor.worker.participantId, anchor.worker.privacyDomainId, input.environmentId];
    await exclusive(client, `notification-work-capacity:${scope[0]}:${scope[1]}:${scope[2]}`);
    const totals = await client.query<{ charged: string }>(
      `select count(*)::text charged from control.notification_async_work
   where participant_id=$1 and privacy_domain_id=$2 and environment_id=$3 and charged`,
      scope,
    );
    let available = Math.max(0, input.concurrency - safeTime(totals.rows[0]!.charged));
    const candidates = await client.query<FullWorkRow>(
      `select ${fullColumns} from control.notification_async_work w
   where w.participant_id=$1 and w.privacy_domain_id=$2 and w.environment_id=$3 and w.worker_installation_digest=$4
   and w.generation_id=$5 and w.input_payload_digest=$6 and w.capacity_payload_digest=$7
   and ((w.state='PENDING') or (w.state='RETRY_WAIT' and w.next_at_ms<=$8) or
    (w.state in ('LEASED','RECONCILING') and w.charged and w.lease_until_ms<=$8) or
    (w.state='QUARANTINED' and w.charged and w.deadline_at_ms>$8 and w.lease_until_ms is null))
   and not exists(select 1 from control.notification_async_work earlier where earlier.participant_id=w.participant_id
    and earlier.privacy_domain_id=w.privacy_domain_id and earlier.environment_id=w.environment_id and earlier.partition=w.partition
    and earlier.sequence<w.sequence and earlier.state not in ('DONE','CANCELLED'))
   order by w.published_at_ms,w.event_id limit $9 for update of w skip locked`,
      [
        ...scope,
        anchor.worker.installationDigest,
        input.generationId,
        admitted.original.inputPayloadDigest,
        admitted.original.capacityPayloadDigest,
        now,
        input.batchSize,
      ],
    );
    const claimed: NotificationAsyncWorkRecord[] = [],
      quarantined: NotificationAsyncWorkRecord[] = [];
    for (const row of candidates.rows) {
      if (!row.charged && available === 0 && safeTime(row.deadline_at_ms) > now) continue;
      const source = {
        worker: anchor.worker,
        eventId: row.event_id,
        notificationOccurrenceId: row.notification_occurrence_id,
      };
      compatible(row, admitted, source);
      // The real source checker is invoked by the same SQL guard for every row;
      // the anchor admits scope, never a fabricated second source.
      const effect = await client.query<{ acquired: boolean }>(
        'select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired',
        [
          `notification-work-effect:${source.worker.participantId}:${source.worker.privacyDomainId}:${source.eventId}`,
        ],
      );
      if (effect.rows[0]?.acquired !== true) continue;
      const intent = await original(client, source);
      const preEffect = await inspectPreEffect(client, source);
      if (preEffect === 'STALE_PREPARED') {
        const stale = await client.query<FullWorkRow>(
          `update control.notification_async_work set state='QUARANTINED',lease_owner=null,lease_until_ms=null,charged=false,effect_uncertain=false,
        next_at_ms=null,original=$4,reason='PRE_EFFECT_STALE',revision=revision+1,transition_event_id=$5
        where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 returning ${fullColumns}`,
          [...args(source), intent, localOperationId()],
        );
        quarantined.push(await record(client, source, stale.rows[0]!));
        if (row.charged) available++;
        continue;
      }
      if (safeTime(row.deadline_at_ms) <= now) {
        const expired = await client.query<FullWorkRow>(
          `update control.notification_async_work set state='QUARANTINED',lease_owner=null,lease_until_ms=null,
     next_at_ms=null,original=$4,reason='DOMAIN_DEADLINE',revision=revision+1,transition_event_id=$5
     where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 returning ${fullColumns}`,
          [...args(source), intent, localOperationId()],
        );
        quarantined.push(await record(client, source, expired.rows[0]!));
        continue;
      }
      const until = Math.min(
        notificationLeaseDeadline(input, safeTime(row.deadline_at_ms), now),
        admitted.capacity.expiresAtMs,
      );
      if (until <= now) throw new NotificationAsyncWorkerError('EXPIRED');
      const updated = await client.query<FullWorkRow>(
        `update control.notification_async_work set
    state=$4,lease_owner=$5,lease_epoch=lease_epoch+1,lease_until_ms=$6,charged=true,effect_uncertain=true,
    next_at_ms=null,original=$7,reason=null,revision=revision+1,transition_event_id=$8
    where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 returning ${fullColumns}`,
        [
          ...args(source),
          row.effect_uncertain &&
          !['UNPREPARED', 'PREPARED', 'SIGNING_PREPARED'].includes(preEffect)
            ? 'RECONCILING'
            : 'LEASED',
          admitted.original.consumer.processInstanceId,
          until,
          intent,
          localOperationId(),
        ],
      );
      if (!row.charged) available--;
      claimed.push(await record(client, source, updated.rows[0]!));
    }
    return { items: claimed, quarantined, heartbeatMs: input.heartbeatMs };
  });
}
export async function heartbeatNotificationAsyncWork(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  leaseValue: unknown,
) {
  const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(value)),
    lease = notificationWorkerLeaseSelector.parse(immutableJsonCopy(leaseValue));
  return withNotificationDeliveryWorkerPeer(pool, kernel, socket, source.worker, async (client) => {
    await client.query(
      "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
    );
    try {
      const row = await readLease(client, source, lease);
      // Immutable SQL source custody and native/generation fences do not require
      // the provider transaction's exclusive Evidence lifecycle lock. Heartbeats
      // must neither acquire that lock nor the exclusive effect fence.
      return await currentNative(client, source, row, async (admitted, now) => {
        await client.query('select openpc.assert_notification_async_worker_owner()');
        const proof = await client.query(
          'select openpc.check_notification_delivery_requested_event(e) from control.outbox_event e where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
          args(source),
        );
        if (proof.rowCount !== 1) throw new NotificationAsyncWorkerError('LEASE');
        if (
          lease.ownerId !== admitted.original.consumer.processInstanceId ||
          safeTime(row.lease_until_ms ?? '0') <= now
        )
          throw new NotificationAsyncWorkerError('EXPIRED');
        const until = Math.min(
          notificationLeaseDeadline(admitted.input, safeTime(row.deadline_at_ms), now),
          admitted.capacity.expiresAtMs,
        );
        const updated = await client.query<FullWorkRow>(
          `update control.notification_async_work set lease_until_ms=$5,revision=revision+1,transition_event_id=$7
   where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 and lease_epoch=$4 and lease_owner=$6
   and lease_until_ms>floor(extract(epoch from clock_timestamp())*1000) returning ${fullColumns}`,
          [...args(source), lease.epoch, until, lease.ownerId, localOperationId()],
        );
        if (updated.rowCount !== 1) throw new NotificationAsyncWorkerError('LEASE');
        return record(client, source, updated.rows[0]!);
      });
    } finally {
      await client.query(
        "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
      );
    }
  });
}
/** Resolve scheduling from authoritative business originals only. Caller
 * supplies neither an outcome nor an uncertainty-clearing flag. Unknown retains
 * its charged slot in protected operational quarantine, not FAILED delivery. */
export async function settleNotificationAsyncWork(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  value: unknown,
  leaseValue: unknown,
) {
  const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(value)),
    lease = notificationWorkerLeaseSelector.parse(immutableJsonCopy(leaseValue));
  return scheduler(pool, kernel, socket, source, async (client, admitted, now) => {
    const row = await readLease(client, source, lease);
    compatible(row, admitted, source);
    if (lease.ownerId !== admitted.original.consumer.processInstanceId)
      throw new NotificationAsyncWorkerError('LEASE');
    await exclusive(
      client,
      `notification-work-effect:${source.worker.participantId}:${source.worker.privacyDomainId}:${source.eventId}`,
    );
    const retained = await original(client, source);
    let state = 'QUARANTINED',
      charged = true,
      uncertain = true,
      next: number | null = null,
      reason = 'ORIGINAL_UNRESOLVED';
    if (retained.outcome) {
      const { readNotificationOutcomePublicationInTransaction } =
        await import('./delivery-outcome-publication.js');
      const publication = await readNotificationOutcomePublicationInTransaction(
        client,
        retained.outcome,
      );
      if (publication) {
        const after = publication.proposal.after.snapshot;
        if (
          after.state === 'RETRY_WAIT' &&
          !after.cancelRequested &&
          after.nextAttemptAtMs !== null &&
          after.nextAttemptAtMs < safeTime(row.deadline_at_ms) &&
          now < safeTime(row.deadline_at_ms)
        ) {
          state = 'RETRY_WAIT';
          next = after.nextAttemptAtMs;
          charged = false;
          uncertain = false;
          reason = 'SIGNED_RETRYABLE_NO_EFFECT';
        } else if (['DELIVERED', 'FAILED', 'CANCELLED'].includes(after.state)) {
          state = after.state === 'CANCELLED' ? 'CANCELLED' : 'DONE';
          charged = false;
          uncertain = false;
          reason = 'SIGNED_TERMINAL';
        } else if (after.state === 'RETRY_WAIT') {
          charged = false;
          uncertain = false;
          reason = 'DOMAIN_DEADLINE';
        }
      }
    }
    // Cancellation projection is accepted only with its immutable signed original.
    const cancellation = await client.query(
      `select openpc.check_notification_delivery_cancellation_original(c)
   from control.notification_delivery_cancellation c join control.notification_delivery d
   using(participant_id,privacy_domain_id,notification_occurrence_id)
   where c.participant_id=$1 and c.privacy_domain_id=$2 and c.notification_occurrence_id=$3
   and d.state='CANCELLED' and d.cancel_requested and c.transition->'after'->>'state'='CANCELLED'`,
      [source.worker.participantId, source.worker.privacyDomainId, source.notificationOccurrenceId],
    );
    if (cancellation.rowCount === 1) {
      state = 'CANCELLED';
      charged = false;
      uncertain = false;
      next = null;
      reason = 'SIGNED_CANCELLATION';
    }
    if (cancellation.rowCount! > 1) throw new NotificationAsyncWorkerError('UNKNOWN');
    if (uncertain && (await inspectPreEffect(client, source)) === 'STALE_PREPARED') {
      state = 'QUARANTINED';
      charged = false;
      uncertain = false;
      next = null;
      reason = 'PRE_EFFECT_STALE';
    }
    const updated = await client.query<FullWorkRow>(
      `update control.notification_async_work set
   state=$5,lease_owner=null,lease_until_ms=null,charged=$6,effect_uncertain=$7,next_at_ms=$8,original=$9,reason=$10,revision=revision+1,transition_event_id=$12
   where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 and lease_epoch=$4 and lease_owner=$11 returning ${fullColumns}`,
      [
        ...args(source),
        lease.epoch,
        state,
        charged,
        uncertain,
        next,
        retained,
        reason,
        lease.ownerId,
        localOperationId(),
      ],
    );
    if (updated.rowCount !== 1) throw new NotificationAsyncWorkerError('LEASE');
    return record(client, source, updated.rows[0]!);
  });
}
