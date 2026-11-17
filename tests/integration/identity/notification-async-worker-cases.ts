import assert from 'node:assert/strict';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { NotificationPayloadReferenceGate } from '../../../services/control-api/src/notifications/payload-reference.js';
import { setTimeout as delay } from 'node:timers/promises';
import { NotificationAsyncWorker } from '../../../services/control-api/src/notifications/async-worker.js';
import {
  NotificationDeliveryRuntime,
  type NotificationDeliveryPeers,
} from '../../../services/control-api/src/notifications/delivery-runtime.js';
import {
  claimNotificationAsyncBatch,
  enqueueNotificationAsyncWork,
  readNotificationAsyncWork,
  settleNotificationAsyncWork,
  heartbeatNotificationAsyncWork,
  withNotificationWorkerLease,
} from '../../../services/control-api/src/notifications/async-worker-state.js';
import {
  prepareNotificationDeliverySigningLeased,
  claimNotificationDeliverySigningLeased,
  withNotificationSigningHistory,
  readNotificationSigningRecord,
} from '../../../services/control-api/src/notifications/delivery-signing-state.js';
import {
  prepareNotificationDeliveryLeased,
  readNotificationDeliveryPreparation,
} from '../../../services/control-api/src/notifications/delivery-start-preparation.js';
import { synchronizeNotificationDeliveryBudgetLeased } from '../../../services/control-api/src/notifications/delivery-start-state.js';
import { withNotificationDeliveryRequest } from '../../../services/control-api/src/notifications/delivery-admission.js';
import {
  discoverNotificationDeliverySources,
  notificationConsumerCeilings,
} from '../../../services/control-api/src/notifications/delivery-source-discovery.js';
import type { NotificationProducerJourneyInput } from './notification-delivery-outcome-cases.js';

export type NotificationAsyncWorkerCase =
  | 'BATCH_PROOF_CUSTODY'
  | 'EXPLICIT_RETRY'
  | 'RETRY_WAIT_CANCELLATION'
  | 'HEARTBEAT_FENCE'
  | 'CLAIM_CRASH'
  | 'PREPARATION_CRASH'
  | 'SIGNING_CLAIM_CRASH'
  | 'EXPIRED_SOURCE_DISCOVERY'
  | 'WITHDRAWN_SOURCE_DISCOVERY';
/** Canonical root supplies genuine governed occurrences, same-scope native
 * qualification/EFFECTIVE configuration and independent cancellation authority.
 * No test can inject admitted capacity, a lease, a receipt or an approval. */
export interface NotificationAsyncWorkerCaseInput {
  current(): readonly NotificationProducerJourneyInput[];
  /** Separate genuinely governed tenant/privacy source for authenticated denial. */
  foreign(): NotificationProducerJourneyInput;
  reopen(): Promise<void>;
  /** Actual mounted physical bounds for discovery cases. Signed native input
   * still owns batchSize and timing. These are not readiness or qualification. */
  consumerCeilings?: unknown;
  /** Runs the existing real producer journey after the committed endpoint
   * change, adds the resulting original to current(), and preserves it on reopen. */
  produceAfterEndpointChange?: () => Promise<NotificationProducerJourneyInput>;
  cancellationSignerInstallationDigest: string;
  gateway: {
    setOutcome(value: 'DELIVERED' | 'RETRYABLE_NO_EFFECT'): void;
    stats(): { calls: number; readbacks: number; delivered: number; receipts: number };
  };
  /** Must execute public endpoint UPDATE with actual approval/step-up; return
   * only its committed operation selector. The cancellation owner verifies it. */
  governEndpointChange(source: NotificationProducerJourneyInput): Promise<string>;
}
function options(input: NotificationProducerJourneyInput, cancellation: string) {
  return {
    pool: input.pool,
    kernel: input.kernel,
    vaultDirectory: input.vaultDirectory,
    kmsTls: input.kmsTls,
    signerTls: input.transport,
    credentialProvider: input.credentialProvider,
    signers: {
      start: input.startSignerInstallationDigest,
      outcome: input.outcomeSignerInstallationDigest,
    },
    cancellationSignerInstallationDigest: cancellation,
  };
}
const peers = <T>(
  input: NotificationProducerJourneyInput,
  run: (value: NotificationDeliveryPeers) => Promise<T>,
) =>
  input.withDeliveryPeer((delivery) =>
    input.withRecipientPeer((recipient) => run({ delivery, recipient })),
  );
const read = (input: NotificationProducerJourneyInput) =>
  input.withDeliveryPeer((socket) =>
    readNotificationAsyncWork(input.pool, input.kernel, socket, input.source),
  );
async function due(input: NotificationProducerJourneyInput) {
  const work = await read(input);
  assert.ok(work);
  assert.equal(work.state, 'RETRY_WAIT');
  assert.ok(work.nextAtMs);
  // Use the real canonical five-second first delay; never rewrite persisted
  // times, advance a fake clock or shorten qualified production settings.
  const remaining = work.nextAtMs - Date.now();
  assert.ok(remaining <= 5000);
  if (remaining > 0) await delay(remaining + 1);
  return work;
}
function passed(results: readonly PromiseSettledResult<unknown>[]) {
  assert.ok(results.length > 0);
  const failed = results.filter((result) => result.status === 'rejected');
  if (failed.length)
    throw new AggregateError(
      failed.map((result) => (result as PromiseRejectedResult).reason),
      'Notification batch failed',
    );
}
async function batchProof(input: NotificationAsyncWorkerCaseInput) {
  const sources = input.current();
  assert.equal(sources.length, 2);
  const first = sources[0]!;
  assert.equal(sources[1]!.pool, first.pool);
  assert.deepEqual(sources[1]!.source.worker, first.source.worker);
  assert.notEqual(sources[1]!.source.eventId, first.source.eventId);
  const worker = new NotificationAsyncWorker(
    options(first, input.cancellationSignerInstallationDigest),
  );
  const before = input.gateway.stats();
  input.gateway.setOutcome('DELIVERED');
  try {
    for (const source of sources) await peers(source, (p) => worker.enqueue(p, source.source));
    const foreign = input.foreign();
    assert.ok(
      foreign.source.worker.participantId !== first.source.worker.participantId ||
        foreign.source.worker.privacyDomainId !== first.source.worker.privacyDomainId,
    );
    assert.equal(await read(foreign), null, 'Foreign source must have no prior scheduler intent');
    await assert.rejects(peers(first, (p) => worker.enqueue(p, foreign.source)));
    assert.equal(
      await read(foreign),
      null,
      'A genuine peer from the first realm cannot enqueue another realm',
    );
    const result = await peers(first, (p) => worker.runOnce(p, first.source));
    assert.equal(
      result.length,
      2,
      'Qualified native batch/concurrency must admit both real sources',
    );
    passed(result);
    await first.withDeliveryPeer((socket) =>
      withNotificationDeliveryRequest(
        first.pool,
        first.kernel,
        socket,
        first.source,
        async (client) => {
          const rows = await client.query<{ operation: string; proof: string; count: string }>(
            `select t.operation_id::text operation,t.proof_event_id::text proof,
       (select count(*)::text from control.outbox_event e where e.participant_id=t.participant_id and e.privacy_domain_id=t.privacy_domain_id and e.event_id=t.proof_event_id
        and e.proof_kind='NOTIFICATION_ASYNC_WORK_TRANSITION_REFERENCE' and e.sequence_namespace='NOTIFICATION_ASYNC_WORK_TRANSITION_V1'
        and e.aggregate_type='notification-async-work' and e.aggregate_id=t.event_id and e.business_sequence=t.revision
        and e.correlation_id=t.operation_id and e.causation_id=t.event_id) count
       from control.notification_async_work_transition t where t.participant_id=$1 and t.privacy_domain_id=$2 and t.event_id=any($3::uuid[]) and t.revision=2`,
            [
              first.source.worker.participantId,
              first.source.worker.privacyDomainId,
              sources.map((s) => s.source.eventId),
            ],
          );
          assert.equal(rows.rowCount, 2);
          assert.equal(new Set(rows.rows.map((r) => r.operation)).size, 1);
          assert.equal(new Set(rows.rows.map((r) => r.proof)).size, 2);
          assert.ok(rows.rows.every((r) => r.count === '1'));
          for (const table of ['notification_async_work', 'notification_async_work_transition']) {
            await client.query('savepoint notification_async_truncate_denial');
            let denied = false;
            try {
              await client.query(`truncate control.${table}`);
            } catch {
              denied = true;
            }
            await client.query('rollback to savepoint notification_async_truncate_denial');
            assert.equal(denied, true, `Runtime must not truncate ${table}`);
          }
        },
      ),
    );
    assert.equal(input.gateway.stats().delivered - before.delivered, 2);
  } finally {
    await worker.close();
  }
  const retained = await Promise.all(sources.map(read));
  assert.ok(retained.every((work) => work?.state === 'DONE' && !work.charged));
  await input.reopen();
  assert.deepEqual(
    await Promise.all(input.current().map(read)),
    retained,
    'Restart preserves original proof IDs and outcomes',
  );
}
async function retry(input: NotificationAsyncWorkerCaseInput, cancel: boolean) {
  assert.equal(input.current().length, 1);
  const source = input.current()[0]!;
  const worker = new NotificationAsyncWorker(
    options(source, input.cancellationSignerInstallationDigest),
  );
  const runtime = new NotificationDeliveryRuntime(
    options(source, input.cancellationSignerInstallationDigest),
  );
  const initial = input.gateway.stats();
  input.gateway.setOutcome('RETRYABLE_NO_EFFECT');
  try {
    await peers(source, (p) => worker.enqueue(p, source.source));
    passed(await peers(source, (p) => worker.runOnce(p, source.source)));
    const wait = await read(source);
    assert.equal(wait?.state, 'RETRY_WAIT');
    assert.ok(wait.original.outcome);
    const original = await peers(source, (p) => runtime.start(p, source.source));
    assert.equal(original.state, 'ORIGINAL');
    assert.equal(input.gateway.stats().calls, initial.calls + 1);
    let cause: string | undefined;
    if (cancel) cause = await input.governEndpointChange(source);
    await due(source);
    const claims = await source.withDeliveryPeer((socket) =>
      claimNotificationAsyncBatch(source.pool, source.kernel, socket, source.source),
    );
    assert.equal(claims.items.length, 1);
    const lease = claims.items[0]!.lease;
    assert.ok(lease);
    await assert.rejects(
      peers(source, (p) =>
        runtime.retryLeased(
          p,
          { ...lease, epoch: String(BigInt(lease.epoch) + 1n) },
          wait.original.outcome,
        ),
      ),
    );
    assert.equal(input.gateway.stats().calls, initial.calls + 1);
    if (cancel) {
      const revision = await source.withDeliveryPeer((socket) =>
        withNotificationDeliveryRequest(
          source.pool,
          source.kernel,
          socket,
          source.source,
          async (client) => {
            const row = await client.query<{ revision: string }>(
              'select revision::text from control.notification_delivery where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3',
              [
                source.source.worker.participantId,
                source.source.worker.privacyDomainId,
                source.source.notificationOccurrenceId,
              ],
            );
            assert.equal(row.rowCount, 1);
            return row.rows[0]!.revision;
          },
        ),
      );
      const result = await peers(source, (p) =>
        worker.cancelLeased(p, lease, {
          source: source.source,
          causeOperationId: cause,
          expectedRevision: revision,
        }),
      );
      assert.equal(result.receipt.disposition, 'PREVENT_LATER_ATTEMPTS');
      assert.equal(result.after.state, 'CANCELLED');
      assert.equal(input.gateway.stats().calls, initial.calls + 1);
    } else {
      input.gateway.setOutcome('DELIVERED');
      const result = await peers(source, (p) =>
        runtime.retryLeased(p, lease, wait.original.outcome),
      );
      assert.equal(result.state, 'PUBLISHED');
      assert.equal(input.gateway.stats().calls, initial.calls + 2);
    }
    const result = await source.withDeliveryPeer((socket) =>
      settleNotificationAsyncWork(source.pool, source.kernel, socket, source.source, lease),
    );
    assert.equal(result.state, cancel ? 'CANCELLED' : 'DONE');
    assert.equal(result.charged, false);
    await input.reopen();
    assert.deepEqual(await read(input.current()[0]!), result);
  } finally {
    await Promise.allSettled([worker.close(), runtime.close()]);
    input.gateway.setOutcome('DELIVERED');
  }
}
async function heartbeatFence(input: NotificationAsyncWorkerCaseInput) {
  assert.equal(input.current().length, 1);
  const source = input.current()[0]!;
  const worker = new NotificationAsyncWorker(
    options(source, input.cancellationSignerInstallationDigest),
  );
  const runtime = new NotificationDeliveryRuntime(
    options(source, input.cancellationSignerInstallationDigest),
  );
  try {
    await peers(source, (p) => worker.enqueue(p, source.source));
    const claimed = await source.withDeliveryPeer((socket) =>
      claimNotificationAsyncBatch(source.pool, source.kernel, socket, source.source),
    );
    assert.equal(claimed.items.length, 1);
    const original = claimed.items[0]!,
      lease = original.lease;
    assert.ok(lease);
    // The actual same-client source/lifecycle and effect transaction remains open
    // while a second real peer transaction renews the very same mounted epoch.
    // This is a database lock-progress check, not mocked provider acceptance.
    await source.withDeliveryPeer((socket) =>
      withNotificationDeliveryRequest(
        source.pool,
        source.kernel,
        socket,
        source.source,
        async (client) =>
          withNotificationWorkerLease(client, source.source, lease, 'PREPARE', async () => {
            await delay(2);
            const renewed = await source.withDeliveryPeer((other) =>
              heartbeatNotificationAsyncWork(
                source.pool,
                source.kernel,
                other,
                source.source,
                lease,
              ),
            );
            assert.deepEqual(renewed.lease, lease);
            assert.ok(renewed.leaseUntilMs! > original.leaseUntilMs!);
            assert.equal(renewed.deadlineAtMs, original.deadlineAtMs);
            await assert.rejects(
              source.withDeliveryPeer((other) =>
                heartbeatNotificationAsyncWork(source.pool, source.kernel, other, source.source, {
                  ...lease,
                  epoch: String(BigInt(lease.epoch) + 1n),
                }),
              ),
            );
          }),
      ),
    );
    input.gateway.setOutcome('DELIVERED');
    const result = await peers(source, (p) => runtime.startLeased(p, lease, source.source));
    assert.equal(result.state, 'PUBLISHED');
    const settled = await source.withDeliveryPeer((socket) =>
      settleNotificationAsyncWork(source.pool, source.kernel, socket, source.source, lease),
    );
    assert.equal(settled.state, 'DONE');
  } finally {
    await Promise.allSettled([worker.close(), runtime.close()]);
  }
}
/** Real committed claims and optional preparation, followed by process-owner
 * closure/reopen without a provider handoff. Nothing rewrites lease timestamps,
 * business rows, native admission or source inboxes to simulate recovery. */
async function preEffectCrash(
  input: NotificationAsyncWorkerCaseInput,
  mode: 'CLAIM' | 'PREPARATION' | 'SIGNING_CLAIM',
) {
  const prepared = mode !== 'CLAIM';
  assert.equal(input.current().length, 1);
  let source = input.current()[0]!;
  const worker = new NotificationAsyncWorker(
    options(source, input.cancellationSignerInstallationDigest),
  );
  const initial = input.gateway.stats();
  let originalPreparation: Awaited<ReturnType<typeof readNotificationDeliveryPreparation>> = null;
  let prior: Awaited<ReturnType<typeof readNotificationAsyncWork>>;
  try {
    await peers(source, (p) => worker.enqueue(p, source.source));
    const claimed = await source.withDeliveryPeer((socket) =>
      claimNotificationAsyncBatch(source.pool, source.kernel, socket, source.source),
    );
    assert.equal(claimed.items.length, 1);
    prior = claimed.items[0]!;
    assert.equal(prior.state, 'LEASED');
    assert.ok(prior.lease);
    assert.ok(prior.leaseUntilMs);
    if (prepared) {
      await source.withDeliveryPeer((socket) =>
        synchronizeNotificationDeliveryBudgetLeased(
          prior!.lease!,
          source.pool,
          source.kernel,
          socket,
          source.source,
        ),
      );
      originalPreparation = await source.withDeliveryPeer((socket) =>
        prepareNotificationDeliveryLeased(
          prior!.lease!,
          source.pool,
          source.kernel,
          socket,
          source.source,
        ),
      );
    }
    if (mode === 'SIGNING_CLAIM') {
      const gate = new NotificationPayloadReferenceGate(source.vaultDirectory);
      const selector = {
        source: source.source,
        operationId: originalPreparation!.operationId,
        signerInstallationDigest: source.startSignerInstallationDigest,
      };
      await source.withDeliveryPeer((socket) =>
        prepareNotificationDeliverySigningLeased(
          prior!.lease!,
          source.pool,
          source.kernel,
          socket,
          gate,
          selector,
        ),
      );
      const signed = await source.withDeliveryPeer((socket) =>
        claimNotificationDeliverySigningLeased(
          prior!.lease!,
          source.pool,
          source.kernel,
          socket,
          gate,
          selector,
        ),
      );
      assert.equal(signed.claimed, true);
      assert.equal(signed.record.state, 'DISPATCHED');
    } else
      await source.withDeliveryPeer((socket) =>
        withNotificationDeliveryRequest(
          source.pool,
          source.kernel,
          socket,
          source.source,
          async (client) => {
            const effects = await client.query<{ count: string }>(
              `select count(*)::text count from control.notification_delivery_signing
      where participant_id=$1 and privacy_domain_id=$2 and operation_id in
      (select operation_id from control.notification_delivery_preparation where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3)`,
              [
                source.source.worker.participantId,
                source.source.worker.privacyDomainId,
                source.source.notificationOccurrenceId,
              ],
            );
            assert.equal(
              effects.rows[0]!.count,
              '0',
              'The crash point precedes all signer requests',
            );
          },
        ),
      );
  } finally {
    await worker.close();
  }
  await input.reopen();
  source = input.current()[0]!;
  assert.deepEqual(await read(source), prior!);
  // Natural expiry of the actual current qualified lease, never an arbitrary
  // timeout used as proof of provider absence. Durable owners prove no handoff.
  const wait = prior!.leaseUntilMs! - Date.now();
  if (wait > 0) await delay(wait + 1);
  const reclaimed = await source.withDeliveryPeer((socket) =>
    claimNotificationAsyncBatch(source.pool, source.kernel, socket, source.source),
  );
  const runtime = new NotificationDeliveryRuntime(
    options(source, input.cancellationSignerInstallationDigest),
  );
  try {
    await assert.rejects(
      source.withDeliveryPeer((socket) =>
        heartbeatNotificationAsyncWork(
          source.pool,
          source.kernel,
          socket,
          source.source,
          prior!.lease!,
        ),
      ),
    );
    await assert.rejects(
      peers(source, (p) => runtime.resumePreEffectLeased(p, prior!.lease!, source.source)),
    );
    assert.equal(
      input.gateway.stats().calls,
      initial.calls,
      'A former lease cannot enter provider I/O',
    );
    if (mode === 'SIGNING_CLAIM') {
      assert.equal(reclaimed.items.length, 1);
      assert.equal(reclaimed.quarantined.length, 0);
      const next = reclaimed.items[0]!;
      assert.equal(next.state, 'RECONCILING');
      assert.ok(next.lease);
      assert.equal(next.charged, true);
      assert.equal(next.effectUncertain, true);
      assert.ok(next.original.start);
      await assert.rejects(
        peers(source, (p) => runtime.resumePreEffectLeased(p, next.lease!, source.source)),
      );
      // Lookup of the original may report ABSENT, but cannot grant a new send.
      const lookup = await peers(source, (p) =>
        runtime.recoverLeased(p, next.lease!, next.original),
      );
      assert.equal(lookup.state, 'ORIGINAL');
      const settled = await source.withDeliveryPeer((socket) =>
        settleNotificationAsyncWork(source.pool, source.kernel, socket, source.source, next.lease!),
      );
      assert.equal(settled.state, 'QUARANTINED');
      assert.equal(settled.charged, true);
      assert.equal(settled.effectUncertain, true);
      await source.withDeliveryPeer((socket) =>
        withNotificationDeliveryRequest(
          source.pool,
          source.kernel,
          socket,
          source.source,
          async (client) => {
            await client.query('savepoint unknown_is_not_initial_quarantine');
            let denied = false;
            try {
              await client.query(
                `update control.notification_async_work
              set reason='INITIAL_DOMAIN_DEADLINE',charged=false,effect_uncertain=false,
              revision=revision+1,transition_event_id=$4
              where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
                [
                  source.source.worker.participantId,
                  source.source.worker.privacyDomainId,
                  source.source.eventId,
                  localOperationId(),
                ],
              );
            } catch {
              denied = true;
            }
            await client.query('rollback to savepoint unknown_is_not_initial_quarantine');
            assert.equal(
              denied,
              true,
              'An ambiguous original cannot become initial no-effect bookkeeping',
            );
          },
        ),
      );
      assert.deepEqual(await read(source), settled);
      const record = await source.withDeliveryPeer((socket) =>
        withNotificationSigningHistory(
          source.pool,
          source.kernel,
          socket,
          next.original.start,
          readNotificationSigningRecord,
        ),
      );
      assert.ok(record);
      assert.equal(record.state, 'DISPATCHED');
      assert.deepEqual(record.preparation.deliveryPreparation, originalPreparation);
      assert.equal(input.gateway.stats().calls, initial.calls);
    } else if (reclaimed.quarantined.length) {
      assert.ok(prepared, 'An unprepared crash must resume under the live original domain');
      assert.equal(reclaimed.items.length, 0);
      assert.equal(reclaimed.quarantined.length, 1);
      const retained = reclaimed.quarantined[0]!;
      assert.equal(retained.state, 'QUARANTINED');
      assert.equal(retained.charged, false);
      assert.equal(retained.effectUncertain, false);
      assert.ok(
        Math.min(
          originalPreparation!.attempt.deadlineAtMs,
          originalPreparation!.authorityValidUntilMs,
          prior!.deadlineAtMs,
        ) <= Date.now(),
        'A stale original is quarantined without inventing a replacement attempt',
      );
      assert.deepEqual(
        await source.withDeliveryPeer((socket) =>
          readNotificationDeliveryPreparation(source.pool, source.kernel, socket, source.source),
        ),
        originalPreparation,
      );
    } else {
      assert.equal(reclaimed.items.length, 1);
      const next = reclaimed.items[0]!;
      assert.equal(next.state, 'LEASED');
      assert.ok(next.lease);
      assert.equal(next.lease.epoch, String(BigInt(prior!.lease!.epoch) + 1n));
      assert.equal(next.deadlineAtMs, prior!.deadlineAtMs);
      input.gateway.setOutcome('DELIVERED');
      const result = await peers(source, (p) =>
        runtime.resumePreEffectLeased(p, next.lease!, source.source),
      );
      assert.equal(result.state, 'PUBLISHED');
      const actual = await source.withDeliveryPeer((socket) =>
        readNotificationDeliveryPreparation(source.pool, source.kernel, socket, source.source),
      );
      assert.ok(actual);
      assert.equal(actual.attempt.attemptNumber, 1);
      if (originalPreparation) assert.deepEqual(actual, originalPreparation);
      const settled = await source.withDeliveryPeer((socket) =>
        settleNotificationAsyncWork(source.pool, source.kernel, socket, source.source, next.lease!),
      );
      assert.equal(settled.state, 'DONE');
      assert.equal(settled.charged, false);
      assert.equal(input.gateway.stats().calls, initial.calls + 1);
      assert.equal(input.gateway.stats().delivered, initial.delivered + 1);
    }
  } finally {
    await runtime.close();
  }
  const retained = await read(source);
  await input.reopen();
  assert.deepEqual(await read(input.current()[0]!), retained);
}
/** Read ORIGINAL rows through the installed proof owners in an authenticated
 * same-scope transaction. The live sibling supplies context after withdrawal;
 * historical proof verification must not renew the rejected source's authority. */
async function initialDispositionProof(
  context: NotificationProducerJourneyInput,
  rejected: NotificationProducerJourneyInput,
  proofEventId: string,
  exerciseDenials = false,
) {
  return context.withDeliveryPeer((socket) =>
    withNotificationDeliveryRequest(
      context.pool,
      context.kernel,
      socket,
      context.source,
      async (client) => {
        const keys = [
          rejected.source.worker.participantId,
          rejected.source.worker.privacyDomainId,
          rejected.source.eventId,
        ];
        await client.query('select openpc.check_notification_async_work_proof($1,1)', [keys[2]]);
        const result = await client.query<{
          transition: { before: unknown; after: Record<string, unknown> };
          transition_record: unknown;
          original_source: unknown;
          proof_event: { event_id: string; correlation_id: string; causation_id: string };
          operation_id: string;
          transitions: string;
          proofs: string;
        }>(
          `select t.transition,to_jsonb(t) transition_record,to_jsonb(o) original_source,
           to_jsonb(e) proof_event,t.operation_id::text,
           (select count(*)::text from control.notification_async_work_transition a
            where a.participant_id=t.participant_id and a.privacy_domain_id=t.privacy_domain_id and a.event_id=t.event_id) transitions,
           (select count(*)::text from control.outbox_event a
            where a.participant_id=t.participant_id and a.privacy_domain_id=t.privacy_domain_id and a.aggregate_id=t.event_id
            and a.sequence_namespace='NOTIFICATION_ASYNC_WORK_TRANSITION_V1') proofs
           from control.notification_async_work_transition t
           join control.outbox_event e on e.participant_id=t.participant_id and e.privacy_domain_id=t.privacy_domain_id and e.event_id=t.proof_event_id
           join control.outbox_event o on o.participant_id=t.participant_id and o.privacy_domain_id=t.privacy_domain_id and o.event_id=t.event_id
           where t.participant_id=$1 and t.privacy_domain_id=$2 and t.event_id=$3 and t.revision=1`,
          keys,
        );
        assert.equal(result.rowCount, 1);
        const original = result.rows[0]!;
        assert.equal(original.transitions, '1');
        assert.equal(original.proofs, '1');
        assert.equal(original.proof_event.event_id, proofEventId);
        assert.equal(original.proof_event.correlation_id, original.operation_id);
        assert.equal(original.proof_event.causation_id, rejected.source.eventId);
        assert.equal(original.transition.before, null);
        assert.equal(original.transition.after.state, 'QUARANTINED');
        if (exerciseDenials) {
          const { notificationAsyncInitialProofInvalidSql } = await import(
            new URL(
              '../../../services/control-api/src/notifications/async-worker-proof-guards.mjs',
              import.meta.url,
            ).href
          );
          // Exercise the production predicate, plus the existing canonical typed
          // after-row comparison, in actual PostgreSQL. These read-only values
          // are malformed probes, never inserted evidence or native authority.
          const checkShape = async (transition: unknown, invalid: boolean, label: string) => {
            await client.query('savepoint initial_shape_probe');
            let observed: boolean | undefined;
            try {
              const checked = await client.query<{ invalid: boolean }>(
                `select item.transition->'after' IS DISTINCT FROM to_jsonb(after_row)
                 OR (${notificationAsyncInitialProofInvalidSql}) invalid
                 from (select $1::jsonb transition) item
                 cross join lateral jsonb_populate_record(NULL::control.notification_async_work,item.transition->'after') after_row`,
                [JSON.stringify(transition)],
              );
              assert.equal(checked.rowCount, 1);
              observed = checked.rows[0]!.invalid;
            } catch (error) {
              // Wrong JSON types may fail at the PostgreSQL row decoder before
              // the condition. A missing owner/permission is never a test pass.
              assert.ok(
                invalid &&
                  ['22P02', '22023', '22003'].includes((error as { code?: string }).code ?? ''),
                `Unexpected SQL failure in ${label}`,
              );
              observed = true;
            } finally {
              await client.query('rollback to savepoint initial_shape_probe');
            }
            assert.equal(observed, invalid, label);
          };
          for (const [state, reason] of [
            ['PENDING', null],
            ['QUARANTINED', 'INITIAL_DOMAIN_DEADLINE'],
            ['QUARANTINED', 'INITIAL_SOURCE_WITHDRAWN'],
          ] as const) {
            const valid = structuredClone(original.transition);
            Object.assign(valid.after, { state, reason });
            await checkShape(valid, false, `${state}/${reason}: exact historical shape`);
            const fields = [
              'revision',
              'lease_epoch',
              'lease_owner',
              'lease_until_ms',
              'charged',
              'effect_uncertain',
              'original',
              'next_at_ms',
              'state',
              'reason',
            ];
            for (const field of fields) {
              const missing = structuredClone(valid);
              delete missing.after[field];
              await checkShape(missing, true, `${state}: missing ${field}`);
              for (const value of [null, 'false', {}, [], 2, true]) {
                if (value === null && valid.after[field] === null) continue;
                const malformed = structuredClone(valid);
                malformed.after[field] = value;
                await checkShape(malformed, true, `${state}: malformed ${field}`);
              }
            }
            for (const before of [undefined, {}, [], 'null', false, 0]) {
              const malformed = { ...valid, before };
              await checkShape(malformed, true, `${state}: malformed before`);
            }
            for (const after of [null, [], false, 'QUARANTINED'])
              await checkShape({ ...valid, after }, true, `${state}: malformed after`);
          }
          for (const assignment of [
            { state: 'PENDING', reason: 'INITIAL_DOMAIN_DEADLINE' },
            { state: 'QUARANTINED', reason: 'UNKNOWN' },
            { state: 'QUARANTINED', reason: null },
            { state: 'LEASED', reason: null },
            { state: 'QUARANTINED', lease_epoch: 1 },
            { state: 'QUARANTINED', charged: true, effect_uncertain: true },
            { state: 'QUARANTINED', original: { attemptNumber: 1 } },
          ]) {
            const malformed = structuredClone(original.transition);
            Object.assign(malformed.after, assignment);
            await checkShape(malformed, true, 'Invalid initial state/reason/effect tuple');
          }
          for (const statement of [
            `update control.notification_async_work_transition set transition=jsonb_set(transition,'{after,reason}','"UNKNOWN"'::jsonb)
             where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
            `update control.outbox_event set payload_digest=decode(repeat('00',32),'hex')
             where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
          ]) {
            await client.query('savepoint initial_proof_immutable');
            let denied = false;
            try {
              await client.query(
                statement,
                statement.includes('update control.outbox_event')
                  ? [keys[0], keys[1], proofEventId]
                  : keys,
              );
              await client.query('set constraints all immediate');
            } catch (error) {
              assert.ok(
                ['P0001', '42501'].includes((error as { code?: string }).code ?? ''),
                'Denial must come from the installed custody guard or runtime privilege boundary',
              );
              denied = true;
            } finally {
              await client.query('rollback to savepoint initial_proof_immutable');
            }
            assert.equal(denied, true, 'Runtime cannot replace original transition/outbox custody');
          }
          await client.query('select openpc.check_notification_async_work_proof($1,1)', [keys[2]]);
        }
        return original;
      },
    ),
  );
}
/** Requires two genuinely governed originals, oldest first, with isolated
 * consumer scope. EXPIRED case waits in the canonical producer setup for the
 * first original's real domain deadline before creating the second; no seeded
 * work, moved timestamp, fake clock, qualification or replacement identity. */
async function discoveryDisposition(input: NotificationAsyncWorkerCaseInput, expired: boolean) {
  const ceilings = notificationConsumerCeilings.parse(input.consumerCeilings);
  const sources = input.current();
  assert.equal(sources.length, expired ? 2 : 1);
  const first = sources[0]!;
  if (!expired) await input.governEndpointChange(first);
  if (!expired)
    assert.ok(input.produceAfterEndpointChange, 'Requires real post-change producer journey');
  const second = expired ? sources[1]! : await input.produceAfterEndpointChange!();
  assert.deepEqual(first.source.worker, second.source.worker);
  assert.notEqual(first.source.eventId, second.source.eventId);
  assert.equal(await read(first), null);
  assert.equal(await read(second), null);
  const discover = (source: NotificationProducerJourneyInput) =>
    source.withDeliveryPeer((socket) =>
      discoverNotificationDeliverySources(
        source.pool,
        source.kernel,
        socket,
        source.source.worker,
        ceilings,
      ),
    );
  const initial = input.gateway.stats();
  const selected = await discover(first);
  assert.equal(
    selected.sources.length,
    expired ? 1 : 2,
    'Real native batchSize must be 1 for expired-head case, 2 for independent-sibling case',
  );
  assert.deepEqual(selected.sources[0], first.source);
  const admissions = [];
  for (const source of selected.sources) {
    admissions.push(
      await first.withDeliveryPeer((socket) =>
        enqueueNotificationAsyncWork(first.pool, first.kernel, socket, source),
      ),
    );
  }
  const retained = admissions[0]!;
  assert.equal(retained.state, 'QUARANTINED');
  assert.equal(retained.reason, expired ? 'INITIAL_DOMAIN_DEADLINE' : 'INITIAL_SOURCE_WITHDRAWN');
  assert.equal(retained.revision, '1');
  assert.equal(retained.charged, false);
  assert.equal(retained.effectUncertain, false);
  assert.equal(retained.lease, null);
  assert.equal(retained.nextAtMs, null);
  assert.deepEqual(retained.original, { source: first.source });
  if (expired) assert.ok(retained.deadlineAtMs <= Date.now());
  assert.deepEqual(input.gateway.stats(), initial, 'Disposition never contacts a gateway');
  const originalProof = await initialDispositionProof(second, first, retained.proofEventId);
  await input.reopen();
  const reopened = input.current();
  assert.deepEqual(
    await read(reopened[0]!),
    retained,
    'Actual pool/transport restart retains original deadline, reason and protected proof',
  );
  assert.deepEqual(
    await initialDispositionProof(reopened[1]!, reopened[0]!, retained.proofEventId),
    originalProof,
    'Restart preserves original source, transition bytes/digest, proof event and cardinality',
  );
  const next = await discover(reopened[1]!);
  assert.ok(next.sources.some((source) => source.eventId === second.source.eventId));
  assert.ok(next.sources.every((source) => source.eventId !== first.source.eventId));
  if (expired) assert.equal(next.sources.length, 1);
  const fresh = reopened[1]!;
  const worker = new NotificationAsyncWorker(
    options(fresh, input.cancellationSignerInstallationDigest),
  );
  input.gateway.setOutcome('DELIVERED');
  try {
    const pending = await fresh.withDeliveryPeer((socket) =>
      enqueueNotificationAsyncWork(fresh.pool, fresh.kernel, socket, fresh.source),
    );
    assert.equal(
      pending.state,
      'PENDING',
      'Terminal initial quarantine consumes no active queue capacity',
    );
    await fresh.withDeliveryPeer((socket) =>
      withNotificationDeliveryRequest(
        fresh.pool,
        fresh.kernel,
        socket,
        fresh.source,
        async (client) => {
          for (const assignment of [
            "state='PENDING',reason=null,revision=revision+1",
            "state='LEASED',lease_epoch=1,lease_owner='forged',lease_until_ms=deadline_at_ms,charged=true,effect_uncertain=true,revision=revision+1",
            "reason='INITIAL_DOMAIN_DEADLINE',revision=revision+1",
          ]) {
            await client.query('savepoint quarantine_no_revival');
            let denied = false;
            try {
              await client.query(
                `update control.notification_async_work set ${assignment},transition_event_id=$4
              where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
                [
                  first.source.worker.participantId,
                  first.source.worker.privacyDomainId,
                  first.source.eventId,
                  localOperationId(),
                ],
              );
            } catch {
              denied = true;
            }
            await client.query('rollback to savepoint quarantine_no_revival');
            assert.equal(denied, true, 'Runtime cannot revive or rewrite initial terminal custody');
          }
        },
      ),
    );
    await assert.rejects(
      fresh.withDeliveryPeer((socket) =>
        readNotificationAsyncWork(fresh.pool, fresh.kernel, socket, input.foreign().source),
      ),
    );
    passed(await peers(fresh, (p) => worker.runOnce(p, fresh.source)));
  } finally {
    await worker.close();
  }
  assert.equal(input.gateway.stats().calls, initial.calls + 1);
  assert.equal(input.gateway.stats().delivered, initial.delivered + 1);
  assert.equal((await read(fresh))?.state, 'DONE');
  assert.deepEqual(
    await read(reopened[0]!),
    retained,
    'Independent delivery cannot revive rejected original',
  );
  await input.reopen();
  assert.deepEqual(await read(input.current()[0]!), retained);
  assert.equal((await read(input.current()[1]!))?.state, 'DONE');
  assert.deepEqual(
    await initialDispositionProof(
      input.current()[1]!,
      input.current()[0]!,
      retained.proofEventId,
      true,
    ),
    originalProof,
    'Denials and independent delivery preserve the exact original proof across restart',
  );
}

export async function exerciseNotificationAsyncWorkerCase(
  kind: NotificationAsyncWorkerCase,
  input: NotificationAsyncWorkerCaseInput,
): Promise<void> {
  switch (kind) {
    case 'EXPIRED_SOURCE_DISCOVERY':
      return discoveryDisposition(input, true);
    case 'WITHDRAWN_SOURCE_DISCOVERY':
      return discoveryDisposition(input, false);
    case 'CLAIM_CRASH':
      return preEffectCrash(input, 'CLAIM');
    case 'PREPARATION_CRASH':
      return preEffectCrash(input, 'PREPARATION');
    case 'SIGNING_CLAIM_CRASH':
      return preEffectCrash(input, 'SIGNING_CLAIM');
    case 'BATCH_PROOF_CUSTODY':
      return batchProof(input);
    case 'EXPLICIT_RETRY':
      return retry(input, false);
    case 'RETRY_WAIT_CANCELLATION':
      return retry(input, true);
    case 'HEARTBEAT_FENCE':
      return heartbeatFence(input);
    default:
      throw new Error(`Unknown notification async case: ${String(kind)}`);
  }
}
