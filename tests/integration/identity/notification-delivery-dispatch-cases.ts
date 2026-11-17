import type { Pool, PoolClient } from 'pg';
import { prepareNotificationDelivery } from '../../../services/control-api/src/notifications/delivery-start-preparation.js';
import {
  prepareNotificationDeliverySigning,
  withNotificationSigningHistory,
} from '../../../services/control-api/src/notifications/delivery-signing-state.js';
import { NotificationDeliverySigningRuntime } from '../../../services/control-api/src/notifications/delivery-signing-runtime.js';
import {
  publishNotificationDeliveryStart,
  readNotificationDeliveryStart,
} from '../../../services/control-api/src/notifications/delivery-start-atomic.js';
import {
  claimNotificationDeliveryDispatch,
  readNotificationDeliveryDispatch,
  consumeNotificationDispatchCapability,
  type NotificationDeliveryDispatchRecord,
  type NotificationDispatchCapability,
} from '../../../services/control-api/src/notifications/delivery-dispatch-state.js';
import type { NotificationDeliverySigningSelector } from '../../../services/control-api/src/notifications/delivery-signing-contract.js';
import type { NotificationSigningJourneyFixture } from './notification-delivery-signing-cases.js';

/** Real installed source/current complete generation, Identity TLS, custody,
 * signing and STARTED owners only. These exported cases do not seed success.
 * Canonical registers/runs them when the genuine prerequisites are available.
 * Cancellation currently lacks its supported mutation owner: do not fake it. */
export interface NotificationDispatchJourneyFixture extends NotificationSigningJourneyFixture {
  /** Native KMS STATUS owner; never insert a success receipt. */
  refreshKmsStatus(): Promise<void>;
  /** Restart the actual worker and invoke its original-only readback. */
  restartAndRead(
    selector: NotificationDeliverySigningSelector,
  ): Promise<NotificationDeliveryDispatchRecord>;
}
async function started(f: NotificationDispatchJourneyFixture) {
  const { expect } = await import('vitest');
  // The shared driver marks known unavailable source/generation prerequisites
  // BLOCKED before dispatching this case. Once dispatched, preserve every real
  // owner failure rather than relabeling arbitrary product defects as BLOCKED.
  const p = await f.withPeer((socket) =>
    prepareNotificationDelivery(f.pool, f.kernel, socket, f.source),
  );
  const q = {
    source: p.source,
    operationId: p.operationId,
    signerInstallationDigest: f.signerInstallationDigest,
  };
  await f.withPeer((socket) =>
    prepareNotificationDeliverySigning(f.pool, f.kernel, socket, f.gate, q),
  );
  const runtime = new NotificationDeliverySigningRuntime(f.pool, f.kernel, f.gate, f.transport);
  expect((await f.withPeer((socket) => runtime.dispatchOnce(socket, q))).state).toBe('OBSERVED');
  await f.refreshKmsStatus();
  const original = await f.withPeer((socket) =>
    publishNotificationDeliveryStart(f.pool, f.kernel, socket, f.gate, q),
  );
  expect(original.after.state).toBe('STARTED');
  await f.refreshKmsStatus();
  return { q, original };
}
const claim = (
  f: NotificationDispatchJourneyFixture,
  q: NotificationDeliverySigningSelector,
  pool = f.pool,
) => f.withPeer((socket) => claimNotificationDeliveryDispatch(pool, f.kernel, socket, f.gate, q));
const read = (f: NotificationDispatchJourneyFixture, q: NotificationDeliverySigningSelector) =>
  f.withPeer((socket) => readNotificationDeliveryDispatch(f.pool, f.kernel, socket, q));
async function unchangedProjection(
  f: NotificationDispatchJourneyFixture,
  q: NotificationDeliverySigningSelector,
  original: NotificationDeliveryDispatchRecord['original'],
) {
  const { expect } = await import('vitest');
  await f.withPeer((socket) =>
    withNotificationSigningHistory(f.pool, f.kernel, socket, q, async (client) => {
      const row = await client.query(
        `select state,attempt_count,last_started_at_ms::text,revision::text,cancel_requested from control.notification_delivery where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3`,
        [
          q.source.worker.participantId,
          q.source.worker.privacyDomainId,
          q.source.notificationOccurrenceId,
        ],
      );
      expect(row.rows[0]).toEqual({
        state: 'STARTED',
        attempt_count: original.attempt.attemptNumber,
        last_started_at_ms: String(original.attempt.startedAtMs),
        revision: (BigInt(original.receipt.deliveryRevision) + 1n).toString(),
        cancel_requested: false,
      });
    }),
  );
}
export async function assertNotificationDispatchClaimJourney(
  f: NotificationDispatchJourneyFixture,
) {
  const { expect } = await import('vitest'),
    before = f.counters(),
    { q, original } = await started(f);
  const results = await Promise.all([claim(f, q), claim(f, q)]);
  expect(results.filter((r) => r.state === 'CLAIMED')).toHaveLength(1);
  expect(results.filter((r) => r.state === 'LOOKUP')).toHaveLength(1);
  const winner = results.find((r) => r.state === 'CLAIMED');
  if (!winner || winner.state !== 'CLAIMED') throw new Error('Missing sole committed claim');
  const saved = await read(f, q);
  expect(saved.original).toEqual(original);
  expect(saved.claim.state).toBe('CLAIMED');
  expect(consumeNotificationDispatchCapability(winner.capability, q)).toEqual(saved);
  expect(() => consumeNotificationDispatchCapability(winner.capability, q)).toThrow();
  expect(() =>
    consumeNotificationDispatchCapability(
      { ...winner.capability } as NotificationDispatchCapability,
      q,
    ),
  ).toThrow();
  expect(await claim(f, q)).toEqual({ state: 'LOOKUP', record: saved });
  expect(
    await f.withPeer((socket) => readNotificationDeliveryStart(f.pool, f.kernel, socket, q)),
  ).toEqual(original);
  await unchangedProjection(f, q, original);
  const restarted = await f.restartAndRead(q);
  expect(restarted).toEqual(saved);
  expect(() =>
    consumeNotificationDispatchCapability(
      restarted as unknown as NotificationDispatchCapability,
      q,
    ),
  ).toThrow();
  expect(f.counters().gatewayCalls).toBe(before.gatewayCalls);
}
/** Ordinary real scoped SQL must not bypass the feature's current custody fences.
 * Each rejection has its own rollback; no disabled guards, seeded claim or repair. */
export async function assertNotificationDispatchGenericDmlDenied(
  f: NotificationDispatchJourneyFixture,
) {
  const { expect } = await import('vitest'),
    { q } = await started(f),
    before = await read(f, q);
  await expect(
    f.withPeer((socket) =>
      withNotificationSigningHistory(f.pool, f.kernel, socket, q, async (client) => {
        await client.query(
          `update control.notification_delivery_dispatch_intent set state='CLAIMED',claim_token=$4,claimed_at_ms=floor(extract(epoch from clock_timestamp())*1000) where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
          [
            q.source.worker.participantId,
            q.source.worker.privacyDomainId,
            q.operationId,
            'ab'.repeat(32),
          ],
        );
      }),
    ),
  ).rejects.toThrow();
  expect(await read(f, q)).toEqual(before);
}
export async function assertNotificationDispatchClaimImmutable(
  f: NotificationDispatchJourneyFixture,
) {
  const { expect } = await import('vitest'),
    { q } = await started(f);
  expect((await claim(f, q)).state).toBe('CLAIMED');
  const before = await read(f, q);
  for (const assignment of [
    "state='PENDING',claim_token=null,claimed_at_ms=null",
    "claim_token=repeat('cd',32)",
    'claimed_at_ms=claimed_at_ms+1',
    'delivery_revision=delivery_revision+1',
    'attempt_id=operation_id',
    'operation_id=attempt_id',
  ]) {
    await expect(
      f.withPeer((socket) =>
        withNotificationSigningHistory(f.pool, f.kernel, socket, q, async (client) => {
          await client.query(
            `update control.notification_delivery_dispatch_intent set ${assignment} where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
            [q.source.worker.participantId, q.source.worker.privacyDomainId, q.operationId],
          );
        }),
      ),
    ).rejects.toThrow();
    expect(await read(f, q)).toEqual(before);
  }
}
export async function assertNotificationDispatchZeroCapacity(
  f: NotificationDispatchJourneyFixture,
) {
  const { expect } = await import('vitest'),
    { q, original } = await started(f),
    before = f.counters();
  await f.invalidate('ZERO_CAP');
  expect(await claim(f, q)).toEqual({
    state: 'WAIT',
    reason: 'ZERO_CAPACITY',
    record: { original, claim: { state: 'PENDING', claimToken: null, claimedAtMs: null } },
  });
  await unchangedProjection(f, q, original);
  expect(f.counters()).toEqual(before);
}
/** Fault injection drops only the ACK of a real COMMIT containing the claim.
 * All authentication, SQL effects, guards and readback still use real PostgreSQL. */
function loseClaimCommit(pool: Pool) {
  let dropped = false;
  const proxy = new Proxy(pool, {
    get(target, property) {
      if (property !== 'connect') {
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      }
      return async () => {
        const client = await target.connect();
        let claimed = false;
        return new Proxy(client, {
          get(actual, key) {
            if (key !== 'query') {
              const value = Reflect.get(actual, key, actual);
              return typeof value === 'function' ? value.bind(actual) : value;
            }
            return async (...args: unknown[]) => {
              const first = args[0],
                text =
                  typeof first === 'string' ? first : ((first as { text?: string })?.text ?? '');
              const result = await Reflect.apply(actual.query, actual, args);
              if (
                /^update control\.notification_delivery_dispatch_intent set state='CLAIMED'/u.test(
                  text,
                )
              )
                claimed = true;
              if (/^commit$/iu.test(text.trim()) && claimed && !dropped) {
                dropped = true;
                throw new Error('Injected lost claim COMMIT acknowledgement');
              }
              return result;
            };
          },
        }) as PoolClient;
      };
    },
  });
  return { pool: proxy, dropped: () => dropped };
}
export async function assertNotificationDispatchCommitUncertainty(
  f: NotificationDispatchJourneyFixture,
) {
  const { expect } = await import('vitest'),
    { q, original } = await started(f),
    fault = loseClaimCommit(f.pool),
    before = f.counters();
  const result = await claim(f, q, fault.pool);
  expect(fault.dropped()).toBe(true);
  expect(result.state).toBe('LOOKUP');
  expect('capability' in result).toBe(false);
  expect(result.record.original).toEqual(original);
  expect(result.record.claim.state).toBe('CLAIMED');
  expect(await claim(f, q)).toEqual(result);
  expect(await f.restartAndRead(q)).toEqual(result.record);
  await unchangedProjection(f, q, original);
  expect(f.counters()).toEqual(before);
}
/** Actual supported withdrawal/expiry/config owner supplied by the journey.
 * CANCEL is deliberately excluded until its real mutation owner is connected. */
export async function assertNotificationDispatchInvalidation(
  f: NotificationDispatchJourneyFixture,
  kind: 'EXPIRE' | 'DECREASED_CAP' | 'STATE_CHANGE',
) {
  const { expect } = await import('vitest'),
    { q } = await started(f),
    before = f.counters();
  await f.invalidate(kind);
  await expect(claim(f, q)).rejects.toThrow();
  expect((await read(f, q)).claim.state).toBe('PENDING');
  expect(f.counters()).toEqual(before);
}
