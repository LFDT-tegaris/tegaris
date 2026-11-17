import { expect } from 'vitest';
import type { PoolClient } from 'pg';
import type { NotificationDeliveryBudgetRecord } from '../../../services/control-api/src/notifications/delivery-start-state.js';
import type {
  NotificationDeliverySourceSelector,
  PublishedNotificationDeliveryRequest,
} from '../../../services/control-api/src/notifications/delivery-source.js';
import type { NotificationDeliveryConfiguration } from '../../../services/control-api/src/notifications/delivery-admission.js';

/** Existing PG/TLS family supplies real HTTP calls to
 * synchronizeNotificationDeliveryBudget using the actual request socket. Source
 * publication, endpoint verification and worker/credential trust use their real
 * owners. No test-created worker admission, effective generation or signed
 * intermediate delivery state is accepted as connected journey evidence. */
export interface NotificationDeliveryBudgetCasesInput {
  source: NotificationDeliverySourceSelector;
  call(value: unknown): Promise<NotificationDeliveryBudgetRecord>;
  /** Restart the real service, preserving the same database and original input. */
  restart(): Promise<void>;
  /** Existing scoped runtime-role inspection, no owner/bypass-RLS connection. */
  inspect<T>(run: (client: PoolClient) => Promise<T>): Promise<T>;
  /** Existing withNotificationDeliveryRequest composition. This is source-only
   * admission so missing current generation can be classified independently. */
  withSource<T>(
    run: (client: PoolClient, source: PublishedNotificationDeliveryRequest) => Promise<T>,
  ): Promise<T>;
}

async function effects(client: PoolClient, source: NotificationDeliverySourceSelector) {
  const scope = [source.worker.participantId, source.worker.privacyDomainId];
  const result: Record<string, unknown> = {};
  for (const table of [
    'notification_delivery',
    'notification_delivery_attempt',
    'notification_delivery_start',
    'outbox_event',
    'notification_occurrence',
  ]) {
    const exists = await client.query('select to_regclass($1)::text relation', [
      `control.${table}`,
    ]);
    if (!exists.rows[0]?.relation) {
      result[table] = null;
      continue;
    }
    // Table identifiers are fixed above, never input-derived.
    const rows = await client.query(
      `select to_jsonb(t) row from control.${table} t where participant_id=$1 and privacy_domain_id=$2 order by to_jsonb(t)::text`,
      scope,
    );
    result[table] = rows.rows;
  }
  return result;
}

/** Runnable even while real positive generation admission is closed. The first
 * failing prerequisite is classified directly; no source/schema failure can
 * masquerade as an expected configuration denial. */
export async function assertNotificationDeliveryBudgetMissingGeneration(
  input: NotificationDeliveryBudgetCasesInput,
) {
  await input.withSource(async (client, source) => {
    expect(source.claims.notificationOccurrenceId).toBe(input.source.notificationOccurrenceId);
    expect(source.claims.eventId).toBe(input.source.eventId);
    await client.query('savepoint notification_budget_unready');
    try {
      await expect(
        client.query('select * from openpc.current_notification_delivery_limit($1)', [
          source.claims.environmentId,
        ]),
      ).rejects.toThrow('OPS_CONFIG_UNREADY');
    } finally {
      await client.query('rollback to savepoint notification_budget_unready');
    }
  });
  const before = await input.inspect((client) => effects(client, input.source));
  await expect(input.call(input.source)).rejects.toThrow(
    'Notification delivery budget unavailable',
  );
  expect(await input.inspect((client) => effects(client, input.source))).toEqual(before);
}

/** Positive connected corpus. Do not call until the canonical generation owner
 * can create/activate these configurations through real supported admission.
 * setConfiguration is a harness orchestration callback to that owner, never SQL
 * seeding, a replacement current-limit function or a parameter to the budget API.
 * This helper does not itself establish registration or execution in CI. */
export async function assertNotificationDeliveryBudgetCases(
  input: NotificationDeliveryBudgetCasesInput & {
    setConfiguration(limit: number): Promise<void>;
    currentConfiguration(): Promise<NotificationDeliveryConfiguration>;
    /** A distinct genuinely published occurrence, created through existing owners. */
    zeroSource: NotificationDeliverySourceSelector;
  },
) {
  await input.setConfiguration(6);
  const configured = await input.currentConfiguration();
  expect(configured.configured_limit).toBe(6);
  const originalEffects = await input.inspect((client) => effects(client, input.source));
  const concurrent = await Promise.allSettled([input.call(input.source), input.call(input.source)]);
  const successes = concurrent.filter(
    (r): r is PromiseFulfilledResult<NotificationDeliveryBudgetRecord> => r.status === 'fulfilled',
  );
  expect(successes.length).toBeGreaterThan(0);
  for (const result of concurrent)
    if (result.status === 'rejected')
      expect(String(result.reason)).toContain('Notification delivery budget unavailable');
  const first = successes[0]!.value;
  expect(first).toMatchObject({
    state: 'PENDING',
    attemptCount: 0,
    attemptLimit: 6,
    revision: '1',
    cancelRequested: false,
    lastStartedAtMs: null,
    budgetGenerationId: configured.generation_id,
    budgetEffectiveDigest: configured.effective_digest,
    budgetConfiguredLimit: 6,
  });
  expect(first.nextAttemptAtMs).toBeGreaterThan(0);
  for (const result of successes) expect(result.value).toEqual(first);
  expect(await input.call(input.source)).toEqual(first);
  await input.restart();
  expect(await input.call(input.source)).toEqual(first);
  await input.setConfiguration(2);
  const lowered = await input.call(input.source);
  const lowerGeneration = await input.currentConfiguration();
  expect(lowered).toEqual({
    ...first,
    attemptLimit: 2,
    revision: '2',
    budgetConfiguredLimit: 2,
    budgetGenerationId: lowerGeneration.generation_id,
    budgetEffectiveDigest: lowerGeneration.effective_digest,
  });
  await input.setConfiguration(100);
  expect(await input.call(input.source)).toEqual(lowered);
  await input.setConfiguration(0);
  expect(input.zeroSource.notificationOccurrenceId).not.toBe(input.source.notificationOccurrenceId);
  const initiallyZero = await input.call(input.zeroSource);
  expect(initiallyZero).toMatchObject({
    state: 'PENDING',
    attemptCount: 0,
    attemptLimit: 0,
    revision: '1',
    cancelRequested: false,
    lastStartedAtMs: null,
  });
  expect(initiallyZero.nextAttemptAtMs).toBeGreaterThan(0);
  const zero = await input.call(input.source);
  expect(zero).toMatchObject({
    state: 'PENDING',
    attemptCount: 0,
    attemptLimit: 0,
    revision: '3',
    cancelRequested: false,
    nextAttemptAtMs: first.nextAttemptAtMs,
    lastStartedAtMs: null,
  });
  await input.setConfiguration(6);
  await input.restart();
  expect(await input.call(input.source)).toEqual(zero);
  for (const patch of [
    { configuredLimit: 6 },
    { generationId: configured.generation_id },
    { ready: true },
    { state: 'STARTED' },
    { eventId: first.deliveryRequestOperationId },
  ]) {
    await expect(input.call({ ...input.source, ...patch })).rejects.toThrow(
      'Notification delivery budget unavailable',
    );
    expect(await input.call(input.source)).toEqual(zero);
  }
  const after = await input.inspect((client) => effects(client, input.source));
  for (const table of [
    'notification_delivery_attempt',
    'notification_delivery_start',
    'outbox_event',
    'notification_occurrence',
  ])
    expect(after[table]).toEqual(originalEffects[table]);
}

/** Real SQL fail-closed corpus after a genuine budget row exists. The caller
 * retains actual source/current worker/channel/configuration fences; direct SQL
 * attempts must fail at the substantive budget guard, not an earlier denial.
 * Unsupported STARTED/cancel state is never seeded to exercise later code. */
export async function assertNotificationDeliveryBudgetSqlDenials(
  client: PoolClient,
  original: NotificationDeliveryBudgetRecord,
) {
  await client.query('select openpc.assert_notification_delivery_budget_owner()');
  const current = await client.query(
    'select * from openpc.current_notification_delivery_limit($1)',
    [original.budgetEnvironmentId],
  );
  expect(current.rows).toEqual([
    {
      generation_id: original.budgetGenerationId,
      effective_digest: original.budgetEffectiveDigest,
      configured_limit: original.budgetConfiguredLimit,
    },
  ]);
  const key = [original.participantId, original.privacyDomainId, original.notificationOccurrenceId];
  const before = (
    await client.query(
      'select to_jsonb(t) row from control.notification_delivery t where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3',
      key,
    )
  ).rows;
  expect(before).toHaveLength(1);
  for (const change of [
    "state='STARTED',attempt_count=1,last_started_at_ms=next_attempt_at_ms,next_attempt_at_ms=null",
    "state='FAILED',next_attempt_at_ms=null",
    "state='CANCELLED',next_attempt_at_ms=null,cancel_requested=true",
    'cancel_requested=not cancel_requested',
    'attempt_limit=6',
    'revision=revision+1',
    'next_attempt_at_ms=next_attempt_at_ms+1',
    "budget_effective_digest='sha256:'||repeat('0',64)",
    'delivery_request_event_id=delivery_request_operation_id',
  ]) {
    await client.query('savepoint notification_budget_sql_denial');
    try {
      await expect(
        client.query(
          `update control.notification_delivery set ${change} where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3`,
          key,
        ),
      ).rejects.toThrow(/NOTIFICATION-DELIVERY-BUDGET-(ONLY|CONFIGURATION|SOURCE)/u);
    } finally {
      await client.query('rollback to savepoint notification_budget_sql_denial');
    }
  }
  expect(
    (
      await client.query(
        'select to_jsonb(t) row from control.notification_delivery t where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3',
        key,
      )
    ).rows,
  ).toEqual(before);
}
