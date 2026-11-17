import { expect } from 'vitest';
import type { PoolClient } from 'pg';
import {
  assertNotificationDeliveryWorkerAdmission,
  notificationDeliveryWorkerContextIdentity,
  type NotificationWorkerAdmission,
} from '../../../services/identity-service/src/domain/notification-worker.js';
import type { NotificationWorkerSelector } from '../../../services/control-api/src/notifications/worker-installation.js';
import type { NotificationDeliveryPreparation } from '../../../services/control-api/src/notifications/delivery-start-preparation.js';
import type {
  NotificationDeliverySourceSelector,
  PublishedNotificationDeliveryRequest,
} from '../../../services/control-api/src/notifications/delivery-source.js';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';

/** The existing genuine TLS/PG fixture supplies calls using request.raw.socket,
 * public generation/endpoint owners and authenticated source publication. No
 * mock admission, source DTO or SQL-seeded business transition completes a case. */
export interface NotificationDeliveryPreparationCasesInput {
  source: NotificationDeliverySourceSelector;
  prepare(value: unknown): Promise<NotificationDeliveryPreparation>;
  read(value: unknown): Promise<NotificationDeliveryPreparation | null>;
  inspect<T>(operation: (client: PoolClient) => Promise<T>): Promise<T>;
  withSource<T>(
    operation: (client: PoolClient, source: PublishedNotificationDeliveryRequest) => Promise<T>,
  ): Promise<T>;
  providerCalls(): Promise<number>;
}
const failure = 'Notification delivery preparation unavailable';
async function snapshot(input: NotificationDeliveryPreparationCasesInput) {
  return input.inspect(async (client) => {
    const result: Record<string, unknown> = {};
    for (const table of [
      'notification_delivery',
      'notification_delivery_preparation',
      'notification_delivery_attempt',
      'notification_delivery_start',
      'notification_occurrence',
      'outbox_event',
    ]) {
      const exists = await client.query('select to_regclass($1)::text relation', [
        `control.${table}`,
      ]);
      if (!exists.rows[0]?.relation) {
        result[table] = null;
        continue;
      }
      result[table] = (
        await client.query(
          `select to_jsonb(t) row from control.${table} t where participant_id=$1 and privacy_domain_id=$2 order by to_jsonb(t)::text`,
          [input.source.worker.participantId, input.source.worker.privacyDomainId],
        )
      ).rows;
    }
    return result;
  });
}
export async function assertNotificationDeliveryPreparationMissingGeneration(
  input: NotificationDeliveryPreparationCasesInput,
) {
  await input.withSource(async (client, source) => {
    expect(source.claims.eventId).toBe(input.source.eventId);
    expect(source.claims.notificationOccurrenceId).toBe(input.source.notificationOccurrenceId);
    await client.query('savepoint notification_preparation_unready');
    try {
      await expect(
        client.query('select * from openpc.current_notification_delivery_limit($1)', [
          source.claims.environmentId,
        ]),
      ).rejects.toThrow('OPS_CONFIG_UNREADY');
    } finally {
      await client.query('rollback to savepoint notification_preparation_unready');
    }
  });
  const before = await snapshot(input),
    calls = await input.providerCalls();
  await expect(input.prepare(input.source)).rejects.toThrow(failure);
  expect(await snapshot(input)).toEqual(before);
  expect(await input.providerCalls()).toBe(calls);
}

/** Prerequisites must have passed through real owners, including budget creation.
 * Lost reply deliberately discards only the HTTP result, never rolls back/replays
 * an effect. The next request must observe the exact original reservation. */
export async function assertNotificationDeliveryPreparationCases(
  input: NotificationDeliveryPreparationCasesInput & {
    restart(): Promise<void>;
    prepareAndLoseReply(value: unknown): Promise<void>;
    /** A separate published, configured and budget-admitted business intent. */
    replyLossSource: NotificationDeliverySourceSelector;
    /** Real owner makes the original generation stale, preserving the reservation. */
    changeGeneration(): Promise<void>;
  },
) {
  const before = await snapshot(input),
    calls = await input.providerCalls();
  expect(await input.read(input.source)).toBeNull();
  const concurrent = await Promise.allSettled([
    input.prepare(input.source),
    input.prepare(input.source),
  ]);
  const success = concurrent.filter(
    (r): r is PromiseFulfilledResult<NotificationDeliveryPreparation> => r.status === 'fulfilled',
  );
  expect(success.length).toBeGreaterThan(0);
  for (const r of concurrent)
    if (r.status === 'rejected') expect(String(r.reason)).toContain(failure);
  const original = success[0]!.value;
  for (const r of success) expect(r.value).toEqual(original);
  expect(original.before.state).toBe('PENDING');
  expect(original.before.attemptCount).toBe(0);
  expect(original.plannedAfter.state).toBe('STARTED');
  expect(original.plannedAfter.attemptCount).toBe(1);
  expect(original.context.auditCorrelationId).toBe(original.operationId);
  expect(original.operationId).not.toBe(original.sourceOperationId);
  expect(original.context.occurrenceId).toBe(input.source.notificationOccurrenceId);
  expect(original.attempt.notificationOccurrenceId).toBe(
    `urn:openpc:resource:${input.source.notificationOccurrenceId}`,
  );
  expect(original.attempt.deadlineAtMs).toBeGreaterThan(original.attempt.startedAtMs);
  const bytes = canonicalJson(original);
  expect(canonicalJson(await input.prepare(input.source))).toBe(bytes);
  await input.restart();
  expect(canonicalJson(await input.read(input.source))).toBe(bytes);
  expect(canonicalJson(await input.prepare(input.source))).toBe(bytes);
  const after = await snapshot(input);
  for (const table of [
    'notification_delivery',
    'notification_delivery_attempt',
    'notification_delivery_start',
    'notification_occurrence',
    'outbox_event',
  ])
    expect(after[table]).toEqual(before[table]);
  expect(await input.providerCalls()).toBe(calls);
  await input.inspect(async (client) => {
    const rows = await client.query(
      'select preparation_bytes,preparation_digest from control.notification_delivery_preparation where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3',
      [
        input.source.worker.participantId,
        input.source.worker.privacyDomainId,
        input.source.notificationOccurrenceId,
      ],
    );
    expect(rows.rowCount).toBe(1);
    expect(rows.rows[0].preparation_bytes.toString('utf8')).toBe(bytes);
    expect(rows.rows[0].preparation_digest).toBe(sha256(Buffer.from(bytes)));
  });
  for (const patch of [
    { ready: true },
    { configuredLimit: 6 },
    { operationId: original.operationId },
    { attempt: original.attempt },
    { context: original.context },
    { deadlineAtMs: original.attempt.deadlineAtMs + 1 },
  ])
    await expect(input.prepare({ ...input.source, ...patch })).rejects.toThrow(failure);
  expect(input.replyLossSource.notificationOccurrenceId).not.toBe(
    input.source.notificationOccurrenceId,
  );
  await input.prepareAndLoseReply(input.replyLossSource);
  const lost = await input.read(input.replyLossSource);
  expect(lost).not.toBeNull();
  expect(await input.prepare(input.replyLossSource)).toEqual(lost);
  await input.changeGeneration();
  expect(canonicalJson(await input.read(input.source))).toBe(bytes);
  // Preparation may now deny current generation admission. Readback still owns
  // the exact original; no subsequent failure can delete/re-time it.
  expect(await input.providerCalls()).toBe(calls);
}

/** Run once per independently admitted negative scenario. The harness causes the
 * named state through its real owner; unsupported transitions remain BLOCKED,
 * never SQL seeded. This helper preserves the first failure via normal assertions. */
export async function assertNotificationDeliveryPreparationDenial(
  input: NotificationDeliveryPreparationCasesInput,
  scenario:
    | 'wrong-peer'
    | 'foreign-scope'
    | 'wrong-subscription'
    | 'unpublished-source'
    | 'endpoint-change'
    | 'cap-zero'
    | 'exhausted'
    | 'not-due'
    | 'cancelled'
    | 'unknown'
    | 'stale-generation'
    | 'epoch-overflow'
    | 'expired',
  actualCall: () => Promise<unknown>,
) {
  expect(scenario).toBeTruthy();
  const before = await snapshot(input),
    calls = await input.providerCalls();
  await expect(actualCall()).rejects.toThrow();
  expect(await snapshot(input)).toEqual(before);
  expect(await input.providerCalls()).toBe(calls);
}

/** Real scoped runtime connection, outside a fabricated admission. Both empty
 * and matching-row statements are denied by the installed immutable trigger. */
export async function assertNotificationDeliveryPreparationImmutable(
  client: PoolClient,
  original: NotificationDeliveryPreparation,
) {
  const values = [
    original.source.worker.participantId,
    original.source.worker.privacyDomainId,
    original.operationId,
  ];
  const select =
    'select preparation_bytes,preparation_digest from control.notification_delivery_preparation where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3';
  const before = (await client.query(select, values)).rows;
  expect(before).toHaveLength(1);
  for (const statement of [
    'update control.notification_delivery_preparation set operation_id=operation_id where false',
    'delete from control.notification_delivery_preparation where false',
    'update control.notification_delivery_preparation set preparation=preparation where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3',
    'delete from control.notification_delivery_preparation where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3',
  ]) {
    await client.query('savepoint notification_preparation_immutable');
    try {
      await expect(client.query(statement, statement.includes('$1') ? values : [])).rejects.toThrow(
        /NOTIFICATION-PREPARATION-IMMUTABLE|permission denied/u,
      );
    } finally {
      await client.query('rollback to savepoint notification_preparation_immutable');
    }
  }
  expect((await client.query(select, values)).rows).toEqual(before);
}

/** Called by the genuine TLS route, then checks escaped admission only after its
 * owning callback has ended. This never constructs an admitted object in tests. */
export async function assertNotificationPreparationLiveAdmission(input: {
  withAdmission<T>(
    operation: (
      client: PoolClient,
      admission: NotificationWorkerAdmission,
      selector: NotificationWorkerSelector,
    ) => Promise<T>,
  ): Promise<T>;
  wrongClient: PoolClient;
}) {
  let expired: (() => void) | undefined;
  await input.withAdmission(async (client, admission, selector) => {
    const identity = notificationDeliveryWorkerContextIdentity(admission, client, selector);
    expect(identity.authorizationContextId).toBe(
      admission.installation.profile.workloadCredentialId,
    );
    expect(identity.authorizationContextEpoch).toBe(
      Number(admission.installation.profile.workloadEpoch),
    );
    expect(identity.authorizationDigest).toBe(admission.authorityDigest);
    expect(identity.accessClassIds).toEqual(['ACCESS-NOTIFICATION']);
    expect(input.wrongClient).not.toBe(client);
    expect(() =>
      notificationDeliveryWorkerContextIdentity({ ...admission }, client, selector),
    ).toThrow();
    expect(() =>
      notificationDeliveryWorkerContextIdentity(admission, input.wrongClient, selector),
    ).toThrow();
    const altered = { ...selector, installationDigest: `sha256:${'0'.repeat(64)}` };
    expect(altered.installationDigest).not.toBe(selector.installationDigest);
    expect(() => assertNotificationDeliveryWorkerAdmission(admission, client, altered)).toThrow();
    expired = () => notificationDeliveryWorkerContextIdentity(admission, client, selector);
  });
  expect(expired).toBeTypeOf('function');
  expect(expired!).toThrow();
}
