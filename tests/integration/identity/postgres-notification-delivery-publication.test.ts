import { readFileSync } from 'node:fs';
import { Pool, type PoolClient } from 'pg';
import { withNotificationDeliveryWorkerPeer } from '../../../services/identity-service/src/domain/notification-worker.js';
import {
  notificationOutcomeSigningSelector,
  readNotificationOutcomeInputInTransaction,
} from '../../../services/control-api/src/notifications/delivery-outcome-state.js';
import { lockEvidenceLifecycle } from '../../../services/control-api/src/evidence/lifecycle-fence.js';
import { it, expect } from 'vitest';
import {
  publishNotificationDeliveryOutcome,
  readNotificationDeliveryOutcomePublication,
} from '../../../services/control-api/src/notifications/delivery-outcome-publication.js';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.js';

it.runIf(process.env.OPENPC_I02_ADMIN_DATABASE_URL !== undefined)(
  'rejects missing forced scope, disabled shared triggers and missing completion uniqueness before publication',
  async () => {
    const pool = new Pool({ connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL, max: 1 });
    const client = await pool.connect();
    try {
      const defects = [
        ...[
          'notification_delivery_outcome',
          'notification_delivery_observation',
          'notification_delivery',
          'work_item',
          'outbox_event',
        ].map((table) => `alter table control.${table} no force row level security`),
        'alter table control.outbox_event disable trigger business_outbox_payload',
        'alter table control.work_item disable trigger work_item_lifecycle',
        'alter table control.notification_delivery disable trigger notification_delivery_budget_guard',
        'alter table control.work_item disable trigger notification_failure_work_complete',
        'drop index control.outbox_notification_completion_sequence_uq',
        'alter table control.outbox_event drop constraint outbox_proof_kind_ck',
      ];
      for (const defect of defects) {
        await client.query('begin');
        try {
          await client.query('set local role openpc_control_owner');
          await client.query(defect);
          await expect(
            client.query('select openpc.assert_notification_outcome_publication_shared_owners()'),
          ).rejects.toMatchObject({ message: 'NOTIFICATION-OUTCOME-SHARED-OWNERS' });
        } finally {
          await client.query('rollback');
        }
      }
      await client.query('select openpc.assert_notification_outcome_publication_shared_owners()');
    } finally {
      client.release(true);
      await pool.end();
    }
  },
);

it.runIf(
  process.env.OPENPC_I02_RUNTIME_DATABASE_URL !== undefined &&
    process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL !== undefined,
)(
  'installs real shared publication guards while retaining read-only historical custody privileges',
  async () => {
    const runtime = new Pool({
      connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL,
      max: 1,
    });
    const worker = new Pool({
      connectionString: process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL,
      max: 1,
    });
    try {
      await runtime.query('select openpc.assert_notification_outcome_publication_shared_owners()');
      for (const [pool, writable] of [
        [runtime, true],
        [worker, false],
      ] as const) {
        expect(
          (
            await pool.query(
              'select not rolsuper and not rolbypassrls safe from pg_roles where rolname=current_user',
            )
          ).rows[0]?.safe,
        ).toBe(true);
        for (const table of [
          'notification_delivery_outcome',
          'notification_delivery_observation',
        ]) {
          expect(
            (
              await pool.query(
                `select has_table_privilege(current_user,$1,'SELECT') readable,has_table_privilege(current_user,$1,'INSERT') writable,has_table_privilege(current_user,$1,'UPDATE') updatable,has_table_privilege(current_user,$1,'DELETE') deletable from pg_class where oid=$1::regclass and relrowsecurity and relforcerowsecurity`,
                [`control.${table}`],
              )
            ).rows,
          ).toEqual([{ readable: true, writable, updatable: false, deletable: false }]);
        }
      }
      const client = await worker.connect();
      try {
        await client.query('begin');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          [localOperationId(), localOperationId(), localOperationId()],
        );
        await expect(
          client.query('select openpc.check_notification_outcome_publication_original($1)', [
            localOperationId(),
          ]),
        ).rejects.toMatchObject({ code: 'P0002' });
      } finally {
        await client.query('rollback');
        client.release();
      }
      await expect(
        worker.query('insert into control.notification_delivery_outcome default values'),
      ).rejects.toMatchObject({ code: '42501' });
      await expect(
        worker.query('select openpc.assert_notification_outcome_publication_owner()'),
      ).rejects.toMatchObject({ code: '42501' });
    } finally {
      await runtime.end();
      await worker.end();
    }
  },
);
/** The canonical real journey driver supplies its existing genuine TLS peer and
 * selector after supported STARTED, dispatch, native receipt and signing owners.
 * No seeding of outcomes/approval/authority, replacement transaction or mocks.
 * This corpus is prepared, not executed by component tests or a skipped PG case. */
export async function assertNotificationOutcomePublicationCases(
  args: Parameters<typeof publishNotificationDeliveryOutcome>,
) {
  const [pool, kernel, socket, selector] = args;
  const before = await readNotificationDeliveryOutcomePublication(...args);
  expect(before).toBeNull();
  const [first, concurrent] = await Promise.all([
    publishNotificationDeliveryOutcome(...args),
    publishNotificationDeliveryOutcome(...args),
  ]);
  expect(concurrent.encoded.transitionBytes).toEqual(first.encoded.transitionBytes);
  const replay = await publishNotificationDeliveryOutcome(...args);
  expect(replay.encoded.coseSign1).toEqual(first.encoded.coseSign1);
  const recovered = await readNotificationDeliveryOutcomePublication(
    pool,
    kernel,
    socket,
    selector,
  );
  expect(recovered?.encoded.transitionDigest).toBe(first.encoded.transitionDigest);
  const r = first.encoded.transition.receipt;
  const counts = await withOriginalReader(args, (client) =>
    client.query<{
      results: string;
      observations: string;
      events: string;
      work: string;
    }>(
      `select
 (select count(*)::text from control.notification_delivery_outcome where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3) results,
 (select count(*)::text from control.notification_delivery_observation where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3) observations,
 (select count(*)::text from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and sequence_namespace='NOTIFICATION_DELIVERY_COMPLETED_V1' and correlation_id=$3) events,
 (select count(*)::text from control.work_item where participant_id=$1 and privacy_domain_id=$2 and work_item_id=$4) work`,
      [r.participantId, r.privacyDomainId, r.operationId, r.receiptId],
    ),
  );
  // Counts use the actual authenticated scoped reader; unscoped RLS cannot
  // be interpreted as success or fabricated expected counts.
  expect(counts.rows[0]).toEqual({
    results: '1',
    observations: '1',
    events: first.event ? '1' : '0',
    work: first.failureWork ? '1' : '0',
  });
  return first;
}
/** Restart/unknown-COMMIT reconciliation takes a newly authenticated peer and
 * original selector. It never resubmits signing or varies business identity. */
export async function assertNotificationOutcomeRestart(
  args: Parameters<typeof readNotificationDeliveryOutcomePublication>,
  expectedDigest: string,
) {
  const retained = await readNotificationDeliveryOutcomePublication(...args);
  expect(retained?.encoded.transitionDigest).toBe(expectedDigest);
  return retained;
}
/** Run after a real denied/stale/cancellation-race publication. Caller supplies
 * only the original scope/operation, not a fabricated business state. */
export async function assertNotificationOutcomeNoPartialEffects(
  client: import('pg').PoolClient,
  scope: {
    participantId: string;
    privacyDomainId: string;
    operationId: string;
  },
) {
  await client.query('select openpc.assert_request_context(true)');
  const context = await client.query(
    'select openpc.current_participant_id()=$1::uuid and openpc.current_privacy_domain_id()=$2::uuid valid',
    [scope.participantId, scope.privacyDomainId],
  );
  expect(context.rows[0]?.valid).toBe(true);
  const result = await client.query(
    `select (select count(*) from control.notification_delivery_outcome where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3)+(select count(*) from control.notification_delivery_observation where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3)+(select count(*) from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and correlation_id=$3)+(select count(*) from control.work_item w join control.notification_delivery_outcome_signing s on s.participant_id=w.participant_id and s.privacy_domain_id=w.privacy_domain_id and s.signing_attempt_id=w.work_item_id where s.participant_id=$1 and s.privacy_domain_id=$2 and s.operation_id=$3) n`,
    [scope.participantId, scope.privacyDomainId, scope.operationId],
  );
  expect(String(result.rows[0]?.n)).toBe('0');
}
it('requires original-selector publication and keeps actual PG/TLS acceptance separate from component support', () => {
  const source = readFileSync(
    new URL(
      '../../../services/control-api/src/notifications/delivery-outcome-publication.ts',
      import.meta.url,
    ),
    'utf8',
  );
  expect(source).toContain('withNotificationDeliveryWorkerPeer');
  expect(source).toContain('withNotificationDeliveryResultAuthority');
  expect(source).not.toContain('insert into control.evidence_record');
});

async function withOriginalReader<T>(
  args: Parameters<typeof publishNotificationDeliveryOutcome>,
  run: (client: PoolClient) => Promise<T>,
) {
  const [pool, kernel, socket, value] = args,
    q = notificationOutcomeSigningSelector.parse(value);
  return withNotificationDeliveryWorkerPeer(pool, kernel, socket, q.worker, async (client) => {
    await client.query(
      "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
    );
    try {
      await lockEvidenceLifecycle(client, q.worker.participantId, q.worker.privacyDomainId);
      return await run(client);
    } finally {
      await client.query(
        "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
      );
    }
  });
}
/** The existing driver first arranges a real stale/cancellation or shared-owner
 * rollback denial. Capture its actual projection; never seed a result to pass. */
export async function assertNotificationOutcomePublicationRejected(
  args: Parameters<typeof publishNotificationDeliveryOutcome>,
) {
  const q = notificationOutcomeSigningSelector.parse(args[3]);
  const before = await withOriginalReader(args, (c) =>
    readNotificationOutcomeInputInTransaction(c, q.original),
  );
  await expect(publishNotificationDeliveryOutcome(...args)).rejects.toThrow();
  await withOriginalReader(args, (c) =>
    assertNotificationOutcomeNoPartialEffects(c, {
      ...q.worker,
      operationId: q.operationId,
    }),
  );
  const after = await withOriginalReader(args, (c) =>
    readNotificationOutcomeInputInTransaction(c, q.original),
  );
  expect(after.current).toEqual(before.current);
  expect(after.first).toBeNull();
}
