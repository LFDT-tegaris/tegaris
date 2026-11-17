import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
import { expect, it } from 'vitest';
import { getTableConfig } from 'drizzle-orm/pg-core';
import { notificationAsyncWork, notificationAsyncWorkTransitions } from './async-worker-schema.js';
const {
  notificationAsyncWorkerGuardsSql,
  notificationAsyncWorkerRequiredOwners,
}: {
  notificationAsyncWorkerGuardsSql: string;
  notificationAsyncWorkerRequiredOwners: Readonly<Record<string, string>>;
} = await import(new URL('./async-worker-guards.mjs', import.meta.url).href);

it('binds the actual composite outbox key and permits multiple transitions in one operation', () => {
  const work = getTableConfig(notificationAsyncWork);
  const source = work.foreignKeys
    .find((key) => key.getName() === 'notification_async_source_event_fk')!
    .reference();
  expect(source.columns.map((column) => column.name)).toEqual(['participant_id', 'event_id']);
  expect(source.foreignColumns.map((column) => column.name)).toEqual([
    'participant_id',
    'event_id',
  ]);
  const transitions = getTableConfig(notificationAsyncWorkTransitions);
  expect(transitions.primaryKeys[0]!.columns.map((column) => column.name)).toEqual([
    'participant_id',
    'privacy_domain_id',
    'event_id',
    'revision',
  ]);
  expect(
    transitions.uniqueConstraints.map((key) => key.columns.map((column) => column.name)),
  ).toEqual([['participant_id', 'proof_event_id']]);
});
it('declares separate mandatory native/publication/history owners and actual statement truncate triggers', () => {
  expect(notificationAsyncWorkerRequiredOwners).toEqual({
    current: 'openpc.assert_notification_async_work_current(control.notification_async_work)',
    proof: 'openpc.publish_notification_async_work_proof(uuid,numeric)',
    historical: 'openpc.check_notification_async_work_proof(uuid,numeric)',
  });
  for (const table of ['notification_async_work', 'notification_async_work_transition'])
    expect(notificationAsyncWorkerGuardsSql).toContain(
      `BEFORE TRUNCATE ON control.${table} FOR EACH STATEMENT`,
    );
  // Declaration coupling only; actual SQL denial/completeness belongs to the
  // real migration/runtime fixture and is not established by this assertion.
  expect(notificationAsyncWorkerGuardsSql).toContain('NEW.transition_event_id,record,payload');
});

it('passes the shared SQL conditional syntax preflight before database allocation', () => {
  expect(() => verifyConditionCases(notificationAsyncWorkerGuardsSql)).not.toThrow();
});

it('preflights the shared original payload SQL owner used by preparation and queue admission', async () => {
  const { notificationDeliveryPreparationGuardsSql } = await import(
    new URL('./delivery-start-preparation-guards.mjs', import.meta.url).href
  );
  expect(() => verifyConditionCases(notificationDeliveryPreparationGuardsSql)).not.toThrow();
});

const { notificationAsyncWorkProofGuardsSql, notificationAsyncInitialProofInvalidSql } =
  await import(new URL('./async-worker-proof-guards.mjs', import.meta.url).href);

it('preflights the historical proof owner and keeps current admission separate', () => {
  expect(() => verifyConditionCases(notificationAsyncWorkProofGuardsSql)).not.toThrow();
  expect(notificationAsyncWorkProofGuardsSql).toContain(
    `IF ${notificationAsyncInitialProofInvalidSql}`,
  );
  expect(notificationAsyncWorkProofGuardsSql).toContain(
    'PERFORM openpc.assert_notification_async_work_current(work)',
  );
  expect(notificationAsyncWorkProofGuardsSql).toContain(
    'item.transition IS DISTINCT FROM expected',
  );
  expect(notificationAsyncInitialProofInvalidSql).not.toMatch(
    /clock_timestamp|current_setting|notification_async_initial_disposition/u,
  );
});

// Cheap declaration preflight catches loss of NULL-safe rejection. Behavioral
// malformed-row coverage executes this exact predicate in the two real SQL
// discovery cases; these assertions do not claim PostgreSQL execution.
it.each([
  "item.transition->'before' IS DISTINCT FROM 'null'::jsonb",
  'after_row.revision IS DISTINCT FROM 1',
  'after_row.lease_epoch IS DISTINCT FROM 0',
  'after_row.lease_owner IS NOT NULL',
  'after_row.lease_until_ms IS NOT NULL',
  'after_row.charged IS DISTINCT FROM false',
  'after_row.effect_uncertain IS DISTINCT FROM false',
  'after_row.original IS NOT NULL',
  'after_row.next_at_ms IS NOT NULL',
  "after_row.state='PENDING' AND after_row.reason IS NULL",
  "after_row.state='QUARANTINED' AND after_row.reason IN ('INITIAL_DOMAIN_DEADLINE','INITIAL_SOURCE_WITHDRAWN')",
  ') IS NOT TRUE',
])('retains initial-shape rejection boundary %s', (predicate) => {
  expect(notificationAsyncInitialProofInvalidSql).toContain(predicate);
});
