import { expect, it } from 'vitest';
import { getTableConfig, PgDialect } from 'drizzle-orm/pg-core';
import {
  verifyConditionCases,
  verifyFunctionGrants,
} from '../../../identity-service/src/db/function-grants.js';
import { notificationSourceInbox, notificationSourceCursors } from './schema.js';

async function registration() {
  const module: Record<string, unknown> = await import(
    new URL('./completion-disposition-registration.mjs', import.meta.url).href
  );
  const sql = module.notificationCompletionDispositionRegistrationSql;
  if (typeof sql !== 'string') throw new Error('Missing completion registration');
  return sql;
}
function body(sql: string, name: string) {
  const start = sql.indexOf(`CREATE OR REPLACE FUNCTION openpc.${name}(`);
  if (start < 0) throw new Error('Missing registered routine');
  return sql.slice(start, sql.indexOf('END $$;', start));
}

it('generates closed operation projections without changing the caller column or weakening existing subscriptions', () => {
  const c = getTableConfig(notificationSourceInbox),
    dialect = new PgDialect();
  const occurrence = notificationSourceInbox.occurrenceAdmissionOperationId,
    completion = notificationSourceInbox.completionAdmissionOperationId;
  expect(occurrence.generated?.type).toBe('always');
  expect(completion.generated?.type).toBe('always');
  const expression = (column: typeof occurrence | typeof completion) =>
    dialect.sqlToQuery(column.generated!.as as Parameters<typeof dialect.sqlToQuery>[0]).sql;
  expect(expression(occurrence)).toContain('SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1');
  expect(expression(occurrence)).toContain('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1');
  expect(expression(occurrence)).toContain('SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1');
  expect(expression(occurrence)).not.toContain('SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1');
  expect(expression(completion)).toContain(
    'WHEN "subscription_id"=\'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1\' THEN "admission_operation_id" ELSE NULL END',
  );
  const fk = (name: string) => c.foreignKeys.find((key) => key.getName() === name)!.reference();
  expect(fk('notification_inbox_operation_fk').columns.map((column) => column.name)).toEqual([
    'participant_id',
    'privacy_domain_id',
    'occurrence_admission_operation_id',
  ]);
  expect(getTableConfig(fk('notification_inbox_operation_fk').foreignTable).name).toBe(
    'notification_occurrence_observation',
  );
  expect(
    fk('notification_inbox_completion_operation_fk').columns.map((column) => column.name),
  ).toEqual(['participant_id', 'privacy_domain_id', 'completion_admission_operation_id']);
  expect(getTableConfig(fk('notification_inbox_completion_operation_fk').foreignTable).name).toBe(
    'notification_completion_disposition',
  );
  expect(
    dialect.sqlToQuery(
      c.checks.find((check) => check.name === 'notification_inbox_state_ck')!.value,
    ).sql,
  ).toContain('is null');
  for (const table of [notificationSourceInbox, notificationSourceCursors])
    expect(
      getTableConfig(table).checks.some((check) =>
        dialect
          .sqlToQuery(check.value)
          .sql.includes('SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'),
      ),
    ).toBe(true);
});

it('preflights generated SQL and function grants before PostgreSQL allocation', async () => {
  const sql = await registration();
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(() => verifyFunctionGrants(sql, sql)).not.toThrow();
  expect(sql).not.toContain('undefined');
  expect(sql).not.toMatch(/SECURITY DEFINER|WHEN OTHERS/u);
  expect(sql).toContain('SELECT openpc.assert_notification_completion_disposition_shared_owner()');
});

it('authenticates installed functions, triggers, generated expressions, scoped constraints and minimal grants', async () => {
  const sql = body(await registration(), 'assert_notification_completion_disposition_shared_owner');
  for (const required of [
    'p.prosrc=',
    'p.proconfig=',
    'NOT p.prosecdef',
    'NOT p.proisstrict',
    'NOT p.proleakproof',
    'NOT p.proretset',
    'p.proargnames IS NOT DISTINCT FROM',
    'p.pronargdefaults=0',
    'NOT c.condeferrable AND NOT c.condeferred',
    'pg_get_triggerdef(t.oid,false)',
    't.tgtype=21',
    't.tgdeferrable=true',
    't.tginitdeferred=true',
    "a.attgenerated='s'",
    'c.confrelid=',
    'c.confmatchtype=',
    'c.convalidated',
    'notification_inbox_completion_operation_fk',
    'c.relforcerowsecurity',
    'pg_policy',
    'has_column_privilege',
    'has_any_column_privilege',
    'has_function_privilege',
    'a.grantee=0',
    'assert_notification_completion_admission_owner()',
  ])
    expect(sql).toContain(required);
  expect(sql).toContain(
    "'control.notification_completion_disposition_signer_installation','INSERT,UPDATE'",
  );
  expect(sql).toContain("'control.notification_completion_disposition','UPDATE'");
  // Every declared CHECK compares its complete deparsed expression, including
  // byte bounds and the grouped signing-state alternatives.
  expect(sql.match(/pg_get_expr\(c\.conbin,c\.conrelid\)/gu)).toHaveLength(21);
  expect(sql).toContain('completion_signing_state_ck');
  expect(sql).toContain('completion_disposition_bytes_ck');
});

it('binds direct shared writes to actual native receipt admission with no role or context shortcut', async () => {
  const sql = await registration();
  const admission = body(sql, 'check_notification_completion_shared_publication');
  expect(admission).toContain(
    "check_notification_completion_receipt_admission(event,'PUBLISH',s.observation)",
  );
  expect(admission).toContain("check_notification_completion_phase_source(event,'PUBLISH')");
  expect(admission).toContain(
    'check_notification_completion_disposition_signed(event,d.transition)',
  );
  expect(admission).not.toMatch(/pg_has_role|current_setting|EXCEPTION WHEN/u);
  const inbox = body(sql, 'check_notification_completion_inbox_effect');
  expect(inbox).toContain(
    'd:=openpc.check_notification_completion_shared_publication(item.event_id)',
  );
  expect(inbox).toContain("previous.state IS DISTINCT FROM 'PENDING'");
  expect(inbox).toContain('item.admission_operation_id IS DISTINCT FROM d.operation_id');
  expect(inbox).toContain('to_jsonb(previous)-ARRAY');
  const cursor = body(sql, 'check_notification_completion_cursor_effect');
  expect(cursor).toContain("d.disposition IS DISTINCT FROM 'ADMITTED'");
  expect(cursor).toContain('previous.last_sequence IS DISTINCT FROM 0');
  expect(cursor).toContain('item.revision IS DISTINCT FROM 2');
  const work = body(sql, 'check_notification_completion_remediation_effect');
  expect(work).toContain(
    'openpc.work_item_business_projection(item) IS DISTINCT FROM openpc.notification_completion_remediation_projection(d)',
  );
});

it('keeps shared dispatch closed across subscription changes and deferred checks independent of live admission', async () => {
  const module: Record<string, unknown> = await import(
    new URL('./occurrence-guards.mjs', import.meta.url).href
  );
  const sql = String(module.notificationOccurrencePublicationGuardsSql);
  const immediate = body(sql, 'guard_notification_occurrence_effect');
  expect(immediate).toContain(
    "OLD.subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'",
  );
  expect(immediate).toContain(
    "TG_OP='DELETE' THEN RAISE EXCEPTION 'COMPLETION-SHARED-EFFECT-IMMUTABLE'",
  );
  expect(immediate).toContain(
    "NEW.subscription_id NOT IN ('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1')",
  );
  expect(immediate).toContain('PERFORM openpc.assert_request_context(true);');
  const deferred = body(sql, 'check_notification_occurrence_effect_pair');
  expect(deferred).toContain('check_notification_completion_disposition_original(NEW.event_id)');
  expect(deferred).toContain(
    'check_notification_completion_disposition_original(NEW.last_event_id)',
  );
  expect(deferred).not.toMatch(/receipt_admission|phase_binding|verified_receipt/u);
  expect(sql).toContain('notification_source_inbox_effect_pair AFTER INSERT OR UPDATE');
  expect(sql).toContain('notification_source_cursor_effect_pair AFTER INSERT OR UPDATE');
});

it('preserves public WorkItem and producer failure owners and queues internal remediation completeness at INSERT', async () => {
  const module: Record<string, unknown> = await import(
    new URL('../../../identity-service/src/db/work-item-receipt-guards.mjs', import.meta.url).href
  );
  const lifecycle = String(module.workItemLifecycleGuardsSql);
  expect(lifecycle).toContain('check_notification_completion_remediation_effect(NEW)');
  expect(lifecycle).toContain('check_notification_delivery_failure_work(NEW)');
  expect(lifecycle).toContain(
    "openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'",
  );
  expect(lifecycle).toContain("IS DISTINCT FROM 'ACT-WORK_ITEMS_CREATE_RESOURCE-V1'");
  expect(lifecycle).toContain('NEW."row_version" <> OLD."row_version" + 1');
  const sql = await registration();
  const deferred = body(sql, 'complete_notification_completion_remediation');
  expect(deferred).toContain('check_notification_completion_disposition_original(event)');
  expect(deferred).not.toMatch(/receipt_admission|phase_binding|verified_receipt/u);
  expect(sql).toContain('notification_completion_remediation_complete AFTER INSERT');
});
