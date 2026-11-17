import { expect, it } from 'vitest';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';

async function publication() {
  const module: Record<string, unknown> = await import(
    new URL('./completion-disposition-publication.mjs', import.meta.url).href
  );
  if (typeof module.notificationCompletionDispositionPublicationSql !== 'string')
    throw new Error('Missing completion publication SQL');
  return module.notificationCompletionDispositionPublicationSql;
}

it('implements the existing publication interface without installing shared security or swallowing failures', async () => {
  const sql = await publication();
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(sql).toContain(
    'CREATE OR REPLACE FUNCTION openpc.publish_notification_completion_disposition_effects(event uuid) RETURNS void',
  );
  expect(sql.match(/CREATE OR REPLACE FUNCTION/gu)).toHaveLength(1);
  expect(sql).toContain('SECURITY INVOKER SET search_path=pg_catalog');
  expect(sql).toContain(
    'REVOKE ALL ON FUNCTION openpc.publish_notification_completion_disposition_effects(uuid) FROM PUBLIC',
  );
  expect(sql).not.toMatch(
    /SECURITY DEFINER|GRANT\s|CREATE (?:TABLE|TRIGGER)|EXCEPTION WHEN|ON CONFLICT|current_setting|pg_has_role|COMMIT;|ROLLBACK;/u,
  );
});

it('checks installed shared ownership, exact originals and live PUBLISH receipt admission before any write', async () => {
  const sql = await publication();
  const firstWrite = sql.search(/\b(?:INSERT INTO|UPDATE control\.)/u);
  expect(firstWrite).toBeGreaterThan(0);
  const preflight = sql.slice(0, firstWrite);
  for (const check of [
    'assert_notification_completion_disposition_shared_owner()',
    "'notification-completion-source:'",
    'SELECT * INTO STRICT d',
    'SELECT * INTO STRICT signing',
    "check_notification_completion_phase_source(event,'PUBLISH')",
    "check_notification_completion_receipt_admission(event,'PUBLISH',signing.observation)",
    'check_notification_completion_disposition_signed(event,d.transition)',
    'SELECT * INTO STRICT s',
    'SELECT * INTO STRICT e',
    "d.receipt_payload IS DISTINCT FROM decode(signing.preparation->'request'->>'payloadHex','hex')",
    "d.cose_sign1 IS DISTINCT FROM decode(signing.observation->>'coseHex','hex')",
    "s.source->'envelope' IS DISTINCT FROM openpc.notification_completion_source_envelope(e)",
    'COMPLETION-PUBLICATION-PARTIAL-WORK',
  ])
    expect(preflight).toContain(check);
  expect(sql).not.toMatch(/'OBSERVE'|'SIGN_CLAIM'|'PREPARE'|archive_cose_binding/u);
});

it('replays only complete immutable effects and never repairs or overwrites retained terminal state', async () => {
  const sql = await publication();
  const start = sql.indexOf("IF inbox.state IN ('ADMITTED','QUARANTINED') THEN");
  expect(start).toBeGreaterThan(0);
  const replay = sql.slice(start, sql.indexOf('END IF;', start));
  expect(replay).toContain('check_notification_completion_disposition_original(event)');
  expect(replay).toContain(
    "check_notification_completion_receipt_admission(event,'PUBLISH',signing.observation)",
  );
  expect(replay).toContain('RETURN;');
  expect(replay).not.toMatch(/INSERT INTO|UPDATE control\./u);
  expect(sql).toContain('has_inbox:=FOUND;');
  expect(sql).toContain('has_cursor:=FOUND;');
  expect(sql).toContain(
    "inbox.state IS DISTINCT FROM 'PENDING' OR inbox.admission_operation_id IS NOT NULL OR inbox.safe_problem_code IS NOT NULL",
  );
  expect(sql).toContain(
    'cursor_row.last_sequence IS DISTINCT FROM 0 OR cursor_row.last_event_id IS NOT NULL OR cursor_row.last_data_digest IS NOT NULL OR cursor_row.revision IS DISTINCT FROM 1',
  );
  expect(sql).not.toMatch(/UPDATE control\.(?:work_item|outbox_event|notification_completion_)/u);
});

it('retains the original envelope and operation binding for both fresh and pending inbox admission', async () => {
  const sql = await publication();
  for (const binding of [
    "subscription constant text:='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'",
    "envelope_bytes:=convert_to(openpc.signing_canonical_json(s.source->'envelope'),'UTF8')",
    'inbox.envelope IS DISTINCT FROM envelope_bytes',
    "inbox.envelope_digest IS DISTINCT FROM s.source->'reference'->>'envelopeDigest'",
    'SET state=d.disposition,safe_problem_code=problem,admission_operation_id=d.operation_id',
    "AND event_id=event AND state='PENDING'",
    'envelope_bytes,d.disposition,problem,d.operation_id)',
    "CASE d.disposition WHEN 'QUARANTINED' THEN 'PC-OPS-9001' ELSE NULL END",
  ])
    expect(sql).toContain(binding);
  expect(sql).not.toMatch(/INSERT INTO control\.outbox_event|uuidv7\(/u);
});

it('advances ADMITTED once, while HOLD creates only minimized remediation and preserves human work', async () => {
  const sql = await publication();
  const cursorStart = sql.indexOf('UPDATE control.notification_source_cursor');
  const workStart = sql.indexOf('INSERT INTO control.work_item');
  expect(cursorStart).toBeGreaterThan(0);
  expect(workStart).toBeGreaterThan(cursorStart);
  const branchStart = sql.lastIndexOf("IF d.disposition='ADMITTED' THEN", cursorStart);
  const admitted = sql.slice(branchStart, sql.indexOf('  -- HOLD', cursorStart));
  const quarantine = sql.slice(workStart, sql.indexOf(' END IF;', workStart));
  expect(admitted).toContain('revision=revision+1');
  expect(admitted).toContain(
    'AND last_sequence=0 AND last_event_id IS NULL AND last_data_digest IS NULL AND revision=1',
  );
  expect(admitted).not.toContain('INSERT INTO control.work_item');
  expect(quarantine).not.toContain('notification_source_cursor');
  expect(quarantine).toContain(
    "'REMEDIATION','OPEN','urn:openpc:resource:'||event::text,sha256(d.receipt_payload)",
  );
  expect(quarantine).toContain(
    "'Notification completion could not be processed.',worker.principal_id,NULL,NULL,NULL,1",
  );
  expect(sql).toContain('openpc.notification_completion_remediation_projection(d)');
  expect(sql).toContain("installation_digest=d.transition->'receipt'->>'workerInstallationDigest'");
  expect(sql).toContain('openpc.check_notification_completion_validated_source(event)');
  expect(sql).not.toContain("worker.state='ACTIVE'");
});

it('propagates late completeness/currentness failure and leaves deferred checks on durable originals', async () => {
  const sql = await publication();
  const afterEffects = sql.slice(sql.indexOf('INSERT INTO control.work_item'));
  expect(afterEffects).toContain('check_notification_completion_disposition_original(event)');
  expect(afterEffects).toContain(
    "check_notification_completion_receipt_admission(event,'PUBLISH',signing.observation)",
  );
  expect(afterEffects).not.toContain('EXCEPTION WHEN');
  const module: Record<string, unknown> = await import(
    new URL('./completion-disposition-effect-guards.mjs', import.meta.url).href
  );
  expect(typeof module.notificationCompletionDispositionStructureGuardsSql).toBe('string');
  const durable = String(module.notificationCompletionDispositionStructureGuardsSql);
  expect(durable).toContain('check_notification_completion_disposition_original(event uuid)');
  expect(durable).not.toMatch(/receipt_admission\(|verified_receipt\(|phase_binding\(/u);
});
