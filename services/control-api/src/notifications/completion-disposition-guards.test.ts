import { it, expect } from 'vitest';
import { getTableConfig } from 'drizzle-orm/pg-core';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
import {
  notificationCompletionSources,
  notificationCompletionAttempts,
  notificationCompletionDispositionSigning,
  notificationCompletionDispositions,
  notificationCompletionDispositionSigners,
} from './completion-disposition-schema.js';
it('parses guard condition structure and leaves all shared grants with canonical', async () => {
  const module: Record<string, unknown> = await import(
    new URL('./completion-disposition-guards.mjs', import.meta.url).href
  );
  if (typeof module.notificationCompletionDispositionGuardsSql !== 'string')
    throw new Error('Missing disposition SQL');
  const sql = module.notificationCompletionDispositionGuardsSql;

  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(sql).not.toMatch(/SECURITY DEFINER|GRANT\s/u);
  for (const required of [
    'require_notification_completion_disposition_authority',
    'check_notification_completion_source_origin',
    'check_notification_completion_disposition_original',
    'DEFERRABLE INITIALLY DEFERRED',
    'COMPLETION-BUDGET-IMMUTABLE',
    'COMPLETION-ATTEMPT-SEALED',
    'COMPLETION-SIGNING-TRANSITION',
    "'occurredAtUs',floor(extract(epoch from e.occurred_at)*1000000)::text",
  ])
    expect(sql).toContain(required);
  expect(sql).not.toContain("field('receiptSignerSpki')");
});
it('declares one source budget, ordered attempts, one signing intent and result per original event', () => {
  for (const table of [
    notificationCompletionSources,
    notificationCompletionAttempts,
    notificationCompletionDispositionSigning,
    notificationCompletionDispositions,
    notificationCompletionDispositionSigners,
  ]) {
    const c = getTableConfig(table);
    expect(c.enableRLS).toBe(true);
    expect(c.primaryKeys).toHaveLength(1);
    expect(c.foreignKeys.length).toBeGreaterThan(0);
  }
  expect(
    getTableConfig(notificationCompletionSources).primaryKeys[0]!.columns.map((x) => x.name),
  ).toEqual(['participant_id', 'privacy_domain_id', 'event_id']);
  expect(
    getTableConfig(notificationCompletionAttempts).primaryKeys[0]!.columns.map((x) => x.name),
  ).toEqual(['participant_id', 'privacy_domain_id', 'event_id', 'number']);
});
it('uses explicit CLAIM and signing phases and checks the live FINISH owner before lease expiry', async () => {
  const module: Record<string, unknown> = await import(
    new URL('./completion-disposition-guards.mjs', import.meta.url).href
  );
  const sql = String(module.notificationCompletionDispositionGuardsSql);
  expect(sql).toContain(
    "check_notification_completion_effect_binding(NEW.event_id,'CLAIM',a->>'workerInstallationDigest',a->>'authorityDigest')",
  );
  expect(sql).toContain(
    "check_notification_completion_effect_binding(NEW.event_id,'FINISH',OLD.attempt->>'workerInstallationDigest',OLD.attempt->>'authorityDigest')",
  );
  expect(sql).toContain("IF n<(OLD.attempt->>'leaseUntilMs')::numeric THEN");
  expect(sql).toContain("OR n>=(a->>'leaseUntilMs')::numeric");
  expect(sql).toContain("phase IS NULL OR phase NOT IN ('PREPARE','SIGN_CLAIM')");
  expect(sql).toContain(
    'check_notification_completion_signing_current(NEW.event_id,NEW.preparation,phase)',
  );
  expect(sql).toContain('installation_digest=binding.installation_digest');
});
it('requires exact-byte cryptographic admission for signed observation and terminal insertion', async () => {
  const module: Record<string, unknown> = await import(
    new URL('./completion-disposition-guards.mjs', import.meta.url).href
  );
  const sql = String(module.notificationCompletionDispositionGuardsSql);
  const start = sql.indexOf(
    'CREATE OR REPLACE FUNCTION openpc.guard_notification_completion_disposition()',
  );
  const terminal = sql.slice(start, sql.indexOf('END $$;', start));
  expect(terminal).toContain(
    "require_notification_completion_disposition_authority(NEW.event_id,'PUBLISH')",
  );
  expect(terminal).toContain(
    "check_notification_completion_receipt_admission(NEW.event_id,'PUBLISH',",
  );
  expect(sql).toContain("IF NEW.observation->>'outcome'='SIGNED' THEN");
  expect(sql).toContain(
    "check_notification_completion_receipt_admission(NEW.event_id,'OBSERVE',NEW.observation)",
  );
  expect(sql).toContain(
    "NEW.observation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.observation_bytes),'hex')",
  );
  expect(terminal).toContain('RETURN NEW');
  expect(terminal).not.toContain('COMPLETION-CRYPTOGRAPHIC-ADMISSION-UNAVAILABLE');
  expect(terminal).not.toContain('EXCEPTION WHEN');
});
