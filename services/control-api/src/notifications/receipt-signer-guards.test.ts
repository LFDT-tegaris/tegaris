import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
const module: Record<string, unknown> = await import(
  new URL('./receipt-signer-guards.mjs', import.meta.url).href
);
if (typeof module.notificationReceiptSignerGuardsSql !== 'string')
  throw new Error('Missing receipt signer guard');
const sql = module.notificationReceiptSignerGuardsSql;
it('preflights generated conditions and denies runtime enrollment or bypassed owner guards', () => {
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(sql).toContain('FORCE ROW LEVEL SECURITY');
  expect(sql).toContain('NOT tgisinternal');
  expect(sql).toContain("current_setting('session_replication_role')<>'origin'");
  expect(sql).toContain(
    'GRANT SELECT ON control.notification_receipt_signer_installation TO openpc_control_runtime',
  );
  expect(sql).not.toMatch(
    /GRANT[^;]*(?:INSERT|UPDATE|DELETE)[^;]*TO openpc_control_runtime|SECURITY DEFINER/iu,
  );
});
it('withdrawal retains exact trust and both mutation paths fail on reversed lock acquisition', () => {
  expect(sql).toContain("OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED'");
  expect(sql).toContain("to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'");
  expect(sql).toContain('pg_try_advisory_xact_lock(');
  expect(sql).toContain('pg_try_advisory_xact_lock_shared(');
  expect(sql).toContain('BEFORE TRUNCATE');
  expect(sql).toContain("TG_OP='DELETE'");
});
it('joins actual installed worker, separate TLS/key roles and exact native signing purpose', () => {
  expect(sql).toContain("w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'");
  expect(sql).toContain("t->>'purpose'='pc.cose.notification-delivery-started-receipt.v1'");
  expect(sql).toContain("c.kind<>'WORKLOAD_MTLS'");
  expect(sql).toContain("c.credential_epoch::text IS DISTINCT FROM t->>'workloadEpoch'");
  expect(sql).toContain(
    "split_part(t->>'secretReference','#',2) IS DISTINCT FROM t->>'secretVersion'",
  );
  expect(sql).not.toMatch(
    /INSERT INTO control\.(?:outbox_event|notification_delivery|notification_delivery_attempt)|SIGN_RECEIPT|readAttempt/iu,
  );
  const source = readFileSync(new URL('./receipt-signer-installation.ts', import.meta.url), 'utf8');
  expect(source).toContain('assertNotificationDeliveryWorkerAdmission(admission');
  expect(source).toContain('select openpc.assert_notification_receipt_signer_owner()');
  expect(source).toContain('rollback to savepoint');
  expect(source).not.toMatch(/signNotificationClaim|httpsRequest|\.perform\(/u);
});
