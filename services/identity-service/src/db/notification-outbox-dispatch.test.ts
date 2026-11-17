import { expect, it } from 'vitest';
import { verifyConditionCases } from './function-grants.js';

async function sqlOwner(path: string, name: string): Promise<string> {
  const owner: Record<string, unknown> = await import(new URL(path, import.meta.url).href);
  const sql = owner[name];
  if (typeof sql !== 'string') throw new Error('Missing notification SQL owner');
  return sql;
}
const sql = await sqlOwner('./business-receipt-guards.mjs', 'businessReceiptGuardsSql');
const start = sql.indexOf('CREATE OR REPLACE FUNCTION openpc.guard_business_outbox()');
const end = sql.indexOf('\nEND $$;', start);
if (start < 0 || end < 0) throw new Error('Missing authoritative outbox dispatcher');
const dispatch = sql.slice(start, end);

// These are generator/dispatch contracts, not PostgreSQL acceptance. The real
// joined PG caller must still exercise missing checker, denied proof, rollback
// and atomic source/receipt/occurrence/outbox/cursor behavior before activation.
it('routes only the exact notification proof family through its required SQL checker', () => {
  const branch = dispatch.match(
    /IF NEW\.proof_kind='NOTIFICATION_DELIVERY_REQUEST_REFERENCE' THEN([\s\S]*?)END IF;/u,
  );
  expect(branch).not.toBeNull();
  expect(branch![1]!.trim()).toBe(
    'PERFORM openpc.check_notification_delivery_requested_event(NEW);\n  RETURN NEW;',
  );
  expect(dispatch.match(/check_notification_delivery_requested_event\(NEW\)/gu)).toHaveLength(1);
  expect(dispatch).not.toMatch(
    /(?:^|\n)\s*EXCEPTION\b|WHEN OTHERS|to_regprocedure|EXECUTE|SECURITY DEFINER/iu,
  );
  expect(dispatch.indexOf('check_notification_delivery_requested_event(NEW)')).toBeLessThan(
    dispatch.indexOf("IF NEW.proof_kind<>'BUSINESS_RECEIPT_REFERENCE'"),
  );
});
it('preserves legacy, export and command receipt paths without a permissive default', () => {
  expect(dispatch).toContain("IF NEW.proof_kind='LEGACY' THEN RETURN NEW; END IF;");
  expect(dispatch).toContain(
    "IF NEW.proof_kind='EVIDENCE_EXPORT_COMPLETION_REFERENCE' THEN\n  PERFORM openpc.check_evidence_export_completion_event(NEW);\n  RETURN NEW;\n END IF;",
  );
  expect(dispatch).toContain(
    "IF NEW.proof_kind<>'BUSINESS_RECEIPT_REFERENCE' THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-OUTBOX-PROOF'; END IF;",
  );
  expect(dispatch).toContain('SELECT * INTO STRICT receipt FROM control.audit_occurrence');
  expect(dispatch).toContain('NEW.payload_digest<>sha256(NEW.payload_cbor)');
  expect(dispatch).toContain('openpc.check_signing_rotation_event(NEW,receipt)');
});
it('requires the distinct final outcome publication owner for completion without falling back to request proof', () => {
  const branch = dispatch.match(
    /IF NEW\.proof_kind='NOTIFICATION_DELIVERY_COMPLETION_REFERENCE' THEN([\s\S]*?)END IF;/u,
  );
  expect(branch?.[1]?.trim()).toBe(
    'PERFORM openpc.check_notification_delivery_completed_event(NEW);\n  RETURN NEW;',
  );
  expect(dispatch.match(/check_notification_delivery_completed_event\(NEW\)/gu)).toHaveLength(1);
  expect(dispatch.indexOf('check_notification_delivery_completed_event(NEW)')).toBeLessThan(
    dispatch.indexOf("IF NEW.proof_kind<>'BUSINESS_RECEIPT_REFERENCE'"),
  );
  expect(dispatch).not.toMatch(/to_regprocedure|WHEN OTHERS|SECURITY DEFINER/iu);
});
it('checks feature SQL CASE conditions with the shared preflight before PostgreSQL allocation', async () => {
  const path = '../../../control-api/src/notifications/occurrence-guards.mjs';
  const preparation = await sqlOwner(path, 'notificationOccurrenceGuardsSql');
  const publication = await sqlOwner(path, 'notificationOccurrencePublicationGuardsSql');
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(() => verifyConditionCases(preparation)).not.toThrow();
  expect(() => verifyConditionCases(publication)).not.toThrow();
  expect(preparation + publication).not.toContain('undefined');
});
