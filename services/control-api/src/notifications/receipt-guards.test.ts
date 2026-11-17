import { expect, it } from 'vitest';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';

async function owner(path: string, name: string): Promise<string> {
  const module: Record<string, unknown> = await import(new URL(path, import.meta.url).href);
  if (typeof module[name] !== 'string') throw new Error('Missing metadata guard owner');
  return module[name];
}
const sql = await owner('./receipt-guards.mjs', 'notificationReceiptGuardsSql');
const publication = await owner(
  './occurrence-guards.mjs',
  'notificationOccurrencePublicationGuardsSql',
);
function body(source: string, name: string) {
  const start = source.indexOf(`CREATE OR REPLACE FUNCTION openpc.${name}(`);
  const end = source.indexOf('END $$;', start);
  if (start < 0 || end < 0) throw new Error('Missing SQL guard');
  return source.slice(start, end);
}
// Generator contracts supplement the real PG denial/rollback helpers. These
// checks never establish SQL execution, TLS or current-key authorization.
it('keeps public CREATE and ACK audit profiles and before/after projections intact', () => {
  const receipt = body(sql, 'assert_notification_receipt');
  expect(receipt).toContain("('CFG-OP-CREATE-NOTIFICATION','CFG-OP-ACKNOWLEDGE-NOTIFICATION')");
  expect(receipt).toContain('receipt.after_revision<>item.revision');
  expect(receipt).toContain(
    'after_projection IS DISTINCT FROM openpc.notification_business_projection(item)',
  );
  expect(receipt).toContain(
    'receipt.before_existence<>0 OR receipt.before_revision<>0 OR receipt.after_revision<>1',
  );
  expect(receipt).toContain(
    "item.candidate_digest IS DISTINCT FROM 'sha256:'||encode(receipt.candidate_digest,'hex')",
  );
  expect(receipt).toContain("before_projection-'1' IS DISTINCT FROM after_projection-'1'");
  expect(receipt).not.toContain('occurrence_metadata');
  const mutation = body(sql, 'guard_notification_mutation');
  expect(mutation).toContain(
    "current_setting('openpc.action_intent_id')<>'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1'",
  );
  expect(mutation).toContain(
    "current_setting('openpc.action_intent_id')<>'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1'",
  );
  expect(mutation).toContain(
    "OLD.state NOT IN ('UNREAD','READ') OR NEW.state<>'ACKNOWLEDGED' OR NEW.revision<>OLD.revision+1",
  );
  expect(mutation).toContain(
    'NEW.message_key,NEW.candidate_digest,NEW.created_at) IS DISTINCT FROM',
  );
});
it('requires the owned live preparation check before accepting workload metadata insertion', () => {
  const mutation = body(sql, 'guard_notification_mutation');
  expect(mutation).toContain(
    "IF current_setting('openpc.action_intent_id')='ACT-EVIDENCE_EXPORT_RECORDS-V1' THEN\n   PERFORM openpc.admit_notification_occurrence_metadata(NEW);\n   RETURN NEW;",
  );
  const admission = body(publication, 'admit_notification_occurrence_metadata');
  expect(admission).toContain(
    'bound_preparation_id:=openpc.notification_occurrence_metadata_preparation(item)',
  );
  expect(admission).toContain('PERFORM openpc.check_notification_occurrence_preparation(op)');
  expect(admission).toContain('PERFORM openpc.check_notification_occurrence_preparation(dp)');
  expect(admission).not.toMatch(/(?:^|\n)\s*EXCEPTION\b|WHEN OTHERS|SECURITY DEFINER/iu);
});
it('selects the deferred proof family from immutable originals and fully checks it independent of context changes', () => {
  const deferred = body(sql, 'check_notification_effect_receipt');
  expect(deferred).not.toMatch(/current_setting|current_action|admitted|ready/u);
  expect(deferred).toContain("IF TG_OP='INSERT' AND EXISTS(");
  expect(deferred).toContain("p.family='NotificationOccurrenceReceiptV1'");
  expect(deferred).toContain(
    "openpc.business_cbor(o.receipt_payload)->'6'=openpc.business_uuid(NEW.notification_id)",
  );
  expect(deferred).toContain(
    'PERFORM openpc.check_notification_occurrence_metadata_effect(NEW);\n  RETURN NEW;',
  );
  expect(deferred).toContain('SELECT * INTO STRICT receipt FROM control.audit_occurrence');
  expect(deferred).toContain("ELSE 'CFG-OP-ACKNOWLEDGE-NOTIFICATION' END)");
  const effect = body(publication, 'check_notification_occurrence_metadata_effect');
  expect(effect).toContain(
    'bound_preparation_id:=openpc.notification_occurrence_metadata_preparation(item)',
  );
  expect(effect).toContain('SELECT e.* INTO STRICT event FROM control.outbox_event');
  expect(effect).toContain('PERFORM openpc.check_notification_delivery_requested_event(event)');
  expect(effect).not.toMatch(/current_setting|current_action|WHEN OTHERS/u);
});
it('rejects missing, substituted or unrelated originals and retains complete effect-chain verification', () => {
  const metadata = body(publication, 'notification_occurrence_metadata_preparation');
  expect(metadata).toContain("p.family='NotificationOccurrenceReceiptV1' AND p.state='OBSERVED'");
  expect(metadata).toContain(
    "key_preparation_id=op.key_preparation_id AND family='NotificationDeliveryRequestedReceiptV1' AND state='OBSERVED'",
  );
  expect(metadata.match(/PERFORM openpc.archive_cose_binding/gu)).toHaveLength(2);
  expect(metadata).toContain(
    "original.receipt_payload IS DISTINCT FROM decode(op.preparation->>'payloadHex','hex')",
  );
  expect(metadata).toContain(
    "proof.receipt_payload IS DISTINCT FROM decode(dp.preparation->>'payloadHex','hex')",
  );
  expect(metadata).toContain('item.candidate_digest IS DISTINCT FROM original.receipt_digest');
  expect(metadata).toContain(
    "item.state IS DISTINCT FROM 'UNREAD' OR item.revision IS DISTINCT FROM 1::numeric",
  );
  expect(metadata).toContain("source.state IS DISTINCT FROM 'PUBLISHED'");
  for (const table of [
    'notification_payload_object',
    'notification_payload',
    'notification_occurrence',
    'notification_source_inbox',
    'notification_source_cursor',
  ])
    expect(body(publication, 'check_notification_delivery_requested_event')).toContain(
      `control.${table}`,
    );
  expect(metadata + sql).not.toMatch(
    /WHEN OTHERS|notification_worker_admitted|notification_reference_ready/u,
  );
});
it('passes the shared PL/pgSQL condition preflight without undefined schema interpolation', () => {
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(() => verifyConditionCases(publication)).not.toThrow();
  expect(sql + publication).not.toContain('undefined');
});
