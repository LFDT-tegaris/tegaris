import { businessReceiptGuardsSql } from '../../../identity-service/src/db/business-receipt-guards.mjs';
import { workItemLifecycleGuardsSql } from '../../../identity-service/src/db/work-item-receipt-guards.mjs';
import { notificationDeliveryBudgetGuardsSql } from './delivery-start-guards.mjs';

const quote = (value) => `'${value.replaceAll("'", "''")}'`;
function body(sql, name) {
  const start = sql.indexOf(`CREATE OR REPLACE FUNCTION openpc.${name}()`);
  const begin = sql.indexOf('AS $$', start),
    end = sql.indexOf('$$;', begin);
  if (start < 0 || begin < start || end < begin)
    throw new Error('Missing shared publication owner');
  return sql.slice(begin + 5, end);
}
const shared = [
  ['guard_business_outbox', businessReceiptGuardsSql, 'outbox_event', 'business_outbox_payload', 7],
  [
    'enforce_work_item_lifecycle',
    workItemLifecycleGuardsSql,
    'work_item',
    'work_item_lifecycle',
    31,
  ],
  [
    'guard_notification_delivery_budget',
    notificationDeliveryBudgetGuardsSql,
    'notification_delivery',
    'notification_delivery_budget_guard',
    31,
  ],
];
const installed = shared.map(
  ([
    name,
    sql,
    table,
    trigger,
    type,
  ]) => `NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
 JOIN pg_trigger t ON t.tgfoid=p.oid
 WHERE n.nspname='openpc' AND p.proname=${quote(name)} AND p.pronargs=0
 AND r.rolname='openpc_control_owner' AND l.lanname='plpgsql' AND NOT p.prosecdef
 AND p.prorettype='trigger'::regtype AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog']
 AND p.prosrc=${quote(body(sql, name))}
 AND t.tgrelid='control.${table}'::regclass AND t.tgname=${quote(trigger)} AND t.tgtype=${type}
 AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgqual IS NULL)`,
);

/** Exact installed shared dispatch, with source-owned failure insertion and a
 * deferred check selected at INSERT time. This grants no publication authority
 * by itself; the feature owner separately verifies the real worker and signer. */
export const notificationOutcomePublicationSharedSql = `
CREATE OR REPLACE FUNCTION openpc.guard_notification_failure_work_complete() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE operation uuid;
BEGIN
 SELECT operation_id INTO STRICT operation FROM control.notification_delivery_outcome
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND receipt_id=NEW.work_item_id;
 PERFORM openpc.check_notification_outcome_publication_original(operation);
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_failure_work_complete ON control.work_item;
CREATE CONSTRAINT TRIGGER notification_failure_work_complete AFTER INSERT ON control.work_item
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
 WHEN (NEW.kind='DELIVERY_FAILURE' AND current_setting('openpc.action_intent_id',true)='ACT-EVIDENCE_EXPORT_RECORDS-V1')
 EXECUTE FUNCTION openpc.guard_notification_failure_work_complete();

CREATE OR REPLACE FUNCTION openpc.assert_notification_outcome_publication_shared_owners() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF ${installed.join('\n OR ')}
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['notification_delivery_outcome','notification_delivery_observation',
  'notification_delivery','work_item','outbox_event']) expected(name)
  WHERE NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='control' AND c.relname=expected.name
   AND r.rolname='openpc_control_owner' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
   AND NOT c.relispartition AND NOT EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)))
 OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='control.outbox_event'::regclass
  AND conname='outbox_proof_kind_ck' AND contype='c' AND convalidated)
 OR NOT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
  WHERE i.indrelid='control.outbox_event'::regclass AND c.relname='outbox_notification_completion_sequence_uq'
  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indnatts=4 AND i.indnkeyatts=4 AND i.indexprs IS NULL
  AND pg_get_expr(i.indpred,i.indrelid)=${quote("(sequence_namespace = 'NOTIFICATION_DELIVERY_COMPLETED_V1'::text)")}
  AND pg_get_indexdef(i.indexrelid,1,true)='participant_id' AND pg_get_indexdef(i.indexrelid,2,true)='privacy_domain_id'
  AND pg_get_indexdef(i.indexrelid,3,true)='aggregate_id' AND pg_get_indexdef(i.indexrelid,4,true)='business_sequence')
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.work_item'::regclass AND tgname='notification_failure_work_complete'
  AND tgfoid='openpc.guard_notification_failure_work_complete()'::regprocedure AND tgenabled IN ('O','A') AND tgtype=5 AND tgdeferrable AND tginitdeferred)
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SHARED-OWNERS'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_notification_failure_work_complete(),openpc.assert_notification_outcome_publication_shared_owners() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_notification_outcome_publication_shared_owners() TO openpc_control_runtime;
`;
