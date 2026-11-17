/** Public work-item effects bind the actual old/new row to the independently
 * verified business receipt. This does not authorize notification worker effects. */
export const workItemReceiptGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.work_item_business_projection(item control.work_item)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',(item).kind,'1',(item).state,
  '2',(item).resource_ref,'3',openpc.business_bytes((item).payload_digest),
  '4',openpc.business_bytes(sha256(convert_to((item).reason,'UTF8'))),
  '5',openpc.business_uuid((item).created_by_principal_id),
  '6',CASE WHEN (item).assignee_principal_id IS NULL THEN 0 ELSE 1 END,
  '8',CASE WHEN (item).claimed_by_principal_id IS NULL THEN 0 ELSE 1 END,
  '10',CASE WHEN (item).completed_by_principal_id IS NULL THEN 0 ELSE 1 END)
  || CASE WHEN (item).assignee_principal_id IS NULL THEN '{}'::jsonb
     ELSE jsonb_build_object('7',openpc.business_uuid((item).assignee_principal_id)) END
  || CASE WHEN (item).claimed_by_principal_id IS NULL THEN '{}'::jsonb
     ELSE jsonb_build_object('9',openpc.business_uuid((item).claimed_by_principal_id)) END
  || CASE WHEN (item).completed_by_principal_id IS NULL THEN '{}'::jsonb
     ELSE jsonb_build_object('11',openpc.business_uuid((item).completed_by_principal_id)) END
$$;
CREATE OR REPLACE FUNCTION openpc.assert_work_item_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.work_item%ROWTYPE; before_state jsonb; after_state jsonb;
 before_projection jsonb; after_projection jsonb; actor uuid;
BEGIN
 IF receipt.profile_version<>1 OR receipt.catalog_operation_id NOT IN
  ('CFG-OP-CREATE-WORK-ITEM','CFG-OP-UPDATE-WORK-ITEM','CFG-OP-CLAIM-WORK-ITEM','CFG-OP-COMPLETE-WORK-ITEM')
 THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-PROFILE'; END IF;
 SELECT * INTO STRICT item FROM control.work_item w WHERE w.participant_id=receipt.participant_id
  AND w.privacy_domain_id=receipt.privacy_domain_id AND w.work_item_id=receipt.aggregate_id;
 SELECT principal_id INTO STRICT actor FROM control.mutation_evidence e
  WHERE e.participant_id=receipt.participant_id AND e.privacy_domain_id=receipt.privacy_domain_id
   AND e.operation_id=receipt.operation_id AND e.action_intent_id=receipt.action_intent_id
   AND e.catalog_operation_id=receipt.catalog_operation_id AND e.aggregate_id=receipt.aggregate_id
   AND e.candidate_digest=receipt.candidate_digest;
 before_state:=openpc.business_cbor(receipt.before_state_preimage);
 after_state:=openpc.business_cbor(receipt.after_state_preimage);
 before_projection:=before_state->8; after_projection:=after_state->8;
 IF receipt.after_existence<>1 OR receipt.after_revision<>item.row_version
  OR after_projection IS DISTINCT FROM openpc.work_item_business_projection(item)
 THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-ACTUAL-STATE'; END IF;
 IF receipt.catalog_operation_id='CFG-OP-CREATE-WORK-ITEM' THEN
  IF receipt.before_existence<>0 OR receipt.before_revision<>0 OR receipt.after_revision<>1
   OR item.state<>'OPEN' OR item.created_by_principal_id<>actor
   OR item.claimed_by_principal_id IS NOT NULL OR item.completed_by_principal_id IS NOT NULL
   OR (item.assignee_principal_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM control.principal p
    WHERE p.participant_id=item.participant_id AND p.principal_id=item.assignee_principal_id AND p.state='ACTIVE'))
  THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-CREATE'; END IF;
 ELSE
  IF receipt.before_existence<>1 OR receipt.after_revision<>receipt.before_revision+1
   OR jsonb_typeof(before_projection) IS DISTINCT FROM 'object'
   OR NOT before_projection ?& ARRAY['0','1','2','3','4','5','6','8','10']
   OR before_projection-ARRAY['0','1','2','3','4','5','6','7','8','9','10','11']<>'{}'::jsonb
   OR EXISTS (SELECT 1 FROM (VALUES ('6','7'),('8','9'),('10','11')) AS presence(marker,value)
     WHERE before_projection->marker NOT IN ('0'::jsonb,'1'::jsonb)
       OR (before_projection->marker='1'::jsonb) IS DISTINCT FROM (before_projection ? value))
  THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-BEFORE-STATE'; END IF;
  IF receipt.catalog_operation_id='CFG-OP-UPDATE-WORK-ITEM' THEN
   IF before_projection->>'1'<>'OPEN' OR item.state<>'OPEN'
    OR before_projection-ARRAY['3','4'] IS DISTINCT FROM after_projection-ARRAY['3','4']
    OR before_projection->'3'=after_projection->'3'
   THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-UPDATE'; END IF;
  ELSIF receipt.catalog_operation_id='CFG-OP-CLAIM-WORK-ITEM' THEN
   IF before_projection->>'1'<>'OPEN' OR item.state<>'CLAIMED'
    OR before_projection-ARRAY['1','6','7','8','9'] IS DISTINCT FROM after_projection-ARRAY['1','6','7','8','9']
    OR (before_projection->'6'='1'::jsonb AND before_projection->'7' IS DISTINCT FROM openpc.business_uuid(actor))
    OR before_projection->'8' IS DISTINCT FROM '0'::jsonb
    OR item.assignee_principal_id IS DISTINCT FROM actor OR item.claimed_by_principal_id IS DISTINCT FROM actor
    OR item.completed_by_principal_id IS NOT NULL
   THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-CLAIM'; END IF;
  ELSE
   IF before_projection->>'1'<>'CLAIMED' OR item.state<>'COMPLETED'
    OR before_projection-ARRAY['1','10','11'] IS DISTINCT FROM after_projection-ARRAY['1','10','11']
    OR before_projection->'10' IS DISTINCT FROM '0'::jsonb
    OR item.assignee_principal_id IS DISTINCT FROM actor OR item.claimed_by_principal_id IS DISTINCT FROM actor
    OR item.completed_by_principal_id IS DISTINCT FROM actor
   THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-COMPLETE'; END IF;
  END IF;
 END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_work_item_effect_receipt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.audit_occurrence%ROWTYPE; before_projection jsonb;
BEGIN
 -- WHEN is evaluated when the row changes, so later context changes cannot
 -- remove the queued check. Internal source-owned effects retain their owners.
 SELECT * INTO STRICT receipt FROM control.audit_occurrence r WHERE r.participant_id=NEW.participant_id
  AND r.privacy_domain_id=NEW.privacy_domain_id AND r.aggregate_type='work-item'
  AND r.aggregate_id=NEW.work_item_id AND r.after_revision=NEW.row_version
  AND r.catalog_operation_id IN ('CFG-OP-CREATE-WORK-ITEM','CFG-OP-UPDATE-WORK-ITEM',
   'CFG-OP-CLAIM-WORK-ITEM','CFG-OP-COMPLETE-WORK-ITEM');
 IF TG_OP='INSERT' THEN before_projection:='{}'::jsonb;
 ELSE before_projection:=openpc.work_item_business_projection(OLD); END IF;
 IF openpc.business_cbor(receipt.before_state_preimage)->8 IS DISTINCT FROM before_projection
  OR openpc.business_cbor(receipt.after_state_preimage)->8 IS DISTINCT FROM openpc.work_item_business_projection(NEW)
  OR receipt.before_revision IS DISTINCT FROM (CASE WHEN TG_OP='INSERT' THEN 0 ELSE OLD.row_version END)
 THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-EFFECT-RECEIPT'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS work_item_effect_receipt ON control.work_item;
CREATE CONSTRAINT TRIGGER work_item_effect_receipt AFTER INSERT OR UPDATE ON control.work_item
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
 WHEN (current_setting('openpc.action_intent_id',true) IN ('ACT-WORK_ITEMS_CREATE_RESOURCE-V1',
  'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1','ACT-OPERATIONS_UPDATE_CLAIM-V1','ACT-OPERATIONS_UPDATE_COMPLETE-V1'))
 EXECUTE FUNCTION openpc.check_work_item_effect_receipt();
`;

/** Shared lifecycle; native failure inserts require their distinct source owner. */
export const workItemLifecycleGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.enforce_work_item_lifecycle()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.work_item';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW."state" <> 'OPEN' OR NEW."row_version" <> 1
       OR NEW."claimed_by_principal_id" IS NOT NULL OR NEW."completed_by_principal_id" IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.work_item initial state';
    END IF;
    -- Public remediation creation keeps its business receipt owner. Every
    -- internal remediation insert must instead prove native completion custody;
    -- context chooses the checker, never supplies its authorization.
    IF openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
      OR (NEW.kind='REMEDIATION' AND openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-WORK_ITEMS_CREATE_RESOURCE-V1') THEN
      PERFORM openpc.check_notification_completion_remediation_effect(NEW);
    END IF;
    IF current_setting('openpc.action_intent_id',true)='ACT-EVIDENCE_EXPORT_RECORDS-V1' AND NEW.kind='DELIVERY_FAILURE' THEN
      PERFORM openpc.check_notification_delivery_failure_work(NEW);
    END IF;
    RETURN NEW;
  END IF;
  IF row(NEW."work_item_id",NEW."participant_id",NEW."privacy_domain_id",NEW."kind",
         NEW."resource_ref",NEW."created_by_principal_id",NEW."created_at")
     IS DISTINCT FROM
     row(OLD."work_item_id",OLD."participant_id",OLD."privacy_domain_id",OLD."kind",
         OLD."resource_ref",OLD."created_by_principal_id",OLD."created_at") THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.work_item identity';
  END IF;
  IF NOT ((OLD."state" = 'OPEN' AND NEW."state" = 'OPEN')
          OR (OLD."state" = 'OPEN' AND NEW."state" = 'CLAIMED')
          OR (OLD."state" = 'CLAIMED' AND NEW."state" = 'COMPLETED')
          OR (OLD."state" IN ('OPEN','CLAIMED') AND NEW."state" = 'CANCELLED')) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6022-INVALID-STATE-TRANSITION', DETAIL = 'control.work_item lifecycle';
  END IF;
  IF NEW."assignee_principal_id" IS DISTINCT FROM OLD."assignee_principal_id"
     AND NOT (OLD."state" = 'OPEN' AND NEW."state" = 'CLAIMED'
              AND OLD."assignee_principal_id" IS NULL) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.work_item assignee';
  END IF;
  IF NEW."row_version" <> OLD."row_version" + 1 OR NEW."updated_at" <= OLD."updated_at" THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.work_item revision';
  END IF;
  IF NEW."state" = 'OPEN' AND
     (NEW."claimed_by_principal_id" IS NOT NULL OR NEW."completed_by_principal_id" IS NOT NULL) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.work_item open actor';
  ELSIF NEW."state" = 'CLAIMED' AND
        (NEW."claimed_by_principal_id" IS NULL OR NEW."completed_by_principal_id" IS NOT NULL
         OR NEW."assignee_principal_id" IS DISTINCT FROM NEW."claimed_by_principal_id") THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.work_item claim actor';
  ELSIF NEW."state" = 'COMPLETED' AND
        (NEW."claimed_by_principal_id" IS NULL OR NEW."completed_by_principal_id" IS NULL
         OR NEW."completed_by_principal_id" IS DISTINCT FROM NEW."claimed_by_principal_id"
         OR NEW."assignee_principal_id" IS DISTINCT FROM NEW."completed_by_principal_id") THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.work_item completion actor';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS work_item_lifecycle ON "control"."work_item";
CREATE TRIGGER work_item_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON "control"."work_item"
FOR EACH ROW EXECUTE FUNCTION openpc.enforce_work_item_lifecycle();
`;
