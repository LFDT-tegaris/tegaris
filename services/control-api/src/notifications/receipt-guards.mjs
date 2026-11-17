/** Public CREATE/ACK retains its audit receipt path. Workload creation uses the
 * distinct immutable occurrence pair and its complete atomic publication proof. */
export const notificationReceiptGuardsSql = `
ALTER TABLE control.notification FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.notification FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT,INSERT,UPDATE ON control.notification TO openpc_control_runtime;
GRANT SELECT ON control.notification TO openpc_control_reader;
CREATE OR REPLACE FUNCTION openpc.notification_business_projection(item control.notification)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',(item).severity,'1',(item).state,'2',(item).message_key,
  '3',CASE WHEN (item).resource_ref IS NULL THEN 0 ELSE 1 END,
  '5',openpc.business_bytes(decode(substr((item).candidate_digest,8),'hex')))
  || CASE WHEN (item).resource_ref IS NULL THEN '{}'::jsonb
     ELSE jsonb_build_object('4',(item).resource_ref) END
$$;
CREATE OR REPLACE FUNCTION openpc.assert_notification_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.notification%ROWTYPE; before_projection jsonb; after_projection jsonb;
BEGIN
 IF receipt.profile_version<>1 OR receipt.catalog_operation_id NOT IN
  ('CFG-OP-CREATE-NOTIFICATION','CFG-OP-ACKNOWLEDGE-NOTIFICATION')
 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-PROFILE'; END IF;
 SELECT * INTO STRICT item FROM control.notification n WHERE n.participant_id=receipt.participant_id
  AND n.privacy_domain_id=receipt.privacy_domain_id AND n.notification_id=receipt.aggregate_id;
 before_projection:=openpc.business_cbor(receipt.before_state_preimage)->8;
 after_projection:=openpc.business_cbor(receipt.after_state_preimage)->8;
 IF receipt.after_existence<>1 OR receipt.after_revision<>item.revision
  OR after_projection IS DISTINCT FROM openpc.notification_business_projection(item)
 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ACTUAL-STATE'; END IF;
 IF receipt.catalog_operation_id='CFG-OP-CREATE-NOTIFICATION' THEN
  IF receipt.before_existence<>0 OR receipt.before_revision<>0 OR receipt.after_revision<>1
   OR item.state<>'UNREAD' OR item.candidate_digest IS DISTINCT FROM 'sha256:'||encode(receipt.candidate_digest,'hex')
  THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-CREATE'; END IF;
 ELSE
  IF receipt.before_existence<>1 OR receipt.after_revision<>receipt.before_revision+1
   OR before_projection->>'1' NOT IN ('UNREAD','READ') OR item.state<>'ACKNOWLEDGED'
   OR before_projection-'1' IS DISTINCT FROM after_projection-'1'
  THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ACKNOWLEDGE'; END IF;
 END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 IF NEW.participant_id<>openpc.current_participant_id() OR NEW.privacy_domain_id<>openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='INSERT' THEN
  IF current_setting('openpc.action_intent_id')='ACT-EVIDENCE_EXPORT_RECORDS-V1' THEN
   PERFORM openpc.admit_notification_occurrence_metadata(NEW);
   RETURN NEW;
  END IF;
  IF current_setting('openpc.action_intent_id')<>'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1'
   OR NEW.state<>'UNREAD' OR NEW.revision<>1
  THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-CREATE'; END IF;
 ELSE
  IF current_setting('openpc.action_intent_id')<>'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1'
   OR OLD.state NOT IN ('UNREAD','READ') OR NEW.state<>'ACKNOWLEDGED' OR NEW.revision<>OLD.revision+1
   OR ROW(NEW.participant_id,NEW.privacy_domain_id,NEW.notification_id,NEW.severity,NEW.resource_ref,
     NEW.message_key,NEW.candidate_digest,NEW.created_at) IS DISTINCT FROM
      ROW(OLD.participant_id,OLD.privacy_domain_id,OLD.notification_id,OLD.severity,OLD.resource_ref,
     OLD.message_key,OLD.candidate_digest,OLD.created_at)
  THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ACKNOWLEDGE'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_mutation_guard ON control.notification;
CREATE TRIGGER notification_mutation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_mutation();
CREATE OR REPLACE FUNCTION openpc.check_notification_effect_receipt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.audit_occurrence%ROWTYPE; before_projection jsonb;
BEGIN
 -- A signed occurrence reserves its exact notification identity. This selects
 -- the proof family only; the full checker below still requires both originals,
 -- exact metadata and every payload/inbox/cursor/outbox effect. No GUC selects
 -- or skips this deferred admission, and a malformed pair never falls back.
 IF TG_OP='INSERT' AND EXISTS(
  SELECT 1 FROM control.notification_occurrence_preparation p
  JOIN control.notification_occurrence_observation o USING(participant_id,privacy_domain_id,preparation_id)
  WHERE p.participant_id=NEW.participant_id AND p.privacy_domain_id=NEW.privacy_domain_id
   AND p.family='NotificationOccurrenceReceiptV1'
   AND openpc.business_cbor(o.receipt_payload)->'6'=openpc.business_uuid(NEW.notification_id)
 ) THEN
  PERFORM openpc.check_notification_occurrence_metadata_effect(NEW);
  RETURN NEW;
 END IF;
 -- Ordinary public CREATE/ACK keeps its unconditional audit receipt check.
 SELECT * INTO STRICT receipt FROM control.audit_occurrence r WHERE r.participant_id=NEW.participant_id
  AND r.privacy_domain_id=NEW.privacy_domain_id AND r.aggregate_type='notification'
  AND r.aggregate_id=NEW.notification_id AND r.after_revision=NEW.revision
  AND r.catalog_operation_id=(CASE WHEN TG_OP='INSERT' THEN 'CFG-OP-CREATE-NOTIFICATION'
    ELSE 'CFG-OP-ACKNOWLEDGE-NOTIFICATION' END);
 IF TG_OP='INSERT' THEN before_projection:='{}'::jsonb;
 ELSE before_projection:=openpc.notification_business_projection(OLD); END IF;
 IF openpc.business_cbor(receipt.before_state_preimage)->8 IS DISTINCT FROM before_projection
  OR openpc.business_cbor(receipt.after_state_preimage)->8 IS DISTINCT FROM openpc.notification_business_projection(NEW)
  OR receipt.before_revision IS DISTINCT FROM (CASE WHEN TG_OP='INSERT' THEN 0 ELSE OLD.revision END)
 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-EFFECT-RECEIPT'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_effect_receipt ON control.notification;
CREATE CONSTRAINT TRIGGER notification_effect_receipt AFTER INSERT OR UPDATE ON control.notification
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_notification_effect_receipt();
REVOKE ALL ON FUNCTION openpc.notification_business_projection(control.notification),
 openpc.assert_notification_receipt(control.audit_occurrence),openpc.guard_notification_mutation(),
 openpc.check_notification_effect_receipt() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.notification_business_projection(control.notification),
 openpc.assert_notification_receipt(control.audit_occurrence) TO openpc_control_runtime;
`;
