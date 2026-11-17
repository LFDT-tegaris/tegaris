export const explorerCustodyGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1','privacy-explorer-profile','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','EXPLORER_DISCLOSURE'),
 ('ACT-PRIVACY_EXPLORER_READ_OCCURRENCE-V1','privacy-explorer-occurrence','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','EXPLORER_DISCLOSURE_STATUS')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
 (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
  idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
 ('ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1','privacy-explorer-profile','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','EXPLORER_DISCLOSURE'),
 ('ACT-PRIVACY_EXPLORER_READ_OCCURRENCE-V1','privacy-explorer-occurrence','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','EXPLORER_DISCLOSURE_STATUS')))<>2 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-DISCLOSURE-ACTION';
 END IF;
END $$;
ALTER TABLE control.privacy_explorer_execution FORCE ROW LEVEL SECURITY;
ALTER TABLE control.privacy_explorer_continuation FORCE ROW LEVEL SECURITY;
ALTER TABLE control.privacy_explorer_route_audit FORCE ROW LEVEL SECURITY;
GRANT SELECT ON control.privacy_explorer_route_audit TO openpc_control_maintenance;
CREATE OR REPLACE FUNCTION openpc.guard_explorer_custody()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' OR current_setting('openpc.action_intent_id')<>'ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN
  RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-CUSTODY';
 END IF;
 IF TG_TABLE_NAME='privacy_explorer_execution' THEN
  IF TG_OP='INSERT' THEN
   IF NEW.revision<>0 OR NEW.disposition<>'OPEN' OR NEW.evidence IS NOT NULL
    OR NEW.deadline_at<=clock_timestamp() THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
   NEW.created_at:=clock_timestamp();
  ELSE
   IF OLD.disposition<>'OPEN' OR
    (to_jsonb(NEW)-ARRAY['snapshot','revision','disposition','evidence','evidence_digest','release_claim_id','release_authorized_at','updated_at'])
      IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['snapshot','revision','disposition','evidence','evidence_digest','release_claim_id','release_authorized_at','updated_at']) THEN
    RAISE EXCEPTION 'PC-DATA-6007';
   END IF;
   IF NEW.revision=OLD.revision THEN
    IF NEW.snapshot IS DISTINCT FROM OLD.snapshot OR NEW.evidence IS DISTINCT FROM OLD.evidence
     OR NEW.evidence_digest IS DISTINCT FROM OLD.evidence_digest
     OR NEW.disposition NOT IN ('RELEASE_AUTHORIZED','INTERRUPTED') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   ELSIF NEW.revision<>OLD.revision+1 OR NEW.disposition NOT IN ('OPEN','SUPPRESSED')
     OR OLD.evidence IS NOT NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   IF NEW.disposition='RELEASE_AUTHORIZED' AND NEW.deadline_at<=clock_timestamp() THEN
    RAISE EXCEPTION 'PC-OPS-9003';
   END IF;
  END IF;
  NEW.updated_at:=clock_timestamp();
 ELSE
  IF TG_OP='INSERT' AND NEW.consumed_by IS NOT NULL THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  IF TG_OP='UPDATE' AND (OLD.consumed_by IS NOT NULL OR NEW.consumed_by IS NULL
    OR (to_jsonb(NEW)-'consumed_by') IS DISTINCT FROM (to_jsonb(OLD)-'consumed_by')) THEN
    RAISE EXCEPTION 'PC-DATA-6007';
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS explorer_execution_guard ON control.privacy_explorer_execution;
CREATE TRIGGER explorer_execution_guard BEFORE INSERT OR UPDATE OR DELETE ON control.privacy_explorer_execution
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_explorer_custody();
DROP TRIGGER IF EXISTS explorer_continuation_guard ON control.privacy_explorer_continuation;
CREATE TRIGGER explorer_continuation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.privacy_explorer_continuation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_explorer_custody();
`;
