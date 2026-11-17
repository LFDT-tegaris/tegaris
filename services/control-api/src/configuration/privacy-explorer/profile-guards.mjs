export const explorerProfileGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1','privacy-explorer-profile','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EXPLORER_PROFILE_PUBLICATION'),
 ('ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1','privacy-explorer-profile','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EXPLORER_PROFILE_REVOCATION'),
 ('ACT-PRIVACY_EXPLORER_PROFILES_READ_RESOURCE-V1','privacy-explorer-profile','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EXPLORER_PROFILE_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
 (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
  idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
 ('ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1','privacy-explorer-profile','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EXPLORER_PROFILE_PUBLICATION'),
 ('ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1','privacy-explorer-profile','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EXPLORER_PROFILE_REVOCATION'),
 ('ACT-PRIVACY_EXPLORER_PROFILES_READ_RESOURCE-V1','privacy-explorer-profile','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EXPLORER_PROFILE_READ')))<>3 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-PROFILE-ACTION';
 END IF;
END $$;
ALTER TABLE control.privacy_explorer_profile FORCE ROW LEVEL SECURITY;
CREATE OR REPLACE FUNCTION openpc.guard_explorer_profile()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.profile_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.profile-'digest'),'UTF8')),'hex') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-PROFILE';
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'REGISTERED' OR NEW.revision<>1 OR NEW.revocation_operation_id IS NOT NULL
   OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>'ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1' THEN
   RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-PROFILE';
  END IF;
  NEW.created_at:=clock_timestamp();
 ELSE
  PERFORM pg_advisory_xact_lock(hashtextextended('privacy-explorer-profile:'||OLD.registration_id::text,0));
  IF (to_jsonb(NEW)-ARRAY['state','revision','revocation_operation_id']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['state','revision','revocation_operation_id'])
   OR OLD.state<>'REGISTERED' OR NEW.state<>'REVOKED' OR NEW.revision<>OLD.revision+1
   OR NEW.revocation_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>'ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1' THEN
   RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-PROFILE';
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS explorer_profile_guard ON control.privacy_explorer_profile;
CREATE TRIGGER explorer_profile_guard BEFORE INSERT OR UPDATE OR DELETE ON control.privacy_explorer_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_explorer_profile();

CREATE OR REPLACE FUNCTION openpc.require_explorer_profile_evidence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE
 operation uuid; catalog text; action text; expected_event_type text; expected bigint;
BEGIN
 IF TG_OP='INSERT' THEN
  operation:=NEW.publication_operation_id; catalog:='CFG-OP-CREATE-EXPLORER-PROFILE';
  action:='ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1'; expected_event_type:='openpc.privacy-explorer.profile.registered.v1'; expected:=0;
 ELSE
  operation:=NEW.revocation_operation_id; catalog:='CFG-OP-REVOKE-EXPLORER-PROFILE';
  action:='ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1'; expected_event_type:='openpc.privacy-explorer.profile.revoked.v1'; expected:=OLD.revision;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=operation AND evidence.aggregate_type='privacy-explorer-profile'
   AND evidence.aggregate_id=NEW.registration_id AND evidence.catalog_operation_id=catalog AND evidence.action_intent_id=action
   AND candidate.resource_id=NEW.registration_id AND candidate.state='CONSUMED' AND candidate.expected_revision=expected
   AND (TG_OP<>'INSERT' OR (candidate.candidate_document->'profile'=NEW.profile
    AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')))
   AND receipt.terminal_state='COMMITTED' AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.registration_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.registration_id
    AND event.aggregate_type='privacy-explorer-profile' AND event.event_type=expected_event_type)) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-PROFILE-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS explorer_profile_evidence ON control.privacy_explorer_profile;
CREATE CONSTRAINT TRIGGER explorer_profile_evidence AFTER INSERT OR UPDATE ON control.privacy_explorer_profile
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_explorer_profile_evidence();
`;
