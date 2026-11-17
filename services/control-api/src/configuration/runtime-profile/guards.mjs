export const runtimeTargetProfileBindingGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1','runtime-target-profile-binding','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RUNTIME_PROFILE_BINDING'),
 ('ACT-RUNTIME_TARGET_PROFILES_READ_RESOURCE-V1','runtime-target-profile-binding','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_MINIMAL','RUNTIME_PROFILE_BINDING_READ')
ON CONFLICT(action_intent_id) DO NOTHING;

ALTER TABLE control.runtime_target_profile_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.runtime_target_profile_binding FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_target_profile_binding()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE expected text;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004-RUNTIME-PROFILE-IMMUTABLE'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1'
   OR NEW.participant_id<>openpc.current_participant_id()
   OR NEW.privacy_domain_id<>openpc.current_privacy_domain_id()
   OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid
   OR NOT pg_has_role(current_user,'openpc_control_runtime','MEMBER') THEN
  RAISE EXCEPTION 'PC-AUTH-0005-RUNTIME-PROFILE-OWNER'; END IF;
 -- Snapshot publication takes UPDATE on this same root before reading mappings.
 PERFORM 1 FROM control.participant WHERE participant_id=NEW.participant_id FOR SHARE;
 PERFORM 1 FROM control.runtime_target WHERE runtime_target_id=NEW.runtime_target_id
  AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
  AND revision=NEW.target_revision AND state IN ('OFFLINE','DISCOVERED')
  AND desired_generation_digest IS NULL AND active_generation_digest IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007-RUNTIME-PROFILE-TARGET'; END IF;
 expected:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
   'purpose','openpc.identity.runtime-target-profile-binding.v1',
   'participant_id',NEW.participant_id::text,'privacy_domain_id',NEW.privacy_domain_id::text,
   'runtime_target_id',NEW.runtime_target_id::text,'target_profile_id',NEW.target_profile_id)),'UTF8')),'hex');
 IF expected<>NEW.binding_digest THEN RAISE EXCEPTION 'PC-DATA-6004-RUNTIME-PROFILE-DIGEST'; END IF;
 NEW.created_at:=clock_timestamp();
 NEW.updated_at:=NEW.created_at;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_runtime_target_profile_binding() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.guard_runtime_target_profile_binding() TO openpc_control_runtime;
DROP TRIGGER IF EXISTS runtime_profile_binding_owner ON control.runtime_target_profile_binding;
CREATE TRIGGER runtime_profile_binding_owner BEFORE INSERT OR UPDATE OR DELETE ON control.runtime_target_profile_binding
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_target_profile_binding();

CREATE OR REPLACE FUNCTION openpc.require_runtime_target_profile_binding()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.publication_operation_id AND evidence.aggregate_id=NEW.binding_id
   AND evidence.aggregate_type='runtime-target-profile-binding' AND evidence.aggregate_version=1
   AND evidence.catalog_operation_id='CFG-OP-CREATE-RUNTIME-TARGET-PROFILE'
   AND evidence.action_intent_id='ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1'
   AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.binding_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND candidate.action_intent_id=evidence.action_intent_id AND receipt.action_intent_id=evidence.action_intent_id
   AND receipt.expected_aggregate_version=0 AND receipt.terminal_state='COMMITTED'
   AND candidate.candidate_document->>'runtimeTargetRef'='urn:openpc:resource:'||NEW.runtime_target_id::text
   AND candidate.candidate_document->>'targetRevision'=NEW.target_revision::text
   AND candidate.candidate_document->>'targetProfileId'=NEW.target_profile_id
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.binding_id::text
   AND receipt.result_payload->>'revision'='1'
   AND EXISTS(SELECT 1 FROM control.approval_request approval
    WHERE approval.participant_id=NEW.participant_id AND approval.privacy_domain_id=NEW.privacy_domain_id
     AND approval.subject_id=candidate.mutation_candidate_id AND approval.subject_digest=candidate.candidate_digest
     AND approval.subject_type='CONFIGURATION_CANDIDATE' AND approval.state='APPROVED'
     AND approval.maker_principal_id<>approval.checker_principal_id)
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.binding_id
    AND event.aggregate_type='runtime-target-profile-binding' AND event.aggregate_sequence=1
    AND event.event_type='openpc.runtime-target.profile-bound.v1'
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'=NEW.publication_authority_digest
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(candidate.candidate_digest,'hex')))
 THEN RAISE EXCEPTION 'PC-AUTH-0005-RUNTIME-PROFILE-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.require_runtime_target_profile_binding() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.require_runtime_target_profile_binding() TO openpc_control_runtime;
DROP TRIGGER IF EXISTS runtime_profile_binding_complete ON control.runtime_target_profile_binding;
CREATE CONSTRAINT TRIGGER runtime_profile_binding_complete AFTER INSERT ON control.runtime_target_profile_binding
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_runtime_target_profile_binding();
`;
