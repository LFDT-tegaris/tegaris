/** Conditional governance is derived from durable lifecycle state, never from a caller's requested target. */
export const signingGovernanceSql = `
CREATE OR REPLACE FUNCTION openpc.signing_governance_required(p_participant uuid,p_privacy uuid,p_rotation uuid,p_action text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.signing_key_rotation r WHERE r.participant_id=p_participant AND r.privacy_domain_id=p_privacy
  AND r.rotation_id=p_rotation AND ((p_action='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND
   (r.state='FAILED' OR EXISTS(SELECT 1 FROM control.signing_rotation_authority_hold h
     WHERE h.participant_id=r.participant_id AND h.privacy_domain_id=r.privacy_domain_id AND h.rotation_id=r.rotation_id AND h.state='ACTIVE')))
   OR (p_action='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' AND EXISTS(SELECT 1 FROM control.signing_rotation_command c
    WHERE c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id AND c.rotation_id=r.rotation_id
     AND c.from_revision=r.revision AND c.state='FAILED' AND c.result_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH'))))
$$;
CREATE OR REPLACE FUNCTION openpc.signing_governance_context(p_rotation uuid,p_action text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE rotation control.signing_key_rotation%ROWTYPE; original control.signing_rotation_command%ROWTYPE;
 hold control.signing_rotation_authority_hold%ROWTYPE; prior_generation uuid; attempts jsonb; selections jsonb;
 authority jsonb; session_rows jsonb; first_attempt uuid; target text; resume_state text; resume_revision bigint; effects jsonb;
BEGIN
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND rotation_id=p_rotation;
 IF NOT openpc.signing_governance_required(rotation.participant_id,rotation.privacy_domain_id,p_rotation,p_action)
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GOVERNANCE-NOT-REQUIRED'; END IF;
 SELECT * INTO hold FROM control.signing_rotation_authority_hold WHERE participant_id=rotation.participant_id
  AND privacy_domain_id=rotation.privacy_domain_id AND rotation_id=p_rotation AND state='ACTIVE';
 SELECT c.* INTO STRICT original FROM control.signing_rotation_command c WHERE c.participant_id=rotation.participant_id
  AND c.privacy_domain_id=rotation.privacy_domain_id AND c.rotation_id=p_rotation AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'
  AND ((hold.hold_id IS NOT NULL AND c.operation_id=hold.operation_id) OR
   (hold.hold_id IS NULL AND rotation.state='FAILED' AND c.state='FAILED' AND c.result_revision=rotation.revision AND c.result_kind='PROVIDER_REJECTED') OR
   (hold.hold_id IS NULL AND p_action='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'
    AND c.state='FAILED' AND c.from_revision=rotation.revision AND c.result_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH'))
  ORDER BY c.updated_at DESC,c.operation_id DESC LIMIT 1;
 SELECT attempt_id INTO STRICT first_attempt FROM control.signing_provider_attempt WHERE participant_id=rotation.participant_id
  AND privacy_domain_id=rotation.privacy_domain_id AND operation_id=original.operation_id AND request->>'method'<>'SIGN_RECEIPT'
  ORDER BY attempt_id LIMIT 1;
 authority:=openpc.signing_attempt_authority_status(first_attempt);
 SELECT coalesce(jsonb_agg(value-ARRAY['idle_expires_at','row_version'] ORDER BY value->>'session_id'),'[]'::jsonb)
  INTO session_rows FROM jsonb_array_elements(authority->'dependencies'->'session') value;
 authority:=jsonb_set(authority,'{dependencies,session}',session_rows);
 SELECT coalesce(jsonb_agg(value-'row_version' ORDER BY value->>'credential_id'),'[]'::jsonb)
  INTO session_rows FROM jsonb_array_elements(authority->'dependencies'->'credential') value;
 authority:=jsonb_set(authority,'{dependencies,credential}',session_rows);
 SELECT generation_id INTO prior_generation FROM control.signing_authorization_generation WHERE participant_id=rotation.participant_id
  AND privacy_domain_id=rotation.privacy_domain_id AND rotation_id=p_rotation AND state='CONSUMED' ORDER BY result_revision DESC LIMIT 1;
 SELECT jsonb_agg(jsonb_build_object('attemptId',a.attempt_id,'method',a.request->>'method','state',a.state,
  'requestDigest',encode(a.request_digest,'hex'),'observationDigest',encode(a.observation_digest,'hex'),
  'dispatchedAtNs',a.dispatched_at_ns::text,'latestObservationDigest',encode(o.observation_digest,'hex')) ORDER BY a.attempt_id)
 INTO attempts FROM control.signing_provider_attempt a LEFT JOIN LATERAL(SELECT observation_digest FROM control.signing_rotation_observation
  WHERE participant_id=a.participant_id AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id
  ORDER BY observed_at_ns DESC,observation_id DESC LIMIT 1) o ON true
 WHERE a.participant_id=rotation.participant_id AND a.privacy_domain_id=rotation.privacy_domain_id AND a.operation_id=original.operation_id
  AND a.request->>'method'<>'SIGN_RECEIPT';
 SELECT jsonb_agg(jsonb_build_object('profileDigest',encode(s.profile_digest,'hex'),'signerId',s.signer_id,
  'selectionVersion',s.row_version::text,'admissionVersion',s.admission_version::text,'fenceGeneration',s.fence_generation::text,'fencedOperationId',s.fenced_operation_id)
  ORDER BY s.profile_digest) INTO selections FROM control.business_signing_selection s JOIN control.business_signing_key k
  USING(participant_id,privacy_domain_id,signer_id) WHERE s.participant_id=rotation.participant_id AND s.privacy_domain_id=rotation.privacy_domain_id
  AND s.environment_id=rotation.environment_id AND k.workload_credential_id=rotation.workload_credential_id;
 IF p_action='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' THEN target:=original.to_state;
 ELSIF rotation.state='FAILED' THEN
  target:='RECOVERING';
  SELECT from_state,from_revision INTO STRICT resume_state,resume_revision FROM control.signing_provider_attempt
   WHERE attempt_id=first_attempt;
 ELSE target:=rotation.state; resume_state:=rotation.recovery_from_state; resume_revision:=rotation.recovery_from_revision;
 END IF;
 effects:=openpc.signing_transition_effects(p_action,rotation.state,target);
 IF effects IS NULL THEN RAISE EXCEPTION 'DATA-6022-SIGNING-GOVERNANCE-MATRIX'; END IF;
 RETURN jsonb_build_object('schema','pc.control.signing-governance-context.v1','participantId',rotation.participant_id,
  'privacyDomainId',rotation.privacy_domain_id,'rotationId',p_rotation,'actionIntentId',p_action,'revision',rotation.revision::text,
  'state',rotation.state,'cutoverAtNs',rotation.cutover_at_ns::text,'newFingerprint',rotation.new_signer_id,
  'holdId',hold.hold_id,'holdReason',hold.reason,'originalOperationId',original.operation_id,
  'originalInputDigest',encode(original.input_digest,'hex'),'originalAuthorityDigest',encode(original.authorization_snapshot_digest,'hex'),
  'originalApprovalId',original.approval_request_id,'originalApprovalDigest',encode(original.approval_candidate_digest,'hex'),
  'originalAuthority',authority,'attempts',attempts,'selections',selections,'priorGenerationId',prior_generation,
  'targetState',target,'resumeState',resume_state,'resumeRevision',resume_revision::text);
END $$;
CREATE OR REPLACE FUNCTION openpc.signing_canonical_json(p_value jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE encoded text;
BEGIN
 CASE jsonb_typeof(p_value)
 WHEN 'object' THEN SELECT '{'||coalesce(string_agg(to_jsonb(key)::text||':'||openpc.signing_canonical_json(value),',' ORDER BY key COLLATE "C"),'')||'}'
  INTO encoded FROM jsonb_each(p_value);
 WHEN 'array' THEN SELECT '['||coalesce(string_agg(openpc.signing_canonical_json(value),',' ORDER BY ordinal),'')||']'
  INTO encoded FROM jsonb_array_elements(p_value) WITH ORDINALITY entries(value,ordinal);
 ELSE encoded:=p_value::text;
 END CASE;
 RETURN encoded;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_signing_generation_current(p_generation uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE generation control.signing_authorization_generation%ROWTYPE; candidate control.mutation_candidate%ROWTYPE;
BEGIN
 SELECT * INTO STRICT generation FROM control.signing_authorization_generation WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND generation_id=p_generation AND state='STAGED';
 SELECT * INTO STRICT candidate FROM control.mutation_candidate WHERE participant_id=generation.participant_id
  AND privacy_domain_id=generation.privacy_domain_id AND mutation_candidate_id=generation.candidate_id
  AND candidate_digest=generation.candidate_digest AND state='APPROVED' AND expires_at>clock_timestamp();
 IF candidate.candidate_document->'context' IS DISTINCT FROM openpc.signing_governance_context(generation.rotation_id,generation.action_intent_id)
  OR NOT EXISTS(SELECT 1 FROM control.approval_request a JOIN control.approval_decision_record d
   USING(participant_id,privacy_domain_id,approval_request_id) WHERE a.participant_id=generation.participant_id
    AND a.privacy_domain_id=generation.privacy_domain_id AND a.subject_id=generation.candidate_id AND a.subject_digest=generation.candidate_digest
    AND a.subject_version=generation.from_revision AND a.state='APPROVED' AND a.expires_at>clock_timestamp()
    AND d.decision='APPROVE' AND d.approver_principal_id<>a.maker_principal_id AND d.candidate_digest=generation.candidate_digest)
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GOVERNANCE-STALE'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_signing_generation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE candidate control.mutation_candidate%ROWTYPE; context jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-SIGNING-GENERATION'; END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT candidate FROM control.mutation_candidate WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
   AND mutation_candidate_id=NEW.candidate_id AND candidate_digest=NEW.candidate_digest AND action_intent_id=NEW.action_intent_id
   AND resource_id=NEW.rotation_id AND expected_revision=NEW.from_revision AND state IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') AND expires_at>clock_timestamp();
  context:=openpc.signing_governance_context(NEW.rotation_id,NEW.action_intent_id);
  IF NEW.state<>'STAGED' OR NEW.consumed_operation_id IS NOT NULL OR NEW.result_revision IS NOT NULL
   OR NEW.action_intent_id IS DISTINCT FROM openpc.current_action_intent_id()
   OR candidate.candidate_document IS DISTINCT FROM jsonb_build_object('schema','pc.control.signing-governance-candidate.v1',
    'context',context,'input',candidate.candidate_document->'input','maker',candidate.candidate_document->'maker')
   OR NEW.candidate_digest<>sha256(convert_to(openpc.signing_canonical_json(candidate.candidate_document),'UTF8'))
   OR NEW.input_digest<>sha256(convert_to(openpc.signing_canonical_json(candidate.candidate_document->'input'),'UTF8'))
   OR NEW.original_operation_id::text IS DISTINCT FROM context->>'originalOperationId'
   OR NEW.prior_generation_id::text IS DISTINCT FROM context->>'priorGenerationId'
   OR NEW.hold_id::text IS DISTINCT FROM context->>'holdId' OR NEW.target_state IS DISTINCT FROM context->>'targetState'
   OR NEW.resume_state IS DISTINCT FROM context->>'resumeState' OR NEW.resume_revision::text IS DISTINCT FROM context->>'resumeRevision'
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GENERATION-CANDIDATE'; END IF;
 ELSE
  IF OLD.state<>'STAGED' OR NEW.state<>'CONSUMED' OR NEW.consumed_operation_id IS DISTINCT FROM openpc.current_operation_id()
   OR NEW.result_revision<>NEW.from_revision+1
   OR (to_jsonb(NEW)-ARRAY['state','consumed_operation_id','result_revision']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','consumed_operation_id','result_revision'])
   OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_history h JOIN control.signing_rotation_command c USING(participant_id,privacy_domain_id,operation_id)
    WHERE h.participant_id=NEW.participant_id AND h.privacy_domain_id=NEW.privacy_domain_id AND h.rotation_id=NEW.rotation_id
     AND h.operation_id=NEW.consumed_operation_id AND h.revision=NEW.result_revision AND h.receipt_id IS NOT NULL
     AND c.authorization_generation_id=NEW.generation_id AND c.from_revision=NEW.from_revision AND c.input_digest=NEW.input_digest)
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GENERATION-SIGNED-COMMIT'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_generation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_authorization_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_generation();
CREATE OR REPLACE FUNCTION openpc.check_signing_generation_completion()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.state<>'CONSUMED' THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_candidate candidate JOIN control.signing_rotation_command command
  ON command.participant_id=candidate.participant_id AND command.privacy_domain_id=candidate.privacy_domain_id
   AND command.operation_id=candidate.consumed_operation_id JOIN control.audit_occurrence receipt
   ON receipt.participant_id=command.participant_id AND receipt.privacy_domain_id=command.privacy_domain_id AND receipt.operation_id=command.operation_id
  WHERE candidate.mutation_candidate_id=NEW.candidate_id AND candidate.state='CONSUMED' AND candidate.consumed_operation_id=NEW.consumed_operation_id
   AND command.authorization_generation_id=NEW.generation_id AND command.state IN ('SUCCEEDED','FAILED') AND command.result_revision=NEW.result_revision
   AND receipt.after_revision=NEW.result_revision AND receipt.before_revision=NEW.from_revision
   AND (NEW.hold_id IS NULL OR EXISTS(SELECT 1 FROM control.signing_rotation_authority_hold h WHERE h.hold_id=NEW.hold_id
    AND h.state='CLEARED' AND h.cleared_by_operation_id=NEW.consumed_operation_id)))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GENERATION-INCOMPLETE'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER signing_generation_complete AFTER UPDATE ON control.signing_authorization_generation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_signing_generation_completion();
`;
export const signingGovernanceGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.signing_governance_required(uuid,uuid,uuid,text),openpc.signing_governance_context(uuid,text)
 TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.check_signing_generation_current(uuid),openpc.signing_canonical_json(jsonb)
 TO openpc_control_runtime,openpc_control_platform_runtime;
-- The shared pure encoder is also consumed by Control custody/checkpoint guards.
-- Its owning migration must preserve that consumer across populated upgrades.
GRANT EXECUTE ON FUNCTION openpc.signing_canonical_json(jsonb) TO openpc_control_worker;
GRANT INSERT,UPDATE(state,consumed_operation_id,result_revision) ON control.signing_authorization_generation TO openpc_control_runtime;
GRANT UPDATE(state,cleared_by_operation_id) ON control.signing_rotation_authority_hold TO openpc_control_runtime;
`;
