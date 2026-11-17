import { signingTransitionGuardsSql } from './signing-transition-guards.mjs';
import { signingAttemptAuthoritySql } from './signing-attempt-authority.mjs';
import { signingHistoryGuardsSql } from './signing-history-guards.mjs';
import { signingAuthorizationGuardsSql } from './signing-authorization-guards.mjs';
import { signingAttestationGuardsSql } from './signing-attestation-guards.mjs';
import { signingObservationGuardsSql } from './signing-observation-guards.mjs';
import { signingRotationOperations } from '../../../../packages/security-kernel/src/signing-operations.ts';

const actions = signingRotationOperations
  .map(
    (o) =>
      `('${o.actionIntentId}','${o.resourceType}','${o.operationClass}','${o.operationClass === 'READ' ? 'LOW' : 'HIGH'}',${o.makerCheckerRequired},false,${o.operationClass !== 'READ'},'AUTHORIZED_ONLY','REDACTED','SIGNING_KEY_LIFECYCLE')`,
  )
  .join(',\n');
export const signingRotationGuardsSql = `
${signingTransitionGuardsSql}
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,
 step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ${actions} ON CONFLICT(action_intent_id) DO NOTHING;
CREATE OR REPLACE FUNCTION openpc.guard_signing_rotation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE governed boolean:=false; generation control.signing_authorization_generation%ROWTYPE; effects jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROTATION'; END IF;
 IF NEW.recovery_case_id IS NOT NULL OR (TG_OP='UPDATE' AND OLD.recovery_case_id IS NOT NULL) THEN
  PERFORM openpc.guard_identity_envelope_recovery_rotation(NEW,OLD,TG_OP);
  RETURN NEW;
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'REQUESTED' OR NEW.revision<>1 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-INITIAL-STATE'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','revision','updated_at','approval_request_id','approved_operation_id','new_signer_id','cutover_at_ns','recovery_from_state','recovery_from_revision'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','revision','updated_at','approval_request_id','approved_operation_id','new_signer_id','cutover_at_ns','recovery_from_state','recovery_from_revision'])
   OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<=OLD.updated_at THEN RAISE EXCEPTION 'DATA-6020-ROTATION-IDENTITY'; END IF;
 SELECT g.* INTO generation FROM control.signing_rotation_command c JOIN control.signing_authorization_generation g
  ON g.generation_id=c.authorization_generation_id WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
   AND c.rotation_id=NEW.rotation_id AND c.operation_id=openpc.current_operation_id()
   AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND g.state='STAGED';
 IF FOUND THEN
  PERFORM openpc.check_signing_generation_current(generation.generation_id);
  governed:=NEW.state=generation.target_state AND NEW.revision=generation.from_revision+1 AND OLD.state<>'COMPLETE'
   AND (NEW.state=OLD.state OR (OLD.state='FAILED' AND NEW.state='RECOVERING'
    AND NEW.recovery_from_state=generation.resume_state AND NEW.recovery_from_revision=generation.resume_revision));
  IF NOT governed THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GOVERNED-TARGET'; END IF;
 END IF;
 IF NOT governed AND NEW.state<>'RECOVERING' AND EXISTS(SELECT 1 FROM control.signing_rotation_command recovery
  WHERE recovery.participant_id=NEW.participant_id AND recovery.privacy_domain_id=NEW.privacy_domain_id
   AND recovery.rotation_id=NEW.rotation_id AND recovery.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1'
   AND recovery.state='ACCEPTED')
 THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-IN-PROGRESS'; END IF;
 IF OLD.approval_request_id IS NOT NULL AND (NEW.approval_request_id IS DISTINCT FROM OLD.approval_request_id OR
    NEW.approved_operation_id IS DISTINCT FROM OLD.approved_operation_id) THEN RAISE EXCEPTION 'DATA-6020-ROTATION-APPROVAL'; END IF;
 IF OLD.new_signer_id IS NOT NULL AND NEW.new_signer_id IS DISTINCT FROM OLD.new_signer_id THEN RAISE EXCEPTION 'DATA-6020-ROTATION-KEY'; END IF;
 IF OLD.cutover_at_ns IS NOT NULL AND NEW.cutover_at_ns IS DISTINCT FROM OLD.cutover_at_ns THEN RAISE EXCEPTION 'DATA-6020-ROTATION-CUTOVER'; END IF;
 IF NOT (OLD.state='REQUESTED' AND NEW.state='APPROVED') THEN
  effects:=openpc.signing_transition_effects(openpc.current_action_intent_id(),OLD.state,NEW.state);
  IF effects IS NULL OR (effects->>'resumeFrom' IS NOT NULL AND effects->>'resumeFrom' IS DISTINCT FROM OLD.recovery_from_state)
   OR (effects->>'kind' IN ('RENEWAL','FORWARD_RECOVERY') AND NOT governed)
   OR (effects->>'kind'='RECOVERY' AND NOT governed AND
     (NEW.recovery_from_state IS DISTINCT FROM coalesce(OLD.recovery_from_state,OLD.state)
      OR NEW.recovery_from_revision IS DISTINCT FROM coalesce(OLD.recovery_from_revision,OLD.revision)))
  THEN RAISE EXCEPTION 'DATA-6022-ROTATION-TRANSITION'; END IF;
 END IF;
 IF NEW.state='APPROVED' AND NOT governed AND (openpc.current_action_intent_id()<>'ACT-POLICY_APPROVE_REQUEST-V1' OR NOT EXISTS(
  SELECT 1 FROM control.approval_request a JOIN control.mutation_candidate c ON c.participant_id=a.participant_id
   AND c.privacy_domain_id=a.privacy_domain_id AND c.mutation_candidate_id=a.subject_id
  JOIN control.approval_decision_record d ON d.participant_id=a.participant_id AND d.privacy_domain_id=a.privacy_domain_id
   AND d.approval_request_id=a.approval_request_id AND d.decision='APPROVE' AND d.approver_principal_id<>a.maker_principal_id
  WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id AND a.approval_request_id=NEW.approval_request_id
   AND a.state='APPROVED' AND c.state='CONSUMED' AND c.consumed_operation_id=NEW.approved_operation_id
   AND c.resource_id=NEW.rotation_id AND c.expected_revision=OLD.revision AND c.candidate_digest=NEW.candidate_digest
   AND a.subject_digest=c.candidate_digest AND d.candidate_digest=c.candidate_digest)) THEN RAISE EXCEPTION 'DATA-6021-ROTATION-CONSUMPTION'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_rotation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_key_rotation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_rotation();
${signingAttemptAuthoritySql}
CREATE OR REPLACE FUNCTION openpc.guard_signing_provider_attempt()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE command control.signing_rotation_command%ROWTYPE; rotation control.signing_key_rotation%ROWTYPE; effects jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-PROVIDER-ATTEMPT'; END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT command FROM control.signing_rotation_command WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND operation_id=NEW.operation_id AND state IN ('ACCEPTED','WRITE_AMBIGUITY');
  SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND revision=NEW.from_revision AND state=NEW.from_state;
  effects:=openpc.signing_transition_effects(command.action_intent_id,NEW.from_state,NEW.to_state);
  IF effects IS NULL OR (effects->>'resumeFrom' IS NOT NULL AND effects->>'resumeFrom' IS DISTINCT FROM rotation.recovery_from_state)
   OR (NEW.request->>'method'<>'SIGN_RECEIPT' AND NOT (effects->'providerSteps' @> jsonb_build_array(jsonb_build_array(NEW.slot,NEW.request->>'method'))))
   OR (NEW.request->>'method'<>'SIGN_RECEIPT' AND NEW.to_state<>command.to_state)
  THEN RAISE EXCEPTION 'DATA-6022-SIGNING-PROVIDER-MATRIX'; END IF;
  IF NEW.dispatched_at_ns IS NOT NULL THEN RAISE EXCEPTION 'DATA-6021-ATTEMPT-DISPATCH-TIME'; END IF;
  IF NEW.state='DISPATCHING' AND NEW.request->>'method' IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') THEN RAISE EXCEPTION 'DATA-6021-ATTEMPT-RESERVE-BEFORE-DISPATCH'; END IF;
  IF NEW.state NOT IN ('READY','DISPATCHING') OR NEW.observation IS NOT NULL THEN RAISE EXCEPTION 'DATA-6021-ATTEMPT-INITIAL'; END IF;
  IF NEW.state='DISPATCHING' THEN NEW.dispatched_at_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000; END IF;
  RETURN NEW;
 END IF;
 IF NEW.dispatched_at_ns IS DISTINCT FROM OLD.dispatched_at_ns THEN RAISE EXCEPTION 'DATA-6020-ATTEMPT-DISPATCH-TIME'; END IF;
 IF (to_jsonb(NEW)-ARRAY['state','observation','observation_digest']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['state','observation','observation_digest']) THEN RAISE EXCEPTION 'DATA-6020-ATTEMPT-IDENTITY'; END IF;
 IF pg_has_role(current_user,'openpc_control_worker','MEMBER') AND
  (OLD.request->>'method' NOT IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') OR NEW.state NOT IN ('DISPATCHING','OBSERVED','CANCELLED'))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-WORKER-OWNER'; END IF;
 IF NOT pg_has_role(current_user,'openpc_control_worker','MEMBER') AND NEW.state='DISPATCHING'
  AND OLD.request->>'method' NOT IN ('PROVE','SIGN_RECEIPT')
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-DISPATCH-OWNER'; END IF;
 IF OLD.state='READY' AND NEW.state='DISPATCHING' AND EXISTS(SELECT 1 FROM control.signing_rotation_command recovery
  WHERE recovery.participant_id=NEW.participant_id AND recovery.privacy_domain_id=NEW.privacy_domain_id
   AND recovery.original_operation_id=NEW.operation_id AND recovery.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1'
   AND recovery.state='ACCEPTED')
 THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-IN-PROGRESS'; END IF;
 IF OLD.state='READY' AND NEW.state='DISPATCHING' AND OLD.request->>'method' IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') AND EXISTS(
  SELECT 1 FROM control.signing_rotation_command c WHERE c.operation_id=NEW.operation_id AND c.state='WRITE_AMBIGUITY')
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-UNRESOLVED-FENCE'; END IF;
 IF OLD.state='READY' AND NEW.state='DISPATCHING' THEN
  IF OLD.request->>'method' IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') AND
   NOT coalesce((openpc.signing_attempt_authority_status(OLD.attempt_id)->>'unchangedLive')::boolean,false)
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-DISPATCH-AUTHORITY-CHANGED'; END IF;
  NEW.dispatched_at_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
 END IF;
 IF OLD.observation IS NOT NULL AND (NEW.observation IS DISTINCT FROM OLD.observation OR
    NEW.observation_digest IS DISTINCT FROM OLD.observation_digest) THEN RAISE EXCEPTION 'DATA-6020-ATTEMPT-OBSERVATION'; END IF;
 IF NEW.state='CANCELLED' THEN
  IF OLD.state<>'READY' OR OLD.dispatched_at_ns IS NOT NULL OR OLD.observation IS NOT NULL OR NOT EXISTS(
   SELECT 1 FROM control.signing_rotation_operation_evidence e WHERE e.participant_id=NEW.participant_id
    AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id AND e.kind='AUTHORITY_CHANGED_BEFORE_DISPATCH')
  THEN RAISE EXCEPTION 'DATA-6021-UNDISPATCHED-CANCELLATION'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.state='SUPERSEDED' THEN
  IF OLD.state NOT IN ('READY','DISPATCHING','OBSERVED') OR OLD.request->>'method'<>'SIGN_RECEIPT' OR NOT (EXISTS(
   SELECT 1 FROM control.signing_rotation_command c JOIN control.signing_rotation_history h
    ON h.participant_id=c.participant_id AND h.privacy_domain_id=c.privacy_domain_id AND h.operation_id=c.operation_id
   WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
    AND c.operation_id=openpc.current_operation_id() AND c.original_operation_id=NEW.operation_id
    AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND h.state='RECOVERING'
    AND h.receipt_id IS NOT NULL AND h.revision>NEW.from_revision) OR EXISTS(SELECT 1 FROM control.signing_continuation capability
     WHERE capability.participant_id=NEW.participant_id AND capability.privacy_domain_id=NEW.privacy_domain_id
      AND capability.operation_id=NEW.operation_id AND capability.operation_id=openpc.current_operation_id()
      AND capability.state='ISSUED' AND capability.expires_at_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000
      AND NOT EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=NEW.participant_id
       AND a.privacy_domain_id=NEW.privacy_domain_id AND a.receipt_id=NEW.attempt_id)))
  THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-SUPERSESSION'; END IF;
  RETURN NEW;
 END IF;
 IF NOT ((OLD.state='READY' AND NEW.state='DISPATCHING') OR (OLD.state='DISPATCHING' AND NEW.state='OBSERVED') OR (OLD.state='OBSERVED' AND NEW.state IN ('ACCEPTED','REJECTED')))
   THEN RAISE EXCEPTION 'DATA-6022-ATTEMPT-TRANSITION'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_provider_attempt
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_provider_attempt();
CREATE OR REPLACE FUNCTION openpc.guard_signing_command()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROTATION-COMMAND'; END IF;
 IF TG_OP='UPDATE' AND NEW.state='WRITE_AMBIGUITY' AND NOT EXISTS(
  SELECT 1 FROM control.signing_rotation_observation o WHERE o.participant_id=NEW.participant_id
   AND o.privacy_domain_id=NEW.privacy_domain_id AND o.operation_id=NEW.operation_id AND o.kind='UNRESOLVED')
 THEN RAISE EXCEPTION 'DATA-6021-AMBIGUITY-OBSERVATION-REQUIRED'; END IF;
 IF pg_has_role(current_user,'openpc_control_worker','MEMBER') AND
  (TG_OP<>'UPDATE' OR OLD.state<>'ACCEPTED' OR (NEW.state<>'WRITE_AMBIGUITY' AND NOT (NEW.state='FAILED' AND NEW.result_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH')))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-COMMAND-OWNER'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'ACCEPTED' THEN RAISE EXCEPTION 'DATA-6021-COMMAND-INITIAL'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' AND NEW.state IN ('SUCCEEDED','FAILED') AND EXISTS(
  SELECT 1 FROM control.signing_rotation_command recovery WHERE recovery.participant_id=NEW.participant_id
   AND recovery.privacy_domain_id=NEW.privacy_domain_id AND recovery.original_operation_id=NEW.operation_id
   AND recovery.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND recovery.state='ACCEPTED')
 THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-IN-PROGRESS'; END IF;
 IF OLD.recovery_observation_digest IS NOT NULL AND NEW.recovery_observation_digest IS DISTINCT FROM OLD.recovery_observation_digest
 THEN RAISE EXCEPTION 'DATA-6020-RECOVERY-OBSERVATION'; END IF;
 IF NEW.recovery_observation_digest IS NOT NULL AND NOT EXISTS(SELECT 1 FROM control.signing_rotation_observation o
  WHERE o.participant_id=NEW.participant_id AND o.privacy_domain_id=NEW.privacy_domain_id
   AND o.operation_id=NEW.original_operation_id AND o.attempt_id=NEW.recovery_attempt_id
   AND o.observation_digest=NEW.recovery_observation_digest AND o.kind IN ('NOT_FOUND','PROVIDER_RESULT'))
 THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-OBSERVATION'; END IF;
 IF NEW.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND NEW.state IN ('SUCCEEDED','FAILED') THEN
  IF NEW.operation_id IS DISTINCT FROM openpc.current_operation_id() OR
   (NEW.state='SUCCEEDED' AND (NEW.result_kind NOT IN ('NO_NEW_OBSERVATION','NEW_OBSERVATION','AUTHORITY_RENEWED','FORWARD_RECOVERY') OR NEW.result_kind IS NULL)) OR
   (NEW.state='FAILED' AND (NEW.result_kind NOT IN ('LOOKUP_UNAVAILABLE','SIGNATURE_UNAVAILABLE') OR NEW.result_kind IS NULL)) OR
   (NEW.result_kind='NO_NEW_OBSERVATION' AND (NEW.recovery_observation_digest IS DISTINCT FROM NEW.prior_observation_digest OR NEW.result_revision<>NEW.from_revision)) OR
   (NEW.result_kind='NEW_OBSERVATION' AND (NEW.recovery_observation_digest IS NULL OR NEW.recovery_observation_digest=NEW.prior_observation_digest
    OR NEW.result_revision<>NEW.from_revision+1 OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_history h
      WHERE h.participant_id=NEW.participant_id AND h.privacy_domain_id=NEW.privacy_domain_id
       AND h.operation_id=NEW.operation_id AND h.revision=NEW.result_revision AND h.state='RECOVERING' AND h.receipt_id IS NOT NULL))) OR
   (NEW.result_kind IN ('LOOKUP_UNAVAILABLE','SIGNATURE_UNAVAILABLE','NO_NEW_OBSERVATION') AND EXISTS(
    SELECT 1 FROM control.signing_rotation_history h WHERE h.participant_id=NEW.participant_id AND h.privacy_domain_id=NEW.privacy_domain_id AND h.operation_id=NEW.operation_id))
  THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-RESULT'; END IF;
  IF NEW.result_kind IN ('AUTHORITY_RENEWED','FORWARD_RECOVERY') AND NOT EXISTS(SELECT 1 FROM control.signing_authorization_generation g
   JOIN control.signing_rotation_history h ON h.participant_id=g.participant_id AND h.privacy_domain_id=g.privacy_domain_id
    AND h.operation_id=g.consumed_operation_id AND h.revision=g.result_revision
   WHERE g.generation_id=NEW.authorization_generation_id AND g.state='CONSUMED' AND g.consumed_operation_id=NEW.operation_id
    AND h.receipt_id IS NOT NULL AND h.event_id IS NULL AND NEW.result_revision=NEW.from_revision+1
    AND ((NEW.result_kind='AUTHORITY_RENEWED' AND h.state=h.prior_state) OR (NEW.result_kind='FORWARD_RECOVERY' AND h.state='RECOVERING')))
  THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-GENERATION-RESULT'; END IF;
 END IF;
 IF NEW.result_kind IN ('AUTHORITY_CHANGED_BEFORE_DISPATCH','NO_EFFECT_RETRYABLE') AND (NEW.state<>'FAILED'
  OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_operation_evidence e
   WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id AND e.kind=NEW.result_kind AND NEW.result_revision=(convert_from(e.preimage,'UTF8')::jsonb->>'currentRevision')::bigint))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-NO-EFFECT-EVIDENCE'; END IF;
 IF NEW.result_kind='PROVIDER_REJECTED' AND (NEW.state<>'FAILED' OR NOT EXISTS(
  SELECT 1 FROM control.signing_rotation_history h JOIN control.signing_provider_attempt p
   ON p.participant_id=h.participant_id AND p.privacy_domain_id=h.privacy_domain_id AND p.operation_id=h.operation_id
  WHERE h.participant_id=NEW.participant_id AND h.privacy_domain_id=NEW.privacy_domain_id AND h.operation_id=NEW.operation_id
   AND h.state='FAILED' AND h.revision=NEW.result_revision AND h.receipt_id IS NOT NULL
   AND p.request->>'method'<>'SIGN_RECEIPT' AND p.state='REJECTED' AND p.observation->>'outcome'='REJECTED'))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-FAILED-RECEIPT'; END IF;
 IF OLD.state IN ('SUCCEEDED','FAILED') OR
  (to_jsonb(NEW)-ARRAY['state','result_revision','updated_at','recovery_observation_digest','result_kind']) IS DISTINCT FROM
  (to_jsonb(OLD)-ARRAY['state','result_revision','updated_at','recovery_observation_digest','result_kind']) THEN RAISE EXCEPTION 'DATA-6020-COMMAND-IDENTITY'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_command_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_rotation_command
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_command();
CREATE TRIGGER qualified_inbox_immutable BEFORE UPDATE OR DELETE ON control.qualified_receipt_inbox
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE OR REPLACE FUNCTION openpc.guard_qualified_checkpoint()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-CHECKPOINT'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.last_sequence<>0 THEN RAISE EXCEPTION 'DATA-6021-CHECKPOINT-INITIAL'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['last_sequence','last_receipt_id']) IS DISTINCT FROM
  (to_jsonb(OLD)-ARRAY['last_sequence','last_receipt_id']) OR NEW.last_sequence<>OLD.last_sequence+1 OR NOT EXISTS(
  SELECT 1 FROM control.qualified_receipt_inbox i WHERE i.participant_id=NEW.participant_id AND i.privacy_domain_id=NEW.privacy_domain_id
   AND i.namespace=NEW.namespace AND i.aggregate_type=NEW.aggregate_type AND i.aggregate_id=NEW.aggregate_id
   AND i.sequence=NEW.last_sequence AND i.receipt_id=NEW.last_receipt_id) THEN RAISE EXCEPTION 'DATA-6021-CHECKPOINT-ACCEPTANCE'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER qualified_checkpoint_guard BEFORE INSERT OR UPDATE OR DELETE ON control.qualified_receipt_checkpoint
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_qualified_checkpoint();
CREATE OR REPLACE FUNCTION openpc.check_rotation_trust_admission()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE rotation control.signing_key_rotation%ROWTYPE; old_key control.business_signing_key%ROWTYPE; proofs integer;
BEGIN
 IF NEW.admission_kind<>'GOVERNED' THEN RETURN NULL; END IF;
 IF NEW.signing_purpose_code=371 THEN
  PERFORM openpc.check_identity_envelope_recovery_trust_admission(NEW);
  RETURN NULL;
 END IF;
 SELECT r.* INTO STRICT rotation FROM control.signing_key_rotation r
 WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
  AND NEW.admission_reference='urn:openpc:resource:'||r.rotation_id::text AND r.new_signer_id=NEW.signer_id
  AND r.state='VERIFIED' AND r.approval_request_id IS NOT NULL;
 SELECT * INTO STRICT old_key FROM control.business_signing_key
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND signer_id=rotation.old_signer_id;
 IF old_key.trust_digest<>rotation.old_trust_digest OR NEW.key_epoch<>old_key.key_epoch+1
  OR NEW.workload_credential_id<>old_key.workload_credential_id OR NEW.workload_credential_epoch<>old_key.workload_credential_epoch
  OR NEW.environment_id<>old_key.environment_id OR NEW.secret_reference<>rotation.request->>'newReference'
  OR NEW.environment_id<>rotation.environment_id OR NEW.workload_credential_id<>rotation.workload_credential_id
  OR NOT EXISTS(SELECT 1 FROM control.signing_provider_attempt a WHERE a.participant_id=NEW.participant_id
    AND a.privacy_domain_id=NEW.privacy_domain_id AND a.rotation_id=rotation.rotation_id AND a.to_state='PREPARED'
    AND a.state='ACCEPTED' AND a.observation->'descriptor'->>'fingerprint'=NEW.signer_id
    AND a.observation->'descriptor'->>'publicKeySpkiHex'=encode(NEW.public_key_spki_der,'hex')
    AND (a.observation->'descriptor'->>'validFromNs')::numeric=NEW.valid_from_ns
    AND (a.observation->'descriptor'->>'validUntilNs')::numeric=NEW.valid_until_ns)
 THEN RAISE EXCEPTION 'DATA-6021-GOVERNED-TRUST-BINDING'; END IF;
 SELECT count(*) INTO proofs FROM control.signing_provider_attempt a
 WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id
  AND a.rotation_id=rotation.rotation_id AND a.to_state='VERIFIED' AND a.state='ACCEPTED'
  AND a.request->>'method'='PROVE' AND a.request->>'rotationId'=rotation.rotation_id::text
  AND a.request->>'participantId'=NEW.participant_id::text AND a.request->>'privacyDomainId'=NEW.privacy_domain_id::text
  AND a.request->>'workloadCredentialId'=NEW.workload_credential_id::text
  AND a.request->>'environmentId'=NEW.environment_id AND a.request->>'challengeHex'=encode(NEW.trust_digest,'hex')
  AND a.request->>'expectedFingerprint'=CASE a.slot WHEN 'old' THEN old_key.signer_id WHEN 'new' THEN NEW.signer_id END
  AND a.observation->>'outcome'='SUCCEEDED' AND a.observation->>'attemptId'=a.attempt_id::text
  AND a.observation->>'requestDigest'='sha256:'||encode(a.request_digest,'hex')
  AND a.observation->'descriptor'->>'publicKeySpkiHex'=CASE a.slot WHEN 'old' THEN encode(old_key.public_key_spki_der,'hex') WHEN 'new' THEN encode(NEW.public_key_spki_der,'hex') END;
 IF proofs<>2 THEN RAISE EXCEPTION 'DATA-6021-GOVERNED-DUAL-PROOF'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER business_rotation_admission AFTER INSERT ON control.business_signing_key
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_rotation_trust_admission();
${signingObservationGuardsSql}
${signingAuthorizationGuardsSql}
${signingHistoryGuardsSql}
${signingAttestationGuardsSql}
REVOKE INSERT,UPDATE ON control.qualified_receipt_inbox,control.qualified_receipt_checkpoint FROM openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT ON control.qualified_receipt_inbox TO openpc_control_worker;
GRANT INSERT ON control.signing_rotation_observation TO openpc_control_runtime,openpc_control_worker;
GRANT UPDATE(admission_version) ON control.business_signing_selection TO openpc_control_runtime,openpc_control_worker;
GRANT UPDATE(state,result_kind,result_revision,updated_at) ON control.signing_rotation_command TO openpc_control_worker;
GRANT INSERT ON control.signing_rotation_operation_evidence TO openpc_control_runtime,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.signing_operation_failure_preimage(uuid,text,uuid) TO openpc_control_runtime,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.signing_observation_preimage(control.signing_provider_attempt,text),
 openpc.record_signing_observation(uuid,text),openpc.record_signing_ambiguity(uuid),
 openpc.signing_admission_open(uuid,uuid,text,uuid),
 openpc.retained_signing_admission_matches(uuid,uuid,text,uuid,numeric,numeric) TO openpc_control_runtime,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.rotation_history_preimage(control.signing_key_rotation,text,uuid,uuid,uuid,uuid,jsonb,numeric),
 openpc.check_signing_rotation_receipt(control.audit_occurrence),openpc.check_signing_rotation_event(control.outbox_event,control.audit_occurrence)
 TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.signing_transition_effects(text,text,text) TO openpc_control_runtime,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.signing_attempt_authority_status(uuid) TO openpc_control_runtime,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.signing_continuation_authority_digest(jsonb) TO openpc_control_runtime,openpc_control_worker;
GRANT UPDATE(state,observation,observation_digest) ON control.signing_provider_attempt TO openpc_control_worker;
GRANT INSERT,UPDATE(last_sequence,last_receipt_id) ON control.qualified_receipt_checkpoint TO openpc_control_worker;
GRANT INSERT ON control.business_signing_key,control.business_signing_grant,control.business_signing_key_state TO openpc_control_runtime;
GRANT UPDATE(state,row_version,changed_at_ns,change_reference,change_digest) ON control.business_signing_key_state TO openpc_control_runtime;
GRANT UPDATE(signer_id,row_version,fence_generation,fenced_operation_id,changed_at_ns,change_reference,change_digest) ON control.business_signing_selection TO openpc_control_runtime;
`;
