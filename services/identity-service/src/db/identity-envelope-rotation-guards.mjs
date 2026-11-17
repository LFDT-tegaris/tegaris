/** Exact purpose371 queue ownership. Historical observations do not confer
 * live custody, ordinary approval, trust admission or consumer acceptance. */
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
} from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';
import {
  identityEnvelopeRecoveryTrustGuardsSql,
  identityEnvelopeRecoveryPredecessorBindingSql,
} from './identity-envelope-recovery-trust-guards.mjs';
import { identityEnvelopeRotationConsumerPredicate } from './identity-envelope-rotation-consumer-guards.mjs';
import {
  identityEnvelopeRotationRetirementPredicate,
  identityEnvelopeRotationRetirementGuardsSql,
} from './identity-envelope-rotation-retirement-guards.mjs';
export const identityEnvelopeRotationGuardsSql = `
${identityEnvelopeRecoveryTrustGuardsSql}
CREATE OR REPLACE FUNCTION openpc.guard_identity_envelope_recovery_rotation(p_new control.signing_key_rotation,p_old control.signing_key_rotation,p_operation text)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE recovery control.platform_recovery_case; enrollment control.identity_envelope_recovery_enrollment; method text; expected_revision numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO recovery FROM control.platform_recovery_case c WHERE c.recovery_id=p_new.recovery_case_id
  AND c.participant_id=p_new.participant_id AND c.privacy_domain_id=p_new.privacy_domain_id;
 IF NOT FOUND OR NOT openpc.matches_participant(p_new.participant_id) OR NOT openpc.matches_privacy(p_new.privacy_domain_id)
  OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR NOT coalesce(openpc.identity_envelope_recovery_lease_current(recovery.recovery_id),false)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-CUSTODY'; END IF;
 SELECT * INTO STRICT enrollment FROM control.identity_envelope_recovery_enrollment e WHERE e.enrollment_id=recovery.signer_repair_enrollment_id
  AND e.participant_id=recovery.participant_id AND e.privacy_domain_id=recovery.privacy_domain_id;
 IF p_new.rotation_id::text IS DISTINCT FROM recovery.lease_bindings->>'rotationId'
  OR p_new.request IS DISTINCT FROM enrollment.document->'request'
  OR p_new.request->>'signerRole' IS DISTINCT FROM 'IDENTITY_ENVELOPE'
  OR p_new.request->>'purpose' IS DISTINCT FROM 'pc.cose.identity-authority-envelope.v1'
  OR NOT EXISTS(SELECT 1 FROM control.action_intent action WHERE action.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1'
    AND action.action_intent_id=p_new.request->>'actionIntentId' AND action.resource_type='signing-key-rotation'
    AND action.operation_class='CREATE' AND action.maker_checker_required
    AND 'sha256:'||encode(action.semantic_digest,'hex')=p_new.request->>'actionIntentDigest')
  OR p_new.candidate_digest IS DISTINCT FROM sha256(convert_to(openpc.signing_canonical_json(
    jsonb_build_object('request',p_new.request,'lease',recovery.lease_bindings)),'UTF8'))
  OR p_new.old_trust_digest IS DISTINCT FROM decode(substr(recovery.lease_bindings->>'oldTrustDigest',8),'hex')
  OR p_new.maker_principal_id::text IS DISTINCT FROM recovery.lease_bindings->>'executorPrincipalId'
  OR p_new.old_signer_id IS DISTINCT FROM p_new.request->>'oldFingerprint'
  OR p_new.environment_id IS DISTINCT FROM p_new.request->>'environmentId'
  OR p_new.workload_credential_id::text IS DISTINCT FROM p_new.request->>'workloadCredentialId'
  OR p_new.approval_request_id IS NOT NULL
  OR (p_new.state NOT IN ('CUTOVER_FENCED','OBSERVING','OLD_REVOKED','OLD_RETIRED','COMPLETE') AND p_new.cutover_at_ns IS NOT NULL)
  OR p_new.recovery_from_state IS NOT NULL OR p_new.recovery_from_revision IS NOT NULL
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-RESERVATION'; END IF;
 IF p_operation='INSERT' THEN
  IF p_new.state<>'REQUESTED' OR p_new.revision<>1 OR p_new.approved_operation_id IS NOT NULL OR p_new.new_signer_id IS NOT NULL
   OR openpc.current_operation_id()::text IS DISTINCT FROM recovery.lease_bindings->>'creationOperationId' THEN
   RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-INITIAL'; END IF;
 ELSIF p_operation='UPDATE' THEN
  IF (p_old.state='OBSERVING' AND p_new.state='OLD_REVOKED') OR (p_old.state='OLD_REVOKED' AND p_new.state='OLD_RETIRED') OR (p_old.state='OLD_RETIRED' AND p_new.state='COMPLETE') THEN
   expected_revision:=CASE p_old.state WHEN 'OBSERVING' THEN 7 WHEN 'OLD_REVOKED' THEN 8 ELSE 9 END;
   method:=CASE p_new.state WHEN 'OLD_REVOKED' THEN 'REVOKE' WHEN 'OLD_RETIRED' THEN 'RETIRE' ELSE NULL END;
   IF p_old.revision<>expected_revision OR p_new.revision<>expected_revision+1 OR p_new.updated_at<=p_old.updated_at
    OR (to_jsonb(p_new)-ARRAY['state','revision','updated_at']) IS DISTINCT FROM (to_jsonb(p_old)-ARRAY['state','revision','updated_at'])
    OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step step WHERE step.operation_id=openpc.current_operation_id()
      AND step.participant_id=p_new.participant_id AND step.privacy_domain_id=p_new.privacy_domain_id AND step.rotation_id=p_new.rotation_id AND step.recovery_id=recovery.recovery_id
      AND step.state='COMMITTED' AND step.from_revision=expected_revision AND step.from_state=p_old.state AND step.to_state=p_new.state
      AND step.result->>'state'=p_new.state AND openpc.identity_envelope_rotation_step_current(step) AND ${identityEnvelopeRotationRetirementPredicate('step')}
      AND (SELECT count(*) FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=step.operation_id)=(CASE WHEN method IS NULL THEN 0 ELSE 1 END)
      AND (method IS NULL OR EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt a JOIN control.business_signing_key key
        ON key.participant_id=a.participant_id AND key.privacy_domain_id=a.privacy_domain_id AND key.signer_id=p_new.old_signer_id
        WHERE a.operation_id=step.operation_id AND a.slot='old' AND a.state='OBSERVED' AND a.request->>'method'=method
        AND a.observation->>'outcome'='SUCCEEDED' AND a.observation=a.first_observation AND a.observation#>>'{descriptor,fingerprint}'=key.signer_id
        AND a.observation#>>'{descriptor,publicKeySpkiHex}'=encode(key.public_key_spki_der,'hex') AND a.observation#>>'{descriptor,reference}'=key.secret_reference
        AND a.observation#>>'{descriptor,state}'=(CASE method WHEN 'REVOKE' THEN 'REVOKED' ELSE 'RETIRED' END)
        AND (a.observation#>>ARRAY['descriptor',CASE method WHEN 'REVOKE' THEN 'revokedAtNs' ELSE 'retiredAtNs' END])::numeric>=floor(extract(epoch from a.started_at)*1000000)*1000
        AND a.observation#>>'{descriptor,revokedAtNs}'=step.result->>'oldPrivateKeyRevokedAtNs'
        AND a.observation#>>'{descriptor,retiredAtNs}' IS NOT DISTINCT FROM step.result->>'oldPrivateKeyRetiredAtNs'
        AND (a.observation->>'recordedAtNs')::numeric<=floor(extract(epoch from step.completed_at)*1000000)*1000))
      AND (p_new.state='OLD_REVOKED' OR EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step prior WHERE prior.participant_id=step.participant_id
        AND prior.privacy_domain_id=step.privacy_domain_id AND prior.rotation_id=step.rotation_id AND prior.recovery_id=step.recovery_id
        AND prior.consumer_observation_operation_id=step.consumer_observation_operation_id AND prior.state='COMMITTED'
        AND prior.from_revision=expected_revision-1 AND prior.to_state=p_old.state
        AND prior.result->>'oldPrivateKeyRevokedAtNs'=step.result->>'oldPrivateKeyRevokedAtNs'
        AND (p_new.state<>'COMPLETE' OR (prior.result->>'oldPrivateKeyRetiredAtNs'=step.result->>'oldPrivateKeyRetiredAtNs' AND step.result->>'postReviewRequired'='true')))))
    THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-RETIREMENT'; END IF;
   RETURN;
  END IF;
  IF p_old.state='CUTOVER_FENCED' AND p_new.state='OBSERVING' THEN
   IF p_old.revision<>6 OR p_new.revision<>7 OR p_new.updated_at<=p_old.updated_at
    OR (to_jsonb(p_new)-ARRAY['state','revision','updated_at']) IS DISTINCT FROM (to_jsonb(p_old)-ARRAY['state','revision','updated_at'])
    OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step step WHERE step.operation_id=openpc.current_operation_id()
      AND step.participant_id=p_new.participant_id AND step.privacy_domain_id=p_new.privacy_domain_id AND step.rotation_id=p_new.rotation_id
      AND step.recovery_id=recovery.recovery_id AND step.from_revision=6 AND step.from_state='CUTOVER_FENCED' AND step.to_state='OBSERVING'
      AND step.state='COMMITTED' AND openpc.identity_envelope_rotation_step_current(step) AND step.result->>'state'='OBSERVING'
      AND step.result->>'permissionEffect'='NONE' AND ${identityEnvelopeRotationConsumerPredicate('step')}
      AND (SELECT count(*) FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=step.operation_id)=1
      AND EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=step.operation_id AND a.slot='effective'
        AND a.state='OBSERVED' AND a.request->>'method'='PROVE' AND a.observation->>'outcome'='SUCCEEDED' AND a.observation=a.first_observation
        AND a.observation#>>'{descriptor,fingerprint}'=p_new.new_signer_id AND a.observation#>>'{descriptor,state}'='ACTIVE'
        AND a.request->>'challengeHex'=substr(step.result->>'trustDigest',8)))
    THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-CONSUMER'; END IF;
   RETURN;
  END IF;
  IF p_old.state='VERIFIED' AND p_new.state='CUTOVER_FENCED' THEN
   IF p_old.revision<>5 OR p_new.revision<>6 OR p_new.new_signer_id IS DISTINCT FROM p_old.new_signer_id OR p_old.cutover_at_ns IS NOT NULL
    OR p_new.cutover_at_ns IS NULL OR p_new.cutover_at_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000
    OR p_new.updated_at<=p_old.updated_at
    OR (to_jsonb(p_new)-ARRAY['state','revision','updated_at','cutover_at_ns']) IS DISTINCT FROM (to_jsonb(p_old)-ARRAY['state','revision','updated_at','cutover_at_ns'])
    OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step s WHERE s.operation_id=openpc.current_operation_id() AND s.participant_id=p_new.participant_id
      AND s.privacy_domain_id=p_new.privacy_domain_id AND s.rotation_id=p_new.rotation_id AND s.recovery_id=recovery.recovery_id
      AND s.from_revision=5 AND s.from_state='VERIFIED' AND s.to_state='CUTOVER_FENCED' AND s.state='COMMITTED'
      AND openpc.identity_envelope_rotation_step_current(s) AND s.result->>'signerId'=p_new.new_signer_id AND s.result->>'state'='CUTOVER_FENCED'
      AND s.result->>'permissionEffect'='NONE' AND (s.result->>'selectionAdmissionVersion')::numeric=(recovery.lease_bindings->>'selectionAdmissionVersion')::numeric+1
      AND p_new.cutover_at_ns=floor(extract(epoch from s.completed_at)*1000000)*1000
      AND NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=s.operation_id))
    THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-CUTOVER'; END IF;
   RETURN;
  END IF;
  IF p_old.state='DISTRIBUTED' AND p_new.state='VERIFIED' THEN
   IF p_old.revision<>4 OR p_new.revision<>5 OR p_new.new_signer_id IS DISTINCT FROM p_old.new_signer_id
    OR p_new.updated_at<=p_old.updated_at
    OR (to_jsonb(p_new)-ARRAY['state','revision','updated_at']) IS DISTINCT FROM (to_jsonb(p_old)-ARRAY['state','revision','updated_at'])
    OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step step WHERE step.operation_id=openpc.current_operation_id()
      AND step.participant_id=p_new.participant_id AND step.privacy_domain_id=p_new.privacy_domain_id AND step.rotation_id=p_new.rotation_id
      AND step.recovery_id=recovery.recovery_id AND step.from_revision=4 AND step.from_state='DISTRIBUTED' AND step.to_state='VERIFIED'
      AND step.state='COMMITTED' AND openpc.identity_envelope_rotation_step_current(step)
      AND step.result->>'state'='VERIFIED' AND step.result->>'admissionState'='ADMITTED' AND step.result->>'signerId'=p_new.new_signer_id
      AND (SELECT count(*) FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=step.operation_id)=2
      AND NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=step.operation_id
        AND (a.state<>'OBSERVED' OR a.request->>'method'<>'PROVE' OR a.observation IS DISTINCT FROM a.first_observation
          OR a.observation->>'outcome'<>'SUCCEEDED' OR a.request->>'challengeHex' IS DISTINCT FROM substr(step.result->>'trustDigest',8))))
    THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-VERIFICATION'; END IF;
   RETURN;
  END IF;
  IF (p_old.state='APPROVED' AND p_new.state='PREPARED') OR (p_old.state='PREPARED' AND p_new.state='DISTRIBUTED') THEN
   method:=CASE WHEN p_new.state='PREPARED' THEN 'PREPARE' ELSE 'DISTRIBUTE' END;
   expected_revision:=CASE WHEN method='PREPARE' THEN 2 ELSE 3 END;
   IF p_old.revision<>expected_revision OR p_new.revision<>expected_revision+1 OR p_new.new_signer_id IS NULL
    OR (method='PREPARE' AND p_old.new_signer_id IS NOT NULL)
    OR (method='DISTRIBUTE' AND p_new.new_signer_id IS DISTINCT FROM p_old.new_signer_id)
    OR p_new.updated_at<=p_old.updated_at
    OR (to_jsonb(p_new)-ARRAY['state','revision','updated_at','new_signer_id'])
      IS DISTINCT FROM (to_jsonb(p_old)-ARRAY['state','revision','updated_at','new_signer_id'])
    OR p_new.approved_operation_id::text IS DISTINCT FROM recovery.lease_bindings->>'activationOperationId'
    OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step step
     JOIN control.identity_envelope_rotation_attempt attempt ON attempt.operation_id=step.operation_id AND attempt.rotation_id=step.rotation_id
      AND attempt.participant_id=step.participant_id AND attempt.privacy_domain_id=step.privacy_domain_id AND attempt.slot='new'
     WHERE step.operation_id=openpc.current_operation_id() AND step.rotation_id=p_new.rotation_id AND step.recovery_id=recovery.recovery_id
      AND step.participant_id=p_new.participant_id AND step.privacy_domain_id=p_new.privacy_domain_id
      AND step.from_revision=expected_revision AND step.from_state=p_old.state AND step.to_state=p_new.state AND step.state='COMMITTED'
      AND openpc.identity_envelope_rotation_step_current(step) AND step.result->>'state'=p_new.state
      AND step.result->>'signerId'=p_new.new_signer_id AND attempt.state='OBSERVED' AND attempt.request->>'method'=method
      AND attempt.observation->>'outcome'='SUCCEEDED' AND attempt.observation=attempt.first_observation
      AND attempt.observation#>>'{descriptor,fingerprint}'=p_new.new_signer_id
      AND attempt.observation#>>'{descriptor,reference}'=p_new.request->>'newReference'
      AND attempt.observation#>>'{descriptor,state}'='ACTIVE'
      AND attempt.observation#>>'{descriptor,fingerprint}'='sha256:'||encode(sha256(decode(attempt.observation#>>'{descriptor,publicKeySpkiHex}','hex')),'hex')
      AND (method='PREPARE' OR EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step prepared
        JOIN control.identity_envelope_rotation_attempt original USING(participant_id,privacy_domain_id,rotation_id,operation_id)
        WHERE prepared.participant_id=step.participant_id AND prepared.privacy_domain_id=step.privacy_domain_id AND prepared.rotation_id=step.rotation_id
          AND prepared.recovery_id=step.recovery_id AND prepared.from_revision=2 AND prepared.to_state='PREPARED'
          AND prepared.state='COMMITTED' AND original.slot='new' AND original.state='OBSERVED'
          AND original.observation->'descriptor'=attempt.observation->'descriptor'
          AND prepared.result->>'trustDigest'=attempt.request->>'trustContextDigest'
          AND prepared.result->>'trustDigest'=step.result->>'trustDigest')))
    THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-PREPARE'; END IF;
   RETURN;
  END IF;
  IF p_old.state<>'REQUESTED' OR p_new.state<>'APPROVED' OR p_new.revision<>p_old.revision+1
   OR openpc.current_operation_id()::text IS DISTINCT FROM recovery.lease_bindings->>'creationOperationId'
   OR p_new.new_signer_id IS NOT NULL
   OR p_new.updated_at<=p_old.updated_at
   OR p_new.approved_operation_id::text IS DISTINCT FROM recovery.lease_bindings->>'activationOperationId'
   OR (to_jsonb(p_new)-ARRAY['state','revision','updated_at','approved_operation_id'])
      IS DISTINCT FROM (to_jsonb(p_old)-ARRAY['state','revision','updated_at','approved_operation_id']) THEN
   -- Later proof/admission/cutover remain closed until immutable
   -- trust, versioned selection and genuine consumer owners are connected.
   RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-PHASE'; END IF;
 ELSE RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-OWNER';
 END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_identity_envelope_recovery_rotation(control.signing_key_rotation,control.signing_key_rotation,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.guard_identity_envelope_recovery_rotation(control.signing_key_rotation,control.signing_key_rotation,text) TO openpc_control_runtime,openpc_control_platform_runtime;

-- The initial rotation is never committed without its original signed creation
-- event. Deferred evaluation observes both state transitions in one transaction.
CREATE OR REPLACE FUNCTION openpc.check_identity_envelope_recovery_rotation_creation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE recovery control.platform_recovery_case;
BEGIN
 IF NEW.recovery_case_id IS NULL THEN RETURN NULL; END IF;
 SELECT * INTO STRICT recovery FROM control.platform_recovery_case c WHERE c.recovery_id=NEW.recovery_case_id
  AND c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id;
 IF NOT EXISTS(SELECT 1 FROM control.signing_key_rotation r WHERE r.participant_id=NEW.participant_id
    AND r.privacy_domain_id=NEW.privacy_domain_id AND r.rotation_id=NEW.rotation_id AND r.state<>'REQUESTED'
    AND r.approved_operation_id::text=recovery.lease_bindings->>'activationOperationId')
  OR NOT EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_type='signing-key-rotation'
    AND event.aggregate_id=NEW.rotation_id AND event.aggregate_sequence=1
    AND event.event_id::text=recovery.lease_bindings->>'creationOperationId'
    AND event.event_type='openpc.identity.envelope-rotation.created.v1'
    AND octet_length(event.payload_cbor)>0 AND event.payload_digest=sha256(event.payload_cbor)
    AND octet_length(event.cose_sign1)>0)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-CREATION'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS identity_envelope_recovery_rotation_creation ON control.signing_key_rotation;
CREATE CONSTRAINT TRIGGER identity_envelope_recovery_rotation_creation AFTER INSERT ON control.signing_key_rotation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_identity_envelope_recovery_rotation_creation();

CREATE OR REPLACE FUNCTION openpc.identity_envelope_rotation_step_bound(p_step control.identity_envelope_rotation_step)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT openpc.matches_participant(p_step.participant_id) AND openpc.matches_privacy(p_step.privacy_domain_id)
  AND EXISTS(SELECT 1 FROM control.signing_key_rotation r JOIN control.platform_recovery_case c
   ON c.recovery_id=r.recovery_case_id AND c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id
   JOIN control.identity_envelope_recovery_enrollment e ON e.enrollment_id=c.signer_repair_enrollment_id
    AND e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
   WHERE r.rotation_id=p_step.rotation_id AND r.participant_id=p_step.participant_id AND r.privacy_domain_id=p_step.privacy_domain_id
    AND c.recovery_id=p_step.recovery_id AND c.activated_at IS NOT NULL
    AND r.request=e.document->'request' AND r.approval_request_id IS NULL
    AND r.rotation_id::text=c.lease_bindings->>'rotationId'
    AND p_step.principal_id::text=c.lease_bindings->>'executorPrincipalId'
    AND p_step.authority_binding=jsonb_build_object('kind','IDENTITY_ENVELOPE_SIGNER_RECOVERY','enrollment',e.document,'lease',c.lease_bindings)
    AND p_step.authority_digest=sha256(convert_to(openpc.signing_canonical_json(p_step.authority_binding),'UTF8')));
$$;
REVOKE ALL ON FUNCTION openpc.identity_envelope_rotation_step_bound(control.identity_envelope_rotation_step) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.identity_envelope_rotation_step_bound(control.identity_envelope_rotation_step) TO openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.identity_envelope_rotation_step_current(p_step control.identity_envelope_rotation_step)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT openpc.identity_envelope_rotation_step_bound(p_step) AND openpc.identity_envelope_recovery_lease_current(p_step.recovery_id);
$$;
REVOKE ALL ON FUNCTION openpc.identity_envelope_rotation_step_current(control.identity_envelope_rotation_step) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.identity_envelope_rotation_step_current(control.identity_envelope_rotation_step) TO openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_identity_envelope_rotation_step()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE rotation control.signing_key_rotation; effects jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR NEW.operation_id IS DISTINCT FROM openpc.current_operation_id()
  OR NOT coalesce(openpc.identity_envelope_rotation_step_bound(NEW),false)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-STEP'; END IF;
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation r WHERE r.participant_id=NEW.participant_id
  AND r.privacy_domain_id=NEW.privacy_domain_id AND r.rotation_id=NEW.rotation_id;
 effects:=openpc.signing_transition_effects('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',NEW.from_state,NEW.to_state);
 IF effects IS NULL OR effects->>'kind'<>'ADVANCE' OR effects->>'resumeFrom' IS NOT NULL
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-TRANSITION'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'READY' OR NEW.started_at IS NOT NULL OR NEW.result IS NOT NULL
   OR NEW.from_revision<>rotation.revision OR NEW.from_state<>rotation.state
   OR (NEW.from_state='CUTOVER_FENCED' AND NOT ${identityEnvelopeRotationConsumerPredicate('NEW')})
   OR (NEW.from_state IN('OBSERVING','OLD_REVOKED','OLD_RETIRED') AND NOT ${identityEnvelopeRotationRetirementPredicate('NEW')})
   OR length(NEW.idempotency_key) NOT BETWEEN 1 AND 200
   OR NOT coalesce(openpc.identity_envelope_rotation_step_current(NEW),false)
   THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-STEP'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','started_at','completed_at','result','evidence_cbor','evidence_digest','cose_sign1'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','started_at','completed_at','result','evidence_cbor','evidence_digest','cose_sign1'])
  OR (OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at)
  OR (OLD.completed_at IS NOT NULL AND (NEW.completed_at,NEW.result,NEW.evidence_cbor,NEW.evidence_digest,NEW.cose_sign1)
   IS DISTINCT FROM (OLD.completed_at,OLD.result,OLD.evidence_cbor,OLD.evidence_digest,OLD.cose_sign1))
  THEN RAISE EXCEPTION 'DATA-6020-ENVELOPE-ROTATION-STEP'; END IF;
 IF NOT ((OLD.state='READY' AND NEW.state='STARTED') OR
  (OLD.state='STARTED' AND NEW.state IN ('COMMITTED','WRITE_AMBIGUITY','FAILED')) OR
  (OLD.state='WRITE_AMBIGUITY' AND NEW.state='STARTED')) THEN
  RAISE EXCEPTION 'DATA-6022-ENVELOPE-ROTATION-STEP'; END IF;
 IF NEW.state='STARTED' AND (
   (OLD.state='READY' AND NEW.from_state IN('OBSERVING','OLD_REVOKED','OLD_RETIRED') AND NOT ${identityEnvelopeRotationRetirementPredicate('NEW')}) OR
   (OLD.state='READY' AND NEW.from_state='CUTOVER_FENCED' AND NOT ${identityEnvelopeRotationConsumerPredicate('NEW')}) OR NEW.started_at IS NULL OR NEW.started_at>clock_timestamp()
   OR rotation.revision<>NEW.from_revision OR rotation.state<>NEW.from_state
   OR (OLD.state='READY' AND NOT coalesce(openpc.identity_envelope_rotation_step_current(NEW),false))) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-START'; END IF;
 IF OLD.state='WRITE_AMBIGUITY' AND NEW.state='STARTED' AND (
  NEW.completed_at IS NOT NULL OR NEW.result IS NOT NULL
  OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt a
    WHERE a.operation_id=NEW.operation_id AND a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id
      AND a.rotation_id=NEW.rotation_id AND a.state='WRITE_AMBIGUITY' AND a.started_at IS NOT NULL AND a.ambiguity_kind IS NOT NULL)
  ) THEN
  -- Historical lookup needs no renewed lease. It cannot open new provider I/O.
  RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-LOOKUP'; END IF;
 IF NEW.state IN ('COMMITTED','FAILED') AND (
  NOT coalesce(openpc.identity_envelope_rotation_step_current(NEW),false)
  OR rotation.revision<>NEW.from_revision OR rotation.state<>NEW.from_state
  OR NEW.evidence_digest IS DISTINCT FROM sha256(NEW.evidence_cbor)
  OR NEW.result->>'operationId' IS DISTINCT FROM NEW.operation_id::text
  OR NEW.result->>'rotationId' IS DISTINCT FROM NEW.rotation_id::text
  OR NEW.result->>'recoveryId' IS DISTINCT FROM NEW.recovery_id::text
  OR (NEW.state='COMMITTED' AND NEW.from_state='CUTOVER_FENCED' AND NOT ${identityEnvelopeRotationConsumerPredicate('NEW')})
  OR (NEW.state='COMMITTED' AND NEW.from_state IN('OBSERVING','OLD_REVOKED','OLD_RETIRED') AND NOT ${identityEnvelopeRotationRetirementPredicate('NEW')})
  OR NEW.result->>'fromRevision' IS DISTINCT FROM NEW.from_revision::text
  OR NEW.result->>'revision' IS DISTINCT FROM (NEW.from_revision+1)::text
  OR NEW.result->>'state' IS DISTINCT FROM (CASE WHEN NEW.state='FAILED' THEN 'FAILED' ELSE NEW.to_state END)
  OR EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=NEW.operation_id AND a.state<>'OBSERVED')
  OR (SELECT count(*) FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=NEW.operation_id)<>jsonb_array_length(effects->'providerSteps')
  OR (NEW.state='COMMITTED' AND EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt a
    WHERE a.operation_id=NEW.operation_id AND a.observation->>'outcome'<>'SUCCEEDED'))
  OR (NEW.state='FAILED' AND NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt a
    WHERE a.operation_id=NEW.operation_id AND a.observation->>'outcome'='REJECTED')))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-RESULT'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_envelope_rotation_step_guard ON control.identity_envelope_rotation_step;
CREATE TRIGGER identity_envelope_rotation_step_guard BEFORE INSERT OR UPDATE OR DELETE ON control.identity_envelope_rotation_step
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_envelope_rotation_step();

CREATE OR REPLACE FUNCTION openpc.guard_identity_envelope_rotation_attempt()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE step control.identity_envelope_rotation_step; rotation control.signing_key_rotation; effects jsonb; issuer jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR NEW.operation_id IS DISTINCT FROM openpc.current_operation_id()
  OR NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-ATTEMPT'; END IF;
 SELECT * INTO STRICT step FROM control.identity_envelope_rotation_step s WHERE s.operation_id=NEW.operation_id
  AND s.participant_id=NEW.participant_id AND s.privacy_domain_id=NEW.privacy_domain_id AND s.rotation_id=NEW.rotation_id;
 IF NOT coalesce(openpc.identity_envelope_rotation_step_bound(step),false) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-ATTEMPT'; END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT rotation FROM control.signing_key_rotation r WHERE r.participant_id=NEW.participant_id
   AND r.privacy_domain_id=NEW.privacy_domain_id AND r.rotation_id=NEW.rotation_id;
  effects:=openpc.signing_transition_effects('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',step.from_state,step.to_state);
  issuer:=step.authority_binding#>'{lease,issuer}';
  IF step.state<>'READY' OR NEW.state<>'READY' OR NEW.started_at IS NOT NULL OR NEW.observation IS NOT NULL OR NEW.first_observation IS NOT NULL OR NEW.ambiguity_kind IS NOT NULL
   OR NOT coalesce(openpc.identity_envelope_rotation_step_current(step),false)
   OR NOT (effects->'providerSteps' @> jsonb_build_array(jsonb_build_array(NEW.slot,NEW.request->>'method')))
   OR NEW.request_digest<>sha256(convert_to('pc.identity.envelope-key-rotation-request.v1','UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json(NEW.request),'UTF8'))
   OR NEW.request->>'participantId' IS DISTINCT FROM NEW.participant_id::text OR NEW.request->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
   OR NEW.request->>'rotationId' IS DISTINCT FROM NEW.rotation_id::text OR NEW.request->>'operationId' IS DISTINCT FROM NEW.operation_id::text
   OR NEW.request->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text
   OR NEW.request->>'purpose' IS DISTINCT FROM 'pc.cose.identity-authority-envelope.v1' OR NEW.request->>'purposeCode' IS DISTINCT FROM '371'
   OR NEW.request->>'schemaId' IS DISTINCT FROM '24034' OR NEW.request->>'schemaVersion' IS DISTINCT FROM '1'
   OR NEW.request->>'secretClass' IS DISTINCT FROM 'SECRET-SIGNING-KEY'
   OR NEW.request->>'schemaDefinitionDigest' IS DISTINCT FROM '${identityEnvelopeContext.definitionDigest}'
   OR NEW.request->>'profileId' IS DISTINCT FROM 'pc.identity.authority-envelope.v1'
   OR NEW.request->>'profileVersion' IS DISTINCT FROM '1'
   OR NEW.request->>'profileDigest' IS DISTINCT FROM '${identityEnvelopeSigningProfileDigest}'
   OR NEW.request-ARRAY['participantId','privacyDomainId','environmentId','workloadCredentialId','workloadCredentialEpoch',
    'secretClass','reference','version','purpose','purposeCode','schemaId','schemaVersion','schemaDefinitionDigest','profileId',
    'profileVersion','profileDigest','callerWorkloadCredentialId','rotationId','operationId','attemptId','issuerParticipantEpoch',
    'issuerPrincipalEpoch','governanceDigest','method','expectedFingerprint']-
      (CASE NEW.request->>'method' WHEN 'DISTRIBUTE' THEN ARRAY['trustContextDigest']
       WHEN 'PROVE' THEN ARRAY['challengeHex','challengeIssuedAtNs','challengeExpiresAtNs','recoveryPredecessor'] ELSE ARRAY[]::text[] END)<>'{}'::jsonb
   OR NEW.request->'recoveryPredecessor' IS DISTINCT FROM
     (CASE WHEN NEW.slot='old' AND NEW.request->>'method'='PROVE'
       THEN ${identityEnvelopeRecoveryPredecessorBindingSql('step.authority_binding')} ELSE NULL END)
   OR NEW.request->>'environmentId' IS DISTINCT FROM rotation.environment_id
   OR NEW.request->>'workloadCredentialId' IS DISTINCT FROM issuer->>'workloadCredentialId'
   OR NEW.request->>'callerWorkloadCredentialId' IS DISTINCT FROM issuer->>'workloadCredentialId'
   OR NEW.request->>'workloadCredentialEpoch' IS DISTINCT FROM issuer->>'workloadCredentialEpoch'
   OR NEW.request->>'issuerParticipantEpoch' IS DISTINCT FROM issuer->>'workloadParticipantEpoch'
   OR NEW.request->>'issuerPrincipalEpoch' IS DISTINCT FROM issuer->>'workloadPrincipalEpoch'
   OR NEW.request->>'reference' IS DISTINCT FROM (CASE WHEN NEW.slot='old' THEN rotation.request->>'oldReference' ELSE rotation.request->>'newReference' END)
   OR NEW.request->>'version' IS DISTINCT FROM split_part(NEW.request->>'reference','#',2)
   OR NEW.request->>'governanceDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
      jsonb_build_object('domain','pc.identity.envelope-rotation-governance.v1','admission',step.authority_binding)),'UTF8')),'hex')
   OR (NEW.request->>'method'<>'PREPARE' AND NEW.request->>'expectedFingerprint' IS DISTINCT FROM
     (CASE WHEN NEW.slot='old' THEN rotation.old_signer_id ELSE rotation.new_signer_id END))
   OR (NEW.request->>'method'='PREPARE' AND NEW.request->>'expectedFingerprint' IS DISTINCT FROM rotation.request->>'newFingerprint')
   OR (NEW.request->>'method'='DISTRIBUTE' AND NOT EXISTS(
     SELECT 1 FROM control.identity_envelope_rotation_step prepared WHERE prepared.participant_id=NEW.participant_id
      AND prepared.privacy_domain_id=NEW.privacy_domain_id AND prepared.rotation_id=NEW.rotation_id AND prepared.recovery_id=step.recovery_id
      AND prepared.from_revision=2 AND prepared.from_state='APPROVED' AND prepared.to_state='PREPARED' AND prepared.state='COMMITTED'
      AND prepared.result->>'signerId'=rotation.new_signer_id AND prepared.result->>'trustDigest'=NEW.request->>'trustContextDigest'))
   OR (NEW.slot='effective' AND NOT EXISTS(SELECT 1 FROM control.identity_envelope_activation consumer WHERE consumer.operation_id=step.consumer_activation_operation_id
     AND consumer.participant_id=step.participant_id AND consumer.privacy_domain_id=step.privacy_domain_id AND consumer.state='COMMITTED'
     AND floor(extract(epoch from consumer.committed_at)*1000000)*1000<=(NEW.request->>'challengeIssuedAtNs')::numeric))
   OR (NEW.request->>'method'='PROVE' AND (
      coalesce(NEW.request->>'challengeHex','') !~ '^[0-9a-f]{64}$'
      OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step prepared WHERE prepared.participant_id=NEW.participant_id
        AND prepared.privacy_domain_id=NEW.privacy_domain_id AND prepared.rotation_id=NEW.rotation_id AND prepared.recovery_id=step.recovery_id
        AND prepared.from_revision=3 AND prepared.to_state='DISTRIBUTED' AND prepared.state='COMMITTED'
        AND prepared.result->>'signerId'=rotation.new_signer_id AND substr(prepared.result->>'trustDigest',8)=NEW.request->>'challengeHex')
      OR
      (NEW.request->>'challengeIssuedAtNs')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000)*1000
      OR (NEW.request->>'challengeExpiresAtNs')::numeric<=(NEW.request->>'challengeIssuedAtNs')::numeric
      OR (NEW.request->>'challengeExpiresAtNs')::numeric>(NEW.request->>'challengeIssuedAtNs')::numeric+300000000000
      OR (NEW.request->>'challengeExpiresAtNs')::numeric>floor(extract(epoch FROM (step.authority_binding#>>'{lease,validUntil}')::timestamptz)*1000000)*1000))
   THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-REQUEST'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','started_at','observed_at','observation','observation_digest','first_observation','first_observation_digest','ambiguity_kind'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','started_at','observed_at','observation','observation_digest','first_observation','first_observation_digest','ambiguity_kind'])
  OR (OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at)
  OR (OLD.first_observation IS NOT NULL AND (NEW.first_observation,NEW.first_observation_digest) IS DISTINCT FROM (OLD.first_observation,OLD.first_observation_digest))
  OR (OLD.observation IS NOT NULL AND (NEW.observation,NEW.observation_digest,NEW.observed_at) IS DISTINCT FROM (OLD.observation,OLD.observation_digest,OLD.observed_at))
  OR (OLD.ambiguity_kind IS NOT NULL AND NEW.ambiguity_kind IS DISTINCT FROM OLD.ambiguity_kind)
  OR OLD.state='OBSERVED' THEN RAISE EXCEPTION 'DATA-6020-ENVELOPE-ROTATION-ATTEMPT'; END IF;
 IF NOT ((OLD.state='READY' AND NEW.state='STARTED') OR
   (OLD.state='STARTED' AND NEW.state IN ('STARTED','OBSERVED','WRITE_AMBIGUITY')) OR
   (OLD.state='WRITE_AMBIGUITY' AND NEW.state IN ('WRITE_AMBIGUITY','OBSERVED'))) THEN
  RAISE EXCEPTION 'DATA-6022-ENVELOPE-ROTATION-ATTEMPT'; END IF;
 IF OLD.state='READY' AND NEW.state='STARTED' AND (step.state<>'STARTED' OR NEW.started_at IS NULL
   OR NEW.started_at>clock_timestamp() OR NOT coalesce(openpc.identity_envelope_rotation_step_current(step),false)
   OR EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt sibling WHERE sibling.operation_id=NEW.operation_id AND sibling.state='WRITE_AMBIGUITY')
   OR (NEW.slot='effective' AND NOT EXISTS(SELECT 1 FROM control.identity_envelope_activation consumer WHERE consumer.operation_id=step.consumer_activation_operation_id
     AND consumer.participant_id=step.participant_id AND consumer.privacy_domain_id=step.privacy_domain_id AND consumer.state='COMMITTED'
     AND floor(extract(epoch from consumer.committed_at)*1000000)*1000<=(NEW.request->>'challengeIssuedAtNs')::numeric))
   OR (NEW.request->>'method'='PROVE' AND (NEW.request->>'challengeExpiresAtNs')::numeric<=floor(extract(epoch FROM clock_timestamp())*1000000)*1000)) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-DISPATCH'; END IF;
 IF NEW.first_observation IS NOT NULL AND (NEW.first_observation_digest IS DISTINCT FROM sha256(convert_to(openpc.signing_canonical_json(NEW.first_observation),'UTF8'))
   OR NEW.first_observation->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text
   OR NEW.first_observation->>'operationId' IS DISTINCT FROM NEW.operation_id::text
   OR NEW.first_observation->>'requestDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.request_digest,'hex')
   OR NEW.first_observation->>'method' IS DISTINCT FROM NEW.request->>'method') THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-OBSERVATION'; END IF;
 IF NEW.state='OBSERVED' AND (NEW.observation IS DISTINCT FROM NEW.first_observation
   OR NEW.observation_digest IS DISTINCT FROM NEW.first_observation_digest OR NEW.observed_at>clock_timestamp()) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-LOOKUP'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_envelope_rotation_attempt_guard ON control.identity_envelope_rotation_attempt;
CREATE TRIGGER identity_envelope_rotation_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON control.identity_envelope_rotation_attempt
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_envelope_rotation_attempt();

-- A signed completion without the same committed business state and outbox
-- is rejected at transaction end. A worker observation alone is not completion.
CREATE OR REPLACE FUNCTION openpc.check_identity_envelope_rotation_step_effect()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.state NOT IN ('COMMITTED','FAILED') THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.signing_key_rotation r WHERE r.participant_id=NEW.participant_id
   AND r.privacy_domain_id=NEW.privacy_domain_id AND r.rotation_id=NEW.rotation_id
   AND r.recovery_case_id=NEW.recovery_id AND r.revision=NEW.from_revision+1 AND r.state=NEW.result->>'state')
  OR NOT EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_type='signing-key-rotation'
    AND event.aggregate_id=NEW.rotation_id AND event.event_id=NEW.operation_id
    AND event.event_type='openpc.identity.envelope-rotation.phase.v1'
    AND event.payload_cbor=NEW.evidence_cbor AND event.payload_digest=NEW.evidence_digest AND event.cose_sign1=NEW.cose_sign1)
  OR (NEW.state='COMMITTED' AND NEW.to_state IN('OLD_REVOKED','OLD_RETIRED','COMPLETE') AND NOT ${identityEnvelopeRotationRetirementPredicate('NEW', true)})
  OR (NEW.state='COMMITTED' AND NEW.to_state='OBSERVING' AND NOT ${identityEnvelopeRotationConsumerPredicate('NEW')})
  OR (NEW.state='COMMITTED' AND NEW.to_state='CUTOVER_FENCED' AND NOT EXISTS(SELECT 1 FROM control.identity_envelope_signing_selection selection
    JOIN control.business_signing_key_state life USING(participant_id,privacy_domain_id,signer_id)
    WHERE selection.participant_id=NEW.participant_id AND selection.privacy_domain_id=NEW.privacy_domain_id AND selection.signer_id=NEW.result->>'signerId'
      AND selection.admission_version::text=NEW.result->>'selectionAdmissionVersion' AND life.state='ACTIVE'))
  OR (NEW.state='COMMITTED' AND NEW.to_state='VERIFIED' AND NOT EXISTS(SELECT 1 FROM control.business_signing_key k
    JOIN control.identity_envelope_signing_grant g USING(participant_id,privacy_domain_id,signer_id)
    JOIN control.business_signing_key_state life USING(participant_id,privacy_domain_id,signer_id)
    WHERE k.participant_id=NEW.participant_id AND k.privacy_domain_id=NEW.privacy_domain_id AND k.signer_id=NEW.result->>'signerId'
      AND k.signing_purpose_code=371 AND g.signing_purpose_code=371 AND g.profile_digest=decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex')
      AND k.trust_digest=decode(substr(NEW.result->>'trustDigest',8),'hex') AND life.state='ADMITTED' AND life.change_digest=NEW.evidence_digest))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-EFFECT'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS identity_envelope_rotation_step_effect ON control.identity_envelope_rotation_step;
CREATE CONSTRAINT TRIGGER identity_envelope_rotation_step_effect AFTER INSERT OR UPDATE ON control.identity_envelope_rotation_step
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_identity_envelope_rotation_step_effect();

${identityEnvelopeRotationRetirementGuardsSql}
`;

/** Restore only the original constrained writes after the shared ACL reset.
 * All function/trigger definitions stay in the ownership-normalized section. */
export const identityEnvelopeRotationGrantsSql = `
REVOKE INSERT,UPDATE,DELETE ON control.identity_envelope_rotation_step,control.identity_envelope_rotation_attempt FROM openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker;
GRANT INSERT ON control.identity_envelope_rotation_step,control.identity_envelope_rotation_attempt TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT UPDATE(state,started_at,completed_at,result,evidence_cbor,evidence_digest,cose_sign1) ON control.identity_envelope_rotation_step TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT UPDATE(state,started_at,observed_at,observation,observation_digest,first_observation,first_observation_digest,ambiguity_kind) ON control.identity_envelope_rotation_attempt TO openpc_control_runtime,openpc_control_platform_runtime;
`;
