/** One database representation for material provider knowledge, shared by API and worker. */
export const signingObservationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.signing_observation_preimage(a control.signing_provider_attempt,p_kind text)
RETURNS bytea LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT convert_to(jsonb_build_object('schema','pc.control.signing-observation.v1',
  'participantId',a.participant_id,'privacyDomainId',a.privacy_domain_id,'rotationId',a.rotation_id,
  'operationId',a.operation_id,'attemptId',a.attempt_id,'method',a.request->>'method',
  'requestDigest',encode(a.request_digest,'hex'),'kind',p_kind,
  'providerObservationDigest',CASE WHEN p_kind='PROVIDER_RESULT' THEN encode(a.observation_digest,'hex') ELSE NULL END)::text,'UTF8')
$$;
CREATE OR REPLACE FUNCTION openpc.guard_signing_observation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.signing_provider_attempt%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM control.signing_provider_attempt WHERE attempt_id=NEW.attempt_id
  AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
  AND rotation_id=NEW.rotation_id AND operation_id=NEW.operation_id;
 IF (NEW.operation_id IS DISTINCT FROM openpc.current_operation_id() AND NOT EXISTS(
  SELECT 1 FROM control.signing_rotation_command c WHERE c.participant_id=NEW.participant_id
   AND c.privacy_domain_id=NEW.privacy_domain_id AND c.operation_id=openpc.current_operation_id()
   AND c.original_operation_id=NEW.operation_id AND c.recovery_attempt_id=NEW.attempt_id
   AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND c.state='ACCEPTED')) OR
  openpc.current_action_intent_id() NOT IN ('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1') OR
  (NEW.kind='NOT_FOUND' AND openpc.current_action_intent_id()<>'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1')
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-OBSERVATION-CONTEXT'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR
  NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id() OR
  NEW.observation_preimage IS DISTINCT FROM openpc.signing_observation_preimage(a,NEW.kind) OR
  NEW.observed_at_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000 OR
  (NEW.kind IN ('UNRESOLVED','NOT_FOUND') AND (a.state<>'DISPATCHING' OR a.observation IS NOT NULL)) OR
  (NEW.kind='PROVIDER_RESULT' AND (a.state NOT IN ('OBSERVED','ACCEPTED','REJECTED') OR a.observation IS NULL))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-OBSERVATION-BINDING'; END IF;
 IF pg_has_role(current_user,'openpc_control_worker','MEMBER') AND
  (a.request->>'method' NOT IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') OR NEW.kind='NOT_FOUND')
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-OBSERVATION-OWNER'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_observation_binding BEFORE INSERT ON control.signing_rotation_observation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_observation();
CREATE OR REPLACE FUNCTION openpc.record_signing_observation(p_attempt uuid,p_kind text)
RETURNS TABLE(observation_id uuid,observation_digest bytea) LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.signing_provider_attempt%ROWTYPE; preimage bytea;
BEGIN
 SELECT * INTO STRICT a FROM control.signing_provider_attempt WHERE attempt_id=p_attempt
  AND participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id();
 preimage:=openpc.signing_observation_preimage(a,p_kind);
 INSERT INTO control.signing_rotation_observation(participant_id,privacy_domain_id,rotation_id,operation_id,attempt_id,kind,observation_preimage,observation_digest)
 VALUES(a.participant_id,a.privacy_domain_id,a.rotation_id,a.operation_id,a.attempt_id,p_kind,preimage,sha256(preimage))
 ON CONFLICT ON CONSTRAINT signing_observation_material_uq DO NOTHING;
 RETURN QUERY SELECT o.observation_id,o.observation_digest FROM control.signing_rotation_observation o
 WHERE o.participant_id=a.participant_id AND o.privacy_domain_id=a.privacy_domain_id AND o.attempt_id=a.attempt_id
  AND o.observation_digest=sha256(preimage);
END $$;
CREATE OR REPLACE FUNCTION openpc.record_signing_provider_result()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.record_signing_observation(NEW.attempt_id,'PROVIDER_RESULT');
 RETURN NULL;
END $$;
CREATE TRIGGER signing_provider_result_observation AFTER UPDATE ON control.signing_provider_attempt
 FOR EACH ROW WHEN (OLD.observation IS NULL AND NEW.observation IS NOT NULL
  AND NEW.request->>'method'<>'SIGN_RECEIPT') EXECUTE FUNCTION openpc.record_signing_provider_result();
CREATE OR REPLACE FUNCTION openpc.signing_admission_open(p_participant uuid,p_privacy uuid,p_signer text,p_operation uuid)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT NOT EXISTS(SELECT 1 FROM control.signing_key_rotation r JOIN control.signing_rotation_command c
  ON c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id AND c.rotation_id=r.rotation_id
  WHERE r.participant_id=p_participant AND r.privacy_domain_id=p_privacy AND p_signer IN(r.old_signer_id,r.new_signer_id)
   AND c.state='WRITE_AMBIGUITY' AND c.operation_id<>p_operation AND NOT EXISTS(
    SELECT 1 FROM control.signing_rotation_command recovery WHERE recovery.participant_id=c.participant_id
     AND recovery.privacy_domain_id=c.privacy_domain_id AND recovery.rotation_id=c.rotation_id
     AND recovery.operation_id=p_operation AND recovery.original_operation_id=c.operation_id
     AND recovery.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND recovery.state='ACCEPTED'))
$$;
-- A retained exact attempt may record its own pre-fence result. This never admits a new attempt.
CREATE OR REPLACE FUNCTION openpc.retained_signing_admission_matches(
 p_participant uuid,p_privacy uuid,p_signer text,p_operation uuid,p_reserved numeric,p_current numeric)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT p_reserved>0 AND (p_current=p_reserved OR (p_current=p_reserved+1 AND EXISTS(
  SELECT 1 FROM control.signing_rotation_command c JOIN control.signing_key_rotation r
   ON r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.rotation_id=c.rotation_id
  WHERE c.participant_id=p_participant AND c.privacy_domain_id=p_privacy AND c.operation_id=p_operation
   AND c.state IN ('WRITE_AMBIGUITY','SUCCEEDED','FAILED') AND p_signer IN(r.old_signer_id,r.new_signer_id)
   AND EXISTS(SELECT 1 FROM control.signing_rotation_observation o WHERE o.participant_id=c.participant_id
    AND o.privacy_domain_id=c.privacy_domain_id AND o.operation_id=c.operation_id AND o.kind='UNRESOLVED'))))
$$;
CREATE OR REPLACE FUNCTION openpc.record_signing_ambiguity(p_attempt uuid)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.signing_provider_attempt%ROWTYPE; c control.signing_rotation_command%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM control.signing_provider_attempt WHERE attempt_id=p_attempt
  AND participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id();
 -- Match receipt-writer lock order, so a preceding synchronous signature commits before this fence.
 PERFORM 1 FROM control.business_signing_selection s JOIN control.business_signing_key k USING(participant_id,privacy_domain_id,signer_id)
 WHERE s.participant_id=a.participant_id AND s.privacy_domain_id=a.privacy_domain_id
  AND s.environment_id=a.request->>'environmentId' AND k.workload_credential_id=(a.request->>'workloadCredentialId')::uuid
 ORDER BY s.profile_digest FOR UPDATE OF s;
 SELECT * INTO STRICT c FROM control.signing_rotation_command WHERE operation_id=a.operation_id FOR UPDATE;
 SELECT * INTO STRICT a FROM control.signing_provider_attempt WHERE attempt_id=p_attempt FOR UPDATE;
 IF c.state IN ('SUCCEEDED','FAILED') OR a.state<>'DISPATCHING' THEN RETURN; END IF;
 PERFORM openpc.record_signing_observation(p_attempt,'UNRESOLVED');
 IF c.state='ACCEPTED' THEN
  UPDATE control.signing_rotation_command SET state='WRITE_AMBIGUITY',updated_at=clock_timestamp() WHERE operation_id=c.operation_id;
  UPDATE control.business_signing_selection s SET admission_version=s.admission_version+1
   FROM control.signing_key_rotation r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id
    AND r.rotation_id=c.rotation_id AND s.participant_id=r.participant_id AND s.privacy_domain_id=r.privacy_domain_id
    AND s.signer_id IN(r.old_signer_id,r.new_signer_id);
 END IF;
END $$;
`;
