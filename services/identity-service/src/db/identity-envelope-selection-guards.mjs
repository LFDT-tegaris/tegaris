import { identityEnvelopeSigningProfileDigest } from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';
/** Immutable original admission plus a single versioned custody cutover. No
 * arbitrary selector update, predecessor resurrection or retirement follows. */
export const identityEnvelopeSelectionGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_identity_envelope_signing_selection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE step control.identity_envelope_rotation_step; rotation control.signing_key_rotation;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-ENVELOPE-SIGNING-SELECTION'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.admission_version<>1 OR (NOT pg_has_role(current_user,'openpc_control_key_governor','MEMBER')
    AND NOT pg_has_role(current_user,'openpc_control_owner','MEMBER')) THEN
   RAISE EXCEPTION 'DATA-6021-ENVELOPE-SIGNING-INSTALLATION-AUTHORITY'; END IF;
 ELSE
  PERFORM openpc.assert_request_context(true);
  IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   OR NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id)
   OR NEW.admission_version<>OLD.admission_version+1 OR NEW.signer_id=OLD.signer_id
   OR (to_jsonb(NEW)-ARRAY['signer_id','admission_version']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['signer_id','admission_version'])
   THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-SIGNING-CUTOVER'; END IF;
  SELECT * INTO STRICT step FROM control.identity_envelope_rotation_step s WHERE s.operation_id=openpc.current_operation_id()
   AND s.participant_id=NEW.participant_id AND s.privacy_domain_id=NEW.privacy_domain_id AND s.from_revision=5
   AND s.from_state='VERIFIED' AND s.to_state='CUTOVER_FENCED' AND s.state='COMMITTED';
  SELECT * INTO STRICT rotation FROM control.signing_key_rotation r WHERE r.participant_id=step.participant_id
   AND r.privacy_domain_id=step.privacy_domain_id AND r.rotation_id=step.rotation_id AND r.recovery_case_id=step.recovery_id
   AND r.state='CUTOVER_FENCED' AND r.revision=6 AND r.old_signer_id=OLD.signer_id AND r.new_signer_id=NEW.signer_id;
  IF NOT coalesce(openpc.identity_envelope_rotation_step_current(step),false)
    OR rotation.environment_id<>NEW.environment_id OR step.result->>'signerId' IS DISTINCT FROM NEW.signer_id
    OR step.result->>'selectionAdmissionVersion' IS DISTINCT FROM NEW.admission_version::text
    OR OLD.admission_version::text IS DISTINCT FROM step.authority_binding#>>'{lease,selectionAdmissionVersion}'
    OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step verified WHERE verified.participant_id=step.participant_id
      AND verified.privacy_domain_id=step.privacy_domain_id AND verified.rotation_id=step.rotation_id AND verified.recovery_id=step.recovery_id
      AND verified.from_revision=4 AND verified.to_state='VERIFIED' AND verified.state='COMMITTED'
      AND verified.result->>'trustDigest'=step.result->>'trustDigest' AND verified.result->>'admissionState'='ADMITTED')
    OR EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt proof WHERE proof.rotation_id=step.rotation_id
      AND proof.request->>'method'='PROVE' AND proof.slot IN('old','new')
      AND (proof.request->>'challengeExpiresAtNs')::numeric<=floor(extract(epoch from clock_timestamp())*1000000)*1000)
   THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-SIGNING-CUTOVER-PROVENANCE'; END IF;
 END IF;
 IF NEW.profile_digest<>decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex') OR NOT EXISTS(
  SELECT 1 FROM control.business_signing_key k JOIN control.business_signing_key_state life USING(participant_id,privacy_domain_id,signer_id)
   JOIN control.credential credential ON credential.participant_id=k.participant_id AND credential.credential_id=k.workload_credential_id
   JOIN control.principal principal ON principal.participant_id=credential.participant_id AND principal.principal_id=credential.principal_id
   JOIN control.participant participant ON participant.participant_id=k.participant_id
   WHERE k.participant_id=NEW.participant_id AND k.privacy_domain_id=NEW.privacy_domain_id AND k.signer_id=NEW.signer_id
    AND k.environment_id=NEW.environment_id AND k.signing_purpose_code=371 AND life.state='ACTIVE'
    AND k.valid_from_ns<=floor(extract(epoch from clock_timestamp())*1000000)*1000 AND k.valid_until_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000
    AND credential.state='ACTIVE' AND credential.kind IN('WORKLOAD_OIDC','WORKLOAD_MTLS') AND credential.credential_epoch=k.workload_credential_epoch
    AND credential.valid_from<=clock_timestamp() AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
    AND principal.kind='WORKLOAD' AND principal.state='ACTIVE' AND principal.authority_epoch=k.envelope_workload_principal_epoch
    AND participant.state='ACTIVE' AND participant.authority_epoch=k.envelope_workload_participant_epoch FOR SHARE OF life)
 THEN RAISE EXCEPTION 'DATA-6021-ENVELOPE-SIGNING-CURRENT-KEY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_envelope_signing_selection_immutable ON control.identity_envelope_signing_selection;
DROP TRIGGER IF EXISTS identity_envelope_signing_selection_guard ON control.identity_envelope_signing_selection;
CREATE TRIGGER identity_envelope_signing_selection_guard BEFORE INSERT OR UPDATE OR DELETE ON control.identity_envelope_signing_selection
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_envelope_signing_selection();

CREATE OR REPLACE FUNCTION openpc.select_identity_envelope_recovery_trust()
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE step control.identity_envelope_rotation_step; rotation control.signing_key_rotation;
 selected control.identity_envelope_signing_selection; next_key control.business_signing_key; changed integer;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO STRICT step FROM control.identity_envelope_rotation_step s WHERE s.operation_id=openpc.current_operation_id()
  AND openpc.matches_participant(s.participant_id) AND openpc.matches_privacy(s.privacy_domain_id)
  AND s.from_revision=5 AND s.from_state='VERIFIED' AND s.to_state='CUTOVER_FENCED' AND s.state='COMMITTED';
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' OR NOT coalesce(openpc.identity_envelope_rotation_step_current(step),false)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-SIGNING-CUTOVER'; END IF;
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation r WHERE r.participant_id=step.participant_id AND r.privacy_domain_id=step.privacy_domain_id
  AND r.rotation_id=step.rotation_id AND r.recovery_case_id=step.recovery_id AND r.state='CUTOVER_FENCED' AND r.revision=6;
 SELECT * INTO STRICT selected FROM control.identity_envelope_signing_selection s WHERE s.participant_id=step.participant_id AND s.privacy_domain_id=step.privacy_domain_id
  AND s.environment_id=rotation.environment_id AND s.profile_digest=decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex')
  AND s.signer_id=rotation.old_signer_id AND s.admission_version::text=step.authority_binding#>>'{lease,selectionAdmissionVersion}' FOR UPDATE;
 SELECT k.* INTO STRICT next_key FROM control.business_signing_key k JOIN control.identity_envelope_signing_grant g USING(participant_id,privacy_domain_id,signer_id)
  WHERE k.participant_id=step.participant_id AND k.privacy_domain_id=step.privacy_domain_id AND k.signer_id=rotation.new_signer_id AND k.signing_purpose_code=371
   AND g.signing_purpose_code=371 AND g.profile_digest=selected.profile_digest AND k.environment_id=selected.environment_id
   AND k.trust_digest=decode(substr(step.result->>'trustDigest',8),'hex');
 UPDATE control.business_signing_key_state SET state='ACTIVE',row_version=row_version+1,
  changed_at_ns=floor(extract(epoch from clock_timestamp())*1000000)*1000,change_reference='urn:openpc:resource:'||rotation.rotation_id::text,change_digest=step.evidence_digest
  WHERE participant_id=step.participant_id AND privacy_domain_id=step.privacy_domain_id AND signer_id=next_key.signer_id AND state='ADMITTED' AND row_version=1;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-SIGNING-CUTOVER-LIFECYCLE'; END IF;
 UPDATE control.identity_envelope_signing_selection SET signer_id=next_key.signer_id,admission_version=admission_version+1
  WHERE participant_id=selected.participant_id AND privacy_domain_id=selected.privacy_domain_id AND environment_id=selected.environment_id
   AND profile_digest=selected.profile_digest AND signer_id=selected.signer_id AND admission_version=selected.admission_version;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-SIGNING-CUTOVER-SELECTION'; END IF;
 RETURN jsonb_build_object('signerId',next_key.signer_id,'trustDigest','sha256:'||encode(next_key.trust_digest,'hex'),
  'selectionAdmissionVersion',(selected.admission_version+1)::text,'state','SELECTED');
END $$;
REVOKE ALL ON FUNCTION openpc.select_identity_envelope_recovery_trust() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.select_identity_envelope_recovery_trust() TO openpc_control_runtime,openpc_control_platform_runtime;
`;
