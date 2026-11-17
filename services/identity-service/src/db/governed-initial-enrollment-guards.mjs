/** Projected by the Identity migration owner. No runtime role can install a
 * profile, change its account list, delete a receipt or replace an authenticator. */
export const governedInitialEnrollmentGuardsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.guard_governed_initial_profile()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,openpc,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'IDENTITY-1004-INITIAL-PROFILE-IMMUTABLE'; END IF;
 IF current_user<>'openpc_control_owner' OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id) THEN
  RAISE EXCEPTION 'IDENTITY-1002-INITIAL-PROFILE-OPERATOR'; END IF;
 IF TG_OP='UPDATE' AND (OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED'
  OR (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state')) THEN
  RAISE EXCEPTION 'IDENTITY-1004-INITIAL-PROFILE-IMMUTABLE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS governed_initial_profile_guard ON control.governed_initial_enrollment_profile;
CREATE TRIGGER governed_initial_profile_guard BEFORE INSERT OR UPDATE OR DELETE ON control.governed_initial_enrollment_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_governed_initial_profile();

CREATE OR REPLACE FUNCTION openpc.guard_governed_initial_enrollment()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,openpc,control AS $$
DECLARE selected record;
BEGIN
 IF TG_OP='UPDATE' AND NEW.governed_initial_profile_digest IS DISTINCT FROM OLD.governed_initial_profile_digest THEN
  RAISE EXCEPTION 'IDENTITY-1004-INITIAL-PROFILE-SUBSTITUTION'; END IF;
 IF NEW.governed_initial_profile_digest IS NULL THEN RETURN NEW; END IF;
 IF current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1' THEN
  RAISE EXCEPTION 'IDENTITY-1002-INITIAL-QA-ONLY'; END IF;
 SELECT profile.profile_digest INTO selected FROM control.governed_initial_enrollment_profile profile
 CROSS JOIN LATERAL jsonb_array_elements(profile.document->'accounts') account
 JOIN control.session session ON session.participant_id=profile.participant_id
  AND session.session_id=NEW.session_id AND session.principal_id=NEW.principal_id
 WHERE profile.profile_digest=NEW.governed_initial_profile_digest AND profile.participant_id=NEW.participant_id
  AND account->>'principalId'=NEW.principal_id::text AND profile.document->>'origin'=NEW.origin
  AND NEW.replaced_credential_id IS NULL
  AND session.context_mode='PLATFORM' AND session.state='ACTIVE'
  AND (TG_OP='UPDATE' OR (profile.state='ACTIVE' AND profile.valid_from<=clock_timestamp()
    AND profile.valid_until>clock_timestamp() AND session.step_up_verified_at IS NULL
    AND NEW.expires_at>clock_timestamp() AND NEW.expires_at<=NEW.created_at+interval '5 minutes'));
 IF NOT FOUND THEN RAISE EXCEPTION 'IDENTITY-1002-INITIAL-PROFILE-SOURCE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS governed_initial_enrollment_guard ON control.webauthn_enrollment;
CREATE TRIGGER governed_initial_enrollment_guard BEFORE INSERT OR UPDATE ON control.webauthn_enrollment
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_governed_initial_enrollment();

CREATE OR REPLACE FUNCTION openpc.check_governed_initial_result()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,openpc,control AS $$
DECLARE source record;
BEGIN
 SELECT enrollment.enrollment_id INTO source FROM control.webauthn_enrollment enrollment
 JOIN control.credential credential ON credential.participant_id=enrollment.participant_id
  AND credential.credential_id=enrollment.credential_id AND credential.principal_id=enrollment.principal_id
 JOIN control.governed_initial_enrollment_profile profile ON profile.participant_id=enrollment.participant_id
  AND profile.profile_digest=enrollment.governed_initial_profile_digest AND profile.privacy_domain_id=NEW.privacy_domain_id
 JOIN control.outbox_event event ON event.participant_id=NEW.participant_id AND event.privacy_domain_id=NEW.privacy_domain_id
  AND event.event_id=NEW.event_id AND event.aggregate_type='credential' AND event.aggregate_id=NEW.credential_id
  AND event.event_type='openpc.identity.webauthn.governed-initial-enrollment.completed.v1'
  AND event.payload_cbor=NEW.evidence_cbor AND event.payload_digest=NEW.evidence_digest AND event.cose_sign1=NEW.cose_sign1
 CROSS JOIN LATERAL jsonb_array_elements(profile.document->'accounts') account
 WHERE enrollment.participant_id=NEW.participant_id AND enrollment.principal_id=NEW.principal_id
  AND enrollment.session_id=NEW.session_id AND enrollment.enrollment_id=NEW.enrollment_id
  AND enrollment.credential_id=NEW.credential_id AND enrollment.consumed_at IS NOT NULL
  AND profile.profile_digest=NEW.profile_digest AND account=NEW.document->'account'
  AND profile.state='ACTIVE' AND profile.valid_from<=NEW.committed_at AND profile.valid_until>clock_timestamp()
  AND NEW.committed_at<=clock_timestamp()+interval '5 seconds'
  AND NEW.committed_at>=clock_timestamp()-interval '1 minute'
  AND NEW.committed_at<enrollment.expires_at
  AND credential.kind='WEBAUTHN' AND credential.state='ACTIVE'
  AND NEW.document->>'origin'=enrollment.origin AND NEW.document->>'rpId'=enrollment.rp_id
  AND NEW.document->>'authenticatorPublicKeyDigest'='sha256:'||encode(credential.public_key_digest,'hex')
  AND NEW.document->>'attestationDigest'='sha256:'||encode(enrollment.attestation_digest,'hex');
 IF NOT FOUND OR NEW.operation_id<>openpc.current_operation_id() THEN
  RAISE EXCEPTION 'IDENTITY-1004-INITIAL-RESULT-SOURCE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS governed_initial_result_verified ON control.governed_initial_enrollment_result;
CREATE CONSTRAINT TRIGGER governed_initial_result_verified AFTER INSERT ON control.governed_initial_enrollment_result
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_governed_initial_result();
DROP TRIGGER IF EXISTS governed_initial_result_immutable ON control.governed_initial_enrollment_result;
CREATE TRIGGER governed_initial_result_immutable BEFORE UPDATE OR DELETE ON control.governed_initial_enrollment_result
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();

CREATE OR REPLACE FUNCTION openpc.check_governed_initial_completion()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,openpc,control AS $$
BEGIN
 IF NEW.governed_initial_profile_digest IS NOT NULL AND NEW.consumed_at IS NOT NULL
  AND NOT EXISTS(SELECT 1 FROM control.governed_initial_enrollment_result result
    WHERE result.participant_id=NEW.participant_id AND result.principal_id=NEW.principal_id
     AND result.session_id=NEW.session_id AND result.enrollment_id=NEW.enrollment_id
     AND result.credential_id=NEW.credential_id AND result.profile_digest=NEW.governed_initial_profile_digest) THEN
  RAISE EXCEPTION 'IDENTITY-1004-INITIAL-COMPLETION-RECEIPT'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS governed_initial_completion_verified ON control.webauthn_enrollment;
CREATE CONSTRAINT TRIGGER governed_initial_completion_verified AFTER INSERT OR UPDATE ON control.webauthn_enrollment
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_governed_initial_completion();
`;

export const governedInitialEnrollmentGrantsSql = String.raw`
REVOKE ALL ON control.governed_initial_enrollment_profile,control.governed_initial_enrollment_result
 FROM openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance,openpc_backup_operator;
GRANT SELECT ON control.governed_initial_enrollment_profile,control.governed_initial_enrollment_result TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT ON control.governed_initial_enrollment_result TO openpc_control_runtime,openpc_control_platform_runtime;
-- SHARE row locks need a column UPDATE grant. The immutable trigger and absence
-- of an UPDATE policy reject every runtime write, including this column.
GRANT UPDATE(created_at) ON control.governed_initial_enrollment_profile TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.guard_governed_initial_enrollment(),openpc.check_governed_initial_result(),openpc.check_governed_initial_completion()
 TO openpc_control_runtime,openpc_control_platform_runtime;
`;
