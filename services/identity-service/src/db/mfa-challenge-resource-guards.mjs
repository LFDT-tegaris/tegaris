/** Existing legacy rows retain NULL. A new assertion resource is immutable
 * with its action/digest/session binding; it cannot be attached after issuance. */
export const mfaChallengeResourceGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_mfa_challenge_resource()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.verified_proof_max_age_ms=3000000 AND (
    NEW.consumed_at IS NOT NULL OR NEW.used_at IS NOT NULL
    OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
    OR current_setting('openpc.local_qa_duration_profile',true) IS DISTINCT FROM 'LOCAL_QA_10X'
    OR NEW.action_intent_id IS DISTINCT FROM openpc.current_action_intent_id()
    OR NOT EXISTS (SELECT 1 FROM control.session session
      WHERE session.participant_id=NEW.participant_id AND session.session_id=NEW.session_id
        AND session.principal_id=NEW.principal_id AND session.duration_profile='LOCAL_QA_10X'
        AND session.state='ACTIVE' AND session.idle_expires_at>clock_timestamp()
        AND session.absolute_expires_at>clock_timestamp()
        AND NEW.expires_at<=session.idle_expires_at AND NEW.expires_at<=session.absolute_expires_at)
  ) THEN RAISE EXCEPTION 'PC-AUTH-0005-STEP-UP-DURATION-PROVENANCE'; END IF;
  RETURN NEW;
 END IF;
 IF (NEW.participant_id,NEW.session_id,NEW.principal_id,NEW.action_intent_id,NEW.resource_id,
     NEW.resource_digest,NEW.challenge_digest,NEW.rp_id_hash,NEW.created_at,NEW.verified_proof_max_age_ms)
 IS DISTINCT FROM
    (OLD.participant_id,OLD.session_id,OLD.principal_id,OLD.action_intent_id,OLD.resource_id,
     OLD.resource_digest,OLD.challenge_digest,OLD.rp_id_hash,OLD.created_at,OLD.verified_proof_max_age_ms) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-STEP-UP-BINDING-IMMUTABLE';
 END IF;
 IF NEW.expires_at>OLD.expires_at THEN
  RAISE EXCEPTION 'PC-AUTH-0005-STEP-UP-EXPIRY-EXTENSION';
 END IF;
 IF OLD.consumed_at IS NOT NULL AND
   (NEW.consumed_at,NEW.signer_credential_id,NEW.signer_credential_epoch)
   IS DISTINCT FROM (OLD.consumed_at,OLD.signer_credential_id,OLD.signer_credential_epoch) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-STEP-UP-VERIFICATION-IMMUTABLE';
 END IF;
 IF OLD.used_at IS NOT NULL AND (NEW.used_at,NEW.used_operation_id) IS DISTINCT FROM (OLD.used_at,OLD.used_operation_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-STEP-UP-CONSUMPTION-IMMUTABLE';
 END IF;
 IF OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL AND NOT EXISTS (
   SELECT 1 FROM control.credential credential WHERE credential.participant_id=NEW.participant_id
    AND credential.principal_id=NEW.principal_id AND credential.credential_id=NEW.signer_credential_id
    AND credential.credential_epoch=NEW.signer_credential_epoch AND credential.kind='WEBAUTHN'
    AND credential.state='ACTIVE' AND credential.valid_from<=clock_timestamp()
    AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
 ) THEN RAISE EXCEPTION 'PC-AUTH-0005-STEP-UP-VERIFICATION-SIGNER'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS mfa_challenge_resource_binding ON control.mfa_challenge;
CREATE TRIGGER mfa_challenge_resource_binding BEFORE INSERT OR UPDATE ON control.mfa_challenge
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_mfa_challenge_resource();

-- Only adopting/changing a proof source reads its original authentication
-- receipt. Ordinary refresh/configuration and INSERT-only platform login do
-- not need access to historical authentication occurrences.
CREATE OR REPLACE FUNCTION openpc.check_session_step_up_source()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE matches bigint;
BEGIN
 IF TG_OP='UPDATE' AND (NEW.step_up_mfa_challenge_id,NEW.step_up_verified_at)
   IS NOT DISTINCT FROM (OLD.step_up_mfa_challenge_id,OLD.step_up_verified_at) THEN RETURN NEW; END IF;
 IF NEW.step_up_mfa_challenge_id IS NULL THEN RETURN NEW; END IF;
 IF openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-IDENTITY_UPDATE_STEP_UP-V1'
   OR NEW.step_up_verified_at IS NULL OR NEW.state<>'ACTIVE' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-STEP-UP-SOURCE';
 END IF;
 SELECT count(*) INTO matches FROM control.mfa_challenge challenge
  JOIN control.credential credential ON credential.participant_id=challenge.participant_id
   AND credential.principal_id=challenge.principal_id AND credential.credential_id=challenge.signer_credential_id
   AND credential.credential_epoch=challenge.signer_credential_epoch
   AND credential.kind='WEBAUTHN' AND credential.state='ACTIVE'
   AND credential.valid_from<=clock_timestamp()
   AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
  JOIN control.authentication_occurrence occurrence ON occurrence.participant_id=challenge.participant_id
   AND occurrence.principal_id=challenge.principal_id AND occurrence.session_id=challenge.session_id
   AND occurrence.source_id=challenge.mfa_challenge_id AND occurrence.method='WEBAUTHN_ASSERTION'
   AND occurrence.credential_id=credential.credential_id AND occurrence.occurred_at=challenge.consumed_at
   AND occurrence.operation_id=openpc.current_operation_id()
  JOIN control.mutation_evidence verification ON verification.participant_id=occurrence.participant_id
   AND verification.privacy_domain_id=occurrence.privacy_domain_id AND verification.principal_id=occurrence.principal_id
   AND verification.operation_id=occurrence.operation_id AND verification.mfa_challenge_id=challenge.mfa_challenge_id
   AND verification.aggregate_id=challenge.session_id AND verification.aggregate_type='webauthn-verification'
   AND verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
   AND verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
   AND verification.signer_credential_id=credential.credential_id
   AND verification.webauthn_assertion_binding_digest=occurrence.proof_digest
   AND verification.evidence_digest=sha256(verification.evidence_cbor)
   AND verification.bound_participant_epoch=NEW.participant_epoch AND verification.bound_principal_epoch=NEW.authority_epoch
   AND verification.occurred_at>=challenge.consumed_at
  JOIN control.idempotency_record committed ON committed.participant_id=verification.participant_id
   AND committed.privacy_domain_id=verification.privacy_domain_id AND committed.principal_id=verification.principal_id
   AND committed.operation_id=verification.operation_id AND committed.catalog_operation_id=verification.catalog_operation_id
   AND committed.input_digest=verification.candidate_digest AND committed.terminal_state='COMMITTED'
   AND committed.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
  JOIN control.outbox_event event ON event.participant_id=verification.participant_id
   AND event.privacy_domain_id=verification.privacy_domain_id AND event.aggregate_type=verification.aggregate_type
   AND event.aggregate_id=verification.aggregate_id AND event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
   AND event.payload_cbor=verification.evidence_cbor AND event.payload_digest=verification.evidence_digest
   AND event.cose_sign1=verification.cose_sign1 AND event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
  WHERE challenge.participant_id=NEW.participant_id AND challenge.principal_id=NEW.principal_id
   AND challenge.session_id=NEW.session_id AND challenge.mfa_challenge_id=NEW.step_up_mfa_challenge_id
   AND challenge.consumed_at=NEW.step_up_verified_at AND challenge.created_at<=challenge.consumed_at
   AND challenge.consumed_at<=clock_timestamp() AND challenge.expires_at>clock_timestamp()
   AND NEW.idle_expires_at>clock_timestamp() AND NEW.absolute_expires_at>clock_timestamp()
   AND (challenge.verified_proof_max_age_ms=300000 OR
     (challenge.verified_proof_max_age_ms=3000000 AND NEW.duration_profile='LOCAL_QA_10X'));
 IF matches<>1 THEN RAISE EXCEPTION 'PC-AUTH-0005-STEP-UP-SOURCE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS session_step_up_source_verified ON control.session;
CREATE CONSTRAINT TRIGGER session_step_up_source_verified AFTER INSERT OR UPDATE ON control.session
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_session_step_up_source();

-- The source was authenticated when its pair was committed. Consumers use
-- its immutable pin and current signer/parents without disclosing the receipt.
CREATE OR REPLACE FUNCTION openpc.session_step_up_valid_until(p_participant uuid,p_session uuid,p_principal uuid)
RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE WHEN session.step_up_mfa_challenge_id IS NULL THEN session.step_up_verified_at+interval '5 minutes'
  ELSE (SELECT least(challenge.consumed_at+make_interval(secs=>challenge.verified_proof_max_age_ms/1000.0),
    challenge.expires_at,session.idle_expires_at,session.absolute_expires_at,credential.valid_until)
   FROM control.mfa_challenge challenge JOIN control.credential credential
    ON credential.participant_id=challenge.participant_id AND credential.principal_id=challenge.principal_id
    AND credential.credential_id=challenge.signer_credential_id AND credential.credential_epoch=challenge.signer_credential_epoch
    AND credential.kind='WEBAUTHN' AND credential.state='ACTIVE' AND credential.valid_from<=clock_timestamp()
    AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
   WHERE challenge.participant_id=session.participant_id AND challenge.principal_id=session.principal_id
    AND challenge.session_id=session.session_id AND challenge.mfa_challenge_id=session.step_up_mfa_challenge_id
    AND challenge.consumed_at=session.step_up_verified_at AND challenge.created_at<=challenge.consumed_at
    AND challenge.consumed_at<=clock_timestamp()
    AND (challenge.verified_proof_max_age_ms=300000 OR
      (challenge.verified_proof_max_age_ms=3000000 AND session.duration_profile='LOCAL_QA_10X'))) END
 FROM control.session session
 JOIN control.participant participant ON participant.participant_id=session.participant_id
  AND participant.state='ACTIVE' AND participant.authority_epoch=session.participant_epoch
 JOIN control.principal principal ON principal.participant_id=session.participant_id
  AND principal.principal_id=session.principal_id AND principal.state='ACTIVE'
  AND principal.authority_epoch=session.authority_epoch
 WHERE session.participant_id=p_participant AND session.session_id=p_session AND session.principal_id=p_principal
  AND session.state='ACTIVE' AND session.idle_expires_at>clock_timestamp() AND session.absolute_expires_at>clock_timestamp()
$$;
REVOKE ALL ON FUNCTION openpc.session_step_up_valid_until(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.session_step_up_valid_until(uuid,uuid,uuid)
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader;
`;
