export const authenticationOccurrenceGuardsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.authentication_occurrence_receipt(
 p_id uuid,p_participant uuid,p_privacy uuid,p_principal uuid,p_session uuid,p_operation uuid,
 p_method text,p_source uuid,p_credential uuid,p_context text,p_proof bytea,p_occurred timestamptz)
RETURNS bytea LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,openpc,control AS $$
 SELECT convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'version','OPENPC_AUTHENTICATION_OCCURRENCE_V1','occurrenceId',p_id::text,
  'participantId',p_participant::text,'privacyDomainId',p_privacy::text,'principalId',p_principal::text,
  'operationId',p_operation::text,'method',p_method,'sourceId',p_source::text,
  'credentialDigest','sha256:'||encode(sha256(convert_to(p_credential::text,'UTF8')),'hex'),
  'contextMode',p_context,'proofDigest','sha256:'||encode(p_proof,'hex'),
  'occurredAt',to_char(p_occurred at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'authorityEffect','NONE','integrity','CONTROL_DATABASE_IMMUTABLE') ||
  CASE WHEN p_method='TLS13_MTLS' THEN jsonb_build_object('transportBindingDigest','sha256:'||encode(p_proof,'hex'))
  ELSE jsonb_build_object('sessionBindingDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
    'domain','openpc.authentication.session.v1','participantId',p_participant::text,'sessionId',p_session::text)),'UTF8')),'hex')) END),'UTF8')
$$;
CREATE OR REPLACE FUNCTION openpc.check_authentication_occurrence()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,openpc,control AS $$
DECLARE s record; c record; source record; expected_proof bytea;
BEGIN
 IF NEW.operation_id<>openpc.current_operation_id() OR NOT openpc.matches_participant(NEW.participant_id)
  OR NEW.occurred_at>clock_timestamp()+interval '5 seconds'
  OR NEW.occurred_at<clock_timestamp()-interval '5 minutes' THEN
  RAISE EXCEPTION 'IDENTITY-1004-AUTHENTICATION-OCCURRENCE-CONTEXT'; END IF;
 SELECT * INTO c FROM control.credential WHERE participant_id=NEW.participant_id AND credential_id=NEW.credential_id;
 IF NEW.method='TLS13_MTLS' THEN
  SELECT principal.*,participant.root_privacy_domain_id,participant.state participant_state INTO s
   FROM control.principal principal JOIN control.participant participant USING(participant_id)
   WHERE principal.participant_id=NEW.participant_id AND principal.principal_id=NEW.principal_id;
  IF c.credential_id IS NULL OR s.principal_id IS NULL OR c.principal_id<>NEW.principal_id
   OR c.kind<>'WORKLOAD_MTLS' OR c.state<>'ACTIVE' OR s.kind<>'WORKLOAD' OR s.state<>'ACTIVE' OR s.participant_state<>'ACTIVE'
   OR NEW.session_id IS NOT NULL OR NEW.context_mode<>'WORKLOAD' OR NEW.source_id<>NEW.operation_id
   OR NEW.occurred_at<>c.last_used_at OR c.valid_from>NEW.occurred_at OR c.valid_until<=NEW.occurred_at
   OR NEW.privacy_domain_id IS DISTINCT FROM coalesce(nullif(current_setting('openpc.privacy_domain_id',true),'')::uuid,s.root_privacy_domain_id)
   OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' THEN
   RAISE EXCEPTION 'IDENTITY-1006-AUTHENTICATION-MTLS-SOURCE'; END IF;
  expected_proof:=NEW.proof_digest;
 ELSE
 SELECT session.*,p.root_privacy_domain_id INTO s FROM control.session session
  JOIN control.participant p USING(participant_id)
  WHERE session.participant_id=NEW.participant_id AND session.session_id=NEW.session_id;
 IF s.session_id IS NULL OR c.credential_id IS NULL OR s.principal_id<>NEW.principal_id
  OR c.principal_id<>NEW.principal_id OR s.context_mode::text<>NEW.context_mode
  OR NEW.privacy_domain_id IS DISTINCT FROM coalesce(s.privacy_domain_id,s.root_privacy_domain_id)
  OR s.state<>'ACTIVE' OR c.state<>'ACTIVE' THEN
  RAISE EXCEPTION 'IDENTITY-1004-AUTHENTICATION-OCCURRENCE-SCOPE'; END IF;
 IF NEW.method='OIDC_CODE_PKCE_S256' THEN
  SELECT * INTO source FROM control.oidc_transaction WHERE transaction_id=NEW.source_id;
  IF source.transaction_id IS NULL OR source.consumed_at IS NULL OR source.purpose<>'SESSION'
   OR c.kind<>'OIDC_SUBJECT' OR c.issuer<>source.issuer OR c.audience<>source.client_id
   OR (source.selected_participant_id IS NOT NULL AND source.selected_participant_id<>NEW.participant_id)
   OR NEW.context_mode<>'PLATFORM' OR NEW.occurred_at<>s.issued_at
   OR openpc.current_action_intent_id()<>'ACT-IDENTITY_CREATE_SESSION-V1' THEN
   RAISE EXCEPTION 'IDENTITY-1004-AUTHENTICATION-OIDC-SOURCE'; END IF;
  expected_proof:=sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
   'version','OPENPC_OIDC_VERIFIED_V1','sourceId',source.transaction_id::text,'credentialId',NEW.credential_id::text,
   'stateDigest',encode(source.state_digest,'hex'),'nonceDigest',encode(source.nonce_digest,'hex'),
   'pkceDigest',encode(source.code_verifier_digest,'hex'),'browserDigest',encode(source.browser_session_digest,'hex'))),'UTF8'));
 ELSE
  SELECT challenge.* INTO source FROM control.mfa_challenge challenge
   WHERE challenge.participant_id=NEW.participant_id AND challenge.mfa_challenge_id=NEW.source_id;
  IF source.mfa_challenge_id IS NULL OR source.consumed_at IS NULL
   OR source.session_id<>NEW.session_id OR source.principal_id<>NEW.principal_id OR c.kind<>'WEBAUTHN'
   OR source.signer_credential_id IS DISTINCT FROM NEW.credential_id
   OR source.signer_credential_epoch IS DISTINCT FROM c.credential_epoch
   OR s.step_up_mfa_challenge_id IS DISTINCT FROM source.mfa_challenge_id
   OR s.step_up_verified_at IS DISTINCT FROM source.consumed_at
   OR NEW.occurred_at IS DISTINCT FROM source.consumed_at
   OR openpc.current_action_intent_id()<>'ACT-IDENTITY_UPDATE_STEP_UP-V1' THEN
   RAISE EXCEPTION 'IDENTITY-1004-AUTHENTICATION-WEBAUTHN-SOURCE'; END IF;
  SELECT evidence.webauthn_assertion_binding_digest INTO expected_proof FROM control.mutation_evidence evidence
   WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
    AND evidence.operation_id=NEW.operation_id AND evidence.principal_id=NEW.principal_id
    AND evidence.aggregate_id=NEW.session_id AND evidence.mfa_challenge_id=NEW.source_id
    AND evidence.signer_credential_id=NEW.credential_id AND evidence.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY';
 END IF;
 END IF;
 IF expected_proof IS NULL OR NEW.proof_digest<>expected_proof
  OR NEW.receipt<>openpc.authentication_occurrence_receipt(NEW.occurrence_id,NEW.participant_id,NEW.privacy_domain_id,
    NEW.principal_id,NEW.session_id,NEW.operation_id,NEW.method,NEW.source_id,NEW.credential_id,NEW.context_mode,
    NEW.proof_digest,NEW.occurred_at) THEN
  RAISE EXCEPTION 'IDENTITY-1004-AUTHENTICATION-OCCURRENCE-INTEGRITY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authentication_occurrence_verified ON control.authentication_occurrence;
CREATE CONSTRAINT TRIGGER authentication_occurrence_verified AFTER INSERT ON control.authentication_occurrence
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_authentication_occurrence();
DROP TRIGGER IF EXISTS authentication_occurrence_immutable ON control.authentication_occurrence;
CREATE TRIGGER authentication_occurrence_immutable BEFORE UPDATE OR DELETE ON control.authentication_occurrence
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
`;
export const authenticationOccurrenceGrantsSql = String.raw`
REVOKE ALL ON control.authentication_occurrence FROM openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance;
GRANT INSERT ON control.authentication_occurrence TO openpc_control_runtime,openpc_control_platform_runtime;
-- The owning schema's protected/preservation RLS policies admit only exact
-- source actions. Keep their table grant through later Identity-only upgrades.
GRANT SELECT ON control.authentication_occurrence TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader;
GRANT EXECUTE ON FUNCTION openpc.authentication_occurrence_receipt(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,text,bytea,timestamptz),openpc.check_authentication_occurrence()
 TO openpc_control_runtime,openpc_control_platform_runtime;
`;
