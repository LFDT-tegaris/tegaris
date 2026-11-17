import { signingContinuationReceiptGuardsSql } from './signing-continuation-receipt-guards.mjs';
/** Closed effect capability: issuance belongs to identity, consumption to the exact original operation. */
export const signingContinuationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.check_signing_continuation_context(context jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE command control.signing_rotation_command%ROWTYPE; attempt control.signing_provider_attempt%ROWTYPE;
 rotation control.signing_key_rotation%ROWTYPE; workload control.credential%ROWTYPE; snapshot jsonb;
 authority jsonb; evidence control.mutation_evidence%ROWTYPE; expected jsonb;
BEGIN
 SELECT * INTO STRICT attempt FROM control.signing_provider_attempt WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND attempt_id=(context->>'providerAttemptId')::uuid
  AND state='OBSERVED' AND dispatched_at_ns IS NOT NULL AND request->>'method' IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE');
 authority:=openpc.signing_attempt_authority_status(attempt.attempt_id);
 SELECT * INTO STRICT command FROM control.signing_rotation_command WHERE participant_id=attempt.participant_id
  AND privacy_domain_id=attempt.privacy_domain_id AND operation_id=attempt.operation_id AND state IN ('ACCEPTED','WRITE_AMBIGUITY')
  AND action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1';
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=attempt.participant_id
  AND privacy_domain_id=attempt.privacy_domain_id AND rotation_id=attempt.rotation_id AND approval_request_id IS NOT NULL;
 SELECT * INTO STRICT workload FROM control.credential c WHERE c.participant_id=attempt.participant_id
  AND c.credential_id=rotation.workload_credential_id AND c.state='ACTIVE' AND c.kind='WORKLOAD_MTLS'
  AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
  AND EXISTS(SELECT 1 FROM control.principal p WHERE p.participant_id=c.participant_id AND p.principal_id=c.principal_id
   AND p.kind='WORKLOAD' AND p.state='ACTIVE');
 SELECT * INTO STRICT evidence FROM control.mutation_evidence WHERE participant_id=command.participant_id
  AND privacy_domain_id=command.privacy_domain_id AND mutation_evidence_id=command.authorization_evidence_id
  AND operation_id=command.operation_id;
 IF NOT ((rotation.revision=attempt.from_revision AND rotation.state=attempt.from_state) OR
  (rotation.state='RECOVERING' AND rotation.recovery_from_revision=attempt.from_revision AND rotation.recovery_from_state=attempt.from_state))
  OR command.from_revision<>attempt.from_revision OR command.to_state<>attempt.to_state
  OR attempt.observation->>'attemptId'<>attempt.attempt_id::text OR attempt.observation->>'operationId'<>attempt.operation_id::text
  OR attempt.observation->>'method'<>attempt.request->>'method'
  OR attempt.observation->>'requestDigest'<>'sha256:'||encode(attempt.request_digest,'hex')
  OR attempt.observation->>'outcome' NOT IN ('SUCCEEDED','REJECTED')
  OR command.to_state IS DISTINCT FROM (CASE attempt.request->>'method' WHEN 'PREPARE' THEN 'PREPARED'
   WHEN 'DISTRIBUTE' THEN 'DISTRIBUTED' WHEN 'REVOKE' THEN 'OLD_REVOKED' WHEN 'RETIRE' THEN 'OLD_RETIRED' END)
  OR EXISTS(SELECT 1 FROM control.signing_rotation_command recovery WHERE recovery.participant_id=command.participant_id
   AND recovery.privacy_domain_id=command.privacy_domain_id AND recovery.original_operation_id=command.operation_id AND recovery.state='ACCEPTED')
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-EXACT-DISPATCHED-ATTEMPT'; END IF;
 snapshot:=convert_from(command.authorization_snapshot,'UTF8')::jsonb;
 expected:=jsonb_build_object('version',1,'purpose','SIGNING_ROTATION_ATTEMPT_RECONCILE_V1',
  'effect','FINALIZE_EXISTING_SIGNING_ROTATION_ATTEMPT','participantId',attempt.participant_id::text,
  'privacyDomainId',attempt.privacy_domain_id::text,'rotationId',rotation.rotation_id::text,'rotationRevision',rotation.revision::text,
  'operationId',command.operation_id::text,'actionIntentId',command.action_intent_id,'targetState',command.to_state,
  'candidateDigest','sha256:'||encode(command.approval_candidate_digest,'hex'),'approvalRequestId',command.approval_request_id::text,
  'originalActorKeyDigest','sha256:'||(openpc.business_cbor(evidence.evidence_cbor)->'1'->>'bytes'),
  'originalAuthoritySnapshotDigest','sha256:'||encode(command.authorization_snapshot_digest,'hex'),
  'originalMakerSnapshotDigest','sha256:'||encode(sha256(convert_to((snapshot->'authorities'->1)::text,'UTF8')),'hex'),
  'originalCheckerSnapshotDigest','sha256:'||encode(sha256(convert_to((snapshot->'authorities'->2)::text,'UTF8')),'hex'),
  'providerAttemptId',attempt.attempt_id::text,'providerMethod',attempt.request->>'method',
  'providerRequestDigest','sha256:'||encode(attempt.request_digest,'hex'),
  'providerObservationDigest','sha256:'||encode(attempt.observation_digest,'hex'),
  'resultDisposition',CASE WHEN attempt.observation->>'outcome'='SUCCEEDED' THEN 'APPLY_RESERVED_TARGET'
   WHEN attempt.observation->>'reason'='NOT_APPLIED' THEN 'NO_EFFECT_RETRYABLE' ELSE 'ENTER_FAILED_STATE' END,
  'workloadPrincipalId',workload.principal_id::text,'workloadCredentialId',workload.credential_id::text,
  'workloadCredentialEpoch',workload.credential_epoch::text,'workloadKeyDigest','sha256:'||encode(workload.public_key_digest,'hex'),
  'currentAuthorityStatus',CASE WHEN (authority->>'unchangedLive')::boolean THEN 'UNCHANGED_LIVE' ELSE 'CHANGED' END,
  'currentAuthorityDigest','sha256:'||encode(openpc.signing_continuation_authority_digest(authority),'hex'));
 IF context IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-CONTEXT'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_signing_continuation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE context jsonb; now_ns numeric;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-CONTINUATION-IMMUTABLE'; END IF;
 now_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
 context:=convert_from(NEW.context_preimage,'UTF8')::jsonb;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR NEW.operation_id IS DISTINCT FROM openpc.current_operation_id()
  OR openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'
  OR context->>'operationId' IS DISTINCT FROM NEW.operation_id::text OR context->>'providerAttemptId' IS DISTINCT FROM NEW.provider_attempt_id::text
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-SCOPE'; END IF;
 IF TG_OP='INSERT' THEN
  IF NOT pg_has_role(current_user,'openpc_signing_continuation_issuer','MEMBER') OR NEW.state<>'ISSUED'
   OR NEW.issued_at_ns>now_ns OR NEW.issued_at_ns<now_ns-1000000000 OR NEW.expires_at_ns<=now_ns
  THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-ISSUER'; END IF;
  PERFORM openpc.check_signing_continuation_context(context);
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','consumed_at_ns','consumed_receipt_id']) IS DISTINCT FROM
  (to_jsonb(OLD)-ARRAY['state','consumed_at_ns','consumed_receipt_id']) OR OLD.state<>'ISSUED'
 THEN RAISE EXCEPTION 'DATA-6020-CONTINUATION-IDENTITY'; END IF;
 IF NEW.state='EXPIRED' THEN
  IF NOT pg_has_role(current_user,'openpc_signing_continuation_issuer','MEMBER') OR OLD.expires_at_ns>now_ns
  THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-EXPIRY'; END IF;
 ELSIF NEW.state='CONSUMED' THEN
  IF pg_has_role(current_user,'openpc_control_worker','MEMBER') OR OLD.expires_at_ns<=now_ns OR NEW.consumed_at_ns IS NOT NULL
  THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-CONSUMPTION'; END IF;
  IF context->>'resultDisposition'='NO_EFFECT_RETRYABLE' THEN
   IF NEW.consumed_receipt_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_operation_evidence e
    WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id
     AND e.continuation_assertion_id=NEW.assertion_id AND e.kind='NO_EFFECT_RETRYABLE')
   THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-NO-EFFECT'; END IF;
  ELSE
   IF NEW.consumed_receipt_id IS NULL OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_attestation a JOIN control.signing_provider_attempt p USING(attempt_id)
    WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id AND a.operation_id=NEW.operation_id
     AND a.continuation_assertion_id=NEW.assertion_id AND a.attempt_id=NEW.consumed_receipt_id
     AND p.state='OBSERVED' AND p.observation->>'outcome'='SUCCEEDED')
   THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-CONSUMPTION'; END IF;
  END IF;
  PERFORM openpc.check_signing_continuation_context(context);
  NEW.consumed_at_ns:=now_ns;
 ELSE RAISE EXCEPTION 'DATA-6021-CONTINUATION-TRANSITION';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_continuation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_continuation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_continuation();
${signingContinuationReceiptGuardsSql}
`;
export const signingContinuationGrantsSql = `
GRANT INSERT,UPDATE(state) ON control.signing_continuation TO openpc_signing_continuation_issuer;
GRANT UPDATE(state,consumed_at_ns,consumed_receipt_id) ON control.signing_continuation TO openpc_control_runtime;
GRANT INSERT ON control.signing_rotation_authority_hold TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.check_signing_continuation_context(jsonb),
 openpc.check_signing_continuation_snapshot(bytea,uuid,uuid,uuid,uuid,numeric,boolean) TO openpc_control_runtime;
`;
