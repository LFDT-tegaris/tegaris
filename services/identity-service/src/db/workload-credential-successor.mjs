/** Historical commitment only. No current actor grant, certificate issuance or
 * arbitrary/multi-hop credential substitution is implied. Expressions are
 * supplied exclusively by the owning query, never request text. */
export function workloadCredentialSuccessorSql(binding) {
  if (binding.sourcePrefix !== undefined && !/^[a-z][a-z0-9_]*$/u.test(binding.sourcePrefix))
    throw new Error('Invalid continuation source prefix');
  const source = binding.sourcePrefix ?? 'control.';
  return `EXISTS (
    SELECT 1 FROM ${source}credential predecessor
    JOIN ${source}credential successor ON successor.participant_id=predecessor.participant_id
      AND successor.rotated_from_credential_id=predecessor.credential_id
      AND successor.principal_id=predecessor.principal_id AND successor.audience=predecessor.audience
    JOIN ${source}mutation_candidate candidate ON candidate.participant_id=predecessor.participant_id
      AND candidate.privacy_domain_id=${binding.privacyDomainId}
      AND candidate.resource_id=predecessor.credential_id
      AND candidate.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'
      AND candidate.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
      AND candidate.state='CONSUMED' AND candidate.consumed_operation_id IS NOT NULL
      AND candidate.candidate_document=jsonb_build_object('replacedCredentialId',predecessor.credential_id::text,
        'credentialId',successor.credential_id::text,
        'publicKeySpkiDer',replace(encode(successor.public_key_spki_der,'base64'),E'\\n',''))
      AND candidate.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(candidate.candidate_document),'UTF8'))
    JOIN ${source}approval_request approval ON approval.participant_id=candidate.participant_id
      AND approval.privacy_domain_id=candidate.privacy_domain_id AND approval.subject_type='CONFIGURATION_CANDIDATE'
      AND approval.subject_id=candidate.mutation_candidate_id AND approval.subject_digest=candidate.candidate_digest
      AND approval.maker_principal_id=candidate.maker_principal_id AND approval.state='APPROVED'
      AND approval.subject_version=candidate.expected_revision AND approval.action_intent_id=candidate.action_intent_id
    JOIN ${source}approval_decision_record decision ON decision.participant_id=approval.participant_id
      AND decision.privacy_domain_id=approval.privacy_domain_id AND decision.approval_request_id=approval.approval_request_id
      AND decision.decision='APPROVE' AND decision.candidate_digest=candidate.candidate_digest
      AND decision.approver_principal_id<>approval.maker_principal_id AND decision.cose_sign1 IS NOT NULL
      AND decision.aggregate_version=approval.subject_version
    JOIN ${source}mutation_evidence evidence ON evidence.participant_id=candidate.participant_id
      AND evidence.privacy_domain_id=candidate.privacy_domain_id AND evidence.operation_id=candidate.consumed_operation_id
      AND evidence.action_intent_id=candidate.action_intent_id AND evidence.catalog_operation_id=candidate.catalog_operation_id
      AND evidence.aggregate_type='workload-credential' AND evidence.aggregate_id=predecessor.credential_id
      AND evidence.candidate_digest=candidate.candidate_digest AND evidence.principal_id=approval.maker_principal_id
      AND evidence.checker_principal_id=decision.approver_principal_id AND evidence.approval_request_id=approval.approval_request_id
      AND evidence.evidence_digest=sha256(evidence.evidence_cbor) AND evidence.cose_sign1 IS NOT NULL
      AND evidence.evidence_cbor=decision.evidence_cbor AND evidence.cose_sign1=decision.cose_sign1
      AND evidence.signer_credential_id=decision.signer_credential_id
      AND evidence.webauthn_assertion_binding_digest IS NOT NULL AND evidence.mfa_challenge_id IS NOT NULL
    JOIN ${source}idempotency_record committed ON committed.participant_id=evidence.participant_id
      AND committed.privacy_domain_id=evidence.privacy_domain_id AND committed.operation_id=evidence.operation_id
      AND committed.action_intent_id=evidence.action_intent_id AND committed.catalog_operation_id=evidence.catalog_operation_id
      AND committed.principal_id=evidence.principal_id
      AND committed.terminal_state='COMMITTED' AND committed.input_digest=evidence.candidate_digest
      AND committed.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
      AND committed.result_payload->>'credentialId'=successor.credential_id::text
      AND committed.result_payload->>'replacedCredentialId'=predecessor.credential_id::text
      AND committed.result_payload->>'principalId'=successor.principal_id::text
      AND committed.result_payload->>'workloadId'=successor.audience
      AND committed.result_payload->>'workloadEpoch'=successor.credential_epoch::text
      AND committed.result_payload->>'state'='ACTIVE'
    JOIN ${source}outbox_event event ON event.participant_id=evidence.participant_id
      AND event.privacy_domain_id=evidence.privacy_domain_id AND event.aggregate_type=evidence.aggregate_type
      AND event.aggregate_id=evidence.aggregate_id AND event.payload_cbor=evidence.evidence_cbor
      AND event.event_type='openpc.identity.workload-credential.mutation.committed.v1'
      AND event.payload_digest=evidence.evidence_digest AND event.cose_sign1=evidence.cose_sign1
      AND event.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
    WHERE predecessor.participant_id=${binding.participantId}
      AND predecessor.credential_id=${binding.predecessorId} AND successor.credential_id=${binding.successorId}
      AND predecessor.kind='WORKLOAD_MTLS' AND predecessor.state='REVOKED'
      AND successor.kind='WORKLOAD_MTLS' AND successor.state='ACTIVE'
      AND predecessor.credential_epoch=${binding.predecessorEpoch}+1
      AND successor.credential_epoch=predecessor.credential_epoch
      AND successor.credential_epoch=${binding.successorEpoch}
      AND successor.valid_from<=clock_timestamp() AND successor.valid_until>clock_timestamp()
      ${binding.operationId ? `AND evidence.operation_id=${binding.operationId}` : ''}
  )`;
}

/** Installation/application readback for one enrolled371 predecessor. This
 * does not expose arbitrary credential or approval history to the host owner. */
export const workloadCredentialContinuationReadSql = `
-- Fixed request-scoped custody facts only; no protected historical table is
-- read here, so its use in their SELECT policies cannot recurse into itself.
CREATE OR REPLACE FUNCTION openpc.read_workload_credential_continuation_scope()
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE result jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_user<>'openpc_control_owner' OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
 THEN RETURN '[]'::jsonb; END IF;
 SELECT jsonb_agg(jsonb_build_object('enrollment_id',enrollment.enrollment_id,
  'participant_id',enrollment.participant_id,'privacy_domain_id',enrollment.privacy_domain_id,
  'document',enrollment.document,'workload_credential_id',source_key.workload_credential_id)) INTO result
 FROM control.identity_envelope_recovery_enrollment enrollment
 JOIN control.business_signing_key source_key ON source_key.participant_id=enrollment.participant_id
  AND source_key.privacy_domain_id=enrollment.privacy_domain_id AND source_key.signing_purpose_code=371
  AND source_key.signer_id=enrollment.document#>>'{request,oldFingerprint}'
  AND source_key.secret_reference=enrollment.document#>>'{request,oldReference}'
  AND 'sha256:'||encode(source_key.trust_digest,'hex')=enrollment.document->>'oldTrustDigest'
 WHERE openpc.matches_participant(enrollment.participant_id) AND openpc.matches_privacy(enrollment.privacy_domain_id)
  AND enrollment.state='ACTIVE' AND enrollment.row_version=1
  AND enrollment.valid_from<=clock_timestamp() AND enrollment.valid_until>clock_timestamp()
  AND openpc.identity_envelope_recovery_source_current(enrollment.enrollment_id);
 RETURN coalesce(result,'[]'::jsonb);
END $$;
REVOKE ALL ON FUNCTION openpc.read_workload_credential_continuation_scope() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_workload_credential_continuation_scope() TO openpc_control_owner;

-- Separate SECURITY DEFINER planning boundaries prevent recursive expansion
-- of the same RLS provenance joins. Returned IDs remain exact source facts.
CREATE OR REPLACE FUNCTION openpc.read_workload_credential_continuation_ids(p_enrollment uuid,p_kind text)
RETURNS uuid[] LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE enrollment control.identity_envelope_recovery_enrollment; source_key control.business_signing_key; result uuid[]; candidates uuid[];
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_user<>'openpc_control_owner' OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR p_kind NOT IN ('CANDIDATE','APPROVAL') OR p_kind IS NULL
  OR openpc.identity_envelope_recovery_source_current(p_enrollment) IS DISTINCT FROM TRUE
 THEN RETURN ARRAY[]::uuid[]; END IF;
 SELECT * INTO enrollment FROM control.identity_envelope_recovery_enrollment
  WHERE enrollment_id=p_enrollment AND openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
   AND state='ACTIVE' AND row_version=1 AND valid_from<=clock_timestamp() AND valid_until>clock_timestamp();
 IF NOT FOUND THEN RETURN ARRAY[]::uuid[]; END IF;
 SELECT * INTO source_key FROM control.business_signing_key
  WHERE participant_id=enrollment.participant_id AND privacy_domain_id=enrollment.privacy_domain_id AND signing_purpose_code=371
   AND signer_id=enrollment.document#>>'{request,oldFingerprint}' AND secret_reference=enrollment.document#>>'{request,oldReference}'
   AND 'sha256:'||encode(trust_digest,'hex')=enrollment.document->>'oldTrustDigest';
 IF NOT FOUND THEN RETURN ARRAY[]::uuid[]; END IF;
 IF p_kind='CANDIDATE' THEN
  SELECT array_agg(candidate.mutation_candidate_id) INTO result FROM control.mutation_candidate candidate
   WHERE candidate.participant_id=enrollment.participant_id AND candidate.privacy_domain_id=enrollment.privacy_domain_id
    AND candidate.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND candidate.state='CONSUMED'
    AND candidate.resource_id=source_key.workload_credential_id
    AND candidate.candidate_document->>'replacedCredentialId'=source_key.workload_credential_id::text
    AND candidate.candidate_document->>'credentialId'=enrollment.document#>>'{request,workloadCredentialId}';
 ELSE
  candidates:=openpc.read_workload_credential_continuation_ids(p_enrollment,'CANDIDATE');
  SELECT array_agg(approval.approval_request_id) INTO result FROM control.approval_request approval
   WHERE approval.participant_id=enrollment.participant_id AND approval.privacy_domain_id=enrollment.privacy_domain_id
    AND approval.subject_type='CONFIGURATION_CANDIDATE' AND approval.state='APPROVED'
    AND approval.subject_id=ANY(candidates);
 END IF;
 RETURN coalesce(result,ARRAY[]::uuid[]);
END $$;
REVOKE ALL ON FUNCTION openpc.read_workload_credential_continuation_ids(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_workload_credential_continuation_ids(uuid,text) TO openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.read_workload_credential_continuation_evidence(p_enrollment uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE scope jsonb; approvals uuid[]; decisions jsonb; result jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_user<>'openpc_control_owner' OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
 THEN RETURN '[]'::jsonb; END IF;
 SELECT source INTO scope FROM jsonb_array_elements(openpc.read_workload_credential_continuation_scope()) source
  WHERE source->>'enrollment_id'=p_enrollment::text;
 IF NOT FOUND THEN RETURN '[]'::jsonb; END IF;
 approvals:=openpc.read_workload_credential_continuation_ids(p_enrollment,'APPROVAL');
 SELECT jsonb_agg(jsonb_build_object('principal',decision.approver_principal_id,'signer',decision.signer_credential_id,
  'mfa',decision.mfa_challenge_id,'cbor',encode(decision.evidence_cbor,'hex'),'cose',encode(decision.cose_sign1,'hex'))) INTO decisions
 FROM control.approval_decision_record decision
 WHERE decision.participant_id=(scope->>'participant_id')::uuid AND decision.privacy_domain_id=(scope->>'privacy_domain_id')::uuid
  AND decision.decision='APPROVE' AND decision.approval_request_id=ANY(approvals);
 SELECT jsonb_agg(jsonb_build_object('operation_id',history.operation_id,'aggregate_type',history.aggregate_type,
  'aggregate_id',history.aggregate_id,'evidence_cbor',encode(history.evidence_cbor,'hex'),
  'evidence_digest',encode(history.evidence_digest,'hex'),'cose_sign1',encode(history.cose_sign1,'hex'))) INTO result
 FROM control.mutation_evidence history
 WHERE history.participant_id=(scope->>'participant_id')::uuid AND history.privacy_domain_id=(scope->>'privacy_domain_id')::uuid
  AND ((history.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND history.aggregate_id=(scope->>'workload_credential_id')::uuid)
   OR (history.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY' AND EXISTS(
    SELECT 1 FROM jsonb_array_elements(decisions) decision WHERE decision->>'principal'=history.principal_id::text
     AND decision->>'signer'=history.signer_credential_id::text AND decision->>'mfa'=history.mfa_challenge_id::text
     AND decision->>'cbor'=encode(history.evidence_cbor,'hex') AND decision->>'cose'=encode(history.cose_sign1,'hex'))));
 RETURN coalesce(result,'[]'::jsonb);
END $$;
REVOKE ALL ON FUNCTION openpc.read_workload_credential_continuation_evidence(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_workload_credential_continuation_evidence(uuid) TO openpc_control_owner;

-- Nested row-security policies make JIT compilation disproportionate for this
-- bounded history read. Keep the setting local to this function and its calls.
CREATE OR REPLACE FUNCTION openpc.read_identity_envelope_credential_continuation(
 p_predecessor uuid,p_predecessor_epoch numeric,p_successor uuid,p_successor_epoch numeric,p_principal uuid)
RETURNS TABLE("principalId" text,"checkerPrincipalId" text,"credentialPublicKey" bytea,
 "credentialPublicKeyDigest" bytea,"evidenceCbor" bytea,"evidenceDigest" bytea,"coseSign1" bytea,
 "verificationCandidateDigest" bytea,"verificationSessionId" text,"verificationOccurredAt" timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on SET jit=off AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' OR p_predecessor=p_successor
  OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_recovery_enrollment enrollment
   JOIN control.business_signing_key key ON key.participant_id=enrollment.participant_id
    AND key.privacy_domain_id=enrollment.privacy_domain_id AND key.signing_purpose_code=371
    AND key.signer_id=enrollment.document#>>'{request,oldFingerprint}'
    AND key.secret_reference=enrollment.document#>>'{request,oldReference}'
    AND 'sha256:'||encode(key.trust_digest,'hex')=enrollment.document->>'oldTrustDigest'
    AND key.workload_credential_id=p_predecessor AND key.workload_credential_epoch=p_predecessor_epoch
   WHERE openpc.matches_participant(enrollment.participant_id) AND openpc.matches_privacy(enrollment.privacy_domain_id)
    AND enrollment.state='ACTIVE' AND enrollment.row_version=1
    AND openpc.identity_envelope_recovery_source_current(enrollment.enrollment_id)
    AND enrollment.valid_from<=clock_timestamp() AND enrollment.valid_until>clock_timestamp()
    AND enrollment.document#>>'{request,workloadCredentialId}'=p_successor::text
    AND enrollment.document->>'issuerCredentialEpoch'=p_successor_epoch::text
    AND enrollment.document->>'issuerPrincipalId'=p_principal::text)
 THEN RETURN; END IF;
 RETURN QUERY WITH
 continuation_mutation_candidate AS MATERIALIZED (
  SELECT candidate.* FROM control.mutation_candidate candidate WHERE candidate.participant_id=openpc.current_participant_id()
   AND candidate.privacy_domain_id=openpc.current_privacy_domain_id() AND candidate.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'
   AND candidate.resource_id=p_predecessor AND candidate.candidate_document->>'credentialId'=p_successor::text),
 continuation_approval_request AS MATERIALIZED (
  SELECT approval.* FROM control.approval_request approval WHERE approval.participant_id=openpc.current_participant_id()
   AND approval.privacy_domain_id=openpc.current_privacy_domain_id()
   AND approval.subject_id IN(SELECT candidate.mutation_candidate_id FROM continuation_mutation_candidate candidate)),
 continuation_approval_decision_record AS MATERIALIZED (
  SELECT decision.* FROM control.approval_decision_record decision WHERE decision.participant_id=openpc.current_participant_id()
   AND decision.privacy_domain_id=openpc.current_privacy_domain_id()
   AND decision.approval_request_id IN(SELECT approval.approval_request_id FROM continuation_approval_request approval)),
 continuation_credential AS MATERIALIZED (
  SELECT credential.* FROM control.credential credential WHERE credential.participant_id=openpc.current_participant_id()
   AND (credential.credential_id IN(p_predecessor,p_successor)
    OR credential.credential_id IN(SELECT decision.signer_credential_id FROM continuation_approval_decision_record decision))),
 continuation_mfa_challenge AS MATERIALIZED (
  SELECT challenge.* FROM control.mfa_challenge challenge WHERE challenge.participant_id=openpc.current_participant_id()
   AND challenge.mfa_challenge_id IN(SELECT decision.mfa_challenge_id FROM continuation_approval_decision_record decision)),
 continuation_mutation_evidence AS MATERIALIZED (
  SELECT history.* FROM control.mutation_evidence history WHERE history.participant_id=openpc.current_participant_id()
   AND history.privacy_domain_id=openpc.current_privacy_domain_id()
   AND ((history.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND history.aggregate_id=p_predecessor)
    OR (history.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY' AND EXISTS(
     SELECT 1 FROM continuation_approval_decision_record decision WHERE decision.approver_principal_id=history.principal_id
      AND decision.signer_credential_id=history.signer_credential_id AND decision.mfa_challenge_id=history.mfa_challenge_id
      AND decision.evidence_cbor=history.evidence_cbor AND decision.cose_sign1=history.cose_sign1)))),
 continuation_idempotency_record AS MATERIALIZED (
  SELECT committed.* FROM control.idempotency_record committed WHERE committed.participant_id=openpc.current_participant_id()
   AND committed.privacy_domain_id=openpc.current_privacy_domain_id()
   AND committed.operation_id IN(SELECT history.operation_id FROM continuation_mutation_evidence history)),
 continuation_outbox_event AS MATERIALIZED (
  SELECT event.* FROM control.outbox_event event WHERE event.participant_id=openpc.current_participant_id()
   AND event.privacy_domain_id=openpc.current_privacy_domain_id() AND EXISTS(
    SELECT 1 FROM continuation_mutation_evidence history WHERE event.aggregate_type=history.aggregate_type
     AND event.aggregate_id=history.aggregate_id AND event.payload_cbor=history.evidence_cbor
     AND event.payload_digest=history.evidence_digest AND event.cose_sign1=history.cose_sign1))
 SELECT successor.principal_id::text,history.checker_principal_id::text,
  credential.public_key_spki_der,credential.public_key_digest,
  history.evidence_cbor,history.evidence_digest,history.cose_sign1,
  verified.candidate_digest,verified.session_id::text,verified.occurred_at
 FROM continuation_credential successor JOIN continuation_mutation_evidence history
  ON history.participant_id=successor.participant_id AND openpc.matches_privacy(history.privacy_domain_id)
   AND history.aggregate_id=p_predecessor AND history.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'
 JOIN continuation_mutation_candidate candidate ON candidate.participant_id=history.participant_id
  AND candidate.privacy_domain_id=history.privacy_domain_id AND candidate.consumed_operation_id=history.operation_id
  AND candidate.candidate_document->>'credentialId'=successor.credential_id::text
 JOIN continuation_approval_decision_record decision ON decision.participant_id=history.participant_id
  AND decision.privacy_domain_id=history.privacy_domain_id AND decision.approval_request_id=history.approval_request_id
  AND decision.approver_principal_id=history.checker_principal_id AND decision.decision='APPROVE'
  AND decision.evidence_cbor=history.evidence_cbor AND decision.cose_sign1=history.cose_sign1
 JOIN continuation_credential credential ON credential.participant_id=decision.participant_id
  AND credential.credential_id=decision.signer_credential_id AND credential.principal_id=decision.approver_principal_id
  AND credential.kind='WEBAUTHN' AND credential.valid_from<=decision.decided_at
  AND (credential.valid_until IS NULL OR credential.valid_until>decision.decided_at)
 LEFT JOIN LATERAL (
  SELECT verification.candidate_digest,challenge.session_id,verification.occurred_at
  FROM continuation_mutation_evidence verification JOIN continuation_mfa_challenge challenge
   ON challenge.participant_id=verification.participant_id AND challenge.mfa_challenge_id=verification.mfa_challenge_id
   AND challenge.principal_id=verification.principal_id AND challenge.session_id=verification.aggregate_id
   AND challenge.consumed_at IS NOT NULL AND challenge.mfa_challenge_id=decision.mfa_challenge_id
   AND challenge.action_intent_id='ACT-POLICY_APPROVE_REQUEST-V1' AND challenge.resource_digest=decision.decision_digest
  JOIN continuation_idempotency_record committed ON committed.participant_id=verification.participant_id
   AND committed.privacy_domain_id=verification.privacy_domain_id AND committed.principal_id=verification.principal_id
   AND committed.operation_id=verification.operation_id AND committed.catalog_operation_id=verification.catalog_operation_id
   AND committed.input_digest=verification.candidate_digest AND committed.terminal_state='COMMITTED'
   AND committed.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
  JOIN continuation_outbox_event event ON event.participant_id=verification.participant_id AND event.privacy_domain_id=verification.privacy_domain_id
   AND event.aggregate_type=verification.aggregate_type AND event.aggregate_id=verification.aggregate_id
   AND event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
   AND event.payload_cbor=verification.evidence_cbor AND event.payload_digest=verification.evidence_digest
   AND event.cose_sign1=verification.cose_sign1 AND event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
  WHERE verification.participant_id=decision.participant_id AND verification.privacy_domain_id=decision.privacy_domain_id
   AND verification.principal_id=decision.approver_principal_id AND verification.signer_credential_id=decision.signer_credential_id
   AND verification.evidence_cbor=decision.evidence_cbor AND verification.cose_sign1=decision.cose_sign1
   AND verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1' AND verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
   AND verification.aggregate_type='webauthn-verification' AND verification.evidence_digest=sha256(verification.evidence_cbor)
   AND verification.webauthn_assertion_binding_digest IS NOT NULL AND verification.occurred_at>=challenge.consumed_at
   AND verification.occurred_at<=decision.decided_at
 ) verified ON true
 WHERE openpc.matches_participant(successor.participant_id) AND successor.credential_id=p_successor
  AND successor.principal_id=p_principal
  AND ${workloadCredentialSuccessorSql({ participantId: 'openpc.current_participant_id()', privacyDomainId: 'history.privacy_domain_id', predecessorId: 'p_predecessor', predecessorEpoch: 'p_predecessor_epoch', successorId: 'p_successor', successorEpoch: 'p_successor_epoch', operationId: 'history.operation_id', sourcePrefix: 'continuation_' })}
 LIMIT 2;
END $$;
REVOKE ALL ON FUNCTION openpc.read_identity_envelope_credential_continuation(uuid,numeric,uuid,numeric,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_identity_envelope_credential_continuation(uuid,numeric,uuid,numeric,uuid)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;
