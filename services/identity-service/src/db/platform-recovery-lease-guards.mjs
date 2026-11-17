/** Recovery is a separate representation. Its current case and all fixed signers remain live dependencies. */
export const platformRecoveryLeaseGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.platform_recovery_envelope_current(p_envelope uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT EXISTS(SELECT 1 FROM control.authority_envelope e
  JOIN control.platform_recovery_case c ON c.recovery_id=e.recovery_case_id AND c.participant_id=e.participant_id
  JOIN control.platform_recovery_enrollment source ON source.enrollment_id=c.enrollment_id
   AND source.participant_id=c.participant_id AND source.privacy_domain_id=c.privacy_domain_id
  JOIN control.platform_context root ON root.platform_context_id=source.platform_context_id
  JOIN LATERAL jsonb_array_elements(c.lease_bindings) binding ON binding->>'envelopeId'=e.authority_envelope_id::text
  JOIN control.principal recipient ON recipient.participant_id=e.participant_id AND recipient.principal_id=e.principal_id
  WHERE e.authority_envelope_id=p_envelope AND e.representation='RECOVERY_V1' AND e.state='ACTIVE'
   AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(c.privacy_domain_id)
   AND e.valid_from<=clock_timestamp() AND e.valid_until>clock_timestamp() AND cardinality(e.runtime_capability_ids)=0
   AND (NOT (c.intent ? 'supersession') OR openpc.platform_recovery_supersession_current(c.participant_id,c.enrollment_id,c.intent->'supersession',c.intent->'preparation'))
   AND ((source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY')=(c.intent ? 'pendingExpiry'))
   AND (NOT (c.intent ? 'pendingExpiry') OR openpc.platform_recovery_pending_expiry_intent_current(c.participant_id,c.enrollment_id,c.intent))
   AND ((source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION')=(c.intent ? 'continuation'))
   AND (NOT (c.intent ? 'continuation') OR openpc.platform_recovery_continuation_current(c.participant_id,c.enrollment_id,c.intent->'continuation',c.intent->'preparation'))
   AND ((c.intent->>'schema'='pc.identity.platform-recovery-intent' AND source.document->>'schema'='pc.identity.platform-recovery-enrollment')
    OR (c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
     AND source.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
     AND false /* discovery-certificate-current */))
   AND c.state='ACTIVE' AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
   AND (source.document->>'assurance'<>'LOCAL_QA_VIRTUAL_AUTHENTICATOR' OR current_setting('openpc.local_qa_runtime',true)='1')
   AND (coalesce(c.intent#>>'{lifetimes,profile}','C17') NOT IN ('LOCAL_QA','LOCAL_QA_10X') OR (source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' AND current_setting('openpc.local_qa_runtime',true)='1'))
   AND source.state='ACTIVE' AND source.row_version=c.enrollment_revision AND source.document_digest=c.enrollment_digest
   AND source.valid_from<=clock_timestamp() AND source.valid_until>clock_timestamp()
   AND root.state='ACTIVE' AND root.authority_epoch=source.root_epoch AND root.row_version=source.root_revision
   AND root.owner_participant_id=e.participant_id AND openpc.platform_recovery_source_root_current(source)
   AND openpc.platform_recovery_original_administrators_current(source)
   AND e.platform_context_id=root.platform_context_id AND e.platform_authority_epoch=root.authority_epoch
   AND recipient.state='ACTIVE' AND recipient.authority_epoch::text=binding->>'principalEpoch'
   AND recipient.principal_id::text=binding->>'principalId'
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(jsonb_build_array(source.document->'recoveryPrincipal')||(source.document->'custodians')) signer
    WHERE NOT EXISTS(SELECT 1 FROM control.principal p JOIN control.credential credential
      ON credential.participant_id=p.participant_id AND credential.principal_id=p.principal_id
     WHERE p.participant_id=e.participant_id AND p.principal_id::text=signer->>'principalId' AND p.state='ACTIVE'
      AND p.authority_epoch::text=signer->>'principalEpoch' AND credential.credential_id::text=signer->>'credentialId'
      AND credential.credential_epoch::text=signer->>'credentialEpoch' AND credential.kind='WEBAUTHN' AND credential.state='ACTIVE'
      AND credential.valid_from<=clock_timestamp() AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
      AND (source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' OR EXISTS(SELECT 1 FROM control.hardware_authenticator hardware
       WHERE hardware.participant_id=p.participant_id AND hardware.principal_id=p.principal_id AND hardware.credential_id=credential.credential_id))))
 )
$$;

-- An exact committed proposal may retain its expired issuer/submission
-- provenance. The selected NEW lease supplies all current operation authority.
CREATE OR REPLACE FUNCTION openpc.platform_recovery_proposal_history_current(
 participant uuid,privacy uuid,selected uuid,proposal_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.authority_envelope receiving
  JOIN control.platform_recovery_case fresh ON fresh.participant_id=receiving.participant_id AND fresh.recovery_id=receiving.recovery_case_id
  JOIN control.platform_recovery_enrollment source ON source.enrollment_id=fresh.enrollment_id
   AND source.participant_id=fresh.participant_id AND source.privacy_domain_id=fresh.privacy_domain_id
  JOIN control.identity_envelope_proposal p ON p.participant_id=fresh.participant_id AND p.privacy_domain_id=fresh.privacy_domain_id
  JOIN control.mutation_candidate created ON created.participant_id=p.participant_id AND created.privacy_domain_id=p.privacy_domain_id
   AND created.mutation_candidate_id=p.create_candidate_id AND created.resource_id=p.envelope_id
   AND created.catalog_operation_id='ID-OP-ENVELOPE-CREATE' AND created.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   AND created.state='CONSUMED' AND created.consumed_operation_id=p.create_operation_id AND created.maker_principal_id=p.maker_principal_id
   AND created.expected_revision=0 AND created.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(created.candidate_document),'UTF8'))
  JOIN control.authority_envelope issuing ON issuing.participant_id=created.participant_id
   AND issuing.authority_envelope_id=created.maker_authority_envelope_id AND issuing.representation='RECOVERY_V1'
  JOIN control.platform_recovery_case historical_case ON historical_case.participant_id=issuing.participant_id
   AND historical_case.privacy_domain_id=p.privacy_domain_id AND historical_case.recovery_id=issuing.recovery_case_id
  JOIN control.approval_request creation_approval ON creation_approval.participant_id=created.participant_id
   AND creation_approval.privacy_domain_id=created.privacy_domain_id AND creation_approval.approval_request_id=p.create_approval_id
   AND creation_approval.subject_type='CONFIGURATION_CANDIDATE' AND creation_approval.subject_id=created.mutation_candidate_id
   AND creation_approval.subject_digest=created.candidate_digest AND creation_approval.subject_version=0
   AND creation_approval.action_intent_id=created.action_intent_id AND creation_approval.maker_principal_id=created.maker_principal_id
   AND creation_approval.state='APPROVED' AND creation_approval.checker_principal_id<>created.maker_principal_id
  JOIN control.mutation_evidence creation_evidence ON creation_evidence.participant_id=created.participant_id
   AND creation_evidence.privacy_domain_id=created.privacy_domain_id AND creation_evidence.operation_id=created.consumed_operation_id
   AND creation_evidence.catalog_operation_id=created.catalog_operation_id AND creation_evidence.action_intent_id=created.action_intent_id
   AND creation_evidence.principal_id=created.maker_principal_id AND creation_evidence.approval_request_id=p.create_approval_id
   AND creation_evidence.checker_principal_id=creation_approval.checker_principal_id
   AND creation_evidence.aggregate_type='authority-envelope' AND creation_evidence.aggregate_id=p.envelope_id
   AND creation_evidence.candidate_digest=created.candidate_digest AND creation_evidence.evidence_digest=sha256(creation_evidence.evidence_cbor)
   AND octet_length(creation_evidence.cose_sign1)>0 AND creation_evidence.webauthn_assertion_binding_digest IS NOT NULL
  JOIN control.idempotency_record creation_receipt ON creation_receipt.participant_id=created.participant_id
   AND creation_receipt.privacy_domain_id=created.privacy_domain_id AND creation_receipt.operation_id=created.consumed_operation_id
   AND creation_receipt.principal_id=created.maker_principal_id AND creation_receipt.action_intent_id=created.action_intent_id
   AND creation_receipt.catalog_operation_id=created.catalog_operation_id AND creation_receipt.idempotency_key=created.idempotency_key
   AND creation_receipt.input_digest=created.candidate_digest AND creation_receipt.expected_aggregate_version=0
   AND creation_receipt.terminal_state='COMMITTED' AND creation_receipt.result_payload->>'id'=p.envelope_id::text
   AND creation_receipt.result_payload->>'participantId'=p.target_participant_id::text
   AND creation_receipt.result_payload->>'semanticDigest'='sha256:'||encode(p.proposal_digest,'hex')
   AND creation_receipt.webauthn_assertion_binding_digest=creation_evidence.webauthn_assertion_binding_digest
  JOIN control.platform_recovery_case original ON original.participant_id=source.participant_id AND original.privacy_domain_id=source.privacy_domain_id
   AND original.recovery_id::text=fresh.intent#>>'{continuation,recoveryId}'
  WHERE receiving.participant_id=participant AND receiving.authority_envelope_id=selected
   AND fresh.privacy_domain_id=privacy AND openpc.matches_participant(participant) AND openpc.matches_privacy(privacy)
   AND receiving.representation='RECOVERY_V1' AND openpc.platform_recovery_envelope_current(selected)
   AND source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' AND source.document->>'schemaVersion'='3'
   AND historical_case.state='EXPIRED' AND historical_case.valid_until<=fresh.valid_from
   AND (historical_case.recovery_id=original.recovery_id OR
     (historical_case.intent->'continuation'=fresh.intent->'continuation'
      AND historical_case.intent->'preparation'=fresh.intent->'preparation'))
   AND p.envelope_id=proposal_id AND p.target_participant_id=participant
   AND p.maker_principal_id::text=fresh.intent#>>'{preparation,administrators,0,principalId}'
   AND p.state IN ('DRAFT','SUBMITTED','APPROVED') AND p.proposal_digest=sha256(p.proposal_cbor)
   AND EXISTS(SELECT 1 FROM control.outbox_event creation_event
    WHERE creation_event.participant_id=creation_evidence.participant_id AND creation_event.privacy_domain_id=creation_evidence.privacy_domain_id
     AND creation_event.aggregate_type=creation_evidence.aggregate_type AND creation_event.aggregate_id=creation_evidence.aggregate_id
     AND creation_event.payload_cbor=creation_evidence.evidence_cbor AND creation_event.payload_digest=creation_evidence.evidence_digest
     AND creation_event.cose_sign1=creation_evidence.cose_sign1
     AND creation_event.webauthn_assertion_binding_digest=creation_evidence.webauthn_assertion_binding_digest)
   AND created.candidate_document->>'platformScopeReplacementId'=fresh.intent#>>'{continuation,replacementId}'
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(fresh.intent#>'{preparation,administrators}') admin
    WHERE admin->>'envelopeId'=p.envelope_id::text
     AND created.candidate_document->'usable'=admin->'usable' AND created.candidate_document->'grantable'=admin->'grantable')
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(historical_case.lease_bindings) historical
    WHERE historical->>'envelopeId'=created.maker_authority_envelope_id::text
     AND historical->>'assignmentId'=created.maker_assignment_id::text
     AND historical->>'principalId'=created.maker_principal_id::text
     AND historical->>'principalEpoch'=created.maker_principal_epoch::text)
   AND p.issuer_authority#>>'{binding,authorityEnvelopeId}'=created.maker_authority_envelope_id::text
   AND p.issuer_authority#>>'{binding,assignmentId}'=created.maker_assignment_id::text
   AND p.issuer_authority#>>'{binding,assignmentVersion}'=created.maker_assignment_row_version::text
   AND p.issuer_authority#>>'{binding,sessionId}'=created.maker_session_id::text
   AND p.issuer_authority#>>'{binding,sessionEpoch}'=created.maker_session_epoch::text
   AND p.issuer_authority#>>'{binding,participantEpoch}'=created.maker_participant_epoch::text
   AND p.issuer_authority#>>'{binding,principalEpoch}'=created.maker_principal_epoch::text
   AND p.issuer_authority#>>'{binding,authorityEpoch}'=created.maker_authority_epoch::text
   AND p.issuer_authority#>>'{binding,delegationEpoch}'=created.maker_delegation_epoch::text
   AND (p.submission_checker_authority IS NULL OR EXISTS(SELECT 1 FROM control.authority_envelope checked
    JOIN control.platform_recovery_case checker_case ON checker_case.participant_id=checked.participant_id
     AND checker_case.recovery_id=checked.recovery_case_id AND checker_case.privacy_domain_id=p.privacy_domain_id
    CROSS JOIN LATERAL jsonb_array_elements(checker_case.lease_bindings) historical
     WHERE historical->>'envelopeId'=p.submission_checker_authority#>>'{binding,authorityEnvelopeId}'
      AND checked.participant_id=p.participant_id AND checked.authority_envelope_id::text=historical->>'envelopeId'
      AND checked.representation='RECOVERY_V1'
      AND (checker_case.recovery_id=original.recovery_id OR (checker_case.intent->'continuation'=fresh.intent->'continuation'
        AND checker_case.intent->'preparation'=fresh.intent->'preparation'))
      AND historical->>'assignmentId'=p.submission_checker_authority#>>'{binding,assignmentId}'
      AND historical->>'principalEpoch'=p.submission_checker_authority#>>'{binding,principalEpoch}'
      AND historical->>'principalId'=p.submission_checker_authority#>>'{binding,principalId}'
      AND historical->>'principalId'=fresh.intent#>>'{preparation,administrators,1,principalId}'
      AND p.submission_checker->'authority'=p.submission_checker_authority->'binding'))
 )
$$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_proposal_history_current(uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_proposal_history_current(uuid,uuid,uuid,uuid)
 TO openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.platform_recovery_approval_resume_subject_visible(
 participant uuid,privacy uuid,principal uuid,selected uuid,approval_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.approval_request a
  JOIN control.mutation_candidate c ON c.participant_id=a.participant_id AND c.privacy_domain_id=a.privacy_domain_id
   AND c.mutation_candidate_id=a.subject_id AND c.candidate_digest=a.subject_digest AND c.expected_revision=a.subject_version
   AND c.action_intent_id=a.action_intent_id AND c.maker_principal_id=a.maker_principal_id
  JOIN control.authority_envelope receiving ON receiving.participant_id=c.participant_id AND receiving.authority_envelope_id=selected
   AND receiving.principal_id=principal AND receiving.representation='RECOVERY_V1'
  JOIN control.platform_recovery_case fresh ON fresh.participant_id=receiving.participant_id AND fresh.recovery_id=receiving.recovery_case_id
  JOIN control.platform_recovery_case previous ON previous.participant_id=c.participant_id AND previous.privacy_domain_id=c.privacy_domain_id
   AND previous.recovery_id=(SELECT old.recovery_case_id FROM control.authority_envelope old
     WHERE old.participant_id=c.participant_id AND old.authority_envelope_id=c.maker_authority_envelope_id AND old.representation='RECOVERY_V1')
  WHERE a.participant_id=participant AND a.privacy_domain_id=privacy AND a.approval_request_id=approval_id
   AND openpc.matches_participant(participant) AND openpc.matches_privacy(privacy)
   AND fresh.intent->>'schema'='pc.identity.platform-recovery-intent' AND fresh.intent ? 'continuation'
   AND NOT (fresh.intent ? 'completionSourceDigest')
   AND openpc.platform_recovery_envelope_current(selected)
   AND principal::text=fresh.intent#>>'{preparation,administrators,0,principalId}'
   AND c.maker_principal_id=principal AND a.subject_type='CONFIGURATION_CANDIDATE'
   AND a.state IN ('OPEN','APPROVED','EXPIRED') AND c.state IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED')
   AND c.consumed_operation_id IS NULL
   AND a.checker_principal_id::text=fresh.intent#>>'{preparation,administrators,1,principalId}'
   AND a.maker_principal_id<>a.checker_principal_id
   AND (previous.recovery_id::text=fresh.intent#>>'{continuation,recoveryId}'
     OR (previous.intent->'continuation'=fresh.intent->'continuation'
       AND previous.intent->'preparation'=fresh.intent->'preparation'))
   AND previous.state='EXPIRED' AND previous.valid_until<=fresh.valid_from
   AND NOT openpc.platform_recovery_envelope_current(c.maker_authority_envelope_id)
   AND c.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE' AND c.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
   AND c.resource_type='participant' AND c.operation_class='ACTIVATE' AND c.expected_revision=3
   AND c.candidate_document=jsonb_build_object('envelopeId',c.resource_id::text)
   AND c.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(c.candidate_document),'UTF8'))
   AND openpc.platform_recovery_proposal_history_current(participant,privacy,selected,c.resource_id)
 ) OR EXISTS(SELECT 1 FROM control.authority_envelope receiving
  JOIN control.platform_recovery_case fresh ON fresh.participant_id=receiving.participant_id
    AND fresh.privacy_domain_id=privacy AND fresh.recovery_id=receiving.recovery_case_id
  WHERE receiving.participant_id=participant AND receiving.authority_envelope_id=selected
    AND receiving.principal_id=principal AND receiving.representation='RECOVERY_V1'
    AND openpc.matches_participant(participant) AND openpc.matches_privacy(privacy)
    AND fresh.intent ? 'approvalContinuation'
    AND principal::text=fresh.intent#>>'{preparation,administrators,0,principalId}'
    AND approval_id::text=fresh.intent#>>'{approvalContinuation,approvalId}'
    AND openpc.platform_recovery_envelope_current(selected)
    AND openpc.platform_recovery_pending_approval_current(participant,fresh.enrollment_id,fresh.intent)
 )
$$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_approval_resume_subject_visible(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_approval_resume_subject_visible(uuid,uuid,uuid,uuid,uuid)
 TO openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_platform_recovery_envelope()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
DECLARE recovery control.platform_recovery_case; source control.platform_recovery_enrollment; binding jsonb;
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.representation='RECOVERY_V1' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  RETURN OLD;
 END IF;
 IF NEW.representation<>'RECOVERY_V1' THEN RETURN NEW; END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 SELECT * INTO recovery FROM control.platform_recovery_case c WHERE c.recovery_id=NEW.recovery_case_id
  AND c.participant_id=NEW.participant_id AND c.state='ACTIVE' AND c.valid_until>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 SELECT * INTO source FROM control.platform_recovery_enrollment s WHERE s.enrollment_id=recovery.enrollment_id
  AND s.participant_id=recovery.participant_id AND s.privacy_domain_id=recovery.privacy_domain_id AND s.state='ACTIVE'
  AND s.row_version=recovery.enrollment_revision AND s.document_digest=recovery.enrollment_digest;
 SELECT value INTO binding FROM jsonb_array_elements(recovery.lease_bindings) a(value)
  WHERE value->>'envelopeId'=NEW.authority_envelope_id::text;
 IF source.enrollment_id IS NULL OR binding IS NULL OR NEW.state<>'ACTIVE' OR NEW.row_version<>1
  OR NEW.authority_epoch<>1 OR NEW.delegation_epoch<>0
  OR NEW.last_mutation_operation_id IS DISTINCT FROM recovery.activation_operation_id
  OR NEW.last_mutation_operation_id IS DISTINCT FROM openpc.current_operation_id()
  OR NEW.principal_id::text IS DISTINCT FROM binding->>'principalId'
  OR NEW.maker_principal_id::text IS DISTINCT FROM source.document#>>'{recoveryPrincipal,principalId}'
  OR NEW.checker_principal_id::text IS DISTINCT FROM source.document#>>'{custodians,0,principalId}'
  OR NEW.platform_context_id IS DISTINCT FROM source.platform_context_id OR NEW.platform_authority_epoch IS DISTINCT FROM source.root_epoch
  OR NEW.valid_from IS DISTINCT FROM (binding#>>'{permissions,validFrom}')::timestamptz OR NEW.valid_until IS DISTINCT FROM recovery.valid_until
  OR NEW.semantic_cbor IS DISTINCT FROM decode(binding->>'evidenceCbor','hex')
  OR NEW.semantic_digest IS DISTINCT FROM decode(binding->>'evidenceDigest','hex') OR NEW.semantic_digest<>sha256(NEW.semantic_cbor)
  OR NEW.cose_sign1 IS DISTINCT FROM decode(binding->>'coseSign1','hex') OR octet_length(NEW.cose_sign1)=0
  OR to_jsonb(NEW.privacy_domain_ids) IS DISTINCT FROM binding#>'{permissions,privacyDomainIds}'
  OR to_jsonb(NEW.action_intent_ids) IS DISTINCT FROM binding#>'{permissions,actionIntentIds}'
  OR to_jsonb(NEW.resource_ids) IS DISTINCT FROM binding#>'{permissions,resourceIds}'
  OR to_jsonb(NEW.risk_classes) IS DISTINCT FROM binding#>'{permissions,riskClasses}'
  OR cardinality(NEW.runtime_capability_ids)<>0 OR '*'=ANY(NEW.resource_ids)
  OR NOT NEW.maker_checker_required OR NOT NEW.step_up_required OR NEW.onward_delegation_depth<>0 THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authority_envelope_recovery_guard ON control.authority_envelope;
CREATE TRIGGER authority_envelope_recovery_guard BEFORE INSERT OR UPDATE OR DELETE ON control.authority_envelope
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_recovery_envelope();
`;
export const platformRecoveryLeaseGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_envelope_current(uuid) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;

/** The selected envelope is explicit: another grant held by the same principal cannot borrow this relation. */
export const platformRecoveryResourceSql = `
CREATE OR REPLACE FUNCTION openpc.administration_resource_permits(
 resources text[],target text,action text,participant uuid,principal uuid,authenticated_session uuid,selected_envelope uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE selected control.authority_envelope;
BEGIN
 SELECT * INTO selected FROM control.authority_envelope e WHERE e.participant_id=participant AND e.authority_envelope_id=selected_envelope;
 IF NOT FOUND THEN RETURN false; END IF;
 IF selected.representation<>'RECOVERY_V1' THEN
  RETURN openpc.administration_resource_permits(resources,target,action,participant,principal,authenticated_session);
 END IF;
 IF selected.principal_id IS DISTINCT FROM principal OR NOT (action=ANY(selected.action_intent_ids))
  OR NOT (resources<@selected.resource_ids) OR NOT openpc.platform_recovery_envelope_current(selected_envelope) THEN RETURN false; END IF;
 IF openpc.administration_resource_permits(resources,target,action,participant,principal,authenticated_session) THEN RETURN true; END IF;
 -- The consumed preparation remains immutable provenance of this exact
 -- continuation. Its approval can be read, never resumed or decided again.
 IF action='ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1' AND EXISTS(
   SELECT 1 FROM control.platform_recovery_case fresh
   JOIN control.platform_recovery_enrollment source ON source.participant_id=fresh.participant_id
    AND source.privacy_domain_id=fresh.privacy_domain_id AND source.enrollment_id=fresh.enrollment_id
   JOIN control.platform_scope_replacement replacement ON replacement.participant_id=fresh.participant_id
    AND replacement.privacy_domain_id=fresh.privacy_domain_id
    AND replacement.replacement_id::text=fresh.intent#>>'{continuation,replacementId}'
   JOIN control.mutation_candidate prepared ON prepared.participant_id=replacement.participant_id
    AND prepared.privacy_domain_id=replacement.privacy_domain_id
    AND prepared.mutation_candidate_id=replacement.prepare_candidate_id
   JOIN control.authority_envelope issuing ON issuing.participant_id=prepared.participant_id
    AND issuing.authority_envelope_id=prepared.maker_authority_envelope_id
   JOIN control.approval_request approval ON approval.participant_id=prepared.participant_id
    AND approval.privacy_domain_id=prepared.privacy_domain_id
    AND approval.approval_request_id=replacement.prepare_approval_id
    AND approval.subject_type='CONFIGURATION_CANDIDATE' AND approval.subject_id=prepared.mutation_candidate_id
    AND approval.subject_digest=prepared.candidate_digest AND approval.subject_version=prepared.expected_revision
   WHERE fresh.participant_id=participant AND openpc.matches_privacy(fresh.privacy_domain_id)
    AND fresh.recovery_id=selected.recovery_case_id AND fresh.intent->>'schema'='pc.identity.platform-recovery-intent'
    AND fresh.intent ? 'continuation'
    AND source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' AND source.document->>'schemaVersion'='3'
    AND source.document->>'schema'='pc.identity.platform-recovery-enrollment'
    AND issuing.representation='RECOVERY_V1'
    AND issuing.recovery_case_id::text=fresh.intent#>>'{continuation,recoveryId}'
    AND principal::text IN(fresh.intent#>>'{preparation,administrators,0,principalId}',fresh.intent#>>'{preparation,administrators,1,principalId}')
    AND target=fresh.intent#>>'{continuation,preparationApprovalId}' AND approval.approval_request_id::text=target
    AND replacement.replacement_id::text=ANY(resources) AND replacement.state='WITHDRAWING' AND replacement.row_version=1
    AND prepared.mutation_candidate_id::text=fresh.intent#>>'{continuation,preparationCandidateId}'
    AND prepared.state='CONSUMED' AND prepared.consumed_operation_id=replacement.prepare_operation_id
    AND prepared.consumed_operation_id::text=fresh.intent#>>'{continuation,preparationOperationId}'
    AND prepared.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' AND prepared.expected_revision=0
    AND prepared.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' AND approval.action_intent_id=prepared.action_intent_id
    AND prepared.resource_id=replacement.replacement_id AND prepared.candidate_document=fresh.intent->'preparation'
    AND prepared.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(prepared.candidate_document),'UTF8'))
    AND approval.state='APPROVED' AND approval.maker_principal_id=prepared.maker_principal_id
    AND approval.maker_principal_id::text=fresh.intent#>>'{preparation,administrators,0,principalId}'
    AND approval.checker_principal_id::text=fresh.intent#>>'{preparation,administrators,1,principalId}'
    AND approval.maker_principal_id<>approval.checker_principal_id
 ) THEN RETURN true; END IF;
 IF action IN ('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1')
  AND target ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  AND (openpc.discovery_approval_resume_subject_visible(participant,openpc.current_privacy_domain_id(),principal,selected_envelope,target::uuid)
    OR openpc.platform_recovery_approval_resume_subject_visible(participant,openpc.current_privacy_domain_id(),principal,selected_envelope,target::uuid))
 THEN RETURN EXISTS(SELECT 1 FROM control.approval_request approval JOIN control.mutation_candidate candidate
   ON candidate.participant_id=approval.participant_id AND candidate.privacy_domain_id=approval.privacy_domain_id
    AND candidate.mutation_candidate_id=approval.subject_id AND approval.subject_type='CONFIGURATION_CANDIDATE'
    AND approval.subject_digest=candidate.candidate_digest AND approval.subject_version=candidate.expected_revision
    AND approval.action_intent_id=candidate.action_intent_id AND approval.maker_principal_id=candidate.maker_principal_id
   WHERE approval.participant_id=participant AND openpc.matches_privacy(approval.privacy_domain_id)
    AND approval.approval_request_id=target::uuid AND candidate.maker_principal_id=principal
    AND candidate.resource_id::text=ANY(resources)); END IF;
 IF action IN ('ACT-POLICY_APPROVE_REQUEST-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','ACT-OPERATIONS_READ_OPERATION-V1') THEN
  RETURN EXISTS(SELECT 1 FROM control.mutation_candidate candidate
   JOIN control.authority_envelope maker ON maker.authority_envelope_id=candidate.maker_authority_envelope_id AND maker.participant_id=candidate.participant_id
   LEFT JOIN control.approval_request approval ON approval.participant_id=candidate.participant_id AND approval.privacy_domain_id=candidate.privacy_domain_id
    AND approval.subject_type='CONFIGURATION_CANDIDATE' AND approval.subject_id=candidate.mutation_candidate_id
    AND approval.subject_digest=candidate.candidate_digest AND approval.subject_version=candidate.expected_revision
    AND approval.maker_principal_id=candidate.maker_principal_id
   WHERE candidate.participant_id=participant AND openpc.matches_privacy(candidate.privacy_domain_id)
    AND maker.representation='RECOVERY_V1' AND maker.recovery_case_id=selected.recovery_case_id
    AND ((candidate.catalog_operation_id IN ('ID-OP-PLATFORM-SCOPE-PREPARE','ID-OP-PLATFORM-SCOPE-COMMIT',
      'ID-OP-ENVELOPE-CREATE','ID-OP-ENVELOPE-ACTIVATE','ID-OP-ASSIGNMENT-CREATE')
      AND EXISTS(SELECT 1 FROM control.platform_recovery_case c WHERE c.recovery_id=selected.recovery_case_id
       AND c.participant_id=participant AND c.intent->>'schema'='pc.identity.platform-recovery-intent'))
     OR (candidate.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'
      AND EXISTS(SELECT 1 FROM control.platform_recovery_case c WHERE c.recovery_id=selected.recovery_case_id
       AND c.participant_id=participant AND c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
       AND candidate.resource_id::text=c.intent#>>'{certificateRecovery,predecessorCredentialId}'
       AND candidate.expected_revision=(c.intent#>>'{certificateRecovery,predecessorRevision}')::numeric
       AND candidate.candidate_document=jsonb_build_object('replacedCredentialId',c.intent#>>'{certificateRecovery,predecessorCredentialId}',
        'credentialId',c.intent#>>'{certificateRecovery,successorCredentialId}',
        'publicKeySpkiDer',c.intent#>>'{certificateRecovery,successorPublicKeySpkiDer}'))))
    AND candidate.resource_id::text=ANY(resources)
    AND ((action='ACT-OPERATIONS_READ_OPERATION-V1' AND target=candidate.consumed_operation_id::text)
      OR (action<>'ACT-OPERATIONS_READ_OPERATION-V1' AND target=approval.approval_request_id::text)))
   OR EXISTS(SELECT 1 FROM control.identity_envelope_proposal proposal
    JOIN control.authority_envelope maker ON maker.authority_envelope_id::text=proposal.issuer_authority#>>'{binding,authorityEnvelopeId}'
     AND maker.participant_id=proposal.participant_id
     AND (maker.recovery_case_id=selected.recovery_case_id
       OR openpc.platform_recovery_proposal_history_current(participant,openpc.current_privacy_domain_id(),selected_envelope,proposal.envelope_id))
    JOIN control.platform_recovery_case c ON c.participant_id=maker.participant_id AND c.recovery_id=selected.recovery_case_id
     AND c.intent->>'schema'='pc.identity.platform-recovery-intent'
    WHERE proposal.participant_id=participant AND openpc.matches_privacy(proposal.privacy_domain_id)
     AND proposal.envelope_id::text=ANY(resources) AND action<>'ACT-OPERATIONS_READ_OPERATION-V1'
     AND proposal.submission_approval_id::text=target);
 END IF;
 RETURN false;
END $$;
`;
export const platformRecoveryResourceGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.administration_resource_permits(text[],text,text,uuid,uuid,uuid,uuid)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;

/** Historical projections without the new owner keep the new purpose denied. */
export function platformRecoveryLeaseProjectionSql(discoveryEnabled) {
  return discoveryEnabled
    ? platformRecoveryLeaseGuardsSql.replace(
        'false /* discovery-certificate-current */',
        "openpc.discovery_certificate_recovery_current(c.enrollment_id,c.recovery_id) AND openpc.discovery_certificate_recovery_administrators_current(c.enrollment_id,c.intent->'administrators',c.lease_bindings) AND (c.intent->>'schemaVersion'='1' OR (c.intent->>'schemaVersion'='2' AND openpc.discovery_certificate_resume_administrators_current(c.enrollment_id)))",
      )
    : platformRecoveryLeaseGuardsSql;
}
