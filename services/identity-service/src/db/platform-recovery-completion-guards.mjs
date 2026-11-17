/** Admission of one unchanged, partly executed administrator handoff. */
export const platformRecoveryCompletionAdmissionSql = `
CREATE OR REPLACE FUNCTION openpc.platform_recovery_completion_admission_current(pid uuid,eid uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
#variable_conflict use_column
DECLARE
 fresh control.platform_recovery_enrollment;
 original control.platform_recovery_case;
 r control.platform_scope_replacement;
 participant uuid := pid;
 plan jsonb;
 witness record;
 administrator_ordinal integer := 1;
 approved_proposal_matched boolean := false;
 p record; e record; created record; issuing record; historical_case record;
 creation_approval record; creation_evidence record; creation_receipt record;
 activation record; activation_approval record;
BEGIN
 SELECT * INTO STRICT fresh FROM control.platform_recovery_enrollment WHERE participant_id=pid AND enrollment_id=eid;
 IF NOT openpc.matches_participant(pid) OR NOT openpc.matches_privacy(fresh.privacy_domain_id)
  OR fresh.source_purpose<>'ROOT_EXPIRY_RECOVERY_CONTINUATION'
  OR fresh.document#>>'{source,activatedHandoff,schemaVersion}' IS DISTINCT FROM '1'
 THEN RETURN false; END IF;
 SELECT * INTO STRICT original FROM control.platform_recovery_case
 WHERE participant_id=pid AND privacy_domain_id=fresh.privacy_domain_id
  AND recovery_id=(fresh.document#>>'{source,continuation,recoveryId}')::uuid;
 SELECT * INTO STRICT r FROM control.platform_scope_replacement
 WHERE participant_id=pid AND privacy_domain_id=fresh.privacy_domain_id
  AND replacement_id=(fresh.document#>>'{source,continuation,replacementId}')::uuid;
 IF openpc.platform_recovery_continuation_current(pid,eid,fresh.document#>'{source,continuation}',r.candidate) IS DISTINCT FROM true
  OR jsonb_array_length(fresh.document#>'{source,activatedHandoff,administrators}') IS DISTINCT FROM 2
 THEN RETURN false; END IF;
 FOR plan,administrator_ordinal IN SELECT value,ordinality FROM jsonb_array_elements(r.candidate->'administrators') WITH ORDINALITY LOOP
  SELECT fresh.document#>'{source,activatedHandoff,administrators}'->(administrator_ordinal-1)::integer AS declared INTO witness;
  IF witness.declared->>'principalId' IS DISTINCT FROM plan->>'principalId'
   OR witness.declared->>'envelopeId' IS DISTINCT FROM plan->>'envelopeId'
   OR witness.declared->>'assignmentId' IS DISTINCT FROM plan->>'assignmentId'
   OR EXISTS(SELECT 1 FROM control.assignment assigned WHERE assigned.participant_id=pid
      AND (assigned.assignment_id::text=plan->>'assignmentId' OR assigned.authority_envelope_id::text=plan->>'envelopeId'))
   OR EXISTS(SELECT 1 FROM control.mutation_candidate pending WHERE pending.participant_id=pid
      AND pending.privacy_domain_id=fresh.privacy_domain_id AND pending.resource_id::text=plan->>'assignmentId')
  THEN RETURN false; END IF;
  IF administrator_ordinal=2 THEN
   IF witness.declared#>>'{effect,state}' IS DISTINCT FROM 'ABSENT'
    OR EXISTS(SELECT 1 FROM control.authority_envelope existing WHERE existing.participant_id=pid AND existing.authority_envelope_id::text=plan->>'envelopeId')
    OR EXISTS(SELECT 1 FROM control.identity_envelope_proposal existing WHERE existing.participant_id=pid AND existing.privacy_domain_id=fresh.privacy_domain_id AND existing.envelope_id::text=plan->>'envelopeId')
    OR EXISTS(SELECT 1 FROM control.identity_envelope_activation existing WHERE existing.participant_id=pid AND existing.privacy_domain_id=fresh.privacy_domain_id AND existing.envelope_id::text=plan->>'envelopeId')
    OR EXISTS(SELECT 1 FROM control.mutation_candidate existing WHERE existing.participant_id=pid AND existing.privacy_domain_id=fresh.privacy_domain_id AND existing.resource_id::text=plan->>'envelopeId')
   THEN RETURN false; END IF;
  ELSE
   IF witness.declared#>>'{effect,state}' IS DISTINCT FROM 'ACTIVE_UNASSIGNED' THEN RETURN false; END IF;

          approved_proposal_matched:=false;
          <<proposal_match>>
          FOR p IN SELECT p.* FROM control.identity_envelope_proposal p WHERE p.participant_id=participant AND p.privacy_domain_id=fresh.privacy_domain_id AND p.envelope_id=CASE WHEN (plan->>'envelopeId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'envelopeId')::uuid ELSE NULL::uuid END LOOP
           FOR e IN SELECT e.* FROM control.authority_envelope e WHERE e.participant_id=p.participant_id AND e.authority_envelope_id=p.envelope_id LOOP
            FOR created IN SELECT created.* FROM control.mutation_candidate created WHERE created.participant_id=p.participant_id AND created.privacy_domain_id=p.privacy_domain_id
   AND created.mutation_candidate_id=p.create_candidate_id AND created.resource_id=p.envelope_id
   AND created.catalog_operation_id='ID-OP-ENVELOPE-CREATE' AND created.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   AND created.state='CONSUMED' AND created.consumed_operation_id=p.create_operation_id AND created.maker_principal_id=p.maker_principal_id
   AND created.expected_revision=0 AND created.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(created.candidate_document),'UTF8')) LOOP
             FOR issuing IN SELECT issuing.* FROM control.authority_envelope issuing WHERE issuing.participant_id=created.participant_id
   AND issuing.authority_envelope_id=created.maker_authority_envelope_id AND issuing.representation='RECOVERY_V1' LOOP
              FOR historical_case IN SELECT historical_case.* FROM control.platform_recovery_case historical_case WHERE historical_case.participant_id=issuing.participant_id
   AND historical_case.privacy_domain_id=p.privacy_domain_id AND historical_case.recovery_id=issuing.recovery_case_id LOOP
               FOR creation_approval IN SELECT creation_approval.* FROM control.approval_request creation_approval WHERE creation_approval.participant_id=created.participant_id
   AND creation_approval.privacy_domain_id=created.privacy_domain_id AND creation_approval.approval_request_id=p.create_approval_id
   AND creation_approval.subject_type='CONFIGURATION_CANDIDATE' AND creation_approval.subject_id=created.mutation_candidate_id
   AND creation_approval.subject_digest=created.candidate_digest AND creation_approval.subject_version=0
   AND creation_approval.action_intent_id=created.action_intent_id AND creation_approval.maker_principal_id=created.maker_principal_id
   AND creation_approval.state='APPROVED' AND creation_approval.checker_principal_id<>created.maker_principal_id LOOP
                FOR creation_evidence IN SELECT creation_evidence.* FROM control.mutation_evidence creation_evidence WHERE creation_evidence.participant_id=created.participant_id
   AND creation_evidence.privacy_domain_id=created.privacy_domain_id AND creation_evidence.operation_id=created.consumed_operation_id
   AND creation_evidence.catalog_operation_id=created.catalog_operation_id AND creation_evidence.action_intent_id=created.action_intent_id
   AND creation_evidence.principal_id=created.maker_principal_id AND creation_evidence.approval_request_id=p.create_approval_id
   AND creation_evidence.checker_principal_id=creation_approval.checker_principal_id
   AND creation_evidence.aggregate_type='authority-envelope' AND creation_evidence.aggregate_id=p.envelope_id
   AND creation_evidence.candidate_digest=created.candidate_digest AND creation_evidence.evidence_digest=sha256(creation_evidence.evidence_cbor)
   AND octet_length(creation_evidence.cose_sign1)>0 AND creation_evidence.webauthn_assertion_binding_digest IS NOT NULL LOOP
                 FOR creation_receipt IN SELECT creation_receipt.* FROM control.idempotency_record creation_receipt WHERE creation_receipt.participant_id=created.participant_id
   AND creation_receipt.privacy_domain_id=created.privacy_domain_id AND creation_receipt.operation_id=created.consumed_operation_id
   AND creation_receipt.principal_id=created.maker_principal_id AND creation_receipt.action_intent_id=created.action_intent_id
   AND creation_receipt.catalog_operation_id=created.catalog_operation_id AND creation_receipt.idempotency_key=created.idempotency_key
   AND creation_receipt.input_digest=created.candidate_digest AND creation_receipt.expected_aggregate_version=0
   AND creation_receipt.terminal_state='COMMITTED' AND creation_receipt.result_payload->>'id'=p.envelope_id::text
   AND creation_receipt.result_payload->>'participantId'=p.target_participant_id::text
   AND creation_receipt.result_payload->>'semanticDigest'='sha256:'||encode(p.proposal_digest,'hex')
   AND creation_receipt.webauthn_assertion_binding_digest=creation_evidence.webauthn_assertion_binding_digest LOOP
                  FOR activation IN SELECT activation.* FROM control.mutation_candidate activation WHERE activation.participant_id=p.participant_id AND activation.privacy_domain_id=p.privacy_domain_id
          AND activation.mutation_candidate_id=CASE WHEN (witness.declared#>>'{effect,activationCandidateId}') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (witness.declared#>>'{effect,activationCandidateId}')::uuid ELSE NULL::uuid END
          AND activation.resource_id=p.envelope_id AND activation.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
          AND activation.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
          AND activation.consumed_operation_id::text=witness.declared#>>'{effect,activationOperationId}'
          AND activation.expected_revision=3
          AND activation.candidate_document=jsonb_build_object('envelopeId',p.envelope_id::text)
          AND activation.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(activation.candidate_document),'UTF8'))
          AND activation.state='CONSUMED' AND activation.attempt::text=witness.declared#>>'{effect,activationAttempt}'
          AND 'sha256:'||encode(activation.candidate_digest,'hex')=witness.declared#>>'{effect,activationCandidateDigest}'
          AND NOT EXISTS(SELECT 1 FROM control.mutation_candidate later WHERE later.participant_id=activation.participant_id
            AND later.privacy_domain_id=activation.privacy_domain_id AND later.predecessor_candidate_id=activation.mutation_candidate_id) LOOP
                   <<proposal_receipt>>
                   FOR activation_approval IN SELECT activation_approval.* FROM control.approval_request activation_approval WHERE activation_approval.participant_id=activation.participant_id
          AND activation_approval.privacy_domain_id=activation.privacy_domain_id AND activation_approval.subject_id=activation.mutation_candidate_id
          AND activation_approval.subject_digest=activation.candidate_digest
          AND activation_approval.approval_request_id=CASE WHEN (witness.declared#>>'{effect,activationApprovalId}') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (witness.declared#>>'{effect,activationApprovalId}')::uuid ELSE NULL::uuid END
          AND activation_approval.state='APPROVED'
          AND activation_approval.subject_type='CONFIGURATION_CANDIDATE' AND activation_approval.subject_version=3
          AND activation_approval.action_intent_id=activation.action_intent_id
          AND activation_approval.maker_principal_id=activation.maker_principal_id
          AND activation_approval.checker_principal_id<>activation.maker_principal_id LOOP
                    IF (p.participant_id=participant) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.privacy_domain_id=fresh.privacy_domain_id) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.envelope_id=CASE WHEN (plan->>'envelopeId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'envelopeId')::uuid ELSE NULL::uuid END) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.envelope_id=CASE WHEN (witness.declared#>>'{effect,proposalEnvelopeId}') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (witness.declared#>>'{effect,proposalEnvelopeId}')::uuid ELSE NULL::uuid END) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.target_participant_id=participant) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.maker_principal_id=created.maker_principal_id) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (historical_case.recovery_id=original.recovery_id) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (EXISTS(SELECT 1 FROM jsonb_array_elements(historical_case.lease_bindings) binding
            WHERE binding->>'envelopeId'=created.maker_authority_envelope_id::text
              AND binding->>'assignmentId'=created.maker_assignment_id::text
              AND binding->>'principalId'=created.maker_principal_id::text
              AND binding->>'principalEpoch'=created.maker_principal_epoch::text)) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (EXISTS(SELECT 1 FROM control.outbox_event creation_event
            WHERE creation_event.participant_id=creation_evidence.participant_id
              AND creation_event.privacy_domain_id=creation_evidence.privacy_domain_id
              AND creation_event.aggregate_type=creation_evidence.aggregate_type AND creation_event.aggregate_id=creation_evidence.aggregate_id
              AND creation_event.payload_cbor=creation_evidence.evidence_cbor AND creation_event.payload_digest=creation_evidence.evidence_digest
              AND creation_event.cose_sign1=creation_evidence.cose_sign1
              AND creation_event.webauthn_assertion_binding_digest=creation_evidence.webauthn_assertion_binding_digest)) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.state='APPROVED') IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.row_version=3) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (witness.declared#>>'{effect,proposalRevision}'='3') IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.proposal_digest=sha256(p.proposal_cbor)) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF ('sha256:'||encode(p.proposal_digest,'hex')=witness.declared#>>'{effect,proposalDigest}') IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.create_candidate_id=CASE WHEN (witness.declared#>>'{effect,createCandidateId}') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (witness.declared#>>'{effect,createCandidateId}')::uuid ELSE NULL::uuid END) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.create_operation_id=CASE WHEN (witness.declared#>>'{effect,createOperationId}') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (witness.declared#>>'{effect,createOperationId}')::uuid ELSE NULL::uuid END) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (p.create_approval_id=CASE WHEN (witness.declared#>>'{effect,createApprovalId}') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (witness.declared#>>'{effect,createApprovalId}')::uuid ELSE NULL::uuid END) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (created.candidate_document->>'platformScopeReplacementId'=r.replacement_id::text) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (created.candidate_document->'usable'=plan->'usable') IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (created.candidate_document->'grantable'=plan->'grantable') IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.state='ACTIVE') IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.representation='TYPED_V1') IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.row_version=4) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.semantic_cbor=p.proposal_cbor) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.semantic_digest=p.proposal_digest) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.platform_context_id=r.platform_context_id) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.platform_authority_epoch=r.predecessor_epoch+1) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.valid_until>=fresh.valid_until) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (cardinality(e.runtime_capability_ids)=0) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.onward_delegation_depth=0) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.maker_checker_required) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.step_up_required) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (witness.declared#>>'{effect,envelopeRevision}'='4') IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (administrator_ordinal=1) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (EXISTS(SELECT 1 FROM control.identity_envelope_activation sealed
              JOIN control.idempotency_record receipt ON receipt.participant_id=sealed.participant_id
                AND receipt.privacy_domain_id=sealed.privacy_domain_id AND receipt.operation_id=sealed.operation_id
                AND receipt.idempotency_record_id=sealed.idempotency_record_id
              JOIN control.mutation_evidence activation_evidence ON activation_evidence.participant_id=sealed.participant_id
                AND activation_evidence.privacy_domain_id=sealed.privacy_domain_id AND activation_evidence.operation_id=sealed.operation_id
              WHERE sealed.participant_id=p.participant_id AND sealed.privacy_domain_id=p.privacy_domain_id
                AND sealed.envelope_id=p.envelope_id AND sealed.operation_id=activation.consumed_operation_id
                AND sealed.attempt_id::text=witness.declared#>>'{effect,activationAttemptId}'
                AND sealed.candidate_id=activation.mutation_candidate_id AND sealed.candidate_digest=activation.candidate_digest
                AND sealed.approval_request_id=activation_approval.approval_request_id
                AND sealed.proposal_digest=p.proposal_digest AND sealed.expected_approved_version=3
                AND sealed.state='COMMITTED' AND sealed.row_version=4 AND sealed.committed_at IS NOT NULL
                AND sealed.principal_id=activation.maker_principal_id AND sealed.idempotency_key=activation.idempotency_key
                AND sealed.payload_digest=sha256(sealed.payload_cbor)
                AND 'sha256:'||encode(sealed.payload_digest,'hex')=witness.declared#>>'{effect,activationPayloadDigest}'
                AND sealed.cose_sign1=e.cose_sign1 AND octet_length(sealed.cose_sign1)>0
                AND e.last_mutation_operation_id=sealed.operation_id
                AND sealed.maker_authority#>>'{binding,principalId}'=activation.maker_principal_id::text
                AND sealed.checker_authority#>>'{binding,principalId}'=activation_approval.checker_principal_id::text
                AND receipt.terminal_state='COMMITTED' AND receipt.expected_aggregate_version=3
                AND receipt.principal_id=activation.maker_principal_id AND receipt.input_digest=activation.candidate_digest
                AND receipt.catalog_operation_id=activation.catalog_operation_id AND receipt.action_intent_id=activation.action_intent_id
                AND receipt.idempotency_key=activation.idempotency_key
                AND activation_evidence.catalog_operation_id=activation.catalog_operation_id
                AND activation_evidence.action_intent_id=activation.action_intent_id
                AND activation_evidence.aggregate_type='authority-envelope' AND activation_evidence.aggregate_id=p.envelope_id
                AND activation_evidence.candidate_digest=activation.candidate_digest
                AND activation_evidence.approval_request_id=activation_approval.approval_request_id
                AND activation_evidence.principal_id=activation.maker_principal_id
                AND activation_evidence.checker_principal_id=activation_approval.checker_principal_id
                AND activation_evidence.evidence_digest=sha256(activation_evidence.evidence_cbor)
                AND 'sha256:'||encode(activation_evidence.evidence_digest,'hex')=witness.declared#>>'{effect,activationEvidenceDigest}'
                AND octet_length(activation_evidence.cose_sign1)>0
                AND activation_evidence.mfa_challenge_id IS NOT NULL
                AND activation_evidence.webauthn_assertion_binding_digest IS NOT NULL
                AND receipt.webauthn_assertion_binding_digest=activation_evidence.webauthn_assertion_binding_digest
                AND EXISTS(SELECT 1 FROM control.outbox_event published
                  WHERE published.participant_id=activation_evidence.participant_id AND published.privacy_domain_id=activation_evidence.privacy_domain_id
                    AND published.aggregate_type=activation_evidence.aggregate_type AND published.aggregate_id=activation_evidence.aggregate_id
                    AND published.payload_cbor=activation_evidence.evidence_cbor AND published.payload_digest=activation_evidence.evidence_digest
                    AND published.cose_sign1=activation_evidence.cose_sign1)
                AND EXISTS(SELECT 1 FROM jsonb_array_elements(original.lease_bindings) binding
                  WHERE binding->>'principalId'=activation.maker_principal_id::text
                    AND binding->>'envelopeId'=activation.maker_authority_envelope_id::text
                    AND binding->>'assignmentId'=activation.maker_assignment_id::text)
                AND NOT EXISTS(SELECT 1 FROM control.identity_envelope_activation another
                  WHERE another.participant_id=p.participant_id AND another.envelope_id=p.envelope_id AND another.operation_id<>sealed.operation_id)
                AND NOT EXISTS(SELECT 1 FROM control.mutation_candidate downstream
                  WHERE downstream.participant_id=p.participant_id AND downstream.privacy_domain_id=p.privacy_domain_id
                    AND (downstream.maker_authority_envelope_id=p.envelope_id
                      OR (downstream.resource_id=p.envelope_id AND downstream.mutation_candidate_id NOT IN (created.mutation_candidate_id,activation.mutation_candidate_id))))
            )) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    approved_proposal_matched:=true; EXIT proposal_match;
                   END LOOP;
                  END LOOP;
                 END LOOP;
                END LOOP;
               END LOOP;
              END LOOP;
             END LOOP;
            END LOOP;
           END LOOP;
          END LOOP;
          IF NOT approved_proposal_matched THEN RETURN false; END IF;

  END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;
ALTER FUNCTION openpc.platform_recovery_completion_admission_current(uuid,uuid) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.platform_recovery_completion_admission_current(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_completion_admission_current(uuid,uuid) TO openpc_control_owner;
`;

export const platformRecoveryCompletionAssignmentReadSql = `
DROP POLICY IF EXISTS platform_completion_assignment_case_read ON control.platform_recovery_case;
CREATE POLICY platform_completion_assignment_case_read ON control.platform_recovery_case FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND current_setting('openpc.local_qa_runtime',true)='1'
  AND openpc.current_action_intent_id()='ACT-PARTICIPANTS_READ_RESOURCE-V1' AND EXISTS(SELECT 1 FROM control.platform_recovery_enrollment source
 WHERE source.participant_id=platform_recovery_case.participant_id AND source.privacy_domain_id=platform_recovery_case.privacy_domain_id
  AND source.enrollment_id=platform_recovery_case.enrollment_id
  AND source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' AND source.document->>'schemaVersion'='3'
  AND source.document#>>'{source,activatedHandoff,schemaVersion}'='1'
  AND source.state='ACTIVE' AND source.row_version=platform_recovery_case.enrollment_revision
  AND source.document_digest=platform_recovery_case.enrollment_digest
  AND source.valid_from<=clock_timestamp() AND source.valid_until>clock_timestamp()
  AND platform_recovery_case.intent->>'completionSourceDigest'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(source.document#>'{source,activatedHandoff}'),'UTF8')),'hex')));
DROP POLICY IF EXISTS platform_completion_assignment_case_lock ON control.platform_recovery_case;
CREATE POLICY platform_completion_assignment_case_lock ON control.platform_recovery_case FOR UPDATE TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND current_setting('openpc.local_qa_runtime',true)='1'
  AND openpc.current_action_intent_id()='ACT-PARTICIPANTS_READ_RESOURCE-V1' AND EXISTS(SELECT 1 FROM control.platform_recovery_enrollment source
 WHERE source.participant_id=platform_recovery_case.participant_id AND source.privacy_domain_id=platform_recovery_case.privacy_domain_id
  AND source.enrollment_id=platform_recovery_case.enrollment_id
  AND source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' AND source.document->>'schemaVersion'='3'
  AND source.document#>>'{source,activatedHandoff,schemaVersion}'='1'
  AND source.state='ACTIVE' AND source.row_version=platform_recovery_case.enrollment_revision
  AND source.document_digest=platform_recovery_case.enrollment_digest
  AND source.valid_from<=clock_timestamp() AND source.valid_until>clock_timestamp()
  AND platform_recovery_case.intent->>'completionSourceDigest'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(source.document#>'{source,activatedHandoff}'),'UTF8')),'hex'))) WITH CHECK(false);
CREATE OR REPLACE FUNCTION openpc.lock_platform_recovery_completion_assignment_read(pid uuid,privacy uuid,actor uuid,envelope_id uuid,assignment_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE selected_recovery uuid; selected_until timestamptz;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(pid) OR NOT openpc.matches_privacy(privacy)
  OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_READ_RESOURCE-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ADMINISTRATION-ASSIGNMENT-READ'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.authority_envelope e JOIN control.platform_recovery_case c
   ON c.participant_id=e.participant_id AND c.recovery_id=e.recovery_case_id
   WHERE e.participant_id=pid AND e.authority_envelope_id=envelope_id AND c.intent ? 'completionSourceDigest')
 THEN RETURN NULL; END IF;
 SELECT recovery.recovery_id,recovery.valid_until INTO selected_recovery,selected_until
 FROM control.authority_envelope envelope
 JOIN control.platform_recovery_case recovery ON recovery.participant_id=envelope.participant_id
  AND recovery.recovery_id=envelope.recovery_case_id
 JOIN control.platform_recovery_enrollment enrollment ON enrollment.participant_id=recovery.participant_id
  AND enrollment.privacy_domain_id=recovery.privacy_domain_id AND enrollment.enrollment_id=recovery.enrollment_id
 JOIN control.platform_scope_replacement replacement ON replacement.participant_id=recovery.participant_id
  AND replacement.privacy_domain_id=recovery.privacy_domain_id
  AND replacement.replacement_id::text=recovery.intent#>>'{preparation,replacementId}'
  AND replacement.state='WITHDRAWING' AND replacement.candidate=recovery.intent->'preparation'
 JOIN control.platform_context root ON root.platform_context_id=replacement.platform_context_id
  AND root.owner_participant_id=pid AND root.state='ACTIVE'
  AND root.authority_epoch=replacement.predecessor_epoch AND root.row_version=replacement.expected_root_revision
 WHERE envelope.participant_id=pid AND recovery.privacy_domain_id=privacy
  AND envelope.principal_id=actor AND envelope.authority_envelope_id=envelope_id
  AND envelope.representation='RECOVERY_V1' AND recovery.state='ACTIVE'
  AND recovery.valid_from<=clock_timestamp() AND recovery.valid_until>clock_timestamp()
  AND recovery.intent->>'schema'='pc.identity.platform-recovery-intent'
  AND enrollment.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION'
  AND enrollment.document->>'schemaVersion'='3'
  AND enrollment.document#>>'{source,activatedHandoff,schemaVersion}'='1'
  AND recovery.intent->>'completionSourceDigest'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(enrollment.document#>'{source,activatedHandoff}'),'UTF8')),'hex')
  AND openpc.platform_recovery_envelope_current(envelope.authority_envelope_id)
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(recovery.intent#>'{preparation,administrators}') administrator
    WHERE administrator->>'principalId'=actor::text)
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(recovery.intent#>'{preparation,administrators}') administrator
    WHERE administrator->>'assignmentId'=assignment_id::text)
 FOR SHARE OF root,enrollment,recovery,replacement NOWAIT;
 IF NOT FOUND THEN RETURN false; END IF;
 -- Locks serialize closure and replacement commit; recheck lease freshness after acquisition.
 RETURN selected_until>clock_timestamp() AND openpc.platform_recovery_envelope_current(envelope_id);
END $$;
ALTER FUNCTION openpc.lock_platform_recovery_completion_assignment_read(uuid,uuid,uuid,uuid,uuid) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.lock_platform_recovery_completion_assignment_read(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_platform_recovery_completion_assignment_read(uuid,uuid,uuid,uuid,uuid) TO openpc_control_runtime,openpc_control_platform_runtime;
`;
