/** Exact v2 history admission. Legacy pending-expiry admission remains separate. */
export const platformRecoveryActivatedHandoffSourceSql = `
CREATE OR REPLACE FUNCTION openpc.platform_recovery_activated_expiry_source_current(participant uuid,enrollment uuid,link jsonb,preparation jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
#variable_conflict use_column
DECLARE fresh control.platform_recovery_enrollment; original control.platform_recovery_case; old_source control.platform_recovery_enrollment; r control.platform_scope_replacement; m control.mutation_candidate; a control.approval_request; evidence control.mutation_evidence; committed control.idempotency_record; p control.identity_envelope_proposal; e control.authority_envelope; created control.mutation_candidate; issuing control.authority_envelope; historical_case control.platform_recovery_case; creation_approval control.approval_request; creation_evidence control.mutation_evidence; creation_receipt control.idempotency_record; activation control.mutation_candidate; activation_approval control.approval_request;
 plan jsonb; administrator_ordinal bigint; witness record; approved_proposal_matched boolean;
BEGIN
FOR fresh IN SELECT fresh.* FROM control.platform_recovery_enrollment fresh WHERE fresh.enrollment_id=enrollment AND fresh.participant_id=participant LOOP
 FOR original IN SELECT original.* FROM control.platform_recovery_case original WHERE original.participant_id=fresh.participant_id
   AND original.privacy_domain_id=fresh.privacy_domain_id
   AND original.recovery_id=CASE WHEN (link->>'recoveryId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (link->>'recoveryId')::uuid ELSE NULL::uuid END AND original.enrollment_id=CASE WHEN (link->>'enrollmentId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (link->>'enrollmentId')::uuid ELSE NULL::uuid END LOOP
  FOR old_source IN SELECT old_source.* FROM control.platform_recovery_enrollment old_source WHERE old_source.participant_id=original.participant_id
   AND old_source.privacy_domain_id=original.privacy_domain_id AND old_source.enrollment_id=original.enrollment_id
   AND old_source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' AND old_source.document->>'schemaVersion'='4'
   AND old_source.document#>>'{source,pendingExpiry,schemaVersion}'='1'
   AND old_source.document#>>'{source,closedApproval,schema}'='pc.identity.closed-platform-approval-source'
   AND old_source.document#>>'{source,closedApproval,schemaVersion}'='1'
   AND 'sha256:'||encode(old_source.document_digest,'hex')=fresh.document#>>'{source,pendingExpiry,predecessorEnrollmentDigest}'
   AND old_source.document_digest=sha256(convert_to(openpc.signing_canonical_json(old_source.document),'UTF8'))
   AND 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(old_source.document#>'{source,closedApproval}'),'UTF8')),'hex')=fresh.document#>>'{source,pendingExpiry,predecessorClosedApprovalDigest}'
   AND original.intent->>'closedApprovalSourceDigest'=fresh.document#>>'{source,pendingExpiry,predecessorClosedApprovalDigest}'
   AND original.intent->'approvalContinuation'=old_source.document#>'{source,closedApproval,approval}'
   AND old_source.document->>'schema'='pc.identity.platform-recovery-enrollment'
   AND old_source.document_digest=original.enrollment_digest AND old_source.row_version=original.enrollment_revision LOOP
   FOR r IN SELECT r.* FROM control.platform_scope_replacement r WHERE r.participant_id=original.participant_id
   AND r.privacy_domain_id=original.privacy_domain_id AND r.candidate=original.intent->'preparation' LOOP
    FOR m IN SELECT m.* FROM control.mutation_candidate m WHERE m.participant_id=r.participant_id AND m.privacy_domain_id=r.privacy_domain_id
   AND m.mutation_candidate_id=r.prepare_candidate_id AND m.candidate_document=r.candidate AND m.candidate_digest=r.candidate_digest
   AND m.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' AND m.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   AND m.resource_id=r.replacement_id AND m.expected_revision=0 AND m.state='CONSUMED' AND m.consumed_operation_id=r.prepare_operation_id
   AND m.predecessor_candidate_id::text=old_source.document#>>'{source,closedApproval,approval,candidateId}' LOOP
     FOR a IN SELECT a.* FROM control.approval_request a WHERE a.participant_id=m.participant_id AND a.privacy_domain_id=m.privacy_domain_id
   AND a.subject_type='CONFIGURATION_CANDIDATE' AND a.subject_id=m.mutation_candidate_id AND a.subject_digest=m.candidate_digest
   AND a.subject_version=m.expected_revision AND a.approval_request_id=r.prepare_approval_id AND a.state='APPROVED'
   AND a.maker_principal_id=m.maker_principal_id AND a.maker_principal_id<>a.checker_principal_id LOOP
      FOR evidence IN SELECT evidence.* FROM control.mutation_evidence evidence WHERE evidence.participant_id=m.participant_id AND evidence.privacy_domain_id=m.privacy_domain_id
   AND evidence.operation_id=r.prepare_operation_id AND evidence.catalog_operation_id=m.catalog_operation_id
   AND evidence.action_intent_id=m.action_intent_id AND evidence.aggregate_type='platform-scope-replacement'
   AND evidence.aggregate_id=r.replacement_id AND evidence.candidate_digest=m.candidate_digest
   AND evidence.principal_id=m.maker_principal_id AND evidence.checker_principal_id=a.checker_principal_id
   AND evidence.approval_request_id=a.approval_request_id AND evidence.evidence_digest=sha256(evidence.evidence_cbor)
   AND octet_length(evidence.cose_sign1)>0 AND evidence.mfa_challenge_id IS NOT NULL AND evidence.webauthn_assertion_binding_digest IS NOT NULL LOOP
       <<matched_receipt>>
       FOR committed IN SELECT committed.* FROM control.idempotency_record committed WHERE committed.participant_id=evidence.participant_id
   AND committed.privacy_domain_id=evidence.privacy_domain_id AND committed.operation_id=evidence.operation_id
   AND committed.terminal_state='COMMITTED' AND committed.principal_id=evidence.principal_id
   AND committed.catalog_operation_id=evidence.catalog_operation_id AND committed.action_intent_id=evidence.action_intent_id
   AND committed.idempotency_key=m.idempotency_key AND committed.input_digest=m.candidate_digest
   AND committed.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
   AND committed.result_payload->>'replacementId'=r.replacement_id::text
   AND committed.result_payload->>'successorDigest'='sha256:'||encode(r.successor_digest,'hex') LOOP
        IF (fresh.enrollment_id=enrollment) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.participant_id=participant) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (openpc.matches_participant(participant)) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (openpc.matches_privacy(fresh.privacy_domain_id)) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (current_setting('openpc.local_qa_runtime',true) IS NOT DISTINCT FROM '1') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.document->>'schemaVersion'='4'
          AND fresh.document#>>'{source,pendingExpiry,schemaVersion}'='2'
          AND NOT (fresh.document#>'{source}' ? 'closedApproval')) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.document->>'schema'='pc.identity.platform-recovery-enrollment') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.state='ACTIVE') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.row_version=1) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.valid_from<=clock_timestamp()) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.valid_until>clock_timestamp()) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (old_source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (old_source.state='ACTIVE') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.platform_context_id=old_source.platform_context_id) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (((fresh.root_epoch=old_source.root_epoch AND fresh.root_revision=old_source.root_revision AND fresh.root_digest=old_source.root_digest)
    OR (old_source.root_epoch=r.predecessor_epoch AND old_source.root_revision=r.expected_root_revision AND old_source.root_digest=r.predecessor_digest
      AND openpc.platform_scope_pending_root_bridge_current(r,fresh.root_epoch,fresh.root_revision,fresh.root_digest)))) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.document->'administratorPrincipalIds'=old_source.document->'administratorPrincipalIds') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.document->'recoveryPrincipal'=old_source.document->'recoveryPrincipal') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (fresh.document->'custodians'=old_source.document->'custodians') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (openpc.platform_recovery_source_root_current(fresh)) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (openpc.platform_recovery_original_administrators_current(fresh)) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (original.state='EXPIRED') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (original.valid_until<=fresh.valid_from) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (original.activation_operation_id IS NOT NULL) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (original.activation_evidence_digest=sha256(original.activation_evidence_cbor)) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (octet_length(original.activation_cose)>0) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (jsonb_array_length(original.lease_bindings)=2) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (original.intent_digest=sha256(convert_to(openpc.signing_canonical_json(original.intent),'UTF8'))) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (NOT (original.intent ? 'continuation')) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (NOT (original.intent ? 'supersession')) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (r.candidate->'supersedes'=jsonb_build_object('replacementId',old_source.document#>>'{source,pendingExpiry,preparation,replacementId}',
          'expectedRevision','1','successorDigest',old_source.document#>>'{source,pendingExpiry,preparation,successorDigest}')) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF ((
     (r.state='WITHDRAWING' AND r.row_version=1 AND r.superseded_by IS NULL)
     OR (r.state='SUPERSEDED' AND r.row_version=2 AND r.superseded_by IS NOT NULL
       AND EXISTS(SELECT 1 FROM control.platform_scope_replacement successor WHERE successor.replacement_id=r.superseded_by
         AND successor.participant_id=r.participant_id AND successor.privacy_domain_id=r.privacy_domain_id
         AND successor.platform_context_id=r.platform_context_id
         AND ((successor.predecessor_epoch=r.predecessor_epoch AND successor.expected_root_revision=r.expected_root_revision AND successor.predecessor_digest=r.predecessor_digest)
          OR openpc.platform_scope_pending_root_bridge_current(r,successor.predecessor_epoch,successor.expected_root_revision,successor.predecessor_digest))
         AND successor.state='WITHDRAWING' AND successor.row_version=1
         AND successor.candidate->'supersedes'=jsonb_build_object('replacementId',r.replacement_id::text,'expectedRevision','1',
           'successorDigest','sha256:'||encode(r.successor_digest,'hex')))))) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (r.commit_operation_id IS NULL) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (r.platform_context_id=fresh.platform_context_id) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (((r.predecessor_epoch=fresh.root_epoch AND r.expected_root_revision=fresh.root_revision AND r.predecessor_digest=fresh.root_digest)
    OR openpc.platform_scope_pending_root_bridge_current(r,fresh.root_epoch,fresh.root_revision,fresh.root_digest))) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (r.candidate=preparation) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (r.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(preparation),'UTF8'))) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (r.successor_digest=sha256(r.successor_preimage)) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (link=fresh.document#>'{source,pendingExpiry,preparation}') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (link=jsonb_build_object('schema','pc.identity.platform-pending-recovery-continuation','schemaVersion',1,
     'enrollmentId',original.enrollment_id::text,'recoveryId',original.recovery_id::text,'intentDigest','sha256:'||encode(original.intent_digest,'hex'),
     'activationOperationId',original.activation_operation_id::text,'activationReceiptDigest','sha256:'||encode(original.activation_evidence_digest,'hex'),
     'replacementId',r.replacement_id::text,'preparationCandidateId',r.prepare_candidate_id::text,
     'preparationDigest','sha256:'||encode(r.candidate_digest,'hex'),'preparationOperationId',r.prepare_operation_id::text,
     'preparationApprovalId',r.prepare_approval_id::text,'expectedRevision','1','successorDigest','sha256:'||encode(r.successor_digest,'hex'))) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (EXISTS(SELECT 1 FROM jsonb_array_elements(original.lease_bindings) b
    WHERE b->>'envelopeId'=m.maker_authority_envelope_id::text AND b->>'assignmentId'=m.maker_assignment_id::text
     AND b->>'principalId'=m.maker_principal_id::text AND b->>'principalEpoch'=m.maker_principal_epoch::text)) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=evidence.participant_id
    AND event.privacy_domain_id=evidence.privacy_domain_id AND event.aggregate_type=evidence.aggregate_type AND event.aggregate_id=evidence.aggregate_id
    AND event.payload_cbor=evidence.evidence_cbor AND event.payload_digest=evidence.evidence_digest AND event.cose_sign1=evidence.cose_sign1)) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=original.participant_id
    AND event.privacy_domain_id=original.privacy_domain_id AND event.aggregate_type='platform-recovery' AND event.aggregate_id=original.recovery_id
    AND event.event_type='openpc.identity.platform-recovery.activated.v1' AND event.aggregate_sequence=1
    AND event.payload_cbor=original.activation_evidence_cbor AND event.payload_digest=original.activation_evidence_digest
    AND event.cose_sign1=original.activation_cose)) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF ((SELECT count(*) FROM control.platform_recovery_proof p WHERE p.participant_id=original.participant_id
     AND p.privacy_domain_id=original.privacy_domain_id AND p.recovery_id=original.recovery_id
     AND p.intent_digest=original.intent_digest AND p.verified_at<=original.activated_at)=4) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (jsonb_array_length(r.candidate->'administrators')=2) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (jsonb_array_length(fresh.document#>'{source,pendingExpiry,administrators}')=2) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        FOR plan,administrator_ordinal IN SELECT value,ordinality FROM jsonb_array_elements(r.candidate->'administrators') WITH ORDINALITY LOOP
         SELECT fresh.document#>'{source,pendingExpiry,administrators}'->(administrator_ordinal-1)::integer AS declared INTO witness;
         IF ((plan#>>'{usable,validUntilNs}')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000000)) THEN CONTINUE matched_receipt; END IF;
         IF ((plan#>>'{grantable,validUntilNs}')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000000)) THEN CONTINUE matched_receipt; END IF;
         IF (witness.declared->>'principalId' IS DISTINCT FROM plan->>'principalId') THEN CONTINUE matched_receipt; END IF;
         IF (witness.declared->>'envelopeId' IS DISTINCT FROM plan->>'envelopeId') THEN CONTINUE matched_receipt; END IF;
         IF (witness.declared->>'assignmentId' IS DISTINCT FROM plan->>'assignmentId') THEN CONTINUE matched_receipt; END IF;
         IF (EXISTS(SELECT 1 FROM control.assignment assigned WHERE assigned.participant_id=participant
        AND (assigned.assignment_id::text=plan->>'assignmentId' OR assigned.authority_envelope_id::text=plan->>'envelopeId'))) THEN CONTINUE matched_receipt; END IF;
         CASE witness.declared#>>'{effect,state}'
         WHEN 'ABSENT' THEN
         IF (EXISTS(SELECT 1 FROM control.identity_envelope_activation activated WHERE activated.participant_id=participant
        AND activated.envelope_id=CASE WHEN (plan->>'envelopeId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'envelopeId')::uuid ELSE NULL::uuid END)) THEN CONTINUE matched_receipt; END IF;
         IF (EXISTS(SELECT 1 FROM control.mutation_candidate prior_activation
        JOIN control.idempotency_record attempted ON attempted.participant_id=prior_activation.participant_id
          AND attempted.privacy_domain_id=prior_activation.privacy_domain_id
          AND attempted.catalog_operation_id=prior_activation.catalog_operation_id
          AND attempted.idempotency_key=prior_activation.idempotency_key
        WHERE prior_activation.participant_id=participant AND prior_activation.privacy_domain_id=fresh.privacy_domain_id
          AND prior_activation.resource_id=CASE WHEN (plan->>'envelopeId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'envelopeId')::uuid ELSE NULL::uuid END
          AND prior_activation.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE')) THEN CONTINUE matched_receipt; END IF;

          IF (EXISTS(SELECT 1 FROM control.authority_envelope e WHERE e.participant_id=participant
          AND e.authority_envelope_id=CASE WHEN (plan->>'envelopeId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'envelopeId')::uuid ELSE NULL::uuid END)) THEN CONTINUE matched_receipt; END IF;
          IF (EXISTS(SELECT 1 FROM control.identity_envelope_proposal p WHERE p.participant_id=participant
          AND p.envelope_id=CASE WHEN (plan->>'envelopeId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'envelopeId')::uuid ELSE NULL::uuid END)) THEN CONTINUE matched_receipt; END IF;
          IF (EXISTS(SELECT 1 FROM control.mutation_candidate pending WHERE pending.participant_id=participant
          AND pending.privacy_domain_id=fresh.privacy_domain_id AND pending.resource_id=CASE WHEN (plan->>'envelopeId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'envelopeId')::uuid ELSE NULL::uuid END)) THEN CONTINUE matched_receipt; END IF;
         WHEN 'ACTIVE_UNASSIGNED' THEN
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
                    IF (e.valid_until<=clock_timestamp()) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
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
          IF NOT approved_proposal_matched THEN CONTINUE matched_receipt; END IF;
         ELSE CONTINUE matched_receipt;
         END CASE;
        END LOOP;
        IF ((SELECT count(*) FROM jsonb_array_elements(fresh.document#>'{source,pendingExpiry,administrators}') declared
      WHERE declared#>>'{effect,state}'='ACTIVE_UNASSIGNED')=1) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (((r.candidate#>>'{successorScope,validUntilNs}')::numeric>=floor(extract(epoch FROM fresh.valid_until)*1000000000)
     OR openpc.platform_scope_pending_root_bridge_current(r,fresh.root_epoch,fresh.root_revision,fresh.root_digest))) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        IF (EXISTS(SELECT 1 FROM control.root_expiry_recovery_scope parent
      WHERE parent.platform_context_id=fresh.platform_context_id AND parent.platform_authority_epoch=fresh.root_epoch
       AND parent.admission_digest=fresh.root_digest
       AND (openpc.business_cbor(parent.scope_cbor)->>'4')::numeric>=floor(extract(epoch FROM fresh.valid_until)*1000000000))) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
        RETURN true;
       END LOOP;
      END LOOP;
     END LOOP;
    END LOOP;
   END LOOP;
  END LOOP;
 END LOOP;
END LOOP;
RETURN false;
END;
$$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_activated_expiry_source_current(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_activated_expiry_source_current(uuid,uuid,jsonb,jsonb)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;
