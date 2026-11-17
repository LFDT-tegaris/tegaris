/** Exact historical-source admission for an expired, wholly uneffected handoff.
 * Fresh installation custody is evidence until four new native proofs activate it. */
const sameRoot = `fresh.root_epoch=old_source.root_epoch AND fresh.root_revision=old_source.root_revision AND fresh.root_digest=old_source.root_digest`;
const nextRootBridge = `old_source.root_epoch=r.predecessor_epoch AND old_source.root_revision=r.expected_root_revision AND old_source.root_digest=r.predecessor_digest
 AND fresh.root_epoch=old_source.root_epoch+1 AND fresh.root_revision=old_source.root_revision+1
 AND openpc.platform_scope_pending_root_bridge_current(r,fresh.root_epoch,fresh.root_revision,fresh.root_digest)
 AND fresh.document#>'{source,ancestorReceipts}'=jsonb_build_array(jsonb_build_object(
   'recoveryId',old_source.document#>>'{source,recoveryId}','enrollmentId',old_source.document#>>'{source,enrollmentId}',
   'activationOperationId',old_source.document#>>'{source,activationOperationId}','receiptDigest',old_source.document#>>'{source,receiptDigest}'))
   ||coalesce(old_source.document#>'{source,ancestorReceipts}','[]'::jsonb)
 AND EXISTS(SELECT 1 FROM control.root_expiry_recovery_scope parent
   WHERE parent.platform_context_id=fresh.platform_context_id AND parent.platform_authority_epoch=fresh.root_epoch
    AND parent.admission_digest=fresh.root_digest
    AND (openpc.business_cbor(parent.scope_cbor)->>'4')::numeric>=floor(extract(epoch FROM fresh.valid_until)*1000000000))`;
export const platformRecoveryUneffectedSourceSql = `
CREATE OR REPLACE FUNCTION openpc.platform_recovery_uneffected_source_current(participant uuid,enrollment uuid,link jsonb,preparation jsonb)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.platform_recovery_enrollment fresh
  JOIN control.platform_recovery_case original ON original.participant_id=fresh.participant_id
   AND original.privacy_domain_id=fresh.privacy_domain_id
   AND original.recovery_id::text=link->>'recoveryId' AND original.enrollment_id::text=link->>'enrollmentId'
  JOIN control.platform_recovery_enrollment old_source ON old_source.participant_id=original.participant_id
   AND old_source.privacy_domain_id=original.privacy_domain_id AND old_source.enrollment_id=original.enrollment_id
   AND old_source.source_purpose='ROOT_EXPIRY_RECOVERY' AND old_source.document->>'schemaVersion'='2'
   AND old_source.document->>'schema'='pc.identity.platform-recovery-enrollment'
   AND old_source.document_digest=original.enrollment_digest AND old_source.row_version=original.enrollment_revision
  JOIN control.platform_scope_replacement r ON r.participant_id=original.participant_id
   AND r.privacy_domain_id=original.privacy_domain_id AND r.candidate=original.intent->'preparation'
  JOIN control.mutation_candidate m ON m.participant_id=r.participant_id AND m.privacy_domain_id=r.privacy_domain_id
   AND m.mutation_candidate_id=r.prepare_candidate_id AND m.candidate_document=r.candidate AND m.candidate_digest=r.candidate_digest
   AND m.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' AND m.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   AND m.resource_id=r.replacement_id AND m.expected_revision=0 AND m.state='CONSUMED' AND m.consumed_operation_id=r.prepare_operation_id
  JOIN control.approval_request a ON a.participant_id=m.participant_id AND a.privacy_domain_id=m.privacy_domain_id
   AND a.subject_type='CONFIGURATION_CANDIDATE' AND a.subject_id=m.mutation_candidate_id AND a.subject_digest=m.candidate_digest
   AND a.subject_version=m.expected_revision AND a.approval_request_id=r.prepare_approval_id AND a.state='APPROVED'
   AND a.maker_principal_id=m.maker_principal_id AND a.maker_principal_id<>a.checker_principal_id
  JOIN control.mutation_evidence evidence ON evidence.participant_id=m.participant_id AND evidence.privacy_domain_id=m.privacy_domain_id
   AND evidence.operation_id=r.prepare_operation_id AND evidence.catalog_operation_id=m.catalog_operation_id
   AND evidence.action_intent_id=m.action_intent_id AND evidence.aggregate_type='platform-scope-replacement'
   AND evidence.aggregate_id=r.replacement_id AND evidence.candidate_digest=m.candidate_digest
   AND evidence.principal_id=m.maker_principal_id AND evidence.checker_principal_id=a.checker_principal_id
   AND evidence.approval_request_id=a.approval_request_id AND evidence.evidence_digest=sha256(evidence.evidence_cbor)
   AND octet_length(evidence.cose_sign1)>0 AND evidence.mfa_challenge_id IS NOT NULL AND evidence.webauthn_assertion_binding_digest IS NOT NULL
  JOIN control.idempotency_record committed ON committed.participant_id=evidence.participant_id
   AND committed.privacy_domain_id=evidence.privacy_domain_id AND committed.operation_id=evidence.operation_id
   AND committed.terminal_state='COMMITTED' AND committed.principal_id=evidence.principal_id
   AND committed.catalog_operation_id=evidence.catalog_operation_id AND committed.action_intent_id=evidence.action_intent_id
   AND committed.idempotency_key=m.idempotency_key AND committed.input_digest=m.candidate_digest
   AND committed.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
   AND committed.result_payload->>'replacementId'=r.replacement_id::text
   AND committed.result_payload->>'successorDigest'='sha256:'||encode(r.successor_digest,'hex')
  WHERE fresh.enrollment_id=enrollment AND fresh.participant_id=participant
   AND openpc.matches_participant(participant) AND openpc.matches_privacy(fresh.privacy_domain_id)
   AND current_setting('openpc.local_qa_runtime',true) IS NOT DISTINCT FROM '1'
   AND fresh.source_purpose='ROOT_EXPIRY_RECOVERY' AND fresh.document->>'schemaVersion'='2'
   AND fresh.document->>'schema'='pc.identity.platform-recovery-enrollment' AND fresh.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
   AND fresh.state='ACTIVE' AND fresh.row_version=1 AND fresh.valid_from<=clock_timestamp() AND fresh.valid_until>clock_timestamp()
   AND old_source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' AND old_source.state='ACTIVE'
   AND fresh.platform_context_id=old_source.platform_context_id
   AND fresh.document->'administratorPrincipalIds'=old_source.document->'administratorPrincipalIds'
   AND fresh.enrollment_id<>old_source.enrollment_id
   AND NOT (old_source.document ? 'uneffectedPredecessor')
   AND ((${sameRoot}
     AND (fresh.document-ARRAY['enrollmentId','validFrom','validUntil','source','uneffectedPredecessor'])=
         (old_source.document-ARRAY['enrollmentId','validFrom','validUntil','source'])
     AND ((fresh.document->'source')-'originalAdministrators')=((old_source.document->'source')-'originalAdministrators'))
    OR (${nextRootBridge}
     AND (fresh.document-ARRAY['enrollmentId','validFrom','validUntil','source','uneffectedPredecessor','rootEpoch','rootRevision','rootDigest'])=
         (old_source.document-ARRAY['enrollmentId','validFrom','validUntil','source','rootEpoch','rootRevision','rootDigest'])
     AND (fresh.document->'source')-ARRAY['originalAdministrators','ancestorReceipts','recoveryId','enrollmentId','activationOperationId','receiptDigest']=
         (old_source.document->'source')-ARRAY['originalAdministrators','ancestorReceipts','recoveryId','enrollmentId','activationOperationId','receiptDigest']))
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(fresh.document#>'{source,originalAdministrators}') WITH ORDINALITY fresh_admin(plan,n)
    LEFT JOIN LATERAL(SELECT old_source.document#>'{source,originalAdministrators}'->(fresh_admin.n-1)::integer old_plan) retained ON true
    WHERE (plan-ARRAY['usable','grantable']) IS DISTINCT FROM (old_plan-ARRAY['usable','grantable'])
      OR ((plan->'usable')-ARRAY['validFromNs','validUntilNs']) IS DISTINCT FROM ((old_plan->'usable')-ARRAY['validFromNs','validUntilNs'])
      OR ((plan->'grantable')-ARRAY['validFromNs','validUntilNs']) IS DISTINCT FROM ((old_plan->'grantable')-ARRAY['validFromNs','validUntilNs']))
   AND openpc.platform_recovery_source_root_current(fresh)
   AND original.state='EXPIRED' AND original.valid_until<=fresh.valid_from
   AND original.activation_operation_id IS NOT NULL AND original.activation_evidence_digest=sha256(original.activation_evidence_cbor)
   AND octet_length(original.activation_cose)>0 AND jsonb_array_length(original.lease_bindings)=2
   AND original.intent_digest=sha256(convert_to(openpc.signing_canonical_json(original.intent),'UTF8'))
   AND NOT (original.intent ? 'continuation') AND NOT (original.intent ? 'supersession')
   AND NOT (r.candidate ? 'supersedes') AND (
    (r.state='WITHDRAWING' AND r.row_version=1 AND r.superseded_by IS NULL)
    OR (r.state='SUPERSEDED' AND r.row_version=2 AND EXISTS(
      SELECT 1 FROM control.platform_scope_replacement successor JOIN control.platform_recovery_case accepted
       ON accepted.participant_id=successor.participant_id AND accepted.privacy_domain_id=successor.privacy_domain_id
        AND accepted.intent->'preparation'=successor.candidate AND accepted.enrollment_id=fresh.enrollment_id
      WHERE successor.replacement_id=r.superseded_by AND successor.state='WITHDRAWING' AND successor.row_version=1
       AND successor.platform_context_id=r.platform_context_id AND successor.predecessor_epoch=fresh.root_epoch
       AND successor.expected_root_revision=fresh.root_revision AND successor.predecessor_digest=fresh.root_digest
       AND accepted.state='ACTIVE' AND accepted.intent#>>'{supersession,recoveryId}'=original.recovery_id::text)))
   AND r.commit_operation_id IS NULL AND r.platform_context_id=fresh.platform_context_id
   AND ((r.predecessor_epoch=fresh.root_epoch AND r.expected_root_revision=fresh.root_revision AND r.predecessor_digest=fresh.root_digest)
     OR (${nextRootBridge}))
   AND r.candidate=preparation AND r.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(preparation),'UTF8'))
   AND r.successor_digest=sha256(r.successor_preimage)
   AND link=fresh.document->'uneffectedPredecessor'
   AND link=jsonb_build_object('schema','pc.identity.platform-expired-uneffected-recovery','schemaVersion',1,
     'enrollmentId',original.enrollment_id::text,'recoveryId',original.recovery_id::text,'intentDigest','sha256:'||encode(original.intent_digest,'hex'),
     'activationOperationId',original.activation_operation_id::text,'activationReceiptDigest','sha256:'||encode(original.activation_evidence_digest,'hex'),
     'replacementId',r.replacement_id::text,'preparationCandidateId',r.prepare_candidate_id::text,
     'preparationDigest','sha256:'||encode(r.candidate_digest,'hex'),'preparationOperationId',r.prepare_operation_id::text,
     'preparationApprovalId',r.prepare_approval_id::text,'expectedRevision','1','successorDigest','sha256:'||encode(r.successor_digest,'hex'))
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(original.lease_bindings) b
    WHERE b->>'envelopeId'=m.maker_authority_envelope_id::text AND b->>'assignmentId'=m.maker_assignment_id::text
     AND b->>'principalId'=m.maker_principal_id::text AND b->>'principalEpoch'=m.maker_principal_epoch::text)
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=evidence.participant_id
    AND event.privacy_domain_id=evidence.privacy_domain_id AND event.aggregate_type=evidence.aggregate_type AND event.aggregate_id=evidence.aggregate_id
    AND event.payload_cbor=evidence.evidence_cbor AND event.payload_digest=evidence.evidence_digest AND event.cose_sign1=evidence.cose_sign1)
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=original.participant_id
    AND event.privacy_domain_id=original.privacy_domain_id AND event.aggregate_type='platform-recovery' AND event.aggregate_id=original.recovery_id
    AND event.event_type='openpc.identity.platform-recovery.activated.v1' AND event.aggregate_sequence=1
    AND event.payload_cbor=original.activation_evidence_cbor AND event.payload_digest=original.activation_evidence_digest
    AND event.cose_sign1=original.activation_cose)
   AND (SELECT count(*) FROM control.platform_recovery_proof p WHERE p.participant_id=original.participant_id
     AND p.privacy_domain_id=original.privacy_domain_id AND p.recovery_id=original.recovery_id
     AND p.intent_digest=original.intent_digest AND p.verified_at<=original.activated_at)=4
   AND jsonb_array_length(r.candidate->'administrators')=2
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(r.candidate->'administrators') admin
    WHERE (admin#>>'{usable,validUntilNs}')::numeric>floor(extract(epoch FROM fresh.valid_from)*1000000000)
      OR (admin#>>'{grantable,validUntilNs}')::numeric>floor(extract(epoch FROM fresh.valid_from)*1000000000)
      OR EXISTS(SELECT 1 FROM control.authority_envelope e WHERE e.participant_id=participant AND e.authority_envelope_id::text=admin->>'envelopeId')
      OR EXISTS(SELECT 1 FROM control.identity_envelope_proposal p WHERE p.participant_id=participant AND p.envelope_id::text=admin->>'envelopeId')
      OR EXISTS(SELECT 1 FROM control.assignment assigned WHERE assigned.participant_id=participant AND assigned.assignment_id::text=admin->>'assignmentId')
      OR EXISTS(SELECT 1 FROM control.mutation_candidate downstream WHERE downstream.participant_id=participant
        AND downstream.privacy_domain_id=fresh.privacy_domain_id
        AND downstream.resource_id::text IN (admin->>'envelopeId',admin->>'assignmentId')
        AND (downstream.state='CONSUMED' OR downstream.consumed_operation_id IS NOT NULL
          OR EXISTS(SELECT 1 FROM control.idempotency_record attempt WHERE attempt.participant_id=downstream.participant_id
            AND attempt.privacy_domain_id=downstream.privacy_domain_id AND attempt.catalog_operation_id=downstream.catalog_operation_id
            AND attempt.idempotency_key=downstream.idempotency_key))))
   AND ((r.candidate#>>'{successorScope,validUntilNs}')::numeric>=floor(extract(epoch FROM fresh.valid_until)*1000000000)
     OR (${nextRootBridge}))
 )
$$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_uneffected_source_current(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_uneffected_source_current(uuid,uuid,jsonb,jsonb)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;

/** The ordinary case guards own configured lifetimes. This comparison permits
 * only their new bounded intervals and five record-name substitutions. */
export const platformRecoveryUneffectedIntentSql = `
CREATE OR REPLACE FUNCTION openpc.platform_recovery_uneffected_supersession_current(participant uuid,enrollment uuid,link jsonb,proposed jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE source control.platform_recovery_enrollment; original control.platform_scope_replacement;
 expected jsonb; old_names text[]; new_names text[]; names jsonb; path text[]; scope jsonb; next_scope jsonb;
 i integer; dimension text; parent_until numeric; bridged boolean;
BEGIN
 SELECT * INTO STRICT source FROM control.platform_recovery_enrollment e
  WHERE e.participant_id=participant AND e.enrollment_id=enrollment
   AND e.document->>'schemaVersion'='2' AND e.document ? 'uneffectedPredecessor';
 SELECT * INTO STRICT original FROM control.platform_scope_replacement r
  WHERE r.participant_id=participant AND r.privacy_domain_id=source.privacy_domain_id
   AND r.replacement_id::text=source.document#>>'{uneffectedPredecessor,replacementId}';
 IF openpc.platform_recovery_uneffected_source_current(participant,enrollment,source.document->'uneffectedPredecessor',original.candidate) IS DISTINCT FROM true
  OR link IS DISTINCT FROM jsonb_build_object('recoveryId',source.document#>>'{uneffectedPredecessor,recoveryId}',
    'intentDigest',source.document#>>'{uneffectedPredecessor,intentDigest}',
    'replacementId',original.replacement_id::text,'preparationDigest','sha256:'||encode(original.candidate_digest,'hex'),
    'preparationOperationId',original.prepare_operation_id::text,'preparationApprovalId',original.prepare_approval_id::text,
    'expectedRevision','1','successorDigest','sha256:'||encode(original.successor_digest,'hex')) THEN RETURN false; END IF;
 bridged:=openpc.platform_scope_pending_root_bridge_current(original,source.root_epoch,source.root_revision,source.root_digest);
 parent_until:=(original.candidate#>>'{successorScope,validUntilNs}')::numeric;
 IF bridged THEN
  SELECT (openpc.business_cbor(parent.scope_cbor)->>'4')::numeric INTO STRICT parent_until FROM control.root_expiry_recovery_scope parent
   WHERE parent.platform_context_id=source.platform_context_id AND parent.platform_authority_epoch=source.root_epoch AND parent.admission_digest=source.root_digest;
 END IF;
 SELECT ARRAY[original.replacement_id::text]||array_agg(name ORDER BY ordinal,kind)
  INTO old_names FROM jsonb_array_elements(original.candidate->'administrators') WITH ORDINALITY a(plan,ordinal)
  CROSS JOIN LATERAL(VALUES(1,plan->>'envelopeId'),(2,plan->>'assignmentId')) n(kind,name);
 SELECT ARRAY[proposed->>'replacementId']||array_agg(name ORDER BY ordinal,kind)
  INTO new_names FROM jsonb_array_elements(proposed->'administrators') WITH ORDINALITY a(plan,ordinal)
  CROSS JOIN LATERAL(VALUES(1,plan->>'envelopeId'),(2,plan->>'assignmentId')) n(kind,name);
 IF cardinality(old_names)<>5 OR cardinality(new_names)<>5 OR old_names&&new_names
  OR (SELECT count(DISTINCT name) FROM unnest(new_names) name)<>5 THEN RETURN false; END IF;
 expected:=jsonb_set(original.candidate,'{replacementId}',to_jsonb(new_names[1]));
 IF bridged THEN
  expected:=jsonb_set(expected,'{predecessorEpoch}',to_jsonb(source.root_epoch::text));
  expected:=jsonb_set(expected,'{expectedRootRevision}',to_jsonb(source.root_revision::text));
  expected:=jsonb_set(expected,'{predecessorDigest}',to_jsonb('sha256:'||encode(source.root_digest,'hex')));
 END IF;
 expected:=jsonb_set(expected,'{supersedes}',jsonb_build_object('replacementId',original.replacement_id::text,
  'expectedRevision','1','successorDigest','sha256:'||encode(original.successor_digest,'hex')));
 FOR i IN 0..1 LOOP
  expected:=jsonb_set(expected,ARRAY['administrators',i::text,'envelopeId'],to_jsonb(new_names[i*2+2]));
  expected:=jsonb_set(expected,ARRAY['administrators',i::text,'assignmentId'],to_jsonb(new_names[i*2+3]));
 END LOOP;
 FOR i IN -1..1 LOOP
  FOREACH dimension IN ARRAY(CASE WHEN i=-1 THEN ARRAY['successorScope'] ELSE ARRAY['usable','grantable'] END) LOOP
   path:=CASE WHEN i=-1 THEN ARRAY['successorScope'] ELSE ARRAY['administrators',i::text,dimension] END;
   scope:=expected#>path; next_scope:=proposed#>path;
   IF (next_scope->>'validFromNs')::numeric<=0 OR
    (next_scope->>'validUntilNs')::numeric<=(next_scope->>'validFromNs')::numeric OR
    (next_scope->>'validUntilNs')::numeric>parent_until OR
    (i=-1 AND (next_scope->>'validFromNs')::numeric<(scope->>'validFromNs')::numeric)
    THEN RETURN false; END IF;
   SELECT coalesce(jsonb_agg(mapped ORDER BY mapped COLLATE "C"),'[]') INTO names FROM (
    SELECT CASE WHEN value=ANY(old_names) THEN new_names[array_position(old_names,value)] ELSE value END mapped
    FROM jsonb_array_elements_text(scope#>'{administration,resourceIds}') value) correspondence;
   scope:=jsonb_set(scope,'{administration,resourceIds}',names);
   scope:=jsonb_set(scope,'{validFromNs}',next_scope->'validFromNs');
   scope:=jsonb_set(scope,'{validUntilNs}',next_scope->'validUntilNs');
   expected:=jsonb_set(expected,path,scope);
  END LOOP;
 END LOOP;
 RETURN coalesce(expected=proposed,false);
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR numeric_value_out_of_range
 THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_uneffected_supersession_current(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_uneffected_supersession_current(uuid,uuid,jsonb,jsonb)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;
