/** Readiness uses the native signed-disposition receipt owner and the ordinary
 * typed-envelope/assignment owners. A UI count or old signature is no proof. */
export const platformScopeCommitGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.read_platform_scope_replacement_readiness(wanted uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE r control.platform_scope_replacement; root control.platform_context; targets jsonb; admins jsonb; bindings jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 PERFORM openpc.assert_runtime_target_disposition_owner();
 IF openpc.current_action_intent_id() NOT IN('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-CONTEXT'; END IF;
 SELECT * INTO STRICT r FROM control.platform_scope_replacement WHERE replacement_id=wanted
  AND participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id();
 SELECT * INTO STRICT root FROM control.platform_context p WHERE p.platform_context_id=r.platform_context_id
  AND p.owner_participant_id=r.participant_id AND p.state='ACTIVE';
 IF r.state<>'WITHDRAWING' OR r.row_version<>1 OR root.authority_epoch<>r.predecessor_epoch
  OR root.row_version<>r.expected_root_revision THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-PREDECESSOR'; END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('targetId',q.runtime_target_id::text,'source',q.source,
  'revision',head.revision::text,'deliveryDigest',d.delivery_digest,'acknowledgementDigest',a.acknowledgement_digest,
  'journalSequence',a.claims->>'journal_sequence','ready',coalesce(
    head.binding->>'action'='Withdraw' AND head.binding->'cause'=jsonb_build_object('kind','Dependency','owner','Platform',
      'resource_id',r.replacement_id::text,'operation_id',r.prepare_operation_id::text,'revision',1)
    AND 'sha256:'||(head.binding#>>'{source,capsule_digest}')=q.source->>'capsuleDigest'
    AND head.binding#>>'{source,original_work_id}'=q.source->>'originalWorkId'
    AND head.binding#>>'{source,original_execution_attempt_id}'=q.source->>'originalAttemptId'
    AND d.claims=head.binding||jsonb_build_object('committed_admission_digest',substring(head.admission_digest from 8))
    AND a.claims->>'installed_state'='NewUseDenied' AND a.claims->'target'=head.binding->'target'
    AND a.claims->>'delivery_digest'=substring(d.delivery_digest from 8)
    AND EXISTS(SELECT 1 FROM control.credential credential JOIN control.principal principal
      ON principal.participant_id=credential.participant_id AND principal.principal_id=credential.principal_id
      WHERE credential.participant_id=q.participant_id AND credential.credential_id=(head.binding#>>'{target,credential_id}')::uuid
        AND credential.kind='WORKLOAD_MTLS' AND credential.state='ACTIVE' AND principal.state='ACTIVE'
        AND credential.principal_id=(head.binding#>>'{target,principal_id}')::uuid
        AND credential.credential_epoch::text=head.binding#>>'{target,credential_epoch}'
        AND principal.authority_epoch::text=head.binding#>>'{target,principal_epoch}'
        AND credential.valid_from<=clock_timestamp() AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp()))
    AND (a.claims->>'disposition_revision')::bigint=head.revision
    AND d.delivery_digest='sha256:'||encode(sha256(d.signed_delivery),'hex')
    AND a.acknowledgement_digest='sha256:'||encode(sha256(a.signed_acknowledgement),'hex'),false))
    ORDER BY q.runtime_target_id),'[]') INTO targets
 FROM control.platform_scope_target_withdrawal q
 LEFT JOIN LATERAL(SELECT h.* FROM control.runtime_target_disposition_admission h WHERE h.participant_id=q.participant_id
  AND h.privacy_domain_id=q.privacy_domain_id AND h.runtime_target_id=q.runtime_target_id ORDER BY h.revision DESC LIMIT 1) head ON true
 LEFT JOIN control.runtime_target_disposition_delivery d ON d.participant_id=q.participant_id AND d.privacy_domain_id=q.privacy_domain_id
  AND d.runtime_target_id=q.runtime_target_id AND d.revision=head.revision
 LEFT JOIN control.runtime_target_disposition_acknowledgement a ON a.participant_id=q.participant_id AND a.privacy_domain_id=q.privacy_domain_id
  AND a.runtime_target_id=q.runtime_target_id AND a.delivery_digest=d.delivery_digest
 WHERE q.participant_id=r.participant_id AND q.privacy_domain_id=r.privacy_domain_id AND q.replacement_id=r.replacement_id;
 IF jsonb_array_length(targets)<>jsonb_array_length(r.candidate->'affectedTargets')
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-COHORT'; END IF;
 SELECT jsonb_agg(jsonb_build_object('principalId',plan->>'principalId','envelopeId',plan->>'envelopeId',
  'assignmentId',plan->>'assignmentId','envelopeDigest','sha256:'||encode(e.semantic_digest,'hex'),
  'signatureDigest','sha256:'||encode(sha256(e.cose_sign1),'hex'),'assignmentRevision',a.row_version::text,
  'roleRevision',role.row_version::text,'ready',coalesce(
    e.state='ACTIVE' AND e.representation='TYPED_V1' AND e.platform_context_id=r.platform_context_id
    AND e.platform_authority_epoch=r.predecessor_epoch+1 AND e.maker_checker_required AND e.step_up_required
    AND e.onward_delegation_depth=0 AND cardinality(e.runtime_capability_ids)=0
    AND e.valid_from<=clock_timestamp() AND e.valid_until>clock_timestamp() AND octet_length(e.cose_sign1)>0
    AND p.state='APPROVED' AND p.row_version=3 AND p.proposal_cbor=e.semantic_cbor
    AND create_intent.state='CONSUMED' AND create_intent.candidate_document->>'platformScopeReplacementId'=r.replacement_id::text
    AND create_intent.candidate_document->'usable'=plan->'usable' AND create_intent.candidate_document->'grantable'=plan->'grantable'
    AND openpc.platform_scope_document_value(openpc.business_cbor(p.proposal_cbor)->'8')=plan->'usable'
    AND openpc.platform_scope_document_value(openpc.business_cbor(p.proposal_cbor)->'9')=plan->'grantable'
    AND activation.state='COMMITTED' AND activation.row_version=4 AND activation.cose_sign1=e.cose_sign1
    AND principal.state='ACTIVE' AND principal.kind IN('USER','PLATFORM_OPERATOR')
    AND role.state='ACTIVE' AND role.row_version::text=plan->>'expectedRoleRevision'
    AND plan->>'roleDigest'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
      'domain','pc.identity.envelope-role-binding.v1','participantId',r.participant_id::text,
      'role',jsonb_build_object('roleId',role.role_id,'version',role.row_version::text,'actions',role.action_intent_ids,
       'origin',role.origin,'createdByPrincipalId',role.created_by_principal_id::text,'creatorParticipantId',role.creator_participant_id::text,
       'bootstrapMandateId',role.bootstrap_mandate_id::text,'bootstrapPlatformParticipantId',role.bootstrap_platform_participant_id::text))),'UTF8')),'hex')
    AND a.state='ACTIVE' AND a.principal_id=principal.principal_id AND a.authority_envelope_id=e.authority_envelope_id
    AND a.role_id=role.role_id AND a.authority_group_id IS NULL AND a.delegation_epoch=e.delegation_epoch
    AND a.valid_during=tstzrange(e.valid_from,e.valid_until,'[)') AND a.valid_during @> clock_timestamp()
    AND a.privacy_domain_ids=e.privacy_domain_ids AND a.action_intent_ids=e.action_intent_ids AND a.resource_ids=e.resource_ids
    AND a.risk_classes=e.risk_classes AND cardinality(a.runtime_capability_ids)=0
    AND a.maker_checker_required AND a.step_up_required AND a.onward_delegation_depth=0,false))
    ORDER BY plan->>'principalId') INTO admins
 FROM jsonb_array_elements(r.candidate->'administrators') plan
 LEFT JOIN control.authority_envelope e ON e.participant_id=r.participant_id AND e.authority_envelope_id=(plan->>'envelopeId')::uuid
 LEFT JOIN control.identity_envelope_proposal p ON p.participant_id=r.participant_id AND p.privacy_domain_id=r.privacy_domain_id AND p.envelope_id=e.authority_envelope_id
 LEFT JOIN control.mutation_candidate create_intent ON create_intent.participant_id=r.participant_id AND create_intent.mutation_candidate_id=p.create_candidate_id
 LEFT JOIN control.identity_envelope_activation activation ON activation.participant_id=r.participant_id AND activation.privacy_domain_id=r.privacy_domain_id
  AND activation.envelope_id=e.authority_envelope_id AND activation.operation_id=e.last_mutation_operation_id
 LEFT JOIN control.assignment a ON a.participant_id=r.participant_id AND a.assignment_id=(plan->>'assignmentId')::uuid
 LEFT JOIN control.authority_role role ON role.participant_id=r.participant_id AND role.authority_role_id=(plan->>'roleId')::uuid
 LEFT JOIN control.principal principal ON principal.participant_id=r.participant_id AND principal.principal_id=(plan->>'principalId')::uuid;
 bindings:=jsonb_build_object('replacementId',r.replacement_id::text,'platformContextId',r.platform_context_id::text,
  'rootRevision',root.row_version::text,'predecessorEpoch',r.predecessor_epoch::text,'predecessorDigest','sha256:'||encode(r.predecessor_digest,'hex'),
  'successorDigest','sha256:'||encode(r.successor_digest,'hex'),'replacementRevision',r.row_version::text,'state',r.state,
  'targets',targets,'administrators',admins,'sourceExpiresAtNs',openpc.business_cbor(r.successor_scope_cbor)->>'4');
 RETURN bindings||jsonb_build_object('readinessDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
  jsonb_build_object('domain','pc.identity.platform-scope-readiness.v1','source',bindings)),'UTF8')),'hex'),
  'unacknowledgedTargets',(SELECT count(*) FROM jsonb_array_elements(targets) t WHERE t->>'ready' IS DISTINCT FROM 'true'),
  'unpreparedAdministrators',(SELECT count(*) FROM jsonb_array_elements(admins) a WHERE a->>'ready' IS DISTINCT FROM 'true'),
  'nowNs',(floor(extract(epoch from clock_timestamp())*1000000)*1000)::text);
END $$;
REVOKE ALL ON FUNCTION openpc.read_platform_scope_replacement_readiness(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.commit_platform_scope_replacement(document jsonb,candidate_id uuid,approval_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE r control.platform_scope_replacement; initial control.platform_envelope_scope; current_root control.platform_context; readiness jsonb; queued record;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-CONTEXT'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('platform-scope-replacement:'||(document->>'platformContextId'),0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT r FROM control.platform_scope_replacement WHERE replacement_id=(document->>'replacementId')::uuid
  AND participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() FOR UPDATE;
 SELECT * INTO STRICT current_root FROM control.platform_context p WHERE p.platform_context_id=r.platform_context_id
  AND p.owner_participant_id=r.participant_id AND p.state='ACTIVE' FOR UPDATE;
 FOR queued IN SELECT q.runtime_target_id FROM control.platform_scope_target_withdrawal q WHERE q.replacement_id=r.replacement_id
  AND q.participant_id=r.participant_id AND q.privacy_domain_id=r.privacy_domain_id ORDER BY q.runtime_target_id LOOP
  IF NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||r.participant_id::text||':'||r.privacy_domain_id::text||':'||queued.runtime_target_id::text,0))
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 readiness:=openpc.read_platform_scope_replacement_readiness(r.replacement_id);
 IF coalesce((document->>'platformContextId'<>readiness->>'platformContextId'
   OR document->>'expectedRootRevision'<>readiness->>'rootRevision'
   OR document->>'expectedReplacementRevision'<>readiness->>'replacementRevision'
   OR document->>'predecessorEpoch'<>readiness->>'predecessorEpoch'
   OR document->>'predecessorDigest'<>readiness->>'predecessorDigest'
   OR document->>'successorDigest'<>readiness->>'successorDigest' OR document->>'readinessDigest'<>readiness->>'readinessDigest'
   OR readiness->>'unacknowledgedTargets'<>'0' OR readiness->>'unpreparedAdministrators'<>'0'
   OR (readiness->>'sourceExpiresAtNs')::numeric<=(readiness->>'nowNs')::numeric),true)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-READINESS'; END IF;
 SELECT * INTO STRICT initial FROM control.platform_envelope_scope s WHERE s.platform_context_id=r.platform_context_id;
 UPDATE control.platform_scope_replacement SET state='COMMITTED',row_version=2,commit_operation_id=openpc.current_operation_id(),
  commit_candidate_id=candidate_id,commit_approval_id=approval_id,readiness_digest=decode(substring(document->>'readinessDigest' from 8),'hex'),
  committed_at=clock_timestamp() WHERE replacement_id=r.replacement_id;
 INSERT INTO control.platform_envelope_scope_successor(platform_context_id,platform_authority_epoch,owner_participant_id,installation_privacy_domain_id,
  replacement_id,preparation_operation_id,predecessor_epoch,predecessor_digest,environment_id,installation_digest,scope_cbor,admission_preimage,admission_digest)
 VALUES(r.platform_context_id,r.predecessor_epoch+1,r.participant_id,r.privacy_domain_id,r.replacement_id,r.prepare_operation_id,
  r.predecessor_epoch,r.predecessor_digest,initial.environment_id,initial.installation_digest,r.successor_scope_cbor,r.successor_preimage,r.successor_digest);
 UPDATE control.platform_context SET authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp()
  WHERE platform_context_id=r.platform_context_id AND authority_epoch=r.predecessor_epoch AND row_version=r.expected_root_revision;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-PREDECESSOR'; END IF;
 RETURN jsonb_build_object('replacementId',r.replacement_id::text,'successorDigest','sha256:'||encode(r.successor_digest,'hex'),
  'state','COMMITTED','revision','2','operationId',openpc.current_operation_id()::text,'platformAuthorityEpoch',(r.predecessor_epoch+1)::text);
END $$;
REVOKE ALL ON FUNCTION openpc.commit_platform_scope_replacement(jsonb,uuid,uuid) FROM PUBLIC;

DROP POLICY IF EXISTS platform_scope_replacement_root_commit ON control.platform_context;
CREATE POLICY platform_scope_replacement_root_commit ON control.platform_context FOR UPDATE TO openpc_control_owner
 USING(openpc.matches_participant(owner_participant_id) AND openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')
 WITH CHECK(openpc.matches_participant(owner_participant_id) AND openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  AND state='ACTIVE' AND EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.platform_context_id=platform_context.platform_context_id
    AND r.participant_id=platform_context.owner_participant_id AND r.state='COMMITTED'
    AND r.commit_operation_id=openpc.current_operation_id() AND r.predecessor_epoch+1=platform_context.authority_epoch
    AND r.expected_root_revision+1=platform_context.row_version));
`;

export const platformScopeCommitGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.read_platform_scope_replacement_readiness(uuid) TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader;
GRANT EXECUTE ON FUNCTION openpc.commit_platform_scope_replacement(jsonb,uuid,uuid) TO openpc_control_runtime,openpc_control_platform_runtime;
`;
