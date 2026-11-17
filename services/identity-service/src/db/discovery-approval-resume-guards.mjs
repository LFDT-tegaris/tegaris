/** Approved native resume is independently governed. Existing preapproval
 * continuation and its immutable migrations keep full source equality. */
export const discoveryApprovalResumeSourceSql = `
CREATE OR REPLACE FUNCTION openpc.discovery_approval_resume_source_compatible(old_source jsonb,new_source jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE expected jsonb:=old_source; actions jsonb; i integer; scope text; old_actions jsonb;
BEGIN
 IF jsonb_typeof(old_source) IS DISTINCT FROM 'object' OR jsonb_typeof(new_source) IS DISTINCT FROM 'object'
  OR jsonb_typeof(old_source->'originalAdministrators') IS DISTINCT FROM 'array'
  OR jsonb_typeof(new_source->'originalAdministrators') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF jsonb_array_length(old_source->'originalAdministrators')<>2
  OR jsonb_array_length(new_source->'originalAdministrators')<>2 THEN RETURN false; END IF;
 actions:=jsonb_build_array('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1','ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1','ACT-OPERATIONS_READ_OPERATION-V1','ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1');
 old_actions:=old_source#>'{originalAdministrators,0,usable,administration,actionIntentIds}';
 IF old_actions IS DISTINCT FROM jsonb_build_array('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1','ACT-OPERATIONS_READ_OPERATION-V1','ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1') AND old_actions IS DISTINCT FROM actions THEN RETURN false; END IF;
 FOR i IN 0..1 LOOP
  FOREACH scope IN ARRAY ARRAY['usable','grantable'] LOOP
   IF old_source#>ARRAY['originalAdministrators',i::text,scope,'administration','actionIntentIds'] IS DISTINCT FROM old_actions
    OR new_source#>ARRAY['originalAdministrators',i::text,scope,'administration','actionIntentIds'] IS DISTINCT FROM actions
   THEN RETURN false; END IF;
   expected:=jsonb_set(expected,ARRAY['originalAdministrators',i::text,scope,'administration','actionIntentIds'],actions,false);
  END LOOP;
 END LOOP;
 RETURN expected=new_source;
END $$;
REVOKE ALL ON FUNCTION openpc.discovery_approval_resume_source_compatible(jsonb,jsonb) FROM PUBLIC;

-- Enrolled descendants may recover an unconsumed original intent. Raw source
-- equality is unchanged; only the installed, completed Root receipt chain can
-- establish the additional provenance. This predicate grants no authority.
CREATE OR REPLACE FUNCTION openpc.discovery_approval_resume_enrollments_compatible(p_old uuid,p_new uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE old_e control.platform_recovery_enrollment; new_e control.platform_recovery_enrollment;
 old_source jsonb; new_source jsonb; old_refs jsonb; new_refs jsonb; suffix jsonb; reference jsonb;
 delta integer; i integer; receipt record; previous_document jsonb; runtime_scope jsonb;
BEGIN
 SELECT * INTO old_e FROM control.platform_recovery_enrollment WHERE enrollment_id=p_old;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO new_e FROM control.platform_recovery_enrollment WHERE enrollment_id=p_new;
 IF NOT FOUND THEN RETURN false; END IF;
 IF current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR NOT openpc.matches_participant(new_e.participant_id) OR NOT openpc.matches_privacy(new_e.privacy_domain_id)
  OR row(new_e.participant_id,new_e.privacy_domain_id,new_e.platform_context_id,new_e.source_purpose)
    IS DISTINCT FROM row(old_e.participant_id,old_e.privacy_domain_id,old_e.platform_context_id,old_e.source_purpose)
  OR old_e.source_purpose IS DISTINCT FROM 'ROOT_EXPIRY_RECOVERY'
  OR old_e.document->>'schema' IS DISTINCT FROM 'pc.identity.discovery-certificate-recovery-enrollment'
  OR new_e.document->>'schema' IS DISTINCT FROM old_e.document->>'schema'
  OR old_e.document->>'schemaVersion' IS DISTINCT FROM '2' OR new_e.document->>'schemaVersion' IS DISTINCT FROM '2'
  OR old_e.document->>'assurance' IS DISTINCT FROM 'LOCAL_QA_VIRTUAL_AUTHENTICATOR'
  OR new_e.document->>'assurance' IS DISTINCT FROM old_e.document->>'assurance'
  OR new_e.document->'certificateRecovery' IS DISTINCT FROM old_e.document->'certificateRecovery'
  OR new_e.document->'administratorPrincipalIds' IS DISTINCT FROM old_e.document->'administratorPrincipalIds'
  OR new_e.document_digest IS DISTINCT FROM sha256(convert_to(openpc.signing_canonical_json(new_e.document),'UTF8'))
  OR old_e.document_digest IS DISTINCT FROM sha256(convert_to(openpc.signing_canonical_json(old_e.document),'UTF8'))
  OR new_e.state IS DISTINCT FROM 'ACTIVE' OR new_e.row_version<>1
  OR new_e.valid_from>clock_timestamp() OR new_e.valid_until<=clock_timestamp()
  OR openpc.platform_recovery_source_root_current(new_e) IS DISTINCT FROM true
 THEN RETURN false; END IF;
 old_source:=old_e.document->'source'; new_source:=new_e.document->'source';
 IF row(new_e.root_epoch,new_e.root_revision,new_e.root_digest)=row(old_e.root_epoch,old_e.root_revision,old_e.root_digest)
 THEN RETURN openpc.discovery_approval_resume_source_compatible(old_source,new_source); END IF;
 IF new_e.root_epoch<=old_e.root_epoch OR new_e.root_epoch-old_e.root_epoch>31
  OR new_e.root_revision-old_e.root_revision IS DISTINCT FROM new_e.root_epoch-old_e.root_epoch
  OR jsonb_typeof(old_source) IS DISTINCT FROM 'object' OR jsonb_typeof(new_source) IS DISTINCT FROM 'object'
  OR old_source->>'kind' IS DISTINCT FROM 'ROOT_EXPIRY_RECOVERY' OR new_source->>'kind' IS DISTINCT FROM old_source->>'kind'
  OR (new_source-ARRAY['recoveryId','enrollmentId','activationOperationId','receiptDigest','ancestorReceipts','originalAdministrators'])
    IS DISTINCT FROM (old_source-ARRAY['recoveryId','enrollmentId','activationOperationId','receiptDigest','ancestorReceipts','originalAdministrators'])
  OR openpc.discovery_approval_resume_source_compatible(old_source,
    old_source||jsonb_build_object('originalAdministrators',new_source->'originalAdministrators')) IS DISTINCT FROM true
 THEN RETURN false; END IF;
 delta:=(new_e.root_epoch-old_e.root_epoch)::integer;
 old_refs:=jsonb_build_array(old_source-ARRAY['kind','originalAdministrators','ancestorReceipts'])||coalesce(old_source->'ancestorReceipts','[]'::jsonb);
 new_refs:=jsonb_build_array(new_source-ARRAY['kind','originalAdministrators','ancestorReceipts'])||coalesce(new_source->'ancestorReceipts','[]'::jsonb);
 IF jsonb_typeof(old_refs) IS DISTINCT FROM 'array' OR jsonb_typeof(new_refs) IS DISTINCT FROM 'array'
  OR jsonb_array_length(new_refs)>32 OR jsonb_array_length(new_refs)<>jsonb_array_length(old_refs)+delta
 THEN RETURN false; END IF;
 SELECT jsonb_agg(value ORDER BY ordinality) INTO suffix FROM jsonb_array_elements(new_refs) WITH ORDINALITY WHERE ordinality>delta;
 IF suffix IS DISTINCT FROM old_refs THEN RETURN false; END IF;
 FOR i IN 0..jsonb_array_length(new_refs)-1 LOOP
  reference:=new_refs->i;
  SELECT recovery.result,recovery.intent,original.document,scope.admission_digest INTO receipt
   FROM control.root_expiry_recovery_case recovery
   JOIN control.root_expiry_recovery_enrollment original ON original.enrollment_id=recovery.enrollment_id
    AND original.participant_id=recovery.participant_id AND original.privacy_domain_id=recovery.privacy_domain_id
    AND original.row_version=recovery.enrollment_revision AND original.document_digest=recovery.enrollment_digest
   JOIN control.root_expiry_recovery_scope scope ON scope.recovery_id=recovery.recovery_id
    AND scope.platform_context_id=new_e.platform_context_id AND scope.owner_participant_id=recovery.participant_id
    AND scope.installation_privacy_domain_id=recovery.privacy_domain_id AND scope.activation_operation_id=recovery.operation_id
    AND scope.platform_authority_epoch=new_e.root_epoch-i
   WHERE recovery.recovery_id::text=reference->>'recoveryId' AND recovery.enrollment_id::text=reference->>'enrollmentId'
    AND recovery.operation_id::text=reference->>'activationOperationId'
    AND 'sha256:'||encode(recovery.evidence_digest,'hex')=reference->>'receiptDigest'
    AND recovery.participant_id=new_e.participant_id AND recovery.privacy_domain_id=new_e.privacy_domain_id
    AND recovery.state='COMPLETED' AND recovery.evidence_digest=sha256(recovery.evidence_cbor)
    AND recovery.intent_digest=sha256(convert_to(openpc.signing_canonical_json(recovery.intent),'UTF8'))
    AND original.document_digest=sha256(convert_to(openpc.signing_canonical_json(original.document),'UTF8'));
  IF NOT FOUND THEN RETURN false; END IF;
  IF receipt.result->>'rootEpoch' IS DISTINCT FROM (new_e.root_epoch-i)::text
   OR receipt.result->>'rootRevision' IS DISTINCT FROM (new_e.root_revision-i)::text
   OR receipt.result->>'rootDigest' IS DISTINCT FROM 'sha256:'||encode(receipt.admission_digest,'hex')
   OR receipt.document->>'rootEpoch' IS DISTINCT FROM (new_e.root_epoch-i-1)::text
   OR receipt.document->>'rootRevision' IS DISTINCT FROM (new_e.root_revision-i-1)::text
   OR receipt.document->>'platformContextId' IS DISTINCT FROM new_e.platform_context_id::text
   OR receipt.document->'administratorPrincipalIds' IS DISTINCT FROM new_e.document->'administratorPrincipalIds'
  THEN RETURN false; END IF;
  IF i=0 THEN
   IF receipt.admission_digest IS DISTINCT FROM new_e.root_digest THEN RETURN false; END IF;
   runtime_scope:=receipt.intent#>'{successorScope,runtime}';
  ELSE
   IF previous_document->>'rootDigest' IS DISTINCT FROM receipt.result->>'rootDigest'
    OR previous_document->>'installationDigest' IS DISTINCT FROM receipt.document->>'installationDigest'
    OR previous_document->>'installationEnvironmentId' IS DISTINCT FROM receipt.document->>'installationEnvironmentId'
    OR receipt.intent#>'{successorScope,runtime}' IS DISTINCT FROM runtime_scope
   THEN RETURN false; END IF;
  END IF;
  IF i=delta AND receipt.admission_digest IS DISTINCT FROM old_e.root_digest THEN RETURN false; END IF;
  previous_document:=receipt.document;
 END LOOP;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION openpc.discovery_approval_resume_enrollments_compatible(uuid,uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.discovery_certificate_resume_administrators_current(p_enrollment uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT coalesce(EXISTS(SELECT 1 FROM control.platform_recovery_enrollment e
 WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
  AND e.source_purpose='ROOT_EXPIRY_RECOVERY' AND e.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
  AND e.document->>'schemaVersion'='2' AND e.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
  AND current_setting('openpc.local_qa_runtime',true)='1'
  AND jsonb_array_length(e.document#>'{source,originalAdministrators}')=2
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(e.document#>'{source,originalAdministrators}') a
   WHERE a#>'{usable,administration,actionIntentIds}' IS DISTINCT FROM jsonb_build_array('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1','ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1','ACT-OPERATIONS_READ_OPERATION-V1','ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1')
    OR a#>'{grantable,administration,actionIntentIds}' IS DISTINCT FROM jsonb_build_array('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1','ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1','ACT-OPERATIONS_READ_OPERATION-V1','ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'))
  AND openpc.platform_recovery_source_root_current(e) AND openpc.platform_recovery_original_administrators_current(e)),false)
$$;
REVOKE ALL ON FUNCTION openpc.discovery_certificate_resume_administrators_current(uuid) FROM PUBLIC;

/** Read-only exact historical subject relation; neither existence nor the
 * source delta grants authority. The supported installation and current lease
 * owners still qualify all original Role/envelope/assignment rights. */
CREATE OR REPLACE FUNCTION openpc.discovery_approval_resume_subject_visible(p_participant uuid,p_privacy uuid,p_principal uuid,p_envelope uuid,p_approval uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT coalesce(EXISTS(SELECT 1 FROM control.approval_request approval
  JOIN control.mutation_candidate c ON c.participant_id=approval.participant_id AND c.privacy_domain_id=approval.privacy_domain_id
   AND c.mutation_candidate_id=approval.subject_id AND c.candidate_digest=approval.subject_digest
   AND c.expected_revision=approval.subject_version AND c.action_intent_id=approval.action_intent_id
   AND c.maker_principal_id=approval.maker_principal_id
  JOIN control.authority_envelope old_e ON old_e.participant_id=c.participant_id AND old_e.authority_envelope_id=c.maker_authority_envelope_id
   AND old_e.principal_id=c.maker_principal_id AND old_e.representation='RECOVERY_V1'
  JOIN control.platform_recovery_case old_case ON old_case.participant_id=c.participant_id AND old_case.privacy_domain_id=c.privacy_domain_id
   AND old_case.recovery_id=old_e.recovery_case_id AND old_case.state='EXPIRED' AND old_case.valid_until<=clock_timestamp()
   AND old_case.completion_operation_id IS NULL AND old_case.completion_result IS NULL
  JOIN control.platform_recovery_enrollment old_source ON old_source.enrollment_id=old_case.enrollment_id
   AND old_source.participant_id=c.participant_id AND old_source.privacy_domain_id=c.privacy_domain_id
   AND old_source.row_version=old_case.enrollment_revision AND old_source.document_digest=old_case.enrollment_digest
  JOIN control.authority_envelope e ON e.participant_id=c.participant_id AND e.authority_envelope_id=p_envelope
   AND e.principal_id=c.maker_principal_id AND e.representation='RECOVERY_V1'
  JOIN control.platform_recovery_case fresh ON fresh.participant_id=c.participant_id AND fresh.privacy_domain_id=c.privacy_domain_id
   AND fresh.recovery_id=e.recovery_case_id AND fresh.recovery_id<>old_case.recovery_id AND fresh.state='ACTIVE'
   AND fresh.valid_from<=clock_timestamp() AND fresh.valid_until>clock_timestamp()
   AND fresh.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent' AND fresh.intent->>'schemaVersion'='2'
   AND fresh.intent->'certificateRecovery'=old_case.intent->'certificateRecovery'
   AND ((fresh.intent#>'{administrators,0}')-'principalEpoch')=((old_case.intent#>'{administrators,0}')-'principalEpoch')
   AND ((fresh.intent#>'{administrators,1}')-'principalEpoch')=((old_case.intent#>'{administrators,1}')-'principalEpoch')
  JOIN control.platform_recovery_enrollment source ON source.enrollment_id=fresh.enrollment_id
   AND source.participant_id=c.participant_id AND source.privacy_domain_id=c.privacy_domain_id
   AND source.row_version=fresh.enrollment_revision AND source.document_digest=fresh.enrollment_digest
  WHERE c.participant_id=p_participant AND c.privacy_domain_id=p_privacy AND c.maker_principal_id=p_principal
   AND openpc.matches_participant(c.participant_id) AND openpc.matches_privacy(c.privacy_domain_id)
   AND current_setting('openpc.local_qa_runtime',true)='1'
   AND approval.approval_request_id=p_approval AND approval.subject_type='CONFIGURATION_CANDIDATE'
   AND approval.state IN ('OPEN','APPROVED','EXPIRED') AND approval.checker_principal_id<>c.maker_principal_id
   AND approval.checker_principal_id::text=fresh.intent#>>'{administrators,1,principalId}'
   AND c.state IN ('APPROVAL_REQUESTED','APPROVED') AND c.consumed_operation_id IS NULL
   AND (c.catalog_operation_id,c.action_intent_id,c.resource_type,c.operation_class)=
     ('ID-OP-WORKLOAD-ROTATE','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','participant','UPDATE')
   AND old_case.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
   AND c.resource_id::text=fresh.intent#>>'{certificateRecovery,predecessorCredentialId}'
   AND c.expected_revision::text=fresh.intent#>>'{certificateRecovery,predecessorRevision}'
   AND c.candidate_document=jsonb_build_object('replacedCredentialId',c.resource_id::text,
     'credentialId',fresh.intent#>>'{certificateRecovery,successorCredentialId}',
     'publicKeySpkiDer',fresh.intent#>>'{certificateRecovery,successorPublicKeySpkiDer}')
   AND c.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(c.candidate_document),'UTF8'))
   AND source.source_purpose='ROOT_EXPIRY_RECOVERY' AND source.document->>'schemaVersion'='2'
   AND old_source.source_purpose=source.source_purpose AND source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
   AND old_source.document->>'assurance'=source.document->>'assurance'
   AND source.document->'certificateRecovery'=old_source.document->'certificateRecovery'
   AND source.document->'administratorPrincipalIds'=old_source.document->'administratorPrincipalIds'
   AND openpc.discovery_approval_resume_enrollments_compatible(old_source.enrollment_id,source.enrollment_id)
   AND old_source.document_digest=sha256(convert_to(openpc.signing_canonical_json(old_source.document),'UTF8'))
   AND source.document_digest=sha256(convert_to(openpc.signing_canonical_json(source.document),'UTF8'))
   AND openpc.platform_recovery_envelope_current(e.authority_envelope_id)),false)
$$;
REVOKE ALL ON FUNCTION openpc.discovery_approval_resume_subject_visible(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.discovery_approval_resume_eligible(p_participant uuid,p_privacy uuid,p_principal uuid,p_envelope uuid,p_approval uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT openpc.discovery_approval_resume_subject_visible(p_participant,p_privacy,p_principal,p_envelope,p_approval)
 AND NOT EXISTS(SELECT 1 FROM control.approval_request a JOIN control.mutation_candidate child
  ON child.participant_id=a.participant_id AND child.privacy_domain_id=a.privacy_domain_id AND child.predecessor_candidate_id=a.subject_id
  WHERE a.participant_id=p_participant AND a.privacy_domain_id=p_privacy AND a.approval_request_id=p_approval)
$$;
REVOKE ALL ON FUNCTION openpc.discovery_approval_resume_eligible(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
`;
export const discoveryApprovalResumeGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.discovery_approval_resume_source_compatible(jsonb,jsonb),
 openpc.discovery_approval_resume_enrollments_compatible(uuid,uuid),
 openpc.discovery_approval_resume_subject_visible(uuid,uuid,uuid,uuid,uuid),
 openpc.discovery_approval_resume_eligible(uuid,uuid,uuid,uuid,uuid),
 openpc.discovery_certificate_resume_administrators_current(uuid)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;

export const discoveryApprovalResumeGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_discovery_approval_resume(n control.mutation_candidate)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE old_attempt control.mutation_candidate; previous control.platform_recovery_case;
 fresh control.platform_recovery_case; old_enrollment control.platform_recovery_enrollment;
 new_enrollment control.platform_recovery_enrollment; old_envelope control.authority_envelope; new_envelope control.authority_envelope;
 lineage_ids uuid[]; original_floor timestamptz; proof_count integer; proofs jsonb[]; proof_deadline timestamptz;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF jsonb_typeof(n.resume_request) IS DISTINCT FROM 'object'
  OR jsonb_typeof(n.resume_request->'discoveryReceivingProof') IS DISTINCT FROM 'object'
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF n.resume_request->'discoveryReceivingProof' IS DISTINCT FROM jsonb_build_object(
    'mfaChallengeId',n.resume_request#>'{discoveryReceivingProof,mfaChallengeId}',
    'verificationOperationId',n.resume_request#>'{discoveryReceivingProof,verificationOperationId}',
    'evidenceDigest',n.resume_request#>'{discoveryReceivingProof,evidenceDigest}')
  OR jsonb_typeof(n.resume_request#>'{discoveryReceivingProof,mfaChallengeId}') IS DISTINCT FROM 'string'
  OR jsonb_typeof(n.resume_request#>'{discoveryReceivingProof,verificationOperationId}') IS DISTINCT FROM 'string'
  OR jsonb_typeof(n.resume_request#>'{discoveryReceivingProof,evidenceDigest}') IS DISTINCT FROM 'string'
  OR (n.resume_request#>>'{discoveryReceivingProof,mfaChallengeId}') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR (n.resume_request#>>'{discoveryReceivingProof,verificationOperationId}') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR (n.resume_request#>>'{discoveryReceivingProof,evidenceDigest}') !~ '^sha256:[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 SELECT * INTO STRICT old_attempt FROM control.mutation_candidate
  WHERE mutation_candidate_id=n.predecessor_candidate_id FOR UPDATE;
 SELECT * INTO STRICT old_envelope FROM control.authority_envelope
  WHERE participant_id=old_attempt.participant_id AND authority_envelope_id=old_attempt.maker_authority_envelope_id;
 SELECT * INTO STRICT previous FROM control.platform_recovery_case
  WHERE participant_id=old_attempt.participant_id AND privacy_domain_id=old_attempt.privacy_domain_id
   AND recovery_id=old_envelope.recovery_case_id;
 SELECT c.* INTO STRICT fresh FROM control.platform_recovery_case c JOIN control.authority_envelope e
  ON e.participant_id=c.participant_id AND e.recovery_case_id=c.recovery_id
  WHERE e.participant_id=n.participant_id AND c.privacy_domain_id=n.privacy_domain_id
   AND e.authority_envelope_id=n.maker_authority_envelope_id AND e.principal_id=n.maker_principal_id
   AND e.representation='RECOVERY_V1' AND e.authority_epoch=n.maker_authority_epoch
   AND e.delegation_epoch=n.maker_delegation_epoch AND openpc.platform_recovery_envelope_current(e.authority_envelope_id);
 SELECT * INTO STRICT new_envelope FROM control.authority_envelope WHERE participant_id=n.participant_id AND authority_envelope_id=n.maker_authority_envelope_id;
 SELECT * INTO STRICT old_enrollment FROM control.platform_recovery_enrollment WHERE enrollment_id=previous.enrollment_id;
 SELECT * INTO STRICT new_enrollment FROM control.platform_recovery_enrollment WHERE enrollment_id=fresh.enrollment_id;
 WITH RECURSIVE lineage AS (
  SELECT c.*,ARRAY[c.mutation_candidate_id] path FROM control.mutation_candidate c WHERE c.mutation_candidate_id=old_attempt.mutation_candidate_id
  UNION ALL SELECT parent.*,child.path||parent.mutation_candidate_id FROM lineage child
   JOIN control.mutation_candidate parent ON parent.mutation_candidate_id=child.predecessor_candidate_id
   WHERE NOT parent.mutation_candidate_id=any(child.path)
 ) SELECT array_agg(mutation_candidate_id),min(created_at) INTO lineage_ids,original_floor FROM lineage;
 IF lineage_ids IS NULL OR NOT EXISTS(SELECT 1 FROM control.mutation_candidate c WHERE c.mutation_candidate_id=any(lineage_ids)
    AND c.predecessor_candidate_id IS NULL AND c.attempt=1)
  OR EXISTS(SELECT 1 FROM control.mutation_candidate c WHERE c.mutation_candidate_id=any(lineage_ids)
    AND (row(c.participant_id,c.privacy_domain_id,c.action_intent_id,c.catalog_operation_id,c.resource_id,
      c.candidate_digest,c.candidate_document,c.expected_revision,c.idempotency_key,c.maker_principal_id)
      IS DISTINCT FROM row(n.participant_id,n.privacy_domain_id,n.action_intent_id,n.catalog_operation_id,n.resource_id,
        n.candidate_digest,n.candidate_document,n.expected_revision,n.idempotency_key,n.maker_principal_id)
      OR c.resource_type<>n.resource_type OR c.operation_class<>n.operation_class
      OR c.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') OR c.consumed_operation_id IS NOT NULL
      OR (c.predecessor_candidate_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM control.mutation_candidate parent
        WHERE parent.mutation_candidate_id=c.predecessor_candidate_id AND parent.mutation_candidate_id=any(lineage_ids) AND parent.attempt=c.attempt-1))
      OR (c.predecessor_candidate_id IS NULL AND c.attempt<>1)))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 SELECT count(*),array_agg(jsonb_build_object('mfaChallengeId',m.mfa_challenge_id::text,
   'verificationOperationId',verification.operation_id::text,'evidenceDigest','sha256:'||encode(verification.evidence_digest,'hex'))),
   min(least(m.expires_at,
     case when proof_session.step_up_mfa_challenge_id is null then m.consumed_at+interval '5 minutes'
       else coalesce(openpc.session_step_up_valid_until(m.participant_id,m.session_id,m.principal_id),'-infinity'::timestamptz) end,
     coalesce(credential.valid_until,'infinity'::timestamptz)))
  INTO proof_count,proofs,proof_deadline FROM control.mfa_challenge m
 JOIN control.session proof_session ON proof_session.participant_id=m.participant_id
  AND proof_session.session_id=m.session_id AND proof_session.principal_id=m.principal_id
 JOIN control.credential credential ON credential.participant_id=m.participant_id AND credential.credential_id=m.signer_credential_id
  AND credential.principal_id=m.principal_id AND credential.kind='WEBAUTHN' AND credential.state='ACTIVE'
  AND credential.credential_epoch=m.signer_credential_epoch AND credential.valid_from<=clock_timestamp()
  AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
  AND sha256(credential.public_key_spki_der)=credential.public_key_digest
 JOIN control.mutation_evidence verification ON verification.participant_id=m.participant_id
  AND verification.mfa_challenge_id=m.mfa_challenge_id AND verification.privacy_domain_id=n.privacy_domain_id
  AND verification.principal_id=n.maker_principal_id AND verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
  AND verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
  AND verification.aggregate_type='webauthn-verification' AND verification.aggregate_id=n.maker_session_id
  AND verification.signer_credential_id=m.signer_credential_id AND verification.webauthn_assertion_binding_digest IS NOT NULL
  AND verification.evidence_digest=sha256(verification.evidence_cbor) AND verification.occurred_at>=greatest(fresh.activated_at,new_envelope.valid_from)
  AND verification.occurred_at>=m.consumed_at AND verification.occurred_at<=clock_timestamp()
  AND verification.bound_participant_epoch=n.maker_participant_epoch AND verification.bound_principal_epoch=n.maker_principal_epoch
  AND verification.bound_authority_envelope_id=n.maker_authority_envelope_id AND verification.bound_envelope_epoch=n.maker_authority_epoch
  AND verification.bound_assignment_id=n.maker_assignment_id
 JOIN control.idempotency_record committed ON committed.participant_id=verification.participant_id
  AND committed.privacy_domain_id=verification.privacy_domain_id AND committed.operation_id=verification.operation_id
  AND committed.principal_id=verification.principal_id AND committed.action_intent_id=verification.action_intent_id
  AND committed.catalog_operation_id=verification.catalog_operation_id
  AND committed.input_digest=verification.candidate_digest AND committed.terminal_state='COMMITTED'
  AND committed.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
 JOIN control.outbox_event event ON event.participant_id=verification.participant_id AND event.privacy_domain_id=verification.privacy_domain_id
  AND event.aggregate_type=verification.aggregate_type AND event.aggregate_id=verification.aggregate_id
  AND event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
  AND event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
  AND event.payload_cbor=verification.evidence_cbor AND event.payload_digest=verification.evidence_digest AND event.cose_sign1=verification.cose_sign1
 WHERE m.participant_id=n.participant_id AND m.principal_id=n.maker_principal_id AND m.session_id=n.maker_session_id
  AND m.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' AND m.resource_digest=sha256(convert_to(openpc.signing_canonical_json(n.resume_request-'discoveryReceivingProof'),'UTF8')) AND m.resource_id=n.predecessor_approval_id::text
  AND m.created_at>=greatest(fresh.activated_at,new_envelope.valid_from) AND m.consumed_at>=greatest(fresh.activated_at,new_envelope.valid_from)
  AND (CASE WHEN proof_session.step_up_mfa_challenge_id IS NULL
    THEN m.consumed_at>clock_timestamp()-interval '5 minutes'
    ELSE proof_session.step_up_mfa_challenge_id=m.mfa_challenge_id
      AND openpc.session_step_up_valid_until(m.participant_id,m.session_id,m.principal_id)>clock_timestamp() END)
  AND m.consumed_at<=clock_timestamp()
  AND m.expires_at>clock_timestamp() AND ((m.used_at IS NULL AND m.used_operation_id IS NULL) OR (m.used_at IS NOT NULL AND m.used_operation_id=n.resume_operation_id));
 IF proof_count<>1 OR n.resume_request->'discoveryReceivingProof' IS DISTINCT FROM proofs[1] THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF current_setting('transaction_isolation')<>'serializable'
  OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR old_enrollment.document->>'assurance' IS DISTINCT FROM 'LOCAL_QA_VIRTUAL_AUTHENTICATOR'
  OR old_enrollment.document_digest<>previous.enrollment_digest OR old_enrollment.row_version<>previous.enrollment_revision
  OR new_enrollment.document_digest<>fresh.enrollment_digest OR new_enrollment.row_version<>fresh.enrollment_revision
  OR new_enrollment.document->>'assurance' IS DISTINCT FROM 'LOCAL_QA_VIRTUAL_AUTHENTICATOR'
  OR old_attempt.catalog_operation_id<>'ID-OP-WORKLOAD-ROTATE'
  OR old_attempt.action_intent_id<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR old_attempt.resource_type<>'participant' OR old_attempt.operation_class<>'UPDATE'
  OR old_attempt.state NOT IN ('APPROVAL_REQUESTED','APPROVED') OR old_attempt.consumed_operation_id IS NOT NULL
  OR n.state NOT IN ('PROPOSED','APPROVAL_REQUESTED') OR n.consumed_operation_id IS NOT NULL
  OR n.predecessor_approval_id IS NULL OR n.resume_operation_id IS NULL
  OR fresh.intent->>'schemaVersion' IS DISTINCT FROM '2'
  OR n.attempt<>old_attempt.attempt+1 OR n.expires_at<=clock_timestamp()
  OR n.expires_at>least(clock_timestamp()+interval '30 minutes',fresh.valid_until,new_envelope.valid_until,
    (SELECT least(s.idle_expires_at,s.absolute_expires_at) FROM control.session s WHERE s.participant_id=n.participant_id AND s.session_id=n.maker_session_id),
    (SELECT upper(a.valid_during) FROM control.assignment a WHERE a.participant_id=n.participant_id AND a.assignment_id=n.maker_assignment_id))
  OR row(n.participant_id,n.privacy_domain_id,n.action_intent_id,n.catalog_operation_id,n.resource_type,
    n.operation_class,n.resource_id,n.candidate_digest,n.candidate_document,n.expected_revision,n.idempotency_key,n.maker_principal_id)
   IS DISTINCT FROM row(old_attempt.participant_id,old_attempt.privacy_domain_id,old_attempt.action_intent_id,
    old_attempt.catalog_operation_id,old_attempt.resource_type,old_attempt.operation_class,old_attempt.resource_id,
    old_attempt.candidate_digest,old_attempt.candidate_document,old_attempt.expected_revision,old_attempt.idempotency_key,old_attempt.maker_principal_id)
  OR old_envelope.representation<>'RECOVERY_V1' OR old_envelope.principal_id<>n.maker_principal_id
  OR old_enrollment.source_purpose<>'ROOT_EXPIRY_RECOVERY' OR new_enrollment.source_purpose<>'ROOT_EXPIRY_RECOVERY'
  OR old_enrollment.document->>'schemaVersion'<>'2' OR new_enrollment.document->>'schemaVersion'<>'2'
  OR previous.state<>'EXPIRED' OR previous.valid_until>clock_timestamp() OR previous.completion_operation_id IS NOT NULL OR previous.completion_result IS NOT NULL
  OR fresh.state<>'ACTIVE' OR fresh.recovery_id=previous.recovery_id OR fresh.valid_until<=clock_timestamp()
  OR previous.intent->>'schema' IS DISTINCT FROM 'pc.identity.discovery-certificate-recovery-intent'
  OR fresh.intent->>'schema' IS DISTINCT FROM previous.intent->>'schema'
  OR fresh.intent->'certificateRecovery' IS DISTINCT FROM previous.intent->'certificateRecovery'
  OR ((fresh.intent#>'{administrators,0}')-'principalEpoch') IS DISTINCT FROM ((previous.intent#>'{administrators,0}')-'principalEpoch')
  OR ((fresh.intent#>'{administrators,1}')-'principalEpoch') IS DISTINCT FROM ((previous.intent#>'{administrators,1}')-'principalEpoch')
  OR fresh.intent#>>'{administrators,0,principalId}' IS DISTINCT FROM n.maker_principal_id::text
  OR openpc.discovery_approval_resume_enrollments_compatible(old_enrollment.enrollment_id,new_enrollment.enrollment_id) IS DISTINCT FROM true
  OR n.resume_request IS DISTINCT FROM (SELECT jsonb_build_object('command','RESUME',
    'actionIntentId','ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1','actionIntentDigest','sha256:'||encode(action.semantic_digest,'hex'),
    'approvalRequestId','urn:openpc:resource:'||prior.approval_request_id::text,'expectedRevision',prior.row_version::text,
    'predecessorCandidateId',old_attempt.mutation_candidate_id::text,'expectedAttempt',old_attempt.attempt::text,
    'candidateDigest','sha256:'||encode(old_attempt.candidate_digest,'hex'),
    'reason','Resume the retained Discovery certificate rotation with fresh custody and independent approval.',
    'discoveryReceivingProof',proofs[1]) FROM control.approval_request prior JOIN control.action_intent action
      ON action.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
    WHERE prior.participant_id=n.participant_id AND prior.privacy_domain_id=n.privacy_domain_id
     AND prior.approval_request_id=n.predecessor_approval_id AND prior.subject_type='CONFIGURATION_CANDIDATE'
     AND prior.subject_id=old_attempt.mutation_candidate_id AND prior.subject_digest=n.candidate_digest
     AND prior.subject_version=n.expected_revision AND prior.action_intent_id=n.action_intent_id
     AND prior.maker_principal_id=n.maker_principal_id AND prior.checker_principal_id<>n.maker_principal_id
     AND prior.checker_principal_id::text=fresh.intent#>>'{administrators,1,principalId}'
     AND prior.state IN ('OPEN','APPROVED','EXPIRED'))
  OR n.candidate_document IS DISTINCT FROM jsonb_build_object('replacedCredentialId',fresh.intent#>>'{certificateRecovery,predecessorCredentialId}',
    'credentialId',fresh.intent#>>'{certificateRecovery,successorCredentialId}',
    'publicKeySpkiDer',fresh.intent#>>'{certificateRecovery,successorPublicKeySpkiDer}')
  OR n.expected_revision::text IS DISTINCT FROM fresh.intent#>>'{certificateRecovery,predecessorRevision}'
  OR n.resource_id::text IS DISTINCT FROM fresh.intent#>>'{certificateRecovery,predecessorCredentialId}'
  OR n.candidate_digest IS DISTINCT FROM sha256(convert_to(openpc.signing_canonical_json(n.candidate_document),'UTF8'))
  OR EXISTS(SELECT 1 FROM control.mutation_candidate child WHERE child.predecessor_candidate_id=old_attempt.mutation_candidate_id
    AND child.mutation_candidate_id<>n.mutation_candidate_id)
  OR NOT EXISTS(SELECT 1 FROM control.participant p JOIN control.principal principal ON principal.participant_id=p.participant_id
    JOIN control.session s ON s.participant_id=p.participant_id AND s.principal_id=principal.principal_id
    JOIN control.assignment a ON a.participant_id=p.participant_id AND a.principal_id=principal.principal_id
    WHERE p.participant_id=n.participant_id AND p.state='ACTIVE' AND p.authority_epoch=n.maker_participant_epoch
     AND principal.principal_id=n.maker_principal_id AND principal.state='ACTIVE' AND principal.kind='PLATFORM_OPERATOR'
     AND principal.authority_epoch=n.maker_principal_epoch AND s.session_id=n.maker_session_id AND s.state='ACTIVE'
     AND s.session_epoch=n.maker_session_epoch AND s.participant_epoch=n.maker_participant_epoch
     AND s.authority_epoch=n.maker_principal_epoch AND s.delegation_epoch=n.maker_delegation_epoch
     AND s.context_mode='PLATFORM' AND s.privacy_domain_id IS NULL
     AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
     AND a.assignment_id=n.maker_assignment_id AND a.row_version=n.maker_assignment_row_version
     AND a.authority_envelope_id=n.maker_authority_envelope_id AND a.state='ACTIVE' AND a.valid_during @> clock_timestamp()
     AND a.delegation_epoch=n.maker_delegation_epoch AND a.maker_checker_required
     AND n.action_intent_id=any(a.action_intent_ids) AND n.privacy_domain_id::text=any(a.privacy_domain_ids)
     AND (n.resource_id::text=any(a.resource_ids) OR '*'=any(a.resource_ids)))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 PERFORM * FROM openpc.lock_discovery_certificate_recovery_source(fresh.enrollment_id,fresh.recovery_id);
 -- No state/time/currentness filter may hide a prior provider claim or effect.
 IF EXISTS(SELECT 1 FROM control.mfa_challenge m WHERE m.participant_id=n.participant_id
    AND m.principal_id=n.maker_principal_id AND m.action_intent_id=n.action_intent_id AND m.resource_digest=n.candidate_digest
    AND (m.used_at IS NOT NULL OR m.used_operation_id IS NOT NULL)
    AND NOT EXISTS(SELECT 1 FROM control.idempotency_record history WHERE history.participant_id=m.participant_id
      AND history.operation_id=m.used_operation_id AND history.terminal_state='COMMITTED'
      AND history.action_intent_id IN ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'))
    AND m.session_id IN(SELECT c.maker_session_id FROM control.mutation_candidate c WHERE c.mutation_candidate_id=any(lineage_ids)))
  OR EXISTS(SELECT 1 FROM control.discovery_certificate_issuance i WHERE i.participant_id=n.participant_id
    AND (i.predecessor_credential_id=n.resource_id OR i.successor_credential_id::text=n.candidate_document->>'credentialId'))
  OR EXISTS(SELECT 1 FROM control.discovery_certificate_issuer_attempt a WHERE a.participant_id=n.participant_id
    AND a.privacy_domain_id=n.privacy_domain_id AND a.idempotency_key=n.idempotency_key)
  OR EXISTS(SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=n.participant_id AND r.privacy_domain_id=n.privacy_domain_id
    AND (r.idempotency_key=n.idempotency_key
     OR (r.input_digest=n.candidate_digest AND r.catalog_operation_id='ID-OP-WORKLOAD-ROTATE')))
  OR EXISTS(SELECT 1 FROM control.mutation_evidence e WHERE e.participant_id=n.participant_id AND e.privacy_domain_id=n.privacy_domain_id
    AND (e.candidate_digest=n.candidate_digest OR e.aggregate_id::text=n.candidate_document->>'credentialId'))
  OR EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=n.participant_id AND a.privacy_domain_id=n.privacy_domain_id
    AND (a.candidate_digest=n.candidate_digest OR a.aggregate_id::text=n.candidate_document->>'credentialId'))
  OR EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=n.participant_id AND e.privacy_domain_id=n.privacy_domain_id
    AND (e.aggregate_id::text=n.candidate_document->>'credentialId'
      OR (e.aggregate_id=n.resource_id AND e.created_at>=original_floor)))
  OR EXISTS(SELECT 1 FROM control.receipt_signing_attempt a JOIN control.business_transition_profile profile USING(profile_digest)
    WHERE a.participant_id=n.participant_id AND a.privacy_domain_id=n.privacy_domain_id
     AND profile.catalog_operation_id=n.catalog_operation_id AND a.reserved_at_ns>=extract(epoch from original_floor)*1000000000
     AND NOT EXISTS(SELECT 1 FROM control.idempotency_record committed WHERE committed.participant_id=a.participant_id
       AND committed.privacy_domain_id=a.privacy_domain_id AND committed.operation_id=a.operation_id AND committed.terminal_state='COMMITTED'))
  OR EXISTS(SELECT 1 FROM control.mutation_candidate c WHERE c.participant_id=n.participant_id AND c.privacy_domain_id=n.privacy_domain_id
    AND c.candidate_digest=n.candidate_digest AND (c.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') OR c.consumed_operation_id IS NOT NULL OR (c.mutation_candidate_id<>n.mutation_candidate_id AND NOT c.mutation_candidate_id=any(lineage_ids))))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 -- Reselect the SAME strict native proof after every local absence scan. The
 -- final invoker trigger repeats this after the private cross-privacy scan and
 -- again at deferred success; crypto never becomes a writable verified flag.
 SELECT count(*),array_agg(jsonb_build_object('mfaChallengeId',m.mfa_challenge_id::text,
   'verificationOperationId',verification.operation_id::text,'evidenceDigest','sha256:'||encode(verification.evidence_digest,'hex'))),
   min(least(m.expires_at,
     case when proof_session.step_up_mfa_challenge_id is null then m.consumed_at+interval '5 minutes'
       else coalesce(openpc.session_step_up_valid_until(m.participant_id,m.session_id,m.principal_id),'-infinity'::timestamptz) end,
     coalesce(credential.valid_until,'infinity'::timestamptz)))
  INTO proof_count,proofs,proof_deadline FROM control.mfa_challenge m
 JOIN control.session proof_session ON proof_session.participant_id=m.participant_id
  AND proof_session.session_id=m.session_id AND proof_session.principal_id=m.principal_id
 JOIN control.credential credential ON credential.participant_id=m.participant_id AND credential.credential_id=m.signer_credential_id
  AND credential.principal_id=m.principal_id AND credential.kind='WEBAUTHN' AND credential.state='ACTIVE'
  AND credential.credential_epoch=m.signer_credential_epoch AND credential.valid_from<=clock_timestamp()
  AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
  AND sha256(credential.public_key_spki_der)=credential.public_key_digest
 JOIN control.mutation_evidence verification ON verification.participant_id=m.participant_id
  AND verification.mfa_challenge_id=m.mfa_challenge_id AND verification.privacy_domain_id=n.privacy_domain_id
  AND verification.principal_id=n.maker_principal_id AND verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
  AND verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
  AND verification.aggregate_type='webauthn-verification' AND verification.aggregate_id=n.maker_session_id
  AND verification.signer_credential_id=m.signer_credential_id AND verification.webauthn_assertion_binding_digest IS NOT NULL
  AND verification.evidence_digest=sha256(verification.evidence_cbor) AND verification.occurred_at>=greatest(fresh.activated_at,new_envelope.valid_from)
  AND verification.occurred_at>=m.consumed_at AND verification.occurred_at<=clock_timestamp()
  AND verification.bound_participant_epoch=n.maker_participant_epoch AND verification.bound_principal_epoch=n.maker_principal_epoch
  AND verification.bound_authority_envelope_id=n.maker_authority_envelope_id AND verification.bound_envelope_epoch=n.maker_authority_epoch
  AND verification.bound_assignment_id=n.maker_assignment_id
 JOIN control.idempotency_record committed ON committed.participant_id=verification.participant_id
  AND committed.privacy_domain_id=verification.privacy_domain_id AND committed.operation_id=verification.operation_id
  AND committed.principal_id=verification.principal_id AND committed.action_intent_id=verification.action_intent_id
  AND committed.catalog_operation_id=verification.catalog_operation_id
  AND committed.input_digest=verification.candidate_digest AND committed.terminal_state='COMMITTED'
  AND committed.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
 JOIN control.outbox_event event ON event.participant_id=verification.participant_id AND event.privacy_domain_id=verification.privacy_domain_id
  AND event.aggregate_type=verification.aggregate_type AND event.aggregate_id=verification.aggregate_id
  AND event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
  AND event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
  AND event.payload_cbor=verification.evidence_cbor AND event.payload_digest=verification.evidence_digest AND event.cose_sign1=verification.cose_sign1
 WHERE m.participant_id=n.participant_id AND m.principal_id=n.maker_principal_id AND m.session_id=n.maker_session_id
  AND m.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' AND m.resource_digest=sha256(convert_to(openpc.signing_canonical_json(n.resume_request-'discoveryReceivingProof'),'UTF8')) AND m.resource_id=n.predecessor_approval_id::text
  AND m.created_at>=greatest(fresh.activated_at,new_envelope.valid_from) AND m.consumed_at>=greatest(fresh.activated_at,new_envelope.valid_from)
  AND (CASE WHEN proof_session.step_up_mfa_challenge_id IS NULL
    THEN m.consumed_at>clock_timestamp()-interval '5 minutes'
    ELSE proof_session.step_up_mfa_challenge_id=m.mfa_challenge_id
      AND openpc.session_step_up_valid_until(m.participant_id,m.session_id,m.principal_id)>clock_timestamp() END)
  AND m.consumed_at<=clock_timestamp()
  AND m.expires_at>clock_timestamp() AND ((m.used_at IS NULL AND m.used_operation_id IS NULL) OR (m.used_at IS NOT NULL AND m.used_operation_id=n.resume_operation_id));
 IF proof_count<>1 OR n.resume_request->'discoveryReceivingProof' IS DISTINCT FROM proofs[1] THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 -- Run again at the actual end boundary, including after the private claim scan.
 PERFORM * FROM openpc.lock_discovery_certificate_recovery_source(fresh.enrollment_id,fresh.recovery_id);
 IF NOT openpc.platform_recovery_envelope_current(n.maker_authority_envelope_id)
  OR NOT EXISTS(SELECT 1 FROM control.idempotency_record resume WHERE resume.participant_id=n.participant_id
    AND resume.privacy_domain_id=n.privacy_domain_id AND resume.operation_id=n.resume_operation_id
    AND resume.principal_id=n.maker_principal_id AND resume.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
    AND resume.catalog_operation_id='LEGACY' AND resume.input_digest=sha256(convert_to(openpc.signing_canonical_json(n.resume_request-'discoveryReceivingProof'),'UTF8'))
    AND ((resume.terminal_state IS NULL AND EXISTS(SELECT 1 FROM control.mfa_challenge unused
      WHERE unused.mfa_challenge_id::text=proofs[1]->>'mfaChallengeId' AND unused.participant_id=n.participant_id
       AND unused.used_at IS NULL AND unused.used_operation_id IS NULL))
      OR (resume.terminal_state='COMMITTED' AND EXISTS(SELECT 1 FROM control.mfa_challenge used
       WHERE used.mfa_challenge_id::text=proofs[1]->>'mfaChallengeId' AND used.participant_id=n.participant_id
        AND used.used_at IS NOT NULL AND used.used_operation_id=n.resume_operation_id))))
  OR proof_deadline<=clock_timestamp() OR fresh.valid_until<=clock_timestamp() OR n.expires_at<=clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM control.session s WHERE s.participant_id=n.participant_id AND s.session_id=n.maker_session_id
    AND s.principal_id=n.maker_principal_id AND s.state='ACTIVE' AND s.authority_epoch=n.maker_principal_epoch
    AND s.session_epoch=n.maker_session_epoch AND s.participant_epoch=n.maker_participant_epoch
    AND s.delegation_epoch=n.maker_delegation_epoch AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp())
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_discovery_approval_resume(control.mutation_candidate) FROM PUBLIC;

`;

export const discoveryApprovalResumeTargetSql = `
DROP POLICY IF EXISTS discovery_approval_resume_stored_child_read ON control.mutation_candidate;
CREATE POLICY discovery_approval_resume_stored_child_read ON control.mutation_candidate FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  AND resume_request->>'command'='RESUME' AND resume_request ? 'discoveryReceivingProof' AND predecessor_candidate_id IS NOT NULL
  AND state IN ('PROPOSED','APPROVAL_REQUESTED') AND consumed_operation_id IS NULL AND EXISTS(
   SELECT 1 FROM control.platform_recovery_case c JOIN control.platform_recovery_enrollment e
    ON e.enrollment_id=c.enrollment_id AND e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
   WHERE c.participant_id=mutation_candidate.participant_id AND c.privacy_domain_id=mutation_candidate.privacy_domain_id
    AND c.recovery_id=(SELECT e2.recovery_case_id FROM control.authority_envelope e2 WHERE e2.participant_id=mutation_candidate.participant_id AND e2.authority_envelope_id=mutation_candidate.maker_authority_envelope_id AND e2.principal_id=mutation_candidate.maker_principal_id AND e2.representation='RECOVERY_V1')
    AND c.state='ACTIVE' AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
    AND e.state='ACTIVE' AND e.row_version=c.enrollment_revision AND e.document_digest=c.enrollment_digest
    AND c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
    AND e.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' AND current_setting('openpc.local_qa_runtime',true)='1'
    AND c.intent->'certificateRecovery'=e.document->'certificateRecovery'
    AND mutation_candidate.resource_id::text=c.intent#>>'{certificateRecovery,predecessorCredentialId}'
    AND mutation_candidate.candidate_document=jsonb_build_object('replacedCredentialId',mutation_candidate.resource_id::text,
      'credentialId',c.intent#>>'{certificateRecovery,successorCredentialId}',
      'publicKeySpkiDer',c.intent#>>'{certificateRecovery,successorPublicKeySpkiDer}')));
CREATE OR REPLACE FUNCTION openpc.guard_discovery_approval_resume_target_claims()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE c control.platform_recovery_case; stored control.mutation_candidate;
BEGIN
 IF TG_TABLE_SCHEMA<>'control' OR TG_TABLE_NAME<>'mutation_candidate' OR TG_OP<>'INSERT'
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF NEW.catalog_operation_id<>'ID-OP-WORKLOAD-ROTATE' OR NEW.resume_request->>'command' IS DISTINCT FROM 'RESUME' THEN RETURN NEW; END IF;
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 SELECT * INTO STRICT stored FROM control.mutation_candidate WHERE mutation_candidate_id=NEW.mutation_candidate_id;
 IF (to_jsonb(stored)-ARRAY['state','updated_at']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['state','updated_at']) OR stored.state NOT IN ('PROPOSED','APPROVAL_REQUESTED') OR stored.consumed_operation_id IS NOT NULL THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 SELECT * INTO STRICT c FROM control.platform_recovery_case
  WHERE recovery_id=(SELECT e.recovery_case_id FROM control.authority_envelope e WHERE e.participant_id=NEW.participant_id AND e.authority_envelope_id=NEW.maker_authority_envelope_id AND e.principal_id=NEW.maker_principal_id AND e.representation='RECOVERY_V1') AND participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
   AND state='ACTIVE' AND valid_from<=clock_timestamp() AND valid_until>clock_timestamp()
   AND intent->>'schema'='pc.identity.discovery-certificate-recovery-intent' AND intent->>'schemaVersion'='2';
 IF current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR NEW.catalog_operation_id<>'ID-OP-WORKLOAD-ROTATE' OR NEW.action_intent_id<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR NEW.resource_id::text IS DISTINCT FROM c.intent#>>'{certificateRecovery,predecessorCredentialId}'
  OR NEW.candidate_document IS DISTINCT FROM jsonb_build_object('replacedCredentialId',NEW.resource_id::text,
    'credentialId',c.intent#>>'{certificateRecovery,successorCredentialId}',
    'publicKeySpkiDer',c.intent#>>'{certificateRecovery,successorPublicKeySpkiDer}')
  OR NEW.expected_revision::text IS DISTINCT FROM c.intent#>>'{certificateRecovery,predecessorRevision}'
  OR NEW.maker_principal_id::text IS DISTINCT FROM c.intent#>>'{administrators,0,principalId}'
  OR NEW.state NOT IN ('PROPOSED','APPROVAL_REQUESTED') OR NEW.consumed_operation_id IS NOT NULL OR NEW.predecessor_candidate_id IS NULL
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 PERFORM * FROM openpc.lock_discovery_certificate_recovery_source(c.enrollment_id,c.recovery_id);
 IF EXISTS(SELECT 1 FROM control.discovery_certificate_issuance i WHERE i.participant_id=c.participant_id
    AND (i.predecessor_credential_id::text=c.intent#>>'{certificateRecovery,predecessorCredentialId}'
     OR i.successor_credential_id::text=c.intent#>>'{certificateRecovery,successorCredentialId}'))
  OR EXISTS(SELECT 1 FROM control.discovery_certificate_issuer_attempt a JOIN control.discovery_certificate_issuance i
    ON i.participant_id=a.participant_id AND i.issuance_id=a.issuance_id WHERE i.participant_id=c.participant_id
     AND (i.predecessor_credential_id::text=c.intent#>>'{certificateRecovery,predecessorCredentialId}'
      OR i.successor_credential_id::text=c.intent#>>'{certificateRecovery,successorCredentialId}'))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 -- A clock advance may have hidden all target rows through their RLS basis.
 -- Reauthenticate the SAME case/source after the scan before any success.
 PERFORM * FROM openpc.lock_discovery_certificate_recovery_source(c.enrollment_id,c.recovery_id);
 IF NOT EXISTS(SELECT 1 FROM control.platform_recovery_case fresh WHERE fresh.recovery_id=c.recovery_id
   AND fresh.participant_id=c.participant_id AND fresh.privacy_domain_id=c.privacy_domain_id AND fresh.state='ACTIVE'
   AND fresh.enrollment_id=c.enrollment_id AND fresh.enrollment_revision=c.enrollment_revision
   AND fresh.enrollment_digest=c.enrollment_digest AND fresh.intent=c.intent
   AND fresh.valid_from<=clock_timestamp() AND fresh.valid_until>clock_timestamp())
  OR NEW.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_discovery_approval_resume_target_claims() FROM PUBLIC;
DROP TRIGGER IF EXISTS zz_discovery_approval_resume_claims ON control.mutation_candidate;
CREATE TRIGGER zz_discovery_approval_resume_claims AFTER INSERT ON control.mutation_candidate
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_approval_resume_target_claims();
DROP TRIGGER IF EXISTS zz_discovery_approval_resume_claims_completed ON control.mutation_candidate;
CREATE CONSTRAINT TRIGGER zz_discovery_approval_resume_claims_completed AFTER INSERT ON control.mutation_candidate
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_approval_resume_target_claims();

CREATE OR REPLACE FUNCTION openpc.guard_discovery_approval_resume_final()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE stored control.mutation_candidate;
BEGIN
 IF NEW.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND NEW.resume_request->>'command'='RESUME' THEN
  SELECT * INTO STRICT stored FROM control.mutation_candidate WHERE mutation_candidate_id=NEW.mutation_candidate_id;
  IF (to_jsonb(stored)-ARRAY['state','updated_at']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['state','updated_at'])
   OR stored.state NOT IN ('PROPOSED','APPROVAL_REQUESTED') OR stored.consumed_operation_id IS NOT NULL
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  PERFORM openpc.assert_discovery_approval_resume(stored);
 END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_discovery_approval_resume_final() FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.guard_discovery_approval_resume_completed()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE stored control.mutation_candidate;
BEGIN
 IF TG_TABLE_SCHEMA<>'control' OR TG_TABLE_NAME<>'mutation_candidate' OR TG_OP<>'INSERT'
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF NEW.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND NEW.resume_request->>'command'='RESUME' THEN
  SELECT * INTO STRICT stored FROM control.mutation_candidate WHERE mutation_candidate_id=NEW.mutation_candidate_id;
  IF (to_jsonb(stored)-ARRAY['state','updated_at']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['state','updated_at'])
   OR stored.state IS DISTINCT FROM 'APPROVAL_REQUESTED' OR stored.consumed_operation_id IS NOT NULL
   OR NOT EXISTS(SELECT 1 FROM control.idempotency_record resume JOIN control.approval_request approval
    ON approval.participant_id=resume.participant_id AND approval.privacy_domain_id=resume.privacy_domain_id
     AND approval.subject_type='CONFIGURATION_CANDIDATE' AND approval.subject_id=stored.mutation_candidate_id
    WHERE resume.participant_id=stored.participant_id AND resume.privacy_domain_id=stored.privacy_domain_id
     AND resume.operation_id=stored.resume_operation_id AND resume.terminal_state='COMMITTED'
     AND resume.expected_aggregate_version::text=stored.resume_request->>'expectedRevision'
     AND resume.principal_id=stored.maker_principal_id AND resume.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
     AND resume.catalog_operation_id='LEGACY' AND approval.state='OPEN' AND approval.row_version=1
     AND approval.subject_digest=stored.candidate_digest AND approval.subject_version=stored.expected_revision
     AND approval.action_intent_id=stored.action_intent_id AND approval.maker_principal_id=stored.maker_principal_id
     AND approval.checker_principal_id<>stored.maker_principal_id AND approval.expires_at=stored.expires_at
     AND resume.result_payload->>'resourceRef'='urn:openpc:resource:'||approval.approval_request_id::text)
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  PERFORM openpc.assert_discovery_approval_resume(stored);
 END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_discovery_approval_resume_completed() FROM PUBLIC;
DROP TRIGGER IF EXISTS zz_discovery_approval_resume_final ON control.mutation_candidate;
CREATE TRIGGER zz_discovery_approval_resume_final AFTER INSERT ON control.mutation_candidate
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_approval_resume_final();
DROP TRIGGER IF EXISTS zz_discovery_approval_resume_final_completed ON control.mutation_candidate;
CREATE CONSTRAINT TRIGGER zz_discovery_approval_resume_final_completed AFTER INSERT ON control.mutation_candidate
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_approval_resume_completed();

`;
export const discoveryApprovalResumeTargetGrantsSql = `GRANT EXECUTE ON FUNCTION openpc.guard_discovery_approval_resume_target_claims() TO openpc_control_owner;
GRANT EXECUTE ON FUNCTION openpc.assert_discovery_approval_resume(control.mutation_candidate) TO openpc_control_runtime,openpc_control_platform_runtime;`;
