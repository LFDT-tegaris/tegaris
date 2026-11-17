// Supported owners commit effects atomically in the control store. Each exact
// operation has an explicit effect check; absence of a receipt is never sufficient.
// Projection deletion is an atomic local effect. Native retirement can resume
// only BEFORE its atomic Control admission: no dispatch authority may exist.
export const mutationResumeGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_mutation_resume_no_effect(candidate_id uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE c control.mutation_candidate%ROWTYPE; selected jsonb; retirement_selection jsonb; source record; projection jsonb; resource_registration boolean;
BEGIN
 SELECT * INTO STRICT c FROM control.mutation_candidate WHERE mutation_candidate_id=candidate_id;
 IF c.catalog_operation_id IN('ID-OP-PLATFORM-SCOPE-PREPARE','ID-OP-PLATFORM-SCOPE-COMMIT') THEN
  IF c.action_intent_id<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' OR c.resource_type<>'participant'
   OR c.operation_class<>'UPDATE' OR c.state NOT IN('PROPOSED','APPROVAL_REQUESTED','APPROVED')
   OR c.consumed_operation_id IS NOT NULL
   OR c.candidate_document->>'replacementId' IS DISTINCT FROM c.resource_id::text
   OR c.expected_revision<>(CASE WHEN c.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' THEN 0 ELSE 1 END)
   OR c.candidate_document->>'schema' IS DISTINCT FROM (CASE WHEN c.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE'
      THEN 'pc.identity.platform-scope-replacement' ELSE 'pc.identity.platform-scope-replacement-commit' END)
   OR current_setting('transaction_isolation')<>'serializable'
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  IF NOT pg_try_advisory_xact_lock(hashtextextended('platform-scope-replacement:'||(c.candidate_document->>'platformContextId'),0))
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='PC-DATA-6007'; END IF;
  SELECT p.* INTO source FROM openpc.lock_platform_scope_context((c.candidate_document->>'platformContextId')::uuid) p
   WHERE p.owner_participant_id=c.participant_id AND p.state='ACTIVE'
    AND p.authority_epoch::text=c.candidate_document->>'predecessorEpoch'
    AND p.row_version::text=c.candidate_document->>'expectedRootRevision';
  IF source.platform_context_id IS NULL THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  IF c.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' THEN
   IF EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.platform_context_id=source.platform_context_id
      AND (r.replacement_id=c.resource_id OR (r.state='WITHDRAWING' AND
        c.candidate_document->'supersedes' IS DISTINCT FROM jsonb_build_object('replacementId',r.replacement_id::text,
          'expectedRevision',r.row_version::text,'successorDigest','sha256:'||encode(r.successor_digest,'hex')))))
    OR (c.candidate_document ? 'supersedes' AND NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement r
      WHERE r.platform_context_id=source.platform_context_id AND r.state='WITHDRAWING'
        AND r.replacement_id::text=c.candidate_document#>>'{supersedes,replacementId}'))
    OR (c.candidate_document#>>'{successorScope,validUntilNs}')::numeric<=extract(epoch from clock_timestamp())*1000000000
   THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  ELSE
   IF NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.participant_id=c.participant_id
     AND r.privacy_domain_id=c.privacy_domain_id AND r.replacement_id=c.resource_id AND r.state='WITHDRAWING' AND r.row_version=1
     AND r.platform_context_id=source.platform_context_id AND r.predecessor_epoch=source.authority_epoch
     AND r.expected_root_revision=source.row_version
     AND (r.candidate#>>'{successorScope,validUntilNs}')::numeric>extract(epoch from clock_timestamp())*1000000000)
   THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  END IF;
  IF EXISTS(SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=c.participant_id
    AND r.privacy_domain_id=c.privacy_domain_id AND r.principal_id=c.maker_principal_id
    AND r.action_intent_id=c.action_intent_id AND r.catalog_operation_id=c.catalog_operation_id AND r.idempotency_key=c.idempotency_key)
   OR EXISTS(SELECT 1 FROM control.mutation_evidence e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_type='platform-scope-replacement'
    AND e.aggregate_id=c.resource_id AND e.catalog_operation_id=c.catalog_operation_id)
   OR EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_type='platform-scope-replacement' AND e.aggregate_id=c.resource_id
    AND c.catalog_operation_id='ID-OP-PLATFORM-SCOPE-COMMIT' AND e.aggregate_sequence>1)
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN;
 END IF;
 IF c.catalog_operation_id='CFG-OP-QUALIFY-PROVIDER-PROFILE' THEN
  -- Qualification approves an existing provider. Its reset/probe history is
  -- required input, not an effect of this unsubmitted qualification intent.
  IF c.action_intent_id<>'ACT-PROVIDER_APPROVE_QUALIFICATION-V1'
   OR c.resource_type<>'provider-profile' OR c.operation_class<>'APPROVE' OR c.expected_revision<1
   OR c.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') OR c.consumed_operation_id IS NOT NULL
   OR c.candidate_document->>'targetRef' IS DISTINCT FROM 'urn:openpc:resource:'||c.resource_id::text
   OR c.candidate_document->>'expectedRevision' IS DISTINCT FROM c.expected_revision::text
   OR current_setting('transaction_isolation')<>'serializable'
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(openpc.signing_canonical_json(jsonb_build_array(
   'mutation-intent',c.participant_id::text,c.privacy_domain_id::text,c.maker_principal_id::text,
   c.action_intent_id,c.catalog_operation_id,c.idempotency_key)),0));
  -- The actual qualification UPDATE takes this same row lock. NOWAIT avoids
  -- reversing its provider/reference lock order; SERIALIZABLE rejects a tuple
  -- newer than this transaction's snapshot before any successor can be issued.
  BEGIN
   SELECT p.* INTO source FROM control.provider_profile p
    WHERE p.participant_id=c.participant_id AND p.privacy_domain_id=c.privacy_domain_id
     AND p.provider_profile_id=c.resource_id FOR UPDATE NOWAIT;
  EXCEPTION WHEN lock_not_available THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='PC-DATA-6007';
  END;
  IF source.provider_profile_id IS NULL OR source.revision<>c.expected_revision
   OR source.state<>'SHADOW' OR source.qualification_observation_id IS NOT NULL
   OR source.behavior_fingerprint IS DISTINCT FROM c.candidate_document->>'inputDigest'
   OR EXISTS(SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=c.participant_id
    AND r.privacy_domain_id=c.privacy_domain_id AND r.principal_id=c.maker_principal_id
    AND r.action_intent_id=c.action_intent_id AND r.catalog_operation_id=c.catalog_operation_id
    AND r.idempotency_key=c.idempotency_key)
   OR EXISTS(SELECT 1 FROM control.configuration_work w WHERE w.participant_id=c.participant_id
    AND w.privacy_domain_id=c.privacy_domain_id AND w.resource_id=c.resource_id
    AND (w.state NOT IN ('COMPLETED','FAILED') OR w.created_at>=c.created_at))
   OR EXISTS(SELECT 1 FROM control.provider_probe_observation o WHERE o.participant_id=c.participant_id
    AND o.privacy_domain_id=c.privacy_domain_id AND o.provider_profile_id=c.resource_id
    AND (o.observed_revision>c.expected_revision OR (o.observed_revision=c.expected_revision AND o.state<>'OBSERVED')))
   OR EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=c.participant_id
    AND a.privacy_domain_id=c.privacy_domain_id AND a.aggregate_id=c.resource_id
    AND (a.after_revision>c.expected_revision OR a.candidate_digest=c.candidate_digest))
   OR EXISTS(SELECT 1 FROM control.mutation_evidence e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_id=c.resource_id
    AND (e.aggregate_version>c.expected_revision OR e.candidate_digest=c.candidate_digest))
   OR EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_id=c.resource_id AND e.created_at>=c.created_at)
   OR EXISTS(SELECT 1 FROM control.receipt_signing_attempt a JOIN control.business_transition_profile p USING(profile_digest)
    WHERE a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
     AND p.catalog_operation_id=c.catalog_operation_id AND NOT EXISTS(
      SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=a.participant_id
       AND r.privacy_domain_id=a.privacy_domain_id AND r.operation_id=a.operation_id AND r.terminal_state='COMMITTED'))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN;
 END IF;
 IF c.catalog_operation_id='CFG-OP-ADMIT-INDEXER-PROFILE' THEN
  IF c.action_intent_id<>'ACT-INDEXER_APPROVE_PROFILE-V1'
   OR c.resource_type<>'indexer-profile' OR c.operation_class<>'APPROVE' OR c.expected_revision<1
   OR c.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') OR c.consumed_operation_id IS NOT NULL
   OR c.candidate_document->>'targetRef' IS DISTINCT FROM 'urn:openpc:resource:'||c.resource_id::text
   OR c.candidate_document->>'expectedRevision' IS DISTINCT FROM c.expected_revision::text
   OR current_setting('transaction_isolation')<>'serializable'
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(openpc.signing_canonical_json(jsonb_build_array(
   'mutation-intent',c.participant_id::text,c.privacy_domain_id::text,c.maker_principal_id::text,
   c.action_intent_id,c.catalog_operation_id,c.idempotency_key)),0));
  BEGIN
   SELECT i.* INTO source FROM control.indexer_profile i
    WHERE i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id
     AND i.indexer_profile_id=c.resource_id FOR UPDATE NOWAIT;
  EXCEPTION WHEN lock_not_available THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='PC-DATA-6007';
  END;
  IF source.indexer_profile_id IS NULL OR source.revision<>c.expected_revision
   OR source.state<>'REGISTERED'
   OR source.method_profile_digest IS DISTINCT FROM c.candidate_document->>'inputDigest'
   OR EXISTS(SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=c.participant_id
    AND r.privacy_domain_id=c.privacy_domain_id AND r.principal_id=c.maker_principal_id
    AND r.action_intent_id=c.action_intent_id AND r.catalog_operation_id=c.catalog_operation_id
    AND r.idempotency_key=c.idempotency_key)
   OR EXISTS(SELECT 1 FROM control.configuration_work w WHERE w.participant_id=c.participant_id
    AND w.privacy_domain_id=c.privacy_domain_id AND w.resource_id=c.resource_id
    AND w.work_kind='INDEXER_ADMISSION')
   OR EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=c.participant_id
    AND a.privacy_domain_id=c.privacy_domain_id AND a.aggregate_id=c.resource_id
    AND (a.after_revision>c.expected_revision OR a.candidate_digest=c.candidate_digest))
   OR EXISTS(SELECT 1 FROM control.mutation_evidence e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_id=c.resource_id
    AND (e.aggregate_version>c.expected_revision OR e.candidate_digest=c.candidate_digest))
   OR EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_id=c.resource_id AND e.created_at>=c.created_at)
   OR EXISTS(SELECT 1 FROM control.receipt_signing_attempt a JOIN control.business_transition_profile p USING(profile_digest)
    WHERE a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
     AND p.catalog_operation_id=c.catalog_operation_id AND NOT EXISTS(
      SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=a.participant_id
       AND r.privacy_domain_id=a.privacy_domain_id AND r.operation_id=a.operation_id AND r.terminal_state='COMMITTED'))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN;
 END IF;
 IF c.catalog_operation_id='ID-OP-ENVELOPE-CREATE' THEN
  -- Qualified only for an inert same-Participant ordinary Platform-root intent.
  -- Preserve its original bounded scopes; resumption never extends business expiry.
  IF c.action_intent_id<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   OR c.resource_type<>'participant' OR c.operation_class<>'UPDATE' OR c.expected_revision<>0
   OR c.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') OR c.consumed_operation_id IS NOT NULL
   OR current_setting('transaction_isolation')<>'serializable'
   OR c.candidate_document->>'schema' IS DISTINCT FROM 'pc.identity.authority-envelope-proposal'
   OR c.candidate_document->>'schemaVersion' IS DISTINCT FROM '1'
   OR c.candidate_document->>'issuance' IS DISTINCT FROM 'PLATFORM_ROOT'
   OR c.candidate_document ? 'platformScopeReplacementId'
   OR c.candidate_document->>'state' IS DISTINCT FROM 'DRAFT'
   OR c.candidate_document->>'id' IS DISTINCT FROM c.resource_id::text
   OR c.candidate_document->>'envelopeId' IS DISTINCT FROM c.resource_id::text
   OR c.candidate_document->>'participantId' IS DISTINCT FROM c.participant_id::text
   OR c.candidate_digest IS DISTINCT FROM sha256(convert_to(openpc.signing_canonical_json(c.candidate_document),'UTF8'))
   OR coalesce((c.candidate_document#>>'{usable,validUntilNs}')::numeric,0)<=extract(epoch from clock_timestamp())*1000000000
   OR coalesce((c.candidate_document#>>'{grantable,validUntilNs}')::numeric,0)<=extract(epoch from clock_timestamp())*1000000000
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(openpc.signing_canonical_json(jsonb_build_array(
   'mutation-intent',c.participant_id::text,c.privacy_domain_id::text,c.maker_principal_id::text,
   c.action_intent_id,c.catalog_operation_id,c.idempotency_key)),0));
  IF EXISTS(SELECT 1 FROM control.authority_envelope e WHERE e.participant_id=c.participant_id
    AND e.authority_envelope_id=c.resource_id)
   OR EXISTS(SELECT 1 FROM control.identity_envelope_proposal p WHERE p.participant_id=c.participant_id
    AND p.envelope_id=c.resource_id)
   OR EXISTS(SELECT 1 FROM control.identity_envelope_activation a WHERE a.participant_id=c.participant_id
    AND a.envelope_id=c.resource_id)
   OR EXISTS(SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=c.participant_id
    AND r.privacy_domain_id=c.privacy_domain_id AND r.principal_id=c.maker_principal_id
    AND r.action_intent_id=c.action_intent_id AND r.catalog_operation_id=c.catalog_operation_id AND r.idempotency_key=c.idempotency_key)
   OR EXISTS(SELECT 1 FROM control.mutation_evidence e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.catalog_operation_id=c.catalog_operation_id
    AND (e.aggregate_id=c.resource_id OR e.candidate_digest=c.candidate_digest))
   OR EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=c.participant_id
    AND a.privacy_domain_id=c.privacy_domain_id AND a.catalog_operation_id=c.catalog_operation_id
    AND (a.aggregate_id=c.resource_id OR a.candidate_digest=c.candidate_digest))
   OR EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_id=c.resource_id)
   OR EXISTS(SELECT 1 FROM control.receipt_signing_attempt a JOIN control.business_transition_profile p USING(profile_digest)
    WHERE a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id AND p.catalog_operation_id=c.catalog_operation_id
    AND a.reserved_at_ns>=extract(epoch from c.created_at)*1000000000
    AND NOT EXISTS(SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=a.participant_id
      AND r.privacy_domain_id=a.privacy_domain_id AND r.operation_id=a.operation_id AND r.terminal_state='COMMITTED'))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN;
 END IF;
 IF c.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE' THEN
  IF c.action_intent_id<>'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
   OR c.resource_type<>'participant' OR c.operation_class<>'ACTIVATE' OR c.expected_revision<>3
   OR c.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') OR c.consumed_operation_id IS NOT NULL
   OR c.candidate_document IS DISTINCT FROM jsonb_build_object('envelopeId',c.resource_id::text)
   OR c.candidate_digest IS DISTINCT FROM sha256(convert_to(openpc.signing_canonical_json(c.candidate_document),'UTF8'))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(openpc.signing_canonical_json(jsonb_build_array(
   'mutation-intent',c.participant_id::text,c.privacy_domain_id::text,c.maker_principal_id::text,
   c.action_intent_id,c.catalog_operation_id,c.idempotency_key)),0));
  SELECT envelope.* INTO source FROM control.authority_envelope envelope
   WHERE envelope.participant_id=c.participant_id AND envelope.authority_envelope_id=c.resource_id
   FOR UPDATE;
  IF source.authority_envelope_id IS NULL OR source.state<>'APPROVED' OR source.row_version<>3
   OR source.representation<>'TYPED_V1' OR octet_length(source.cose_sign1)<>0
   OR EXISTS(SELECT 1 FROM control.identity_envelope_activation activation
      WHERE activation.participant_id=c.participant_id AND activation.privacy_domain_id=c.privacy_domain_id
       AND (activation.candidate_id=c.mutation_candidate_id OR activation.envelope_id=c.resource_id))
   OR EXISTS(SELECT 1 FROM control.idempotency_record record
      WHERE record.participant_id=c.participant_id AND record.privacy_domain_id=c.privacy_domain_id
       AND record.principal_id=c.maker_principal_id AND record.action_intent_id=c.action_intent_id
       AND record.catalog_operation_id=c.catalog_operation_id AND record.idempotency_key=c.idempotency_key)
   OR EXISTS(SELECT 1 FROM control.mutation_evidence evidence
      WHERE evidence.participant_id=c.participant_id AND evidence.privacy_domain_id=c.privacy_domain_id
       AND evidence.catalog_operation_id=c.catalog_operation_id AND evidence.candidate_digest=c.candidate_digest)
   OR EXISTS(SELECT 1 FROM control.audit_occurrence receipt
      WHERE receipt.participant_id=c.participant_id AND receipt.privacy_domain_id=c.privacy_domain_id
       AND receipt.catalog_operation_id=c.catalog_operation_id AND receipt.candidate_digest=c.candidate_digest)
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN;
 END IF;
 IF c.catalog_operation_id='MOD-OP-INSTALL' THEN
  -- Registration is a prerequisite effect. Resume only the still-inert exact
  -- install, never a changed installation or an ambiguous lifecycle execution.
  IF c.action_intent_id<>'ACT-MODULE_CREATE_INSTALL-V1' OR c.resource_type<>'module'
   OR c.operation_class<>'CREATE' OR c.expected_revision<>1
   OR c.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') OR c.consumed_operation_id IS NOT NULL
   OR c.candidate_document->>'targetRef' IS DISTINCT FROM 'urn:openpc:resource:'||c.resource_id::text
   OR c.candidate_document->>'expectedRevision' IS DISTINCT FROM c.expected_revision::text
   OR current_setting('transaction_isolation')<>'serializable'
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(openpc.signing_canonical_json(jsonb_build_array(
   'mutation-intent',c.participant_id::text,c.privacy_domain_id::text,c.maker_principal_id::text,
   c.action_intent_id,c.catalog_operation_id,c.idempotency_key)),0));
  PERFORM pg_advisory_xact_lock(hashtextextended('module-admission:'||c.participant_id::text||':'||c.privacy_domain_id::text,0));
  SELECT i.*,v.manifest_digest INTO source FROM control.module_installation i
   JOIN control.module_version v USING(module_version_id)
   WHERE i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id
    AND i.module_installation_id=c.resource_id FOR UPDATE OF i;
  IF source.module_installation_id IS NULL OR source.state<>'ADMITTED' OR source.aggregate_version<>c.expected_revision
   OR source.active_manifest_digest IS NOT NULL OR source.lifecycle_operation_id IS NOT NULL
   OR source.lifecycle_evaluation_digest IS NOT NULL
   OR c.candidate_document->>'inputDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(
    openpc.signing_canonical_json(jsonb_build_object('targetRef','urn:openpc:resource:'||c.resource_id::text,
     'expectedRevision',c.expected_revision::text,'manifestDigest','sha256:'||encode(source.manifest_digest,'hex'))),'UTF8')),'hex')
   OR (SELECT count(*) FROM control.module_configuration_generation g WHERE g.participant_id=c.participant_id
    AND g.privacy_domain_id=c.privacy_domain_id AND g.module_installation_id=c.resource_id)<>1
   OR NOT EXISTS(SELECT 1 FROM control.module_configuration_generation g WHERE g.participant_id=c.participant_id
    AND g.privacy_domain_id=c.privacy_domain_id AND g.module_installation_id=c.resource_id AND g.generation=1 AND NOT g.active)
   OR EXISTS(SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=c.participant_id
    AND r.privacy_domain_id=c.privacy_domain_id AND r.principal_id=c.maker_principal_id
    AND r.action_intent_id=c.action_intent_id AND r.catalog_operation_id=c.catalog_operation_id AND r.idempotency_key=c.idempotency_key)
   OR EXISTS(SELECT 1 FROM control.configuration_work w WHERE w.participant_id=c.participant_id
    AND w.privacy_domain_id=c.privacy_domain_id AND w.resource_id=c.resource_id)
   OR EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=c.participant_id
    AND a.privacy_domain_id=c.privacy_domain_id AND (a.candidate_digest=c.candidate_digest
     OR (a.aggregate_id=c.resource_id AND (a.after_revision>c.expected_revision OR a.catalog_operation_id=c.catalog_operation_id))))
   OR EXISTS(SELECT 1 FROM control.mutation_evidence e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND (e.candidate_digest=c.candidate_digest
     OR (e.aggregate_id=c.resource_id AND (e.aggregate_version>c.expected_revision OR e.catalog_operation_id=c.catalog_operation_id))))
   OR EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_id=c.resource_id AND e.aggregate_sequence>c.expected_revision)
   OR EXISTS(SELECT 1 FROM control.receipt_signing_attempt a JOIN control.business_transition_profile p USING(profile_digest)
    WHERE a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
     AND p.catalog_operation_id=c.catalog_operation_id AND NOT EXISTS(SELECT 1 FROM control.idempotency_record r
      WHERE r.participant_id=a.participant_id AND r.privacy_domain_id=a.privacy_domain_id
       AND r.operation_id=a.operation_id AND r.terminal_state='COMMITTED'))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN;
 END IF;
 resource_registration:=(c.catalog_operation_id,c.action_intent_id,c.resource_type,c.operation_class) IN (
  ('CFG-OP-CREATE-RUNTIME-TARGET-PROFILE','ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1','runtime-target-profile-binding','CREATE'),
  ('CFG-OP-CREATE-PROVIDER-PROFILE','ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1','provider-profiles','CREATE'),
  ('CFG-OP-CREATE-ABI-ARTIFACT','ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1','abi-artifact','CREATE'),
  ('CFG-OP-CREATE-LOGICAL-CONTRACT','ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1','logical-contract-asset','CREATE'),
  ('CFG-OP-CREATE-RUNTIME-BINDING','ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1','contract-runtime-binding','CREATE'),
  ('CFG-OP-CREATE-METHOD-POLICY','ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1','contract-method-policy','CREATE'));
 IF (resource_registration OR (c.catalog_operation_id='MOD-OP-REGISTER' AND c.action_intent_id='ACT-MODULES_CREATE_RESOURCE-V1' AND c.resource_type='modules')
      OR (c.catalog_operation_id='ID-OP-ASSIGNMENT-CREATE' AND c.action_intent_id='ACT-PARTICIPANT_CREATE_MEMBER-V1' AND c.resource_type='principal')
      OR (c.catalog_operation_id='CFG-OP-CREATE-EVIDENCE-HOLD' AND c.action_intent_id='ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1'
          AND c.resource_type='evidence-holds' AND c.candidate_document->'selector'->>'type'<>'PARTICIPANT')
      OR (c.catalog_operation_id='CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD' AND c.action_intent_id='ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1'
          AND c.resource_type='evidence-holds' AND c.candidate_document->'selector'->>'type'='PARTICIPANT')
      OR (c.catalog_operation_id='CFG-OP-ACTIVATE-RETENTION-POLICY'
          AND c.action_intent_id='ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1' AND c.resource_type='retention-policies')
      OR (c.catalog_operation_id='CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE'
          AND c.action_intent_id='ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1' AND c.resource_type='evidence-deletions')
      OR (c.catalog_operation_id='CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH'
          AND c.action_intent_id='ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1' AND c.resource_type='evidence-deletions')
      OR (c.catalog_operation_id='CFG-OP-ADMIT-STORE-RETIREMENT'
          AND c.action_intent_id='ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1' AND c.resource_type='evidence-deletions')
      OR (c.catalog_operation_id='CFG-OP-DELETE-PROJECTION-BATCH'
          AND c.action_intent_id='ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1' AND c.resource_type='evidence-deletions')) IS NOT TRUE
    OR c.operation_class<>'CREATE' OR c.expected_revision<>0
    OR c.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') OR c.consumed_operation_id IS NOT NULL
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF c.catalog_operation_id='CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH' AND NOT
  pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(openpc.signing_canonical_json(jsonb_build_array(
  'mutation-intent',c.participant_id::text,c.privacy_domain_id::text,c.maker_principal_id::text,
  c.action_intent_id,c.catalog_operation_id,c.idempotency_key)),0));
 IF resource_registration THEN
  IF current_setting('transaction_isolation')<>'serializable'
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  IF c.catalog_operation_id='CFG-OP-CREATE-RUNTIME-TARGET-PROFILE' THEN
   -- Match the binding owner's lock order. The target cannot change between
   -- checking its revision and committing this continuation.
   IF (c.candidate_document->>'runtimeTargetRef' ~ '^urn:openpc:resource:[0-9a-f-]{36}$'
       AND c.candidate_document->>'targetRevision' ~ '^[1-9][0-9]{0,18}$'
       AND c.candidate_document->>'targetProfileId' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') IS NOT TRUE
   THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
   BEGIN
    PERFORM 1 FROM control.participant WHERE participant_id=c.participant_id FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
    PERFORM 1 FROM control.runtime_target
     WHERE participant_id=c.participant_id AND privacy_domain_id=c.privacy_domain_id
      AND runtime_target_id=substring(c.candidate_document->>'runtimeTargetRef' from 21)::uuid
      AND revision::text=c.candidate_document->>'targetRevision'
      AND state IN ('OFFLINE','DISCOVERED')
      AND desired_generation_digest IS NULL AND active_generation_digest IS NULL
     FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
   EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='PC-DATA-6007';
   END;
  END IF;
  -- These creators commit only their own row and the common atomic
  -- evidence/outbox. Referenced ABI, logical, binding and rule rows are inputs.
  -- Preserve both the original resource identity and its actual unique key.
  IF (c.catalog_operation_id='CFG-OP-CREATE-RUNTIME-TARGET-PROFILE' AND EXISTS (
       SELECT 1 FROM control.runtime_target_profile_binding b WHERE b.participant_id=c.participant_id
        AND (b.binding_id=c.resource_id
         OR b.runtime_target_id=substring(c.candidate_document->>'runtimeTargetRef' from 21)::uuid
         OR (b.privacy_domain_id=c.privacy_domain_id
          AND b.target_profile_id=c.candidate_document->>'targetProfileId'))))
   OR (c.catalog_operation_id='CFG-OP-CREATE-PROVIDER-PROFILE' AND EXISTS (
       SELECT 1 FROM control.provider_profile p WHERE p.participant_id=c.participant_id
        AND p.privacy_domain_id=c.privacy_domain_id AND (p.provider_profile_id=c.resource_id
         OR (p.chain_id=c.candidate_document->>'chainId'
          AND p.endpoint_secret_ref=c.candidate_document->>'endpointSecretRef'
          AND p.behavior_fingerprint=c.candidate_document->>'behaviorFingerprint'))))
   OR (c.catalog_operation_id='CFG-OP-CREATE-ABI-ARTIFACT' AND EXISTS (
       SELECT 1 FROM control.abi_artifact a WHERE a.participant_id=c.participant_id
        AND a.privacy_domain_id=c.privacy_domain_id AND (a.abi_artifact_id=c.resource_id
         OR a.abi_digest=c.candidate_document->>'abiDigest')))
   OR (c.catalog_operation_id='CFG-OP-CREATE-LOGICAL-CONTRACT' AND EXISTS (
       SELECT 1 FROM control.logical_contract_asset a WHERE a.participant_id=c.participant_id
        AND a.privacy_domain_id=c.privacy_domain_id AND (a.logical_contract_id=c.resource_id
         OR a.logical_name=c.candidate_document->>'logicalName')))
   OR (c.catalog_operation_id='CFG-OP-CREATE-RUNTIME-BINDING' AND EXISTS (
       SELECT 1 FROM control.contract_runtime_binding b WHERE b.participant_id=c.participant_id
        AND b.privacy_domain_id=c.privacy_domain_id AND (b.runtime_binding_id=c.resource_id
         OR (b.chain_id=c.candidate_document->>'chainId' AND b.network_id=c.candidate_document->>'networkId'
          AND b.contract_address=c.candidate_document->>'contractAddress'))))
   OR (c.catalog_operation_id='CFG-OP-CREATE-METHOD-POLICY' AND EXISTS (
       SELECT 1 FROM control.contract_method_policy m WHERE m.participant_id=c.participant_id
        AND m.privacy_domain_id=c.privacy_domain_id AND (m.contract_method_policy_id=c.resource_id
         OR ('urn:openpc:resource:'||m.runtime_binding_id::text=c.candidate_document->>'runtimeBindingId'
          AND m.selector=c.candidate_document->>'selector'))))
   OR EXISTS (SELECT 1 FROM control.outbox_aggregate_head h WHERE h.participant_id=c.participant_id
        AND h.aggregate_type=c.resource_type AND h.aggregate_id=c.resource_id)
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF c.catalog_operation_id='MOD-OP-REGISTER' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('module-admission:'||c.participant_id::text||':'||c.privacy_domain_id::text,0));
 END IF;
 IF c.catalog_operation_id IN ('CFG-OP-CREATE-EVIDENCE-HOLD','CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD') THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
  IF EXISTS (SELECT 1 FROM control.retention_hold h WHERE h.participant_id=c.participant_id AND h.retention_hold_id=c.resource_id)
    OR EXISTS (SELECT 1 FROM control.evidence_hold_coverage h WHERE h.participant_id=c.participant_id AND h.retention_hold_id=c.resource_id)
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF c.catalog_operation_id='CFG-OP-ACTIVATE-RETENTION-POLICY' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
  -- Activation is atomic and local. Check both the original identity and the
  -- version's natural key; execution still rechecks the current predecessor.
  IF EXISTS (SELECT 1 FROM control.retention_policy p WHERE p.participant_id=c.participant_id
    AND p.privacy_domain_id=c.privacy_domain_id AND (p.retention_policy_id=c.resource_id
      OR (p.data_class=c.candidate_document->'policy'->>'dataClass'
        AND p.policy_version=c.candidate_document->'policy'->>'policyVersion')))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF c.catalog_operation_id='CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
  -- An admitted permanent source denial cannot be renewed or replaced by a
  -- second approval. Only the original native/operation readback may reconcile.
  IF EXISTS(SELECT 1 FROM control.runtime_artifact_source_disposition a WHERE a.participant_id=c.participant_id
    AND a.privacy_domain_id=c.privacy_domain_id AND (a.disposition_id=c.resource_id
     OR a.configuration_digest=decode(substring(c.candidate_document->'selection'->'observation'->'source'->>'configurationDigest' from 8),'hex')))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF c.catalog_operation_id='CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH' THEN
  retirement_selection:=c.candidate_document->'selection';
  -- Renewal proves only no physical effect. It neither reads source bytes nor
  -- borrows current deletion eligibility; execution rechecks every live gate.
  IF (retirement_selection->>'version'='OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1'
    AND retirement_selection->>'participantId'='urn:openpc:participant:'||c.participant_id::text
    AND retirement_selection->>'privacyDomainId'=c.privacy_domain_id::text
    AND retirement_selection->>'targetDatabase'='openpc_control' AND retirement_selection->>'dataClass'='RUNTIME_ARTIFACT'
    AND retirement_selection->>'deletionMode'='ROW_DELETE'
    AND retirement_selection->'source'->>'participantId'=c.participant_id::text
    AND retirement_selection->'source'->>'privacyDomainId'=c.privacy_domain_id::text) IS NOT TRUE
   OR c.candidate_digest IS DISTINCT FROM sha256(convert_to(openpc.signing_canonical_json(c.candidate_document),'UTF8'))
   OR NOT EXISTS(SELECT 1 FROM control.action_intent i WHERE i.action_intent_id=c.action_intent_id
    AND c.candidate_document->>'actionIntentId'=i.action_intent_id
    AND c.candidate_document->>'actionIntentDigest'='sha256:'||encode(i.semantic_digest,'hex'))
   OR NOT EXISTS(SELECT 1 FROM control.business_transition_profile p
    WHERE p.profile_id='pc.control.evidence-deletion.runtime-artifact' AND p.profile_version=1
    AND p.catalog_operation_id=c.catalog_operation_id AND p.action_intent_id=c.action_intent_id
    AND p.profile_digest=decode('d1f1c8ccfbd049063197e8511e1b0604888963b29cc40fec7ca8e72f539d85c5','hex'))
   OR NOT EXISTS(SELECT 1 FROM control.runtime_configuration_input i WHERE i.participant_id=c.participant_id
    AND i.privacy_domain_id=c.privacy_domain_id
    AND i.runtime_configuration_input_id::text=retirement_selection->'source'->>'runtimeConfigurationInputId'
    AND retirement_selection->'source'=jsonb_build_object('participantId',i.participant_id::text,'privacyDomainId',i.privacy_domain_id::text,
     'runtimeConfigurationInputId',i.runtime_configuration_input_id::text,'moduleInstallationId',i.module_installation_id::text,
     'moduleConfigurationGenerationId',i.module_configuration_generation_id::text,'configurationDigest','sha256:'||encode(i.configuration_digest,'hex'),
     'configurationBytes',(openpc.runtime_artifact_input_information(i.runtime_configuration_input_id)->>'byteLength')::integer,
     'resourceBindingsDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(i.resource_bindings),'UTF8')),'hex'),
     'createdAt',to_char(i.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    AND openpc.runtime_artifact_input_information(i.runtime_configuration_input_id)->'bytesMatch'='true'::jsonb)
   OR EXISTS(SELECT 1 FROM control.runtime_artifact_retirement r WHERE r.participant_id=c.participant_id
    AND r.privacy_domain_id=c.privacy_domain_id AND (r.deletion_job_id=c.resource_id
     OR r.runtime_configuration_input_id::text=retirement_selection->'source'->>'runtimeConfigurationInputId'
     OR r.configuration_digest=retirement_selection->'source'->>'configurationDigest'))
   OR EXISTS(SELECT 1 FROM control.deletion_job j WHERE j.participant_id=c.participant_id
    AND j.privacy_domain_id=c.privacy_domain_id AND (j.deletion_job_id=c.resource_id
     OR (j.target_data_class='RUNTIME_ARTIFACT' AND
      (j.selection->'source'->>'runtimeConfigurationInputId'=retirement_selection->'source'->>'runtimeConfigurationInputId'
       OR j.selection->'source'->>'configurationDigest'=retirement_selection->'source'->>'configurationDigest'))))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF c.catalog_operation_id='CFG-OP-ADMIT-STORE-RETIREMENT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
  -- An admitted UNKNOWN outcome must reconcile its original dispatch; absence
  -- of a terminal native receipt never permits fresh approval or re-dispatch.
  IF EXISTS (SELECT 1 FROM control.store_retirement_admission a
    WHERE a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
      AND (a.attempt_id=c.resource_id OR a.approval_request_id IN
        (SELECT r.approval_request_id FROM control.approval_request r
          WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id
            AND r.subject_type='CONFIGURATION_CANDIDATE' AND r.subject_id=c.mutation_candidate_id)))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF c.catalog_operation_id='CFG-OP-DELETE-PROJECTION-BATCH' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
  selected:=c.candidate_document->'selection';
  IF (selected->>'version'='OPENPC_PROJECTION_DELETION_BATCH_V1'
    AND selected->>'participantId'='urn:openpc:participant:'||c.participant_id::text
    AND selected->>'privacyDomainId'=c.privacy_domain_id::text
    AND selected->>'targetDatabase'='openpc_control' AND selected->>'deletionMode'='PROJECTION_DELETE'
    AND ((selected->>'dataClass'='SEARCH_PROJECTION' AND selected->>'sourceKind' IN ('AUTHENTICATION_CATALOGUE','RETENTION_POLICY_CATALOGUE'))
      OR (selected->>'dataClass'='NORMALIZED_JSON_PROJECTION'
        AND selected->>'sourceKind' IN ('RPC_PRE_ADMISSION_DENIAL','RPC_CLOSED_TRANSITION','FACT_PROVENANCE','DEPLOYMENT_PROVENANCE')))) IS NOT TRUE
   OR EXISTS (SELECT 1 FROM control.deletion_job j WHERE j.participant_id=c.participant_id
     AND j.privacy_domain_id=c.privacy_domain_id AND (j.deletion_job_id=c.resource_id OR j.selection=selected))
   OR EXISTS (SELECT 1 FROM control.evidence_projection_retirement r WHERE r.participant_id=c.participant_id
     AND r.privacy_domain_id=c.privacy_domain_id AND r.data_class=selected->>'dataClass'
     AND 'urn:openpc:resource:'||r.evidence_id::text=selected->>'evidenceId')
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  -- Recovery proves absence of this local effect without borrowing the raw
  -- source-disclosure authority of a deletion execution. Full source, retention,
  -- hold, finality and continuation admission still runs at actual execution.
  SELECT * INTO source FROM control.evidence_catalogue e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND 'urn:openpc:resource:'||e.evidence_id::text=selected->>'evidenceId'
    AND e.stream_id=selected->>'streamId' AND e.record_id=selected->>'recordId'
    AND e.segment_id::text=selected->>'segmentId' AND e.sequence::text=selected->>'sequence'
    AND e.receipt_digest=selected->>'sourceReceiptDigest';
  IF NOT FOUND THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  IF (selected->>'sourceKind'='AUTHENTICATION_CATALOGUE' AND source.source_format='OPENPC_AUTHENTICATION_OCCURRENCE_V1'
    AND source.evidence_class='AUTHENTICATION') OR (selected->>'sourceKind'='RETENTION_POLICY_CATALOGUE'
    AND source.evidence_class='BUSINESS_TRANSITION') THEN
   SELECT openpc.evidence_catalogue_projection(e) INTO projection FROM control.evidence_catalogue e
    WHERE e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id AND e.evidence_id=source.evidence_id;
  ELSIF selected->>'sourceKind'='FACT_PROVENANCE' AND source.source_format='OPENPC_CANONICAL_FACT_V1' AND source.evidence_class='EFFECT' THEN
   SELECT p.projection INTO projection FROM control.evidence_fact_provenance p WHERE p.participant_id=c.participant_id
    AND p.privacy_domain_id=c.privacy_domain_id AND p.stream_id=source.stream_id AND p.record_id=source.record_id
    AND p.projection_digest=selected->>'projectionDigest';
  ELSIF selected->>'sourceKind'='DEPLOYMENT_PROVENANCE' AND source.source_format='PC-DEPLOYMENT-JOURNAL-PROJECTION-1' AND source.evidence_class='EFFECT' THEN
   SELECT p.projection INTO projection FROM control.evidence_deployment_provenance p WHERE p.participant_id=c.participant_id
    AND p.privacy_domain_id=c.privacy_domain_id AND p.stream_id=source.stream_id AND p.record_id=source.record_id
    AND p.projection_digest=selected->>'projectionDigest';
  ELSIF selected->>'sourceKind' IN ('RPC_PRE_ADMISSION_DENIAL','RPC_CLOSED_TRANSITION')
    AND source.source_format='OPENPC_RPC_DECISION_TRANSITION_V1' AND source.evidence_class='EFFECT' THEN
   SELECT p.projection INTO projection FROM control.evidence_rpc_provenance p WHERE p.participant_id=c.participant_id
    AND p.privacy_domain_id=c.privacy_domain_id AND p.stream_id=source.stream_id AND p.record_id=source.record_id
    AND p.projection_digest=selected->>'projectionDigest';
  END IF;
  IF projection IS NULL OR ('sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(projection),'UTF8')),'hex'))
      IS DISTINCT FROM selected->>'projectionDigest'
    OR octet_length(convert_to(openpc.signing_canonical_json(projection),'UTF8'))::text IS DISTINCT FROM selected->>'projectionBytes'
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF EXISTS (SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=c.participant_id
      AND r.privacy_domain_id=c.privacy_domain_id AND r.principal_id=c.maker_principal_id
      AND r.action_intent_id=c.action_intent_id AND r.catalog_operation_id=c.catalog_operation_id
      AND r.idempotency_key=c.idempotency_key)
 OR (c.catalog_operation_id='ID-OP-ASSIGNMENT-CREATE' AND EXISTS (
      SELECT 1 FROM control.assignment a WHERE a.participant_id=c.participant_id AND a.assignment_id=c.resource_id))
 OR (c.catalog_operation_id='MOD-OP-REGISTER' AND EXISTS (SELECT 1 FROM control.module_installation i JOIN control.module_version v USING(module_version_id)
      WHERE i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id
      AND (i.module_installation_id=c.resource_id OR (v.module_id=c.candidate_document->>'name'
        AND v.semantic_version=c.candidate_document->>'semanticVersion'))))
 OR EXISTS (SELECT 1 FROM control.configuration_work w WHERE w.participant_id=c.participant_id
      AND w.privacy_domain_id=c.privacy_domain_id AND (w.resource_id=c.resource_id OR w.input_digest='sha256:'||encode(c.candidate_digest,'hex')))
 OR EXISTS (SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=c.participant_id
      AND a.privacy_domain_id=c.privacy_domain_id AND (a.aggregate_id=c.resource_id OR a.candidate_digest=c.candidate_digest))
 OR EXISTS (SELECT 1 FROM control.mutation_evidence e WHERE e.participant_id=c.participant_id
      AND e.privacy_domain_id=c.privacy_domain_id AND (e.aggregate_id=c.resource_id OR
        (e.catalog_operation_id=c.catalog_operation_id AND e.candidate_digest=c.candidate_digest)))
 OR EXISTS (SELECT 1 FROM control.outbox_event e WHERE e.participant_id=c.participant_id
      AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_id=c.resource_id)
 OR EXISTS (SELECT 1 FROM control.receipt_signing_attempt a JOIN control.business_transition_profile p USING(profile_digest)
      WHERE a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
        AND p.catalog_operation_id=c.catalog_operation_id AND NOT EXISTS (
          SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=a.participant_id
            AND r.privacy_domain_id=a.privacy_domain_id AND r.operation_id=a.operation_id AND r.terminal_state='COMMITTED'))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
END $$;

-- This local no-effect boundary is distinct from approval-backed RESUME. Both
-- immediate and deferred triggers authenticate the retained immutable lineage.
CREATE OR REPLACE FUNCTION openpc.assert_discovery_preapproval_continuation(n control.mutation_candidate)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE old_attempt control.mutation_candidate; previous control.platform_recovery_case;
 fresh control.platform_recovery_case; old_enrollment control.platform_recovery_enrollment;
 new_enrollment control.platform_recovery_enrollment; old_envelope control.authority_envelope; new_envelope control.authority_envelope;
 lineage_ids uuid[]; original_floor timestamptz; proof_count integer; proofs jsonb[]; proof_deadline timestamptz;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id() IS DISTINCT FROM n.action_intent_id THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
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
      OR c.state<>'PROPOSED' OR c.consumed_operation_id IS NOT NULL
      OR (c.predecessor_candidate_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM control.mutation_candidate parent
        WHERE parent.mutation_candidate_id=c.predecessor_candidate_id AND parent.mutation_candidate_id=any(lineage_ids) AND parent.attempt=c.attempt-1))
      OR (c.predecessor_candidate_id IS NULL AND c.attempt<>1)))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 SELECT count(*),array_agg(jsonb_build_object('mfaChallengeId',m.mfa_challenge_id::text,
   'verificationOperationId',verification.operation_id::text,'evidenceDigest','sha256:'||encode(verification.evidence_digest,'hex'))),
   min(least(m.expires_at,m.consumed_at+interval '5 minutes',coalesce(credential.valid_until,'infinity'::timestamptz)))
  INTO proof_count,proofs,proof_deadline FROM control.mfa_challenge m
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
  AND m.action_intent_id=n.action_intent_id AND m.resource_digest=n.candidate_digest AND m.resource_id=n.resource_id::text
  AND m.created_at>=greatest(fresh.activated_at,new_envelope.valid_from) AND m.consumed_at>=greatest(fresh.activated_at,new_envelope.valid_from)
  AND m.consumed_at>clock_timestamp()-interval '5 minutes' AND m.consumed_at<=clock_timestamp()
  AND m.expires_at>clock_timestamp() AND m.used_at IS NULL AND m.used_operation_id IS NULL;
 IF proof_count<>1 OR n.resume_request->'receivingProof' IS DISTINCT FROM proofs[1] THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF current_setting('transaction_isolation')<>'serializable'
  OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR old_enrollment.document->>'assurance' IS DISTINCT FROM 'LOCAL_QA_VIRTUAL_AUTHENTICATOR'
  OR new_enrollment.document->>'assurance' IS DISTINCT FROM 'LOCAL_QA_VIRTUAL_AUTHENTICATOR'
  OR old_attempt.catalog_operation_id<>'ID-OP-WORKLOAD-ROTATE'
  OR old_attempt.action_intent_id<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR old_attempt.resource_type<>'participant' OR old_attempt.operation_class<>'UPDATE'
  OR old_attempt.state<>'PROPOSED' OR old_attempt.consumed_operation_id IS NOT NULL
  OR n.state<>'PROPOSED' OR n.consumed_operation_id IS NOT NULL
  OR n.predecessor_approval_id IS NOT NULL OR n.resume_operation_id IS NOT NULL
  OR n.attempt<>old_attempt.attempt+1 OR n.expires_at<=clock_timestamp()
  OR n.expires_at>least(clock_timestamp()+interval '30 minutes',fresh.valid_until)
  OR row(n.participant_id,n.privacy_domain_id,n.action_intent_id,n.catalog_operation_id,n.resource_type,
    n.operation_class,n.resource_id,n.candidate_digest,n.candidate_document,n.expected_revision,n.idempotency_key,n.maker_principal_id)
   IS DISTINCT FROM row(old_attempt.participant_id,old_attempt.privacy_domain_id,old_attempt.action_intent_id,
    old_attempt.catalog_operation_id,old_attempt.resource_type,old_attempt.operation_class,old_attempt.resource_id,
    old_attempt.candidate_digest,old_attempt.candidate_document,old_attempt.expected_revision,old_attempt.idempotency_key,old_attempt.maker_principal_id)
  OR old_envelope.representation<>'RECOVERY_V1' OR old_envelope.principal_id<>n.maker_principal_id
  OR previous.state<>'EXPIRED' OR previous.valid_until>clock_timestamp() OR previous.completion_operation_id IS NOT NULL OR previous.completion_result IS NOT NULL
  OR fresh.state<>'ACTIVE' OR fresh.recovery_id=previous.recovery_id OR fresh.valid_until<=clock_timestamp()
  OR previous.intent->>'schema' IS DISTINCT FROM 'pc.identity.discovery-certificate-recovery-intent'
  OR fresh.intent->>'schema' IS DISTINCT FROM previous.intent->>'schema'
  OR fresh.intent->'certificateRecovery' IS DISTINCT FROM previous.intent->'certificateRecovery'
  OR ((fresh.intent#>'{administrators,0}')-'principalEpoch') IS DISTINCT FROM ((previous.intent#>'{administrators,0}')-'principalEpoch')
  OR ((fresh.intent#>'{administrators,1}')-'principalEpoch') IS DISTINCT FROM ((previous.intent#>'{administrators,1}')-'principalEpoch')
  OR fresh.intent#>>'{administrators,0,principalId}' IS DISTINCT FROM n.maker_principal_id::text
  OR row(new_enrollment.participant_id,new_enrollment.privacy_domain_id,new_enrollment.platform_context_id,
    new_enrollment.source_purpose,new_enrollment.root_epoch,new_enrollment.root_revision,new_enrollment.root_digest)
   IS DISTINCT FROM row(old_enrollment.participant_id,old_enrollment.privacy_domain_id,old_enrollment.platform_context_id,
    old_enrollment.source_purpose,old_enrollment.root_epoch,old_enrollment.root_revision,old_enrollment.root_digest)
  OR new_enrollment.document->'source' IS DISTINCT FROM old_enrollment.document->'source'
  OR n.resume_request IS DISTINCT FROM jsonb_build_object('command','DISCOVERY_PREAPPROVAL_CONTINUE',
    'predecessorCandidateId',old_attempt.mutation_candidate_id::text,'expectedAttempt',old_attempt.attempt::text,
    'candidateDigest','sha256:'||encode(old_attempt.candidate_digest,'hex'),
    'predecessorRecoveryId',previous.recovery_id::text,'recoveryId',fresh.recovery_id::text,'receivingProof',proofs[1])
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
    AND m.session_id IN(SELECT c.maker_session_id FROM control.mutation_candidate c WHERE c.mutation_candidate_id=any(lineage_ids)))
  OR EXISTS(SELECT 1 FROM control.approval_decision_record d WHERE d.participant_id=n.participant_id
    AND d.privacy_domain_id=n.privacy_domain_id AND d.candidate_digest=n.candidate_digest)
  OR EXISTS(SELECT 1 FROM control.approval_request a WHERE a.participant_id=n.participant_id
    AND a.privacy_domain_id=n.privacy_domain_id AND a.subject_digest=n.candidate_digest)
  OR EXISTS(SELECT 1 FROM control.discovery_certificate_issuance i WHERE i.participant_id=n.participant_id
    AND (i.predecessor_credential_id=n.resource_id OR i.successor_credential_id::text=n.candidate_document->>'credentialId'))
  OR EXISTS(SELECT 1 FROM control.discovery_certificate_issuer_attempt a WHERE a.participant_id=n.participant_id
    AND a.privacy_domain_id=n.privacy_domain_id AND a.idempotency_key=n.idempotency_key)
  OR EXISTS(SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=n.participant_id AND r.privacy_domain_id=n.privacy_domain_id
    AND (r.idempotency_key IN(n.idempotency_key,n.idempotency_key||'-request')
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
    AND c.candidate_digest=n.candidate_digest AND (c.state<>'PROPOSED' OR c.consumed_operation_id IS NOT NULL))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 -- Reselect the SAME strict native proof after every local absence scan. The
 -- final invoker trigger repeats this after the private cross-privacy scan and
 -- again at deferred success; crypto never becomes a writable verified flag.
 SELECT count(*),array_agg(jsonb_build_object('mfaChallengeId',m.mfa_challenge_id::text,
   'verificationOperationId',verification.operation_id::text,'evidenceDigest','sha256:'||encode(verification.evidence_digest,'hex'))),
   min(least(m.expires_at,m.consumed_at+interval '5 minutes',coalesce(credential.valid_until,'infinity'::timestamptz)))
  INTO proof_count,proofs,proof_deadline FROM control.mfa_challenge m
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
  AND m.action_intent_id=n.action_intent_id AND m.resource_digest=n.candidate_digest AND m.resource_id=n.resource_id::text
  AND m.created_at>=greatest(fresh.activated_at,new_envelope.valid_from) AND m.consumed_at>=greatest(fresh.activated_at,new_envelope.valid_from)
  AND m.consumed_at>clock_timestamp()-interval '5 minutes' AND m.consumed_at<=clock_timestamp()
  AND m.expires_at>clock_timestamp() AND m.used_at IS NULL AND m.used_operation_id IS NULL;
 IF proof_count<>1 OR n.resume_request->'receivingProof' IS DISTINCT FROM proofs[1] THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 -- Run again at the actual end boundary, including after the private claim scan.
 PERFORM * FROM openpc.lock_discovery_certificate_recovery_source(fresh.enrollment_id,fresh.recovery_id);
 IF NOT openpc.platform_recovery_envelope_current(n.maker_authority_envelope_id)
  OR proof_deadline<=clock_timestamp() OR fresh.valid_until<=clock_timestamp() OR n.expires_at<=clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM control.session s WHERE s.participant_id=n.participant_id AND s.session_id=n.maker_session_id
    AND s.principal_id=n.maker_principal_id AND s.state='ACTIVE' AND s.authority_epoch=n.maker_principal_epoch
    AND s.session_epoch=n.maker_session_epoch AND s.participant_epoch=n.maker_participant_epoch
    AND s.delegation_epoch=n.maker_delegation_epoch AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp())
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_discovery_preapproval_continuation(control.mutation_candidate) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.enforce_mutation_resume()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE old_attempt control.mutation_candidate%ROWTYPE; prior control.approval_request%ROWTYPE;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF row(NEW.predecessor_candidate_id,NEW.predecessor_approval_id,NEW.resume_operation_id,NEW.resume_request,NEW.attempt)
    IS DISTINCT FROM row(OLD.predecessor_candidate_id,OLD.predecessor_approval_id,OLD.resume_operation_id,OLD.resume_request,OLD.attempt)
   OR EXISTS (SELECT 1 FROM control.mutation_candidate s WHERE s.predecessor_candidate_id=OLD.mutation_candidate_id)
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.predecessor_candidate_id IS NULL THEN
  IF NEW.resume_request IS NOT NULL THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT old_attempt FROM control.mutation_candidate
  WHERE mutation_candidate_id=NEW.predecessor_candidate_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM control.authority_envelope e JOIN control.platform_recovery_case c
  ON c.participant_id=e.participant_id AND c.recovery_id=e.recovery_case_id
  WHERE e.participant_id=NEW.participant_id AND e.authority_envelope_id=NEW.maker_authority_envelope_id
   AND e.representation='RECOVERY_V1' AND c.intent ? 'continuation')
  AND NOT (NEW.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE' AND NEW.resume_request ? 'platformReceivingProof')
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF NEW.resume_request->>'command'='DISCOVERY_PREAPPROVAL_CONTINUE' THEN
  PERFORM openpc.assert_discovery_preapproval_continuation(NEW);
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT prior FROM control.approval_request
  WHERE approval_request_id=NEW.predecessor_approval_id FOR UPDATE;
 IF row(NEW.participant_id,NEW.privacy_domain_id,NEW.action_intent_id,NEW.catalog_operation_id,
        NEW.resource_type,NEW.operation_class,NEW.resource_id,NEW.candidate_digest,NEW.candidate_document,
        NEW.expected_revision,NEW.idempotency_key,NEW.maker_principal_id)
    IS DISTINCT FROM row(old_attempt.participant_id,old_attempt.privacy_domain_id,old_attempt.action_intent_id,
        old_attempt.catalog_operation_id,old_attempt.resource_type,old_attempt.operation_class,old_attempt.resource_id,
        old_attempt.candidate_digest,old_attempt.candidate_document,old_attempt.expected_revision,
        old_attempt.idempotency_key,old_attempt.maker_principal_id)
   OR NEW.attempt<>old_attempt.attempt+1 OR NEW.expires_at<=clock_timestamp()
   OR NEW.expires_at>clock_timestamp()+interval '30 minutes'
   OR prior.participant_id<>NEW.participant_id OR prior.privacy_domain_id<>NEW.privacy_domain_id
   OR prior.subject_type<>'CONFIGURATION_CANDIDATE' OR prior.subject_id<>old_attempt.mutation_candidate_id
   OR prior.subject_digest<>NEW.candidate_digest OR prior.subject_version<>NEW.expected_revision
   OR prior.maker_principal_id<>NEW.maker_principal_id OR prior.checker_principal_id IS NULL
   OR prior.checker_principal_id=NEW.maker_principal_id
   OR NOT EXISTS(SELECT 1 FROM control.principal checker WHERE checker.participant_id=NEW.participant_id
      AND checker.principal_id=prior.checker_principal_id AND checker.state='ACTIVE') OR prior.state NOT IN ('OPEN','APPROVED','EXPIRED')
   OR EXISTS (SELECT 1 FROM control.mutation_candidate s WHERE s.predecessor_candidate_id=old_attempt.mutation_candidate_id)
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 -- The database independently clips CREATE continuation to both original scope deadlines.
 IF NEW.catalog_operation_id='ID-OP-ENVELOPE-CREATE' AND NEW.expires_at>least(
    to_timestamp((old_attempt.candidate_document#>>'{usable,validUntilNs}')::numeric/1000000000),
    to_timestamp((old_attempt.candidate_document#>>'{grantable,validUntilNs}')::numeric/1000000000))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 -- A still-live approval cannot be replaced merely to obtain another authorization.
 IF NOT (NEW.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND NEW.resume_request ? 'discoveryReceivingProof')
  AND NOT (NEW.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE' AND NEW.resume_request ? 'platformReceivingProof')
  AND old_attempt.expires_at>clock_timestamp() AND prior.expires_at>clock_timestamp() AND
    (prior.state='OPEN' OR EXISTS (SELECT 1 FROM control.approval_decision_record d
      JOIN control.mfa_challenge m ON m.participant_id=d.participant_id AND m.mfa_challenge_id=d.mfa_challenge_id
      JOIN control.session proof_session ON proof_session.participant_id=m.participant_id
        AND proof_session.session_id=m.session_id AND proof_session.principal_id=m.principal_id
        AND proof_session.session_id=d.approver_session_id AND proof_session.session_epoch=d.approver_session_epoch
      WHERE d.participant_id=prior.participant_id AND d.privacy_domain_id=prior.privacy_domain_id
        AND d.approval_request_id=prior.approval_request_id AND d.decision='APPROVE'
        AND m.principal_id=d.approver_principal_id AND m.session_id=d.approver_session_id
        AND CASE WHEN proof_session.step_up_mfa_challenge_id IS NULL
          THEN m.consumed_at>clock_timestamp()-interval '5 minutes'
          ELSE proof_session.step_up_mfa_challenge_id=m.mfa_challenge_id
            AND openpc.session_step_up_valid_until(m.participant_id,m.session_id,m.principal_id)>clock_timestamp() END
        AND m.expires_at>clock_timestamp()))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF NEW.resume_request IS NULL OR jsonb_typeof(NEW.resume_request)<>'object' OR NEW.resume_request->>'command' IS DISTINCT FROM 'RESUME'
    OR NEW.resume_request->>'actionIntentId' IS DISTINCT FROM 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
    OR NEW.resume_request->>'approvalRequestId' IS DISTINCT FROM 'urn:openpc:resource:'||prior.approval_request_id::text
    OR NEW.resume_request->>'expectedRevision' IS DISTINCT FROM prior.row_version::text
    OR NEW.resume_request->>'expectedAttempt' IS DISTINCT FROM old_attempt.attempt::text
    OR NEW.resume_request->>'predecessorCandidateId' IS DISTINCT FROM old_attempt.mutation_candidate_id::text
    OR NEW.resume_request->>'candidateDigest' IS DISTINCT FROM 'sha256:'||encode(old_attempt.candidate_digest,'hex')
    OR NOT EXISTS (SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=NEW.participant_id
      AND r.privacy_domain_id=NEW.privacy_domain_id AND r.operation_id=NEW.resume_operation_id
      AND r.principal_id=NEW.maker_principal_id AND r.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
      AND r.catalog_operation_id='LEGACY' AND r.expected_aggregate_version=prior.row_version
      AND r.input_digest=sha256(convert_to(openpc.signing_canonical_json(CASE WHEN NEW.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'
       AND NEW.resume_request ? 'discoveryReceivingProof' THEN NEW.resume_request-'discoveryReceivingProof'
       WHEN NEW.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE' AND NEW.resume_request ? 'platformReceivingProof'
         THEN NEW.resume_request-'platformReceivingProof' ELSE NEW.resume_request END),'UTF8')))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF NEW.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND NEW.resume_request->>'command'='RESUME' THEN
  PERFORM openpc.assert_discovery_approval_resume(NEW);
 ELSIF NEW.resume_request ? 'platformReceivingProof' THEN
  PERFORM openpc.assert_platform_recovery_approval_resume(NEW);
 ELSE
  PERFORM openpc.assert_mutation_resume_no_effect(old_attempt.mutation_candidate_id);
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS mutation_candidate_resume ON control.mutation_candidate;
CREATE TRIGGER mutation_candidate_resume BEFORE INSERT OR UPDATE ON control.mutation_candidate
 FOR EACH ROW EXECUTE FUNCTION openpc.enforce_mutation_resume();

CREATE OR REPLACE FUNCTION openpc.require_completed_mutation_resume()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE stored control.mutation_candidate;
BEGIN
 IF NEW.resume_request->>'command'='DISCOVERY_PREAPPROVAL_CONTINUE' THEN
  PERFORM openpc.assert_discovery_preapproval_continuation(NEW);
  RETURN NULL;
 END IF;
 IF NEW.catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND NEW.resume_request->>'command'='RESUME' THEN
  PERFORM openpc.assert_discovery_approval_resume(NEW);
 END IF;
 IF NEW.resume_request ? 'platformReceivingProof' THEN
  SELECT * INTO STRICT stored FROM control.mutation_candidate WHERE mutation_candidate_id=NEW.mutation_candidate_id;
  PERFORM openpc.assert_platform_recovery_approval_resume(stored);
 END IF;
 IF NEW.predecessor_candidate_id IS NOT NULL AND NOT EXISTS (
   SELECT 1 FROM control.idempotency_record r JOIN control.approval_request a
    ON a.participant_id=r.participant_id AND a.privacy_domain_id=r.privacy_domain_id
    AND a.subject_id=NEW.mutation_candidate_id AND a.subject_type='CONFIGURATION_CANDIDATE'
   JOIN control.approval_request prior ON prior.approval_request_id=NEW.predecessor_approval_id
   WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
     AND r.operation_id=NEW.resume_operation_id AND r.terminal_state='COMMITTED'
     AND r.principal_id=NEW.maker_principal_id AND r.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
     AND r.catalog_operation_id='LEGACY' AND r.expected_aggregate_version=prior.row_version
     AND r.input_digest=sha256(convert_to(openpc.signing_canonical_json(CASE WHEN NEW.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'
       AND NEW.resume_request ? 'discoveryReceivingProof' THEN NEW.resume_request-'discoveryReceivingProof'
       WHEN NEW.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE' AND NEW.resume_request ? 'platformReceivingProof'
         THEN NEW.resume_request-'platformReceivingProof' ELSE NEW.resume_request END),'UTF8'))
     AND r.result_payload->>'resourceRef'='urn:openpc:resource:'||a.approval_request_id::text
     AND a.subject_digest=NEW.candidate_digest AND a.subject_version=NEW.expected_revision
     AND a.maker_principal_id=NEW.maker_principal_id AND a.checker_principal_id=prior.checker_principal_id
     AND a.state='OPEN' AND a.expires_at=NEW.expires_at
 ) THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS mutation_resume_completed ON control.mutation_candidate;
CREATE CONSTRAINT TRIGGER mutation_resume_completed AFTER INSERT ON control.mutation_candidate
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_completed_mutation_resume();
`;

export const mutationResumeGrantsSql = `GRANT EXECUTE ON FUNCTION openpc.assert_mutation_resume_no_effect(uuid)
 TO openpc_control_runtime, openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.assert_discovery_preapproval_continuation(control.mutation_candidate)
 TO openpc_control_runtime,openpc_control_platform_runtime;`;

export const discoveryPreapprovalFinalGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_discovery_preapproval_final()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.resume_request->>'command'='DISCOVERY_PREAPPROVAL_CONTINUE' THEN
  PERFORM openpc.assert_discovery_preapproval_continuation(NEW);
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_discovery_preapproval_final() FROM PUBLIC;
DROP TRIGGER IF EXISTS zz_discovery_preapproval_final ON control.mutation_candidate;
CREATE TRIGGER zz_discovery_preapproval_final AFTER INSERT ON control.mutation_candidate
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_preapproval_final();
DROP TRIGGER IF EXISTS zz_discovery_preapproval_final_completed ON control.mutation_candidate;
CREATE CONSTRAINT TRIGGER zz_discovery_preapproval_final_completed AFTER INSERT ON control.mutation_candidate
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_preapproval_final();
`;
