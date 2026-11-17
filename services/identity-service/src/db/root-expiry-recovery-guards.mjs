import { identityEnvelopeContext } from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';
import { platformScopeCommitGuardsSql } from './platform-scope-commit-guards.mjs';

/** Separate local installation authority; existing normal Root replacement and
 * signer-repair guards retain their lifetime and purpose restrictions. */
const rootExpiryRecoveryBaseSql = `
-- V2 observes the original consumed preparation and every current partial
-- administration/target fact. It does not change any of these rows.
CREATE OR REPLACE FUNCTION openpc.read_root_expiry_pending_witness(context_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE r control.platform_scope_replacement; root control.platform_context; current_scope bytea;
 current_digest bytea; evidence_digest bytea; readiness jsonb; effects jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' THEN RETURN NULL; END IF;
 SELECT * INTO STRICT root FROM control.platform_context p WHERE p.platform_context_id=context_id
  AND p.owner_participant_id=openpc.current_participant_id() AND p.state='ACTIVE';
 SELECT * INTO STRICT r FROM control.platform_scope_replacement p WHERE p.platform_context_id=context_id
  AND openpc.matches_participant(p.participant_id) AND openpc.matches_privacy(p.privacy_domain_id) AND p.state='WITHDRAWING';
 SELECT s.scope_cbor,s.admission_digest INTO STRICT current_scope,current_digest FROM (
  SELECT platform_context_id,platform_authority_epoch,scope_cbor,admission_digest FROM control.platform_envelope_scope
  UNION ALL SELECT platform_context_id,platform_authority_epoch,scope_cbor,admission_digest FROM control.platform_envelope_scope_successor
  UNION ALL SELECT platform_context_id,platform_authority_epoch,scope_cbor,admission_digest FROM control.root_expiry_recovery_scope
 ) s WHERE s.platform_context_id=context_id AND s.platform_authority_epoch=root.authority_epoch;
 IF r.row_version<>1 OR r.superseded_by IS NOT NULL OR r.commit_operation_id IS NOT NULL
  OR r.predecessor_epoch<>root.authority_epoch OR r.expected_root_revision<>root.row_version
  OR r.predecessor_digest<>current_digest OR r.candidate_digest<>sha256(convert_to(openpc.signing_canonical_json(r.candidate),'UTF8'))
  OR r.successor_digest<>sha256(r.successor_preimage)
  OR (openpc.business_cbor(current_scope)->>'4')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000000)
  OR r.candidate#>'{successorScope,runtime}' IS DISTINCT FROM openpc.platform_scope_document(current_scope)->'runtime'
  OR jsonb_array_length(r.candidate->'administrators')<>2
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(r.candidate->'administrators') a
    WHERE (a#>>'{usable,validUntilNs}')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000000)
      OR (a#>>'{grantable,validUntilNs}')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000000))
  OR jsonb_array_length(r.candidate->'affectedTargets')>128 THEN RETURN NULL; END IF;
 SELECT e.evidence_digest INTO STRICT evidence_digest FROM control.mutation_candidate m
 JOIN control.approval_request a ON a.participant_id=m.participant_id AND a.privacy_domain_id=m.privacy_domain_id
  AND a.approval_request_id=r.prepare_approval_id AND a.subject_type='CONFIGURATION_CANDIDATE'
  AND a.subject_id=m.mutation_candidate_id AND a.subject_digest=m.candidate_digest AND a.subject_version=m.expected_revision
  AND a.state='APPROVED' AND a.maker_principal_id=m.maker_principal_id AND a.checker_principal_id<>a.maker_principal_id
 JOIN control.mutation_evidence e ON e.participant_id=m.participant_id AND e.privacy_domain_id=m.privacy_domain_id
  AND e.operation_id=r.prepare_operation_id AND e.catalog_operation_id=m.catalog_operation_id AND e.action_intent_id=m.action_intent_id
  AND e.aggregate_type='platform-scope-replacement' AND e.aggregate_id=r.replacement_id AND e.candidate_digest=m.candidate_digest
  AND e.principal_id=m.maker_principal_id AND e.checker_principal_id=a.checker_principal_id AND e.approval_request_id=a.approval_request_id
  AND e.evidence_digest=sha256(e.evidence_cbor) AND octet_length(e.cose_sign1)>0
  AND e.mfa_challenge_id IS NOT NULL AND e.webauthn_assertion_binding_digest IS NOT NULL
 JOIN control.idempotency_record committed ON committed.participant_id=e.participant_id AND committed.privacy_domain_id=e.privacy_domain_id
  AND committed.operation_id=e.operation_id AND committed.terminal_state='COMMITTED' AND committed.principal_id=e.principal_id
  AND committed.catalog_operation_id=e.catalog_operation_id AND committed.action_intent_id=e.action_intent_id
  AND committed.idempotency_key=m.idempotency_key AND committed.input_digest=m.candidate_digest
  AND committed.webauthn_assertion_binding_digest=e.webauthn_assertion_binding_digest
  AND committed.result_payload->>'replacementId'=r.replacement_id::text
  AND committed.result_payload->>'successorDigest'='sha256:'||encode(r.successor_digest,'hex')
 WHERE m.participant_id=r.participant_id AND m.privacy_domain_id=r.privacy_domain_id
  AND m.mutation_candidate_id=r.prepare_candidate_id AND m.candidate_document=r.candidate AND m.candidate_digest=r.candidate_digest
  AND m.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' AND m.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  AND m.resource_id=r.replacement_id AND m.expected_revision=0 AND m.state='CONSUMED' AND m.consumed_operation_id=r.prepare_operation_id
  AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=e.participant_id AND event.privacy_domain_id=e.privacy_domain_id
    AND event.aggregate_type=e.aggregate_type AND event.aggregate_id=e.aggregate_id AND event.payload_cbor=e.evidence_cbor
    AND event.payload_digest=e.evidence_digest AND event.cose_sign1=e.cose_sign1);
 readiness:=openpc.read_platform_scope_replacement_readiness(r.replacement_id);
 IF jsonb_array_length(readiness->'targets')<>jsonb_array_length(r.candidate->'affectedTargets')
  OR (SELECT coalesce(jsonb_agg(q.source ORDER BY q.runtime_target_id),'[]') FROM control.platform_scope_target_withdrawal q
    WHERE q.replacement_id=r.replacement_id AND q.participant_id=r.participant_id AND q.privacy_domain_id=r.privacy_domain_id)
   IS DISTINCT FROM (SELECT coalesce(jsonb_agg(t ORDER BY t->>'targetId'),'[]') FROM jsonb_array_elements(r.candidate->'affectedTargets') t)
 THEN RETURN NULL; END IF;
 SELECT jsonb_agg(jsonb_build_object('plan',plan,'envelope',to_jsonb(e),'proposal',to_jsonb(p),
  'candidates',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.mutation_candidate_id),'[]') FROM control.mutation_candidate m
    WHERE m.participant_id=r.participant_id AND m.privacy_domain_id=r.privacy_domain_id AND m.resource_id=(plan->>'envelopeId')::uuid),
  'approvals',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.approval_request_id),'[]') FROM control.approval_request a
    JOIN control.mutation_candidate m ON m.participant_id=a.participant_id AND m.privacy_domain_id=a.privacy_domain_id
      AND m.mutation_candidate_id=a.subject_id AND a.subject_type='CONFIGURATION_CANDIDATE'
    WHERE m.participant_id=r.participant_id AND m.privacy_domain_id=r.privacy_domain_id AND m.resource_id=(plan->>'envelopeId')::uuid),
  'assignment',to_jsonb(a),'activations',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.operation_id),'[]')
    FROM control.identity_envelope_activation x WHERE x.participant_id=r.participant_id AND x.envelope_id=(plan->>'envelopeId')::uuid))
   ORDER BY plan->>'principalId') INTO effects
 FROM jsonb_array_elements(r.candidate->'administrators') plan
 LEFT JOIN control.authority_envelope e ON e.participant_id=r.participant_id AND e.authority_envelope_id=(plan->>'envelopeId')::uuid
 LEFT JOIN control.identity_envelope_proposal p ON p.participant_id=r.participant_id AND p.envelope_id=(plan->>'envelopeId')::uuid
 LEFT JOIN control.assignment a ON a.participant_id=r.participant_id AND a.assignment_id=(plan->>'assignmentId')::uuid;
 RETURN jsonb_build_object('schema','pc.identity.local-root-expiry-pending-witness','schemaVersion',1,
  'replacementId',r.replacement_id::text,'replacementRevision',r.row_version::text,'predecessorEpoch',r.predecessor_epoch::text,
  'expectedRootRevision',r.expected_root_revision::text,'predecessorDigest','sha256:'||encode(r.predecessor_digest,'hex'),
  'preparationCandidateId',r.prepare_candidate_id::text,'preparationOperationId',r.prepare_operation_id::text,
  'preparationApprovalId',r.prepare_approval_id::text,'preparationDigest','sha256:'||encode(r.candidate_digest,'hex'),
  'preparationReceiptDigest','sha256:'||encode(evidence_digest,'hex'),'successorDigest','sha256:'||encode(r.successor_digest,'hex'),
  'pendingRecordDigest','sha256:'||encode(openpc.platform_scope_pending_record_digest(r),'hex'),
  'administrationEffectsDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(effects),'UTF8')),'hex'),
  'affectedTargetCount',jsonb_array_length(r.candidate->'affectedTargets'),'readinessDigest',readiness->>'readinessDigest');
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR numeric_value_out_of_range THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.read_root_expiry_pending_witness(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_root_expiry_pending_witness(uuid) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.lock_root_expiry_pending_source(context_id uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE target uuid;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR NOT pg_try_advisory_xact_lock(hashtextextended('platform-scope-replacement:'||context_id::text,0))
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-PENDING'; END IF;
 PERFORM 1 FROM control.participant WHERE participant_id=openpc.current_participant_id() AND state='ACTIVE' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-PENDING'; END IF;
 PERFORM 1 FROM control.platform_context WHERE platform_context_id=context_id
  AND owner_participant_id=openpc.current_participant_id() AND state='ACTIVE' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-PENDING'; END IF;
 PERFORM 1 FROM control.platform_scope_replacement WHERE platform_context_id=context_id
  AND openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id) AND state='WITHDRAWING' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-PENDING'; END IF;
 FOR target IN SELECT q.runtime_target_id FROM control.platform_scope_target_withdrawal q JOIN control.platform_scope_replacement r
  ON r.replacement_id=q.replacement_id AND r.participant_id=q.participant_id AND r.privacy_domain_id=q.privacy_domain_id
  WHERE r.platform_context_id=context_id AND r.state='WITHDRAWING' ORDER BY q.runtime_target_id LOOP
  IF NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||openpc.current_participant_id()::text||':'||
    openpc.current_privacy_domain_id()::text||':'||target::text,0)) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  PERFORM 1 FROM control.runtime_target WHERE runtime_target_id=target AND openpc.matches_participant(participant_id)
    AND openpc.matches_privacy(privacy_domain_id) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-PENDING'; END IF;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_root_expiry_pending_source(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_root_expiry_pending_source(uuid) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.root_expiry_recovery_source_current(p_enrollment uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 RETURN current_setting('openpc.local_qa_runtime',true) IS NOT DISTINCT FROM '1'
 AND openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
 AND EXISTS(SELECT 1 FROM control.root_expiry_recovery_enrollment e
  JOIN control.root_expiry_recovery_trust t ON t.custody_trust_id=e.custody_trust_id AND t.participant_id=e.participant_id
   AND t.privacy_domain_id=e.privacy_domain_id AND t.document_digest=e.custody_trust_digest
   AND t.state='ACTIVE' AND t.row_version=1 AND t.valid_from<=e.valid_from AND t.valid_until>=e.valid_until
  JOIN control.platform_context p ON p.platform_context_id=e.platform_context_id AND p.owner_participant_id=e.participant_id
   AND p.state='ACTIVE' AND p.authority_epoch::text=e.document->>'rootEpoch' AND p.row_version::text=e.document->>'rootRevision'
  JOIN (SELECT platform_context_id,platform_authority_epoch,admission_digest,scope_cbor FROM control.platform_envelope_scope
   UNION ALL SELECT platform_context_id,platform_authority_epoch,admission_digest,scope_cbor FROM control.platform_envelope_scope_successor
   UNION ALL SELECT platform_context_id,platform_authority_epoch,admission_digest,scope_cbor FROM control.root_expiry_recovery_scope) s
   ON s.platform_context_id=p.platform_context_id AND s.platform_authority_epoch=p.authority_epoch
    AND 'sha256:'||encode(s.admission_digest,'hex')=e.document->>'rootDigest'
  JOIN control.operations_installation i ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id
   AND i.environment_id=e.document->>'installationEnvironmentId' AND i.installation_digest=e.document->>'installationDigest' AND i.state='ACTIVE'
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
   AND e.state='ACTIVE' AND e.row_version=1 AND e.valid_from<=clock_timestamp() AND e.valid_until>clock_timestamp()
   AND (e.document->>'successorValidFrom')::timestamptz>=greatest(e.created_at,t.created_at)-interval '30 seconds'
   AND e.document->>'schema'='pc.identity.local-root-expiry-recovery-enrollment'
   AND ((e.document->>'schemaVersion'='1' AND t.document->>'schemaVersion'='1' AND e.document->>'purpose'='pc.installation.local-root-expiry-recovery-custody.v1'
     AND NOT (e.document ? 'pending') AND NOT (t.document ? 'pending')
     AND NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.platform_context_id=p.platform_context_id AND r.state='WITHDRAWING'))
    OR (e.document->>'schemaVersion'='2' AND e.document->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'
      AND t.document->>'schemaVersion'='2' AND e.document->'pending'=t.document->'pending'
      AND e.document->'pending'=openpc.read_root_expiry_pending_witness(p.platform_context_id))
    OR (e.document->>'schemaVersion'='3' AND t.document->>'schemaVersion'='3'
      AND e.document->>'purpose'='pc.installation.local-root-expiry-pending-ancestry-custody.v3'
      AND e.document->'pending'=t.document->'pending' AND e.document->'rootAncestry'=t.document->'rootAncestry'
      AND jsonb_build_object('pending',e.document->'pending','rootAncestry',e.document->'rootAncestry')=
        openpc.read_root_expiry_pending_ancestry_witness(p.platform_context_id)))
   AND t.document->>'purpose'=e.document->>'purpose' AND t.document->>'profile'='LOCAL_QA' AND e.document->>'profile'='LOCAL_QA'
   AND i.installation#>>'{pins,profile}' IN ('local','development','test')
   AND e.document_digest=sha256(convert_to(openpc.signing_canonical_json(e.document),'UTF8'))
   AND t.document_digest=sha256(convert_to(openpc.signing_canonical_json(t.document),'UTF8'))
   AND i.installation_bytes=convert_to(openpc.signing_canonical_json(i.installation),'UTF8')
   AND i.installation_digest='sha256:'||encode(sha256(i.installation_bytes),'hex')
   AND openpc.operations_source_authentication_valid(i.installation)
   AND (openpc.business_cbor(s.scope_cbor)->>'4')::numeric<=floor(extract(epoch from clock_timestamp())*1000000000)
  );
END $$;
REVOKE ALL ON FUNCTION openpc.root_expiry_recovery_source_current(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.root_expiry_recovery_source_current(uuid) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;

-- Runtime callers never receive installation documents or an installation-table grant.
DROP FUNCTION IF EXISTS openpc.read_root_expiry_recovery_source(uuid);
CREATE OR REPLACE FUNCTION openpc.read_root_expiry_recovery_source(p_enrollment uuid)
RETURNS TABLE(root_revision numeric,participant_epoch numeric,server_now timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.root_expiry_recovery_source_current(p_enrollment) IS DISTINCT FROM TRUE
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 RETURN QUERY SELECT p.row_version,participant.authority_epoch,clock_timestamp()
  FROM control.root_expiry_recovery_enrollment e
  JOIN control.platform_context p ON p.platform_context_id=e.platform_context_id AND p.owner_participant_id=e.participant_id
  JOIN control.participant participant ON participant.participant_id=e.participant_id
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id);
END $$;
REVOKE ALL ON FUNCTION openpc.read_root_expiry_recovery_source(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_root_expiry_recovery_source(uuid) TO openpc_control_runtime,openpc_control_platform_runtime;

-- Neutral receiving facts retain invoker FORCE RLS and the authenticated
-- installation/current expired Root/original consumed pending closure. They
-- must not consume the administration assignment/effect/readiness witness:
-- that witness itself reads assignments through this policy. The complete
-- witness remains mandatory in installation and every effect-consuming
-- ceremony/activation through root_expiry_recovery_source_current.
CREATE OR REPLACE FUNCTION openpc.root_expiry_recovery_installation_source_current(p_enrollment uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_user<>'openpc_control_owner' THEN RETURN FALSE; END IF;
 -- A failed prerequisite denies before planning the full witness. The complete
 -- original check below remains authoritative whenever this precheck passes.
 IF NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_enrollment e
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
   AND e.state='ACTIVE' AND e.row_version=1 AND e.valid_from<=clock_timestamp() AND e.valid_until>clock_timestamp()
   AND EXISTS(SELECT 1 FROM control.platform_context p
    WHERE p.platform_context_id=e.platform_context_id AND p.owner_participant_id=e.participant_id
     AND p.state='ACTIVE' AND p.authority_epoch::text=e.document->>'rootEpoch' AND p.row_version::text=e.document->>'rootRevision')) THEN RETURN FALSE; END IF;
 RETURN current_setting('openpc.local_qa_runtime',true) IS NOT DISTINCT FROM '1'
 AND openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
 AND EXISTS(SELECT 1 FROM control.root_expiry_recovery_enrollment e
  JOIN control.root_expiry_recovery_trust t ON t.custody_trust_id=e.custody_trust_id AND t.participant_id=e.participant_id
   AND t.privacy_domain_id=e.privacy_domain_id AND t.document_digest=e.custody_trust_digest
   AND t.state='ACTIVE' AND t.row_version=1 AND t.valid_from<=e.valid_from AND t.valid_until>=e.valid_until
  JOIN control.platform_context p ON p.platform_context_id=e.platform_context_id AND p.owner_participant_id=e.participant_id
   AND p.state='ACTIVE' AND p.authority_epoch::text=e.document->>'rootEpoch' AND p.row_version::text=e.document->>'rootRevision'
  JOIN (SELECT platform_context_id,platform_authority_epoch,admission_digest,scope_cbor FROM control.platform_envelope_scope
   UNION ALL SELECT platform_context_id,platform_authority_epoch,admission_digest,scope_cbor FROM control.platform_envelope_scope_successor
   UNION ALL SELECT platform_context_id,platform_authority_epoch,admission_digest,scope_cbor FROM control.root_expiry_recovery_scope) s
   ON s.platform_context_id=p.platform_context_id AND s.platform_authority_epoch=p.authority_epoch
    AND 'sha256:'||encode(s.admission_digest,'hex')=e.document->>'rootDigest'
  JOIN control.operations_installation i ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id
   AND i.environment_id=e.document->>'installationEnvironmentId' AND i.installation_digest=e.document->>'installationDigest' AND i.state='ACTIVE'
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
   AND e.state='ACTIVE' AND e.row_version=1 AND e.valid_from<=clock_timestamp() AND e.valid_until>clock_timestamp()
   AND (e.document->>'successorValidFrom')::timestamptz>=greatest(e.created_at,t.created_at)-interval '30 seconds'
   AND e.document->>'schema'='pc.identity.local-root-expiry-recovery-enrollment'
   AND ((e.document->>'schemaVersion'='1' AND t.document->>'schemaVersion'='1' AND e.document->>'purpose'='pc.installation.local-root-expiry-recovery-custody.v1'
     AND NOT (e.document ? 'pending') AND NOT (t.document ? 'pending')
     AND NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.platform_context_id=p.platform_context_id AND r.state='WITHDRAWING'))
    OR (e.document->>'schemaVersion'='2' AND e.document->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'
      AND t.document->>'schemaVersion'='2' AND e.document->'pending'=t.document->'pending'
      AND EXISTS(SELECT 1 FROM control.platform_scope_replacement pending
       JOIN control.mutation_evidence preparation ON preparation.participant_id=pending.participant_id
        AND preparation.privacy_domain_id=pending.privacy_domain_id AND preparation.operation_id=pending.prepare_operation_id
        AND preparation.aggregate_type='platform-scope-replacement' AND preparation.aggregate_id=pending.replacement_id
        AND preparation.candidate_digest=pending.candidate_digest AND preparation.evidence_digest=sha256(preparation.evidence_cbor)
        AND octet_length(preparation.cose_sign1)>0
       WHERE pending.platform_context_id=p.platform_context_id AND pending.participant_id=e.participant_id
        AND pending.privacy_domain_id=e.privacy_domain_id AND pending.state='WITHDRAWING' AND pending.row_version=1
        AND pending.superseded_by IS NULL AND num_nonnulls(pending.commit_operation_id,pending.commit_candidate_id,
          pending.commit_approval_id,pending.readiness_digest,pending.committed_at)=0
        AND pending.predecessor_epoch=p.authority_epoch AND pending.expected_root_revision=p.row_version
        AND pending.predecessor_digest=s.admission_digest
        AND pending.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(pending.candidate),'UTF8'))
        AND pending.successor_digest=sha256(pending.successor_preimage)
        AND pending.candidate#>'{successorScope,runtime}'=openpc.platform_scope_document(s.scope_cbor)->'runtime'
        AND jsonb_array_length(pending.candidate->'administrators')=2
        AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(pending.candidate->'administrators') administrator
          WHERE (administrator#>>'{usable,validUntilNs}')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000000)
           OR (administrator#>>'{grantable,validUntilNs}')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000000))
        AND e.document#>>'{pending,replacementId}'=pending.replacement_id::text
        AND e.document#>>'{pending,replacementRevision}'=pending.row_version::text
        AND e.document#>>'{pending,predecessorEpoch}'=pending.predecessor_epoch::text
        AND e.document#>>'{pending,expectedRootRevision}'=pending.expected_root_revision::text
        AND e.document#>>'{pending,predecessorDigest}'='sha256:'||encode(pending.predecessor_digest,'hex')
        AND e.document#>>'{pending,preparationCandidateId}'=pending.prepare_candidate_id::text
        AND e.document#>>'{pending,preparationOperationId}'=pending.prepare_operation_id::text
        AND e.document#>>'{pending,preparationApprovalId}'=pending.prepare_approval_id::text
        AND e.document#>>'{pending,preparationDigest}'='sha256:'||encode(pending.candidate_digest,'hex')
        AND e.document#>>'{pending,preparationReceiptDigest}'='sha256:'||encode(preparation.evidence_digest,'hex')
        AND e.document#>>'{pending,successorDigest}'='sha256:'||encode(pending.successor_digest,'hex')
        AND e.document#>>'{pending,pendingRecordDigest}'='sha256:'||encode(openpc.platform_scope_pending_record_digest(pending),'hex')
        AND (e.document#>>'{pending,affectedTargetCount}')::integer=jsonb_array_length(pending.candidate->'affectedTargets')))
    OR (e.document->>'schemaVersion'='3' AND t.document->>'schemaVersion'='3'
      AND e.document->>'purpose'='pc.installation.local-root-expiry-pending-ancestry-custody.v3'
      AND e.document->'pending'=t.document->'pending' AND e.document->'rootAncestry'=t.document->'rootAncestry'
      AND EXISTS(SELECT 1 FROM control.platform_scope_replacement pending
        WHERE pending.platform_context_id=p.platform_context_id AND pending.participant_id=e.participant_id
          AND pending.privacy_domain_id=e.privacy_domain_id
          AND pending.replacement_id::text=e.document#>>'{pending,replacementId}'
          AND e.document->'rootAncestry'=openpc.root_expiry_pending_ancestry(p.platform_context_id,to_jsonb(pending)))))
   AND t.document->>'purpose'=e.document->>'purpose' AND t.document->>'profile'='LOCAL_QA' AND e.document->>'profile'='LOCAL_QA'
   AND i.installation#>>'{pins,profile}' IN ('local','development','test')
   AND e.document_digest=sha256(convert_to(openpc.signing_canonical_json(e.document),'UTF8'))
   AND t.document_digest=sha256(convert_to(openpc.signing_canonical_json(t.document),'UTF8'))
   AND i.installation_bytes=convert_to(openpc.signing_canonical_json(i.installation),'UTF8')
   AND i.installation_digest='sha256:'||encode(sha256(i.installation_bytes),'hex')
   AND openpc.operations_source_authentication_valid(i.installation)
   AND (openpc.business_cbor(s.scope_cbor)->>'4')::numeric<=floor(extract(epoch from clock_timestamp())*1000000000)
  );
END $$;
REVOKE ALL ON FUNCTION openpc.root_expiry_recovery_installation_source_current(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.root_expiry_recovery_installation_source_current(uuid) TO openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.lock_root_expiry_recovery_enrollment(p_enrollment uuid)
RETURNS SETOF control.root_expiry_recovery_enrollment LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE source control.root_expiry_recovery_enrollment; declared record;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 PERFORM 1 FROM control.participant WHERE participant_id=openpc.current_participant_id() AND state='ACTIVE' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 PERFORM 1 FROM control.platform_context p JOIN control.root_expiry_recovery_enrollment e ON e.platform_context_id=p.platform_context_id
  AND e.participant_id=p.owner_participant_id WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id)
   AND openpc.matches_privacy(e.privacy_domain_id) AND p.state='ACTIVE' FOR UPDATE OF p;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 IF EXISTS(SELECT 1 FROM control.root_expiry_recovery_enrollment e WHERE e.enrollment_id=p_enrollment
   AND e.document->>'schemaVersion' IN ('2','3'))
   AND NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_case c WHERE c.enrollment_id=p_enrollment
     AND c.state='COMPLETED' AND openpc.matches_participant(c.participant_id) AND openpc.matches_privacy(c.privacy_domain_id)) THEN
  PERFORM openpc.lock_root_expiry_pending_source((SELECT e.platform_context_id FROM control.root_expiry_recovery_enrollment e WHERE e.enrollment_id=p_enrollment));
 END IF;
 SELECT * INTO STRICT source FROM control.root_expiry_recovery_enrollment e WHERE e.enrollment_id=p_enrollment
  AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id) FOR SHARE;
 -- Revocation must not race verification of the current or historical custody.
 -- Runtime callers have no UPDATE privilege on these installation tables.
 PERFORM 1 FROM control.root_expiry_recovery_trust t WHERE t.custody_trust_id=source.custody_trust_id
  AND t.participant_id=source.participant_id AND t.privacy_domain_id=source.privacy_domain_id
  AND t.document_digest=source.custody_trust_digest FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 IF source.document->>'schemaVersion'='3' THEN
  IF jsonb_typeof(source.document#>'{rootAncestry,receipts}') IS DISTINCT FROM 'array'
    OR jsonb_array_length(source.document#>'{rootAncestry,receipts}') NOT BETWEEN 1 AND 32
   THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
  FOR declared IN SELECT value FROM jsonb_array_elements(source.document#>'{rootAncestry,receipts}') LOOP
   PERFORM 1 FROM control.root_expiry_recovery_enrollment e
    JOIN control.root_expiry_recovery_trust t ON t.custody_trust_id=e.custody_trust_id
      AND t.participant_id=e.participant_id AND t.privacy_domain_id=e.privacy_domain_id
      AND t.document_digest=e.custody_trust_digest
    JOIN control.root_expiry_recovery_case c ON c.enrollment_id=e.enrollment_id
      AND c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
      AND c.enrollment_digest=e.document_digest AND c.state='COMPLETED'
    WHERE e.enrollment_id::text=declared.value->>'enrollmentId'
      AND c.recovery_id::text=declared.value->>'recoveryId' AND c.operation_id::text=declared.value->>'activationOperationId'
      AND e.participant_id=source.participant_id AND e.privacy_domain_id=source.privacy_domain_id
      AND e.platform_context_id=source.platform_context_id
      AND 'sha256:'||encode(e.document_digest,'hex')=declared.value->>'enrollmentDigest'
      AND 'sha256:'||encode(c.intent_digest,'hex')=declared.value->>'intentDigest'
      AND 'sha256:'||encode(c.evidence_digest,'hex')=declared.value->>'receiptDigest'
      AND e.state='ACTIVE' AND e.row_version=1 AND t.state='ACTIVE' AND t.row_version=1 FOR SHARE OF e,t;
   IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
  END LOOP;
 END IF;
 RETURN QUERY SELECT e.* FROM control.root_expiry_recovery_enrollment e WHERE e.enrollment_id=p_enrollment
  AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id) FOR SHARE OF e;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_root_expiry_recovery_enrollment(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_root_expiry_recovery_enrollment(uuid) TO openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.root_expiry_recovery_executor_has_grants(p_enrollment uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.root_expiry_recovery_enrollment e JOIN control.assignment a
  ON a.participant_id=e.participant_id AND a.principal_id::text=e.document#>>'{recoveryPrincipal,principalId}'
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
   AND a.state='ACTIVE' AND (upper_inf(a.valid_during) OR upper(a.valid_during)>clock_timestamp()))
$$;
REVOKE ALL ON FUNCTION openpc.root_expiry_recovery_executor_has_grants(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.root_expiry_recovery_executor_has_grants(uuid) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
CREATE OR REPLACE FUNCTION openpc.guard_root_expiry_recovery_installation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
DECLARE expected_schema text; record_id text;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR NEW.row_version<>OLD.row_version+1
   OR (to_jsonb(NEW)-ARRAY['state','row_version','revoked_at','revocation_reason_digest']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['state','row_version','revoked_at','revocation_reason_digest']) THEN
   RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
  NEW.revoked_at:=clock_timestamp();
  RETURN NEW;
 END IF;
 IF current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1' OR current_user<>'openpc_control_owner' OR NOT pg_has_role(session_user,'openpc_control_owner','MEMBER')
  OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY-INSTALLATION'; END IF;
 PERFORM openpc.assert_request_context(true);
 expected_schema:=CASE TG_TABLE_NAME
  WHEN 'root_expiry_recovery_trust' THEN 'pc.installation.local-root-expiry-recovery-receiving-trust'
  WHEN 'root_expiry_recovery_enrollment' THEN 'pc.identity.local-root-expiry-recovery-enrollment'
  ELSE NULL END;
 record_id:=CASE TG_TABLE_NAME
  WHEN 'root_expiry_recovery_trust' THEN to_jsonb(NEW)->>'custody_trust_id'
  ELSE to_jsonb(NEW)->>'enrollment_id' END;
 IF NEW.document->>'schemaVersion' IN ('2','3') THEN PERFORM openpc.lock_root_expiry_pending_source(NEW.platform_context_id); END IF;
 IF expected_schema IS NULL OR NEW.document->>'schema' IS DISTINCT FROM expected_schema
  OR NOT coalesce(((NEW.document->>'schemaVersion'='1'
      AND NEW.document->>'purpose'='pc.installation.local-root-expiry-recovery-custody.v1' AND NOT (NEW.document ? 'pending')
      AND NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.platform_context_id=NEW.platform_context_id AND r.state='WITHDRAWING'))
    OR (NEW.document->>'schemaVersion'='2'
      AND NEW.document->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'
      AND NEW.document->'pending'=openpc.read_root_expiry_pending_witness(NEW.platform_context_id))
    OR (NEW.document->>'schemaVersion'='3'
      AND NEW.document->>'purpose'='pc.installation.local-root-expiry-pending-ancestry-custody.v3'
      AND jsonb_build_object('pending',NEW.document->'pending','rootAncestry',NEW.document->'rootAncestry')=
        openpc.read_root_expiry_pending_ancestry_witness(NEW.platform_context_id))),false)
  OR NEW.document->>'profile' IS DISTINCT FROM 'LOCAL_QA'
  OR (NEW.document ? 'qaDurationProfile' AND (NEW.document->>'qaDurationProfile' IS DISTINCT FROM 'LOCAL_QA_10X'
      OR current_setting('openpc.local_qa_duration_profile',true) IS DISTINCT FROM 'LOCAL_QA_10X'))
  OR NEW.valid_until>NEW.valid_from+(CASE WHEN NEW.document->>'qaDurationProfile'='LOCAL_QA_10X' THEN interval '10 days' ELSE interval '1 day' END)
  OR NEW.state<>'ACTIVE' OR NEW.row_version<>1
  OR NEW.document_digest<>sha256(convert_to(openpc.signing_canonical_json(NEW.document),'UTF8'))
  OR NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id)
  OR NEW.document->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR NEW.document->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR NEW.document->>'platformContextId' IS DISTINCT FROM NEW.platform_context_id::text
  OR (NEW.document->>'validFrom')::timestamptz IS DISTINCT FROM NEW.valid_from
  OR (NEW.document->>'validUntil')::timestamptz IS DISTINCT FROM NEW.valid_until
  OR NEW.valid_from>clock_timestamp() OR NEW.valid_until<=clock_timestamp()
  OR (CASE WHEN TG_TABLE_NAME='root_expiry_recovery_trust'
    THEN NEW.document->>'custodyTrustId' ELSE NEW.document->>'enrollmentId' END) IS DISTINCT FROM record_id
  THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY-INSTALLATION'; END IF;
 IF TG_TABLE_NAME='root_expiry_recovery_enrollment' THEN
  IF NEW.document->>'custodyTrustId' IS DISTINCT FROM NEW.custody_trust_id::text
   OR NEW.document->>'custodyTrustDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.custody_trust_digest,'hex')
   OR NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_trust trust
    WHERE trust.custody_trust_id=NEW.custody_trust_id AND trust.participant_id=NEW.participant_id
     AND trust.privacy_domain_id=NEW.privacy_domain_id AND trust.document_digest=NEW.custody_trust_digest
     AND trust.document->'qaDurationProfile' IS NOT DISTINCT FROM NEW.document->'qaDurationProfile'
     AND trust.document->>'schemaVersion'=NEW.document->>'schemaVersion'
     AND trust.document->>'purpose'=NEW.document->>'purpose'
     AND trust.document->'pending' IS NOT DISTINCT FROM NEW.document->'pending'
     AND trust.document->'rootAncestry' IS NOT DISTINCT FROM NEW.document->'rootAncestry'
     AND trust.state='ACTIVE' AND trust.row_version=1 AND trust.valid_from<=NEW.valid_from AND trust.valid_until>=NEW.valid_until)
   THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY-CUSTODY'; END IF;
  IF (NEW.document->>'successorValidFrom')::timestamptz < clock_timestamp()-interval '30 seconds'
   OR NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_trust trust WHERE trust.custody_trust_id=NEW.custody_trust_id
    AND (NEW.document->>'successorValidFrom')::timestamptz>=trust.created_at-interval '30 seconds')
   THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY-INSTALLATION-TIME'; END IF;
 END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS root_expiry_recovery_trust_guard ON control.root_expiry_recovery_trust;
CREATE TRIGGER root_expiry_recovery_trust_guard BEFORE INSERT OR UPDATE OR DELETE ON control.root_expiry_recovery_trust
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_root_expiry_recovery_installation();
DROP TRIGGER IF EXISTS root_expiry_recovery_enrollment_guard ON control.root_expiry_recovery_enrollment;
CREATE TRIGGER root_expiry_recovery_enrollment_guard BEFORE INSERT OR UPDATE OR DELETE ON control.root_expiry_recovery_enrollment
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_root_expiry_recovery_installation();

-- Avoid compiling the RLS-expanded plan for this bounded proof check.
CREATE OR REPLACE FUNCTION openpc.root_expiry_recovery_proofs_current(p_case control.root_expiry_recovery_case,p_activation uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on SET jit=off AS $$
 SELECT p_case.enrollment_id IS NOT NULL
 AND openpc.matches_participant(p_case.participant_id) AND openpc.matches_privacy(p_case.privacy_domain_id)
 AND EXISTS(SELECT 1 FROM control.root_expiry_recovery_enrollment e
  WHERE e.enrollment_id=p_case.enrollment_id AND e.participant_id=p_case.participant_id
   AND e.privacy_domain_id=p_case.privacy_domain_id AND e.state='ACTIVE' AND e.row_version=p_case.enrollment_revision
   AND e.document_digest=p_case.enrollment_digest AND openpc.root_expiry_recovery_source_current(e.enrollment_id)
   AND jsonb_array_length(e.document->'custodians')=2
   AND (SELECT count(*) FROM control.root_expiry_recovery_proof proof WHERE proof.participant_id=e.participant_id
    AND proof.recovery_id=p_case.recovery_id)=4
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(
    jsonb_build_array(jsonb_build_object('signer',e.document->'recoveryPrincipal','phase','REQUEST'),
     jsonb_build_object('signer',e.document->'recoveryPrincipal','phase','ACTIVATE')) ||
     (SELECT jsonb_agg(jsonb_build_object('signer',custodian,'phase','APPROVE')) FROM jsonb_array_elements(e.document->'custodians') custodian)) required
    WHERE NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_proof proof
     JOIN control.root_expiry_recovery_challenge h ON h.participant_id=proof.participant_id AND h.recovery_id=proof.recovery_id
      AND h.challenge_id=proof.challenge_id AND h.proof_id=proof.proof_id AND h.consumed_at IS NOT NULL
     JOIN control.principal p ON p.participant_id=proof.participant_id AND p.principal_id=proof.principal_id
      AND p.state='ACTIVE' AND p.kind IN ('USER','PLATFORM_OPERATOR') AND p.authority_epoch=proof.principal_epoch
     JOIN control.credential c ON c.participant_id=p.participant_id AND c.principal_id=p.principal_id
      AND c.credential_id=proof.credential_id AND c.credential_epoch=proof.credential_epoch AND c.kind='WEBAUTHN' AND c.state='ACTIVE'
      AND c.valid_from<=clock_timestamp() AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
     JOIN control.session s ON s.participant_id=p.participant_id AND s.principal_id=p.principal_id
      AND s.session_id=proof.session_id AND s.session_epoch=proof.session_epoch AND s.authority_epoch=p.authority_epoch
      AND s.participant_epoch=(p_case.intent->>'sourceParticipantEpoch')::numeric AND s.state='ACTIVE'
      AND s.context_mode='PLATFORM' AND s.privacy_domain_id IS NULL
      AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
     WHERE proof.participant_id=p_case.participant_id AND proof.privacy_domain_id=p_case.privacy_domain_id
      AND proof.recovery_id=p_case.recovery_id AND proof.intent_digest=p_case.intent_digest
      AND proof.phase=required->>'phase' AND proof.principal_id::text=required#>>'{signer,principalId}'
      AND proof.credential_id::text=required#>>'{signer,credentialId}'
      AND proof.principal_epoch::text=required#>>'{signer,principalEpoch}' AND proof.credential_epoch::text=required#>>'{signer,credentialEpoch}'
      AND (proof.phase<>'ACTIVATE' OR proof.proof_id=p_activation)
      AND proof.verified_at>=p_case.valid_from AND proof.verified_at<=clock_timestamp()
      AND proof.verified_at>clock_timestamp()-make_interval(secs=>h.verified_proof_max_age_ms/1000.0)
      AND (h.verified_proof_max_age_ms=300000 OR (h.verified_proof_max_age_ms=3000000
        AND h.duration_profile='LOCAL_QA_10X' AND s.duration_profile='LOCAL_QA_10X' AND h.expires_at>clock_timestamp()))
      AND (e.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' OR EXISTS(SELECT 1 FROM control.hardware_authenticator hardware
        WHERE hardware.participant_id=c.participant_id AND hardware.principal_id=c.principal_id AND hardware.credential_id=c.credential_id))))
 );
$$;
REVOKE ALL ON FUNCTION openpc.root_expiry_recovery_proofs_current(control.root_expiry_recovery_case,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.root_expiry_recovery_proofs_current(control.root_expiry_recovery_case,uuid) TO openpc_control_runtime,openpc_control_platform_runtime;


CREATE OR REPLACE FUNCTION openpc.guard_root_expiry_recovery_case()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
DECLARE e control.root_expiry_recovery_enrollment;
BEGIN
 IF TG_OP='DELETE' OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1' THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.intent->>'qaDurationProfile'='LOCAL_QA_10X' AND
     current_setting('openpc.local_qa_duration_profile',true) IS DISTINCT FROM 'LOCAL_QA_10X' THEN
   RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
  IF NEW.state<>'DRAFT' OR NEW.row_version<>1 OR NEW.result IS NOT NULL OR NEW.operation_id IS NOT NULL THEN
   RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 ELSE
  IF NEW.row_version<>OLD.row_version+1 OR NEW.updated_at<=OLD.updated_at
   OR (to_jsonb(NEW)-ARRAY['state','row_version','updated_at','result','operation_id','evidence_cbor','evidence_digest','evidence_cose']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['state','row_version','updated_at','result','operation_id','evidence_cbor','evidence_digest','evidence_cose'])
   OR NOT ((OLD.state='DRAFT' AND NEW.state IN ('REQUESTED','REVOKED','EXPIRED')) OR
      (OLD.state='REQUESTED' AND NEW.state IN ('COMPLETED','REVOKED','EXPIRED')))
   THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 END IF;
 IF NEW.intent->>'schema' IS DISTINCT FROM 'pc.identity.local-root-expiry-recovery-intent'
   OR NOT coalesce(((NEW.intent->>'schemaVersion'='1' AND NEW.intent->>'purpose'='LOCAL_ROOT_EXPIRY_RECOVERY_ONLY'
      AND NOT (NEW.intent ? 'pending')) OR (NEW.intent->>'schemaVersion'='2'
      AND NEW.intent->>'purpose'='LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY' AND jsonb_typeof(NEW.intent->'pending')='object')
      OR (NEW.intent->>'schemaVersion'='3' AND NEW.intent->>'purpose'='LOCAL_ROOT_EXPIRY_PENDING_ANCESTRY_RECOVERY_ONLY'
        AND jsonb_typeof(NEW.intent->'pending')='object' AND jsonb_typeof(NEW.intent->'rootAncestry')='object')),false)
   OR NEW.intent_digest<>sha256(convert_to(openpc.signing_canonical_json(NEW.intent),'UTF8'))
   OR NEW.intent->>'recoveryId' IS DISTINCT FROM NEW.recovery_id::text OR NEW.intent->>'enrollmentId' IS DISTINCT FROM NEW.enrollment_id::text
   OR NEW.intent->>'enrollmentRevision' IS DISTINCT FROM NEW.enrollment_revision::text
   OR NEW.intent->>'enrollmentDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.enrollment_digest,'hex')
   OR (NEW.intent->>'validFrom')::timestamptz IS DISTINCT FROM NEW.valid_from OR (NEW.intent->>'validUntil')::timestamptz IS DISTINCT FROM NEW.valid_until
   THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 IF NEW.state IN ('DRAFT','REQUESTED') THEN
  SELECT * INTO e FROM control.root_expiry_recovery_enrollment WHERE enrollment_id=NEW.enrollment_id AND participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND row_version=NEW.enrollment_revision AND document_digest=NEW.enrollment_digest
   AND valid_until>=NEW.valid_until AND openpc.root_expiry_recovery_source_current(enrollment_id);
  IF NOT FOUND OR NEW.valid_until<=clock_timestamp()
   OR NEW.intent->'qaDurationProfile' IS DISTINCT FROM e.document->'qaDurationProfile'
   OR NEW.intent->>'schemaVersion' IS DISTINCT FROM e.document->>'schemaVersion'
   OR NEW.intent->'pending' IS DISTINCT FROM e.document->'pending'
   OR NEW.intent->'rootAncestry' IS DISTINCT FROM e.document->'rootAncestry'
   OR NEW.valid_until>NEW.valid_from+(CASE WHEN e.document->>'qaDurationProfile'='LOCAL_QA_10X' THEN interval '2 days' ELSE interval '15 minutes' END)
   -- Historical signed cases retain their original ceiling on continuation.
   OR (TG_OP='INSERT' AND e.document->>'qaDurationProfile'='LOCAL_QA_10X'
       AND NEW.valid_until>NEW.valid_from+interval '150 minutes')
   OR NEW.intent->>'predecessorEpoch' IS DISTINCT FROM e.document->>'rootEpoch'
   OR NEW.intent->>'predecessorRevision' IS DISTINCT FROM e.document->>'rootRevision'
   OR NEW.intent->>'predecessorDigest' IS DISTINCT FROM e.document->>'rootDigest'
   THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 END IF;
 IF NEW.state='REQUESTED' AND NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_proof p
  WHERE p.recovery_id=NEW.recovery_id AND p.participant_id=NEW.participant_id AND p.phase='REQUEST' AND p.intent_digest=NEW.intent_digest) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 IF NEW.state='COMPLETED' AND (current_user<>'openpc_control_owner' OR NEW.operation_id IS DISTINCT FROM openpc.current_operation_id()
  OR NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_scope s WHERE s.recovery_id=NEW.recovery_id
    AND s.owner_participant_id=NEW.participant_id AND s.installation_privacy_domain_id=NEW.privacy_domain_id
    AND s.activation_operation_id=NEW.operation_id AND s.intent_digest=NEW.intent_digest AND s.enrollment_digest=NEW.enrollment_digest)) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS root_expiry_case_guard ON control.root_expiry_recovery_case;
CREATE TRIGGER root_expiry_case_guard BEFORE INSERT OR UPDATE OR DELETE ON control.root_expiry_recovery_case
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_root_expiry_recovery_case();
CREATE OR REPLACE FUNCTION openpc.guard_root_expiry_recovery_challenge()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF TG_OP='UPDATE' AND (OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL OR NEW.proof_id IS NULL
   OR (to_jsonb(NEW)-ARRAY['consumed_at','proof_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['consumed_at','proof_id'])
   OR NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_proof p WHERE p.proof_id=NEW.proof_id AND p.challenge_id=NEW.challenge_id
    AND p.participant_id=NEW.participant_id AND p.privacy_domain_id=NEW.privacy_domain_id AND p.recovery_id=NEW.recovery_id)) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF TG_OP='INSERT' AND (NEW.consumed_at IS NOT NULL OR NEW.proof_id IS NOT NULL) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF TG_OP='INSERT' AND NEW.verified_proof_max_age_ms IS DISTINCT FROM
   (CASE WHEN NEW.duration_profile='LOCAL_QA_10X' THEN 3000000 ELSE 300000 END) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF TG_OP='INSERT' AND NEW.duration_profile='LOCAL_QA_10X' AND
  (current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
   OR current_setting('openpc.local_qa_duration_profile',true) IS DISTINCT FROM 'LOCAL_QA_10X'
   OR NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_case r
     WHERE r.recovery_id=NEW.recovery_id AND r.participant_id=NEW.participant_id
      AND r.privacy_domain_id=NEW.privacy_domain_id AND r.intent_digest=NEW.intent_digest
      AND r.intent->>'qaDurationProfile'='LOCAL_QA_10X' AND NEW.expires_at<=r.valid_until)
   OR NOT EXISTS(SELECT 1 FROM control.session s JOIN control.credential c
      ON c.participant_id=s.participant_id AND c.principal_id=s.principal_id AND c.credential_id=NEW.credential_id
     WHERE s.participant_id=NEW.participant_id AND s.principal_id=NEW.principal_id AND s.session_id=NEW.session_id
      AND s.session_epoch=NEW.session_epoch AND s.duration_profile='LOCAL_QA_10X' AND s.state='ACTIVE'
      AND NEW.expires_at<=s.idle_expires_at AND NEW.expires_at<=s.absolute_expires_at
      AND c.kind='WEBAUTHN' AND c.state='ACTIVE' AND c.valid_from<=clock_timestamp()
      AND (c.valid_until IS NULL OR NEW.expires_at<=c.valid_until))) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS root_expiry_recovery_challenge_guard ON control.root_expiry_recovery_challenge;
CREATE TRIGGER root_expiry_recovery_challenge_guard BEFORE INSERT OR UPDATE OR DELETE ON control.root_expiry_recovery_challenge
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_root_expiry_recovery_challenge();

CREATE OR REPLACE FUNCTION openpc.guard_root_expiry_recovery_proof()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_challenge c JOIN control.root_expiry_recovery_case r
   ON r.recovery_id=c.recovery_id AND r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id
  JOIN control.root_expiry_recovery_enrollment source ON source.enrollment_id=r.enrollment_id
   AND source.participant_id=r.participant_id AND source.privacy_domain_id=r.privacy_domain_id
   AND source.state='ACTIVE' AND source.row_version=r.enrollment_revision AND source.document_digest=r.enrollment_digest
   AND openpc.root_expiry_recovery_source_current(source.enrollment_id)
  JOIN LATERAL jsonb_array_elements(CASE WHEN NEW.phase='APPROVE' THEN source.document->'custodians'
    ELSE jsonb_build_array(source.document->'recoveryPrincipal') END) signer
   ON signer->>'principalId'=NEW.principal_id::text AND signer->>'credentialId'=NEW.credential_id::text
    AND signer->>'principalEpoch'=NEW.principal_epoch::text AND signer->>'credentialEpoch'=NEW.credential_epoch::text
  JOIN control.principal p ON p.participant_id=NEW.participant_id AND p.principal_id=NEW.principal_id
   AND p.state='ACTIVE' AND p.authority_epoch=NEW.principal_epoch
  JOIN control.credential credential ON credential.participant_id=p.participant_id AND credential.principal_id=p.principal_id
   AND credential.credential_id=NEW.credential_id AND credential.credential_epoch=NEW.credential_epoch
   AND credential.kind='WEBAUTHN' AND credential.state='ACTIVE' AND credential.valid_from<=clock_timestamp()
   AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
  JOIN control.session session ON session.participant_id=p.participant_id AND session.principal_id=p.principal_id
   AND session.session_id=NEW.session_id AND session.session_epoch=NEW.session_epoch AND session.authority_epoch=p.authority_epoch
   AND session.context_mode='PLATFORM' AND session.privacy_domain_id IS NULL AND session.state='ACTIVE'
   AND session.idle_expires_at>clock_timestamp() AND session.absolute_expires_at>clock_timestamp()
  JOIN control.participant participant ON participant.participant_id=p.participant_id AND participant.state='ACTIVE'
   AND participant.authority_epoch=session.participant_epoch
  WHERE c.challenge_id=NEW.challenge_id AND c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
   AND c.recovery_id=NEW.recovery_id AND c.principal_id=NEW.principal_id AND c.credential_id=NEW.credential_id
   AND c.session_id=NEW.session_id AND c.session_epoch=NEW.session_epoch AND c.phase=NEW.phase
   AND c.intent_digest=NEW.intent_digest AND r.intent_digest=NEW.intent_digest
   AND ((NEW.phase='REQUEST' AND r.state='DRAFT') OR (NEW.phase IN ('APPROVE','ACTIVATE') AND r.state='REQUESTED'))
   AND c.consumed_at IS NULL AND c.expires_at>clock_timestamp() AND r.valid_until>clock_timestamp()
   AND NEW.verified_at BETWEEN c.created_at AND clock_timestamp()
   AND source.valid_from<=clock_timestamp() AND source.valid_until>clock_timestamp()
   AND (source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' OR EXISTS(SELECT 1 FROM control.hardware_authenticator h
    WHERE h.participant_id=p.participant_id AND h.principal_id=p.principal_id AND h.credential_id=credential.credential_id))
   AND NEW.assertion_evidence#>>'{verified,version}'='OPENPC_VERIFIED_WEBAUTHN_ASSERTION_V1'
   AND NEW.assertion_evidence#>>'{verified,userVerification}'='REQUIRED_VERIFIED'
   AND NEW.assertion_evidence#>>'{verified,credentialId}'=credential.credential_id::text
   AND NEW.assertion_evidence#>>'{verified,credentialPublicKeyDigest}'='sha256:'||encode(credential.public_key_digest,'hex')
   AND NEW.assertion_evidence#>>'{verified,principalId}'=NEW.principal_id::text
   AND NEW.assertion_evidence#>>'{verified,sessionId}'=NEW.session_id::text
   AND NEW.assertion_evidence#>>'{verified,actionIntentId}'='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   AND NEW.assertion_evidence#>>'{verified,resourceDigest}'='sha256:'||encode(NEW.intent_digest,'hex')
   AND NEW.assertion_evidence#>>'{verified,challengeDigest}'='sha256:'||encode(c.challenge_digest,'hex')
   AND NEW.assertion_evidence#>>'{verified,origin}'=c.origin
   AND NEW.assertion_evidence#>>'{verified,signCount}'=NEW.authenticator_sign_count::text
   AND (NEW.assertion_evidence#>>'{verified,verifiedAt}')::timestamptz=NEW.verified_at) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF NEW.assertion_digest IS DISTINCT FROM sha256(convert_to(NEW.assertion_evidence#>>'{verified,version}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,credentialId}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,credentialPublicKeyDigest}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,principalId}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,sessionId}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,actionIntentId}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,resourceDigest}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,challengeDigest}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,rpIdHash}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,origin}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,authenticatorDataDigest}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,clientDataJsonDigest}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,signatureDigest}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,signCount}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,verifiedAt}','UTF8')||decode('00','hex')||convert_to(NEW.assertion_evidence#>>'{verified,userVerification}','UTF8')) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS root_expiry_recovery_proof_guard ON control.root_expiry_recovery_proof;
CREATE TRIGGER root_expiry_recovery_proof_guard BEFORE INSERT OR UPDATE OR DELETE ON control.root_expiry_recovery_proof
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_root_expiry_recovery_proof();

CREATE OR REPLACE FUNCTION openpc.commit_root_expiry_recovery(p_recovery uuid,p_activation uuid,p_scope bytea,p_preimage bytea,
 p_evidence bytea,p_digest bytea,p_cose bytea,p_result jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE c control.root_expiry_recovery_case; e control.root_expiry_recovery_enrollment; root control.platform_context;
 original_scope bytea; original_digest bytea; original jsonb; successor jsonb; base jsonb; expected jsonb; actual_result jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 PERFORM 1 FROM control.participant WHERE participant_id=openpc.current_participant_id() AND state='ACTIVE' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 SELECT * INTO STRICT c FROM control.root_expiry_recovery_case WHERE recovery_id=p_recovery
  AND openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id) FOR UPDATE;
 SELECT * INTO STRICT e FROM openpc.lock_root_expiry_recovery_enrollment(c.enrollment_id);
 SELECT * INTO STRICT root FROM control.platform_context WHERE platform_context_id=e.platform_context_id FOR UPDATE;
 IF c.state<>'REQUESTED' OR c.valid_until<=clock_timestamp() OR NOT openpc.root_expiry_recovery_source_current(e.enrollment_id)
  OR NOT openpc.root_expiry_recovery_proofs_current(c,p_activation) OR openpc.root_expiry_recovery_executor_has_grants(e.enrollment_id)
  OR root.authority_epoch::text<>c.intent->>'predecessorEpoch' OR root.row_version::text<>c.intent->>'predecessorRevision'
  OR p_digest IS DISTINCT FROM sha256(p_evidence) OR octet_length(p_cose)=0 THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 SELECT s.scope_cbor,s.admission_digest INTO STRICT original_scope,original_digest FROM (
  SELECT platform_context_id,platform_authority_epoch,scope_cbor,admission_digest FROM control.platform_envelope_scope
  UNION ALL SELECT platform_context_id,platform_authority_epoch,scope_cbor,admission_digest FROM control.platform_envelope_scope_successor
  UNION ALL SELECT platform_context_id,platform_authority_epoch,scope_cbor,admission_digest FROM control.root_expiry_recovery_scope
 ) s WHERE s.platform_context_id=root.platform_context_id AND s.platform_authority_epoch=root.authority_epoch;
 original:=openpc.business_cbor(original_scope); successor:=openpc.business_cbor(p_scope);
 IF NOT openpc.identity_envelope_scope_valid(p_scope) OR (successor-ARRAY['3','4']) IS DISTINCT FROM (original-ARRAY['3','4'])
  OR (original->>'4')::numeric>floor(extract(epoch from clock_timestamp())*1000000000)
  OR (successor->>'3')::numeric<(original->>'4')::numeric
  OR (successor->>'3')::numeric>floor(extract(epoch from clock_timestamp())*1000000000)
  OR (successor->>'4')::numeric<=floor(extract(epoch from clock_timestamp())*1000000000)
  OR (successor->>'4')::numeric-(successor->>'3')::numeric>((original->>'4')::numeric-(original->>'3')::numeric)*(CASE WHEN e.document->>'qaDurationProfile'='LOCAL_QA_10X' THEN 10 ELSE 1 END)
  OR (successor->>'4')::numeric-(successor->>'3')::numeric>86400000000000*(CASE WHEN e.document->>'qaDurationProfile'='LOCAL_QA_10X' THEN 10 ELSE 1 END)
  OR (successor->>'3')::numeric<>extract(epoch from (e.document->>'successorValidFrom')::timestamptz)*1000000000
  OR (successor->>'4')::numeric<>extract(epoch from (e.document->>'successorValidUntil')::timestamptz)*1000000000
  OR c.intent->'successorScope' IS DISTINCT FROM openpc.platform_scope_document(p_scope)
  OR 'sha256:'||encode(original_digest,'hex')<>c.intent->>'predecessorDigest'
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY-BOUNDS'; END IF;
 base:=jsonb_build_array('pc.identity.platform-envelope-scope.v1',24034,1,
  openpc.business_bytes(decode('${identityEnvelopeContext.definitionDigest.slice(7)}','hex')),
  openpc.business_uuid(root.platform_context_id),openpc.business_uuid(root.owner_participant_id),
  openpc.business_uuid(e.privacy_domain_id),root.authority_epoch+1,e.document->>'installationEnvironmentId',
  openpc.business_bytes(decode(substring(e.document->>'installationDigest' from 8),'hex')),openpc.business_bytes(p_scope));
 expected:=openpc.business_cbor(p_preimage);
 IF jsonb_typeof(expected) IS DISTINCT FROM 'array' OR jsonb_array_length(expected)<>9
  OR expected->>0 IS DISTINCT FROM 'pc.identity.platform-envelope-scope.local-expiry-recovery.v1' OR expected->>1 IS DISTINCT FROM '1'
  OR expected->2 IS DISTINCT FROM openpc.business_uuid(c.recovery_id)
  OR expected->3 IS DISTINCT FROM openpc.business_uuid(openpc.current_operation_id())
  OR expected->4 IS DISTINCT FROM openpc.business_bytes(c.enrollment_digest)
  OR expected->5 IS DISTINCT FROM openpc.business_bytes(c.intent_digest)
  OR expected->>6 IS DISTINCT FROM root.authority_epoch::text
  OR expected->7 IS DISTINCT FROM openpc.business_bytes(original_digest)
  OR openpc.business_cbor(decode(expected#>>'{8,bytes}','hex')) IS DISTINCT FROM base
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY-BYTES'; END IF;
 actual_result:=jsonb_build_object('rootEpoch',(root.authority_epoch+1)::text,'rootRevision',(root.row_version+1)::text,
  'rootDigest','sha256:'||encode(sha256(p_preimage),'hex'),'operationId',openpc.current_operation_id()::text);
 IF p_result IS DISTINCT FROM actual_result THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY-RESULT'; END IF;
 INSERT INTO control.root_expiry_recovery_scope(platform_context_id,platform_authority_epoch,recovery_id,activation_operation_id,
  enrollment_digest,intent_digest,predecessor_epoch,predecessor_digest,owner_participant_id,installation_privacy_domain_id,
  environment_id,installation_digest,scope_cbor,admission_preimage,admission_digest)
 VALUES(root.platform_context_id,root.authority_epoch+1,c.recovery_id,openpc.current_operation_id(),c.enrollment_digest,c.intent_digest,
  root.authority_epoch,original_digest,root.owner_participant_id,e.privacy_domain_id,e.document->>'installationEnvironmentId',e.document->>'installationDigest',
  p_scope,p_preimage,sha256(p_preimage));
 UPDATE control.platform_context SET authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp()
  WHERE platform_context_id=root.platform_context_id AND authority_epoch=root.authority_epoch AND row_version=root.row_version;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY-FENCE'; END IF;
 UPDATE control.root_expiry_recovery_case SET state='COMPLETED',row_version=row_version+1,updated_at=clock_timestamp(),
  result=actual_result,operation_id=openpc.current_operation_id(),evidence_cbor=p_evidence,evidence_digest=p_digest,evidence_cose=p_cose
 WHERE recovery_id=c.recovery_id AND state='REQUESTED';
 INSERT INTO control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence) VALUES(c.participant_id,'local-root-expiry-recovery',c.recovery_id,1);
 INSERT INTO control.outbox_event(participant_id,privacy_domain_id,aggregate_type,aggregate_id,aggregate_sequence,event_id,event_type,
  payload_cbor,payload_digest,cose_sign1,occurred_at) VALUES(c.participant_id,c.privacy_domain_id,'local-root-expiry-recovery',c.recovery_id,1,
  openpc.current_operation_id(),'openpc.identity.local-root-expiry-recovery.completed.v1',p_evidence,p_digest,p_cose,clock_timestamp());
 RETURN actual_result;
END $$;
REVOKE ALL ON FUNCTION openpc.commit_root_expiry_recovery(uuid,uuid,bytea,bytea,bytea,bytea,bytea,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.commit_root_expiry_recovery(uuid,uuid,bytea,bytea,bytea,bytea,bytea,jsonb) TO openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_root_expiry_recovery_scope()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP<>'INSERT' OR current_user<>'openpc_control_owner' OR NEW.activation_operation_id IS DISTINCT FROM openpc.current_operation_id()
 OR NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_case c JOIN control.root_expiry_recovery_enrollment e
  ON e.enrollment_id=c.enrollment_id AND e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
  JOIN control.platform_context p ON p.platform_context_id=e.platform_context_id AND p.owner_participant_id=e.participant_id
  WHERE c.recovery_id=NEW.recovery_id AND c.state='REQUESTED' AND c.intent_digest=NEW.intent_digest AND c.enrollment_digest=NEW.enrollment_digest
   AND p.authority_epoch=NEW.predecessor_epoch AND p.authority_epoch+1=NEW.platform_authority_epoch
   AND openpc.root_expiry_recovery_source_current(e.enrollment_id)
   AND openpc.root_expiry_recovery_proofs_current(c,(select proof_id from control.root_expiry_recovery_proof
     where recovery_id=c.recovery_id and participant_id=c.participant_id and phase='ACTIVATE'))
   AND NEW.predecessor_digest=decode(substring(c.intent->>'predecessorDigest' from 8),'hex')
   AND openpc.platform_scope_document(NEW.scope_cbor)=c.intent->'successorScope') THEN RAISE EXCEPTION 'PC-AUTH-0005-ROOT-EXPIRY-RECOVERY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS root_expiry_scope_guard ON control.root_expiry_recovery_scope;
CREATE TRIGGER root_expiry_scope_guard BEFORE INSERT OR UPDATE OR DELETE ON control.root_expiry_recovery_scope
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_root_expiry_recovery_scope();

-- Only the exact independent proof-backed successor admits the Root write.
DROP POLICY IF EXISTS root_expiry_context_commit ON control.platform_context;
CREATE POLICY root_expiry_context_commit ON control.platform_context FOR UPDATE TO openpc_control_owner
 USING(openpc.matches_participant(owner_participant_id) AND EXISTS(SELECT 1 FROM control.root_expiry_recovery_enrollment e
  WHERE e.platform_context_id=platform_context.platform_context_id AND e.participant_id=platform_context.owner_participant_id
   AND openpc.matches_privacy(e.privacy_domain_id) AND e.state='ACTIVE'))
 WITH CHECK(EXISTS(SELECT 1 FROM control.root_expiry_recovery_scope s JOIN control.root_expiry_recovery_case c
  ON c.recovery_id=s.recovery_id AND c.participant_id=s.owner_participant_id
  WHERE s.platform_context_id=platform_context.platform_context_id AND s.platform_authority_epoch=platform_context.authority_epoch
   AND s.owner_participant_id=platform_context.owner_participant_id AND c.state='REQUESTED'
   AND c.operation_id IS NULL AND s.activation_operation_id=openpc.current_operation_id()
   AND openpc.matches_participant(s.owner_participant_id) AND openpc.matches_privacy(s.installation_privacy_domain_id)));
DROP POLICY IF EXISTS root_expiry_outbox_head ON control.outbox_aggregate_head;
CREATE POLICY root_expiry_outbox_head ON control.outbox_aggregate_head FOR INSERT TO openpc_control_owner
 WITH CHECK(aggregate_type='local-root-expiry-recovery' AND last_sequence=1 AND openpc.matches_participant(participant_id)
  AND EXISTS(SELECT 1 FROM control.root_expiry_recovery_case c WHERE c.recovery_id=aggregate_id AND c.participant_id=outbox_aggregate_head.participant_id
   AND c.state='COMPLETED' AND c.operation_id=openpc.current_operation_id() AND openpc.matches_privacy(c.privacy_domain_id)));
DROP POLICY IF EXISTS root_expiry_outbox_event ON control.outbox_event;
CREATE POLICY root_expiry_outbox_event ON control.outbox_event FOR INSERT TO openpc_control_owner
 WITH CHECK(aggregate_type='local-root-expiry-recovery' AND aggregate_sequence=1 AND event_type='openpc.identity.local-root-expiry-recovery.completed.v1'
  AND event_id=openpc.current_operation_id() AND openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND EXISTS(SELECT 1 FROM control.root_expiry_recovery_case c WHERE c.recovery_id=aggregate_id AND c.participant_id=outbox_event.participant_id
   AND c.privacy_domain_id=outbox_event.privacy_domain_id AND c.state='COMPLETED' AND c.operation_id=openpc.current_operation_id()
   AND c.evidence_cbor=payload_cbor AND c.evidence_digest=payload_digest AND c.evidence_cose=cose_sign1));

CREATE OR REPLACE FUNCTION openpc.is_platform_recovery_executor(p_principal uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM (
  SELECT participant_id,document FROM control.platform_recovery_enrollment
  UNION ALL SELECT participant_id,document FROM control.identity_envelope_recovery_enrollment
  UNION ALL SELECT participant_id,document FROM control.root_expiry_recovery_enrollment
 ) e WHERE openpc.matches_participant(e.participant_id) AND e.document#>>'{recoveryPrincipal,principalId}'=p_principal::text)
$$;
REVOKE ALL ON FUNCTION openpc.is_platform_recovery_executor(uuid) FROM PUBLIC;

DROP TRIGGER IF EXISTS root_expiry_recovery_trust_truncate ON control.root_expiry_recovery_trust;
CREATE TRIGGER root_expiry_recovery_trust_truncate BEFORE TRUNCATE ON control.root_expiry_recovery_trust FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_mutation();

DROP TRIGGER IF EXISTS root_expiry_recovery_enrollment_truncate ON control.root_expiry_recovery_enrollment;
CREATE TRIGGER root_expiry_recovery_enrollment_truncate BEFORE TRUNCATE ON control.root_expiry_recovery_enrollment FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_mutation();

DROP TRIGGER IF EXISTS root_expiry_recovery_case_truncate ON control.root_expiry_recovery_case;
CREATE TRIGGER root_expiry_recovery_case_truncate BEFORE TRUNCATE ON control.root_expiry_recovery_case FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_mutation();

DROP TRIGGER IF EXISTS root_expiry_recovery_challenge_truncate ON control.root_expiry_recovery_challenge;
CREATE TRIGGER root_expiry_recovery_challenge_truncate BEFORE TRUNCATE ON control.root_expiry_recovery_challenge FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_mutation();

DROP TRIGGER IF EXISTS root_expiry_recovery_proof_truncate ON control.root_expiry_recovery_proof;
CREATE TRIGGER root_expiry_recovery_proof_truncate BEFORE TRUNCATE ON control.root_expiry_recovery_proof FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_mutation();

DROP TRIGGER IF EXISTS root_expiry_recovery_scope_truncate ON control.root_expiry_recovery_scope;
CREATE TRIGGER root_expiry_recovery_scope_truncate BEFORE TRUNCATE ON control.root_expiry_recovery_scope FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_mutation();
`;
export const rootExpiryAncestryPreambleSql = `
CREATE OR REPLACE FUNCTION openpc.root_expiry_pending_ancestry(context_id uuid,p_pending jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN RETURN NULL; END $$;
REVOKE ALL ON FUNCTION openpc.root_expiry_pending_ancestry(uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.root_expiry_pending_ancestry(uuid,jsonb) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;
const rootExpiryAncestryHeaderSql = `CREATE OR REPLACE FUNCTION openpc.root_expiry_pending_ancestry(context_id uuid,p_pending jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE pending control.platform_scope_replacement; root control.platform_context;
 scope control.root_expiry_recovery_scope; completed control.root_expiry_recovery_case;
 custody control.root_expiry_recovery_enrollment; trust control.root_expiry_recovery_trust;
 cursor_epoch numeric; cursor_revision numeric; cursor_digest bytea; previous_scope bytea; previous_digest bytea;
 installation record; link_row record; receipts jsonb:='[]'; visited uuid[]:=ARRAY[]::uuid[]; depth integer:=0; declared record; prefix jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR p_pending IS NULL OR jsonb_typeof(p_pending)<>'object' THEN RETURN NULL; END IF;
 pending:=jsonb_populate_record(NULL::control.platform_scope_replacement,p_pending);
 IF to_jsonb(pending) IS DISTINCT FROM p_pending OR NOT openpc.matches_participant(pending.participant_id)
  OR NOT openpc.matches_privacy(pending.privacy_domain_id) OR pending.platform_context_id<>context_id
  OR pending.state<>'WITHDRAWING' OR pending.row_version<>1 OR pending.superseded_by IS NOT NULL
  OR num_nonnulls(pending.commit_operation_id,pending.commit_candidate_id,pending.commit_approval_id,pending.readiness_digest,pending.committed_at)<>0
  OR pending.candidate_digest<>sha256(convert_to(openpc.signing_canonical_json(pending.candidate),'UTF8'))
  OR pending.successor_digest<>sha256(pending.successor_preimage) THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement actual WHERE actual.replacement_id=pending.replacement_id
  AND actual.participant_id=pending.participant_id AND actual.privacy_domain_id=pending.privacy_domain_id AND to_jsonb(actual)=p_pending)
 THEN RETURN NULL; END IF;
 SELECT * INTO STRICT root FROM control.platform_context p WHERE p.platform_context_id=context_id
  AND p.owner_participant_id=pending.participant_id AND p.state='ACTIVE';
 IF root.authority_epoch-pending.predecessor_epoch NOT BETWEEN 1 AND 32
  OR root.row_version-pending.expected_root_revision<>root.authority_epoch-pending.predecessor_epoch THEN RETURN NULL; END IF;
 SELECT i.installation_digest,i.environment_id INTO STRICT installation FROM control.operations_installation i
  WHERE i.participant_id=pending.participant_id AND i.privacy_domain_id=pending.privacy_domain_id AND i.state='ACTIVE'
   AND i.installation#>>'{pins,profile}' IN ('local','development','test')
   AND i.installation_bytes=convert_to(openpc.signing_canonical_json(i.installation),'UTF8')
   AND i.installation_digest='sha256:'||encode(sha256(i.installation_bytes),'hex')
   AND openpc.operations_source_authentication_valid(i.installation);
 SELECT s.admission_digest INTO STRICT cursor_digest FROM control.root_expiry_recovery_scope s
  WHERE s.platform_context_id=context_id AND s.owner_participant_id=pending.participant_id
   AND s.installation_privacy_domain_id=pending.privacy_domain_id AND s.platform_authority_epoch=root.authority_epoch;
 cursor_epoch:=root.authority_epoch;cursor_revision:=root.row_version;
 WHILE cursor_epoch>pending.predecessor_epoch LOOP
  depth:=depth+1;IF depth>32 THEN RETURN NULL; END IF;
  SELECT s AS scope,c AS completed,e AS custody,t AS trust INTO STRICT link_row FROM control.root_expiry_recovery_scope s
   JOIN control.root_expiry_recovery_case c ON c.recovery_id=s.recovery_id AND c.participant_id=s.owner_participant_id
    AND c.privacy_domain_id=s.installation_privacy_domain_id AND c.operation_id=s.activation_operation_id
    AND c.enrollment_digest=s.enrollment_digest AND c.intent_digest=s.intent_digest
   JOIN control.root_expiry_recovery_enrollment e ON e.enrollment_id=c.enrollment_id AND e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.document_digest=c.enrollment_digest AND e.row_version=c.enrollment_revision
   JOIN control.root_expiry_recovery_trust t ON t.custody_trust_id=e.custody_trust_id AND t.participant_id=e.participant_id
    AND t.privacy_domain_id=e.privacy_domain_id AND t.document_digest=e.custody_trust_digest
   WHERE s.platform_context_id=context_id AND s.owner_participant_id=pending.participant_id
    AND s.installation_privacy_domain_id=pending.privacy_domain_id AND s.platform_authority_epoch=cursor_epoch;
  scope:=link_row.scope;completed:=link_row.completed;custody:=link_row.custody;trust:=link_row.trust;
  IF (completed.state<>'COMPLETED' OR scope.admission_digest<>cursor_digest OR scope.admission_digest<>sha256(scope.admission_preimage)
   OR scope.predecessor_epoch<>cursor_epoch-1 OR scope.environment_id<>installation.environment_id OR scope.installation_digest<>installation.installation_digest
   OR custody.state<>'ACTIVE' OR custody.row_version<>1 OR trust.state<>'ACTIVE' OR trust.row_version<>1
   OR custody.platform_context_id<>context_id OR trust.platform_context_id<>context_id
   OR custody.document_digest<>sha256(convert_to(openpc.signing_canonical_json(custody.document),'UTF8'))
   OR trust.document_digest<>sha256(convert_to(openpc.signing_canonical_json(trust.document),'UTF8'))
   OR completed.intent_digest<>sha256(convert_to(openpc.signing_canonical_json(completed.intent),'UTF8'))
   OR completed.evidence_digest<>sha256(completed.evidence_cbor) OR octet_length(completed.evidence_cose)=0
   OR octet_length(custody.signature)<>64 OR custody.document->>'schemaVersion' IS DISTINCT FROM completed.intent->>'schemaVersion'
   OR custody.document->>'schemaVersion' IS DISTINCT FROM trust.document->>'schemaVersion'
   OR custody.document->>'purpose' IS DISTINCT FROM trust.document->>'purpose'
   OR custody.document->'pending' IS DISTINCT FROM trust.document->'pending'
   OR custody.document->'pending' IS DISTINCT FROM completed.intent->'pending'
   OR custody.document->>'rootEpoch' IS DISTINCT FROM scope.predecessor_epoch::text
   OR custody.document->>'rootRevision' IS DISTINCT FROM (cursor_revision-1)::text
   OR custody.document->>'rootDigest' IS DISTINCT FROM 'sha256:'||encode(scope.predecessor_digest,'hex')
   OR completed.intent->>'predecessorEpoch' IS DISTINCT FROM custody.document->>'rootEpoch'
   OR completed.intent->>'predecessorRevision' IS DISTINCT FROM custody.document->>'rootRevision'
   OR completed.intent->>'predecessorDigest' IS DISTINCT FROM custody.document->>'rootDigest'
   OR completed.intent->'successorScope' IS DISTINCT FROM openpc.platform_scope_document(scope.scope_cbor)
   OR custody.document->>'installationDigest' IS DISTINCT FROM installation.installation_digest
   OR custody.document->>'installationEnvironmentId' IS DISTINCT FROM installation.environment_id
   OR completed.result IS DISTINCT FROM jsonb_build_object('rootEpoch',cursor_epoch::text,'rootRevision',cursor_revision::text,
    'rootDigest','sha256:'||encode(scope.admission_digest,'hex'),'operationId',completed.operation_id::text)
   OR custody.document#>>'{pending,replacementId}' IS DISTINCT FROM pending.replacement_id::text
   OR custody.document#>>'{pending,replacementRevision}' IS DISTINCT FROM pending.row_version::text
   OR custody.document#>>'{pending,predecessorEpoch}' IS DISTINCT FROM pending.predecessor_epoch::text
   OR custody.document#>>'{pending,expectedRootRevision}' IS DISTINCT FROM pending.expected_root_revision::text
   OR custody.document#>>'{pending,predecessorDigest}' IS DISTINCT FROM 'sha256:'||encode(pending.predecessor_digest,'hex')
   OR custody.document#>>'{pending,preparationCandidateId}' IS DISTINCT FROM pending.prepare_candidate_id::text
   OR custody.document#>>'{pending,preparationOperationId}' IS DISTINCT FROM pending.prepare_operation_id::text
   OR custody.document#>>'{pending,preparationApprovalId}' IS DISTINCT FROM pending.prepare_approval_id::text
   OR custody.document#>>'{pending,preparationDigest}' IS DISTINCT FROM 'sha256:'||encode(pending.candidate_digest,'hex')
   OR custody.document#>>'{pending,successorDigest}' IS DISTINCT FROM 'sha256:'||encode(pending.successor_digest,'hex')
   OR custody.document#>>'{pending,pendingRecordDigest}' IS DISTINCT FROM 'sha256:'||encode(openpc.platform_scope_pending_record_digest(pending),'hex')
   OR (custody.document#>>'{pending,affectedTargetCount}')::integer<>jsonb_array_length(pending.candidate->'affectedTargets')
   OR completed.recovery_id=completed.operation_id OR completed.recovery_id=custody.enrollment_id OR completed.operation_id=custody.enrollment_id
   OR completed.recovery_id=ANY(visited) OR completed.operation_id=ANY(visited) OR custody.enrollment_id=ANY(visited)) IS DISTINCT FROM FALSE
   THEN RETURN NULL; END IF;
  IF cursor_epoch=pending.predecessor_epoch+1 THEN
   IF custody.document->>'schemaVersion'<>'2' OR custody.document->>'purpose'<>'pc.installation.local-root-expiry-pending-recovery-custody.v2'
    OR completed.intent->>'purpose'<>'LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY' THEN RETURN NULL; END IF;
  ELSE
   IF custody.document->>'schemaVersion'<>'3' OR custody.document->>'purpose'<>'pc.installation.local-root-expiry-pending-ancestry-custody.v3'
    OR completed.intent->>'purpose'<>'LOCAL_ROOT_EXPIRY_PENDING_ANCESTRY_RECOVERY_ONLY'
    OR custody.document->'rootAncestry' IS DISTINCT FROM trust.document->'rootAncestry'
    OR custody.document->'rootAncestry' IS DISTINCT FROM completed.intent->'rootAncestry' THEN RETURN NULL; END IF;
  END IF;
  SELECT s.scope_cbor,s.admission_digest INTO STRICT previous_scope,previous_digest FROM (
   SELECT platform_context_id,owner_participant_id,installation_privacy_domain_id,platform_authority_epoch,scope_cbor,admission_digest FROM control.platform_envelope_scope
   UNION ALL SELECT platform_context_id,owner_participant_id,installation_privacy_domain_id,platform_authority_epoch,scope_cbor,admission_digest FROM control.platform_envelope_scope_successor
   UNION ALL SELECT platform_context_id,owner_participant_id,installation_privacy_domain_id,platform_authority_epoch,scope_cbor,admission_digest FROM control.root_expiry_recovery_scope
  ) s WHERE s.platform_context_id=context_id AND s.owner_participant_id=pending.participant_id
   AND s.installation_privacy_domain_id=pending.privacy_domain_id AND s.platform_authority_epoch=scope.predecessor_epoch;
  IF previous_digest<>scope.predecessor_digest OR (openpc.platform_scope_document(previous_scope)-ARRAY['validFromNs','validUntilNs'])
    IS DISTINCT FROM (openpc.platform_scope_document(scope.scope_cbor)-ARRAY['validFromNs','validUntilNs']) THEN RETURN NULL; END IF;
  receipts:=jsonb_build_array(jsonb_build_object('enrollmentId',custody.enrollment_id::text,'recoveryId',completed.recovery_id::text,
   'activationOperationId',completed.operation_id::text,'enrollmentDigest','sha256:'||encode(completed.enrollment_digest,'hex'),
   'intentDigest','sha256:'||encode(completed.intent_digest,'hex'),'receiptDigest','sha256:'||encode(completed.evidence_digest,'hex'),
   'predecessorEpoch',scope.predecessor_epoch::text,'predecessorRevision',(cursor_revision-1)::text,
   'predecessorDigest','sha256:'||encode(scope.predecessor_digest,'hex'),'rootEpoch',cursor_epoch::text,
   'rootRevision',cursor_revision::text,'rootDigest','sha256:'||encode(scope.admission_digest,'hex')))||receipts;
  visited:=visited||ARRAY[completed.recovery_id,completed.operation_id,custody.enrollment_id];
  cursor_epoch:=scope.predecessor_epoch;cursor_revision:=cursor_revision-1;cursor_digest:=scope.predecessor_digest;
 END LOOP;
 IF cursor_epoch<>pending.predecessor_epoch OR cursor_revision<>pending.expected_root_revision OR cursor_digest<>pending.predecessor_digest THEN RETURN NULL; END IF;
 FOR declared IN SELECT value,ordinality FROM jsonb_array_elements(receipts) WITH ORDINALITY LOOP
  IF declared.ordinality>1 THEN
   SELECT intent->'rootAncestry' INTO STRICT prefix FROM control.root_expiry_recovery_case c
    WHERE c.recovery_id=(declared.value->>'recoveryId')::uuid AND c.participant_id=pending.participant_id AND c.privacy_domain_id=pending.privacy_domain_id;
   IF prefix IS DISTINCT FROM jsonb_build_object('schema','pc.identity.local-root-expiry-pending-ancestry','schemaVersion',1,
    'rootEpoch',declared.value->>'predecessorEpoch','rootRevision',declared.value->>'predecessorRevision','rootDigest',declared.value->>'predecessorDigest',
    'receipts',(SELECT jsonb_agg(value ORDER BY ordinality) FROM jsonb_array_elements(receipts) WITH ORDINALITY WHERE ordinality<declared.ordinality))
   THEN RETURN NULL; END IF;
  END IF;
 END LOOP;
 RETURN jsonb_build_object('schema','pc.identity.local-root-expiry-pending-ancestry','schemaVersion',1,
  'rootEpoch',root.authority_epoch::text,'rootRevision',root.row_version::text,
  'rootDigest',receipts->(jsonb_array_length(receipts)-1)->>'rootDigest','receipts',receipts);
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.root_expiry_pending_ancestry(uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.root_expiry_pending_ancestry(uuid,jsonb) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;

function replacePendingWitnessBoundary(source, before, after) {
  if (source.split(before).length !== 2) throw new Error('Changed owning pending witness boundary');
  return source.replace(before, after);
}
// Historical observation reuses the complete owning readiness body. The normal
// reader and commit retain their direct-predecessor admission and existing grants.
const rootExpiryAncestryReadinessSql = (() => {
  const marker =
    'CREATE OR REPLACE FUNCTION openpc.read_platform_scope_replacement_readiness(wanted uuid)';
  if (platformScopeCommitGuardsSql.split(marker).length !== 2)
    throw new Error('Changed owning readiness definition');
  const start = platformScopeCommitGuardsSql.indexOf(marker);
  const end = platformScopeCommitGuardsSql.indexOf('\nEND $$;', start);
  if (end < start) throw new Error('Missing owning readiness body');
  let own = platformScopeCommitGuardsSql.slice(start, end + 8);
  own = replacePendingWitnessBoundary(
    own,
    'openpc.read_platform_scope_replacement_readiness(wanted uuid)',
    'openpc.read_root_expiry_pending_ancestry_readiness(wanted uuid)',
  );
  own = replacePendingWitnessBoundary(
    own,
    "IF openpc.current_action_intent_id() NOT IN('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')",
    "IF current_user<>'openpc_control_owner' OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'\n  OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'",
  );
  own = replacePendingWitnessBoundary(
    own,
    `IF r.state<>'WITHDRAWING' OR r.row_version<>1 OR root.authority_epoch<>r.predecessor_epoch
  OR root.row_version<>r.expected_root_revision THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-PREDECESSOR'; END IF;`,
    `IF (r.state<>'WITHDRAWING' OR r.row_version<>1 OR r.superseded_by IS NOT NULL
  OR num_nonnulls(r.commit_operation_id,r.commit_candidate_id,r.commit_approval_id,r.readiness_digest,r.committed_at)<>0
  OR openpc.root_expiry_pending_ancestry(r.platform_context_id,to_jsonb(r)) IS NULL
  OR NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_scope head
    WHERE head.platform_context_id=r.platform_context_id AND head.owner_participant_id=r.participant_id
      AND head.installation_privacy_domain_id=r.privacy_domain_id AND head.platform_authority_epoch=root.authority_epoch
      AND (openpc.business_cbor(head.scope_cbor)->>'4')::numeric<=floor(extract(epoch FROM clock_timestamp())*1000000000)))
  IS DISTINCT FROM FALSE THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-PREDECESSOR'; END IF;`,
  );
  return (
    own +
    `\nREVOKE ALL ON FUNCTION openpc.read_root_expiry_pending_ancestry_readiness(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_root_expiry_pending_ancestry_readiness(uuid) TO openpc_control_owner;\n`
  );
})();
const rootExpiryAncestryWitnessSql = (() => {
  const start = rootExpiryRecoveryBaseSql.indexOf(
    'CREATE OR REPLACE FUNCTION openpc.read_root_expiry_pending_witness(context_id uuid)',
  );
  const end = rootExpiryRecoveryBaseSql.indexOf('\nEND $$;', start) + 8;
  if (start < 0 || end < 8) throw new Error('Missing owning pending witness');
  let own = rootExpiryRecoveryBaseSql.slice(start, end);
  own = replacePendingWitnessBoundary(
    own,
    'openpc.read_root_expiry_pending_witness(context_id uuid)',
    'openpc.read_root_expiry_pending_ancestry_witness(context_id uuid)',
  );
  own = replacePendingWitnessBoundary(
    own,
    'current_digest bytea; evidence_digest bytea; readiness jsonb; effects jsonb;',
    'current_digest bytea; evidence_digest bytea; readiness jsonb; effects jsonb; pending_witness jsonb; ancestry jsonb; declared record; historical_pending jsonb;',
  );
  own = replacePendingWitnessBoundary(
    own,
    's.platform_authority_epoch=root.authority_epoch;',
    's.platform_authority_epoch=r.predecessor_epoch;',
  );
  own = replacePendingWitnessBoundary(
    own,
    'readiness:=openpc.read_platform_scope_replacement_readiness(r.replacement_id);',
    'readiness:=openpc.read_root_expiry_pending_ancestry_readiness(r.replacement_id);',
  );
  own = replacePendingWitnessBoundary(
    own,
    `OR r.predecessor_epoch<>root.authority_epoch OR r.expected_root_revision<>root.row_version
  OR r.predecessor_digest<>current_digest`,
    `OR r.predecessor_digest<>current_digest
  OR openpc.root_expiry_pending_ancestry(context_id,to_jsonb(r)) IS NULL
  OR NOT EXISTS(SELECT 1 FROM control.root_expiry_recovery_scope head
    WHERE head.platform_context_id=context_id AND head.owner_participant_id=r.participant_id
      AND head.installation_privacy_domain_id=r.privacy_domain_id AND head.platform_authority_epoch=root.authority_epoch
      AND (openpc.business_cbor(head.scope_cbor)->>'4')::numeric<=floor(extract(epoch FROM clock_timestamp())*1000000000))`,
  );
  own = replacePendingWitnessBoundary(
    own,
    "RETURN jsonb_build_object('schema','pc.identity.local-root-expiry-pending-witness','schemaVersion',1,",
    "pending_witness:=jsonb_build_object('schema','pc.identity.local-root-expiry-pending-witness','schemaVersion',1,",
  );
  own = replacePendingWitnessBoundary(
    own,
    "'affectedTargetCount',jsonb_array_length(r.candidate->'affectedTargets'),'readinessDigest',readiness->>'readinessDigest');",
    `'affectedTargetCount',jsonb_array_length(r.candidate->'affectedTargets'),'readinessDigest',readiness->>'readinessDigest');
 ancestry:=openpc.root_expiry_pending_ancestry(context_id,to_jsonb(r));
 IF ancestry IS NULL THEN RETURN NULL; END IF;
 FOR declared IN SELECT value FROM jsonb_array_elements(ancestry->'receipts') LOOP
  SELECT intent->'pending' INTO STRICT historical_pending FROM control.root_expiry_recovery_case c
   WHERE c.recovery_id=(declared.value->>'recoveryId')::uuid AND c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id;
  IF (historical_pending-ARRAY['administrationEffectsDigest','readinessDigest']) IS DISTINCT FROM
    (pending_witness-ARRAY['administrationEffectsDigest','readinessDigest']) THEN RETURN NULL; END IF;
 END LOOP;
 RETURN jsonb_build_object('pending',pending_witness,'rootAncestry',ancestry);`,
  );
  return (
    own +
    `\nREVOKE ALL ON FUNCTION openpc.read_root_expiry_pending_ancestry_witness(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_root_expiry_pending_ancestry_witness(uuid) TO openpc_control_owner;\n`
  );
})();
export const rootExpiryRecoveryGuardsSql =
  rootExpiryAncestryHeaderSql +
  rootExpiryRecoveryBaseSql +
  rootExpiryAncestryReadinessSql +
  rootExpiryAncestryWitnessSql;

export const rootExpiryRecoveryGrantsSql = `
REVOKE ALL ON control.root_expiry_recovery_trust,control.root_expiry_recovery_enrollment,control.root_expiry_recovery_scope,
 control.root_expiry_recovery_case,control.root_expiry_recovery_challenge,control.root_expiry_recovery_proof FROM openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader;
GRANT SELECT ON control.root_expiry_recovery_trust,control.root_expiry_recovery_enrollment,control.root_expiry_recovery_scope,
 control.root_expiry_recovery_case,control.root_expiry_recovery_challenge,control.root_expiry_recovery_proof TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT,UPDATE ON control.root_expiry_recovery_case,control.root_expiry_recovery_challenge TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT ON control.root_expiry_recovery_proof TO openpc_control_runtime,openpc_control_platform_runtime;
`;
