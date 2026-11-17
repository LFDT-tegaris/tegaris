import {
  platformScopeCommitGuardsSql,
  platformScopeCommitGrantsSql,
} from './platform-scope-commit-guards.mjs';
import { identityEnvelopeContext } from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';

/** Project only a validated frozen Scope, so SQL can independently compare the
 * stored bytes with the exact JSON candidate approved by maker and checker. */
export const platformScopeReplacementGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.platform_scope_document_value(scope jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE dimensions jsonb; slice jsonb; slices jsonb:='{}'; dimension_values jsonb;
 module_id integer; dimension integer; label text; key text;
BEGIN
 FOR module_id IN 1..2 LOOP
  dimensions:=scope->module_id::text; slice:='{}';
  FOR dimension IN 1..7 LOOP
   key:=(ARRAY['participantIds','privacyDomainIds','resourceIds','dataClasses','targetProfileIds','riskClasses',
    CASE WHEN module_id=1 THEN 'actionIntentIds' ELSE 'capabilityIds' END])[dimension];
   IF dimension IN(1,2) THEN
    SELECT coalesce(jsonb_agg(to_jsonb((substr(v->>'bytes',1,8)||'-'||substr(v->>'bytes',9,4)||'-'||
      substr(v->>'bytes',13,4)||'-'||substr(v->>'bytes',17,4)||'-'||substr(v->>'bytes',21,12))::uuid::text)
      ORDER BY ordinal),'[]'::jsonb) INTO dimension_values
     FROM jsonb_array_elements(dimensions->dimension::text) WITH ORDINALITY a(v,ordinal);
   ELSE dimension_values:=dimensions->dimension::text; END IF;
   slice:=slice||jsonb_build_object(key,dimension_values);
  END LOOP;
  label:=CASE WHEN module_id=1 THEN 'administration' ELSE 'runtime' END;
  slices:=slices||jsonb_build_object(label,slice);
 END LOOP;
 RETURN slices||jsonb_build_object('validFromNs',scope->>'3','validUntilNs',scope->>'4',
  'makerCheckerRequired',(scope->>'5')='1','stepUpRequired',(scope->>'6')='1','onwardDelegationDepth',(scope->>'7')::integer);
END $$;
REVOKE ALL ON FUNCTION openpc.platform_scope_document_value(jsonb) FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.platform_scope_document(p_bytes bytea)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
BEGIN
 IF NOT openpc.identity_envelope_scope_valid(p_bytes) THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE'; END IF;
 RETURN openpc.platform_scope_document_value(openpc.business_cbor(p_bytes));
END $$;
REVOKE ALL ON FUNCTION openpc.platform_scope_document(bytea) FROM PUBLIC;

-- Complete conservative cohort within the installed finite runtime scope. An
-- unresolved original effect or in-flight activation blocks preparation.
CREATE OR REPLACE FUNCTION openpc.read_platform_scope_affected_targets(root_id uuid)
RETURNS TABLE(target jsonb) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE pid uuid; privacy uuid; root control.platform_context; missing integer;
BEGIN
 PERFORM openpc.assert_request_context(true);
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 IF root_id IS NULL OR openpc.current_action_intent_id() NOT IN('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-CONTEXT'; END IF;
 SELECT * INTO STRICT root FROM control.platform_context p
  WHERE p.platform_context_id=root_id AND p.owner_participant_id=pid AND p.state='ACTIVE' FOR SHARE;
 PERFORM 1 FROM control.platform_envelope_scope s WHERE s.platform_context_id=root_id
  AND s.owner_participant_id=pid AND s.installation_privacy_domain_id=privacy;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-CONTEXT'; END IF;
 IF EXISTS(SELECT 1 FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
   AND w.work_kind='RUNTIME_ACTIVATION' AND w.state IN('PENDING','LEASED','RECONCILING'))
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-WORK-PENDING'; END IF;
 SELECT count(*) INTO missing FROM control.runtime_target t
  WHERE t.participant_id=pid AND t.privacy_domain_id=privacy AND t.active_generation_digest IS NOT NULL
   AND NOT EXISTS(SELECT 1 FROM control.runtime_activation_observation o JOIN control.configuration_work w
    ON w.participant_id=o.participant_id AND w.privacy_domain_id=o.privacy_domain_id
      AND w.configuration_work_id=o.configuration_work_id AND w.execution_attempt_id=o.execution_attempt_id
      AND w.operation_id=o.operation_id AND w.runtime_target_id=o.runtime_target_id
      AND w.runtime_configuration_generation_id=o.runtime_configuration_generation_id
      AND w.generation_digest=o.generation_digest AND w.xds_version_digest=o.xds_version_digest
      AND w.state='COMPLETED' AND w.result_receipt_digest=o.activation_receipt_digest
    WHERE o.participant_id=pid AND o.privacy_domain_id=privacy AND o.runtime_target_id=t.runtime_target_id
      AND o.capsule_digest=t.active_generation_digest);
 IF missing<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-ORIGINAL-AMBIGUITY'; END IF;
 RETURN QUERY SELECT jsonb_build_object('participantId',pid::text,'privacyDomainId',privacy::text,
    'targetId',t.runtime_target_id::text,'expectedRevision',t.revision::text,
    'capsuleDigest',o.capsule_digest,'originalWorkId',o.configuration_work_id::text,
    'originalAttemptId',o.execution_attempt_id::text,'activationReceiptDigest',o.activation_receipt_digest)
  FROM control.runtime_target t JOIN control.runtime_activation_observation o
    ON o.participant_id=t.participant_id AND o.privacy_domain_id=t.privacy_domain_id
      AND o.runtime_target_id=t.runtime_target_id AND o.capsule_digest=t.active_generation_digest
  WHERE t.participant_id=pid AND t.privacy_domain_id=privacy AND t.active_generation_digest IS NOT NULL
  ORDER BY t.runtime_target_id;
END $$;
REVOKE ALL ON FUNCTION openpc.read_platform_scope_affected_targets(uuid) FROM PUBLIC;

-- The signed V2 receipt keeps this immutable original identity across exactly
-- one Root epoch. Normal preparation still creates and approves a new intent.
CREATE OR REPLACE FUNCTION openpc.platform_scope_pending_record_digest(r control.platform_scope_replacement)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object('candidate',r.candidate,
  'candidateDigest',encode(r.candidate_digest,'hex'),'successorScope',encode(r.successor_scope_cbor,'hex'),
  'successorPreimage',encode(r.successor_preimage,'hex'),'successorDigest',encode(r.successor_digest,'hex'),
  'state','WITHDRAWING','supersededBy',NULL,'commitOperationId',r.commit_operation_id,
  'commitCandidateId',r.commit_candidate_id,'commitApprovalId',r.commit_approval_id,'readinessDigest',encode(r.readiness_digest,'hex'))),'UTF8'))
$$;
REVOKE ALL ON FUNCTION openpc.platform_scope_pending_record_digest(control.platform_scope_replacement) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_scope_pending_record_digest(control.platform_scope_replacement) TO openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.platform_scope_pending_root_bridge_current(r control.platform_scope_replacement,
 next_epoch numeric,next_revision numeric,next_digest bytea)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF to_regclass('control.root_expiry_recovery_scope') IS NULL THEN RETURN false; END IF;
 IF current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR NOT openpc.matches_participant(r.participant_id) OR NOT openpc.matches_privacy(r.privacy_domain_id)
  OR NOT ((r.state='WITHDRAWING' AND r.row_version=1 AND r.superseded_by IS NULL)
    OR (r.state='SUPERSEDED' AND r.row_version=2 AND r.superseded_by IS NOT NULL))
  OR num_nonnulls(r.commit_operation_id,r.commit_candidate_id,r.commit_approval_id,r.readiness_digest,r.committed_at)<>0
 THEN RETURN false; END IF;
 RETURN EXISTS(SELECT 1 FROM control.root_expiry_recovery_scope s
 JOIN control.root_expiry_recovery_case c ON c.recovery_id=s.recovery_id AND c.participant_id=s.owner_participant_id
  AND c.privacy_domain_id=s.installation_privacy_domain_id AND c.state='COMPLETED' AND c.operation_id=s.activation_operation_id
  AND c.intent_digest=s.intent_digest AND c.enrollment_digest=s.enrollment_digest
  AND c.evidence_digest=sha256(c.evidence_cbor) AND octet_length(c.evidence_cose)>0
 JOIN control.root_expiry_recovery_enrollment e ON e.enrollment_id=c.enrollment_id AND e.participant_id=c.participant_id
  AND e.privacy_domain_id=c.privacy_domain_id AND e.document_digest=c.enrollment_digest AND e.row_version=c.enrollment_revision
  AND e.state='ACTIVE' AND e.document->>'schemaVersion'='2'
  AND e.document->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'
  AND e.document_digest=sha256(convert_to(openpc.signing_canonical_json(e.document),'UTF8'))
 JOIN control.root_expiry_recovery_trust t ON t.custody_trust_id=e.custody_trust_id AND t.document_digest=e.custody_trust_digest
  AND t.participant_id=e.participant_id AND t.privacy_domain_id=e.privacy_domain_id AND t.state='ACTIVE' AND t.row_version=1
  AND t.document->>'schemaVersion'='2' AND t.document->>'purpose'=e.document->>'purpose' AND t.document->'pending'=e.document->'pending'
 JOIN control.platform_context p ON p.platform_context_id=s.platform_context_id AND p.owner_participant_id=s.owner_participant_id
  AND p.state='ACTIVE' AND p.authority_epoch=s.platform_authority_epoch AND p.row_version=next_revision
 WHERE s.platform_context_id=r.platform_context_id AND s.owner_participant_id=r.participant_id AND s.installation_privacy_domain_id=r.privacy_domain_id
  AND s.platform_authority_epoch=next_epoch AND s.admission_digest=next_digest AND s.admission_digest=sha256(s.admission_preimage)
  AND s.predecessor_epoch=r.predecessor_epoch AND s.predecessor_digest=r.predecessor_digest AND next_epoch=r.predecessor_epoch+1
  AND next_revision=r.expected_root_revision+1 AND e.document->>'rootRevision'=r.expected_root_revision::text
  AND e.document->>'rootEpoch'=r.predecessor_epoch::text AND e.document->>'rootDigest'='sha256:'||encode(r.predecessor_digest,'hex')
  AND c.intent->>'schemaVersion'='2' AND c.intent->>'purpose'='LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY'
  AND c.intent->'pending'=e.document->'pending'
  AND c.intent_digest=sha256(convert_to(openpc.signing_canonical_json(c.intent),'UTF8'))
  AND e.document#>>'{pending,replacementId}'=r.replacement_id::text
  AND e.document#>>'{pending,replacementRevision}'='1'
  AND e.document#>>'{pending,predecessorEpoch}'=r.predecessor_epoch::text
  AND e.document#>>'{pending,expectedRootRevision}'=r.expected_root_revision::text
  AND e.document#>>'{pending,predecessorDigest}'='sha256:'||encode(r.predecessor_digest,'hex')
  AND e.document#>>'{pending,preparationCandidateId}'=r.prepare_candidate_id::text
  AND e.document#>>'{pending,preparationOperationId}'=r.prepare_operation_id::text
  AND e.document#>>'{pending,preparationApprovalId}'=r.prepare_approval_id::text
  AND e.document#>>'{pending,preparationDigest}'='sha256:'||encode(r.candidate_digest,'hex')
  AND e.document#>>'{pending,successorDigest}'='sha256:'||encode(r.successor_digest,'hex')
  AND e.document#>>'{pending,pendingRecordDigest}'='sha256:'||encode(openpc.platform_scope_pending_record_digest(r),'hex')
  AND (e.document#>>'{pending,affectedTargetCount}')::integer=jsonb_array_length(r.candidate->'affectedTargets')
  AND (SELECT count(*) FROM control.platform_scope_target_withdrawal q WHERE q.replacement_id=r.replacement_id
    AND q.participant_id=r.participant_id AND q.privacy_domain_id=r.privacy_domain_id)=jsonb_array_length(r.candidate->'affectedTargets')
  AND NOT EXISTS(SELECT 1 FROM control.platform_scope_target_withdrawal q WHERE q.replacement_id=r.replacement_id
    AND NOT (r.candidate->'affectedTargets' @> jsonb_build_array(q.source)))
  AND (SELECT count(*) FROM control.root_expiry_recovery_proof proof WHERE proof.recovery_id=c.recovery_id
    AND proof.participant_id=c.participant_id AND proof.privacy_domain_id=c.privacy_domain_id AND proof.intent_digest=c.intent_digest)=4
  AND c.result=jsonb_build_object('rootEpoch',next_epoch::text,'rootRevision',next_revision::text,
    'rootDigest','sha256:'||encode(next_digest,'hex'),'operationId',s.activation_operation_id::text)
  AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=c.participant_id AND event.privacy_domain_id=c.privacy_domain_id
    AND event.aggregate_type='local-root-expiry-recovery' AND event.aggregate_id=c.recovery_id AND event.aggregate_sequence=1
    AND event.event_id=c.operation_id AND event.event_type='openpc.identity.local-root-expiry-recovery.completed.v1'
    AND event.payload_cbor=c.evidence_cbor AND event.payload_digest=c.evidence_digest AND event.cose_sign1=c.evidence_cose));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION openpc.platform_scope_pending_root_bridge_current(control.platform_scope_replacement,numeric,numeric,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_scope_pending_root_bridge_current(control.platform_scope_replacement,numeric,numeric,bytea)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_platform_scope_replacement()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE root control.platform_context; initial control.platform_envelope_scope; base jsonb; expected jsonb; predecessor bytea; predecessor_scope bytea; current_scope jsonb; next_scope jsonb; dimension integer; readiness jsonb;
BEGIN
 IF TG_OP='DELETE' OR current_user<>'openpc_control_owner' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-OWNER'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id)
  OR openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-CONTEXT'; END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT root FROM control.platform_context p WHERE p.platform_context_id=NEW.platform_context_id FOR UPDATE;
  SELECT * INTO STRICT initial FROM control.platform_envelope_scope s WHERE s.platform_context_id=root.platform_context_id;
  SELECT s.admission_digest,s.scope_cbor INTO STRICT predecessor,predecessor_scope FROM (
    SELECT platform_context_id,platform_authority_epoch,admission_digest,scope_cbor FROM control.platform_envelope_scope
    UNION ALL
    SELECT s.platform_context_id,s.platform_authority_epoch,s.admission_digest,s.scope_cbor
      FROM control.platform_envelope_scope_successor s JOIN control.platform_scope_replacement r
        ON r.replacement_id=s.replacement_id AND r.state='COMMITTED'
    UNION ALL SELECT platform_context_id,platform_authority_epoch,admission_digest,scope_cbor FROM control.root_expiry_recovery_scope
   ) s WHERE s.platform_context_id=root.platform_context_id AND s.platform_authority_epoch=root.authority_epoch;
  IF coalesce((root.owner_participant_id<>NEW.participant_id OR initial.installation_privacy_domain_id<>NEW.privacy_domain_id
    OR root.state<>'ACTIVE' OR root.authority_epoch<>NEW.predecessor_epoch OR root.row_version<>NEW.expected_root_revision
    OR NEW.state<>'WITHDRAWING' OR NEW.row_version<>1 OR NEW.prepare_operation_id<>openpc.current_operation_id()
    OR NEW.candidate->>'replacementId'<>NEW.replacement_id::text
    OR NEW.candidate->>'platformContextId'<>NEW.platform_context_id::text
    OR NEW.candidate->>'predecessorEpoch'<>NEW.predecessor_epoch::text
    OR NEW.candidate->>'expectedRootRevision'<>NEW.expected_root_revision::text
    OR NEW.candidate->>'predecessorDigest'<>'sha256:'||encode(NEW.predecessor_digest,'hex')
    OR NEW.candidate->'successorScope' IS DISTINCT FROM openpc.platform_scope_document(NEW.successor_scope_cbor)
    OR NEW.predecessor_digest IS DISTINCT FROM predecessor),true)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-PREDECESSOR'; END IF;
  current_scope:=openpc.business_cbor(predecessor_scope); next_scope:=openpc.business_cbor(NEW.successor_scope_cbor);
  IF NOT coalesce(openpc.identity_envelope_scope_valid(NEW.successor_scope_cbor),false)
    OR coalesce(((next_scope->>'3')::numeric<(current_scope->>'3')::numeric
      OR (next_scope->>'4')::numeric>(current_scope->>'4')::numeric
      OR (next_scope->>'3')::numeric>extract(epoch from clock_timestamp())*1000000000
      OR (next_scope->>'4')::numeric<=extract(epoch from clock_timestamp())*1000000000
      OR next_scope->>'7'<>'0' OR next_scope=current_scope),true)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-BOUNDS'; END IF;
  FOR dimension IN 1..7 LOOP
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(next_scope->'2'->dimension::text) value
      WHERE NOT (current_scope->'2'->dimension::text @> jsonb_build_array(value)))
   THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RUNTIME-WIDENING'; END IF;
  END LOOP;
  IF (SELECT coalesce(jsonb_agg(entry ORDER BY entry->>'targetId'),'[]') FROM jsonb_array_elements(NEW.candidate->'affectedTargets') entry)
    IS DISTINCT FROM (SELECT coalesce(jsonb_agg(target ORDER BY target->>'targetId'),'[]')
      FROM openpc.read_platform_scope_affected_targets(NEW.platform_context_id))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-COHORT'; END IF;
  base:=jsonb_build_array('pc.identity.platform-envelope-scope.v1',24034,1,
    openpc.business_bytes(decode('${identityEnvelopeContext.definitionDigest.slice(7)}','hex')),
    openpc.business_uuid(root.platform_context_id),openpc.business_uuid(root.owner_participant_id),
    openpc.business_uuid(initial.installation_privacy_domain_id),NEW.predecessor_epoch+1,initial.environment_id,
    openpc.business_bytes(decode(substring(initial.installation_digest FROM 8),'hex')),
    openpc.business_bytes(NEW.successor_scope_cbor));
  expected:=openpc.business_cbor(NEW.successor_preimage);
  IF jsonb_typeof(expected) IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-PREIMAGE';
  END IF;
  IF coalesce((jsonb_array_length(expected)<>7
    OR expected->>0<>'pc.identity.platform-envelope-scope.successor.v1' OR expected->>1<>'1'
    OR expected->2 IS DISTINCT FROM openpc.business_uuid(NEW.replacement_id)
    OR expected->3 IS DISTINCT FROM openpc.business_uuid(NEW.prepare_operation_id)
    OR expected->>4<>NEW.predecessor_epoch::text
    OR expected->5 IS DISTINCT FROM openpc.business_bytes(NEW.predecessor_digest)
    OR openpc.business_cbor(decode(expected#>>'{6,bytes}','hex')) IS DISTINCT FROM base),true)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-PREIMAGE'; END IF;
 ELSIF NEW.state='SUPERSEDED' THEN
  -- Candidate visibility is bound to an inserted replacement by RLS. Validate
  -- its complete consumed provenance at the deferred boundary below, after
  -- both rows exist, without granting pre-insert candidate visibility.
  IF OLD.state<>'WITHDRAWING' OR OLD.row_version<>1 OR NEW.row_version<>2
    OR NEW.superseded_by IS NULL OR NEW.superseded_by=OLD.replacement_id
    OR EXISTS(SELECT 1 FROM jsonb_array_elements(OLD.candidate->'administrators') a
      WHERE greatest((a#>>'{usable,validUntilNs}')::numeric,(a#>>'{grantable,validUntilNs}')::numeric)
        >extract(epoch from clock_timestamp())*1000000000)
    OR (to_jsonb(NEW)-'state'-'row_version'-'superseded_by') IS DISTINCT FROM
       (to_jsonb(OLD)-'state'-'row_version'-'superseded_by')
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-SUPERSESSION'; END IF;
 ELSE
  readiness:=openpc.read_platform_scope_replacement_readiness(OLD.replacement_id);
  IF readiness->>'unacknowledgedTargets'<>'0' OR readiness->>'unpreparedAdministrators'<>'0'
    OR NEW.readiness_digest IS DISTINCT FROM decode(substring(readiness->>'readinessDigest' from 8),'hex')
    OR (readiness->>'sourceExpiresAtNs')::numeric<=(readiness->>'nowNs')::numeric
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-READINESS'; END IF;
  IF coalesce((OLD.state<>'WITHDRAWING' OR NEW.state<>'COMMITTED' OR NEW.row_version<>OLD.row_version+1
    OR NEW.commit_operation_id<>openpc.current_operation_id()
    OR (to_jsonb(NEW)-'state'-'row_version'-'commit_operation_id'-'commit_candidate_id'-'commit_approval_id'-'readiness_digest'-'committed_at')
      IS DISTINCT FROM (to_jsonb(OLD)-'state'-'row_version'-'commit_operation_id'-'commit_candidate_id'-'commit_approval_id'-'readiness_digest'-'committed_at')),true)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-HISTORY'; END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_platform_scope_replacement() FROM PUBLIC;
DROP TRIGGER IF EXISTS platform_scope_replacement_guard ON control.platform_scope_replacement;
CREATE TRIGGER platform_scope_replacement_guard BEFORE INSERT OR UPDATE OR DELETE ON control.platform_scope_replacement
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_scope_replacement();

CREATE OR REPLACE FUNCTION openpc.require_platform_scope_replacement_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE r control.platform_scope_replacement; phase text; operation uuid; candidate uuid; approval uuid; valid boolean;
BEGIN
 SELECT * INTO STRICT r FROM control.platform_scope_replacement WHERE replacement_id=NEW.replacement_id;
 IF TG_OP='UPDATE' AND NEW.state='SUPERSEDED' THEN
  -- Deferred: both rows and the successor's ordinary PREPARE provenance must
  -- commit together. The old intent, approvals and target evidence stay intact.
  IF NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement successor
    WHERE successor.replacement_id=r.superseded_by AND successor.participant_id=r.participant_id
      AND successor.privacy_domain_id=r.privacy_domain_id AND successor.platform_context_id=r.platform_context_id
      AND ((successor.predecessor_epoch=r.predecessor_epoch AND successor.expected_root_revision=r.expected_root_revision
        AND successor.predecessor_digest=r.predecessor_digest)
        OR openpc.platform_scope_pending_root_bridge_current(r,successor.predecessor_epoch,successor.expected_root_revision,successor.predecessor_digest))
      AND successor.prepare_operation_id=openpc.current_operation_id()
      AND successor.candidate->'supersedes'=jsonb_build_object('replacementId',r.replacement_id::text,
        'expectedRevision','1','successorDigest','sha256:'||encode(r.successor_digest,'hex')))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-SUPERSESSION-PROVENANCE'; END IF;
  RETURN NULL;
 END IF;
 phase:=CASE WHEN TG_OP='INSERT' THEN 'PREPARE' ELSE 'COMMIT' END;
 operation:=CASE WHEN phase='PREPARE' THEN r.prepare_operation_id ELSE r.commit_operation_id END;
 candidate:=CASE WHEN phase='PREPARE' THEN r.prepare_candidate_id ELSE r.commit_candidate_id END;
 approval:=CASE WHEN phase='PREPARE' THEN r.prepare_approval_id ELSE r.commit_approval_id END;
 SELECT EXISTS(SELECT 1 FROM control.mutation_candidate c
  JOIN control.approval_request a ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
    AND a.approval_request_id=approval AND a.subject_type='CONFIGURATION_CANDIDATE'
    AND a.subject_id=c.mutation_candidate_id AND a.subject_digest=c.candidate_digest
    AND a.subject_version=c.expected_revision AND a.state='APPROVED'
  JOIN control.mutation_evidence e ON e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
    AND e.operation_id=operation AND e.catalog_operation_id=c.catalog_operation_id
    AND e.aggregate_type='platform-scope-replacement' AND e.aggregate_id=r.replacement_id
    AND e.candidate_digest=c.candidate_digest AND e.approval_request_id=approval
    AND e.principal_id=c.maker_principal_id AND e.checker_principal_id<>e.principal_id
    AND e.mfa_challenge_id IS NOT NULL AND e.webauthn_assertion_binding_digest IS NOT NULL
  JOIN control.idempotency_record receipt ON receipt.participant_id=c.participant_id AND receipt.privacy_domain_id=c.privacy_domain_id
    AND receipt.operation_id=operation AND receipt.terminal_state='COMMITTED'
    AND receipt.result_payload->>'replacementId'=r.replacement_id::text
    AND receipt.result_payload->>'successorDigest'='sha256:'||encode(r.successor_digest,'hex')
  WHERE c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id
    AND c.mutation_candidate_id=candidate AND c.consumed_operation_id=operation AND c.state='CONSUMED'
    AND c.catalog_operation_id='ID-OP-PLATFORM-SCOPE-'||phase AND c.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
    AND c.resource_id=r.replacement_id AND c.expected_revision=CASE WHEN phase='PREPARE' THEN 0 ELSE 1 END
    AND ((phase='PREPARE' AND c.candidate_document=r.candidate AND c.candidate_digest=r.candidate_digest)
      OR (phase='COMMIT' AND c.candidate_document->>'readinessDigest'='sha256:'||encode(r.readiness_digest,'hex')
        AND c.candidate_document->>'successorDigest'='sha256:'||encode(r.successor_digest,'hex')
        AND c.candidate_document->>'predecessorEpoch'=r.predecessor_epoch::text
        AND c.candidate_document->>'expectedRootRevision'=r.expected_root_revision::text))) INTO valid;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-PROVENANCE'; END IF;
 IF phase='PREPARE' AND (
  (SELECT count(*) FROM control.platform_scope_target_withdrawal q WHERE q.replacement_id=r.replacement_id
    AND q.participant_id=r.participant_id AND q.privacy_domain_id=r.privacy_domain_id)<>jsonb_array_length(r.candidate->'affectedTargets')
  OR EXISTS(SELECT 1 FROM control.platform_scope_target_withdrawal q WHERE q.replacement_id=r.replacement_id
    AND NOT (r.candidate->'affectedTargets' @> jsonb_build_array(q.source))))
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-COHORT'; END IF;
 IF phase='COMMIT' AND NOT EXISTS(SELECT 1 FROM control.platform_context p
    JOIN control.platform_envelope_scope_successor s ON s.platform_context_id=p.platform_context_id
      AND s.platform_authority_epoch=p.authority_epoch AND s.replacement_id=r.replacement_id
    WHERE p.platform_context_id=r.platform_context_id AND p.owner_participant_id=r.participant_id AND p.state='ACTIVE'
      AND p.authority_epoch=r.predecessor_epoch+1 AND p.row_version=r.expected_root_revision+1)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-EFFECT'; END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.require_platform_scope_replacement_provenance() FROM PUBLIC;
DROP TRIGGER IF EXISTS platform_scope_replacement_provenance ON control.platform_scope_replacement;
CREATE CONSTRAINT TRIGGER platform_scope_replacement_provenance AFTER INSERT OR UPDATE ON control.platform_scope_replacement
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_platform_scope_replacement_provenance();

CREATE OR REPLACE FUNCTION openpc.guard_platform_scope_successor()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP<>'INSERT' OR current_user<>'openpc_control_owner'
  OR NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement r
    JOIN control.platform_envelope_scope initial ON initial.platform_context_id=r.platform_context_id
    WHERE r.replacement_id=NEW.replacement_id AND r.state='COMMITTED' AND r.row_version=2
      AND r.commit_operation_id=openpc.current_operation_id()
      AND r.platform_context_id=NEW.platform_context_id AND NEW.platform_authority_epoch=r.predecessor_epoch+1
      AND NEW.preparation_operation_id=r.prepare_operation_id AND NEW.predecessor_epoch=r.predecessor_epoch
      AND NEW.predecessor_digest=r.predecessor_digest
      AND r.participant_id=NEW.owner_participant_id AND r.privacy_domain_id=NEW.installation_privacy_domain_id
      AND NEW.scope_cbor=r.successor_scope_cbor AND NEW.admission_preimage=r.successor_preimage
      AND NEW.admission_digest=r.successor_digest AND NEW.environment_id=initial.environment_id
      AND NEW.installation_digest=initial.installation_digest)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-IMMUTABLE-PLATFORM-SUCCESSOR'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_platform_scope_successor() FROM PUBLIC;
DROP TRIGGER IF EXISTS platform_scope_successor_guard ON control.platform_envelope_scope_successor;
CREATE TRIGGER platform_scope_successor_guard BEFORE INSERT OR UPDATE OR DELETE ON control.platform_envelope_scope_successor
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_scope_successor();

CREATE OR REPLACE FUNCTION openpc.prepare_platform_scope_replacement(document jsonb,scope bytea,preimage bytea,candidate_id uuid,approval_id uuid)
RETURNS TABLE(replacement jsonb) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE inserted control.platform_scope_replacement; pending control.platform_scope_replacement; target_source jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-CONTEXT'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('platform-scope-replacement:'||(document->>'platformContextId'),0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM 1 FROM control.runtime_target t WHERE t.participant_id=openpc.current_participant_id()
   AND t.privacy_domain_id=openpc.current_privacy_domain_id() ORDER BY t.runtime_target_id FOR SHARE;
 -- Serialize the old/new pending boundary with commits, before changing either.
 PERFORM 1 FROM control.platform_context WHERE platform_context_id=(document->>'platformContextId')::uuid
  AND owner_participant_id=openpc.current_participant_id() FOR UPDATE;
 SELECT * INTO pending FROM control.platform_scope_replacement r
  WHERE r.platform_context_id=(document->>'platformContextId')::uuid AND r.state='WITHDRAWING' FOR UPDATE;
 IF pending.replacement_id IS NULL THEN
  IF document ? 'supersedes' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-SUPERSESSION'; END IF;
 ELSE
  IF document->'supersedes' IS DISTINCT FROM jsonb_build_object('replacementId',pending.replacement_id::text,
      'expectedRevision',pending.row_version::text,'successorDigest','sha256:'||encode(pending.successor_digest,'hex'))
    OR pending.participant_id<>openpc.current_participant_id() OR pending.privacy_domain_id<>openpc.current_privacy_domain_id()
    OR (((pending.predecessor_epoch::text IS DISTINCT FROM document->>'predecessorEpoch'
      OR pending.expected_root_revision::text IS DISTINCT FROM document->>'expectedRootRevision'
      OR 'sha256:'||encode(pending.predecessor_digest,'hex') IS DISTINCT FROM document->>'predecessorDigest'))
      AND openpc.platform_scope_pending_root_bridge_current(pending,(document->>'predecessorEpoch')::numeric,
        (document->>'expectedRootRevision')::numeric,decode(substring(document->>'predecessorDigest' from 8),'hex')) IS DISTINCT FROM true)
    OR pending.replacement_id=(document->>'replacementId')::uuid
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-SUPERSESSION'; END IF;
  UPDATE control.platform_scope_replacement SET state='SUPERSEDED',row_version=2,
    superseded_by=(document->>'replacementId')::uuid WHERE replacement_id=pending.replacement_id;
 END IF;
 INSERT INTO control.platform_scope_replacement(replacement_id,platform_context_id,participant_id,privacy_domain_id,
  predecessor_epoch,expected_root_revision,predecessor_digest,candidate,candidate_digest,
  successor_scope_cbor,successor_preimage,successor_digest,prepare_operation_id,prepare_candidate_id,prepare_approval_id)
 VALUES((document->>'replacementId')::uuid,(document->>'platformContextId')::uuid,openpc.current_participant_id(),openpc.current_privacy_domain_id(),
  (document->>'predecessorEpoch')::numeric,(document->>'expectedRootRevision')::numeric,
  decode(substring(document->>'predecessorDigest' from 8),'hex'),document,
  sha256(convert_to(openpc.signing_canonical_json(document),'UTF8')),scope,preimage,sha256(preimage),openpc.current_operation_id(),candidate_id,approval_id)
 RETURNING * INTO STRICT inserted;
 FOR target_source IN SELECT v FROM jsonb_array_elements(document->'affectedTargets') v LOOP
  INSERT INTO control.platform_scope_target_withdrawal(replacement_id,participant_id,privacy_domain_id,runtime_target_id,source)
  VALUES(inserted.replacement_id,inserted.participant_id,inserted.privacy_domain_id,(target_source->>'targetId')::uuid,target_source);
 END LOOP;
 RETURN QUERY SELECT jsonb_build_object('replacementId',inserted.replacement_id::text,'successorDigest','sha256:'||encode(inserted.successor_digest,'hex'),
   'state',inserted.state,'revision',inserted.row_version::text,'operationId',inserted.prepare_operation_id::text);
END $$;
REVOKE ALL ON FUNCTION openpc.prepare_platform_scope_replacement(jsonb,bytea,bytea,uuid,uuid) FROM PUBLIC;

${platformScopeCommitGuardsSql}

CREATE OR REPLACE FUNCTION openpc.reject_platform_scope_truncate()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-HISTORY'; END $$;
REVOKE ALL ON FUNCTION openpc.reject_platform_scope_truncate() FROM PUBLIC;
DROP TRIGGER IF EXISTS platform_scope_replacement_truncate ON control.platform_scope_replacement;
CREATE TRIGGER platform_scope_replacement_truncate BEFORE TRUNCATE ON control.platform_scope_replacement
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_platform_scope_truncate();
DROP TRIGGER IF EXISTS platform_scope_successor_truncate ON control.platform_envelope_scope_successor;
CREATE TRIGGER platform_scope_successor_truncate BEFORE TRUNCATE ON control.platform_envelope_scope_successor
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_platform_scope_truncate();
`;

export const platformScopeReplacementGrantsSql = `
${platformScopeCommitGrantsSql}
GRANT EXECUTE ON FUNCTION openpc.platform_scope_document_value(jsonb) TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT SELECT ON control.platform_scope_replacement,control.platform_envelope_scope_successor TO openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.read_platform_scope_affected_targets(uuid)
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader;
GRANT EXECUTE ON FUNCTION openpc.prepare_platform_scope_replacement(jsonb,bytea,bytea,uuid,uuid)
 TO openpc_control_runtime,openpc_control_platform_runtime;
`;

// Readiness is executed by the SQL owner under FORCE RLS. Its source closure is
// the approved pending cohort and the explicitly declared administration only;
// ordinary runtime roles receive no new read or write permission.
const pendingScope = (table) => `replacement.participant_id=${table}.participant_id
 AND openpc.matches_privacy(replacement.privacy_domain_id) AND replacement.state='WITHDRAWING'`;
const declaredAdministrationReadPolicies = [
  ['principal', 'principal_id', 'principalId'],
  ['authority_envelope', 'authority_envelope_id', 'envelopeId'],
  ['assignment', 'assignment_id', 'assignmentId'],
  ['authority_role', 'authority_role_id', 'roleId'],
  ['identity_envelope_proposal', 'envelope_id', 'envelopeId'],
  ['identity_envelope_activation', 'envelope_id', 'envelopeId'],
]
  .map(
    ([table, identity, declared]) => `
DROP POLICY IF EXISTS platform_scope_handoff_read ON control.${table};
CREATE POLICY platform_scope_handoff_read ON control.${table} FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)
 AND openpc.current_action_intent_id() IN('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')
 AND EXISTS(SELECT 1 FROM control.platform_scope_replacement replacement,
   jsonb_array_elements(replacement.candidate->'administrators') administrator
  WHERE ${pendingScope(table)} AND ${table}.${identity}=(administrator->>'${declared}')::uuid));
`,
  )
  .join('\n');
const pendingTargetReadPolicies = [
  ['principal', 'principal_id', 'principal_id'],
  ['credential', 'credential_id', 'credential_id'],
]
  .map(
    ([table, identity, declared]) => `
DROP POLICY IF EXISTS platform_scope_target_identity_read ON control.${table};
CREATE POLICY platform_scope_target_identity_read ON control.${table} FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)
 AND openpc.current_action_intent_id() IN('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')
 AND EXISTS(SELECT 1 FROM control.platform_scope_replacement replacement
  JOIN control.platform_scope_target_withdrawal cohort ON cohort.replacement_id=replacement.replacement_id
   AND cohort.participant_id=replacement.participant_id AND cohort.privacy_domain_id=replacement.privacy_domain_id
  JOIN control.runtime_target_disposition_admission disposition ON disposition.participant_id=cohort.participant_id
   AND disposition.privacy_domain_id=cohort.privacy_domain_id AND disposition.runtime_target_id=cohort.runtime_target_id
  WHERE ${pendingScope(table)} AND disposition.binding->>'action'='Withdraw'
   AND disposition.binding->'cause'=jsonb_build_object('kind','Dependency','owner','Platform',
     'resource_id',replacement.replacement_id::text,'operation_id',replacement.prepare_operation_id::text,'revision',1)
   AND ${table}.${identity}=(disposition.binding#>>'{target,${declared}}')::uuid));
`,
  )
  .join('\n');
const declaredCreateIntentReadPolicy = `
DROP POLICY IF EXISTS platform_scope_handoff_read ON control.mutation_candidate;
CREATE POLICY platform_scope_handoff_read ON control.mutation_candidate FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')
 AND EXISTS(SELECT 1 FROM control.platform_scope_replacement replacement,
   jsonb_array_elements(replacement.candidate->'administrators') administrator
  JOIN control.identity_envelope_proposal proposal ON proposal.envelope_id=(administrator->>'envelopeId')::uuid
  WHERE ${pendingScope('mutation_candidate')} AND replacement.privacy_domain_id=mutation_candidate.privacy_domain_id
   AND proposal.participant_id=replacement.participant_id AND proposal.privacy_domain_id=replacement.privacy_domain_id
   AND proposal.create_candidate_id=mutation_candidate.mutation_candidate_id));
`;

export const platformScopeReplacementSourcePoliciesSql = `${[
  'runtime_target',
  'configuration_work',
  'runtime_activation_observation',
]
  .map(
    (table) => `
DO $platform_source_policy$ BEGIN
IF to_regclass('control.${table}') IS NOT NULL THEN
DROP POLICY IF EXISTS platform_scope_source_read ON control.${table};
CREATE POLICY platform_scope_source_read ON control.${table} FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id() IN('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'));
DROP POLICY IF EXISTS platform_scope_source_lock ON control.${table};
CREATE POLICY platform_scope_source_lock ON control.${table} FOR UPDATE TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1') WITH CHECK(false);
END IF; END $platform_source_policy$;
`,
  )
  .join('\n')}
${[
  ['mutation_candidate', 'mutation_candidate_id', 'candidate'],
  ['approval_request', 'approval_request_id', 'approval'],
  ['mutation_evidence', 'operation_id', 'operation'],
  ['idempotency_record', 'operation_id', 'operation'],
]
  .map(
    ([table, identity, reference]) => `
DROP POLICY IF EXISTS platform_scope_provenance_read ON control.${table};
CREATE POLICY platform_scope_provenance_read ON control.${table} FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  AND EXISTS(SELECT 1 FROM control.platform_scope_replacement replacement
    WHERE replacement.participant_id=${table}.participant_id
      AND replacement.privacy_domain_id=${table}.privacy_domain_id
      AND (${table}.${identity}=replacement.prepare_${reference}_id
        OR ${table}.${identity}=replacement.commit_${reference}_id)));
`,
  )
  .join('\n')}
${declaredAdministrationReadPolicies}
${pendingTargetReadPolicies}
${declaredCreateIntentReadPolicy}
`;
