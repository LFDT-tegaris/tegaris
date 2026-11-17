import {
  platformRecoveryCompletionAdmissionSql,
  platformRecoveryCompletionAssignmentReadSql,
} from './platform-recovery-completion-guards.mjs';
import { platformRecoveryActivatedHandoffSourceSql } from './platform-recovery-activated-handoff-guards.mjs';
import {
  platformRecoveryClosedApprovalLinkSql,
  platformRecoveryClosedApprovalSourceSql,
} from './platform-recovery-closed-approval-guards.mjs';
import { discoveryCertificateRecoveryResumeActions } from '../domain/discovery-certificate-recovery.js';
import { platformRecoveryContinuationLeaseActions } from '../domain/platform-recovery-lease.js';
import {
  platformRecoveryUneffectedSourceSql,
  platformRecoveryUneffectedIntentSql,
} from './platform-recovery-uneffected-guards.mjs';

import { mfaChallenges } from './schema/participants.js';
import {
  approvalRequests,
  idempotencyRecords,
  mutationCandidates,
  mutationEvidence,
  outboxEvents,
} from './schema/workflow.js';
import { authorityEnvelopes, assignments } from './schema/authority.js';
import { identityEnvelopeProposals } from './schema/identity-envelope-proposal.js';
import { platformRecoveryApprovalOwnerReadDefinitions } from './schema/platform-recovery-source.js';
const historyOwnerDefinitions = [
  approvalRequests,
  mfaChallenges,
  idempotencyRecords,
  mutationEvidence,
  outboxEvents,
  authorityEnvelopes,
  assignments,
  identityEnvelopeProposals,
  mutationCandidates,
].flatMap(platformRecoveryApprovalOwnerReadDefinitions);
if (
  historyOwnerDefinitions.length !== 15 ||
  new Set(historyOwnerDefinitions.map((x) => x.functionName)).size !== 15
)
  throw new Error('Incomplete private history owner definitions');

const discoverySourceActions = discoveryCertificateRecoveryResumeActions
  .map((action) => "'" + action + "'")
  .join(',');
const continuationSourceActions = platformRecoveryContinuationLeaseActions
  .map((action) => "'" + action + "'")
  .join(',');

// Preserve UUID::text equality, including rejection of noncanonical strings,
// while allowing native UUID indexes to select the exact identity before RLS.
const canonicalUuidSql = (expression) =>
  `CASE WHEN ${expression} ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (${expression})::uuid ELSE NULL END`;

export const platformRecoveryPendingActivationReceiptSql = `CREATE OR REPLACE FUNCTION openpc.platform_recovery_pending_activation_receipt_current(p_participant uuid,p_privacy uuid,p_key text,p_envelope text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 RETURN EXISTS(SELECT 1 FROM control.mutation_candidate activation
  WHERE activation.participant_id=p_participant AND activation.privacy_domain_id=p_privacy
   AND activation.resource_id::text=p_envelope
   AND activation.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
   AND activation.idempotency_key=p_key);
END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_pending_activation_receipt_current(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_pending_activation_receipt_current(uuid,uuid,text,text) TO openpc_control_owner;
`;

/** A new policy must parse before its final guard is projected. Scalar inputs
 * avoid both missing composite types at bootstrap and row-alias shadowing. */
export const platformRecoveryContinuationRootPreambleSql =
  `
CREATE OR REPLACE FUNCTION openpc.platform_recovery_continuation_root_matches(p_root uuid,p_owner uuid,p_epoch numeric,p_revision numeric)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN RETURN false; END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_continuation_root_matches(uuid,uuid,numeric,numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_continuation_root_matches(uuid,uuid,numeric,numeric) TO openpc_control_owner;
` +
  `CREATE OR REPLACE FUNCTION openpc.platform_recovery_pending_activation_receipt_current(p_participant uuid,p_privacy uuid,p_key text,p_envelope text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN RETURN false; END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_pending_activation_receipt_current(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_pending_activation_receipt_current(uuid,uuid,text,text) TO openpc_control_owner;
` +
  historyOwnerDefinitions.map((x) => x.preamble).join('\n');

/** Durable immutability and phase transitions; application proof verification remains mandatory. */
export const platformRecoveryGuardsSql =
  historyOwnerDefinitions.map((x) => x.body).join('\n') +
  platformRecoveryPendingActivationReceiptSql +
  `
-- Historical witness visibility may be reached from a Root row-lock policy.
-- Keep this leaf in a separate invoker statement so that PostgreSQL does not
-- recursively expand the Root through the witness's own row policy. It reads
-- only Root fields and does not consume recovery history or confer authority.
CREATE OR REPLACE FUNCTION openpc.platform_recovery_continuation_root_matches(p_root uuid,p_owner uuid,p_epoch numeric,p_revision numeric)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 RETURN EXISTS(SELECT 1 FROM control.platform_context root
  WHERE root.platform_context_id=p_root AND root.owner_participant_id=p_owner
   AND root.state='ACTIVE' AND root.authority_epoch=p_epoch AND root.row_version=p_revision);
END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_continuation_root_matches(uuid,uuid,numeric,numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_continuation_root_matches(uuid,uuid,numeric,numeric) TO openpc_control_owner;

-- Purpose is exclusive. This is a read predicate over independently enrolled
-- source bytes, never a grant or a receipt-signature verifier.
CREATE OR REPLACE FUNCTION openpc.platform_recovery_source_root_current(source control.platform_recovery_enrollment)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE source_recovery control.root_expiry_recovery_case;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.platform_context root
  WHERE root.platform_context_id=source.platform_context_id AND root.owner_participant_id=source.participant_id
   AND root.state='ACTIVE' AND root.authority_epoch=source.root_epoch AND root.row_version=source.root_revision) THEN RETURN false; END IF;
 IF (source.source_purpose='EXPIRED_REPLACEMENT' AND source.expired_replacement_id IS NOT NULL AND source.root_expiry_recovery_id IS NULL
     AND source.document->>'schemaVersion'='1' AND NOT (source.document ? 'source')) IS TRUE THEN
  RETURN EXISTS(SELECT 1 FROM control.platform_scope_replacement replacement
      JOIN control.platform_envelope_scope_successor scope ON scope.replacement_id=replacement.replacement_id
       AND scope.platform_context_id=source.platform_context_id AND scope.platform_authority_epoch=source.root_epoch
       AND scope.admission_digest=source.root_digest
      WHERE replacement.replacement_id=source.expired_replacement_id AND replacement.participant_id=source.participant_id
       AND replacement.privacy_domain_id=source.privacy_domain_id AND replacement.platform_context_id=source.platform_context_id
       AND replacement.state='COMMITTED');
 ELSIF (source.source_purpose IN ('ROOT_EXPIRY_RECOVERY','ROOT_EXPIRY_RECOVERY_CONTINUATION','PENDING_ADMINISTRATION_EXPIRY_RECOVERY') AND source.expired_replacement_id IS NULL AND source.root_expiry_recovery_id IS NOT NULL
     AND current_setting('openpc.local_qa_runtime',true) IS NOT DISTINCT FROM '1'
     AND source.document->>'schema' IN ('pc.identity.platform-recovery-enrollment','pc.identity.discovery-certificate-recovery-enrollment')
     AND ((source.source_purpose='ROOT_EXPIRY_RECOVERY' AND source.document->>'schemaVersion'='2')
       OR (source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' AND source.document->>'schema'='pc.identity.platform-recovery-enrollment'
         AND source.document->>'schemaVersion'='3' AND jsonb_typeof(source.document#>'{source,continuation}')='object')
       OR (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' AND source.document->>'schema'='pc.identity.platform-recovery-enrollment'
         AND source.document->>'schemaVersion'='4' AND jsonb_typeof(source.document#>'{source,pendingExpiry}')='object'))
     AND source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
     AND source.document#>>'{source,kind}'='ROOT_EXPIRY_RECOVERY' AND NOT (source.document ? 'expiredReplacementId')) IS TRUE THEN
  FOR source_recovery IN SELECT recovery.* FROM control.root_expiry_recovery_case recovery
      WHERE recovery.recovery_id=source.root_expiry_recovery_id AND recovery.participant_id=source.participant_id
       AND recovery.privacy_domain_id=source.privacy_domain_id AND recovery.state='COMPLETED'
       AND source.document#>>'{source,recoveryId}'=recovery.recovery_id::text
       AND source.document#>>'{source,enrollmentId}'=recovery.enrollment_id::text
       AND source.document#>>'{source,activationOperationId}'=recovery.operation_id::text
       AND source.document#>>'{source,receiptDigest}'='sha256:'||encode(recovery.evidence_digest,'hex') LOOP
   IF EXISTS(SELECT 1 FROM control.root_expiry_recovery_scope scope WHERE scope.recovery_id=source_recovery.recovery_id
       AND scope.owner_participant_id=source_recovery.participant_id AND scope.installation_privacy_domain_id=source_recovery.privacy_domain_id
       AND scope.activation_operation_id=source_recovery.operation_id AND scope.platform_context_id=source.platform_context_id
       AND scope.platform_authority_epoch=source.root_epoch AND scope.admission_digest=source.root_digest) THEN RETURN true; END IF;
  END LOOP;
  RETURN false;
 END IF;
 RETURN false;
END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_source_root_current(control.platform_recovery_enrollment) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_source_root_current(control.platform_recovery_enrollment)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
-- Separate from Root visibility to avoid recursion through the original
-- envelope's installation-source row policy. A changed original closes a lease.
CREATE OR REPLACE FUNCTION openpc.platform_recovery_original_administrators_current(source control.platform_recovery_enrollment)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT source.source_purpose='EXPIRED_REPLACEMENT' OR coalesce(
  source.source_purpose IN ('ROOT_EXPIRY_RECOVERY','ROOT_EXPIRY_RECOVERY_CONTINUATION','PENDING_ADMINISTRATION_EXPIRY_RECOVERY')
  AND jsonb_array_length(source.document#>'{source,originalAdministrators}')=2
  AND EXISTS(SELECT 1 FROM control.root_expiry_recovery_enrollment original
    WHERE original.enrollment_id=${canonicalUuidSql("coalesce(source.document#>>'{source,ancestorReceipts,-1,enrollmentId}',source.document#>>'{source,enrollmentId}')")}
     AND original.participant_id=source.participant_id AND original.privacy_domain_id=source.privacy_domain_id
     AND original.document->'administratorPrincipalIds'=source.document->'administratorPrincipalIds'
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(source.document#>'{source,originalAdministrators}') declared
    WHERE NOT EXISTS(SELECT 1 FROM control.assignment assignment
      JOIN control.authority_envelope envelope ON envelope.participant_id=assignment.participant_id
       AND envelope.authority_envelope_id=assignment.authority_envelope_id
      JOIN control.principal principal ON principal.participant_id=assignment.participant_id AND principal.principal_id=assignment.principal_id
      JOIN control.authority_role role ON role.participant_id=assignment.participant_id AND role.role_id=assignment.role_id
      WHERE assignment.participant_id=source.participant_id AND assignment.assignment_id=${canonicalUuidSql("declared->>'assignmentId'")}
       AND envelope.authority_envelope_id=${canonicalUuidSql("declared->>'envelopeId'")} AND principal.principal_id=${canonicalUuidSql("declared->>'principalId'")}
       AND envelope.principal_id=assignment.principal_id AND assignment.state='ACTIVE' AND envelope.state='ACTIVE'
       AND principal.state='ACTIVE' AND principal.kind='PLATFORM_OPERATOR' AND role.state='ACTIVE'
       AND envelope.representation='LEGACY' AND envelope.platform_context_id=source.platform_context_id
       AND envelope.platform_authority_epoch=(original.document->>'rootEpoch')::numeric AND assignment.delegation_epoch=envelope.delegation_epoch
       AND assignment.row_version::text=declared->>'assignmentRevision' AND envelope.row_version::text=declared->>'envelopeRevision'
       AND role.authority_role_id=${canonicalUuidSql("declared->>'roleId'")} AND role.row_version::text=declared->>'expectedRoleRevision'
       AND declared->>'roleDigest'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
        'domain','pc.identity.envelope-role-binding.v1','participantId',source.participant_id::text,
        'role',jsonb_build_object('roleId',role.role_id,'version',role.row_version::text,'actions',role.action_intent_ids,
          'origin',role.origin,'createdByPrincipalId',role.created_by_principal_id::text,'creatorParticipantId',role.creator_participant_id::text,
          'bootstrapMandateId',role.bootstrap_mandate_id::text,'bootstrapPlatformParticipantId',role.bootstrap_platform_participant_id::text))), 'UTF8')),'hex')
       AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(jsonb_build_array(declared->'usable',declared->'grantable')) scope
        CROSS JOIN LATERAL jsonb_array_elements_text(scope#>'{administration,actionIntentIds}') action
        WHERE NOT (action=ANY(role.action_intent_ids) AND action=ANY(envelope.action_intent_ids) AND action=ANY(assignment.action_intent_ids)))))),false)
$$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_original_administrators_current(control.platform_recovery_enrollment) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_original_administrators_current(control.platform_recovery_enrollment)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
-- A separate PL/pgSQL statement prevents the Root's envelope visibility policy
-- from recursively expanding inside the envelope row-lock policy. INVOKER keeps
-- the actual installation owner and FORCE RLS; this returns no source data.
CREATE OR REPLACE FUNCTION openpc.platform_recovery_installation_source_current(p_enrollment uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 RETURN current_user='openpc_control_owner'
 AND EXISTS(SELECT 1 FROM control.platform_recovery_enrollment enrollment
  WHERE enrollment.enrollment_id=p_enrollment AND openpc.matches_participant(enrollment.participant_id)
   AND openpc.matches_privacy(enrollment.privacy_domain_id) AND enrollment.state='ACTIVE' AND enrollment.row_version=1
   AND (openpc.current_action_intent_id() IN ('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')
    OR (enrollment.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
     AND enrollment.document->>'schemaVersion'='2'
     AND openpc.current_action_intent_id() IN (${discoverySourceActions}))
    OR (enrollment.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION'
     AND enrollment.document->>'schema'='pc.identity.platform-recovery-enrollment'
     AND enrollment.document->>'schemaVersion'='3'
     AND enrollment.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
     AND current_setting('openpc.local_qa_runtime',true) IS NOT DISTINCT FROM '1'
     AND openpc.current_action_intent_id() IN (${continuationSourceActions}))
    OR (enrollment.source_purpose='ROOT_EXPIRY_RECOVERY'
     AND enrollment.document->>'schema'='pc.identity.platform-recovery-enrollment'
     AND enrollment.document->>'schemaVersion'='2'
     AND enrollment.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'
     AND enrollment.document#>>'{uneffectedPredecessor,schemaVersion}'='1'
     AND enrollment.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
     AND current_setting('openpc.local_qa_runtime',true) IS NOT DISTINCT FROM '1'
     AND openpc.current_action_intent_id() IN (${continuationSourceActions}))
    OR (enrollment.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY'
     AND enrollment.document->>'schema'='pc.identity.platform-recovery-enrollment' AND enrollment.document->>'schemaVersion'='4'
     AND enrollment.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
     AND current_setting('openpc.local_qa_runtime',true) IS NOT DISTINCT FROM '1'
     AND openpc.current_action_intent_id() IN (${continuationSourceActions})))
   AND openpc.platform_recovery_source_root_current(enrollment)
   AND enrollment.valid_from<=clock_timestamp() AND enrollment.valid_until>clock_timestamp());
END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_installation_source_current(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_installation_source_current(uuid) TO openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.is_platform_recovery_executor(p_principal uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.platform_recovery_enrollment e
  WHERE openpc.matches_participant(e.participant_id)
   AND e.document#>>'{recoveryPrincipal,principalId}'=p_principal::text)
$$;
REVOKE ALL ON FUNCTION openpc.is_platform_recovery_executor(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.lock_platform_recovery_enrollment(p_enrollment_id uuid)
RETURNS SETOF control.platform_recovery_enrollment LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 -- Recovery activation writes recipient epochs and session families. Declare the
 -- common Participant write fence first, rather than upgrading child share locks.
 PERFORM 1 FROM control.participant p WHERE p.participant_id=openpc.current_participant_id() AND p.state='ACTIVE' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 RETURN QUERY SELECT e.* FROM control.platform_recovery_enrollment e WHERE e.enrollment_id=p_enrollment_id
  AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id) FOR UPDATE OF e;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_platform_recovery_enrollment(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.guard_platform_recovery_enrollment()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR NEW.row_version<>OLD.row_version+1
   OR (to_jsonb(NEW)-ARRAY['state','row_version','revoked_at','revocation_reason_digest']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['state','row_version','revoked_at','revocation_reason_digest']) THEN
   RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 ELSE
  IF NEW.document->>'schema' IS NULL OR NEW.document->>'schema' NOT IN ('pc.identity.platform-recovery-enrollment','pc.identity.discovery-certificate-recovery-enrollment')
   OR (NEW.source_purpose='EXPIRED_REPLACEMENT' AND NEW.document->>'schemaVersion' IS DISTINCT FROM '1')
   OR (NEW.source_purpose='ROOT_EXPIRY_RECOVERY' AND NEW.document->>'schemaVersion' IS DISTINCT FROM '2')
   OR (NEW.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' AND (NEW.document->>'schemaVersion' IS DISTINCT FROM '3'
     OR NEW.document->>'schema' IS DISTINCT FROM 'pc.identity.platform-recovery-enrollment'))
   OR (NEW.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' AND (NEW.document->>'schemaVersion' IS DISTINCT FROM '4'
     OR NEW.document->>'schema' IS DISTINCT FROM 'pc.identity.platform-recovery-enrollment'))
   OR NEW.state<>'ACTIVE' OR NEW.row_version<>1 OR NEW.document_digest<>sha256(convert_to(openpc.signing_canonical_json(NEW.document),'UTF8'))
   OR NEW.document->>'enrollmentId' IS DISTINCT FROM NEW.enrollment_id::text
   OR NEW.document->>'participantId' IS DISTINCT FROM NEW.participant_id::text
   OR NEW.document->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
   OR NEW.document->>'platformContextId' IS DISTINCT FROM NEW.platform_context_id::text
   OR (NEW.source_purpose='EXPIRED_REPLACEMENT' AND NEW.document->>'expiredReplacementId' IS DISTINCT FROM NEW.expired_replacement_id::text)
   OR NEW.document->>'rootEpoch' IS DISTINCT FROM NEW.root_epoch::text
   OR NEW.document->>'rootRevision' IS DISTINCT FROM NEW.root_revision::text
   OR NEW.document->>'rootDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.root_digest,'hex')
   OR (NEW.document->>'validFrom')::timestamptz IS DISTINCT FROM NEW.valid_from
   OR (NEW.document->>'validUntil')::timestamptz IS DISTINCT FROM NEW.valid_until
   OR NOT coalesce(openpc.platform_recovery_source_root_current(NEW),false)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS platform_recovery_enrollment_guard ON control.platform_recovery_enrollment;
CREATE TRIGGER platform_recovery_enrollment_guard BEFORE INSERT OR UPDATE OR DELETE ON control.platform_recovery_enrollment
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_recovery_enrollment();

-- A new recovery request may supersede only the independently governed expired, uneffected handoff.
${platformRecoveryUneffectedSourceSql}
${platformRecoveryUneffectedIntentSql}
CREATE OR REPLACE FUNCTION openpc.platform_recovery_supersession_current(participant uuid,enrollment uuid,link jsonb,preparation jsonb)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.platform_recovery_case original
  JOIN control.platform_scope_replacement r ON r.participant_id=original.participant_id
   AND r.privacy_domain_id=original.privacy_domain_id AND r.candidate=original.intent->'preparation'
  JOIN control.mutation_candidate m ON m.participant_id=r.participant_id AND m.privacy_domain_id=r.privacy_domain_id
   AND m.mutation_candidate_id=r.prepare_candidate_id AND m.candidate_digest=r.candidate_digest
   AND m.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' AND m.state='CONSUMED' AND m.consumed_operation_id=r.prepare_operation_id
  JOIN control.approval_request a ON a.participant_id=m.participant_id AND a.privacy_domain_id=m.privacy_domain_id
   AND a.subject_id=m.mutation_candidate_id AND a.subject_digest=m.candidate_digest
   AND a.approval_request_id=r.prepare_approval_id AND a.state='APPROVED'
  WHERE original.participant_id=participant AND original.enrollment_id=enrollment
   AND openpc.matches_participant(participant) AND openpc.matches_privacy(original.privacy_domain_id)
   AND original.state='EXPIRED' AND original.valid_until<=clock_timestamp() AND original.activation_operation_id IS NOT NULL
   AND link=jsonb_build_object('recoveryId',original.recovery_id::text,'intentDigest','sha256:'||encode(original.intent_digest,'hex'),
     'replacementId',r.replacement_id::text,'preparationDigest','sha256:'||encode(r.candidate_digest,'hex'),
     'preparationOperationId',r.prepare_operation_id::text,'preparationApprovalId',r.prepare_approval_id::text,
     'expectedRevision','1','successorDigest','sha256:'||encode(r.successor_digest,'hex'))
   AND preparation->'supersedes'=jsonb_build_object('replacementId',r.replacement_id::text,'expectedRevision','1',
       'successorDigest','sha256:'||encode(r.successor_digest,'hex'))
   AND preparation->>'replacementId'<>r.replacement_id::text
   AND preparation->>'platformContextId'=r.platform_context_id::text
   AND preparation->>'predecessorEpoch'=r.predecessor_epoch::text
   AND preparation->>'expectedRootRevision'=r.expected_root_revision::text
   AND preparation->>'predecessorDigest'='sha256:'||encode(r.predecessor_digest,'hex')
   AND ((r.state='WITHDRAWING' AND r.row_version=1 AND r.superseded_by IS NULL)
     OR (r.state='SUPERSEDED' AND r.row_version=2 AND r.superseded_by::text=preparation->>'replacementId'
       AND EXISTS(SELECT 1 FROM control.platform_scope_replacement next WHERE next.replacement_id=r.superseded_by
         AND next.participant_id=participant AND next.privacy_domain_id=r.privacy_domain_id AND next.state='WITHDRAWING'
         AND next.candidate=preparation)))
   AND jsonb_array_length(r.candidate->'administrators')=2
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(r.candidate->'administrators') admin
    WHERE (admin#>>'{usable,validUntilNs}')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000000)
      OR (admin#>>'{grantable,validUntilNs}')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000000)
      OR EXISTS(SELECT 1 FROM control.authority_envelope e WHERE e.participant_id=participant AND e.authority_envelope_id::text=admin->>'envelopeId')
      OR EXISTS(SELECT 1 FROM control.assignment assignment WHERE assignment.participant_id=participant AND assignment.assignment_id::text=admin->>'assignmentId')
      OR EXISTS(SELECT 1 FROM control.identity_envelope_proposal proposal WHERE proposal.participant_id=participant AND proposal.envelope_id::text=admin->>'envelopeId'))
 ) OR openpc.platform_recovery_uneffected_supersession_current(participant,enrollment,link,preparation)
$$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_supersession_current(uuid,uuid,jsonb,jsonb) FROM PUBLIC;

-- The original source is authenticated history, never a renewed grant. A new
-- case may consume only the unchanged, still-live pending business suffix.
CREATE OR REPLACE FUNCTION openpc.platform_recovery_continuation_current(participant uuid,enrollment uuid,link jsonb,preparation jsonb)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.platform_recovery_enrollment fresh
  JOIN control.platform_recovery_case original ON original.participant_id=fresh.participant_id
   AND original.privacy_domain_id=fresh.privacy_domain_id
   AND original.recovery_id::text=link->>'recoveryId' AND original.enrollment_id::text=link->>'enrollmentId'
  JOIN control.platform_recovery_enrollment old_source ON old_source.participant_id=original.participant_id
   AND old_source.privacy_domain_id=original.privacy_domain_id AND old_source.enrollment_id=original.enrollment_id
   AND ((NOT (fresh.document#>'{source}' ? 'activatedHandoff')
      AND old_source.source_purpose='ROOT_EXPIRY_RECOVERY' AND old_source.document->>'schemaVersion'='2')
    OR (fresh.document#>>'{source,activatedHandoff,schemaVersion}'='1'
      AND old_source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY'
      AND old_source.document->>'schemaVersion'='4'
      AND old_source.document#>>'{source,pendingExpiry,schemaVersion}'='2'
      AND NOT (old_source.document#>'{source}' ? 'closedApproval')
      AND NOT (original.intent ?| ARRAY['completionSourceDigest','approvalContinuation','closedApprovalSourceDigest'])
      AND original.intent->'pendingExpiry'=old_source.document#>'{source,pendingExpiry}'
      AND 'sha256:'||encode(old_source.document_digest,'hex')=fresh.document#>>'{source,activatedHandoff,predecessorEnrollmentDigest}'
      AND (fresh.document#>'{source,activatedHandoff}')-ARRAY['schemaVersion','predecessorEnrollmentDigest','administrators']='{}'::jsonb
      AND fresh.document->'recoveryPrincipal'=old_source.document->'recoveryPrincipal'
      AND fresh.document->'custodians'=old_source.document->'custodians'
      AND ((fresh.document->'source')-ARRAY['continuation','activatedHandoff'])=((old_source.document->'source')-'pendingExpiry')
      AND original.intent#>'{preparation,supersedes}'=jsonb_build_object(
        'replacementId',old_source.document#>>'{source,pendingExpiry,preparation,replacementId}',
        'expectedRevision','1','successorDigest',old_source.document#>>'{source,pendingExpiry,preparation,successorDigest}')))
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
   AND fresh.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' AND fresh.document->>'schemaVersion'='3'
   AND fresh.document->>'schema'='pc.identity.platform-recovery-enrollment' AND fresh.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
   AND fresh.state='ACTIVE' AND fresh.row_version=1 AND fresh.valid_from<=clock_timestamp() AND fresh.valid_until>clock_timestamp()
   AND old_source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' AND old_source.state='ACTIVE'
   AND fresh.platform_context_id=old_source.platform_context_id AND fresh.root_epoch=old_source.root_epoch
   AND fresh.root_revision=old_source.root_revision AND fresh.root_digest=old_source.root_digest
   AND fresh.document->'administratorPrincipalIds'=old_source.document->'administratorPrincipalIds'
   AND openpc.platform_recovery_source_root_current(fresh)
   AND original.state='EXPIRED' AND original.valid_until<=fresh.valid_from
   AND original.activation_operation_id IS NOT NULL AND original.activation_evidence_digest=sha256(original.activation_evidence_cbor)
   AND octet_length(original.activation_cose)>0 AND jsonb_array_length(original.lease_bindings)=2
   AND original.intent_digest=sha256(convert_to(openpc.signing_canonical_json(original.intent),'UTF8'))
   AND NOT (original.intent ? 'continuation') AND NOT (original.intent ? 'supersession')
   AND (NOT (r.candidate ? 'supersedes') OR fresh.document#>>'{source,activatedHandoff,schemaVersion}'='1') AND r.state='WITHDRAWING' AND r.row_version=1 AND r.superseded_by IS NULL
   AND r.commit_operation_id IS NULL AND r.platform_context_id=fresh.platform_context_id
   AND r.predecessor_epoch=fresh.root_epoch AND r.expected_root_revision=fresh.root_revision AND r.predecessor_digest=fresh.root_digest
   AND r.candidate=preparation AND r.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(preparation),'UTF8'))
   AND r.successor_digest=sha256(r.successor_preimage)
   AND link=fresh.document#>'{source,continuation}'
   AND link=jsonb_build_object('schema','pc.identity.platform-pending-recovery-continuation','schemaVersion',1,
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
    WHERE (admin#>>'{usable,validUntilNs}')::numeric<floor(extract(epoch FROM fresh.valid_until)*1000000000)
      OR (admin#>>'{grantable,validUntilNs}')::numeric<floor(extract(epoch FROM fresh.valid_until)*1000000000))
   AND (r.candidate#>>'{successorScope,validUntilNs}')::numeric>=floor(extract(epoch FROM fresh.valid_until)*1000000000)
 )
$$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_continuation_current(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_continuation_current(uuid,uuid,jsonb,jsonb)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;

${platformRecoveryCompletionAdmissionSql}
${platformRecoveryCompletionAssignmentReadSql}

${platformRecoveryActivatedHandoffSourceSql}

-- Distinct exact expired-partial witness; generic supersession/continuation remain unchanged.
CREATE OR REPLACE FUNCTION openpc.platform_recovery_pending_expiry_source_current(participant uuid,enrollment uuid,link jsonb,preparation jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
#variable_conflict use_column
DECLARE fresh control.platform_recovery_enrollment; original control.platform_recovery_case; old_source control.platform_recovery_enrollment; r control.platform_scope_replacement; m control.mutation_candidate; a control.approval_request; evidence control.mutation_evidence; committed control.idempotency_record; p control.identity_envelope_proposal; e control.authority_envelope; created control.mutation_candidate; issuing control.authority_envelope; historical_case control.platform_recovery_case; creation_approval control.approval_request; creation_evidence control.mutation_evidence; creation_receipt control.idempotency_record; activation control.mutation_candidate; activation_approval control.approval_request;
 plan jsonb; administrator_ordinal bigint; witness record; approved_proposal_matched boolean;
BEGIN
IF EXISTS(SELECT 1 FROM control.platform_recovery_enrollment fresh
 WHERE fresh.enrollment_id=enrollment AND fresh.participant_id=participant
  AND fresh.document#>>'{source,pendingExpiry,schemaVersion}'='2') THEN
 RETURN openpc.platform_recovery_activated_expiry_source_current(participant,enrollment,link,preparation);
END IF;
FOR fresh IN SELECT fresh.* FROM control.platform_recovery_enrollment fresh WHERE fresh.enrollment_id=enrollment AND fresh.participant_id=participant LOOP
 FOR original IN SELECT original.* FROM control.platform_recovery_case original WHERE original.participant_id=fresh.participant_id
   AND original.privacy_domain_id=fresh.privacy_domain_id
   AND original.recovery_id=CASE WHEN (link->>'recoveryId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (link->>'recoveryId')::uuid ELSE NULL::uuid END AND original.enrollment_id=CASE WHEN (link->>'enrollmentId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (link->>'enrollmentId')::uuid ELSE NULL::uuid END LOOP
  FOR old_source IN SELECT old_source.* FROM control.platform_recovery_enrollment old_source WHERE old_source.participant_id=original.participant_id
   AND old_source.privacy_domain_id=original.privacy_domain_id AND old_source.enrollment_id=original.enrollment_id
   AND old_source.source_purpose='ROOT_EXPIRY_RECOVERY' AND old_source.document->>'schemaVersion'='2'
   AND old_source.document->>'schema'='pc.identity.platform-recovery-enrollment'
   AND old_source.document_digest=original.enrollment_digest AND old_source.row_version=original.enrollment_revision LOOP
   FOR r IN SELECT r.* FROM control.platform_scope_replacement r WHERE r.participant_id=original.participant_id
   AND r.privacy_domain_id=original.privacy_domain_id AND r.candidate=original.intent->'preparation' LOOP
    FOR m IN SELECT m.* FROM control.mutation_candidate m WHERE m.participant_id=r.participant_id AND m.privacy_domain_id=r.privacy_domain_id
   AND m.mutation_candidate_id=r.prepare_candidate_id AND m.candidate_document=r.candidate AND m.candidate_digest=r.candidate_digest
   AND m.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' AND m.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   AND m.resource_id=r.replacement_id AND m.expected_revision=0 AND m.state='CONSUMED' AND m.consumed_operation_id=r.prepare_operation_id LOOP
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
        IF (fresh.document->>'schemaVersion'='4') IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
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
        IF (NOT (r.candidate ? 'supersedes')) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
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
        AND assigned.assignment_id=CASE WHEN (plan->>'assignmentId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'assignmentId')::uuid ELSE NULL::uuid END)) THEN CONTINUE matched_receipt; END IF;
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
         CASE witness.declared#>>'{effect,state}'
         WHEN 'ABSENT' THEN
          IF (EXISTS(SELECT 1 FROM control.authority_envelope e WHERE e.participant_id=participant
          AND e.authority_envelope_id=CASE WHEN (plan->>'envelopeId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'envelopeId')::uuid ELSE NULL::uuid END)) THEN CONTINUE matched_receipt; END IF;
          IF (EXISTS(SELECT 1 FROM control.identity_envelope_proposal p WHERE p.participant_id=participant
          AND p.envelope_id=CASE WHEN (plan->>'envelopeId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'envelopeId')::uuid ELSE NULL::uuid END)) THEN CONTINUE matched_receipt; END IF;
          IF (EXISTS(SELECT 1 FROM control.mutation_candidate pending WHERE pending.participant_id=participant
          AND pending.privacy_domain_id=fresh.privacy_domain_id AND pending.resource_id=CASE WHEN (plan->>'envelopeId') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (plan->>'envelopeId')::uuid ELSE NULL::uuid END)) THEN CONTINUE matched_receipt; END IF;
         WHEN 'APPROVED_PROPOSAL' THEN
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
          AND activation.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' AND activation.consumed_operation_id IS NULL
          AND activation.state IN ('APPROVAL_REQUESTED','APPROVED') AND activation.attempt::text=witness.declared#>>'{effect,activationAttempt}'
          AND 'sha256:'||encode(activation.candidate_digest,'hex')=witness.declared#>>'{effect,activationCandidateDigest}'
          AND NOT EXISTS(SELECT 1 FROM control.mutation_candidate later WHERE later.participant_id=activation.participant_id
            AND later.privacy_domain_id=activation.privacy_domain_id AND later.predecessor_candidate_id=activation.mutation_candidate_id) LOOP
                   <<proposal_receipt>>
                   FOR activation_approval IN SELECT activation_approval.* FROM control.approval_request activation_approval WHERE activation_approval.participant_id=activation.participant_id
          AND activation_approval.privacy_domain_id=activation.privacy_domain_id AND activation_approval.subject_id=activation.mutation_candidate_id
          AND activation_approval.subject_digest=activation.candidate_digest
          AND activation_approval.approval_request_id=CASE WHEN (witness.declared#>>'{effect,activationApprovalId}') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (witness.declared#>>'{effect,activationApprovalId}')::uuid ELSE NULL::uuid END
          AND activation_approval.state IN ('OPEN','APPROVED') LOOP
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
                    IF (e.state='APPROVED') IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.representation='TYPED_V1') IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.row_version=3) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.semantic_cbor=p.proposal_cbor) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.semantic_digest=p.proposal_digest) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.platform_context_id=r.platform_context_id) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.platform_authority_epoch=r.predecessor_epoch+1) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.valid_until<=clock_timestamp()) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (cardinality(e.runtime_capability_ids)=0) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.onward_delegation_depth=0) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.maker_checker_required) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (e.step_up_required) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
                    IF (NOT EXISTS(SELECT 1 FROM control.mutation_candidate effect WHERE effect.participant_id=p.participant_id
            AND effect.privacy_domain_id=p.privacy_domain_id AND effect.resource_id=p.envelope_id
            AND effect.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE' AND effect.consumed_operation_id IS NOT NULL)) IS NOT TRUE THEN CONTINUE proposal_receipt; END IF;
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
      WHERE declared#>>'{effect,state}'='APPROVED_PROPOSAL')=1) IS NOT TRUE THEN CONTINUE matched_receipt; END IF;
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
REVOKE ALL ON FUNCTION openpc.platform_recovery_pending_expiry_source_current(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_pending_expiry_source_current(uuid,uuid,jsonb,jsonb)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;

-- A separate prospective case may adopt exactly one expired unconsumed
-- PREPARE intent. Historical custody is data, never a resurrected grant.
-- Historical signed receipts prove provenance, never a renewed grant.
${platformRecoveryClosedApprovalLinkSql}

CREATE OR REPLACE FUNCTION openpc.platform_recovery_pending_approval_history_current(
 p_participant uuid,p_enrollment uuid,p_recovery uuid,p_candidate uuid,p_approval uuid,p_receiving uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE source control.platform_recovery_enrollment; history control.platform_recovery_case;
 candidate control.mutation_candidate; approval control.approval_request; parent control.mutation_candidate;
 visited_cases uuid[]:=ARRAY[]::uuid[]; visited_candidates uuid[]:=ARRAY[]::uuid[];
 later_candidate uuid; later_from timestamptz; later_witness jsonb; witness jsonb;
 selected_recovery uuid:=p_recovery; selected_candidate uuid:=p_candidate; selected_approval uuid:=p_approval;
 children integer; hop integer; closed jsonb; historical_enrollment uuid;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(p_participant)
  OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1' THEN RETURN false; END IF;
 SELECT * INTO STRICT source FROM control.platform_recovery_enrollment e
  WHERE e.participant_id=p_participant AND e.privacy_domain_id=openpc.current_privacy_domain_id()
   AND e.enrollment_id=p_enrollment AND e.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY'
   AND e.document->>'schemaVersion'='4' AND e.state='ACTIVE'
   AND e.valid_from<=clock_timestamp() AND e.valid_until>clock_timestamp();
 closed:=source.document#>'{source,closedApproval}';
 historical_enrollment:=CASE WHEN closed IS NULL THEN p_enrollment ELSE (closed->>'enrollmentId')::uuid END;
 IF closed IS NOT NULL AND (closed#>>'{approval,candidateId}' IS DISTINCT FROM p_candidate::text
   OR closed#>>'{approval,approvalId}' IS DISTINCT FROM p_approval::text
   OR openpc.platform_recovery_closed_approval_link_current(p_participant,p_enrollment,p_recovery) IS DISTINCT FROM true)
 THEN RETURN false; END IF;
 FOR hop IN 1..32 LOOP
  IF selected_recovery=ANY(visited_cases) OR selected_candidate=ANY(visited_candidates)
   OR selected_recovery=p_receiving THEN RETURN false; END IF;
  visited_cases:=array_append(visited_cases,selected_recovery);
  visited_candidates:=array_append(visited_candidates,selected_candidate);
  SELECT * INTO STRICT history FROM control.platform_recovery_case c
   WHERE c.participant_id=p_participant AND c.privacy_domain_id=source.privacy_domain_id
    AND c.enrollment_id=historical_enrollment AND c.recovery_id=selected_recovery;
  SELECT * INTO STRICT candidate FROM control.mutation_candidate m
   WHERE m.participant_id=p_participant AND m.privacy_domain_id=source.privacy_domain_id
    AND m.mutation_candidate_id=selected_candidate;
  SELECT * INTO STRICT approval FROM control.approval_request a
   WHERE a.participant_id=p_participant AND a.privacy_domain_id=source.privacy_domain_id
    AND a.approval_request_id=selected_approval;
  IF (closed IS NULL AND (history.state IS DISTINCT FROM 'EXPIRED' OR history.valid_until>clock_timestamp()
   OR (later_from IS NOT NULL AND history.valid_until>later_from)
   OR history.enrollment_revision<>source.row_version OR history.enrollment_digest<>source.document_digest))
   OR history.intent->'pendingExpiry' IS DISTINCT FROM source.document#>'{source,pendingExpiry}'
   OR history.intent ? 'continuation' OR history.intent ? 'supersession'
   OR history.intent_digest<>sha256(convert_to(openpc.signing_canonical_json(history.intent),'UTF8'))
   OR history.activation_operation_id IS NULL OR history.activated_at IS NULL
   OR history.activated_at<history.valid_from OR history.activated_at>=history.valid_until
   OR history.activation_evidence_digest IS DISTINCT FROM sha256(history.activation_evidence_cbor)
   OR coalesce(octet_length(history.activation_cose),0)=0
   OR jsonb_array_length(history.lease_bindings)<>2
   OR candidate.catalog_operation_id IS DISTINCT FROM 'ID-OP-PLATFORM-SCOPE-PREPARE'
   OR candidate.action_intent_id IS DISTINCT FROM 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   OR candidate.resource_type IS DISTINCT FROM 'participant' OR candidate.operation_class IS DISTINCT FROM 'UPDATE'
   OR candidate.expected_revision<>0 OR candidate.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED')
   OR candidate.consumed_operation_id IS NOT NULL OR candidate.expires_at>clock_timestamp()
   OR candidate.created_at<history.activated_at OR candidate.expires_at<=candidate.created_at
   OR candidate.expires_at>history.valid_until
   OR candidate.resource_id::text IS DISTINCT FROM history.intent#>>'{preparation,replacementId}'
   OR candidate.candidate_document IS DISTINCT FROM history.intent->'preparation'
   OR candidate.candidate_digest<>sha256(convert_to(openpc.signing_canonical_json(candidate.candidate_document),'UTF8'))
   OR candidate.maker_principal_id::text IS DISTINCT FROM history.intent#>>'{preparation,administrators,0,principalId}'
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(history.lease_bindings) b
     WHERE b->>'envelopeId'=candidate.maker_authority_envelope_id::text
      AND b->>'assignmentId'=candidate.maker_assignment_id::text
      AND b->>'principalId'=candidate.maker_principal_id::text
      AND b->>'principalEpoch'=candidate.maker_principal_epoch::text)
   OR ROW(approval.subject_type,approval.subject_id,approval.subject_digest,approval.subject_version,
      approval.action_intent_id,approval.maker_principal_id)
    IS DISTINCT FROM ROW('CONFIGURATION_CANDIDATE'::text,candidate.mutation_candidate_id,candidate.candidate_digest,
      candidate.expected_revision,candidate.action_intent_id,candidate.maker_principal_id)
   OR approval.checker_principal_id::text IS DISTINCT FROM history.intent#>>'{preparation,administrators,1,principalId}'
   OR approval.checker_principal_id=approval.maker_principal_id OR approval.state NOT IN ('OPEN','APPROVED','EXPIRED')
   OR (SELECT count(*) FROM control.platform_recovery_proof proof WHERE proof.participant_id=p_participant
     AND proof.privacy_domain_id=source.privacy_domain_id AND proof.recovery_id=history.recovery_id
     AND proof.intent_digest=history.intent_digest AND proof.verified_at>=history.valid_from
     AND proof.verified_at<=history.activated_at)<>4
   OR NOT EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=p_participant
     AND event.privacy_domain_id=source.privacy_domain_id AND event.aggregate_type='platform-recovery'
     AND event.aggregate_id=history.recovery_id AND event.aggregate_sequence=1
     AND event.event_type='openpc.identity.platform-recovery.activated.v1'
     AND event.payload_cbor=history.activation_evidence_cbor AND event.payload_digest=history.activation_evidence_digest
     AND event.cose_sign1=history.activation_cose) THEN RETURN false; END IF;
  witness:=jsonb_build_object('schema','pc.identity.platform-prepare-approval-continuation','schemaVersion',1,
   'recoveryId',history.recovery_id::text,'intentDigest','sha256:'||encode(history.intent_digest,'hex'),
   'activationOperationId',history.activation_operation_id::text,
   'activationReceiptDigest','sha256:'||encode(history.activation_evidence_digest,'hex'),
   'candidateId',candidate.mutation_candidate_id::text,'approvalId',approval.approval_request_id::text,
   'candidateDigest','sha256:'||encode(candidate.candidate_digest,'hex'),
   'businessKey',candidate.idempotency_key,'attempt',candidate.attempt::text);
  IF later_witness IS NOT NULL AND later_witness IS DISTINCT FROM witness THEN RETURN false; END IF;
  IF closed IS NOT NULL AND closed->'approval' IS DISTINCT FROM witness THEN RETURN false; END IF;
  SELECT count(*) INTO children FROM control.mutation_candidate child WHERE child.participant_id=p_participant
   AND child.privacy_domain_id=source.privacy_domain_id AND child.predecessor_candidate_id=candidate.mutation_candidate_id;
  IF children>1 OR (later_candidate IS NOT NULL AND (children<>1 OR NOT EXISTS(
    SELECT 1 FROM control.mutation_candidate child WHERE child.participant_id=p_participant
     AND child.privacy_domain_id=source.privacy_domain_id AND child.mutation_candidate_id=later_candidate
     AND child.predecessor_candidate_id=candidate.mutation_candidate_id)))
   OR (later_candidate IS NULL AND children=1 AND (p_receiving IS NULL OR NOT EXISTS(
    SELECT 1 FROM control.mutation_candidate child JOIN control.authority_envelope receiving
      ON receiving.participant_id=child.participant_id AND receiving.authority_envelope_id=child.maker_authority_envelope_id
    WHERE child.participant_id=p_participant AND child.privacy_domain_id=source.privacy_domain_id
     AND child.predecessor_candidate_id=candidate.mutation_candidate_id
     AND receiving.representation='RECOVERY_V1' AND receiving.recovery_case_id=p_receiving)))
  THEN RETURN false; END IF;
  IF closed IS NOT NULL THEN
   RETURN NOT (history.intent ? 'approvalContinuation') AND candidate.predecessor_candidate_id IS NULL
    AND candidate.predecessor_approval_id IS NULL AND candidate.resume_operation_id IS NULL AND candidate.attempt=1;
  END IF;
  IF NOT (history.intent ? 'approvalContinuation') THEN
   RETURN candidate.predecessor_candidate_id IS NULL AND candidate.predecessor_approval_id IS NULL
    AND candidate.resume_operation_id IS NULL AND candidate.attempt=1
    AND openpc.platform_recovery_pending_expiry_intent_current(p_participant,p_enrollment,history.intent);
  END IF;
  IF candidate.predecessor_candidate_id IS NULL OR candidate.predecessor_approval_id IS NULL
   OR candidate.resume_operation_id IS NULL OR candidate.resume_request->>'command' IS DISTINCT FROM 'RESUME'
   OR candidate.resume_request->>'predecessorCandidateId' IS DISTINCT FROM candidate.predecessor_candidate_id::text
   OR candidate.resume_request->>'candidateDigest' IS DISTINCT FROM 'sha256:'||encode(candidate.candidate_digest,'hex')
   OR candidate.resume_request->>'approvalRequestId' IS DISTINCT FROM 'urn:openpc:resource:'||candidate.predecessor_approval_id::text
  THEN RETURN false; END IF;
  SELECT * INTO STRICT parent FROM control.mutation_candidate m WHERE m.participant_id=p_participant
   AND m.privacy_domain_id=source.privacy_domain_id AND m.mutation_candidate_id=candidate.predecessor_candidate_id;
  IF candidate.attempt<>parent.attempt+1 OR candidate.resume_request->>'expectedAttempt' IS DISTINCT FROM parent.attempt::text
   OR ROW(candidate.action_intent_id,candidate.catalog_operation_id,candidate.resource_type,candidate.operation_class,
      candidate.resource_id,candidate.candidate_document,candidate.candidate_digest,candidate.expected_revision,
      candidate.idempotency_key,candidate.maker_principal_id)
    IS DISTINCT FROM ROW(parent.action_intent_id,parent.catalog_operation_id,parent.resource_type,parent.operation_class,
      parent.resource_id,parent.candidate_document,parent.candidate_digest,parent.expected_revision,parent.idempotency_key,parent.maker_principal_id)
   OR NOT EXISTS(SELECT 1 FROM control.idempotency_record resume WHERE resume.participant_id=p_participant
     AND resume.privacy_domain_id=source.privacy_domain_id AND resume.operation_id=candidate.resume_operation_id
     AND resume.principal_id=candidate.maker_principal_id AND resume.catalog_operation_id='LEGACY'
     AND resume.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' AND resume.terminal_state='COMMITTED'
     AND resume.input_digest=sha256(convert_to(openpc.signing_canonical_json(candidate.resume_request),'UTF8')))
   OR (SELECT count(*) FROM control.mfa_challenge challenge JOIN control.mutation_evidence verification
      ON verification.participant_id=challenge.participant_id AND verification.mfa_challenge_id=challenge.mfa_challenge_id
     JOIN control.outbox_event event ON event.participant_id=verification.participant_id
      AND event.privacy_domain_id=verification.privacy_domain_id AND event.aggregate_type=verification.aggregate_type
      AND event.aggregate_id=verification.aggregate_id AND event.payload_digest=verification.evidence_digest
      AND event.payload_cbor=verification.evidence_cbor AND event.cose_sign1=verification.cose_sign1
     WHERE challenge.participant_id=p_participant AND challenge.principal_id=candidate.maker_principal_id
      AND challenge.session_id=candidate.maker_session_id
      AND ((challenge.used_at IS NULL AND challenge.used_operation_id IS NULL)
        OR (challenge.used_operation_id=candidate.resume_operation_id AND challenge.used_at IS NOT NULL
          AND challenge.used_at<=candidate.created_at))
      AND challenge.resource_id=candidate.predecessor_approval_id::text
      AND challenge.consumed_at IS NOT NULL AND challenge.consumed_at<=candidate.created_at
      AND candidate.created_at<challenge.expires_at AND challenge.consumed_at<=challenge.expires_at
      AND challenge.created_at>=history.activated_at AND challenge.consumed_at>=history.activated_at
      AND challenge.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
      AND challenge.resource_digest=sha256(convert_to(openpc.signing_canonical_json(candidate.resume_request),'UTF8'))
      AND verification.principal_id=candidate.maker_principal_id
      AND verification.privacy_domain_id=candidate.privacy_domain_id
      AND verification.evidence_digest=sha256(verification.evidence_cbor)
      AND verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
      AND verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
      AND verification.aggregate_type='webauthn-verification' AND verification.aggregate_id=candidate.maker_session_id
      AND verification.bound_authority_envelope_id=candidate.maker_authority_envelope_id
      AND verification.bound_assignment_id=candidate.maker_assignment_id
      AND verification.bound_principal_epoch=candidate.maker_principal_epoch
      AND verification.bound_participant_epoch=candidate.maker_participant_epoch
      AND verification.bound_envelope_epoch=candidate.maker_authority_epoch
      AND verification.signer_credential_id=challenge.signer_credential_id
      AND verification.occurred_at>=challenge.consumed_at AND verification.occurred_at<=candidate.created_at
      AND coalesce(octet_length(verification.cose_sign1),0)>0
      AND EXISTS(SELECT 1 FROM control.idempotency_record verified WHERE verified.participant_id=verification.participant_id
       AND verified.privacy_domain_id=verification.privacy_domain_id AND verified.operation_id=verification.operation_id
       AND verified.principal_id=verification.principal_id AND verified.catalog_operation_id=verification.catalog_operation_id
       AND verified.action_intent_id=verification.action_intent_id AND verified.input_digest=verification.candidate_digest
       AND verified.terminal_state='COMMITTED' AND verified.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
       AND verified.created_at>=challenge.created_at AND verified.created_at<=challenge.consumed_at)
      AND verification.webauthn_assertion_binding_digest IS NOT NULL
      AND event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
      AND event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1')<>1
  THEN RETURN false; END IF;
  later_candidate:=candidate.mutation_candidate_id;later_from:=history.valid_from;
  later_witness:=history.intent->'approvalContinuation';
  selected_recovery:=(later_witness->>'recoveryId')::uuid;
  selected_candidate:=candidate.predecessor_candidate_id;selected_approval:=candidate.predecessor_approval_id;
 END LOOP;
 RETURN false;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR numeric_value_out_of_range
 THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_pending_approval_history_current(uuid,uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_pending_approval_history_current(uuid,uuid,uuid,uuid,uuid,uuid)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;

${platformRecoveryClosedApprovalSourceSql}

CREATE OR REPLACE FUNCTION openpc.platform_recovery_pending_approval_current(participant uuid,enrollment uuid,p_intent jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE previous control.platform_recovery_case; original control.mutation_candidate;
 approval control.approval_request; child control.mutation_candidate; witness jsonb;
 fresh_from timestamptz; fresh_until timestamptz; descendants integer; closed jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(participant) OR NOT (p_intent ? 'pendingExpiry')
  OR p_intent ? 'continuation' OR p_intent ? 'supersession'
  OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1' THEN RETURN false; END IF;
 SELECT e.document#>'{source,closedApproval}' INTO STRICT closed FROM control.platform_recovery_enrollment e
  WHERE e.participant_id=participant AND e.privacy_domain_id=openpc.current_privacy_domain_id() AND e.enrollment_id=enrollment;
 SELECT * INTO STRICT previous FROM control.platform_recovery_case c
  WHERE c.participant_id=participant AND c.privacy_domain_id=openpc.current_privacy_domain_id()
   AND c.enrollment_id=CASE WHEN closed IS NULL THEN enrollment ELSE (closed->>'enrollmentId')::uuid END
   AND c.recovery_id::text=p_intent#>>'{approvalContinuation,recoveryId}'
   AND ((closed IS NULL AND c.state='EXPIRED' AND c.valid_until<=clock_timestamp())
     OR (closed IS NOT NULL AND openpc.platform_recovery_closed_approval_link_current(participant,enrollment,c.recovery_id)))
   AND c.intent ? 'pendingExpiry';
 fresh_from:=(p_intent->>'validFrom')::timestamptz; fresh_until:=(p_intent->>'validUntil')::timestamptz;
 IF previous.recovery_id::text=p_intent->>'recoveryId'
  OR (CASE WHEN closed IS NULL THEN previous.valid_until ELSE previous.updated_at END)>fresh_from
  OR (CASE WHEN closed IS NULL THEN p_intent ? 'closedApprovalSourceDigest'
    ELSE p_intent->>'closedApprovalSourceDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(closed),'UTF8')),'hex') END)
  OR p_intent->'preparation' IS DISTINCT FROM previous.intent->'preparation'
  OR p_intent->'pendingExpiry' IS DISTINCT FROM previous.intent->'pendingExpiry'
  OR fresh_until<=fresh_from OR fresh_until<=clock_timestamp()
  OR previous.intent_digest<>sha256(convert_to(openpc.signing_canonical_json(previous.intent),'UTF8'))
  OR previous.activation_operation_id IS NULL
  OR previous.activation_evidence_digest<>sha256(previous.activation_evidence_cbor)
  OR octet_length(previous.activation_cose)=0 OR jsonb_array_length(previous.lease_bindings)<>2
  OR NOT EXISTS(SELECT 1 FROM control.platform_recovery_enrollment e
    WHERE e.participant_id=participant AND e.privacy_domain_id=previous.privacy_domain_id AND e.enrollment_id=enrollment
     AND e.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' AND e.document->>'schemaVersion'='4'
     AND e.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
     AND e.state='ACTIVE' AND e.valid_from<=fresh_from AND e.valid_until>=fresh_until
     AND (closed IS NOT NULL OR (e.row_version=previous.enrollment_revision AND e.document_digest=previous.enrollment_digest))
     AND p_intent->>'enrollmentRevision'=e.row_version::text
     AND p_intent->>'enrollmentDigest'='sha256:'||encode(e.document_digest,'hex')
     AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(e.document#>'{source,originalAdministrators}') a
       WHERE NOT ((a#>'{usable,administration,actionIntentIds}') ? 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1')
         OR NOT ((a#>'{grantable,administration,actionIntentIds}') ? 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1')))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_intent#>'{preparation,administrators}') a
    WHERE (a#>>'{usable,validUntilNs}')::numeric<floor(extract(epoch FROM fresh_until)*1000000000)
      OR (a#>>'{grantable,validUntilNs}')::numeric<floor(extract(epoch FROM fresh_until)*1000000000))
 THEN RETURN false; END IF;
 SELECT * INTO STRICT original FROM control.mutation_candidate m WHERE m.participant_id=participant
  AND m.privacy_domain_id=previous.privacy_domain_id AND m.mutation_candidate_id::text=p_intent#>>'{approvalContinuation,candidateId}'
  AND m.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' AND m.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  AND m.resource_type='participant' AND m.operation_class='UPDATE' AND m.expected_revision=0
  AND m.resource_id::text=p_intent#>>'{preparation,replacementId}' AND m.candidate_document=p_intent->'preparation'
  AND m.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(m.candidate_document),'UTF8'))
  AND m.maker_principal_id::text=p_intent#>>'{preparation,administrators,0,principalId}'
  AND m.state IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') AND m.consumed_operation_id IS NULL
  AND m.expires_at<=fresh_from;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(previous.lease_bindings) b
   WHERE b->>'envelopeId'=original.maker_authority_envelope_id::text
    AND b->>'assignmentId'=original.maker_assignment_id::text AND b->>'principalId'=original.maker_principal_id::text
    AND b->>'principalEpoch'=original.maker_principal_epoch::text)
  OR (SELECT count(*) FROM control.platform_recovery_proof p WHERE p.participant_id=participant
    AND p.privacy_domain_id=previous.privacy_domain_id AND p.recovery_id=previous.recovery_id
    AND p.intent_digest=previous.intent_digest AND p.verified_at<=previous.activated_at)<>4
  OR NOT EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=participant
    AND event.privacy_domain_id=previous.privacy_domain_id AND event.aggregate_type='platform-recovery'
    AND event.aggregate_id=previous.recovery_id AND event.aggregate_sequence=1
    AND event.event_type='openpc.identity.platform-recovery.activated.v1'
    AND event.payload_cbor=previous.activation_evidence_cbor AND event.payload_digest=previous.activation_evidence_digest
    AND event.cose_sign1=previous.activation_cose) THEN RETURN false; END IF;
 SELECT * INTO STRICT approval FROM control.approval_request a WHERE a.participant_id=participant
  AND a.privacy_domain_id=previous.privacy_domain_id AND a.approval_request_id::text=p_intent#>>'{approvalContinuation,approvalId}'
  AND a.subject_type='CONFIGURATION_CANDIDATE' AND a.subject_id=original.mutation_candidate_id
  AND a.subject_digest=original.candidate_digest AND a.subject_version=original.expected_revision
  AND a.action_intent_id=original.action_intent_id AND a.maker_principal_id=original.maker_principal_id
  AND a.checker_principal_id::text=p_intent#>>'{preparation,administrators,1,principalId}'
  AND a.checker_principal_id<>a.maker_principal_id AND a.state IN ('OPEN','APPROVED','EXPIRED');
 witness:=jsonb_build_object('schema','pc.identity.platform-prepare-approval-continuation','schemaVersion',1,
  'recoveryId',previous.recovery_id::text,'intentDigest','sha256:'||encode(previous.intent_digest,'hex'),
  'activationOperationId',previous.activation_operation_id::text,
  'activationReceiptDigest','sha256:'||encode(previous.activation_evidence_digest,'hex'),
  'candidateId',original.mutation_candidate_id::text,'approvalId',approval.approval_request_id::text,
  'candidateDigest','sha256:'||encode(original.candidate_digest,'hex'),'businessKey',original.idempotency_key,'attempt',original.attempt::text);
 IF p_intent->'approvalContinuation' IS DISTINCT FROM witness THEN RETURN false; END IF;
 IF openpc.platform_recovery_pending_approval_history_current(participant,enrollment,previous.recovery_id,
  original.mutation_candidate_id,approval.approval_request_id,(p_intent->>'recoveryId')::uuid) IS DISTINCT FROM true
 THEN RETURN false; END IF;
 SELECT count(*) INTO descendants FROM control.mutation_candidate c WHERE c.participant_id=participant
  AND c.privacy_domain_id=previous.privacy_domain_id AND c.predecessor_candidate_id=original.mutation_candidate_id;
 IF descendants>1 THEN RETURN false; END IF;
 IF descendants=1 THEN
  SELECT * INTO STRICT child FROM control.mutation_candidate c WHERE c.participant_id=participant
   AND c.privacy_domain_id=previous.privacy_domain_id AND c.predecessor_candidate_id=original.mutation_candidate_id;
  IF ROW(child.action_intent_id,child.catalog_operation_id,child.resource_type,child.operation_class,child.resource_id,
    child.candidate_document,child.candidate_digest,child.expected_revision,child.idempotency_key,child.maker_principal_id)
   IS DISTINCT FROM ROW(original.action_intent_id,original.catalog_operation_id,original.resource_type,original.operation_class,
    original.resource_id,original.candidate_document,original.candidate_digest,original.expected_revision,original.idempotency_key,original.maker_principal_id)
   OR child.attempt<>original.attempt+1 OR child.predecessor_approval_id<>approval.approval_request_id
   OR child.resume_operation_id IS NULL OR child.resume_request->>'command' IS DISTINCT FROM 'RESUME'
   OR NOT EXISTS(SELECT 1 FROM control.authority_envelope receiving WHERE receiving.participant_id=participant
     AND receiving.authority_envelope_id=child.maker_authority_envelope_id AND receiving.representation='RECOVERY_V1'
     AND receiving.recovery_case_id::text=p_intent->>'recoveryId')
   OR EXISTS(SELECT 1 FROM control.mutation_candidate further WHERE further.predecessor_candidate_id=child.mutation_candidate_id)
  THEN RETURN false; END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.participant_id=participant
   AND r.privacy_domain_id=previous.privacy_domain_id AND r.replacement_id=original.resource_id) THEN
  RETURN descendants=1
   AND EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.participant_id=participant
    AND r.privacy_domain_id=previous.privacy_domain_id AND r.replacement_id=original.resource_id
    AND r.state='WITHDRAWING' AND r.row_version=1 AND r.candidate=p_intent->'preparation'
    AND r.prepare_candidate_id=child.mutation_candidate_id
    AND ((child.state='CONSUMED' AND child.consumed_operation_id=r.prepare_operation_id)
      OR (child.state='APPROVED' AND child.consumed_operation_id IS NULL
        AND r.prepare_operation_id=openpc.current_operation_id()
        AND EXISTS(SELECT 1 FROM control.idempotency_record running WHERE running.participant_id=participant
          AND running.privacy_domain_id=previous.privacy_domain_id AND running.operation_id=r.prepare_operation_id
          AND running.principal_id=child.maker_principal_id AND running.action_intent_id=child.action_intent_id
          AND running.catalog_operation_id=child.catalog_operation_id AND running.idempotency_key=child.idempotency_key
          AND running.input_digest=child.candidate_digest AND running.terminal_state='RESERVED'))));
 END IF;
 RETURN (descendants=0 OR child.consumed_operation_id IS NULL)
  AND NOT EXISTS(SELECT 1 FROM control.idempotency_record effect WHERE effect.participant_id=participant
   AND effect.privacy_domain_id=previous.privacy_domain_id AND effect.principal_id=original.maker_principal_id
   AND effect.action_intent_id=original.action_intent_id AND effect.catalog_operation_id=original.catalog_operation_id
   AND effect.idempotency_key=original.idempotency_key
   AND NOT (descendants=1 AND child.state='APPROVED' AND effect.operation_id=openpc.current_operation_id()
     AND effect.terminal_state='RESERVED' AND effect.input_digest=child.candidate_digest))
  AND NOT EXISTS(SELECT 1 FROM control.mutation_evidence effect WHERE effect.participant_id=participant
   AND effect.privacy_domain_id=previous.privacy_domain_id AND effect.aggregate_type='platform-scope-replacement'
   AND effect.aggregate_id=original.resource_id AND effect.catalog_operation_id=original.catalog_operation_id)
  AND NOT EXISTS(SELECT 1 FROM control.outbox_event effect WHERE effect.participant_id=participant
   AND effect.privacy_domain_id=previous.privacy_domain_id AND effect.aggregate_type='platform-scope-replacement'
   AND effect.aggregate_id=original.resource_id);
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR numeric_value_out_of_range
 THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_pending_approval_current(uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_pending_approval_current(uuid,uuid,jsonb)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;

-- Independently enforce ordered owner-generated correspondence and temporal-only renewal.
CREATE OR REPLACE FUNCTION openpc.platform_recovery_pending_expiry_intent_current(participant uuid,enrollment uuid,intent jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE source control.platform_recovery_enrollment; original control.platform_scope_replacement;
 expected jsonb; proposed jsonb; witness jsonb; link jsonb; old_names text[]; new_names text[];
 path text[]; names jsonb; i integer; dimension text; scope jsonb; next_scope jsonb;
 from_ns numeric; until_ns numeric; parent_until numeric; administrator_ms numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF intent#>>'{pendingExpiry,schemaVersion}'='2' AND (intent ? 'approvalContinuation' OR intent ? 'closedApprovalSourceDigest') THEN
  RETURN false;
 END IF;
 IF intent ? 'approvalContinuation' THEN
  RETURN openpc.platform_recovery_pending_approval_current(participant,enrollment,intent);
 END IF;
 SELECT * INTO STRICT source FROM control.platform_recovery_enrollment e WHERE e.enrollment_id=enrollment
  AND e.participant_id=participant AND e.privacy_domain_id=openpc.current_privacy_domain_id()
  AND e.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' AND e.document->>'schemaVersion'='4';
 witness:=source.document#>'{source,pendingExpiry}'; link:=witness->'preparation'; proposed:=intent->'preparation';
 SELECT * INTO STRICT original FROM control.platform_scope_replacement r WHERE r.participant_id=participant
  AND r.privacy_domain_id=source.privacy_domain_id AND r.replacement_id::text=link->>'replacementId';
 IF intent->'pendingExpiry' IS DISTINCT FROM witness OR intent ? 'continuation' OR intent ? 'supersession'
  OR openpc.platform_recovery_pending_expiry_source_current(participant,enrollment,link,original.candidate) IS DISTINCT FROM true
  OR (original.state='SUPERSEDED' AND original.superseded_by::text IS DISTINCT FROM proposed->>'replacementId')
 THEN RETURN false; END IF;
 from_ns:=floor(extract(epoch FROM (intent->>'validFrom')::timestamptz)*1000000000);
 until_ns:=floor(extract(epoch FROM (intent->>'validUntil')::timestamptz)*1000000000);
 parent_until:=(original.candidate#>>'{successorScope,validUntilNs}')::numeric;
 IF openpc.platform_scope_pending_root_bridge_current(original,source.root_epoch,source.root_revision,source.root_digest) THEN
  SELECT (openpc.business_cbor(parent.scope_cbor)->>'4')::numeric INTO STRICT parent_until FROM control.root_expiry_recovery_scope parent
   WHERE parent.platform_context_id=source.platform_context_id AND parent.platform_authority_epoch=source.root_epoch AND parent.admission_digest=source.root_digest;
 END IF;
 administrator_ms:=coalesce((intent#>>'{lifetimes,administratorMs}')::numeric,3600000);
 IF from_ns<floor(extract(epoch FROM source.valid_from)*1000000000) OR until_ns<=from_ns
  OR until_ns>floor(extract(epoch FROM source.valid_until)*1000000000) OR until_ns>parent_until
  OR administrator_ms<=0 THEN RETURN false; END IF;
 old_names:=ARRAY[original.candidate->>'replacementId',original.candidate#>>'{administrators,0,envelopeId}',
   original.candidate#>>'{administrators,0,assignmentId}',original.candidate#>>'{administrators,1,envelopeId}',
   original.candidate#>>'{administrators,1,assignmentId}'];
 new_names:=ARRAY[proposed->>'replacementId',proposed#>>'{administrators,0,envelopeId}',proposed#>>'{administrators,0,assignmentId}',
   proposed#>>'{administrators,1,envelopeId}',proposed#>>'{administrators,1,assignmentId}'];
 IF cardinality(new_names)<>5 OR array_position(new_names,NULL) IS NOT NULL
  OR (SELECT count(DISTINCT name) FROM unnest(new_names) name)<>5 OR new_names&&old_names
  OR jsonb_array_length(proposed->'administrators')<>2 THEN RETURN false; END IF;
 expected:=jsonb_set(original.candidate,'{replacementId}',to_jsonb(new_names[1]));
 IF openpc.platform_scope_pending_root_bridge_current(original,source.root_epoch,source.root_revision,source.root_digest) THEN
  expected:=jsonb_set(expected,'{predecessorEpoch}',to_jsonb(source.root_epoch::text));
  expected:=jsonb_set(expected,'{expectedRootRevision}',to_jsonb(source.root_revision::text));
  expected:=jsonb_set(expected,'{predecessorDigest}',to_jsonb('sha256:'||encode(source.root_digest,'hex')));
 END IF;
 expected:=jsonb_set(expected,'{reason}',to_jsonb('Renew the exact expired partial Platform administrator handoff under fresh independent recovery custody.'::text));
 expected:=jsonb_set(expected,'{supersedes}',jsonb_build_object('replacementId',original.replacement_id::text,
   'expectedRevision','1','successorDigest','sha256:'||encode(original.successor_digest,'hex')));
 FOR i IN 0..1 LOOP
  expected:=jsonb_set(expected,ARRAY['administrators',i::text,'envelopeId'],to_jsonb(new_names[i*2+2]));
  expected:=jsonb_set(expected,ARRAY['administrators',i::text,'assignmentId'],to_jsonb(new_names[i*2+3]));
 END LOOP;
 FOR i IN -1..1 LOOP
  FOREACH dimension IN ARRAY (CASE WHEN i=-1 THEN ARRAY['successorScope'] ELSE ARRAY['usable','grantable'] END) LOOP
   path:=CASE WHEN i=-1 THEN ARRAY['successorScope'] ELSE ARRAY['administrators',i::text,dimension] END;
   scope:=expected#>path; next_scope:=proposed#>path;
   IF (next_scope->>'validUntilNs')::numeric>parent_until
    OR (next_scope->>'validUntilNs')::numeric<=floor(extract(epoch FROM clock_timestamp())*1000000000)
    OR (i=-1 AND ((next_scope->>'validFromNs')::numeric<(scope->>'validFromNs')::numeric
      OR (next_scope->>'validFromNs')::numeric>floor(extract(epoch FROM clock_timestamp())*1000000000)))
    OR (i>=0 AND ((next_scope->>'validFromNs')::numeric<from_ns
      OR (next_scope->>'validUntilNs')::numeric<until_ns
      OR (next_scope->>'validUntilNs')::numeric>from_ns+administrator_ms*1000000))
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
REVOKE ALL ON FUNCTION openpc.platform_recovery_pending_expiry_intent_current(uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_pending_expiry_intent_current(uuid,uuid,jsonb)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.require_platform_recovery_continuation_enrollment()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE original_preparation jsonb;
BEGIN
 IF NEW.source_purpose='ROOT_EXPIRY_RECOVERY' AND NEW.document ? 'uneffectedPredecessor' THEN
  SELECT c.intent->'preparation' INTO STRICT original_preparation FROM control.platform_recovery_case c
   WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
    AND c.recovery_id::text=NEW.document#>>'{uneffectedPredecessor,recoveryId}'
    AND c.enrollment_id::text=NEW.document#>>'{uneffectedPredecessor,enrollmentId}';
  IF openpc.platform_recovery_uneffected_source_current(NEW.participant_id,NEW.enrollment_id,
    NEW.document->'uneffectedPredecessor',original_preparation) IS DISTINCT FROM true
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  RETURN NULL;
 END IF;
 IF NEW.source_purpose NOT IN ('ROOT_EXPIRY_RECOVERY_CONTINUATION','PENDING_ADMINISTRATION_EXPIRY_RECOVERY') THEN RETURN NULL; END IF;
 SELECT c.intent->'preparation' INTO STRICT original_preparation FROM control.platform_recovery_case c
  WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
   AND c.recovery_id::text=coalesce(NEW.document#>>'{source,continuation,recoveryId}',NEW.document#>>'{source,pendingExpiry,preparation,recoveryId}')
   AND c.enrollment_id::text=coalesce(NEW.document#>>'{source,continuation,enrollmentId}',NEW.document#>>'{source,pendingExpiry,preparation,enrollmentId}');
 IF NEW.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' THEN
  IF NEW.document#>'{source}' ? 'closedApproval' AND
    openpc.platform_recovery_closed_approval_source_current(NEW.participant_id,NEW.enrollment_id,null::uuid) IS DISTINCT FROM true
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  IF openpc.platform_recovery_pending_expiry_source_current(NEW.participant_id,NEW.enrollment_id,
    NEW.document#>'{source,pendingExpiry,preparation}',original_preparation) IS DISTINCT FROM true
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  RETURN NULL;
 END IF;
 IF openpc.platform_recovery_continuation_current(NEW.participant_id,NEW.enrollment_id,
    NEW.document#>'{source,continuation}',original_preparation) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF NEW.document#>'{source}' ? 'activatedHandoff' AND
  openpc.platform_recovery_completion_admission_current(NEW.participant_id,NEW.enrollment_id) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.require_platform_recovery_continuation_enrollment() FROM PUBLIC;
DROP TRIGGER IF EXISTS platform_recovery_continuation_enrollment_completed ON control.platform_recovery_enrollment;
CREATE CONSTRAINT TRIGGER platform_recovery_continuation_enrollment_completed AFTER INSERT ON control.platform_recovery_enrollment
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_platform_recovery_continuation_enrollment();

CREATE OR REPLACE FUNCTION openpc.guard_platform_recovery_case()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
DECLARE source record; signer_repair boolean; review boolean;
BEGIN
 signer_repair:=NEW.signer_repair_enrollment_id IS NOT NULL;
 review:=TG_OP='UPDATE' AND NEW.reviewed_at IS NOT NULL AND OLD.reviewed_at IS NULL;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF TG_OP='INSERT' THEN
  IF EXISTS(SELECT 1 FROM control.platform_recovery_enrollment completion_source
   WHERE completion_source.participant_id=NEW.participant_id AND completion_source.privacy_domain_id=NEW.privacy_domain_id
    AND completion_source.enrollment_id=NEW.enrollment_id
    AND CASE WHEN completion_source.document#>'{source}' ? 'activatedHandoff' THEN
      NEW.intent->>'completionSourceDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(completion_source.document#>'{source,activatedHandoff}'),'UTF8')),'hex')
      OR NOT (NEW.intent ? 'continuation') OR NEW.intent ?| ARRAY['pendingExpiry','approvalContinuation','closedApprovalSourceDigest','supersession']
     ELSE NEW.intent ? 'completionSourceDigest' END)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  IF EXISTS(SELECT 1 FROM control.platform_recovery_enrollment source_enrollment WHERE source_enrollment.participant_id=NEW.participant_id
    AND source_enrollment.privacy_domain_id=NEW.privacy_domain_id AND source_enrollment.enrollment_id=NEW.enrollment_id
    AND CASE WHEN source_enrollment.document#>'{source}' ? 'closedApproval' THEN
      NEW.intent->>'closedApprovalSourceDigest' IS DISTINCT FROM
        'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(source_enrollment.document#>'{source,closedApproval}'),'UTF8')),'hex')
      OR NEW.intent->'approvalContinuation' IS DISTINCT FROM source_enrollment.document#>'{source,closedApproval,approval}'
     ELSE NEW.intent ? 'closedApprovalSourceDigest' END)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  IF NEW.state<>'DRAFT' OR NEW.row_version<>1 OR NEW.activated_at IS NOT NULL
   OR NEW.intent_digest<>sha256(convert_to(openpc.signing_canonical_json(NEW.intent),'UTF8'))
   OR NEW.intent->>'recoveryId' IS DISTINCT FROM NEW.recovery_id::text
   OR NEW.intent->>'enrollmentId' IS DISTINCT FROM coalesce(NEW.enrollment_id,NEW.signer_repair_enrollment_id)::text
   OR NEW.intent->>'enrollmentRevision' IS DISTINCT FROM NEW.enrollment_revision::text
   OR NEW.intent->>'enrollmentDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.enrollment_digest,'hex')
   OR (NEW.intent->>'validFrom')::timestamptz IS DISTINCT FROM NEW.valid_from
   OR (NEW.intent->>'validUntil')::timestamptz IS DISTINCT FROM NEW.valid_until
   OR NEW.intent->>'schema' IS NULL OR NEW.intent->>'schema' NOT IN ('pc.identity.platform-recovery-intent','pc.identity.discovery-certificate-recovery-intent','pc.identity.identity-envelope-recovery-intent')
   OR (NEW.intent->>'schemaVersion' IS DISTINCT FROM '1'
    AND NOT (NEW.intent->>'schemaVersion' IS NOT DISTINCT FROM '2'
     AND NEW.intent->>'schema' IS NOT DISTINCT FROM 'pc.identity.discovery-certificate-recovery-intent'
     AND NOT signer_repair))
   OR jsonb_array_length(NEW.planned_record_ids)<>(CASE WHEN signer_repair THEN 2 WHEN NEW.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent' THEN 0 ELSE 5 END)
   OR NEW.completion_operation_id IS NOT NULL OR NEW.completion_result IS NOT NULL
   OR num_nonnulls(NEW.reviewed_at,NEW.reviewed_by_principal_id,NEW.review_operation_id,NEW.review_note_digest)<>0
   OR (NEW.intent#>>'{lifetimes,profile}'='LOCAL_QA_10X' AND
       (current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1' OR
        current_setting('openpc.local_qa_duration_profile',true) IS DISTINCT FROM 'LOCAL_QA_10X'))
   OR (NEW.intent ? 'lifetimes' AND (NOT (NEW.intent->'lifetimes' ?& ARRAY['profile','leaseMs','administratorMs'])
      OR (NEW.intent->'lifetimes')-ARRAY['profile','leaseMs','administratorMs']<>'{}'::jsonb
      OR NEW.intent#>>'{lifetimes,profile}' NOT IN ('C17','LOCAL_QA','LOCAL_QA_10X')
      OR (NEW.intent#>>'{lifetimes,leaseMs}')::bigint NOT BETWEEN 1 AND CASE NEW.intent#>>'{lifetimes,profile}' WHEN 'LOCAL_QA_10X' THEN 9000000 WHEN 'LOCAL_QA' THEN 3600000 ELSE 900000 END
      OR (NEW.intent#>>'{lifetimes,administratorMs}')::bigint NOT BETWEEN 1 AND CASE NEW.intent#>>'{lifetimes,profile}' WHEN 'LOCAL_QA_10X' THEN 36000000 WHEN 'LOCAL_QA' THEN 86400000 ELSE 3600000 END
      OR NEW.valid_until>NEW.valid_from+((NEW.intent#>>'{lifetimes,leaseMs}')::bigint*interval '1 millisecond')))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 ELSE
  IF NEW.row_version<>OLD.row_version+1 OR NEW.updated_at<=OLD.updated_at
   OR (to_jsonb(NEW)-ARRAY['state','row_version','updated_at','activated_at','activation_operation_id',
      'activation_evidence_cbor','activation_evidence_digest','activation_cose','lease_bindings','completion_operation_id','completion_result',
      'reviewed_at','reviewed_by_principal_id','review_operation_id','review_note_digest']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['state','row_version','updated_at','activated_at','activation_operation_id',
      'activation_evidence_cbor','activation_evidence_digest','activation_cose','lease_bindings','completion_operation_id','completion_result',
      'reviewed_at','reviewed_by_principal_id','review_operation_id','review_note_digest'])
   OR NOT ((OLD.state='DRAFT' AND NEW.state IN ('REQUESTED','REVOKED','EXPIRED'))
      OR (OLD.state='REQUESTED' AND NEW.state IN ('ACTIVE','REVOKED','EXPIRED'))
      OR (OLD.state='ACTIVE' AND NEW.state IN ('COMPLETED','REVOKED','EXPIRED'))
      OR (review AND OLD.state=NEW.state AND OLD.state IN ('COMPLETED','REVOKED','EXPIRED')))
   OR (NEW.state<>'ACTIVE' AND (NEW.activated_at,NEW.activation_operation_id,NEW.activation_evidence_cbor,
      NEW.activation_evidence_digest,NEW.activation_cose,NEW.lease_bindings) IS DISTINCT FROM
     (OLD.activated_at,OLD.activation_operation_id,OLD.activation_evidence_cbor,
      OLD.activation_evidence_digest,OLD.activation_cose,OLD.lease_bindings))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 END IF;
 IF TG_OP='UPDATE' AND (NEW.completion_operation_id,NEW.completion_result) IS DISTINCT FROM (OLD.completion_operation_id,OLD.completion_result)
  AND NOT (OLD.state='ACTIVE' AND NEW.state='COMPLETED' AND NEW.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
   AND NEW.completion_operation_id IS NOT NULL AND NEW.completion_result IS NOT NULL) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF signer_repair THEN
  IF NEW.enrollment_id IS NOT NULL OR NEW.intent->>'schema' IS DISTINCT FROM 'pc.identity.identity-envelope-recovery-intent'
   OR NEW.intent->>'purpose' IS DISTINCT FROM 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY'
   OR NEW.intent->'postReviewRequired' IS DISTINCT FROM 'true'::jsonb
   OR NEW.intent-ARRAY['schema','schemaVersion','purpose','recoveryId','enrollmentId','enrollmentRevision','enrollmentDigest',
     'rotationId','creationOperationId','sourceParticipantEpoch','sourceIssuerPrincipalEpoch','sourceIssuerCredentialEpoch','lifetimes',
     'oldTrustDigest','selectionAdmissionVersion','validFrom','validUntil','postReviewRequired']<>'{}'::jsonb
   OR NEW.planned_record_ids IS DISTINCT FROM jsonb_build_array(NEW.intent->>'rotationId',NEW.intent->>'creationOperationId')
   OR NEW.intent->>'rotationId'=NEW.intent->>'creationOperationId'
   OR (NEW.intent ? 'lifetimes' AND NEW.intent#>>'{lifetimes,profile}' IS DISTINCT FROM 'LOCAL_QA_10X')
   OR NEW.valid_until>NEW.valid_from+coalesce((NEW.intent#>>'{lifetimes,leaseMs}')::bigint,900000)*interval '1 millisecond'
   OR (TG_OP='INSERT' AND EXISTS(SELECT 1 FROM control.platform_recovery_case prior
     JOIN control.identity_envelope_recovery_enrollment original ON original.enrollment_id=prior.signer_repair_enrollment_id
      AND original.participant_id=prior.participant_id
     JOIN control.identity_envelope_recovery_enrollment proposed ON proposed.enrollment_id=NEW.signer_repair_enrollment_id
      AND proposed.participant_id=NEW.participant_id
     WHERE prior.participant_id=NEW.participant_id AND original.document->>'issuerPrincipalId'=proposed.document->>'issuerPrincipalId'
      AND prior.activated_at IS NOT NULL AND prior.reviewed_at IS NULL))
   -- Completion is owned by the genuine consumer/old-key retirement suffix.
   OR NEW.state='COMPLETED' THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
  IF NEW.state='ACTIVE' AND (NEW.activation_operation_id IS DISTINCT FROM openpc.current_operation_id()
    OR NEW.activation_operation_id::text IS DISTINCT FROM NEW.lease_bindings->>'activationOperationId'
    OR NEW.activated_at IS DISTINCT FROM (NEW.lease_bindings->>'validFrom')::timestamptz
    OR NOT coalesce(openpc.identity_envelope_recovery_binding_current(NEW.signer_repair_enrollment_id,NEW.intent,NEW.lease_bindings),false)
    OR NOT openpc.identity_envelope_recovery_proofs_current(NEW,(NEW.lease_bindings#>>'{proofIds,3}')::uuid)) THEN
    RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 END IF;
 IF TG_OP='UPDATE' AND (NEW.reviewed_at,NEW.reviewed_by_principal_id,NEW.review_operation_id,NEW.review_note_digest)
   IS DISTINCT FROM (OLD.reviewed_at,OLD.reviewed_by_principal_id,OLD.review_operation_id,OLD.review_note_digest) THEN
  IF NOT review OR NOT signer_repair OR NEW.review_operation_id IS DISTINCT FROM openpc.current_operation_id()
    OR OLD.activated_at IS NULL OR OLD.state NOT IN ('COMPLETED','REVOKED','EXPIRED')
    OR NEW.reviewed_by_principal_id IS NULL OR NEW.review_note_digest IS NULL
    OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_recovery_enrollment enrollment
      JOIN control.mutation_candidate candidate ON candidate.participant_id=enrollment.participant_id
       AND candidate.privacy_domain_id=enrollment.privacy_domain_id AND candidate.catalog_operation_id='ID-OP-RECOVERY-POST-REVIEW'
       AND candidate.resource_id=NEW.recovery_id AND candidate.maker_principal_id=NEW.reviewed_by_principal_id
       AND candidate.state='APPROVED' AND candidate.candidate_document->>'recoveryId'=NEW.recovery_id::text
       AND sha256(convert_to(candidate.candidate_document->>'note','UTF8'))=NEW.review_note_digest
      JOIN control.approval_request approval ON approval.participant_id=candidate.participant_id
       AND approval.privacy_domain_id=candidate.privacy_domain_id AND approval.subject_id=candidate.mutation_candidate_id
       AND approval.subject_digest=candidate.candidate_digest AND approval.state='APPROVED'
      WHERE enrollment.enrollment_id=NEW.signer_repair_enrollment_id
       AND NEW.reviewed_by_principal_id::text NOT IN (enrollment.document->>'issuerPrincipalId',enrollment.document#>>'{recoveryPrincipal,principalId}')
       AND approval.checker_principal_id::text NOT IN (enrollment.document->>'issuerPrincipalId',enrollment.document#>>'{recoveryPrincipal,principalId}')
       AND approval.checker_principal_id<>NEW.reviewed_by_principal_id
       AND EXISTS(SELECT 1 FROM control.approval_decision_record decision WHERE decision.participant_id=approval.participant_id
         AND decision.privacy_domain_id=approval.privacy_domain_id AND decision.approval_request_id=approval.approval_request_id
         AND decision.approver_principal_id=approval.checker_principal_id AND decision.decision='APPROVE'
         AND decision.candidate_digest=candidate.candidate_digest)) THEN
    RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY-REVIEW'; END IF;
 END IF;
 IF NEW.state IN ('DRAFT','REQUESTED','ACTIVE') THEN
  IF (NEW.intent ? 'continuation' OR NEW.intent ? 'pendingExpiry') AND NEW.planned_record_ids IS DISTINCT FROM
    jsonb_build_array(NEW.intent#>>'{preparation,replacementId}',NEW.intent#>>'{preparation,administrators,0,envelopeId}',
      NEW.intent#>>'{preparation,administrators,0,assignmentId}',NEW.intent#>>'{preparation,administrators,1,envelopeId}',
      NEW.intent#>>'{preparation,administrators,1,assignmentId}') THEN
   RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  IF NEW.intent ? 'continuation' AND NOT coalesce(openpc.platform_recovery_continuation_current(NEW.participant_id,NEW.enrollment_id,NEW.intent->'continuation',NEW.intent->'preparation'),false) THEN
   RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  IF NEW.intent ? 'pendingExpiry' AND openpc.platform_recovery_pending_expiry_intent_current(NEW.participant_id,NEW.enrollment_id,NEW.intent) IS DISTINCT FROM true THEN
   RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  IF NEW.intent ? 'supersession' AND NOT openpc.platform_recovery_supersession_current(NEW.participant_id,NEW.enrollment_id,NEW.intent->'supersession',NEW.intent->'preparation') THEN
   RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  IF signer_repair THEN
   SELECT * INTO source FROM control.identity_envelope_recovery_enrollment e WHERE e.enrollment_id=NEW.signer_repair_enrollment_id
    AND e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.state='ACTIVE'
    AND e.row_version=NEW.enrollment_revision AND e.document_digest=NEW.enrollment_digest
    AND e.valid_from<=clock_timestamp() AND e.valid_until>clock_timestamp()
    AND openpc.identity_envelope_recovery_source_current(e.enrollment_id);
  ELSE
   SELECT * INTO source FROM control.platform_recovery_enrollment e WHERE e.enrollment_id=NEW.enrollment_id
    AND e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.state='ACTIVE'
    AND e.row_version=NEW.enrollment_revision AND e.document_digest=NEW.enrollment_digest
    AND e.valid_from<=clock_timestamp() AND e.valid_until>clock_timestamp();
  END IF;
  IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  IF signer_repair AND (
    NEW.intent->>'sourceParticipantEpoch' IS DISTINCT FROM source.document->>'issuerParticipantEpoch'
    OR NEW.intent->>'sourceIssuerPrincipalEpoch' IS DISTINCT FROM source.document->>'issuerPrincipalEpoch'
    OR NEW.intent->>'sourceIssuerCredentialEpoch' IS DISTINCT FROM source.document->>'issuerCredentialEpoch'
    OR NEW.intent->>'oldTrustDigest' IS DISTINCT FROM source.document->>'oldTrustDigest'
    OR NEW.intent->>'selectionAdmissionVersion' IS DISTINCT FROM source.document->>'selectionAdmissionVersion') THEN
   RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
  IF NOT signer_repair THEN
   IF (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY') IS DISTINCT FROM (NEW.intent ? 'pendingExpiry') THEN
    RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
   IF (source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION') IS DISTINCT FROM (NEW.intent ? 'continuation') THEN
    RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
  END IF;
  IF NEW.intent->>'schema' IS DISTINCT FROM (CASE source.document->>'schema'
     WHEN 'pc.identity.platform-recovery-enrollment' THEN 'pc.identity.platform-recovery-intent'
     WHEN 'pc.identity.discovery-certificate-recovery-enrollment' THEN 'pc.identity.discovery-certificate-recovery-intent'
     WHEN 'pc.identity.identity-envelope-recovery-enrollment' THEN 'pc.identity.identity-envelope-recovery-intent' ELSE NULL END)
    OR NEW.valid_until>source.valid_until OR NEW.valid_until<=clock_timestamp()
   OR (source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' AND current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1')
   OR (NEW.intent#>>'{lifetimes,profile}' IN ('LOCAL_QA','LOCAL_QA_10X') AND source.document->>'assurance' IS DISTINCT FROM 'LOCAL_QA_VIRTUAL_AUTHENTICATOR') THEN
   RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 END IF;
 IF NEW.state IN ('REQUESTED','ACTIVE') THEN
  IF NOT EXISTS(SELECT 1 FROM control.platform_recovery_proof proof
     JOIN control.platform_recovery_challenge h ON h.participant_id=proof.participant_id
      AND h.privacy_domain_id=proof.privacy_domain_id AND h.recovery_id=proof.recovery_id
      AND h.challenge_id=proof.challenge_id AND h.proof_id=proof.proof_id
     WHERE proof.recovery_id=NEW.recovery_id
   AND proof.participant_id=NEW.participant_id AND proof.privacy_domain_id=NEW.privacy_domain_id AND proof.phase='REQUEST'
   AND proof.principal_id::text=source.document#>>'{recoveryPrincipal,principalId}' AND proof.intent_digest=NEW.intent_digest
   AND proof.verified_at<=clock_timestamp()
    AND proof.verified_at>clock_timestamp()-make_interval(secs=>h.verified_proof_max_age_ms/1000.0)
    AND (h.verified_proof_max_age_ms=300000 OR (h.verified_proof_max_age_ms=3000000
      AND h.duration_profile='LOCAL_QA_10X' AND h.expires_at>clock_timestamp()))) THEN
   RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 END IF;
 IF NEW.state='ACTIVE' THEN
  IF NEW.activation_evidence_digest<>sha256(NEW.activation_evidence_cbor)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(source.document->'custodians') custodian
    WHERE NOT EXISTS(SELECT 1 FROM control.platform_recovery_proof proof
     JOIN control.platform_recovery_challenge h ON h.participant_id=proof.participant_id
      AND h.privacy_domain_id=proof.privacy_domain_id AND h.recovery_id=proof.recovery_id
      AND h.challenge_id=proof.challenge_id AND h.proof_id=proof.proof_id
     WHERE proof.recovery_id=NEW.recovery_id
     AND proof.participant_id=NEW.participant_id AND proof.privacy_domain_id=NEW.privacy_domain_id AND proof.phase='APPROVE'
     AND proof.principal_id::text=custodian->>'principalId' AND proof.credential_id::text=custodian->>'credentialId'
     AND proof.principal_epoch::text=custodian->>'principalEpoch' AND proof.credential_epoch::text=custodian->>'credentialEpoch'
     AND proof.intent_digest=NEW.intent_digest AND proof.verified_at<=clock_timestamp()
    AND proof.verified_at>clock_timestamp()-make_interval(secs=>h.verified_proof_max_age_ms/1000.0)
    AND (h.verified_proof_max_age_ms=300000 OR (h.verified_proof_max_age_ms=3000000
      AND h.duration_profile='LOCAL_QA_10X' AND h.expires_at>clock_timestamp()))))
   OR NOT EXISTS(SELECT 1 FROM control.platform_recovery_proof proof
     JOIN control.platform_recovery_challenge h ON h.participant_id=proof.participant_id
      AND h.privacy_domain_id=proof.privacy_domain_id AND h.recovery_id=proof.recovery_id
      AND h.challenge_id=proof.challenge_id AND h.proof_id=proof.proof_id
     WHERE proof.recovery_id=NEW.recovery_id
    AND proof.participant_id=NEW.participant_id AND proof.privacy_domain_id=NEW.privacy_domain_id AND proof.phase='ACTIVATE'
    AND proof.principal_id::text=source.document#>>'{recoveryPrincipal,principalId}' AND proof.intent_digest=NEW.intent_digest
    AND proof.verified_at<=clock_timestamp()
    AND proof.verified_at>clock_timestamp()-make_interval(secs=>h.verified_proof_max_age_ms/1000.0)
    AND (h.verified_proof_max_age_ms=300000 OR (h.verified_proof_max_age_ms=3000000
      AND h.duration_profile='LOCAL_QA_10X' AND h.expires_at>clock_timestamp()))) THEN
   RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS platform_recovery_case_guard ON control.platform_recovery_case;
CREATE TRIGGER platform_recovery_case_guard BEFORE INSERT OR UPDATE OR DELETE ON control.platform_recovery_case
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_recovery_case();

CREATE OR REPLACE FUNCTION openpc.guard_platform_recovery_challenge()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF TG_OP='UPDATE' AND (OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL OR NEW.proof_id IS NULL
   OR (to_jsonb(NEW)-ARRAY['consumed_at','proof_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['consumed_at','proof_id'])
   OR NOT EXISTS(SELECT 1 FROM control.platform_recovery_proof p WHERE p.proof_id=NEW.proof_id AND p.challenge_id=NEW.challenge_id
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
   OR NOT EXISTS(SELECT 1 FROM control.platform_recovery_case r
     WHERE r.recovery_id=NEW.recovery_id AND r.participant_id=NEW.participant_id
      AND r.privacy_domain_id=NEW.privacy_domain_id AND r.intent_digest=NEW.intent_digest
      AND r.intent#>>'{lifetimes,profile}'='LOCAL_QA_10X' AND NEW.expires_at<=r.valid_until)
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
DROP TRIGGER IF EXISTS platform_recovery_challenge_guard ON control.platform_recovery_challenge;
CREATE TRIGGER platform_recovery_challenge_guard BEFORE INSERT OR UPDATE OR DELETE ON control.platform_recovery_challenge
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_recovery_challenge();

CREATE OR REPLACE FUNCTION openpc.guard_platform_recovery_proof()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-RECOVERY'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.platform_recovery_challenge c JOIN control.platform_recovery_case r
   ON r.recovery_id=c.recovery_id AND r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id
  JOIN (SELECT enrollment_id,participant_id,privacy_domain_id,state,row_version,document_digest,document,valid_from,valid_until,
    CASE document->>'schema' WHEN 'pc.identity.platform-recovery-enrollment' THEN 'pc.identity.platform-recovery-intent'
      WHEN 'pc.identity.discovery-certificate-recovery-enrollment' THEN 'pc.identity.discovery-certificate-recovery-intent' END purpose
    FROM control.platform_recovery_enrollment
   UNION ALL SELECT enrollment_id,participant_id,privacy_domain_id,state,row_version,document_digest,document,valid_from,valid_until,
    'pc.identity.identity-envelope-recovery-intent' purpose FROM control.identity_envelope_recovery_enrollment) source
   ON source.enrollment_id=coalesce(r.enrollment_id,r.signer_repair_enrollment_id) AND source.purpose=r.intent->>'schema'
   AND source.participant_id=r.participant_id AND source.privacy_domain_id=r.privacy_domain_id
   AND source.state='ACTIVE' AND source.row_version=r.enrollment_revision AND source.document_digest=r.enrollment_digest
   AND (r.signer_repair_enrollment_id IS NULL OR openpc.identity_envelope_recovery_source_current(source.enrollment_id))
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
DROP TRIGGER IF EXISTS platform_recovery_proof_guard ON control.platform_recovery_proof;
CREATE TRIGGER platform_recovery_proof_guard BEFORE INSERT OR UPDATE OR DELETE ON control.platform_recovery_proof
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_recovery_proof();
`;

export const platformRecoveryGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_supersession_current(uuid,uuid,jsonb,jsonb) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.is_platform_recovery_executor(uuid) TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.lock_platform_recovery_enrollment(uuid) TO openpc_control_runtime,openpc_control_platform_runtime;

REVOKE ALL ON control.platform_recovery_enrollment,control.platform_recovery_case,control.platform_recovery_challenge,
 control.platform_recovery_proof FROM openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader;
GRANT SELECT ON control.platform_recovery_enrollment,control.platform_recovery_case,control.platform_recovery_challenge,
 control.platform_recovery_proof TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT,UPDATE ON control.platform_recovery_case,control.platform_recovery_challenge TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT ON control.platform_recovery_proof TO openpc_control_runtime,openpc_control_platform_runtime;
`;
