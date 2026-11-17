// Generated alongside the owning Drizzle schema. Terminal custody cannot reopen after handoff.
export const bootstrapCustodyGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.require_bootstrap_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE original_mode text:=current_setting('openpc.context_mode');
 original_participant uuid:=nullif(current_setting('openpc.participant_id'),'')::uuid;
 original_privacy uuid:=nullif(current_setting('openpc.privacy_domain_id'),'')::uuid;
 original_operation uuid:=current_setting('openpc.operation_id')::uuid;
 original_action text:=current_setting('openpc.action_intent_id');
 valid_source boolean; valid_target boolean;
BEGIN
 IF NEW.candidate_digest<>sha256(convert_to(openpc.signing_canonical_json(NEW.candidate),'UTF8'))
   OR NEW.configuration_digest<>sha256(convert_to(openpc.signing_canonical_json(NEW.candidate->'configuration'),'UTF8'))
   OR NEW.first_admin_invite_ttl_ms<>(NEW.candidate#>>'{configuration,participant.first_admin_invite_ttl}')::integer
   OR NEW.platform_participant_id::text IS DISTINCT FROM NEW.issuance_authority->>'participantId'
   OR NEW.maker_principal_id::text IS DISTINCT FROM NEW.issuance_authority#>>'{signers,0,principalId}'
   OR NEW.checker_principal_id::text IS DISTINCT FROM NEW.issuance_authority#>>'{signers,1,principalId}'
   OR NEW.created_operation_id::text IS DISTINCT FROM NEW.issuance_authority->>'operationId'
   OR NEW.mandate_id::text IS DISTINCT FROM NEW.candidate->>'mandateId'
   OR NEW.invitation_id::text IS DISTINCT FROM NEW.candidate->>'invitationId' THEN RAISE EXCEPTION 'PC-AUTH-0002-BOOTSTRAP-PROVENANCE'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.platform_participant_id,(NEW.issuance_authority->>'privacyDomainId')::uuid,original_operation,original_action,true);
 SELECT EXISTS(
  SELECT 1 FROM control.mutation_candidate candidate
  JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id AND evidence.privacy_domain_id=candidate.privacy_domain_id
    AND evidence.operation_id=candidate.consumed_operation_id AND evidence.candidate_digest=candidate.candidate_digest
    AND evidence.principal_id=NEW.maker_principal_id AND evidence.checker_principal_id=NEW.checker_principal_id
    AND evidence.approval_request_id=(NEW.issuance_authority->>'approvalRequestId')::uuid
  JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id AND receipt.operation_id=candidate.consumed_operation_id
    AND receipt.terminal_state='COMMITTED' AND receipt.result_payload#>>'{result,bootstrap,issuanceAuthorityDigest}'=
      'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.issuance_authority),'UTF8')),'hex')
  WHERE candidate.participant_id=NEW.platform_participant_id AND candidate.resource_id=NEW.participant_id
    AND candidate.candidate_document->>'participantId'=NEW.participant_id::text
    AND candidate.candidate_document->'firstAdministrator'=NEW.candidate
    AND candidate.candidate_digest=decode(substr(NEW.issuance_authority->>'candidateDigest',8),'hex')
    AND candidate.consumed_operation_id=NEW.created_operation_id AND candidate.state='CONSUMED'
    AND candidate.catalog_operation_id='ID-OP-PARTICIPANT-CREATE'
 ) INTO valid_source;
 IF NOT coalesce(valid_source,false) THEN
  PERFORM openpc.set_request_context(original_mode,original_participant,original_privacy,original_operation,original_action,original_privacy IS NOT NULL);
  RAISE EXCEPTION 'PC-AUTH-0002-BOOTSTRAP-SOURCE-PROVENANCE';
 END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.participant_id,(NEW.candidate->>'privacyDomainId')::uuid,original_operation,original_action,true);
 SELECT EXISTS(
  SELECT 1 FROM control.participant_invitation invitation JOIN control.authority_role role
    ON role.participant_id=invitation.participant_id AND role.authority_role_id=invitation.intended_role_id
      AND role.authority_role_id=(NEW.candidate->>'roleId')::uuid AND role.bootstrap_mandate_id=NEW.mandate_id
      AND role.bootstrap_platform_participant_id=NEW.platform_participant_id
      AND to_jsonb(role.action_intent_ids)=NEW.candidate->'actionIntentIds'
  WHERE invitation.participant_id=NEW.participant_id AND invitation.invitation_id=NEW.invitation_id
    AND invitation.bootstrap_mandate_id=NEW.mandate_id AND invitation.bootstrap_platform_participant_id=NEW.platform_participant_id
    AND invitation.privacy_domain_id=(NEW.candidate->>'privacyDomainId')::uuid
    AND invitation.recipient_issuer=NEW.candidate->>'recipientIssuer'
    AND invitation.recipient_subject=NEW.candidate->>'recipientSubject'
    AND invitation.recipient_audience=NEW.candidate->>'recipientAudience'
 ) INTO valid_target;
 PERFORM openpc.set_request_context(original_mode,original_participant,original_privacy,original_operation,original_action,original_privacy IS NOT NULL);
 IF NOT coalesce(valid_source AND valid_target,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-BOOTSTRAP-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS bootstrap_provenance ON control.participant_bootstrap_custody;
CREATE CONSTRAINT TRIGGER bootstrap_provenance AFTER INSERT OR UPDATE ON control.participant_bootstrap_custody
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_bootstrap_provenance();
CREATE OR REPLACE FUNCTION openpc.guard_bootstrap_custody()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0002'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'ACTIVE' OR NEW.participant_epoch<>0 OR NEW.custody_generation<>1 OR NEW.row_version<>1
    OR NEW.candidate_membership_id IS NOT NULL OR NEW.accepted_membership_id IS NOT NULL
    OR NOT EXISTS(SELECT 1 FROM control.participant WHERE participant_id=NEW.participant_id AND state='PROVISIONING' AND authority_epoch=0)
    OR EXISTS(SELECT 1 FROM control.principal WHERE participant_id=NEW.participant_id AND state='ACTIVE') THEN
   RAISE EXCEPTION 'PC-AUTH-0002';
  END IF;
 ELSE
  IF OLD.state NOT IN ('ACTIVE','CLAIM_PENDING') OR NEW.row_version<>OLD.row_version+1
    OR (to_jsonb(NEW)-'custody_generation'-'state'-'candidate_membership_id'-'candidate_session_id'-'accepted_membership_id'-'accepted_operation_id'-'accepted_intent_digest'-'acceptance_result'-'closed_at'-'row_version')
      IS DISTINCT FROM (to_jsonb(OLD)-'custody_generation'-'state'-'candidate_membership_id'-'candidate_session_id'-'accepted_membership_id'-'accepted_operation_id'-'accepted_intent_digest'-'acceptance_result'-'closed_at'-'row_version')
    OR NOT ((OLD.state='ACTIVE' AND NEW.state='CLAIM_PENDING' AND NEW.custody_generation=OLD.custody_generation AND NEW.candidate_membership_id IS NOT NULL AND NEW.expires_at>clock_timestamp())
      OR (OLD.state='CLAIM_PENDING' AND NEW.state='ACCEPTED' AND NEW.custody_generation=OLD.custody_generation AND NEW.candidate_membership_id=OLD.candidate_membership_id
        AND NEW.candidate_session_id=OLD.candidate_session_id AND NEW.accepted_membership_id=OLD.candidate_membership_id AND NEW.expires_at>clock_timestamp())
      OR (NEW.state='ACTIVE' AND NEW.custody_generation=OLD.custody_generation+1 AND NEW.candidate_membership_id IS NULL AND NEW.candidate_session_id IS NULL AND NEW.expires_at>clock_timestamp())
      OR (NEW.state IN ('CANCELLED','RECOVERY_REQUIRED') AND NEW.custody_generation=OLD.custody_generation AND NEW.candidate_membership_id IS NOT DISTINCT FROM OLD.candidate_membership_id AND NEW.candidate_session_id IS NOT DISTINCT FROM OLD.candidate_session_id)) THEN RAISE EXCEPTION 'PC-AUTH-0002'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS bootstrap_custody_lifecycle ON control.participant_bootstrap_custody;
CREATE TRIGGER bootstrap_custody_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.participant_bootstrap_custody
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_bootstrap_custody();

CREATE OR REPLACE FUNCTION openpc.require_bootstrap_custody_change()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE original_mode text:=current_setting('openpc.context_mode');
 original_participant uuid:=nullif(current_setting('openpc.participant_id'),'')::uuid;
 original_privacy uuid:=nullif(current_setting('openpc.privacy_domain_id'),'')::uuid;
 operation uuid:=current_setting('openpc.operation_id')::uuid;
 action text:=current_setting('openpc.action_intent_id');
 candidate_document jsonb; changed boolean:=NEW.custody_generation<>OLD.custody_generation;
BEGIN
 IF NOT changed AND NEW.state<>'CANCELLED' THEN RETURN NULL; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.platform_participant_id,(NEW.issuance_authority->>'privacyDomainId')::uuid,operation,action,true);
 SELECT candidate.candidate_document INTO candidate_document
 FROM control.mutation_candidate candidate
 JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id AND evidence.operation_id=candidate.consumed_operation_id
   AND evidence.candidate_digest=candidate.candidate_digest AND evidence.principal_id=NEW.maker_principal_id AND evidence.checker_principal_id=NEW.checker_principal_id
 JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id AND receipt.operation_id=candidate.consumed_operation_id
   AND receipt.terminal_state='COMMITTED' AND receipt.result_payload->>'operationId'=operation::text
   AND receipt.result_payload#>>'{result,mandateId}'=NEW.mandate_id::text
   AND receipt.result_payload#>>'{result,custodyGeneration}'=NEW.custody_generation::text
 WHERE candidate.participant_id=NEW.platform_participant_id AND candidate.resource_id=NEW.participant_id
   AND candidate.consumed_operation_id=operation AND candidate.state='CONSUMED'
   AND candidate.catalog_operation_id=CASE WHEN changed THEN 'ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE' ELSE 'ID-OP-PARTICIPANT-FIRST-ADMIN-REVOKE' END
   AND candidate.candidate_document->>'participantId'=NEW.participant_id::text
   AND candidate.candidate_document->>'mandateId'=NEW.mandate_id::text
   AND candidate.candidate_document->>'invitationId'=NEW.invitation_id::text
   AND candidate.candidate_document->>'custodyGeneration'=OLD.custody_generation::text
   AND candidate.candidate_document->>'tokenVersion'=OLD.custody_generation::text
   AND candidate.candidate_document->>'expectedRevision'=evidence.aggregate_version::text
   AND candidate.candidate_document#>>'{change,mutation}'=CASE WHEN changed THEN 'ROTATE' ELSE 'REVOKE' END;
 IF candidate_document IS NULL THEN RAISE EXCEPTION 'PC-AUTH-0002-BOOTSTRAP-CHANGE-PROVENANCE'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.participant_id,(NEW.candidate->>'privacyDomainId')::uuid,operation,action,true);
 IF NOT EXISTS(SELECT 1 FROM control.participant_invitation invitation JOIN control.participant_invitation_token token
   ON token.participant_id=invitation.participant_id AND token.invitation_id=invitation.invitation_id AND token.token_version=invitation.token_version
   WHERE invitation.participant_id=NEW.participant_id AND invitation.invitation_id=NEW.invitation_id
     AND invitation.expires_at=NEW.expires_at AND invitation.last_mutation_operation_id=operation
     AND invitation.token_version=NEW.custody_generation
     AND ((changed AND invitation.state='PENDING' AND token.operation_id=operation
       AND 'sha256:'||encode(token.token_digest,'hex')=candidate_document#>>'{change,tokenDigest}')
       OR (NOT changed AND invitation.state='REVOKED')))
   OR (OLD.candidate_session_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM control.session WHERE participant_id=NEW.participant_id
      AND session_id=OLD.candidate_session_id AND state='REVOKED'
      AND revoked_reason=CASE WHEN changed THEN 'first-administrator-custody-rotated' ELSE 'first-administrator-custody-revoked' END))
 THEN RAISE EXCEPTION 'PC-AUTH-0002-BOOTSTRAP-CHANGE-EFFECT'; END IF;
 PERFORM openpc.set_request_context(original_mode,original_participant,original_privacy,operation,action,original_privacy IS NOT NULL);
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS bootstrap_custody_change ON control.participant_bootstrap_custody;
CREATE CONSTRAINT TRIGGER bootstrap_custody_change AFTER UPDATE ON control.participant_bootstrap_custody
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_bootstrap_custody_change();
CREATE OR REPLACE FUNCTION openpc.require_first_admin_handoff()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.state='ACCEPTED' AND NOT EXISTS (
  SELECT 1 FROM control.participant participant
  JOIN control.principal principal ON principal.participant_id=participant.participant_id AND principal.principal_id=NEW.accepted_membership_id AND principal.state='ACTIVE'
  JOIN control.participant_membership member ON member.participant_id=principal.participant_id AND member.membership_id=principal.principal_id
  JOIN control.assignment assignment ON assignment.participant_id=participant.participant_id AND assignment.principal_id=principal.principal_id
    AND assignment.bootstrap_mandate_id=NEW.mandate_id AND assignment.state='ACTIVE' AND assignment.last_mutation_operation_id=NEW.accepted_operation_id
  JOIN control.authority_envelope envelope ON envelope.participant_id=assignment.participant_id AND envelope.authority_envelope_id=assignment.authority_envelope_id
    AND envelope.state='ACTIVE' AND envelope.bootstrap_mandate_id=NEW.mandate_id AND envelope.last_mutation_operation_id=NEW.accepted_operation_id
  JOIN control.mutation_evidence evidence ON evidence.participant_id=participant.participant_id AND evidence.operation_id=NEW.accepted_operation_id
    AND evidence.principal_id=NEW.accepted_membership_id AND evidence.catalog_operation_id='ID-OP-PARTICIPANT-FIRST-ADMIN-ACCEPT'
    AND evidence.candidate_digest=NEW.accepted_intent_digest
  JOIN control.outbox_event event ON event.participant_id=participant.participant_id AND event.aggregate_id=participant.participant_id
    AND event.event_type='openpc.identity.first-administrator.accepted.v1' AND event.payload_digest=evidence.evidence_digest
  WHERE participant.participant_id=NEW.participant_id AND participant.state='ACTIVE' AND participant.authority_epoch=NEW.participant_epoch+1
    AND NEW.acceptance_result IS NOT NULL AND NEW.closed_at IS NOT NULL
 ) THEN RAISE EXCEPTION 'PC-AUTH-0002'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS first_admin_handoff ON control.participant_bootstrap_custody;
CREATE CONSTRAINT TRIGGER first_admin_handoff AFTER INSERT OR UPDATE ON control.participant_bootstrap_custody
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_first_admin_handoff();
`;
