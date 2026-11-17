import { identityEnvelopeContext } from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';

/** Generated with the owning schema. Typed activation is admitted only when
 * the current operation owns an OBSERVED provider-signed activation journal. */
export const identityEnvelopeProposalGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_identity_envelope_representation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' AND (NEW.representation,NEW.participant_id,NEW.issuer_participant_id,NEW.issuer_privacy_domain_id,NEW.principal_id)
   IS DISTINCT FROM (OLD.representation,OLD.participant_id,OLD.issuer_participant_id,OLD.issuer_privacy_domain_id,OLD.principal_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-REPRESENTATION';
 END IF;
 IF NEW.representation IN ('LEGACY','RECOVERY_V1') THEN RETURN NEW; END IF;
 IF NEW.representation<>'TYPED_V1' OR NEW.platform_context_id IS NULL OR NEW.platform_authority_epoch IS NULL
   OR NEW.valid_until IS NULL
   OR (NEW.state='ACTIVE') IS DISTINCT FROM (octet_length(NEW.cose_sign1)>0)
   OR NEW.semantic_digest<>sha256(NEW.semantic_cbor) THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-PROPOSAL'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'DRAFT' OR NEW.row_version<>1 OR NEW.checker_principal_id IS NOT NULL THEN
   RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-INITIAL-STATE'; END IF;
 ELSE
  IF (to_jsonb(NEW)-'creator_participant_id'-'state'-'checker_principal_id'-'last_mutation_operation_id'-'row_version'-'updated_at'-'cose_sign1')
    IS DISTINCT FROM (to_jsonb(OLD)-'creator_participant_id'-'state'-'checker_principal_id'-'last_mutation_operation_id'-'row_version'-'updated_at'-'cose_sign1')
    OR NEW.row_version<>OLD.row_version+1 OR NEW.last_mutation_operation_id IS NULL
    OR NOT (
      (OLD.state='DRAFT' AND NEW.state='SUBMITTED' AND NEW.checker_principal_id IS NULL
       AND NEW.cose_sign1=OLD.cose_sign1)
      OR (OLD.state='SUBMITTED' AND NEW.state='APPROVED' AND NEW.checker_principal_id IS NOT NULL
       AND NEW.cose_sign1=OLD.cose_sign1)
      OR (OLD.state='APPROVED' AND NEW.state='ACTIVE' AND NEW.checker_principal_id=OLD.checker_principal_id
       AND EXISTS(SELECT 1 FROM control.identity_envelope_activation activation
        WHERE activation.participant_id=NEW.participant_id
         AND activation.privacy_domain_id=NEW.issuer_privacy_domain_id
         AND activation.envelope_id=NEW.authority_envelope_id
         AND activation.operation_id=openpc.current_operation_id()
         AND activation.state='OBSERVED' AND activation.row_version=3
         AND activation.cose_sign1=NEW.cose_sign1))
    ) THEN
   RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-SEALED-ACTIVATION-REQUIRED'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authority_envelope_representation ON control.authority_envelope;
CREATE TRIGGER authority_envelope_representation BEFORE INSERT OR UPDATE ON control.authority_envelope
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_envelope_representation();

CREATE OR REPLACE FUNCTION openpc.guard_identity_envelope_proposal()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE proposal jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-HISTORY'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'DRAFT' OR NEW.row_version<>1 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-INITIAL-STATE'; END IF;
 ELSE
  IF (to_jsonb(NEW)-'state'-'submission_operation_id'-'submission_intent_digest'-'submission_approval_id'-'submission_maker'-'submission_checker'-'submission_checker_authority'-'row_version')
    IS DISTINCT FROM (to_jsonb(OLD)-'state'-'submission_operation_id'-'submission_intent_digest'-'submission_approval_id'-'submission_maker'-'submission_checker'-'submission_checker_authority'-'row_version')
    OR NEW.row_version<>OLD.row_version+1
    OR NOT ((OLD.state='DRAFT' AND NEW.state='SUBMITTED') OR (OLD.state='SUBMITTED' AND NEW.state='APPROVED')) THEN
   RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-HISTORY'; END IF;
  IF OLD.state='SUBMITTED' AND (NEW.submission_operation_id,NEW.submission_intent_digest,NEW.submission_approval_id,NEW.submission_maker)
    IS DISTINCT FROM (OLD.submission_operation_id,OLD.submission_intent_digest,OLD.submission_approval_id,OLD.submission_maker) THEN
   RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-SUBMISSION-IMMUTABLE'; END IF;
 END IF;
 proposal:=openpc.business_cbor(NEW.proposal_cbor);
 IF jsonb_typeof(proposal) IS DISTINCT FROM 'object'
   OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(proposal) key) IS DISTINCT FROM ARRAY['0','1','10','2','3','4','5','6','7','8','9']
   OR proposal->'0' IS DISTINCT FROM jsonb_build_object('bytes','${identityEnvelopeContext.definitionDigest.slice(7)}')
   OR proposal->'1' IS DISTINCT FROM jsonb_build_object('bytes',replace(NEW.envelope_id::text,'-',''))
   OR proposal->>'2' IS DISTINCT FROM '1'
   OR proposal->'3' IS DISTINCT FROM jsonb_build_object('bytes',replace(NEW.target_participant_id::text,'-',''))
   OR proposal#>'{10,2,1}' IS DISTINCT FROM jsonb_build_object('bytes',replace(NEW.participant_id::text,'-',''))
   OR proposal#>'{10,2,3}' IS DISTINCT FROM jsonb_build_object('bytes',replace(NEW.maker_principal_id::text,'-',''))
   OR NEW.issuer_authority#>>'{binding,participantId}' IS DISTINCT FROM NEW.participant_id::text
   OR NEW.issuer_authority#>>'{binding,principalId}' IS DISTINCT FROM NEW.maker_principal_id::text
   OR NEW.issuer_authority#>>'{durable,grant,privacyDomainId}' IS DISTINCT FROM NEW.privacy_domain_id::text THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-PROVENANCE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_envelope_proposal_history ON control.identity_envelope_proposal;
CREATE TRIGGER identity_envelope_proposal_history BEFORE INSERT OR UPDATE OR DELETE ON control.identity_envelope_proposal
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_envelope_proposal();

CREATE OR REPLACE FUNCTION openpc.require_identity_envelope_proposal()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE original_mode text; original_participant uuid; original_privacy uuid;
 operation uuid; action text;
	 p control.identity_envelope_proposal%ROWTYPE; envelope control.authority_envelope%ROWTYPE;
	 valid_source boolean; activation_cose bytea;
BEGIN
 IF TG_TABLE_NAME='authority_envelope' THEN
  -- Recovery provenance is enforced by guard_platform_recovery_envelope and
  -- its immutable signed case bindings. It has no ordinary typed issuer or
  -- proposal sidecar; typed envelopes must retain the checks below.
  IF NEW.representation IN ('LEGACY','RECOVERY_V1') THEN RETURN NULL; END IF;
 END IF;
 -- Legacy initialization has no typed governance context. Typed rows still
 -- require every ordinary context field before any scoped lookup or switch.
 original_mode:=current_setting('openpc.context_mode');
 original_participant:=openpc.current_participant_id(); original_privacy:=openpc.current_privacy_domain_id();
 operation:=openpc.current_operation_id(); action:=openpc.current_action_intent_id();
 IF TG_TABLE_NAME='authority_envelope' THEN
  -- Resolve only the envelope's immutable original issuer; no tenant OR-policy.
  PERFORM openpc.set_request_context('PARTICIPANT',NEW.issuer_participant_id,NEW.issuer_privacy_domain_id,operation,action,true);
  SELECT * INTO p FROM control.identity_envelope_proposal WHERE participant_id=NEW.issuer_participant_id
    AND privacy_domain_id=NEW.issuer_privacy_domain_id AND envelope_id=NEW.authority_envelope_id;
 ELSE
  PERFORM openpc.set_request_context('PARTICIPANT',NEW.participant_id,NEW.privacy_domain_id,operation,action,true);
  SELECT * INTO p FROM control.identity_envelope_proposal WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND envelope_id=NEW.envelope_id;
 END IF;
 IF p.envelope_id IS NULL THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-SIDECAR'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',p.participant_id,p.privacy_domain_id,operation,action,true);
 SELECT EXISTS(SELECT 1 FROM control.mutation_candidate candidate
   JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id AND evidence.privacy_domain_id=candidate.privacy_domain_id
     AND evidence.operation_id=candidate.consumed_operation_id AND evidence.candidate_digest=candidate.candidate_digest
     AND evidence.principal_id=p.maker_principal_id AND evidence.approval_request_id=p.create_approval_id
   JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id AND receipt.privacy_domain_id=candidate.privacy_domain_id
     AND receipt.operation_id=candidate.consumed_operation_id AND receipt.terminal_state='COMMITTED'
     AND receipt.result_payload->>'id'=p.envelope_id::text
     AND receipt.result_payload->>'semanticDigest'='sha256:'||encode(p.proposal_digest,'hex')
   WHERE candidate.participant_id=p.participant_id AND candidate.privacy_domain_id=p.privacy_domain_id
     AND candidate.mutation_candidate_id=p.create_candidate_id AND candidate.consumed_operation_id=p.create_operation_id
     AND candidate.state='CONSUMED' AND candidate.catalog_operation_id='ID-OP-ENVELOPE-CREATE'
     AND candidate.resource_id=p.envelope_id AND candidate.maker_principal_id=p.maker_principal_id
     AND candidate.candidate_document->>'schema'='pc.identity.authority-envelope-proposal'
     AND candidate.candidate_document->>'envelopeId'=p.envelope_id::text
     AND candidate.candidate_document->>'participantId'=p.target_participant_id::text
     AND candidate.maker_session_id::text=p.issuer_authority#>>'{binding,sessionId}'
     AND candidate.maker_session_epoch::text=p.issuer_authority#>>'{binding,sessionEpoch}'
     AND candidate.maker_participant_epoch::text=p.issuer_authority#>>'{binding,participantEpoch}'
     AND candidate.maker_principal_epoch::text=p.issuer_authority#>>'{binding,principalEpoch}'
     AND candidate.maker_assignment_id::text=p.issuer_authority#>>'{binding,assignmentId}'
     AND candidate.maker_assignment_row_version::text=p.issuer_authority#>>'{binding,assignmentVersion}'
     AND candidate.maker_authority_envelope_id::text=p.issuer_authority#>>'{binding,authorityEnvelopeId}'
     AND candidate.maker_authority_epoch::text=p.issuer_authority#>>'{binding,authorityEpoch}'
     AND candidate.maker_delegation_epoch::text=p.issuer_authority#>>'{binding,delegationEpoch}') INTO valid_source;
 IF NOT coalesce(valid_source,false) THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-CREATE-PROVENANCE'; END IF;
 IF p.state<>'DRAFT' THEN
  SELECT EXISTS(SELECT 1 FROM control.approval_request request
    JOIN control.idempotency_record receipt ON receipt.participant_id=request.participant_id AND receipt.privacy_domain_id=request.privacy_domain_id
      AND receipt.operation_id=p.submission_operation_id AND receipt.input_digest=p.submission_intent_digest
      AND receipt.action_intent_id='ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1' AND receipt.terminal_state='COMMITTED'
      AND receipt.principal_id=p.maker_principal_id AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||request.approval_request_id::text
    JOIN control.mfa_challenge challenge ON challenge.participant_id=request.participant_id AND challenge.principal_id=p.maker_principal_id
      AND challenge.mfa_challenge_id=(p.submission_maker->>'stepUpChallengeId')::uuid
      AND challenge.session_id=(p.submission_maker#>>'{authority,sessionId}')::uuid
      AND challenge.action_intent_id='ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1' AND challenge.resource_digest=p.submission_intent_digest
      AND challenge.resource_id=p.envelope_id::text
      AND challenge.used_operation_id=p.submission_operation_id AND challenge.used_at IS NOT NULL
      AND challenge.used_at>=challenge.consumed_at AND challenge.used_at<challenge.expires_at
      AND challenge.used_at<challenge.consumed_at+interval '5 minutes'
    JOIN control.mutation_evidence verification ON verification.participant_id=challenge.participant_id
      AND verification.privacy_domain_id=p.privacy_domain_id AND verification.principal_id=p.maker_principal_id
      AND verification.mfa_challenge_id=challenge.mfa_challenge_id AND verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
      AND verification.evidence_digest=decode(substr(p.submission_maker->>'stepUpEvidenceDigest',8),'hex')
      AND verification.signer_credential_id=(p.submission_maker->>'signerCredentialId')::uuid
      AND challenge.signer_credential_id=verification.signer_credential_id
      AND challenge.signer_credential_epoch::text=p.submission_maker->>'signerCredentialEpoch'
    WHERE request.participant_id=p.participant_id AND request.privacy_domain_id=p.privacy_domain_id
      AND request.approval_request_id=p.submission_approval_id AND request.subject_type='AUTHORITY_ENVELOPE'
      AND request.subject_id=p.envelope_id AND request.subject_digest=p.proposal_digest AND request.subject_version=1
      AND request.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' AND request.maker_principal_id=p.maker_principal_id
      AND p.submission_maker->'authority'=p.issuer_authority->'binding'
      AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=p.participant_id AND event.privacy_domain_id=p.privacy_domain_id
        AND event.aggregate_type='authority-envelope' AND event.aggregate_id=p.envelope_id
        AND event.event_type='openpc.identity.authority-envelope.submitted.v1' AND event.payload_digest=verification.evidence_digest
        AND event.payload_cbor=verification.evidence_cbor AND event.cose_sign1=verification.cose_sign1)
      AND ((p.state='SUBMITTED' AND request.state='OPEN') OR (p.state='APPROVED' AND request.state='APPROVED'))) INTO valid_source;
  IF NOT coalesce(valid_source,false) THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-SUBMISSION-PROVENANCE'; END IF;
 END IF;
 IF p.state='APPROVED' THEN
  SELECT EXISTS(SELECT 1 FROM control.approval_decision_record decision
    JOIN control.mfa_challenge challenge ON challenge.participant_id=decision.participant_id AND challenge.mfa_challenge_id=decision.mfa_challenge_id
      AND challenge.principal_id=decision.approver_principal_id AND challenge.action_intent_id='ACT-POLICY_APPROVE_REQUEST-V1'
      AND challenge.session_id=decision.approver_session_id
      AND challenge.resource_digest=decision.decision_digest AND challenge.used_at IS NOT NULL
      AND challenge.resource_id=decision.approval_request_id::text
      AND challenge.signer_credential_id=decision.signer_credential_id
      AND challenge.signer_credential_epoch=decision.signer_credential_epoch
      AND challenge.used_at>=challenge.consumed_at AND challenge.used_at<challenge.expires_at
      AND challenge.used_at<challenge.consumed_at+interval '5 minutes'
    JOIN control.mutation_evidence verification ON verification.participant_id=decision.participant_id
      AND verification.privacy_domain_id=decision.privacy_domain_id AND verification.principal_id=decision.approver_principal_id
      AND verification.mfa_challenge_id=challenge.mfa_challenge_id AND verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
      AND verification.bound_participant_epoch=decision.approver_participant_epoch
      AND verification.bound_principal_epoch=decision.approver_principal_epoch
      AND verification.signer_credential_id=decision.signer_credential_id
      AND verification.evidence_cbor=decision.evidence_cbor AND verification.cose_sign1=decision.cose_sign1
    WHERE decision.participant_id=p.participant_id AND decision.privacy_domain_id=p.privacy_domain_id
      AND decision.approval_request_id=p.submission_approval_id AND decision.decision='APPROVE'
      AND decision.candidate_digest=p.proposal_digest AND decision.aggregate_version=1
      AND decision.approver_principal_id<>p.maker_principal_id
      AND decision.approver_principal_id::text=p.submission_checker#>>'{authority,principalId}'
      AND decision.participant_id::text=p.submission_checker#>>'{authority,participantId}'
      AND decision.approver_participant_epoch::text=p.submission_checker#>>'{authority,participantEpoch}'
      AND decision.approver_principal_epoch::text=p.submission_checker#>>'{authority,principalEpoch}'
      AND decision.approver_session_id::text=p.submission_checker#>>'{authority,sessionId}'
      AND decision.approver_session_epoch::text=p.submission_checker#>>'{authority,sessionEpoch}'
      AND decision.approver_assignment_id::text=p.submission_checker#>>'{authority,assignmentId}'
      AND decision.approver_assignment_row_version::text=p.submission_checker#>>'{authority,assignmentVersion}'
      AND decision.approver_authority_envelope_id::text=p.submission_checker#>>'{authority,authorityEnvelopeId}'
      AND decision.approver_envelope_epoch::text=p.submission_checker#>>'{authority,authorityEpoch}'
      AND decision.approver_delegation_epoch::text=p.submission_checker#>>'{authority,delegationEpoch}'
      AND p.submission_checker_authority->'binding'=p.submission_checker->'authority'
      AND p.submission_checker_authority#>'{durable,grant}' @> jsonb_build_object(
        'principalId',decision.approver_principal_id::text,'participantEpoch',decision.approver_participant_epoch::text,
        'principalEpoch',decision.approver_principal_epoch::text,'assignmentId',decision.approver_assignment_id::text,
        'assignmentRowVersion',decision.approver_assignment_row_version::text,'authorityEnvelopeId',decision.approver_authority_envelope_id::text,
        'authorityEpoch',decision.approver_envelope_epoch::text,'delegationEpoch',decision.approver_delegation_epoch::text,
        'privacyDomainId',p.privacy_domain_id::text,'actionIntentId','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','resourceId',p.envelope_id::text)
      AND decision.mfa_challenge_id::text=p.submission_checker->>'stepUpChallengeId'
      AND decision.mfa_challenge_id::text<>p.submission_maker->>'stepUpChallengeId'
      AND decision.signer_credential_id::text=p.submission_checker->>'signerCredentialId'
      AND decision.signer_credential_epoch::text=p.submission_checker->>'signerCredentialEpoch'
      AND sha256(decision.evidence_cbor)=decode(substr(p.submission_checker->>'stepUpEvidenceDigest',8),'hex')
      AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=p.participant_id AND event.privacy_domain_id=p.privacy_domain_id
        AND event.aggregate_type='authority-envelope' AND event.aggregate_id=p.envelope_id
        AND event.event_type='openpc.identity.authority-envelope.approved.v1' AND event.payload_digest=sha256(decision.evidence_cbor)
        AND event.payload_cbor=decision.evidence_cbor AND event.cose_sign1=decision.cose_sign1)) INTO valid_source;
	  IF NOT coalesce(valid_source,false) THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-APPROVAL-PROVENANCE'; END IF;
	 END IF;
	 IF p.state='APPROVED' THEN
	  SELECT activation.cose_sign1 INTO activation_cose
	    FROM control.identity_envelope_activation activation
	   WHERE activation.participant_id=p.participant_id AND activation.privacy_domain_id=p.privacy_domain_id
	     AND activation.envelope_id=p.envelope_id AND activation.operation_id=operation
	     AND activation.state='COMMITTED' AND activation.row_version=4;
	 END IF;
	 PERFORM openpc.set_request_context('PARTICIPANT',p.target_participant_id,NULL,operation,action,false);
 SELECT * INTO envelope FROM control.authority_envelope WHERE participant_id=p.target_participant_id AND authority_envelope_id=p.envelope_id;
 IF envelope.representation IS DISTINCT FROM 'TYPED_V1' OR envelope.issuer_participant_id IS DISTINCT FROM p.participant_id
   OR envelope.issuer_privacy_domain_id IS DISTINCT FROM p.privacy_domain_id
	 OR envelope.maker_principal_id IS DISTINCT FROM p.maker_principal_id OR envelope.semantic_cbor IS DISTINCT FROM p.proposal_cbor
	 OR envelope.semantic_digest IS DISTINCT FROM p.proposal_digest
	 OR NOT (
	   (envelope.state::text=p.state AND envelope.row_version=p.row_version)
	   OR (p.state='APPROVED' AND envelope.state='ACTIVE' AND envelope.row_version=p.row_version+1
	     AND octet_length(envelope.cose_sign1)>0
	     AND activation_cose=envelope.cose_sign1)
	 )
	 OR (p.state='APPROVED' AND envelope.checker_principal_id::text IS DISTINCT FROM p.submission_checker#>>'{authority,principalId}')
   THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-TARGET-BINDING'; END IF;
 PERFORM openpc.set_request_context(original_mode,original_participant,original_privacy,operation,action,original_privacy IS NOT NULL);
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS identity_envelope_proposal_provenance ON control.identity_envelope_proposal;
CREATE CONSTRAINT TRIGGER identity_envelope_proposal_provenance AFTER INSERT OR UPDATE ON control.identity_envelope_proposal
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_identity_envelope_proposal();
DROP TRIGGER IF EXISTS identity_envelope_target_provenance ON control.authority_envelope;
CREATE CONSTRAINT TRIGGER identity_envelope_target_provenance AFTER INSERT OR UPDATE ON control.authority_envelope
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_identity_envelope_proposal();
`;
