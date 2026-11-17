import { platformScopeRowsSql } from './current-platform-envelope.ts';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
} from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';
import { identityEnvelopeActivationSourceGuardsSql } from './identity-envelope-activation-source-guards.mjs';

/** Reservation, dispatch, observation and an atomic publication receipt. */
export const identityEnvelopeActivationGuardsSql = `
${identityEnvelopeActivationSourceGuardsSql}
CREATE OR REPLACE FUNCTION openpc.guard_identity_envelope_activation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p control.identity_envelope_proposal%ROWTYPE; c control.mutation_candidate%ROWTYPE;
 a control.approval_request%ROWTYPE; d control.approval_decision_record%ROWTYPE;
 i control.idempotency_record%ROWTYPE; k control.business_signing_key%ROWTYPE;
 payload jsonb; proposal jsonb; maker jsonb; checker jsonb; expected jsonb;
 submission_digest bytea; outer_cose jsonb; header jsonb; source_envelope uuid; now_ns numeric;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-HISTORY'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR NEW.operation_id IS DISTINCT FROM openpc.current_operation_id()
  OR openpc.current_action_intent_id()<>'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-CONTEXT'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'state'-'observation'-'cose_sign1'-'dispatched_at'-'observed_at'-'committed_at'-'row_version')
   IS DISTINCT FROM (to_jsonb(OLD)-'state'-'observation'-'cose_sign1'-'dispatched_at'-'observed_at'-'committed_at'-'row_version')
   OR NEW.row_version<>OLD.row_version+1
   OR NOT ((OLD.state='PREPARED' AND NEW.state='DISPATCHED')
    OR (OLD.state='DISPATCHED' AND NEW.state='OBSERVED')
    OR (OLD.state='OBSERVED' AND NEW.state='COMMITTED'))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-PHASE'; END IF;
  IF OLD.state='DISPATCHED' AND NEW.dispatched_at IS DISTINCT FROM OLD.dispatched_at
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-DISPATCH'; END IF;
 ELSE
  IF NEW.state<>'PREPARED' OR NEW.row_version<>1
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-INITIAL'; END IF;
 END IF;
 payload:=openpc.business_cbor(NEW.payload_cbor);
 SELECT * INTO STRICT p FROM control.identity_envelope_proposal WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND envelope_id=NEW.envelope_id;
 proposal:=openpc.business_cbor(p.proposal_cbor);
 IF p.state<>'APPROVED' OR p.row_version<>3 OR p.target_participant_id<>NEW.participant_id
  OR p.proposal_digest<>NEW.proposal_digest OR proposal->>'7'<>'1'
  OR payload->'0' IS DISTINCT FROM openpc.business_bytes(decode('${identityEnvelopeContext.definitionDigest.slice(7)}','hex'))
  OR payload->'1' IS DISTINCT FROM openpc.business_bytes(p.proposal_cbor)
  OR payload->'2' IS DISTINCT FROM openpc.business_bytes(p.proposal_digest)
  OR payload->>'6' IS DISTINCT FROM NEW.reserved_at_ns::text
  OR NEW.reserved_at_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-PROPOSAL'; END IF;
 SELECT * INTO STRICT i FROM control.idempotency_record WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND principal_id=NEW.principal_id
  AND action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' AND catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
  AND idempotency_key=NEW.idempotency_key AND idempotency_record_id=NEW.idempotency_record_id
  AND operation_id=NEW.operation_id AND input_digest=NEW.candidate_digest AND expected_aggregate_version=3
  AND terminal_state IS NULL;
 SELECT * INTO STRICT c FROM control.mutation_candidate WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND mutation_candidate_id=NEW.candidate_id
  AND resource_id=NEW.envelope_id AND expected_revision=3 AND (NEW.state='OBSERVED' OR state='APPROVED')
  AND maker_principal_id=NEW.principal_id AND candidate_digest=NEW.candidate_digest
  AND action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' AND catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
  AND candidate_document=jsonb_build_object('envelopeId',NEW.envelope_id::text);
 SELECT * INTO STRICT a FROM control.approval_request WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND approval_request_id=NEW.approval_request_id
  AND (NEW.state='OBSERVED' OR state='APPROVED') AND subject_type='CONFIGURATION_CANDIDATE' AND subject_id=c.mutation_candidate_id
  AND subject_digest=c.candidate_digest AND subject_version=3 AND maker_principal_id=NEW.principal_id
  AND action_intent_id=c.action_intent_id;
 SELECT * INTO STRICT d FROM control.approval_decision_record WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND approval_request_id=a.approval_request_id
  AND decision='APPROVE' AND candidate_digest=c.candidate_digest AND aggregate_version=3
  AND approver_principal_id<>NEW.principal_id;
 SELECT decision.decision_digest INTO STRICT submission_digest FROM control.approval_decision_record decision
  JOIN control.approval_request approved ON approved.participant_id=decision.participant_id
   AND approved.privacy_domain_id=decision.privacy_domain_id AND approved.approval_request_id=decision.approval_request_id
   AND approved.subject_type='AUTHORITY_ENVELOPE' AND approved.subject_id=p.envelope_id
   AND approved.subject_digest=p.proposal_digest AND approved.subject_version=1 AND approved.state='APPROVED'
  WHERE decision.participant_id=p.participant_id AND decision.privacy_domain_id=p.privacy_domain_id
   AND decision.approval_request_id=p.submission_approval_id AND decision.decision='APPROVE'
   AND decision.candidate_digest=p.proposal_digest AND decision.aggregate_version=1
   AND decision.approver_principal_id::text=p.submission_checker#>>'{authority,principalId}';
 SELECT jsonb_build_object('authority',NEW.maker_authority->'binding','stepUpChallengeId',challenge.mfa_challenge_id::text,
   'stepUpEvidenceDigest','sha256:'||encode(verification.evidence_digest,'hex'),
   'signerCredentialId',verification.signer_credential_id::text,'signerCredentialEpoch',challenge.signer_credential_epoch::text)
 INTO STRICT maker FROM control.mfa_challenge challenge JOIN control.mutation_evidence verification
  ON verification.participant_id=challenge.participant_id AND verification.privacy_domain_id=NEW.privacy_domain_id
   AND verification.principal_id=challenge.principal_id AND verification.mfa_challenge_id=challenge.mfa_challenge_id
   AND verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
   AND verification.webauthn_assertion_binding_digest=i.webauthn_assertion_binding_digest
   AND verification.evidence_digest=sha256(verification.evidence_cbor)
   AND verification.signer_credential_id=challenge.signer_credential_id
 WHERE challenge.participant_id=NEW.participant_id AND challenge.principal_id=NEW.principal_id
  AND challenge.mfa_challenge_id=NEW.maker_challenge_id AND challenge.resource_id=NEW.envelope_id::text
  AND challenge.resource_digest=NEW.candidate_digest AND challenge.action_intent_id=c.action_intent_id
  AND challenge.session_id=c.maker_session_id AND challenge.used_operation_id=NEW.operation_id
  AND challenge.used_at IS NOT NULL AND challenge.used_at>=challenge.consumed_at
  AND challenge.used_at<challenge.expires_at AND challenge.used_at<challenge.consumed_at+interval '5 minutes';
 checker:=jsonb_build_object('authority',NEW.checker_authority->'binding','stepUpChallengeId',d.mfa_challenge_id::text,
  'stepUpEvidenceDigest','sha256:'||encode(sha256(d.evidence_cbor),'hex'),'signerCredentialId',d.signer_credential_id::text,
  'signerCredentialEpoch',d.signer_credential_epoch::text);
 IF NEW.maker_authority#>>'{binding,principalId}' IS DISTINCT FROM c.maker_principal_id::text
  OR NEW.maker_authority#>>'{binding,sessionId}' IS DISTINCT FROM c.maker_session_id::text
  OR NEW.maker_authority#>>'{binding,sessionEpoch}' IS DISTINCT FROM c.maker_session_epoch::text
  OR NEW.maker_authority#>>'{binding,participantEpoch}' IS DISTINCT FROM c.maker_participant_epoch::text
  OR NEW.maker_authority#>>'{binding,principalEpoch}' IS DISTINCT FROM c.maker_principal_epoch::text
  OR NEW.maker_authority#>>'{binding,authorityEpoch}' IS DISTINCT FROM c.maker_authority_epoch::text
  OR NEW.maker_authority#>>'{binding,delegationEpoch}' IS DISTINCT FROM c.maker_delegation_epoch::text
  OR NEW.maker_authority#>>'{binding,assignmentId}' IS DISTINCT FROM c.maker_assignment_id::text
  OR NEW.maker_authority#>>'{binding,assignmentVersion}' IS DISTINCT FROM c.maker_assignment_row_version::text
  OR NEW.maker_authority#>>'{binding,authorityEnvelopeId}' IS DISTINCT FROM c.maker_authority_envelope_id::text
  OR NEW.checker_authority#>>'{binding,principalId}' IS DISTINCT FROM d.approver_principal_id::text
  OR NEW.checker_authority#>>'{binding,sessionId}' IS DISTINCT FROM d.approver_session_id::text
  OR NEW.checker_authority#>>'{binding,sessionEpoch}' IS DISTINCT FROM d.approver_session_epoch::text
  OR NEW.checker_authority#>>'{binding,participantEpoch}' IS DISTINCT FROM d.approver_participant_epoch::text
  OR NEW.checker_authority#>>'{binding,principalEpoch}' IS DISTINCT FROM d.approver_principal_epoch::text
  OR NEW.checker_authority#>>'{binding,authorityEpoch}' IS DISTINCT FROM d.approver_envelope_epoch::text
  OR NEW.checker_authority#>>'{binding,delegationEpoch}' IS DISTINCT FROM d.approver_delegation_epoch::text
  OR NEW.checker_authority#>>'{binding,assignmentId}' IS DISTINCT FROM d.approver_assignment_id::text
  OR NEW.checker_authority#>>'{binding,assignmentVersion}' IS DISTINCT FROM d.approver_assignment_row_version::text
  OR NEW.checker_authority#>>'{binding,authorityEnvelopeId}' IS DISTINCT FROM d.approver_authority_envelope_id::text
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-ACTOR'; END IF;
 expected:=jsonb_build_object('1',openpc.business_uuid(p.submission_operation_id),'2',openpc.business_uuid(p.envelope_id),
  '3',openpc.business_bytes(p.proposal_digest),'4',openpc.business_uuid(p.submission_approval_id),
  '5',openpc.business_bytes(submission_digest),'6',2,'7',3,
  '8',openpc.identity_envelope_actor_wire(p.submission_maker),'9',openpc.identity_envelope_actor_wire(p.submission_checker));
 IF payload->'3' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-SUBMISSION'; END IF;
 expected:=jsonb_build_object('domain','pc.identity.authority-envelope-activation-idempotency.v1',
  'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'envelopeId',NEW.envelope_id::text,
  'operationId',NEW.operation_id::text,'actionIntentId',c.action_intent_id,'catalogOperationId',c.catalog_operation_id,
  'candidateDigest','sha256:'||encode(c.candidate_digest,'hex'),'expectedApprovedVersion','3',
  'recordId',i.idempotency_record_id::text,'key',i.idempotency_key,'principalId',i.principal_id::text,
  'assertionBindingDigest','sha256:'||encode(i.webauthn_assertion_binding_digest,'hex'));
 expected:=jsonb_build_object('1',openpc.business_uuid(NEW.operation_id),'2',openpc.business_uuid(c.mutation_candidate_id),
  '3',openpc.business_bytes(c.candidate_digest),'4',openpc.business_uuid(a.approval_request_id),
  '5',openpc.business_bytes(d.decision_digest),'6',3,'7',4,
  '8',openpc.business_bytes(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8'))),
  '9',1,'10',1,
  '11',openpc.identity_envelope_actor_wire(maker),'12',openpc.identity_envelope_actor_wire(checker));
 IF payload->'4' IS DISTINCT FROM expected
  OR (SELECT count(DISTINCT value) FROM (VALUES (p.submission_maker->>'stepUpChallengeId'),
   (p.submission_checker->>'stepUpChallengeId'),(maker->>'stepUpChallengeId'),(checker->>'stepUpChallengeId')) proof(value))<>4
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-INTENT'; END IF;
 -- Observation resolves the immutable original key, even after selection or
 -- lifecycle changes. Current selection is a separate pre-dispatch fence.
 SELECT key.* INTO STRICT k FROM control.business_signing_key key
  WHERE key.participant_id=NEW.participant_id AND key.privacy_domain_id=NEW.privacy_domain_id
   AND key.environment_id=NEW.request->>'environmentId' AND key.signer_id=NEW.request->>'expectedFingerprint'
   AND key.signing_purpose_code=371;
 expected:=jsonb_build_object('1',k.environment_id,'2',openpc.business_uuid(k.participant_id),'3',openpc.business_uuid(k.privacy_domain_id),
  '4','pc.identity.authority-envelope.v1','5',1,'6',openpc.business_bytes(decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex')),
  '7',openpc.business_bytes(decode(substr(k.signer_id,8),'hex')),'8',k.secret_version,
  '9',openpc.business_uuid(k.workload_credential_id),'10',k.workload_credential_epoch,'11',openpc.business_bytes(k.trust_digest));
 IF payload->'5' IS DISTINCT FROM expected OR payload IS DISTINCT FROM jsonb_build_object('0',payload->'0','1',payload->'1',
  '2',payload->'2','3',payload->'3','4',payload->'4','5',expected,'6',NEW.reserved_at_ns)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-SIGNER'; END IF;
 expected:=jsonb_build_object('participantId',k.participant_id::text,'privacyDomainId',k.privacy_domain_id::text,
  'environmentId',k.environment_id,'workloadCredentialId',k.workload_credential_id::text,
  'workloadCredentialEpoch',k.workload_credential_epoch::text,'secretClass','SECRET-SIGNING-KEY','reference',k.secret_reference,
  'version',k.secret_version,'purpose','pc.cose.identity-authority-envelope.v1','purposeCode',371,'schemaId',24034,
  'schemaVersion',1,'schemaDefinitionDigest','${identityEnvelopeContext.definitionDigest}',
  'profileId','pc.identity.authority-envelope.v1','profileVersion',1,'profileDigest','${identityEnvelopeSigningProfileDigest}',
  'trustContextDigest','sha256:'||encode(k.trust_digest,'hex'),'method','SIGN_AUTHORITY_ENVELOPE',
  'callerWorkloadCredentialId',NEW.request->'callerWorkloadCredentialId','attemptId',NEW.attempt_id::text,
  'operationId',NEW.operation_id::text,'expectedFingerprint',k.signer_id,'payloadHex',encode(NEW.payload_cbor,'hex'));
 IF NEW.request IS DISTINCT FROM expected OR NEW.request_digest<>sha256(convert_to('pc.identity.authority-envelope-provider-request.v1','UTF8')
  ||decode('00','hex')||convert_to(openpc.signing_canonical_json(expected),'UTF8'))
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-REQUEST'; END IF;
 IF NEW.state IN ('PREPARED','DISPATCHED') THEN
  now_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
  IF (NEW.state='PREPARED' AND i.expires_at<=clock_timestamp())
   OR NOT openpc.identity_envelope_activation_intent_current(NEW.participant_id,NEW.privacy_domain_id,
    NEW.candidate_id,NEW.approval_request_id)
   OR (proposal#>>'{8,3}')::numeric>now_ns OR (proposal#>>'{8,4}')::numeric<=now_ns
   OR (proposal#>>'{9,3}')::numeric>now_ns OR (proposal#>>'{9,4}')::numeric<=now_ns
   OR NOT EXISTS(SELECT 1 FROM control.participant target WHERE target.participant_id=NEW.participant_id
     AND target.state='ACTIVE' AND target.authority_epoch=(proposal->>'4')::numeric
     AND target.authority_epoch=(proposal->>'5')::numeric)
   OR NOT openpc.identity_envelope_activation_authority_current(NEW.participant_id,NEW.privacy_domain_id,
    NEW.maker_authority,c.action_intent_id,NEW.envelope_id,NEW.state='PREPARED')
   OR NOT openpc.identity_envelope_activation_authority_current(NEW.participant_id,NEW.privacy_domain_id,
    NEW.checker_authority,c.action_intent_id,NEW.envelope_id,NEW.state='PREPARED')
   OR NOT ((openpc.identity_envelope_activation_authority_current(NEW.participant_id,NEW.privacy_domain_id,
    p.issuer_authority,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',NEW.envelope_id,false)
    AND openpc.identity_envelope_activation_authority_current(NEW.participant_id,NEW.privacy_domain_id,
    p.submission_checker_authority,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',NEW.envelope_id,false))
    OR (NEW.principal_id=p.maker_principal_id
      AND NEW.checker_authority#>>'{binding,principalId}'=p.submission_checker#>>'{authority,principalId}'
      AND openpc.platform_recovery_proposal_history_current(NEW.participant_id,NEW.privacy_domain_id,
      (NEW.maker_authority#>>'{binding,authorityEnvelopeId}')::uuid,NEW.envelope_id)
      AND openpc.platform_recovery_proposal_history_current(NEW.participant_id,NEW.privacy_domain_id,
      (NEW.checker_authority#>>'{binding,authorityEnvelopeId}')::uuid,NEW.envelope_id)))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-CURRENT-AUTHORITY'; END IF;
  FOREACH source_envelope IN ARRAY ARRAY[
   (p.issuer_authority#>>'{binding,authorityEnvelopeId}')::uuid,
   (p.submission_checker_authority#>>'{binding,authorityEnvelopeId}')::uuid,
   (NEW.maker_authority#>>'{binding,authorityEnvelopeId}')::uuid,
   (NEW.checker_authority#>>'{binding,authorityEnvelopeId}')::uuid] LOOP
   IF NOT EXISTS(SELECT 1 FROM control.authority_envelope source
     JOIN control.platform_context platform ON platform.platform_context_id=source.platform_context_id
      AND platform.authority_epoch=source.platform_authority_epoch AND platform.state='ACTIVE'
     JOIN ${platformScopeRowsSql} root ON root.platform_context_id=platform.platform_context_id
      AND root.platform_authority_epoch=platform.authority_epoch AND root.owner_participant_id=NEW.participant_id
     WHERE source.participant_id=NEW.participant_id AND source.authority_envelope_id=source_envelope
      AND source.state='ACTIVE' AND platform.owner_participant_id=NEW.participant_id
      AND openpc.business_uuid(platform.platform_context_id)=proposal#>'{10,3}'
      AND ((to_jsonb(platform.authority_epoch)=proposal#>'{10,4}'
         AND openpc.business_bytes(root.admission_digest)=proposal#>'{10,5}')
        OR EXISTS(SELECT 1 FROM control.platform_scope_replacement pending
          JOIN control.mutation_candidate create_intent ON create_intent.participant_id=pending.participant_id
            AND create_intent.mutation_candidate_id=p.create_candidate_id AND create_intent.state='CONSUMED'
          CROSS JOIN LATERAL jsonb_array_elements(pending.candidate->'administrators') admin
          WHERE pending.platform_context_id=platform.platform_context_id AND pending.participant_id=NEW.participant_id
            AND pending.privacy_domain_id=NEW.privacy_domain_id AND pending.state='WITHDRAWING' AND pending.row_version=1
            AND pending.predecessor_epoch=platform.authority_epoch AND pending.expected_root_revision=platform.row_version
            AND to_jsonb(pending.predecessor_epoch+1)=proposal#>'{10,4}'
            AND openpc.business_bytes(pending.successor_digest)=proposal#>'{10,5}'
            AND create_intent.candidate_document->>'platformScopeReplacementId'=pending.replacement_id::text
            AND admin->>'envelopeId'=NEW.envelope_id::text
            AND create_intent.candidate_document->'usable'=admin->'usable'
            AND create_intent.candidate_document->'grantable'=admin->'grantable'
            AND openpc.platform_scope_document_value(proposal->'8')=admin->'usable'
            AND openpc.platform_scope_document_value(proposal->'9')=admin->'grantable')))

   THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-ROOT'; END IF;
  END LOOP;
  IF k.valid_from_ns>now_ns OR k.valid_until_ns<=now_ns
   OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_signing_selection selection
     JOIN control.identity_envelope_signing_grant grant_row ON grant_row.participant_id=selection.participant_id
      AND grant_row.privacy_domain_id=selection.privacy_domain_id AND grant_row.signer_id=selection.signer_id
      AND grant_row.profile_digest=selection.profile_digest AND grant_row.signing_purpose_code=371
     WHERE selection.participant_id=k.participant_id AND selection.privacy_domain_id=k.privacy_domain_id
      AND selection.environment_id=k.environment_id AND selection.signer_id=k.signer_id AND selection.admission_version>0
      AND selection.profile_digest=decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex'))
   OR NOT EXISTS(SELECT 1 FROM control.business_signing_key_state lifecycle
     JOIN control.credential credential ON credential.participant_id=lifecycle.participant_id
      AND credential.credential_id=k.workload_credential_id AND credential.kind='WORKLOAD_MTLS'
      AND credential.credential_epoch=k.workload_credential_epoch AND credential.state='ACTIVE'
      AND credential.valid_from<=clock_timestamp() AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
     JOIN control.principal principal ON principal.participant_id=credential.participant_id
      AND principal.principal_id=credential.principal_id AND principal.kind='WORKLOAD' AND principal.state='ACTIVE'
      AND principal.authority_epoch=k.envelope_workload_principal_epoch
     JOIN control.participant participant ON participant.participant_id=principal.participant_id
      AND participant.state='ACTIVE' AND participant.authority_epoch=k.envelope_workload_participant_epoch
     WHERE lifecycle.participant_id=k.participant_id AND lifecycle.privacy_domain_id=k.privacy_domain_id
      AND lifecycle.signer_id=k.signer_id AND lifecycle.state='ACTIVE')
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-CURRENT-KEY'; END IF;
 END IF;
 IF NEW.state='DISPATCHED' AND (NEW.dispatched_at<NEW.created_at OR NEW.dispatched_at>clock_timestamp())
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-DISPATCH'; END IF;
 IF NEW.state IN ('OBSERVED','COMMITTED') THEN
  expected:=(NEW.request-ARRAY['method','callerWorkloadCredentialId','attemptId','operationId','expectedFingerprint','payloadHex'])
   ||jsonb_build_object('algorithm','ES256','publicKeySpkiHex',encode(k.public_key_spki_der,'hex'),
    'fingerprint',k.signer_id,'validFromNs',k.valid_from_ns::text,'validUntilNs',k.valid_until_ns::text,'state','ACTIVE');
  IF NEW.observed_at<NEW.dispatched_at OR NEW.observed_at>clock_timestamp()
   OR NEW.observation->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text
   OR NEW.observation->>'operationId' IS DISTINCT FROM NEW.operation_id::text
   OR NEW.observation->>'requestDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.request_digest,'hex')
   OR NEW.observation->>'method' IS DISTINCT FROM 'SIGN_AUTHORITY_ENVELOPE'
   OR NEW.observation->>'coseHex' IS DISTINCT FROM encode(NEW.cose_sign1,'hex')
   OR NEW.observation->'descriptor' IS DISTINCT FROM expected
   OR NEW.observation IS DISTINCT FROM jsonb_build_object('schemaVersion',1,'method','SIGN_AUTHORITY_ENVELOPE',
    'attemptId',NEW.attempt_id::text,'operationId',NEW.operation_id::text,
    'requestDigest','sha256:'||encode(NEW.request_digest,'hex'),'recordedAtNs',NEW.observation->'recordedAtNs',
    'descriptor',expected,'coseHex',encode(NEW.cose_sign1,'hex'))
   OR (NEW.observation->>'recordedAtNs')::numeric<NEW.reserved_at_ns
   OR (NEW.observation->>'recordedAtNs')::numeric>=k.valid_until_ns
   OR (NEW.observation->>'recordedAtNs')::numeric>floor(extract(epoch FROM NEW.observed_at)*1000000)*1000
   OR get_byte(NEW.cose_sign1,0)<>210
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-OBSERVATION'; END IF;
  outer_cose:=openpc.business_cbor_item(NEW.cose_sign1,1,0);
  IF (outer_cose->>'next')::integer<>octet_length(NEW.cose_sign1)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-COSE'; END IF;
  outer_cose:=outer_cose->'value';
  IF jsonb_typeof(outer_cose)<>'array' OR jsonb_array_length(outer_cose)<>4 OR outer_cose->1<>'{}'::jsonb
   OR outer_cose->2 IS DISTINCT FROM openpc.business_bytes(NEW.payload_cbor) OR length(outer_cose->3->>'bytes') IS DISTINCT FROM 128
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-COSE'; END IF;
  header:=openpc.business_cbor(decode(outer_cose->0->>'bytes','hex'));
  IF header IS DISTINCT FROM jsonb_build_object('1',-7,'2',jsonb_build_array(100,101,102,103),
   '3','application/pc+cbor','4',openpc.business_bytes(convert_to(k.signer_id,'UTF8')),'100',24034,'101',1,'102',371,'103',2)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-COSE-CONTEXT'; END IF;
 END IF;
 IF NEW.state='COMMITTED' AND NOT EXISTS(
  SELECT 1 FROM control.authority_envelope envelope
   WHERE envelope.participant_id=NEW.participant_id
    AND envelope.authority_envelope_id=NEW.envelope_id
    AND envelope.state='ACTIVE' AND envelope.row_version=4
    AND envelope.last_mutation_operation_id=NEW.operation_id
    AND envelope.cose_sign1=NEW.cose_sign1)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-SEALED-ACTIVATION-REQUIRED'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_envelope_activation_guard ON control.identity_envelope_activation;
CREATE TRIGGER identity_envelope_activation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.identity_envelope_activation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_envelope_activation();

CREATE OR REPLACE FUNCTION openpc.preserve_identity_envelope_activation_intent()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM control.identity_envelope_activation a WHERE a.participant_id=OLD.participant_id
   AND a.privacy_domain_id=OLD.privacy_domain_id AND a.idempotency_record_id=OLD.idempotency_record_id) THEN
  IF TG_OP='DELETE' OR NOT (
    (to_jsonb(NEW)-'result_digest'-'result_payload'-'result_aggregate_version'-'terminal_state')
      IS NOT DISTINCT FROM
    (to_jsonb(OLD)-'result_digest'-'result_payload'-'result_aggregate_version'-'terminal_state')
    AND OLD.terminal_state IS NULL AND NEW.terminal_state='COMMITTED'
    AND NEW.result_digest IS NOT NULL AND NEW.result_payload IS NOT NULL
    AND NEW.result_aggregate_version=4
    AND EXISTS(SELECT 1 FROM control.identity_envelope_activation a
      WHERE a.idempotency_record_id=OLD.idempotency_record_id
       AND a.operation_id=OLD.operation_id AND a.state='COMMITTED' AND a.row_version=4)
  ) THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ACTIVATION-ORIGINAL-INTENT'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_envelope_activation_idempotency ON control.idempotency_record;
CREATE TRIGGER identity_envelope_activation_idempotency BEFORE UPDATE OR DELETE ON control.idempotency_record
 FOR EACH ROW EXECUTE FUNCTION openpc.preserve_identity_envelope_activation_intent();
`;
