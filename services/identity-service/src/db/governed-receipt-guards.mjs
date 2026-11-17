import { governedReceiptOperationIds } from './governed-receipt-inputs.ts';
import { stepUpOnlyConfigurationOperations } from '../domain/configuration-step-up-admission.ts';
const operations = governedReceiptOperationIds.map((id) => `'${id}'`).join(',');
const stepUpOperations = stepUpOnlyConfigurationOperations.map((id) => `'${id}'`).join(',');

/** Exact consumed approval and actor step-up references for admitted governed receipts. */
export const governedReceiptGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.check_governed_configuration_receipt(receipt control.audit_occurrence)
RETURNS control.mutation_candidate LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE actual jsonb; approval control.approval_decision_record%ROWTYPE;
 evidence control.mutation_evidence%ROWTYPE; verification control.mutation_evidence%ROWTYPE;
 candidate control.mutation_candidate%ROWTYPE; request control.approval_request%ROWTYPE; challenge control.mfa_challenge%ROWTYPE;
BEGIN
 IF receipt.catalog_operation_id NOT IN (${operations}) THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-GOVERNED-RECEIPT'; END IF;
 SELECT * INTO STRICT candidate FROM control.mutation_candidate c WHERE c.participant_id=receipt.participant_id
  AND c.privacy_domain_id=receipt.privacy_domain_id AND c.catalog_operation_id=receipt.catalog_operation_id
  AND c.action_intent_id=receipt.action_intent_id AND c.resource_id=receipt.aggregate_id
  AND c.candidate_digest=receipt.candidate_digest AND c.state='CONSUMED' AND c.consumed_operation_id=receipt.operation_id;
 SELECT * INTO STRICT evidence FROM control.mutation_evidence e WHERE e.participant_id=receipt.participant_id
  AND e.privacy_domain_id=receipt.privacy_domain_id AND e.operation_id=receipt.operation_id
  AND e.catalog_operation_id=receipt.catalog_operation_id AND e.action_intent_id=receipt.action_intent_id
  AND e.aggregate_id=receipt.aggregate_id AND e.principal_id=candidate.maker_principal_id
  AND e.candidate_digest=receipt.candidate_digest;
 SELECT * INTO STRICT request FROM control.approval_request r WHERE r.participant_id=receipt.participant_id
  AND r.privacy_domain_id=receipt.privacy_domain_id AND r.approval_request_id=evidence.approval_request_id
  AND r.subject_type='CONFIGURATION_CANDIDATE' AND r.subject_id=candidate.mutation_candidate_id
  AND r.subject_digest=candidate.candidate_digest AND r.subject_version=candidate.expected_revision
  AND r.action_intent_id=receipt.action_intent_id AND r.maker_principal_id=candidate.maker_principal_id;
 SELECT * INTO STRICT approval FROM control.approval_decision_record d WHERE d.participant_id=receipt.participant_id
  AND d.privacy_domain_id=receipt.privacy_domain_id AND d.approval_request_id=request.approval_request_id
  AND d.decision='APPROVE' AND d.approver_principal_id=evidence.checker_principal_id
  AND d.approver_principal_id<>evidence.principal_id AND d.candidate_digest=receipt.candidate_digest
  AND d.aggregate_version=candidate.expected_revision AND d.evidence_cbor=evidence.evidence_cbor
  AND sha256(d.evidence_cbor)=evidence.evidence_digest
  AND d.decision_digest=sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
   'actionIntentId','ACT-POLICY_APPROVE_REQUEST-V1',
   'approvalRequestId','urn:openpc:resource:'||request.approval_request_id::text,
   'candidateDigest','sha256:'||encode(candidate.candidate_digest,'hex'),
   'decision','APPROVE','expectedRevision','1')),'UTF8'))
  AND d.cose_sign1=evidence.cose_sign1;
 SELECT * INTO STRICT challenge FROM control.mfa_challenge c WHERE c.participant_id=receipt.participant_id
  AND c.principal_id=evidence.principal_id AND c.mfa_challenge_id=evidence.mfa_challenge_id
  AND c.action_intent_id=receipt.action_intent_id AND c.resource_digest=receipt.candidate_digest
  AND c.used_operation_id=receipt.operation_id AND c.used_at IS NOT NULL;
 SELECT * INTO STRICT verification FROM control.mutation_evidence v WHERE v.participant_id=receipt.participant_id
  AND v.privacy_domain_id=receipt.privacy_domain_id AND v.principal_id=evidence.principal_id
  AND v.mfa_challenge_id=challenge.mfa_challenge_id AND v.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
  AND v.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
  AND v.evidence_digest=sha256(v.evidence_cbor);
 actual:=openpc.business_cbor(receipt.receipt_cbor);
 IF actual->'20' IS DISTINCT FROM jsonb_build_array(
  jsonb_build_object('0',3,'1',approval.approval_decision_id::text,'2',openpc.business_bytes(sha256(approval.evidence_cbor))),
  jsonb_build_object('0',4,'1',verification.mutation_evidence_id::text,'2',openpc.business_bytes(verification.evidence_digest)))
  OR receipt.actor_key_digest<>sha256(convert_to('pc.identity.actor-key.v2','UTF8')||decode('00','hex')||
    int4send(octet_length(convert_to(receipt.participant_id::text,'UTF8')))||convert_to(receipt.participant_id::text,'UTF8')||
    int4send(octet_length(convert_to(evidence.principal_id::text,'UTF8')))||convert_to(evidence.principal_id::text,'UTF8'))
 THEN RAISE EXCEPTION 'DATA-6021-GOVERNED-EVIDENCE'; END IF;
 RETURN candidate;
END $$;
CREATE OR REPLACE FUNCTION openpc.configuration_step_up_receipt_input(receipt control.audit_occurrence,authorization_row control.mutation_evidence)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE verification control.mutation_evidence%ROWTYPE; snapshot jsonb;
BEGIN
 IF receipt.catalog_operation_id NOT IN (${stepUpOperations}) OR authorization_row.approval_request_id IS NOT NULL
  OR authorization_row.checker_principal_id IS NOT NULL OR authorization_row.mfa_challenge_id IS NULL
  OR authorization_row.webauthn_assertion_binding_digest IS NULL
 THEN RAISE EXCEPTION 'DATA-6021-STEP-UP-RECEIPT-ADMISSION'; END IF;
 snapshot:=convert_from(receipt.authority_snapshot,'UTF8')::jsonb;
 SELECT v.* INTO STRICT verification FROM control.mutation_evidence v
  JOIN control.mfa_challenge c ON c.participant_id=v.participant_id AND c.mfa_challenge_id=v.mfa_challenge_id
   AND c.principal_id=v.principal_id AND c.session_id=v.aggregate_id
  JOIN control.idempotency_record committed ON committed.participant_id=v.participant_id
   AND committed.privacy_domain_id=v.privacy_domain_id AND committed.principal_id=v.principal_id
   AND committed.operation_id=v.operation_id AND committed.catalog_operation_id=v.catalog_operation_id
   AND committed.input_digest=v.candidate_digest AND committed.terminal_state='COMMITTED'
   AND committed.webauthn_assertion_binding_digest=v.webauthn_assertion_binding_digest
  WHERE v.participant_id=receipt.participant_id AND v.privacy_domain_id=receipt.privacy_domain_id
   AND v.principal_id=authorization_row.principal_id AND v.mfa_challenge_id=authorization_row.mfa_challenge_id
   AND v.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1' AND v.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
   AND v.aggregate_type='webauthn-verification' AND v.evidence_digest=sha256(v.evidence_cbor)
   AND v.webauthn_assertion_binding_digest=authorization_row.webauthn_assertion_binding_digest
   AND c.action_intent_id=receipt.action_intent_id
   AND c.resource_digest=receipt.candidate_digest AND c.used_operation_id=receipt.operation_id
   AND c.used_at IS NOT NULL AND c.consumed_at IS NOT NULL
   AND extract(epoch from c.consumed_at)*1000000000<=receipt.recorded_at_ns
   AND extract(epoch from c.consumed_at)*1000000000>receipt.recorded_at_ns-300000000000
   AND (SELECT count(*) FROM jsonb_array_elements(snapshot->'authorities') a
    WHERE a->>'principalId'=v.principal_id::text AND a->>'sessionId'=c.session_id::text
     AND a->>'actionIntentId'=receipt.action_intent_id AND a->>'resourceId'=receipt.aggregate_id::text)=1
   AND EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=v.participant_id
    AND e.privacy_domain_id=v.privacy_domain_id AND e.aggregate_type=v.aggregate_type AND e.aggregate_id=v.aggregate_id
    AND e.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
    AND e.payload_cbor=v.evidence_cbor AND e.payload_digest=v.evidence_digest AND e.cose_sign1=v.cose_sign1
    AND e.webauthn_assertion_binding_digest=v.webauthn_assertion_binding_digest);
 RETURN jsonb_build_object('0',4,'1',verification.mutation_evidence_id::text,'2',openpc.business_bytes(verification.evidence_digest));
END $$;
REVOKE ALL ON FUNCTION openpc.configuration_step_up_receipt_input(control.audit_occurrence,control.mutation_evidence) FROM PUBLIC;
`;
