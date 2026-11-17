import { identityEnvelopeSigningProfileDigest } from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';

/** Shared predicate in the actual INSERT/STARTED/COMMITTED owners. Crypto stays
 * in Participant; SQL independently binds original durable normal effects. */
export function identityEnvelopeRotationConsumerPredicate(step) {
  return `EXISTS(SELECT 1 FROM control.signing_key_rotation r
 JOIN control.identity_envelope_activation a ON a.participant_id=r.participant_id AND a.privacy_domain_id=r.privacy_domain_id AND a.operation_id=${step}.consumer_activation_operation_id
 JOIN control.identity_envelope_proposal p ON p.participant_id=a.participant_id AND p.privacy_domain_id=a.privacy_domain_id AND p.envelope_id=a.envelope_id
 JOIN control.authority_envelope e ON e.participant_id=a.participant_id AND e.authority_envelope_id=a.envelope_id
 JOIN control.identity_envelope_signing_selection selection ON selection.participant_id=r.participant_id AND selection.privacy_domain_id=r.privacy_domain_id AND selection.environment_id=r.environment_id AND selection.signer_id=r.new_signer_id
 JOIN control.business_signing_key k ON k.participant_id=selection.participant_id AND k.privacy_domain_id=selection.privacy_domain_id AND k.signer_id=selection.signer_id
 JOIN control.identity_envelope_signing_grant g ON g.participant_id=k.participant_id AND g.privacy_domain_id=k.privacy_domain_id AND g.signer_id=k.signer_id
 JOIN control.business_signing_key_state life ON life.participant_id=k.participant_id AND life.privacy_domain_id=k.privacy_domain_id AND life.signer_id=k.signer_id
 JOIN control.mutation_candidate candidate ON candidate.participant_id=a.participant_id AND candidate.privacy_domain_id=a.privacy_domain_id AND candidate.mutation_candidate_id=a.candidate_id
 JOIN control.idempotency_record idem ON idem.participant_id=a.participant_id AND idem.privacy_domain_id=a.privacy_domain_id AND idem.operation_id=a.operation_id AND idem.idempotency_record_id=a.idempotency_record_id
 JOIN control.mutation_evidence receipt ON receipt.participant_id=a.participant_id AND receipt.privacy_domain_id=a.privacy_domain_id AND receipt.operation_id=a.operation_id AND receipt.aggregate_id=a.envelope_id
 JOIN control.outbox_event event ON event.participant_id=receipt.participant_id AND event.privacy_domain_id=receipt.privacy_domain_id AND event.aggregate_type='authority-envelope' AND event.aggregate_id=a.envelope_id AND event.event_type='openpc.authority-envelope.mutation.committed.v1'
  AND event.payload_cbor=receipt.evidence_cbor AND event.payload_digest=receipt.evidence_digest AND event.cose_sign1=receipt.cose_sign1
 WHERE r.participant_id=${step}.participant_id AND r.privacy_domain_id=${step}.privacy_domain_id AND r.rotation_id=${step}.rotation_id AND r.recovery_case_id=${step}.recovery_id
  AND selection.admission_version=(${step}.authority_binding#>>'{lease,selectionAdmissionVersion}')::numeric+1 AND selection.profile_digest=decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex')
  AND k.signing_purpose_code=371 AND g.signing_purpose_code=371 AND g.profile_digest=selection.profile_digest AND life.state='ACTIVE'
  AND NOT EXISTS(SELECT 1 FROM control.business_signing_grant ordinary WHERE ordinary.participant_id=k.participant_id AND ordinary.privacy_domain_id=k.privacy_domain_id AND ordinary.signer_id=k.signer_id)
  AND a.state='COMMITTED' AND a.row_version=4 AND a.reserved_at_ns>=r.cutover_at_ns AND a.committed_at<=${step}.created_at
  AND a.payload_digest=sha256(a.payload_cbor) AND a.request->>'expectedFingerprint'=k.signer_id AND a.request->>'trustContextDigest'='sha256:'||encode(k.trust_digest,'hex')
  AND a.request->>'reference'=k.secret_reference AND a.request->>'version'=k.secret_version AND a.request->>'callerWorkloadCredentialId'=k.workload_credential_id::text
  AND candidate.state='CONSUMED' AND candidate.consumed_operation_id=a.operation_id AND candidate.candidate_digest=a.candidate_digest AND candidate.resource_id=a.envelope_id
  AND candidate.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' AND candidate.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
  AND idem.terminal_state='COMMITTED' AND idem.action_intent_id=candidate.action_intent_id AND idem.catalog_operation_id=candidate.catalog_operation_id
  AND e.representation='TYPED_V1' AND e.state='ACTIVE' AND e.row_version=4 AND e.last_mutation_operation_id=a.operation_id
  AND e.cose_sign1=a.cose_sign1 AND e.semantic_cbor=p.proposal_cbor AND e.semantic_digest=p.proposal_digest
  AND receipt.action_intent_id=candidate.action_intent_id AND receipt.catalog_operation_id=candidate.catalog_operation_id AND receipt.aggregate_version=3
  AND receipt.evidence_digest=sha256(receipt.evidence_cbor) AND octet_length(receipt.cose_sign1)>0
  AND (${step}.result IS NULL OR (${step}.result->>'consumerActivationOperationId'=a.operation_id::text
   AND ${step}.result->>'consumerEnvelopeId'=a.envelope_id::text AND ${step}.result->>'consumerPayloadDigest'='sha256:'||encode(a.payload_digest,'hex')
   AND ${step}.result->>'consumerReceiptDigest'='sha256:'||encode(receipt.evidence_digest,'hex') AND ${step}.result->>'signerId'=k.signer_id
   AND ${step}.result->>'trustDigest'='sha256:'||encode(k.trust_digest,'hex') AND ${step}.result->>'selectionAdmissionVersion'=selection.admission_version::text
   AND EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt proof WHERE proof.operation_id=${step}.operation_id
    AND proof.participant_id=${step}.participant_id AND proof.privacy_domain_id=${step}.privacy_domain_id AND proof.rotation_id=${step}.rotation_id
    AND proof.slot='effective' AND proof.state='OBSERVED' AND proof.request->>'method'='PROVE' AND proof.observation->>'outcome'='SUCCEEDED'
    AND proof.observation=proof.first_observation AND proof.request->>'expectedFingerprint'=k.signer_id
    AND proof.request->>'challengeHex'=encode(k.trust_digest,'hex') AND proof.observation#>>'{descriptor,fingerprint}'=k.signer_id
    AND proof.observation#>>'{descriptor,publicKeySpkiHex}'=encode(k.public_key_spki_der,'hex') AND proof.observation#>>'{descriptor,state}'='ACTIVE'
    AND (proof.request->>'challengeExpiresAtNs')::numeric>floor(extract(epoch from clock_timestamp())*1000000)*1000
    AND (proof.observation->>'recordedAtNs')::numeric<=floor(extract(epoch from ${step}.completed_at)*1000000)*1000))))`;
}
