import { identityEnvelopeSigningProfileDigest } from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';
export function identityEnvelopeRotationRetirementPredicate(step, completedEffect = false) {
  return `EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step consumer
 JOIN control.signing_key_rotation r ON r.participant_id=consumer.participant_id AND r.privacy_domain_id=consumer.privacy_domain_id AND r.rotation_id=consumer.rotation_id AND r.recovery_case_id=consumer.recovery_id
 JOIN control.identity_envelope_signing_selection selection ON selection.participant_id=r.participant_id AND selection.privacy_domain_id=r.privacy_domain_id AND selection.environment_id=r.environment_id AND selection.signer_id=r.new_signer_id
 JOIN control.business_signing_key next ON next.participant_id=selection.participant_id AND next.privacy_domain_id=selection.privacy_domain_id AND next.signer_id=selection.signer_id
 JOIN control.identity_envelope_signing_grant next_grant ON next_grant.participant_id=next.participant_id AND next_grant.privacy_domain_id=next.privacy_domain_id AND next_grant.signer_id=next.signer_id AND next_grant.profile_digest=selection.profile_digest AND next_grant.signing_purpose_code=371
 JOIN control.business_signing_key_state next_life ON next_life.participant_id=next.participant_id AND next_life.privacy_domain_id=next.privacy_domain_id AND next_life.signer_id=next.signer_id
 JOIN control.business_signing_key old_key ON old_key.participant_id=r.participant_id AND old_key.privacy_domain_id=r.privacy_domain_id AND old_key.signer_id=r.old_signer_id
 JOIN control.business_signing_key_state old_life ON old_life.participant_id=old_key.participant_id AND old_life.privacy_domain_id=old_key.privacy_domain_id AND old_life.signer_id=old_key.signer_id
 JOIN control.identity_envelope_activation a ON a.participant_id=consumer.participant_id AND a.privacy_domain_id=consumer.privacy_domain_id AND a.operation_id=consumer.consumer_activation_operation_id
 WHERE consumer.operation_id=${step}.consumer_observation_operation_id AND consumer.participant_id=${step}.participant_id AND consumer.privacy_domain_id=${step}.privacy_domain_id
 AND consumer.rotation_id=${step}.rotation_id AND consumer.recovery_id=${step}.recovery_id AND consumer.principal_id=${step}.principal_id
 AND consumer.from_revision=6 AND consumer.from_state='CUTOVER_FENCED' AND consumer.to_state='OBSERVING' AND consumer.state='COMMITTED'
 AND consumer.authority_binding=${step}.authority_binding AND consumer.authority_digest=${step}.authority_digest
 AND consumer.evidence_digest=sha256(consumer.evidence_cbor) AND octet_length(consumer.cose_sign1)>0
 AND a.state='COMMITTED' AND a.row_version=4 AND a.payload_digest=sha256(a.payload_cbor)
 AND a.operation_id::text=consumer.result->>'consumerActivationOperationId' AND a.envelope_id::text=consumer.result->>'consumerEnvelopeId'
 AND 'sha256:'||encode(a.payload_digest,'hex')=consumer.result->>'consumerPayloadDigest'
 AND NOT EXISTS(SELECT 1 FROM control.business_signing_grant ordinary WHERE ordinary.participant_id=next.participant_id AND ordinary.privacy_domain_id=next.privacy_domain_id AND ordinary.signer_id IN(next.signer_id,old_key.signer_id))
 AND next_life.state='ACTIVE' AND next.signing_purpose_code=371 AND old_key.signing_purpose_code=371
 AND selection.profile_digest=decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex')
 AND selection.admission_version=(${step}.authority_binding#>>'{lease,selectionAdmissionVersion}')::numeric+1
 AND selection.admission_version::text=consumer.result->>'selectionAdmissionVersion'
 AND 'sha256:'||encode(next.trust_digest,'hex')=consumer.result->>'trustDigest' AND next.signer_id=consumer.result->>'signerId'
 AND old_key.trust_digest=decode(substr(${step}.authority_binding#>>'{lease,oldTrustDigest}',8),'hex')
 AND old_life.state=(CASE WHEN ${step}.from_state='OBSERVING' AND ${completedEffect ? 'false' : 'true'} THEN 'ACTIVE' ELSE 'REVOKED' END)
 AND (${step}.result IS NULL OR (${step}.result->>'consumerObservationOperationId'=consumer.operation_id::text
 AND ${step}.result->>'consumerActivationOperationId'=consumer.result->>'consumerActivationOperationId'
 AND ${step}.result->>'consumerEnvelopeId'=consumer.result->>'consumerEnvelopeId' AND ${step}.result->>'consumerPayloadDigest'=consumer.result->>'consumerPayloadDigest'
 AND ${step}.result->>'consumerReceiptDigest'=consumer.result->>'consumerReceiptDigest' AND ${step}.result->>'signerId'=consumer.result->>'signerId'
 AND ${step}.result->>'trustDigest'=consumer.result->>'trustDigest' AND ${step}.result->>'selectionAdmissionVersion'=consumer.result->>'selectionAdmissionVersion'
 AND ${step}.result->>'predecessorSignerId'=old_key.signer_id AND ${step}.result->>'permissionEffect'='NONE')))`;
}

/** Narrow final public revocation callback. No private effect is issued here;
 * provider first response and original lookup already precede this transaction. */
export const identityEnvelopeRotationRetirementGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.revoke_identity_envelope_recovery_trust()
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE step control.identity_envelope_rotation_step; old_key control.business_signing_key; prior control.business_signing_key_state;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO STRICT step FROM control.identity_envelope_rotation_step s WHERE s.operation_id=openpc.current_operation_id()
 AND s.from_revision=7 AND s.from_state='OBSERVING' AND s.to_state='OLD_REVOKED' AND s.state='COMMITTED';
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' OR NOT openpc.identity_envelope_rotation_step_current(step)
 OR NOT EXISTS(SELECT 1 FROM control.signing_key_rotation r WHERE r.participant_id=step.participant_id AND r.privacy_domain_id=step.privacy_domain_id
 AND r.rotation_id=step.rotation_id AND r.recovery_case_id=step.recovery_id AND r.state='OLD_REVOKED' AND r.revision=8 AND r.old_signer_id=step.result->>'predecessorSignerId')
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-REVOCATION'; END IF;
 SELECT * INTO STRICT old_key FROM control.business_signing_key WHERE participant_id=step.participant_id AND privacy_domain_id=step.privacy_domain_id
 AND signer_id=step.result->>'predecessorSignerId' AND signing_purpose_code=371;
 SELECT * INTO STRICT prior FROM control.business_signing_key_state WHERE participant_id=old_key.participant_id AND privacy_domain_id=old_key.privacy_domain_id AND signer_id=old_key.signer_id FOR UPDATE;
 IF prior.state<>'ACTIVE' OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=step.operation_id AND a.slot='old'
 AND a.participant_id=step.participant_id AND a.privacy_domain_id=step.privacy_domain_id AND a.rotation_id=step.rotation_id AND a.state='OBSERVED'
 AND a.request->>'method'='REVOKE' AND a.request->>'reference'=old_key.secret_reference AND a.request->>'expectedFingerprint'=old_key.signer_id
 AND a.observation=a.first_observation AND a.observation->>'outcome'='SUCCEEDED' AND a.observation#>>'{descriptor,state}'='REVOKED'
 AND a.observation#>>'{descriptor,fingerprint}'=old_key.signer_id AND a.observation#>>'{descriptor,publicKeySpkiHex}'=encode(old_key.public_key_spki_der,'hex')
 AND a.observation#>>'{descriptor,revokedAtNs}'=step.result->>'oldPrivateKeyRevokedAtNs')
 OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_rotation_step consumer WHERE consumer.operation_id=step.consumer_observation_operation_id
 AND consumer.participant_id=step.participant_id AND consumer.privacy_domain_id=step.privacy_domain_id AND consumer.rotation_id=step.rotation_id
 AND consumer.recovery_id=step.recovery_id AND consumer.state='COMMITTED' AND consumer.from_revision=6 AND consumer.to_state='OBSERVING'
 AND consumer.authority_binding=step.authority_binding AND consumer.authority_digest=step.authority_digest
 AND consumer.result->>'consumerActivationOperationId'=step.result->>'consumerActivationOperationId'
 AND consumer.result->>'consumerReceiptDigest'=step.result->>'consumerReceiptDigest')
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-REVOCATION'; END IF;
 UPDATE control.business_signing_key_state SET state='REVOKED',row_version=prior.row_version+1,
 changed_at_ns=floor(extract(epoch from step.completed_at)*1000000)*1000,change_reference='urn:openpc:resource:'||step.rotation_id::text,change_digest=step.evidence_digest
 WHERE participant_id=old_key.participant_id AND privacy_domain_id=old_key.privacy_domain_id AND signer_id=old_key.signer_id AND state='ACTIVE' AND row_version=prior.row_version;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-REVOCATION'; END IF;
 IF NOT ${identityEnvelopeRotationRetirementPredicate('step', true)} THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-ROTATION-REVOCATION'; END IF;
 RETURN jsonb_build_object('signerId',old_key.signer_id,'operationId',step.operation_id,'state','REVOKED');
END $$;
REVOKE ALL ON FUNCTION openpc.revoke_identity_envelope_recovery_trust() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.revoke_identity_envelope_recovery_trust() TO openpc_control_runtime,openpc_control_platform_runtime;
`;
