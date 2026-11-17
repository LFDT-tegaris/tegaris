import { identityEnvelopeSigningProfileDigest } from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';
import { workloadCredentialSuccessorSql } from './workload-credential-successor.mjs';

/** Exact public custody binding for old-key possession. This expression never
 * extends the predecessor trust's validity or authorizes normal signing. */
export function identityEnvelopeRecoveryPredecessorBindingSql(binding) {
  return `jsonb_build_object('purpose','IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    'enrollmentId',${binding}#>>'{lease,enrollmentId}',
    'enrollmentDigest',${binding}#>>'{lease,enrollmentDigest}',
    'recoveryId',${binding}#>>'{lease,recoveryId}',
    'activationOperationId',${binding}#>>'{lease,activationOperationId}',
    'leaseDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(${binding}->'lease'),'UTF8')),'hex'),
    'oldTrustDigest',${binding}#>>'{lease,oldTrustDigest}')`;
}

/** Exact recovery admission; ordinary receipt/bootstrap grants remain separate. */
export const identityEnvelopeRecoveryTrustGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.check_identity_envelope_recovery_trust_admission(p_key control.business_signing_key)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE rotation control.signing_key_rotation; step control.identity_envelope_rotation_step;
 old_key control.business_signing_key; descriptor jsonb; issuer jsonb; expected_digest bytea; proofs integer;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR p_key.signing_purpose_code<>371 OR p_key.admission_kind<>'GOVERNED'
  OR NOT openpc.matches_participant(p_key.participant_id) OR NOT openpc.matches_privacy(p_key.privacy_domain_id)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-TRUST-ADMISSION'; END IF;
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation r WHERE r.participant_id=p_key.participant_id
  AND r.privacy_domain_id=p_key.privacy_domain_id AND r.recovery_case_id IS NOT NULL
  AND p_key.admission_reference='urn:openpc:resource:'||r.rotation_id::text AND r.new_signer_id=p_key.signer_id
  AND r.state='VERIFIED' AND r.revision=5 AND r.approval_request_id IS NULL;
 SELECT * INTO STRICT step FROM control.identity_envelope_rotation_step s WHERE s.operation_id=openpc.current_operation_id()
  AND s.participant_id=rotation.participant_id AND s.privacy_domain_id=rotation.privacy_domain_id
  AND s.rotation_id=rotation.rotation_id AND s.recovery_id=rotation.recovery_case_id
  AND s.from_revision=4 AND s.from_state='DISTRIBUTED' AND s.to_state='VERIFIED' AND s.state='COMMITTED';
 IF NOT coalesce(openpc.identity_envelope_rotation_step_current(step),false)
  OR step.result->>'state' IS DISTINCT FROM 'VERIFIED' OR step.result->>'admissionState' IS DISTINCT FROM 'ADMITTED'
  OR step.result->>'signerId' IS DISTINCT FROM p_key.signer_id
  OR step.result->>'trustDigest' IS DISTINCT FROM 'sha256:'||encode(p_key.trust_digest,'hex')
  OR step.evidence_digest IS DISTINCT FROM sha256(step.evidence_cbor) OR step.cose_sign1 IS NULL
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-TRUST-PROVENANCE'; END IF;
 SELECT * INTO STRICT old_key FROM control.business_signing_key k WHERE k.participant_id=rotation.participant_id
  AND k.privacy_domain_id=rotation.privacy_domain_id AND k.signer_id=rotation.old_signer_id AND k.signing_purpose_code=371;
 SELECT a.observation->'descriptor' INTO STRICT descriptor FROM control.identity_envelope_rotation_step prepared
  JOIN control.identity_envelope_rotation_attempt a USING(participant_id,privacy_domain_id,rotation_id,operation_id)
  WHERE prepared.participant_id=rotation.participant_id AND prepared.privacy_domain_id=rotation.privacy_domain_id
   AND prepared.rotation_id=rotation.rotation_id AND prepared.recovery_id=rotation.recovery_case_id
   AND prepared.state='COMMITTED' AND prepared.from_revision=2 AND prepared.to_state='PREPARED'
   AND a.slot='new' AND a.state='OBSERVED';
 issuer:=step.authority_binding#>'{lease,issuer}';
 expected_digest:=sha256(convert_to('pc.identity.envelope-key-recovery-admission.v1','UTF8')||decode('00','hex')||
  convert_to(openpc.signing_canonical_json(step.authority_binding||jsonb_build_object('issuer',issuer,
    'newFingerprint',descriptor->>'fingerprint','newReference',descriptor->>'reference','newVersion',descriptor->>'version')),'UTF8'));
 IF old_key.trust_digest<>rotation.old_trust_digest OR p_key.key_epoch<>old_key.key_epoch+1
  OR NOT ((p_key.workload_credential_id=old_key.workload_credential_id AND p_key.workload_credential_epoch=old_key.workload_credential_epoch)
   OR ${workloadCredentialSuccessorSql({ participantId: 'p_key.participant_id', privacyDomainId: 'p_key.privacy_domain_id', predecessorId: 'old_key.workload_credential_id', predecessorEpoch: 'old_key.workload_credential_epoch', successorId: 'p_key.workload_credential_id', successorEpoch: 'p_key.workload_credential_epoch' })})
  OR p_key.environment_id<>old_key.environment_id OR p_key.environment_id<>rotation.environment_id
  OR p_key.workload_credential_id::text IS DISTINCT FROM issuer->>'workloadCredentialId'
  OR p_key.workload_credential_epoch::text IS DISTINCT FROM issuer->>'workloadCredentialEpoch'
  OR p_key.envelope_workload_participant_epoch::text IS DISTINCT FROM issuer->>'workloadParticipantEpoch'
  OR p_key.envelope_workload_principal_epoch::text IS DISTINCT FROM issuer->>'workloadPrincipalEpoch'
  OR p_key.admission_digest<>expected_digest OR p_key.secret_class<>'SECRET-SIGNING-KEY'
  OR p_key.secret_reference IS DISTINCT FROM descriptor->>'reference' OR p_key.secret_version IS DISTINCT FROM descriptor->>'version'
  OR p_key.signer_id IS DISTINCT FROM descriptor->>'fingerprint' OR encode(p_key.public_key_spki_der,'hex') IS DISTINCT FROM descriptor->>'publicKeySpkiHex'
  OR p_key.valid_from_ns::text IS DISTINCT FROM descriptor->>'validFromNs' OR p_key.valid_until_ns::text IS DISTINCT FROM descriptor->>'validUntilNs'
  OR p_key.valid_from_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000
  OR p_key.valid_until_ns<=floor(extract(epoch from clock_timestamp())*1000000)*1000
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-TRUST-BINDING'; END IF;
 SELECT count(*) INTO proofs FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=step.operation_id
  AND a.participant_id=step.participant_id AND a.privacy_domain_id=step.privacy_domain_id AND a.rotation_id=step.rotation_id
  AND a.slot IN('old','new') AND a.state='OBSERVED' AND a.observation=a.first_observation
  AND a.request->>'method'='PROVE' AND a.request->>'challengeHex'=encode(p_key.trust_digest,'hex')
  AND a.request->>'expectedFingerprint'=CASE a.slot WHEN 'old' THEN old_key.signer_id ELSE p_key.signer_id END
  AND a.request->'recoveryPredecessor' IS NOT DISTINCT FROM
    (CASE WHEN a.slot='old' THEN ${identityEnvelopeRecoveryPredecessorBindingSql('step.authority_binding')} ELSE NULL END)
  AND a.observation->>'outcome'='SUCCEEDED' AND a.observation->>'resultHex' ~ '^[0-9a-f]{128}$'
  AND a.observation->>'attemptId'=a.attempt_id::text AND a.observation->>'operationId'=step.operation_id::text
  AND a.observation->>'requestDigest'='sha256:'||encode(a.request_digest,'hex')
  AND a.observation_digest=sha256(convert_to(openpc.signing_canonical_json(a.observation),'UTF8'))
  AND a.first_observation_digest=a.observation_digest
  AND (a.request->>'challengeIssuedAtNs')::numeric<=(a.observation->>'recordedAtNs')::numeric
  AND (a.observation->>'recordedAtNs')::numeric<=floor(extract(epoch from clock_timestamp())*1000000)*1000
  AND (a.request->>'challengeExpiresAtNs')::numeric>floor(extract(epoch from clock_timestamp())*1000000)*1000
  AND (a.request->>'challengeExpiresAtNs')::numeric>(a.observation->>'recordedAtNs')::numeric
  AND a.observation#>>'{descriptor,state}'='ACTIVE'
  AND a.observation#>>'{descriptor,participantId}'=p_key.participant_id::text
  AND a.observation#>>'{descriptor,privacyDomainId}'=p_key.privacy_domain_id::text
  AND a.observation#>>'{descriptor,environmentId}'=p_key.environment_id
  AND a.observation#>>'{descriptor,workloadCredentialId}'=CASE a.slot WHEN 'old' THEN old_key.workload_credential_id::text ELSE p_key.workload_credential_id::text END
  AND a.observation#>>'{descriptor,workloadCredentialEpoch}'=CASE a.slot WHEN 'old' THEN old_key.workload_credential_epoch::text ELSE p_key.workload_credential_epoch::text END
  AND a.observation#>>'{descriptor,publicKeySpkiHex}'=CASE a.slot WHEN 'old' THEN encode(old_key.public_key_spki_der,'hex') ELSE encode(p_key.public_key_spki_der,'hex') END
  AND a.observation#>>'{descriptor,fingerprint}'=CASE a.slot WHEN 'old' THEN old_key.signer_id ELSE p_key.signer_id END
  AND a.observation#>>'{descriptor,reference}'=CASE a.slot WHEN 'old' THEN old_key.secret_reference ELSE p_key.secret_reference END
  AND a.observation#>>'{descriptor,version}'=CASE a.slot WHEN 'old' THEN old_key.secret_version ELSE p_key.secret_version END
  AND a.observation#>>'{descriptor,validFromNs}'=CASE a.slot WHEN 'old' THEN old_key.valid_from_ns::text ELSE p_key.valid_from_ns::text END
  AND a.observation#>>'{descriptor,validUntilNs}'=CASE a.slot WHEN 'old' THEN old_key.valid_until_ns::text ELSE p_key.valid_until_ns::text END
  AND a.observation#>'{descriptor,revokedAtNs}'='null'::jsonb AND a.observation#>'{descriptor,retiredAtNs}'='null'::jsonb
  AND (a.slot='old' OR a.observation->'descriptor'=descriptor);
 IF (SELECT count(DISTINCT a.request->>'challengeIssuedAtNs') FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=step.operation_id)<>1
  OR step.result->>'observationsDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
    (SELECT jsonb_agg(jsonb_build_object('slot',a.slot,'request',a.request,'observation',a.observation) ORDER BY CASE a.slot WHEN 'old' THEN 0 ELSE 1 END)
     FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=step.operation_id)),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-TRUST-PROOF-BINDING'; END IF;
 IF proofs<>2 OR (SELECT count(*) FROM control.identity_envelope_rotation_attempt a WHERE a.operation_id=step.operation_id)<>2
  THEN RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-TRUST-DUAL-PROOF'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.check_identity_envelope_recovery_trust_admission(control.business_signing_key) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.check_identity_envelope_recovery_trust_admission(control.business_signing_key) TO openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.admit_identity_envelope_recovery_trust(p_preimage bytea,p_digest bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE step control.identity_envelope_rotation_step; rotation control.signing_key_rotation; old_key control.business_signing_key;
 descriptor jsonb; issuer jsonb; key_row control.business_signing_key; admission bytea;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO STRICT step FROM control.identity_envelope_rotation_step s WHERE s.operation_id=openpc.current_operation_id()
  AND openpc.matches_participant(s.participant_id) AND openpc.matches_privacy(s.privacy_domain_id)
  AND s.from_revision=4 AND s.from_state='DISTRIBUTED' AND s.to_state='VERIFIED' AND s.state='COMMITTED';
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' OR p_digest<>sha256(p_preimage)
  OR step.result->>'trustDigest' IS DISTINCT FROM 'sha256:'||encode(p_digest,'hex') THEN
  RAISE EXCEPTION 'PC-AUTH-0005-ENVELOPE-TRUST-ADMISSION'; END IF;
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation r WHERE r.participant_id=step.participant_id
  AND r.privacy_domain_id=step.privacy_domain_id AND r.rotation_id=step.rotation_id AND r.recovery_case_id=step.recovery_id
  AND r.state='VERIFIED' AND r.revision=5;
 SELECT * INTO STRICT old_key FROM control.business_signing_key k WHERE k.participant_id=step.participant_id
  AND k.privacy_domain_id=step.privacy_domain_id AND k.signer_id=rotation.old_signer_id;
 SELECT a.observation->'descriptor' INTO STRICT descriptor FROM control.identity_envelope_rotation_attempt a
  JOIN control.identity_envelope_rotation_step prepared USING(participant_id,privacy_domain_id,rotation_id,operation_id)
  WHERE prepared.participant_id=step.participant_id AND prepared.privacy_domain_id=step.privacy_domain_id
   AND prepared.rotation_id=step.rotation_id AND prepared.recovery_id=step.recovery_id
   AND prepared.from_revision=2 AND prepared.to_state='PREPARED' AND prepared.state='COMMITTED' AND a.slot='new' AND a.state='OBSERVED';
 issuer:=step.authority_binding#>'{lease,issuer}';
 admission:=sha256(convert_to('pc.identity.envelope-key-recovery-admission.v1','UTF8')||decode('00','hex')||
  convert_to(openpc.signing_canonical_json(step.authority_binding||jsonb_build_object('issuer',issuer,
    'newFingerprint',descriptor->>'fingerprint','newReference',descriptor->>'reference','newVersion',descriptor->>'version')),'UTF8'));
 key_row.participant_id:=step.participant_id;key_row.privacy_domain_id:=step.privacy_domain_id;key_row.signer_id:=descriptor->>'fingerprint';
 key_row.signing_purpose_code:=371;key_row.environment_id:=rotation.environment_id;key_row.public_key_spki_der:=decode(descriptor->>'publicKeySpkiHex','hex');
 key_row.workload_credential_id:=(issuer->>'workloadCredentialId')::uuid;key_row.workload_credential_epoch:=(issuer->>'workloadCredentialEpoch')::numeric;
 key_row.envelope_workload_participant_epoch:=(issuer->>'workloadParticipantEpoch')::numeric;key_row.envelope_workload_principal_epoch:=(issuer->>'workloadPrincipalEpoch')::numeric;
 key_row.key_epoch:=old_key.key_epoch+1;key_row.valid_from_ns:=(descriptor->>'validFromNs')::numeric;key_row.valid_until_ns:=(descriptor->>'validUntilNs')::numeric;
 key_row.admission_kind:='GOVERNED';key_row.admission_reference:='urn:openpc:resource:'||rotation.rotation_id::text;key_row.admission_digest:=admission;
 key_row.secret_class:='SECRET-SIGNING-KEY';key_row.secret_reference:=descriptor->>'reference';key_row.secret_version:=descriptor->>'version';
 key_row.trust_preimage:=p_preimage;key_row.trust_digest:=p_digest;
 PERFORM openpc.check_identity_envelope_recovery_trust_admission(key_row);
 INSERT INTO control.business_signing_key SELECT (key_row).*;
 INSERT INTO control.identity_envelope_signing_grant(participant_id,privacy_domain_id,signer_id,signing_purpose_code,profile_digest)
  VALUES(key_row.participant_id,key_row.privacy_domain_id,key_row.signer_id,371,decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex'));
 INSERT INTO control.business_signing_key_state(participant_id,privacy_domain_id,signer_id,state,row_version,changed_at_ns,change_reference,change_digest)
  VALUES(key_row.participant_id,key_row.privacy_domain_id,key_row.signer_id,'ADMITTED',1,
   floor(extract(epoch from clock_timestamp())*1000000)*1000,key_row.admission_reference,step.evidence_digest);
 RETURN jsonb_build_object('signerId',key_row.signer_id,'trustDigest','sha256:'||encode(key_row.trust_digest,'hex'),'state','ADMITTED');
END $$;
REVOKE ALL ON FUNCTION openpc.admit_identity_envelope_recovery_trust(bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.admit_identity_envelope_recovery_trust(bytea,bytea) TO openpc_control_runtime,openpc_control_platform_runtime;
`;
