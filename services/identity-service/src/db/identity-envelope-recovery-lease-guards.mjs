/** Exact custody facts and issuer epoch fencing; no ordinary role, key-byte
 * permission, Root handoff, envelope or assignment is issued by this owner. */
import { identityEnvelopeSigningProfileDigest } from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';
import { workloadCredentialSuccessorSql } from './workload-credential-successor.mjs';

export const identityEnvelopeRecoveryLeaseGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.identity_envelope_recovery_old_selection_current(p_enrollment uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.identity_envelope_recovery_enrollment e
  JOIN control.identity_envelope_signing_selection selection ON selection.participant_id=e.participant_id
   AND selection.privacy_domain_id=e.privacy_domain_id AND selection.environment_id=e.document#>>'{request,environmentId}'
   AND selection.signer_id=e.document#>>'{request,oldFingerprint}' AND selection.admission_version::text=e.document->>'selectionAdmissionVersion'
   AND selection.profile_digest=decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex')
  JOIN control.identity_envelope_signing_grant grant_row ON grant_row.participant_id=selection.participant_id
   AND grant_row.privacy_domain_id=selection.privacy_domain_id AND grant_row.signer_id=selection.signer_id
   AND grant_row.profile_digest=selection.profile_digest AND grant_row.signing_purpose_code=371
  JOIN control.business_signing_key key ON key.participant_id=selection.participant_id AND key.privacy_domain_id=selection.privacy_domain_id
   AND key.signer_id=selection.signer_id AND key.signing_purpose_code=371 AND key.secret_reference=e.document#>>'{request,oldReference}'
   AND key.environment_id=selection.environment_id AND (
    (key.workload_credential_id::text=e.document#>>'{request,workloadCredentialId}'
     AND key.workload_credential_epoch::text=e.document->>'issuerCredentialEpoch')
    OR ${workloadCredentialSuccessorSql({ participantId: 'e.participant_id', privacyDomainId: 'e.privacy_domain_id', predecessorId: 'key.workload_credential_id', predecessorEpoch: 'key.workload_credential_epoch', successorId: "(e.document#>>'{request,workloadCredentialId}')::uuid", successorEpoch: "(e.document->>'issuerCredentialEpoch')::numeric" })})
   AND 'sha256:'||encode(key.trust_digest,'hex')=e.document->>'oldTrustDigest'
  JOIN control.business_signing_key_state lifecycle ON lifecycle.participant_id=key.participant_id
   AND lifecycle.privacy_domain_id=key.privacy_domain_id AND lifecycle.signer_id=key.signer_id AND lifecycle.state='ACTIVE'
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
   AND NOT EXISTS(SELECT 1 FROM control.business_signing_grant receipt WHERE receipt.participant_id=key.participant_id
    AND receipt.privacy_domain_id=key.privacy_domain_id AND receipt.signer_id=key.signer_id));
$$;
REVOKE ALL ON FUNCTION openpc.identity_envelope_recovery_old_selection_current(uuid) FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.identity_envelope_recovery_proofs_current(p_case control.platform_recovery_case,p_activation uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT p_case.signer_repair_enrollment_id IS NOT NULL
 AND openpc.matches_participant(p_case.participant_id) AND openpc.matches_privacy(p_case.privacy_domain_id)
 AND EXISTS(SELECT 1 FROM control.identity_envelope_recovery_enrollment e
  WHERE e.enrollment_id=p_case.signer_repair_enrollment_id AND e.participant_id=p_case.participant_id
   AND e.privacy_domain_id=p_case.privacy_domain_id AND e.state='ACTIVE' AND e.row_version=p_case.enrollment_revision
   AND e.document_digest=p_case.enrollment_digest AND openpc.identity_envelope_recovery_source_current(e.enrollment_id)
   AND jsonb_array_length(e.document->'custodians')=2
   AND (SELECT count(*) FROM control.platform_recovery_proof proof WHERE proof.participant_id=e.participant_id
    AND proof.recovery_id=p_case.recovery_id)=4
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(
    jsonb_build_array(jsonb_build_object('signer',e.document->'recoveryPrincipal','phase','REQUEST'),
     jsonb_build_object('signer',e.document->'recoveryPrincipal','phase','ACTIVATE')) ||
     (SELECT jsonb_agg(jsonb_build_object('signer',custodian,'phase','APPROVE')) FROM jsonb_array_elements(e.document->'custodians') custodian)) required
    WHERE NOT EXISTS(SELECT 1 FROM control.platform_recovery_proof proof
     JOIN control.platform_recovery_challenge h ON h.participant_id=proof.participant_id AND h.recovery_id=proof.recovery_id
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
REVOKE ALL ON FUNCTION openpc.identity_envelope_recovery_proofs_current(control.platform_recovery_case,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.identity_envelope_recovery_proofs_current(control.platform_recovery_case,uuid) TO openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.fence_identity_envelope_recovery_issuer(p_recovery uuid,p_activation uuid)
RETURNS numeric LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE recovery control.platform_recovery_case; enrollment control.identity_envelope_recovery_enrollment; epoch numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' OR openpc.current_operation_id() IS NULL THEN
  RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 SELECT * INTO recovery FROM control.platform_recovery_case c WHERE c.recovery_id=p_recovery
  AND openpc.matches_participant(c.participant_id) AND openpc.matches_privacy(c.privacy_domain_id);
 IF NOT FOUND OR recovery.signer_repair_enrollment_id IS NULL THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 SELECT * INTO enrollment FROM openpc.lock_identity_envelope_recovery_enrollment(recovery.signer_repair_enrollment_id);
 SELECT * INTO recovery FROM control.platform_recovery_case c WHERE c.recovery_id=p_recovery FOR UPDATE;
 IF enrollment.enrollment_id IS NULL OR recovery.state<>'REQUESTED' OR recovery.activated_at IS NOT NULL
  OR recovery.valid_from>clock_timestamp() OR recovery.valid_until<=clock_timestamp()
  OR recovery.intent_digest<>sha256(convert_to(openpc.signing_canonical_json(recovery.intent),'UTF8'))
  OR NOT coalesce(openpc.identity_envelope_recovery_proofs_current(recovery,p_activation),false)
  OR NOT openpc.identity_envelope_recovery_old_selection_current(enrollment.enrollment_id)
  OR recovery.intent->>'sourceIssuerPrincipalEpoch' IS DISTINCT FROM enrollment.document->>'issuerPrincipalEpoch'
  OR recovery.intent->>'sourceIssuerCredentialEpoch' IS DISTINCT FROM enrollment.document->>'issuerCredentialEpoch'
  OR recovery.intent->>'sourceParticipantEpoch' IS DISTINCT FROM enrollment.document->>'issuerParticipantEpoch'
  OR EXISTS(SELECT 1 FROM control.platform_recovery_case prior JOIN control.identity_envelope_recovery_enrollment original
    ON original.enrollment_id=prior.signer_repair_enrollment_id AND original.participant_id=prior.participant_id
    WHERE prior.participant_id=recovery.participant_id AND original.document->>'issuerPrincipalId'=enrollment.document->>'issuerPrincipalId'
     AND prior.recovery_id<>recovery.recovery_id AND prior.activated_at IS NOT NULL AND prior.reviewed_at IS NULL)
  OR EXISTS(SELECT 1 FROM control.signing_key_rotation rotation WHERE rotation.participant_id=enrollment.participant_id
    AND rotation.privacy_domain_id=enrollment.privacy_domain_id AND rotation.environment_id=enrollment.document#>>'{request,environmentId}'
    AND rotation.workload_credential_id::text=enrollment.document#>>'{request,workloadCredentialId}' AND rotation.state<>'COMPLETE')
  THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 PERFORM 1 FROM control.credential credential JOIN control.principal issuer
  ON issuer.participant_id=credential.participant_id AND issuer.principal_id=credential.principal_id
  JOIN control.participant participant ON participant.participant_id=issuer.participant_id
  WHERE credential.participant_id=enrollment.participant_id AND credential.credential_id::text=enrollment.document#>>'{request,workloadCredentialId}'
   AND issuer.principal_id::text=enrollment.document->>'issuerPrincipalId' AND issuer.kind='WORKLOAD' AND issuer.state='ACTIVE'
   AND issuer.authority_epoch::text=enrollment.document->>'issuerPrincipalEpoch'
   AND participant.state='ACTIVE' AND participant.authority_epoch::text=enrollment.document->>'issuerParticipantEpoch'
   AND credential.kind='WORKLOAD_MTLS' AND credential.state='ACTIVE' AND credential.credential_epoch::text=enrollment.document->>'issuerCredentialEpoch'
   AND 'sha256:'||encode(credential.public_key_digest,'hex')=enrollment.document->>'issuerCredentialPublicKeyDigest'
   AND credential.valid_from<=clock_timestamp() AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
  FOR UPDATE OF issuer FOR SHARE OF credential;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 UPDATE control.principal SET authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp()
  WHERE participant_id=enrollment.participant_id AND principal_id::text=enrollment.document->>'issuerPrincipalId'
   AND state='ACTIVE' AND authority_epoch=(enrollment.document->>'issuerPrincipalEpoch')::numeric RETURNING authority_epoch INTO epoch;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 UPDATE control.session SET state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='identity-envelope-signer-recovery',
  session_epoch=session_epoch+1,row_version=row_version+1,updated_at=clock_timestamp()
  WHERE participant_id=enrollment.participant_id AND principal_id::text=enrollment.document->>'issuerPrincipalId'
   AND state IN ('ACTIVE','STEP_UP_REQUIRED');
 RETURN epoch;
END $$;
REVOKE ALL ON FUNCTION openpc.fence_identity_envelope_recovery_issuer(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.fence_identity_envelope_recovery_issuer(uuid,uuid) TO openpc_control_runtime,openpc_control_platform_runtime;

-- Validate the exact recorded post-fence issuer. Epoch drift cannot be recaptured
-- as new authority, and an unchanged proof cannot refresh a signed lifetime.
CREATE OR REPLACE FUNCTION openpc.identity_envelope_recovery_rotation_selection_current(p_enrollment uuid,p_binding jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 IF openpc.identity_envelope_recovery_old_selection_current(p_enrollment) THEN RETURN true; END IF;
 RETURN EXISTS(SELECT 1 FROM control.identity_envelope_recovery_enrollment e
  JOIN control.signing_key_rotation r ON r.participant_id=e.participant_id AND r.privacy_domain_id=e.privacy_domain_id
    AND r.rotation_id::text=p_binding->>'rotationId' AND r.recovery_case_id::text=p_binding->>'recoveryId'
    AND r.old_signer_id=e.document#>>'{request,oldFingerprint}' AND r.approval_request_id IS NULL
    AND r.state IN('CUTOVER_FENCED','OBSERVING','OLD_REVOKED','OLD_RETIRED','COMPLETE')
  JOIN control.identity_envelope_rotation_step cutover ON cutover.participant_id=r.participant_id AND cutover.privacy_domain_id=r.privacy_domain_id
    AND cutover.rotation_id=r.rotation_id AND cutover.recovery_id=r.recovery_case_id AND cutover.state='COMMITTED'
    AND cutover.from_revision=5 AND cutover.from_state='VERIFIED' AND cutover.to_state='CUTOVER_FENCED'
    AND cutover.authority_binding=jsonb_build_object('kind','IDENTITY_ENVELOPE_SIGNER_RECOVERY','enrollment',e.document,'lease',p_binding)
    AND cutover.evidence_digest=sha256(cutover.evidence_cbor) AND octet_length(cutover.cose_sign1)>0
  JOIN control.identity_envelope_signing_selection selection ON selection.participant_id=r.participant_id AND selection.privacy_domain_id=r.privacy_domain_id
    AND selection.environment_id=r.environment_id AND selection.signer_id=r.new_signer_id
    AND selection.admission_version=(p_binding->>'selectionAdmissionVersion')::numeric+1
    AND selection.admission_version::text=cutover.result->>'selectionAdmissionVersion'
    AND selection.profile_digest=decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex')
  JOIN control.business_signing_key k ON k.participant_id=selection.participant_id AND k.privacy_domain_id=selection.privacy_domain_id
    AND k.signer_id=selection.signer_id AND k.signing_purpose_code=371 AND k.environment_id=selection.environment_id
    AND 'sha256:'||encode(k.trust_digest,'hex')=cutover.result->>'trustDigest'
  JOIN control.business_signing_key_state life ON life.participant_id=k.participant_id AND life.privacy_domain_id=k.privacy_domain_id
    AND life.signer_id=k.signer_id AND life.state='ACTIVE'
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
    AND k.workload_credential_id::text=p_binding#>>'{issuer,workloadCredentialId}'
    AND k.workload_credential_epoch::text=p_binding#>>'{issuer,workloadCredentialEpoch}'
    AND k.envelope_workload_participant_epoch::text=p_binding#>>'{issuer,workloadParticipantEpoch}'
    AND k.envelope_workload_principal_epoch::text=p_binding#>>'{issuer,workloadPrincipalEpoch}'
    AND k.valid_from_ns<=floor(extract(epoch from clock_timestamp())*1000000)*1000 AND k.valid_until_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000
    AND NOT EXISTS(SELECT 1 FROM control.business_signing_grant ordinary WHERE ordinary.participant_id=k.participant_id AND ordinary.privacy_domain_id=k.privacy_domain_id AND ordinary.signer_id=k.signer_id));
END $$;
REVOKE ALL ON FUNCTION openpc.identity_envelope_recovery_rotation_selection_current(uuid,jsonb) FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.identity_envelope_recovery_binding_current(p_enrollment uuid,p_intent jsonb,p_binding jsonb)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT p_binding->>'schema'='pc.identity.identity-envelope-recovery-lease' AND p_binding->>'schemaVersion'='1'
  AND p_binding->>'purpose'='IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY' AND p_binding->'postReviewRequired'='true'::jsonb
  AND p_binding-ARRAY['schema','schemaVersion','purpose','recoveryId','enrollmentId','enrollmentDigest','intentDigest','rotationId',
    'creationOperationId','activationOperationId','executorPrincipalId','issuer','oldTrustDigest','selectionAdmissionVersion',
    'proofIds','proofEvidenceDigest','validFrom','validUntil','postReviewRequired','lifetimes']='{}'::jsonb
  AND p_binding->'lifetimes' IS NOT DISTINCT FROM p_intent->'lifetimes'
  AND (NOT (p_binding ? 'lifetimes') OR p_binding#>>'{lifetimes,profile}'='LOCAL_QA_10X')
  AND p_binding->>'recoveryId'=p_intent->>'recoveryId' AND p_binding->>'enrollmentId'=p_intent->>'enrollmentId'
  AND p_binding->>'enrollmentDigest'=p_intent->>'enrollmentDigest'
  AND p_binding->>'intentDigest'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p_intent),'UTF8')),'hex')
  AND p_binding->>'rotationId'=p_intent->>'rotationId' AND p_binding->>'creationOperationId'=p_intent->>'creationOperationId'
  AND p_binding->>'oldTrustDigest'=p_intent->>'oldTrustDigest' AND p_binding->>'selectionAdmissionVersion'=p_intent->>'selectionAdmissionVersion'
  AND (p_binding->>'validFrom')::timestamptz>=(p_intent->>'validFrom')::timestamptz
  AND (p_binding->>'validFrom')::timestamptz<=clock_timestamp() AND (p_binding->>'validUntil')::timestamptz>clock_timestamp()
  AND (p_binding->>'validUntil')::timestamptz<=(p_intent->>'validUntil')::timestamptz
  AND (p_binding->>'validUntil')::timestamptz<=(p_binding->>'validFrom')::timestamptz+coalesce((p_binding#>>'{lifetimes,leaseMs}')::bigint,900000)*interval '1 millisecond'
  AND EXISTS(SELECT 1 FROM control.identity_envelope_recovery_enrollment e
   JOIN control.principal issuer ON issuer.participant_id=e.participant_id AND issuer.principal_id::text=e.document->>'issuerPrincipalId'
    AND issuer.state='ACTIVE' AND issuer.kind='WORKLOAD' AND issuer.authority_epoch=(p_intent->>'sourceIssuerPrincipalEpoch')::numeric+1
   JOIN control.participant participant ON participant.participant_id=e.participant_id AND participant.state='ACTIVE'
    AND participant.authority_epoch=(p_intent->>'sourceParticipantEpoch')::numeric
   JOIN control.credential credential ON credential.participant_id=e.participant_id AND credential.principal_id=issuer.principal_id
    AND credential.credential_id::text=e.document#>>'{request,workloadCredentialId}' AND credential.kind='WORKLOAD_MTLS'
    AND credential.state='ACTIVE' AND credential.credential_epoch=(p_intent->>'sourceIssuerCredentialEpoch')::numeric
    AND credential.valid_from<=clock_timestamp() AND (credential.valid_until IS NULL OR credential.valid_until>=(p_binding->>'validUntil')::timestamptz)
   WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
    AND e.enrollment_id::text=p_binding->>'enrollmentId' AND e.document_digest=decode(substr(p_binding->>'enrollmentDigest',8),'hex')
    AND e.state='ACTIVE' AND e.row_version=1 AND e.valid_until>=(p_binding->>'validUntil')::timestamptz
    AND openpc.identity_envelope_recovery_source_current(e.enrollment_id)
    AND openpc.identity_envelope_recovery_rotation_selection_current(e.enrollment_id,p_binding)
    AND p_binding->>'executorPrincipalId'=e.document#>>'{recoveryPrincipal,principalId}'
    AND p_binding->'issuer'=jsonb_build_object('participantId',e.participant_id::text,'privacyDomainId',e.privacy_domain_id::text,
      'workloadCredentialId',credential.credential_id::text,'workloadPrincipalId',issuer.principal_id::text,
      'workloadParticipantEpoch',participant.authority_epoch::text,'workloadPrincipalEpoch',issuer.authority_epoch::text,
      'workloadCredentialEpoch',credential.credential_epoch::text,'workloadPublicKeyDigest','sha256:'||encode(credential.public_key_digest,'hex'),
      'credentialValidFromNs',(floor(extract(epoch FROM credential.valid_from)*1000000)*1000)::text,
      'credentialValidUntilNs',(floor(extract(epoch FROM credential.valid_until)*1000000)*1000)::text)
    AND NOT EXISTS(SELECT 1 FROM control.session s WHERE s.participant_id=e.participant_id AND s.principal_id=issuer.principal_id
      AND s.state IN ('ACTIVE','STEP_UP_REQUIRED') AND s.authority_epoch<= (p_intent->>'sourceIssuerPrincipalEpoch')::numeric)
    AND jsonb_array_length(p_binding->'proofIds')=4
    AND p_binding->>'proofEvidenceDigest'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
      (SELECT jsonb_agg(jsonb_build_object('proofId',proof.proof_id::text,'principalId',proof.principal_id::text,
        'principalEpoch',proof.principal_epoch::text,'credentialId',proof.credential_id::text,'credentialEpoch',proof.credential_epoch::text,
        'sessionId',proof.session_id::text,'sessionEpoch',proof.session_epoch::text,'phase',proof.phase,
        'intentDigest','sha256:'||encode(proof.intent_digest,'hex'),
        'verifiedAt',to_char(proof.verified_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        'assertionDigest','sha256:'||encode(proof.assertion_digest,'hex')) ORDER BY names.ordinality)
       FROM jsonb_array_elements_text(p_binding->'proofIds') WITH ORDINALITY names(proof_id,ordinality)
       JOIN control.platform_recovery_proof proof ON proof.proof_id::text=names.proof_id
        AND proof.participant_id=e.participant_id AND proof.privacy_domain_id=e.privacy_domain_id
        AND proof.recovery_id::text=p_binding->>'recoveryId')),'UTF8')),'hex')
    AND (SELECT count(DISTINCT value) FROM jsonb_array_elements_text(p_binding->'proofIds'))=4
    AND (SELECT count(*) FROM control.platform_recovery_proof proof WHERE proof.participant_id=e.participant_id
      AND proof.privacy_domain_id=e.privacy_domain_id AND proof.recovery_id::text=p_binding->>'recoveryId'
      AND proof.intent_digest=decode(substr(p_binding->>'intentDigest',8),'hex'))=4
    AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(p_binding->'proofIds') supplied(proof_id)
      WHERE NOT EXISTS(SELECT 1 FROM control.platform_recovery_proof proof
       JOIN control.principal human ON human.participant_id=proof.participant_id AND human.principal_id=proof.principal_id
        AND human.state='ACTIVE' AND human.authority_epoch=proof.principal_epoch
       JOIN control.credential authenticator ON authenticator.participant_id=human.participant_id AND authenticator.principal_id=human.principal_id
        AND authenticator.credential_id=proof.credential_id AND authenticator.credential_epoch=proof.credential_epoch
        AND authenticator.state='ACTIVE' AND authenticator.kind='WEBAUTHN'
       JOIN control.session s ON s.participant_id=human.participant_id AND s.principal_id=human.principal_id AND s.session_id=proof.session_id
        AND s.authority_epoch=human.authority_epoch AND s.participant_epoch=participant.authority_epoch AND s.session_epoch=proof.session_epoch
        AND s.state='ACTIVE' AND s.context_mode='PLATFORM' AND s.privacy_domain_id IS NULL
       WHERE proof.proof_id::text=supplied.proof_id AND proof.participant_id=e.participant_id AND proof.privacy_domain_id=e.privacy_domain_id
        AND proof.recovery_id::text=p_binding->>'recoveryId' AND proof.intent_digest=decode(substr(p_binding->>'intentDigest',8),'hex')
        AND s.idle_expires_at>=(p_binding->>'validUntil')::timestamptz AND s.absolute_expires_at>=(p_binding->>'validUntil')::timestamptz
        AND authenticator.valid_from<=clock_timestamp() AND (authenticator.valid_until IS NULL OR authenticator.valid_until>=(p_binding->>'validUntil')::timestamptz)
        AND EXISTS(SELECT 1 FROM jsonb_array_elements(jsonb_build_array(e.document->'recoveryPrincipal')||e.document->'custodians') actor
          WHERE actor->>'principalId'=human.principal_id::text AND actor->>'credentialId'=authenticator.credential_id::text
           AND actor->>'principalEpoch'=human.authority_epoch::text AND actor->>'credentialEpoch'=authenticator.credential_epoch::text)
        AND (e.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' OR EXISTS(SELECT 1 FROM control.hardware_authenticator hardware
          WHERE hardware.participant_id=human.participant_id AND hardware.principal_id=human.principal_id AND hardware.credential_id=authenticator.credential_id)))))
$$;
REVOKE ALL ON FUNCTION openpc.identity_envelope_recovery_binding_current(uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.identity_envelope_recovery_binding_current(uuid,jsonb,jsonb) TO openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.identity_envelope_recovery_lease_current(p_recovery uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.platform_recovery_case c WHERE c.recovery_id=p_recovery
  AND c.state='ACTIVE' AND c.signer_repair_enrollment_id IS NOT NULL
  AND openpc.matches_participant(c.participant_id) AND openpc.matches_privacy(c.privacy_domain_id)
  AND c.activation_operation_id::text=c.lease_bindings->>'activationOperationId'
  AND c.activation_evidence_digest=sha256(c.activation_evidence_cbor) AND octet_length(c.activation_cose)>0
  AND openpc.identity_envelope_recovery_binding_current(c.signer_repair_enrollment_id,c.intent,c.lease_bindings));
$$;
REVOKE ALL ON FUNCTION openpc.identity_envelope_recovery_lease_current(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.identity_envelope_recovery_lease_current(uuid) TO openpc_control_runtime,openpc_control_platform_runtime;
`;
