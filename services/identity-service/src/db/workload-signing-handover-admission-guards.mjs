import { workloadSigningHandoverAdmissionOperation as operation } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.ts';
import { workloadHandoverCurrentIssuerValidationSql } from './workload-signing-handover-preparation-guards.mjs';
import { workloadHandoverGenerationPreparationsSql } from './workload-signing-handover-possession-guards.mjs';

/** Catalogue registration only. Retained authority grants and installation
 * ceilings are never rewritten by this migration owner. */
export const workloadSigningHandoverAdmissionGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,
 step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('${operation.actionIntentId}','${operation.resourceType}','ACTIVATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','SIGNING_KEY_LIFECYCLE')
ON CONFLICT(action_intent_id) DO NOTHING;

CREATE OR REPLACE FUNCTION openpc.assert_handover_admission_candidate(candidate_row control.mutation_candidate)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE candidate_material jsonb:=candidate_row.candidate_document; source_document jsonb; generation_document jsonb;
 owner_row control.workload_signing_handover; generation_row control.workload_signing_handover_generation;
 proof_document jsonb; key_document jsonb; selection_document jsonb; actual_count bigint;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'serializable'
  OR NOT openpc.matches_participant(candidate_row.participant_id) OR NOT openpc.matches_privacy(candidate_row.privacy_domain_id)
  OR candidate_row.catalog_operation_id<>'${operation.catalogOperationId}' OR candidate_row.action_intent_id<>'${operation.actionIntentId}'
  OR candidate_row.resource_type<>'${operation.resourceType}' OR candidate_row.operation_class<>'ACTIVATE'
  OR candidate_row.expected_revision<>1
  OR candidate_material-ARRAY['schema','participantId','privacyDomainId','environmentId','handoverId','makerPrincipalId','workloadId','catalogOperationId','expectedRevision','validityPolicy','request','preparedAtNs','expiresAtNs','source','generation','predecessorTrusts','proofs']<>'{}'::jsonb
  OR NOT candidate_material ?& ARRAY['schema','participantId','privacyDomainId','environmentId','handoverId','makerPrincipalId','workloadId','catalogOperationId','expectedRevision','validityPolicy','request','preparedAtNs','expiresAtNs','source','generation','predecessorTrusts','proofs']
  OR candidate_material->>'schema' IS DISTINCT FROM 'pc.identity.workload-signing-handover.admission-candidate.v1'
  OR candidate_material->>'participantId' IS DISTINCT FROM candidate_row.participant_id::text
  OR candidate_material->>'privacyDomainId' IS DISTINCT FROM candidate_row.privacy_domain_id::text
  OR candidate_material->>'handoverId' IS DISTINCT FROM candidate_row.resource_id::text
  OR candidate_material->>'makerPrincipalId' IS DISTINCT FROM candidate_row.maker_principal_id::text
  OR candidate_material->>'catalogOperationId' IS DISTINCT FROM candidate_row.catalog_operation_id
  OR candidate_material->>'expectedRevision' IS DISTINCT FROM '1'
  OR candidate_material->>'validityPolicy' IS DISTINCT FROM 'FROM_ATOMIC_ADMISSION_TO_EARLIEST_KEY_OR_CREDENTIAL_EXPIRY'
  OR candidate_material->'request'->>'actionIntentId' IS DISTINCT FROM candidate_row.action_intent_id
  OR candidate_material->'request'->>'actionIntentDigest' IS DISTINCT FROM
    (SELECT 'sha256:'||encode(semantic_digest,'hex') FROM control.action_intent WHERE action_intent_id=candidate_row.action_intent_id)
  OR candidate_row.candidate_digest<>sha256(convert_to(openpc.signing_canonical_json(candidate_material),'UTF8'))
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ADMISSION-CANDIDATE'; END IF;
 SELECT * INTO STRICT owner_row FROM control.workload_signing_handover WHERE participant_id=candidate_row.participant_id
  AND privacy_domain_id=candidate_row.privacy_domain_id AND handover_id=candidate_row.resource_id
  AND maker_principal_id=candidate_row.maker_principal_id;
 SELECT * INTO STRICT generation_row FROM control.workload_signing_handover_generation WHERE participant_id=candidate_row.participant_id
  AND privacy_domain_id=candidate_row.privacy_domain_id AND handover_id=owner_row.handover_id
  AND generation_id=(candidate_material->'request'->>'generationId')::uuid AND maker_principal_id=candidate_row.maker_principal_id;
 source_document:=owner_row.source; generation_document:=generation_row.document;
${workloadHandoverCurrentIssuerValidationSql.replaceAll('NEW.', 'candidate_row.')}
${workloadHandoverGenerationPreparationsSql.replaceAll('NEW.', 'candidate_row.')}
 IF candidate_material->'source' IS DISTINCT FROM source_document OR candidate_material->'generation' IS DISTINCT FROM generation_document
  OR candidate_material->>'environmentId' IS DISTINCT FROM owner_row.environment_id
  OR candidate_material->'request'->>'generationDigest' IS DISTINCT FROM 'sha256:'||encode(generation_row.document_digest,'hex')
  OR candidate_material->>'expiresAtNs' IS DISTINCT FROM generation_document->>'expiresAtNs'
  OR candidate_material->>'preparedAtNs' !~ '^[1-9][0-9]{0,19}$' OR mod((candidate_material->>'preparedAtNs')::numeric,1000)<>0
  OR (candidate_material->>'preparedAtNs')::numeric<(generation_document->>'issuedAtNs')::numeric
  OR (candidate_material->>'preparedAtNs')::numeric>floor(extract(epoch from clock_timestamp())*1000000)*1000
  OR (candidate_material->>'expiresAtNs')::numeric<=floor(extract(epoch from clock_timestamp())*1000000)*1000
  OR candidate_row.expires_at<=clock_timestamp()
  OR extract(epoch from candidate_row.expires_at)*1000000000>(generation_document->>'expiresAtNs')::numeric
  OR EXISTS(SELECT 1 FROM control.workload_signing_handover_generation WHERE participant_id=candidate_row.participant_id
   AND privacy_domain_id=candidate_row.privacy_domain_id AND supersedes_generation_id=generation_row.generation_id)
  OR NOT EXISTS(SELECT 1 FROM control.credential credential WHERE credential.participant_id=candidate_row.participant_id
    AND credential.credential_id=owner_row.successor_credential_id AND credential.audience=candidate_material->>'workloadId')
  OR NOT EXISTS(SELECT 1 FROM control.credential credential WHERE credential.participant_id=candidate_row.participant_id
    AND credential.credential_id=owner_row.predecessor_credential_id AND credential.principal_id=owner_row.workload_principal_id
    AND credential.audience=candidate_material->>'workloadId' AND credential.kind='WORKLOAD_MTLS' AND credential.state='REVOKED'
    AND credential.credential_epoch::text=source_document->'issuer'->>'workloadCredentialEpoch')
  OR jsonb_typeof(candidate_material->'proofs') IS DISTINCT FROM 'array'
  OR jsonb_typeof(candidate_material->'predecessorTrusts') IS DISTINCT FROM 'array'
  OR jsonb_array_length(candidate_material->'proofs')<>jsonb_array_length(source_document->'keys')
  OR jsonb_array_length(candidate_material->'predecessorTrusts')<>jsonb_array_length(source_document->'keys')
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ADMISSION-CURRENT'; END IF;
 FOR key_document IN SELECT value FROM jsonb_array_elements(source_document->'keys') LOOP
  IF NOT EXISTS(SELECT 1 FROM control.business_signing_key key JOIN control.business_signing_key_state lifecycle USING(participant_id,privacy_domain_id,signer_id)
    WHERE key.participant_id=candidate_row.participant_id AND key.privacy_domain_id=candidate_row.privacy_domain_id
     AND key.signer_id=key_document->>'oldFingerprint' AND key.environment_id=owner_row.environment_id
     AND key.workload_credential_id=owner_row.predecessor_credential_id AND key.key_epoch::text=key_document->>'expectedKeyEpoch'
     AND key.trust_digest=decode(substr(key_document->>'oldTrustDigest',8),'hex')
     AND key.trust_preimage=decode(key_document->>'oldTrustPreimageBase64','base64') AND lifecycle.state='ACTIVE')
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ADMISSION-OLD-TRUST'; END IF;
 END LOOP;
 FOR proof_document IN SELECT value FROM jsonb_array_elements(candidate_material->'proofs') LOOP
  IF NOT EXISTS(SELECT 1 FROM control.workload_signing_handover_attempt command
    JOIN control.workload_signing_handover_dispatch dispatch USING(participant_id,privacy_domain_id,attempt_id)
    WHERE command.participant_id=candidate_row.participant_id AND command.privacy_domain_id=candidate_row.privacy_domain_id
     AND command.handover_id=owner_row.handover_id AND command.generation_id=generation_row.generation_id AND command.stage='POSSESSION'
     AND command.attempt=proof_document->'attempt'
     AND EXISTS(SELECT 1 FROM control.workload_signing_handover_observation observed WHERE observed.participant_id=command.participant_id
       AND observed.privacy_domain_id=command.privacy_domain_id AND observed.attempt_id=command.attempt_id
       AND observed.result->>'state'='OBSERVED' AND observed.result->'observation'=proof_document->'observation'
       AND observed.result->'observation'->>'outcome'='SUCCEEDED')
     AND NOT EXISTS(SELECT 1 FROM control.workload_signing_handover_observation observed WHERE observed.participant_id=command.participant_id
       AND observed.privacy_domain_id=command.privacy_domain_id AND observed.attempt_id=command.attempt_id
       AND observed.result->>'state'='OBSERVED' AND observed.result->'observation' IS DISTINCT FROM proof_document->'observation'))
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ADMISSION-PROOF'; END IF;
 END LOOP;
 IF (SELECT count(DISTINCT value->'attempt'->'request'->>'attemptId') FROM jsonb_array_elements(candidate_material->'proofs'))<>jsonb_array_length(source_document->'keys')
  OR EXISTS(SELECT 1 FROM control.business_signing_key key JOIN jsonb_array_elements(generation_document->'keys') prepared
    ON key.signer_id=prepared->'observation'->'descriptor'->>'fingerprint'
    WHERE key.participant_id=candidate_row.participant_id AND key.privacy_domain_id=candidate_row.privacy_domain_id)
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ADMISSION-KEY-SET'; END IF;
 FOR selection_document IN SELECT value FROM jsonb_array_elements(source_document->'receiptSelections') LOOP
  IF NOT EXISTS(SELECT 1 FROM control.business_signing_selection selection WHERE selection.participant_id=candidate_row.participant_id
    AND selection.privacy_domain_id=candidate_row.privacy_domain_id AND selection.environment_id=owner_row.environment_id
    AND selection.signer_id=selection_document->>'signerId' AND selection.profile_digest=decode(substr(selection_document->>'profileDigest',8),'hex')
    AND selection.row_version::text=selection_document->>'rowVersion' AND selection.admission_version::text=selection_document->>'admissionVersion'
    AND selection.fence_generation::text=selection_document->>'fenceGeneration' AND selection.fenced_operation_id IS NULL)
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ADMISSION-SELECTION'; END IF;
 END LOOP;
 FOR selection_document IN SELECT value FROM jsonb_array_elements(source_document->'envelopeSelections') LOOP
  IF NOT EXISTS(SELECT 1 FROM control.identity_envelope_signing_selection selection WHERE selection.participant_id=candidate_row.participant_id
    AND selection.privacy_domain_id=candidate_row.privacy_domain_id AND selection.environment_id=owner_row.environment_id
    AND selection.signer_id=selection_document->>'signerId' AND selection.profile_digest=decode(substr(selection_document->>'profileDigest',8),'hex')
    AND selection.admission_version::text=selection_document->>'admissionVersion')
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ADMISSION-ENVELOPE-SELECTION'; END IF;
 END LOOP;
 SELECT count(*) INTO actual_count FROM control.business_signing_selection selection JOIN control.business_signing_key key USING(participant_id,privacy_domain_id,signer_id)
  JOIN control.credential credential ON credential.participant_id=key.participant_id AND credential.credential_id=key.workload_credential_id
  WHERE selection.participant_id=candidate_row.participant_id AND selection.privacy_domain_id=candidate_row.privacy_domain_id
   AND selection.environment_id=owner_row.environment_id AND credential.principal_id=owner_row.workload_principal_id AND credential.audience=candidate_material->>'workloadId';
 IF actual_count<>jsonb_array_length(source_document->'receiptSelections') THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ADMISSION-COMPLETE-SELECTIONS'; END IF;
 SELECT count(*) INTO actual_count FROM control.identity_envelope_signing_selection selection JOIN control.business_signing_key key USING(participant_id,privacy_domain_id,signer_id)
  JOIN control.credential credential ON credential.participant_id=key.participant_id AND credential.credential_id=key.workload_credential_id
  WHERE selection.participant_id=candidate_row.participant_id AND selection.privacy_domain_id=candidate_row.privacy_domain_id
   AND selection.environment_id=owner_row.environment_id AND credential.principal_id=owner_row.workload_principal_id AND credential.audience=candidate_material->>'workloadId';
 IF actual_count<>jsonb_array_length(source_document->'envelopeSelections') THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ADMISSION-COMPLETE-ENVELOPE'; END IF;
 IF EXISTS(SELECT 1 FROM control.workload_renewal_signing_selection selection JOIN control.business_signing_key key USING(participant_id,privacy_domain_id,signer_id)
  JOIN control.credential credential ON credential.participant_id=key.participant_id AND credential.credential_id=key.workload_credential_id
  WHERE selection.participant_id=candidate_row.participant_id AND selection.privacy_domain_id=candidate_row.privacy_domain_id
   AND selection.environment_id=owner_row.environment_id AND credential.principal_id=owner_row.workload_principal_id AND credential.audience=candidate_material->>'workloadId')
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ADMISSION-UNDISCLOSED-RENEWAL'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_handover_admission_candidate()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.catalog_operation_id='${operation.catalogOperationId}' THEN
  IF TG_OP<>'INSERT' OR openpc.current_action_intent_id()<>'${operation.actionIntentId}' THEN RAISE EXCEPTION 'PC-AUTH-0005-HANDOVER-ADMISSION-STAGING'; END IF;
  PERFORM openpc.assert_handover_admission_candidate(NEW);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER handover_admission_candidate_guard BEFORE INSERT ON control.mutation_candidate
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_handover_admission_candidate();

CREATE OR REPLACE FUNCTION openpc.guard_handover_admission_candidate_commit()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.catalog_operation_id='${operation.catalogOperationId}' THEN PERFORM openpc.assert_handover_admission_candidate(NEW); END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER handover_admission_candidate_commit_guard AFTER INSERT ON control.mutation_candidate
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_handover_admission_candidate_commit();

CREATE OR REPLACE FUNCTION openpc.guard_handover_admission_approval()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE candidate_row control.mutation_candidate;
BEGIN
 IF NEW.action_intent_id='${operation.actionIntentId}' THEN
  IF NEW.subject_type<>'CONFIGURATION_CANDIDATE' THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-APPROVAL-SUBJECT'; END IF;
  SELECT * INTO STRICT candidate_row FROM control.mutation_candidate WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND mutation_candidate_id=NEW.subject_id
    AND maker_principal_id=NEW.maker_principal_id AND candidate_digest=NEW.subject_digest;
  IF TG_OP='INSERT' OR (NEW.state='APPROVED' AND OLD.state IS DISTINCT FROM 'APPROVED') THEN
   PERFORM openpc.assert_handover_admission_candidate(candidate_row);
   IF NEW.expires_at>candidate_row.expires_at THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-APPROVAL-EXPIRY'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER handover_admission_approval_guard BEFORE INSERT OR UPDATE ON control.approval_request
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_handover_admission_approval();
`;

/** The assertion reads through the caller's existing scoped rights. It cannot
 * grant signing authority or bypass the candidate's context/source checks. */
export const workloadSigningHandoverAdmissionGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.assert_handover_admission_candidate(control.mutation_candidate)
 TO openpc_control_runtime,openpc_control_platform_runtime;
`;
