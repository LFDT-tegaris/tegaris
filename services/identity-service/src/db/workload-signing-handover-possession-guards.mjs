import {
  workloadHandoverAuthorityValidationSql,
  workloadHandoverCurrentIssuerValidationSql,
} from './workload-signing-handover-preparation-guards.mjs';

/** Requires generation_document and key_document variables in the caller. */
export const workloadHandoverGenerationPreparationsSql = `
 FOR key_document IN SELECT value FROM jsonb_array_elements(generation_document->'keys') LOOP
  IF NOT EXISTS(SELECT 1 FROM control.workload_signing_handover_attempt a
   JOIN control.workload_signing_handover_dispatch d USING(participant_id,privacy_domain_id,attempt_id)
   WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id
    AND a.handover_id=(generation_document->>'handoverId')::uuid AND a.stage='PREPARATION'
    AND a.attempt_id=(key_document->'attempt'->'request'->>'attemptId')::uuid
    AND a.binding=key_document->'binding' AND a.attempt=key_document->'attempt'
    AND EXISTS(SELECT 1 FROM control.workload_signing_handover_observation o
     WHERE o.participant_id=a.participant_id AND o.privacy_domain_id=a.privacy_domain_id AND o.attempt_id=a.attempt_id
      AND o.result->>'state'='OBSERVED' AND o.result->'observation'=key_document->'observation')
    AND NOT EXISTS(SELECT 1 FROM control.workload_signing_handover_observation o
     WHERE o.participant_id=a.participant_id AND o.privacy_domain_id=a.privacy_domain_id AND o.attempt_id=a.attempt_id
      AND o.result->>'state'='OBSERVED' AND o.result->'observation' IS DISTINCT FROM key_document->'observation'))
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-GENERATION-PREPARATION-CONFLICT'; END IF;
 END LOOP;
`;

export const workloadSigningHandoverPossessionGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_workload_handover_generation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE snapshot jsonb; expected jsonb; bound jsonb; source_document jsonb; generation_document jsonb;
 owner_row control.workload_signing_handover; parent control.workload_signing_handover_generation;
 key_document jsonb; descriptor jsonb; proof_row control.workload_signing_handover_attempt; prior text; seen_fingerprints text[]:=array[]::text[]; seen_references text[]:=array[]::text[];
BEGIN
${workloadHandoverAuthorityValidationSql}
 SELECT * INTO STRICT owner_row FROM control.workload_signing_handover WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND handover_id=NEW.handover_id AND maker_principal_id=NEW.maker_principal_id;
 source_document:=owner_row.source; generation_document:=NEW.document;
${workloadHandoverCurrentIssuerValidationSql}
 IF NEW.request_canonical<>convert_to(openpc.signing_canonical_json(NEW.request),'UTF8')
  OR NEW.request_digest<>sha256(convert_to('pc.identity.workload-signing-handover.possession-generation-request.v1','UTF8')||decode('00','hex')||NEW.request_canonical)
  OR NEW.document_canonical<>convert_to(openpc.signing_canonical_json(generation_document),'UTF8')
  OR NEW.document_digest<>sha256(convert_to('pc.identity.workload-signing-handover.possession-generation.v1','UTF8')||decode('00','hex')||NEW.document_canonical)
  OR NEW.request-ARRAY['schemaVersion','supersedesGenerationId','reason']<>'{}'::jsonb
  OR NOT NEW.request ?& ARRAY['schemaVersion','supersedesGenerationId','reason']
  OR NEW.request->>'schemaVersion' IS DISTINCT FROM '1'
  OR NEW.request->>'supersedesGenerationId' IS DISTINCT FROM NEW.supersedes_generation_id::text
  OR jsonb_typeof(NEW.request->'reason') IS DISTINCT FROM 'string' OR char_length(NEW.request->>'reason') NOT BETWEEN 12 AND 1024
  OR generation_document-ARRAY['schema','participantId','privacyDomainId','environmentId','handoverId','sourceDigest','generationId','operationId','makerPrincipalId','supersedesGenerationId','issuedAtNs','expiresAtNs','issuer','keys']<>'{}'::jsonb
  OR NOT generation_document ?& ARRAY['schema','participantId','privacyDomainId','environmentId','handoverId','sourceDigest','generationId','operationId','makerPrincipalId','supersedesGenerationId','issuedAtNs','expiresAtNs','issuer','keys']
  OR generation_document->>'schema' IS DISTINCT FROM 'pc.identity.workload-signing-handover.possession-generation.v1'
  OR generation_document->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR generation_document->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR generation_document->>'environmentId' IS DISTINCT FROM owner_row.environment_id
  OR generation_document->>'handoverId' IS DISTINCT FROM NEW.handover_id::text
  OR generation_document->>'generationId' IS DISTINCT FROM NEW.generation_id::text
  OR generation_document->>'operationId' IS DISTINCT FROM NEW.operation_id::text
  OR generation_document->>'makerPrincipalId' IS DISTINCT FROM NEW.maker_principal_id::text
  OR generation_document->>'supersedesGenerationId' IS DISTINCT FROM NEW.supersedes_generation_id::text
  OR generation_document->>'sourceDigest' IS DISTINCT FROM 'sha256:'||encode(owner_row.source_digest,'hex')
  OR generation_document->'issuer' IS DISTINCT FROM source_document->'issuer'
  OR generation_document->>'issuedAtNs' !~ '^[1-9][0-9]{0,19}$' OR generation_document->>'expiresAtNs' !~ '^[1-9][0-9]{0,19}$'
  OR mod((generation_document->>'issuedAtNs')::numeric,1000)<>0 OR mod((generation_document->>'expiresAtNs')::numeric,1000)<>0
  OR (generation_document->>'issuedAtNs')::numeric>NEW.recorded_at_ns
  OR (generation_document->>'expiresAtNs')::numeric<=floor(extract(epoch from clock_timestamp())*1000000)*1000
  OR (generation_document->>'expiresAtNs')::numeric<=(generation_document->>'issuedAtNs')::numeric
  OR (generation_document->>'expiresAtNs')::numeric-(generation_document->>'issuedAtNs')::numeric>300000000000
  OR (generation_document->>'expiresAtNs')::numeric>18446744073709551615
  OR (generation_document->>'issuedAtNs')::numeric<(source_document->'issuer'->>'credentialValidFromNs')::numeric
  OR (source_document->'issuer'->>'credentialValidUntilNs' IS NOT NULL AND (generation_document->>'expiresAtNs')::numeric>(source_document->'issuer'->>'credentialValidUntilNs')::numeric)
  OR jsonb_typeof(generation_document->'keys') IS DISTINCT FROM 'array'
  OR jsonb_array_length(generation_document->'keys')<>jsonb_array_length(source_document->'keys')
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-GENERATION-CUSTODY'; END IF;
 prior:='';
 FOR key_document IN SELECT value FROM jsonb_array_elements(generation_document->'keys') LOOP
  descriptor:=key_document->'observation'->'descriptor';
  IF key_document-ARRAY['binding','attempt','observation']<>'{}'::jsonb OR NOT key_document ?& ARRAY['binding','attempt','observation']
   OR key_document->'binding'->>'handoverId' IS DISTINCT FROM NEW.handover_id::text
   OR key_document->'binding'->>'sourceDigest' IS DISTINCT FROM 'sha256:'||encode(owner_row.source_digest,'hex')
   OR key_document->'binding'->'replacement'->>'oldFingerprint' IS NULL
   OR key_document->'binding'->'replacement'->>'oldFingerprint'<=prior
   OR key_document->'observation'->>'outcome' IS DISTINCT FROM 'SUCCEEDED'
   OR (key_document->'observation'->>'recordedAtNs')::numeric>(generation_document->>'issuedAtNs')::numeric
   OR jsonb_typeof(descriptor) IS DISTINCT FROM 'object' OR descriptor->>'state' IS DISTINCT FROM 'ACTIVE'
   OR descriptor->'revokedAtNs' IS DISTINCT FROM 'null'::jsonb OR descriptor->'retiredAtNs' IS DISTINCT FROM 'null'::jsonb
   OR (descriptor->>'validFromNs')::numeric>(generation_document->>'issuedAtNs')::numeric
   OR (descriptor->>'validUntilNs')::numeric<(generation_document->>'expiresAtNs')::numeric
   OR descriptor->>'fingerprint'=any(seen_fingerprints) OR descriptor->>'reference'=any(seen_references)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(source_document->'keys') old_key WHERE old_key->>'oldFingerprint'=descriptor->>'fingerprint')
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-GENERATION-KEY'; END IF;
  prior:=key_document->'binding'->'replacement'->>'oldFingerprint';
  seen_fingerprints:=array_append(seen_fingerprints,descriptor->>'fingerprint');seen_references:=array_append(seen_references,descriptor->>'reference');
 END LOOP;
${workloadHandoverGenerationPreparationsSql}
 IF NEW.supersedes_generation_id IS NOT NULL THEN
  SELECT * INTO STRICT parent FROM control.workload_signing_handover_generation WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND generation_id=NEW.supersedes_generation_id
   AND handover_id=NEW.handover_id AND maker_principal_id=NEW.maker_principal_id;
  IF (parent.document->>'expiresAtNs')::numeric>(generation_document->>'issuedAtNs')::numeric
   OR EXISTS(SELECT 1 FROM control.workload_signing_handover_generation WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND supersedes_generation_id=parent.generation_id)
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-GENERATION-REFRESH'; END IF;
  FOR proof_row IN SELECT * FROM control.workload_signing_handover_attempt WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND generation_id=parent.generation_id AND stage='POSSESSION' LOOP
   IF NOT EXISTS(SELECT 1 FROM control.workload_signing_handover_observation o
    WHERE o.participant_id=NEW.participant_id AND o.privacy_domain_id=NEW.privacy_domain_id AND o.attempt_id=proof_row.attempt_id
     AND o.result->>'state'='OBSERVED' AND o.result->'observation'->>'outcome'='SUCCEEDED')
    OR (SELECT count(DISTINCT result->'observation') FROM control.workload_signing_handover_observation
     WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=proof_row.attempt_id AND result->>'state'='OBSERVED')<>1
   THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-GENERATION-UNSETTLED'; END IF;
  END LOOP;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workload_handover_generation_guard BEFORE INSERT ON control.workload_signing_handover_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_handover_generation();

CREATE OR REPLACE FUNCTION openpc.guard_workload_handover_generation_complete()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE snapshot jsonb; expected jsonb; bound jsonb; source_document jsonb;
BEGIN
${workloadHandoverAuthorityValidationSql}
 SELECT source INTO STRICT source_document FROM control.workload_signing_handover WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND handover_id=NEW.handover_id;
${workloadHandoverCurrentIssuerValidationSql}
 IF (NEW.document->>'expiresAtNs')::numeric<=floor(extract(epoch from clock_timestamp())*1000000)*1000
  OR (SELECT count(*) FROM control.workload_signing_handover_attempt WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND handover_id=NEW.handover_id AND generation_id=NEW.generation_id AND stage='POSSESSION')<>jsonb_array_length(NEW.document->'keys')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.document->'keys') key_document WHERE NOT EXISTS(
   SELECT 1 FROM control.workload_signing_handover_attempt command WHERE command.participant_id=NEW.participant_id
    AND command.privacy_domain_id=NEW.privacy_domain_id AND command.handover_id=NEW.handover_id AND command.generation_id=NEW.generation_id
    AND command.stage='POSSESSION' AND command.predecessor_fingerprint=key_document->'binding'->'replacement'->>'oldFingerprint'))
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-GENERATION-INCOMPLETE'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER workload_handover_generation_complete_guard AFTER INSERT ON control.workload_signing_handover_generation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_handover_generation_complete();

CREATE OR REPLACE FUNCTION openpc.guard_workload_handover_possession_attempt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE snapshot jsonb; expected jsonb; bound jsonb; source_document jsonb; generation_document jsonb;
 generation_row control.workload_signing_handover_generation; key_document jsonb; request_document jsonb; request_domain text;
BEGIN
${workloadHandoverAuthorityValidationSql}
 SELECT * INTO STRICT generation_row FROM control.workload_signing_handover_generation WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND generation_id=NEW.generation_id AND handover_id=NEW.handover_id
  AND operation_id=NEW.operation_id AND maker_principal_id=NEW.maker_principal_id;
 generation_document:=generation_row.document;
 SELECT source INTO STRICT source_document FROM control.workload_signing_handover WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND handover_id=NEW.handover_id;
${workloadHandoverCurrentIssuerValidationSql}
 SELECT value INTO STRICT key_document FROM jsonb_array_elements(generation_document->'keys') WHERE value->'binding'->'replacement'->>'oldFingerprint'=NEW.predecessor_fingerprint;
 request_document:=NEW.attempt->'request';request_domain:=CASE WHEN NEW.attempt->>'purpose'='pc.cose.identity-authority-envelope.v1' THEN 'pc.identity.envelope-key-rotation-request.v1' ELSE 'pc.control.signing-provider-request.v1' END;
 IF NEW.stage<>'POSSESSION' OR NEW.recorded_at_ns<generation_row.recorded_at_ns
  OR NEW.authority_snapshot_digest<>generation_row.authority_snapshot_digest
  OR NEW.authority_snapshot<>generation_row.authority_snapshot
  OR (generation_document->>'expiresAtNs')::numeric<=floor(extract(epoch from clock_timestamp())*1000000)*1000
  OR NEW.preparation_attempt_id::text IS DISTINCT FROM key_document->'attempt'->'request'->>'attemptId'
  OR NEW.binding IS DISTINCT FROM key_document->'binding'
  OR NEW.binding_canonical<>convert_to(openpc.signing_canonical_json(NEW.binding),'UTF8')
  OR NEW.binding_digest<>sha256(convert_to('pc.identity.workload-signing-handover.provider-binding.v1','UTF8')||decode('00','hex')||NEW.binding_canonical)
  OR NEW.attempt_canonical<>convert_to(openpc.signing_canonical_json(NEW.attempt),'UTF8')
  OR NEW.attempt_digest<>sha256(convert_to('pc.identity.workload-signing-handover.possession-attempt.v1','UTF8')||decode('00','hex')||NEW.attempt_canonical)
  OR NEW.attempt-ARRAY['schemaVersion','stage','handoverId','sourceDigest','predecessorFingerprint','providerId','bindingDigest','requestDigest','generationId','generationDigest','preparationAttemptId','preparationAttemptDigest','preparationObservationDigest','challengeNonceHex','purpose','signerRole','request']<>'{}'::jsonb
  OR NEW.attempt->>'schemaVersion' IS DISTINCT FROM '1' OR NEW.attempt->>'stage' IS DISTINCT FROM 'POSSESSION'
  OR NEW.attempt->>'handoverId' IS DISTINCT FROM NEW.handover_id::text
  OR NEW.attempt->>'sourceDigest' IS DISTINCT FROM generation_document->>'sourceDigest'
  OR NEW.attempt->>'generationId' IS DISTINCT FROM NEW.generation_id::text
  OR NEW.attempt->>'generationDigest' IS DISTINCT FROM 'sha256:'||encode(generation_row.document_digest,'hex')
  OR NEW.attempt->>'predecessorFingerprint' IS DISTINCT FROM NEW.predecessor_fingerprint
  OR NEW.attempt->>'providerId' IS DISTINCT FROM NEW.provider_id OR NEW.provider_id IS DISTINCT FROM NEW.binding->>'providerId'
  OR NEW.attempt->>'bindingDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.binding_digest,'hex')
  OR NEW.attempt->>'preparationAttemptId' IS DISTINCT FROM NEW.preparation_attempt_id::text
  OR NEW.attempt->>'preparationAttemptDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('pc.identity.workload-signing-handover.provider-attempt.v1','UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json(key_document->'attempt'),'UTF8')),'hex')
  OR NEW.attempt->>'preparationObservationDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('pc.identity.workload-signing-handover.provider-observation.v1','UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json(key_document->'observation'),'UTF8')),'hex')
  OR NEW.attempt->>'challengeNonceHex' IS NULL OR NEW.attempt->>'challengeNonceHex' !~ '^[0-9a-f]{64}$'
  OR NEW.attempt->>'purpose' IS DISTINCT FROM key_document->'attempt'->>'purpose'
  OR NEW.attempt->>'signerRole' IS DISTINCT FROM key_document->'attempt'->>'signerRole'
  OR NEW.attempt->>'requestDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(request_domain,'UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json(request_document),'UTF8')),'hex')
  OR request_document->>'method' IS DISTINCT FROM 'PROVE'
  OR request_document->>'operationId' IS DISTINCT FROM NEW.operation_id::text
  OR request_document->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text
  OR request_document->>'rotationId' IS DISTINCT FROM NEW.handover_id::text
  OR request_document->>'expectedFingerprint' IS DISTINCT FROM key_document->'observation'->'descriptor'->>'fingerprint'
  OR request_document->>'challengeHex' IS DISTINCT FROM encode(sha256(convert_to('pc.identity.workload-signing-handover.possession-challenge.v1','UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json((NEW.attempt-ARRAY['purpose','signerRole','request','requestDigest'])||jsonb_build_object('operationId',NEW.operation_id::text,'attemptId',NEW.attempt_id::text,'issuedAtNs',generation_document->>'issuedAtNs','expiresAtNs',generation_document->>'expiresAtNs')),'UTF8')),'hex')
  OR request_document ? 'recoveryPredecessor'
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-POSSESSION-CUSTODY'; END IF;
 expected:=key_document->'attempt'->'request';
 IF NEW.attempt->>'purpose'='pc.cose.identity-authority-envelope.v1' THEN
  expected:=(expected-'method')||jsonb_build_object('method','PROVE','operationId',NEW.operation_id::text,'attemptId',NEW.attempt_id::text,'expectedFingerprint',key_document->'observation'->'descriptor'->>'fingerprint','challengeHex',request_document->>'challengeHex','challengeIssuedAtNs',generation_document->>'issuedAtNs','challengeExpiresAtNs',generation_document->>'expiresAtNs','governanceDigest','sha256:'||encode(generation_row.document_digest,'hex'));
 ELSE
  expected:=expected||jsonb_build_object('method','PROVE','operationId',NEW.operation_id::text,'attemptId',NEW.attempt_id::text,'rotationId',NEW.handover_id::text,'expectedFingerprint',key_document->'observation'->'descriptor'->>'fingerprint','challengeHex',request_document->>'challengeHex');
 END IF;
 IF request_document IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-POSSESSION-REQUEST'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workload_handover_possession_guard BEFORE INSERT ON control.workload_signing_handover_attempt
 FOR EACH ROW WHEN(NEW.stage='POSSESSION') EXECUTE FUNCTION openpc.guard_workload_handover_possession_attempt();
`;
