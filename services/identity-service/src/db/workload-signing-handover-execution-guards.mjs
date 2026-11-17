import {
  workloadHandoverAuthorityValidationSql,
  workloadHandoverCurrentIssuerValidationSql,
} from './workload-signing-handover-preparation-guards.mjs';
import { workloadHandoverGenerationPreparationsSql } from './workload-signing-handover-possession-guards.mjs';

export const workloadSigningHandoverExecutionGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_workload_signing_handover_dispatch()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE snapshot jsonb; expected jsonb; bound jsonb; source_document jsonb;
 command control.workload_signing_handover_attempt; owner_row control.workload_signing_handover;
 generation_row control.workload_signing_handover_generation; generation_document jsonb; key_document jsonb;
BEGIN
${workloadHandoverAuthorityValidationSql}
 SELECT * INTO STRICT command FROM control.workload_signing_handover_attempt
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.attempt_id;
 SELECT * INTO STRICT owner_row FROM control.workload_signing_handover
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND handover_id=NEW.handover_id;
 IF command.handover_id<>NEW.handover_id OR command.maker_principal_id<>NEW.maker_principal_id
  OR owner_row.maker_principal_id<>NEW.maker_principal_id OR NEW.attempt_digest<>command.attempt_digest
  OR NEW.source_digest<>owner_row.source_digest
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-DISPATCH-CUSTODY'; END IF;
 source_document:=owner_row.source;
${workloadHandoverCurrentIssuerValidationSql}
 IF command.stage='POSSESSION' THEN
  SELECT * INTO STRICT generation_row FROM control.workload_signing_handover_generation WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND generation_id=command.generation_id AND handover_id=NEW.handover_id;
  generation_document:=generation_row.document;
  IF (generation_document->>'expiresAtNs')::numeric<=floor(extract(epoch from clock_timestamp())*1000000)*1000
   OR EXISTS(SELECT 1 FROM control.workload_signing_handover_generation WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND supersedes_generation_id=generation_row.generation_id)
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-POSSESSION-DISPATCH-EXPIRED'; END IF;
${workloadHandoverGenerationPreparationsSql}
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workload_handover_dispatch_guard BEFORE INSERT ON control.workload_signing_handover_dispatch
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_signing_handover_dispatch();

CREATE OR REPLACE FUNCTION openpc.guard_workload_signing_handover_observation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE dispatch control.workload_signing_handover_dispatch; command control.workload_signing_handover_attempt;
 previous control.workload_signing_handover_observation; observation jsonb; descriptor jsonb; expected jsonb;
 generation_document jsonb; key_document jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'INSERT' OR openpc.current_action_intent_id()<>'ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1'
  OR NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id)
  OR NEW.operation_id<>openpc.current_operation_id()
  OR NEW.recorded_at_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000
 THEN RAISE EXCEPTION 'PC-AUTH-0005-HANDOVER-OBSERVATION-SCOPE'; END IF;
 SELECT * INTO STRICT dispatch FROM control.workload_signing_handover_dispatch
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND dispatch_id=NEW.dispatch_id;
 SELECT * INTO STRICT command FROM control.workload_signing_handover_attempt
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.attempt_id;
 IF dispatch.attempt_id<>NEW.attempt_id OR dispatch.handover_id<>NEW.handover_id
  OR command.handover_id<>NEW.handover_id OR dispatch.attempt_digest<>command.attempt_digest
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-OWNER'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('pc.identity.workload-signing-handover.observation:'||NEW.attempt_id::text,0));
 SELECT * INTO previous FROM control.workload_signing_handover_observation
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.attempt_id
  ORDER BY sequence DESC LIMIT 1;
 IF NEW.sequence IS DISTINCT FROM coalesce(previous.sequence,0)+1
  OR NEW.previous_digest IS DISTINCT FROM previous.entry_digest
  OR (previous.recorded_at_ns IS NOT NULL AND NEW.recorded_at_ns<previous.recorded_at_ns)
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-SEQUENCE'; END IF;
 expected:=jsonb_build_object('schemaVersion',1,'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,
  'handoverId',NEW.handover_id::text,'attemptId',NEW.attempt_id::text,'dispatchId',NEW.dispatch_id::text,
  'observationId',NEW.observation_id::text,'operationId',NEW.operation_id::text,'sequence',NEW.sequence,
  'previousDigest',CASE WHEN NEW.previous_digest IS NULL THEN NULL ELSE 'sha256:'||encode(NEW.previous_digest,'hex') END,
  'resultDigest','sha256:'||encode(NEW.result_digest,'hex'),'recordedAtNs',NEW.recorded_at_ns::text);
 IF NEW.entry_canonical<>convert_to(openpc.signing_canonical_json(expected),'UTF8')
  OR NEW.entry_digest<>sha256(convert_to('pc.identity.workload-signing-handover.observation-entry.v1','UTF8')||decode('00','hex')||NEW.entry_canonical)
  OR NEW.result_canonical<>convert_to(openpc.signing_canonical_json(NEW.result),'UTF8')
  OR NEW.result_digest<>sha256(convert_to('pc.identity.workload-signing-handover.provider-result.v1','UTF8')||decode('00','hex')||NEW.result_canonical)
  OR jsonb_typeof(NEW.result) IS DISTINCT FROM 'object' OR NEW.result->>'state' IS NULL
  OR NEW.result->>'via' IS NULL OR NEW.result->>'via' NOT IN('DISPATCH','LOOKUP')
 THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-CUSTODY'; END IF;
 CASE NEW.result->>'state'
 WHEN 'UNKNOWN' THEN
  IF NEW.result-ARRAY['state','via','reason']<>'{}'::jsonb
   OR NEW.result->>'reason' IS DISTINCT FROM 'TRANSPORT_OR_PROTOCOL_UNKNOWN'
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-UNKNOWN'; END IF;
 WHEN 'UNOBSERVED' THEN
  IF NEW.result-ARRAY['state','via','reason']<>'{}'::jsonb OR NEW.result->>'via'<>'LOOKUP'
   OR NEW.result->>'reason' IS NULL OR NEW.result->>'reason' NOT IN('ABSENT','NOT_FOUND','UNKNOWN')
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-UNOBSERVED'; END IF;
 WHEN 'OBSERVED' THEN
  observation:=NEW.result->'observation'; descriptor:=observation->'descriptor';
  IF NEW.result-ARRAY['state','via','observation']<>'{}'::jsonb OR jsonb_typeof(observation) IS DISTINCT FROM 'object'
   OR observation-ARRAY['schemaVersion','providerId','attemptId','operationId','requestDigest','method','recordedAtNs','outcome','reason','descriptor','resultHex']<>'{}'::jsonb
   OR observation->>'schemaVersion' IS DISTINCT FROM '1'
   OR observation->>'providerId' IS DISTINCT FROM command.provider_id
   OR observation->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text
   OR observation->>'operationId' IS DISTINCT FROM command.operation_id::text
   OR observation->>'requestDigest' IS DISTINCT FROM command.attempt->>'requestDigest'
   OR observation->>'method' IS DISTINCT FROM command.attempt->'request'->>'method'
   OR observation->>'recordedAtNs' IS NULL OR observation->>'recordedAtNs' !~ '^[1-9][0-9]{0,19}$'
   OR mod((observation->>'recordedAtNs')::numeric,1000)<>0
   OR (observation->>'recordedAtNs')::numeric>18446744073709551615
   OR observation->>'outcome' IS NULL OR observation->>'outcome' NOT IN('SUCCEEDED','REJECTED')
   OR (command.stage='PREPARATION' AND observation->'resultHex' IS DISTINCT FROM 'null'::jsonb)
   OR (command.stage='POSSESSION' AND observation->>'outcome'='SUCCEEDED' AND (observation->>'resultHex' IS NULL OR observation->>'resultHex' !~ '^[0-9a-f]{128}$'))
   OR (observation->>'outcome'='REJECTED' AND observation->'resultHex' IS DISTINCT FROM 'null'::jsonb)
   OR NOT observation ?& ARRAY['reason','descriptor']
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-BINDING'; END IF;
  IF observation->>'outcome'='REJECTED' THEN
   IF observation->>'reason' IS NULL OR observation->>'reason' NOT IN('KEY_NOT_FOUND','REVOKED','EXPIRED','WRONG_SCOPE','FINGERPRINT_MISMATCH','INVALID_REQUEST','ATTEMPT_CONFLICT','NOT_APPLIED')
   THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-REJECTION'; END IF;
  ELSIF observation->'reason' IS DISTINCT FROM 'null'::jsonb OR jsonb_typeof(descriptor) IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-DESCRIPTOR';
  END IF;
  IF descriptor IS DISTINCT FROM 'null'::jsonb THEN
   IF descriptor->>'participantId' IS DISTINCT FROM NEW.participant_id::text
    OR descriptor->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
    OR descriptor->>'environmentId' IS DISTINCT FROM command.binding->>'environmentId'
    OR descriptor->>'workloadCredentialId' IS DISTINCT FROM command.binding->>'successorCredentialId'
    OR descriptor->>'reference' IS DISTINCT FROM command.attempt->'request'->>'reference'
    OR descriptor->>'version' IS DISTINCT FROM command.attempt->'request'->>'version'
    OR descriptor->>'purpose' IS DISTINCT FROM command.attempt->>'purpose'
    OR descriptor->>'secretClass' IS DISTINCT FROM 'SECRET-SIGNING-KEY'
    OR descriptor->>'algorithm' IS DISTINCT FROM 'ES256'
    OR descriptor->>'publicKeySpkiHex' IS NULL OR descriptor->>'publicKeySpkiHex' !~ '^([0-9a-f]{2})+$'
    OR descriptor->>'fingerprint' IS DISTINCT FROM 'sha256:'||encode(sha256(decode(descriptor->>'publicKeySpkiHex','hex')),'hex')
   THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-DESCRIPTOR-SCOPE'; END IF;
   IF command.attempt->>'purpose'='pc.cose.identity-authority-envelope.v1' AND (
    descriptor->>'workloadCredentialEpoch' IS DISTINCT FROM command.attempt->'request'->>'workloadCredentialEpoch'
    OR descriptor->>'purposeCode' IS DISTINCT FROM '371' OR descriptor->>'schemaId' IS DISTINCT FROM '24034'
    OR descriptor->>'schemaVersion' IS DISTINCT FROM '1'
    OR descriptor->>'schemaDefinitionDigest' IS DISTINCT FROM command.attempt->'request'->>'schemaDefinitionDigest'
    OR descriptor->>'profileId' IS DISTINCT FROM command.attempt->'request'->>'profileId'
    OR descriptor->>'profileVersion' IS DISTINCT FROM '1'
    OR descriptor->>'profileDigest' IS DISTINCT FROM command.attempt->'request'->>'profileDigest')
   THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-ENVELOPE'; END IF;
  END IF;
  IF command.stage='POSSESSION' AND observation->>'outcome'='SUCCEEDED' THEN
   SELECT document INTO STRICT generation_document FROM control.workload_signing_handover_generation WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND generation_id=command.generation_id;
   SELECT value INTO STRICT key_document FROM jsonb_array_elements(generation_document->'keys') WHERE value->'binding'->'replacement'->>'oldFingerprint'=command.predecessor_fingerprint;
   IF descriptor IS DISTINCT FROM key_document->'observation'->'descriptor'
    OR (observation->>'recordedAtNs')::numeric<(generation_document->>'issuedAtNs')::numeric
    OR (observation->>'recordedAtNs')::numeric>=(generation_document->>'expiresAtNs')::numeric
   THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-POSSESSION-OBSERVATION'; END IF;
  END IF;
 ELSE RAISE EXCEPTION 'DATA-6021-HANDOVER-OBSERVATION-STATE';
 END CASE;
 RETURN NEW;
END $$;
CREATE TRIGGER workload_handover_observation_guard BEFORE INSERT ON control.workload_signing_handover_observation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_signing_handover_observation();
`;
