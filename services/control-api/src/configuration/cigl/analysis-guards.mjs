export const ciglAnalysisGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1','cigl-analysis','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_CREATE'),
 ('ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1','cigl-analysis','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_OBSERVE'),
 ('ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1','cigl-analysis','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_REVIEW'),
 ('ACT-CIGL_ANALYSES_READ_RESOURCE-V1','cigl-analysis','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_ANALYSIS_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1','cigl-analysis','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_CREATE'),
  ('ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1','cigl-analysis','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_OBSERVE'),
  ('ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1','cigl-analysis','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_REVIEW'),
  ('ACT-CIGL_ANALYSES_READ_RESOURCE-V1','cigl-analysis','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_ANALYSIS_READ')))<>4 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ANALYSIS-ACTION'; END IF;
END $$;
ALTER TABLE control.cigl_analysis FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_analysis()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE capsule text; policy text;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ANALYSIS'; END IF;
 IF TG_OP='INSERT' THEN
  IF current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1'
   OR NEW.creation_operation_id<>NEW.publication_operation_id OR NEW.state<>'OPEN' OR NEW.revision<>1 THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ANALYSIS-CREATE'; END IF;
  IF jsonb_typeof(NEW.definition) IS DISTINCT FROM 'object'
   OR EXISTS(SELECT 1 FROM jsonb_each(NEW.definition) field WHERE field.key<>'expiresInSeconds' AND jsonb_typeof(field.value)<>'string')
   OR (NEW.definition-ARRAY['targetRuntimeId','expectedGenerationDigest','runtimeBindingId','contractMethodPolicyId',
     'expectedRuntimeBindingRevision','expectedMethodRevision','workloadId','transactionHash','expiresInSeconds']) IS DISTINCT FROM '{}'::jsonb
   OR NOT NEW.definition ?& ARRAY['targetRuntimeId','expectedGenerationDigest','runtimeBindingId','contractMethodPolicyId',
     'expectedRuntimeBindingRevision','expectedMethodRevision','workloadId','transactionHash','expiresInSeconds']
   OR NEW.definition->>'targetRuntimeId' IS DISTINCT FROM 'urn:openpc:resource:'||NEW.runtime_target_id::text
   OR NEW.definition->>'runtimeBindingId' IS DISTINCT FROM 'urn:openpc:resource:'||NEW.runtime_binding_id::text
   OR NEW.definition->>'contractMethodPolicyId' IS DISTINCT FROM 'urn:openpc:resource:'||NEW.contract_method_policy_id::text
   OR (NEW.definition->>'transactionHash' ~ '^0x[0-9a-f]{64}$') IS DISTINCT FROM true
   OR (NEW.definition->>'expectedGenerationDigest' ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true
   OR (NEW.definition->>'expectedRuntimeBindingRevision' ~ '^[1-9][0-9]{0,19}$') IS DISTINCT FROM true
   OR (NEW.definition->>'expectedMethodRevision' ~ '^[1-9][0-9]{0,19}$') IS DISTINCT FROM true
   OR jsonb_typeof(NEW.definition->'expiresInSeconds') IS DISTINCT FROM 'number'
   OR (NEW.definition->>'expiresInSeconds' ~ '^[0-9]+$') IS DISTINCT FROM true
   OR (NEW.definition->>'expiresInSeconds')::numeric NOT BETWEEN 30 AND 900 THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-DEFINITION'; END IF;
  NEW.created_at:=date_trunc('milliseconds',clock_timestamp());
  NEW.expires_at:=NEW.created_at+make_interval(secs=>(NEW.definition->>'expiresInSeconds')::integer);
 ELSE
  IF clock_timestamp()>=OLD.expires_at
   OR ROW(NEW.analysis_id,NEW.participant_id,NEW.privacy_domain_id,NEW.runtime_target_id,NEW.runtime_binding_id,
     NEW.contract_method_policy_id,NEW.definition,NEW.capsule_digest,NEW.policy_generation_digest,NEW.creation_operation_id,NEW.created_at,NEW.expires_at)
   IS DISTINCT FROM ROW(OLD.analysis_id,OLD.participant_id,OLD.privacy_domain_id,OLD.runtime_target_id,OLD.runtime_binding_id,
     OLD.contract_method_policy_id,OLD.definition,OLD.capsule_digest,OLD.policy_generation_digest,OLD.creation_operation_id,OLD.created_at,OLD.expires_at)
   OR NEW.receipt_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.signed_receipt),'hex') THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-IMMUTABLE'; END IF;
  IF OLD.state='OPEN' AND OLD.revision=1 THEN
   IF current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1' OR NEW.state<>'OBSERVED' OR NEW.revision<>2 THEN
    RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-IMMUTABLE'; END IF;
  ELSIF OLD.state='OBSERVED' AND OLD.revision=2 THEN
   IF current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1' OR NEW.state<>'REVIEWED' OR NEW.revision<>3
    OR ROW(NEW.signed_receipt,NEW.receipt_digest,NEW.analysis_digest) IS DISTINCT FROM ROW(OLD.signed_receipt,OLD.receipt_digest,OLD.analysis_digest)
    OR NEW.review_definition->>'analysisDigest' IS DISTINCT FROM NEW.analysis_digest
    OR NEW.review_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.review_definition),'UTF8')),'hex') THEN
    RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-IMMUTABLE'; END IF;
  ELSE RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-IMMUTABLE'; END IF;
 END IF;
 -- Share-lock the actual source owners through the mutation. A supplied digest
 -- cannot manufacture a current activation, method or workload credential.
 SELECT observation.capsule_digest,target.policy_generation_digest INTO STRICT capsule,policy
 FROM control.runtime_target target JOIN control.runtime_activation_observation observation
  ON observation.participant_id=target.participant_id AND observation.privacy_domain_id=target.privacy_domain_id
   AND observation.runtime_target_id=target.runtime_target_id AND observation.capsule_digest=target.active_generation_digest
 JOIN control.contract_runtime_binding binding ON binding.participant_id=target.participant_id
  AND binding.privacy_domain_id=target.privacy_domain_id AND binding.runtime_binding_id=NEW.runtime_binding_id
 JOIN control.contract_method_policy method ON method.participant_id=binding.participant_id AND method.privacy_domain_id=binding.privacy_domain_id
  AND method.runtime_binding_id=binding.runtime_binding_id AND method.contract_method_policy_id=NEW.contract_method_policy_id
 WHERE target.runtime_target_id=NEW.runtime_target_id AND target.participant_id=NEW.participant_id AND target.privacy_domain_id=NEW.privacy_domain_id
  AND target.state='ACTIVE_MATCHED' AND target.active_generation_digest=target.desired_generation_digest
  AND target.active_generation_digest=NEW.definition->>'expectedGenerationDigest'
  AND binding.state='BOUND' AND binding.revision::text=NEW.definition->>'expectedRuntimeBindingRevision'
  AND method.state IN ('PREPARED','ACTIVE') AND method.revision::text=NEW.definition->>'expectedMethodRevision'
  AND openpc.cigl_subject_current(NEW.participant_id,jsonb_build_object('kind','WORKLOAD','id',NEW.definition->>'workloadId'))
 FOR SHARE OF target,binding,method;
 IF TG_OP='INSERT' THEN NEW.capsule_digest:=capsule; NEW.policy_generation_digest:=policy;
 ELSIF NEW.capsule_digest<>capsule OR NEW.policy_generation_digest<>policy THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-ANALYSIS-REFERENCE'; END IF;
 RETURN NEW;
 EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-ANALYSIS-REFERENCE';
END $$;
DROP TRIGGER IF EXISTS cigl_analysis_guard ON control.cigl_analysis;
CREATE TRIGGER cigl_analysis_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_analysis
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_analysis();

CREATE OR REPLACE FUNCTION openpc.require_cigl_analysis_publication()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE operation text:=CASE NEW.revision WHEN 1 THEN 'CFG-OP-CREATE-CIGL-ANALYSIS' WHEN 2 THEN 'CFG-OP-UPDATE-CIGL-ANALYSIS' ELSE 'CFG-OP-REVIEW-CIGL-ANALYSIS' END;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id AND receipt.privacy_domain_id=evidence.privacy_domain_id
   AND receipt.operation_id=evidence.operation_id AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id AND candidate.privacy_domain_id=evidence.privacy_domain_id
   AND candidate.consumed_operation_id=evidence.operation_id AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id AND evidence.operation_id=NEW.publication_operation_id
   AND evidence.aggregate_type='cigl-analysis' AND evidence.aggregate_id=NEW.analysis_id AND evidence.catalog_operation_id=operation
   AND evidence.action_intent_id=CASE NEW.revision WHEN 1 THEN 'ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1' WHEN 2 THEN 'ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1' ELSE 'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1' END
   AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.analysis_id AND candidate.state='CONSUMED' AND candidate.expected_revision=NEW.revision-1
   AND ((NEW.revision=1 AND candidate.candidate_document->'definition'=NEW.definition)
    OR (NEW.revision=2 AND candidate.candidate_document->>'targetRef'='urn:openpc:resource:'||NEW.analysis_id::text
      AND candidate.candidate_document->>'expectedRevision'='1'
      AND candidate.candidate_document->>'signedReceipt'='0x'||encode(NEW.signed_receipt,'hex'))
    OR (NEW.revision=3 AND candidate.candidate_document->>'targetRef'='urn:openpc:resource:'||NEW.analysis_id::text
      AND candidate.candidate_document->>'expectedRevision'='2' AND candidate.candidate_document->'review'=NEW.review_definition))
   AND receipt.terminal_state='COMMITTED' AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.analysis_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id AND event.privacy_domain_id=NEW.privacy_domain_id
    AND event.aggregate_id=NEW.analysis_id AND event.aggregate_type='cigl-analysis' AND event.aggregate_sequence=NEW.revision
    AND event.event_type=CASE NEW.revision WHEN 1 THEN 'openpc.cigl.analysis.created.v1' WHEN 2 THEN 'openpc.cigl.analysis.observed.v1' ELSE 'openpc.cigl.analysis.reviewed.v1' END)) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ANALYSIS-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_analysis_publication ON control.cigl_analysis;
CREATE CONSTRAINT TRIGGER cigl_analysis_publication AFTER INSERT OR UPDATE ON control.cigl_analysis
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_analysis_publication();
`;
