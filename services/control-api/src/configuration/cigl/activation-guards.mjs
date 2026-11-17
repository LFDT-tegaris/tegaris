export const ciglActivationGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES('ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1','runtime-targets','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_PROFILE_ACTIVATION')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.action_intent WHERE action_intent_id='ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1'
  AND resource_type='runtime-targets' AND operation_class='UPDATE' AND risk_class='HIGH'
  AND maker_checker_required AND step_up_required AND idempotency_required
  AND existence_disclosure='AUTHORIZED_ONLY' AND payload_disclosure='REDACTED' AND evidence_class='CIGL_PROFILE_ACTIVATION')
 THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ACTIVATION-ACTION'; END IF;
END $$;

-- Compilation permanently names its original analysis capsule. A subsequent
-- publication may use the actual approved/observed installation of that exact
-- compiled profile without rewriting the analysis or its signed receipt.
CREATE OR REPLACE FUNCTION openpc.cigl_profile_has_installed_lineage(
 p_profile uuid,p_revision bigint,p_target uuid,p_capsule text,p_policy text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT EXISTS(
  SELECT 1 FROM control.cigl_profile_version version
  JOIN control.cigl_analysis analysis ON analysis.analysis_id=version.analysis_id
   AND analysis.participant_id=version.participant_id AND analysis.privacy_domain_id=version.privacy_domain_id
  JOIN control.runtime_target target ON target.runtime_target_id=analysis.runtime_target_id
   AND target.participant_id=analysis.participant_id AND target.privacy_domain_id=analysis.privacy_domain_id
  WHERE version.profile_id=p_profile AND version.revision=p_revision AND version.state='COMPILED'
   AND version.participant_id=openpc.current_participant_id() AND version.privacy_domain_id=openpc.current_privacy_domain_id()
   AND analysis.state='REVIEWED' AND analysis.revision=3 AND analysis.runtime_target_id=p_target
   AND target.active_generation_digest=p_capsule
   AND ((analysis.capsule_digest=p_capsule AND analysis.policy_generation_digest=p_policy) OR EXISTS(
    SELECT 1 FROM control.runtime_activation_observation observation
    JOIN control.runtime_configuration_generation generation
     ON generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
      AND generation.participant_id=observation.participant_id AND generation.privacy_domain_id=observation.privacy_domain_id
    JOIN control.configuration_work work ON work.configuration_work_id=observation.configuration_work_id
     AND work.participant_id=observation.participant_id AND work.privacy_domain_id=observation.privacy_domain_id
     AND work.operation_id=observation.operation_id AND work.execution_attempt_id=observation.execution_attempt_id
     AND work.runtime_configuration_generation_id=generation.runtime_configuration_generation_id
     AND work.runtime_target_id=observation.runtime_target_id AND work.xds_version_digest=observation.xds_version_digest
     AND work.generation_digest=generation.generation_digest
    WHERE observation.participant_id=version.participant_id AND observation.privacy_domain_id=version.privacy_domain_id
     AND observation.runtime_target_id=p_target AND observation.capsule_digest=p_capsule
     AND generation.runtime_target_id=p_target AND generation.policy_generation_digest=p_policy AND generation.state='ACTIVE'
     AND work.work_kind='RUNTIME_ACTIVATION' AND work.state='COMPLETED' AND work.execution_started_at IS NOT NULL
     AND work.result_receipt_digest=observation.activation_receipt_digest
     AND generation.cigl_profile_selection->'profiles' @> jsonb_build_array(jsonb_build_object(
      'profileId','urn:openpc:resource:'||version.profile_id::text,'profileRevision',version.revision::text,
      'profileDigest',version.profile_digest,'compilationArtifactDigest',version.artifact_digest)))))
$$;
REVOKE ALL ON FUNCTION openpc.cigl_profile_has_installed_lineage(uuid,bigint,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.cigl_profile_has_installed_lineage(uuid,bigint,uuid,text,text)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_activation_selection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE item jsonb; last_id text:=''; selected control.cigl_profile_version; root_id uuid; roots uuid[]:='{}';
BEGIN
 IF TG_OP='UPDATE' THEN
  IF NEW.cigl_profile_selection IS DISTINCT FROM OLD.cigl_profile_selection THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-ACTIVATION-IMMUTABLE'; END IF;
  IF OLD.cigl_profile_selection IS NOT NULL AND
   ROW(NEW.runtime_configuration_generation_id,NEW.participant_id,NEW.privacy_domain_id,NEW.runtime_target_id,
     NEW.provider_profile_id,NEW.projection_plan_id,NEW.predecessor_digest,NEW.generation_digest,NEW.policy_generation_digest,NEW.created_at)
   IS DISTINCT FROM ROW(OLD.runtime_configuration_generation_id,OLD.participant_id,OLD.privacy_domain_id,OLD.runtime_target_id,
     OLD.provider_profile_id,OLD.projection_plan_id,OLD.predecessor_digest,OLD.generation_digest,OLD.policy_generation_digest,OLD.created_at) THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-ACTIVATION-IMMUTABLE'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.cigl_profile_selection IS NULL THEN
  IF EXISTS(SELECT 1 FROM control.runtime_target target
   JOIN control.runtime_activation_observation observation ON observation.runtime_target_id=target.runtime_target_id
    AND observation.participant_id=target.participant_id AND observation.privacy_domain_id=target.privacy_domain_id
    AND observation.capsule_digest=target.active_generation_digest
   JOIN control.runtime_configuration_generation previous ON previous.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
   WHERE target.runtime_target_id=NEW.runtime_target_id AND previous.cigl_profile_selection IS NOT NULL) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ACTIVATION-REQUIRED'; END IF;
  RETURN NEW;
 END IF;
 PERFORM openpc.assert_request_context(true);
 PERFORM openpc.lock_cigl_grant_sources();
 IF openpc.current_action_intent_id()<>'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1'
  OR NEW.participant_id<>openpc.current_participant_id() OR NEW.privacy_domain_id<>openpc.current_privacy_domain_id()
  OR NEW.state<>'ACTIVATING' OR NEW.revision<>1 OR NEW.predecessor_digest IS NULL
  OR NOT EXISTS(SELECT 1 FROM control.participant WHERE participant_id=NEW.participant_id AND state='ACTIVE'
    AND archived_at IS NULL AND authority_epoch::text=NEW.cigl_profile_selection->>'participantEpoch')
  OR NOT EXISTS(SELECT 1 FROM control.runtime_target WHERE runtime_target_id=NEW.runtime_target_id
    AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND state='ACTIVE_MATCHED'
    AND active_generation_digest=NEW.predecessor_digest AND desired_generation_digest=NEW.predecessor_digest) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ACTIVATION-SOURCE'; END IF;
 IF NEW.cigl_profile_selection ? 'policyRenewal' THEN
  IF NOT EXISTS(SELECT 1 FROM control.policy_activation_occurrence occurrence
   JOIN control.policy_activation activation ON activation.policy_activation_id=occurrence.activation_occurrence_id
    AND activation.participant_id=occurrence.participant_id AND activation.privacy_domain_id=occurrence.privacy_domain_id
    AND activation.policy_generation_id=occurrence.policy_generation_id AND activation.state='PREPARED'
   JOIN control.policy_generation policy ON policy.policy_generation_id=occurrence.policy_generation_id
    AND policy.participant_id=occurrence.participant_id AND policy.privacy_domain_id=occurrence.privacy_domain_id
    AND policy.state='PREPARED' AND NOT policy.active
   JOIN control.policy_activation_occurrence_target cohort ON cohort.activation_occurrence_id=occurrence.activation_occurrence_id
    AND cohort.participant_id=occurrence.participant_id AND cohort.privacy_domain_id=occurrence.privacy_domain_id
   WHERE occurrence.participant_id=NEW.participant_id AND occurrence.privacy_domain_id=NEW.privacy_domain_id
    AND 'urn:openpc:resource:'||occurrence.activation_occurrence_id::text=NEW.cigl_profile_selection->'policyRenewal'->>'activationOccurrenceRef'
    AND occurrence.revision::text=NEW.cigl_profile_selection->'policyRenewal'->>'expectedRevision'
    AND occurrence.state='REQUESTED' AND occurrence.total_target_count=1
    AND 'sha256:'||encode(policy.generation_digest,'hex')=NEW.policy_generation_digest
    AND NEW.policy_generation_digest=NEW.cigl_profile_selection->'policyRenewal'->>'policyGenerationDigest'
    AND cohort.runtime_target_id=NEW.runtime_target_id AND cohort.phase='FORWARD' AND cohort.state='REQUESTED'
    AND cohort.expected_predecessor_digest=NEW.predecessor_digest AND cohort.configuration_work_id IS NULL) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-RENEWAL-AUTHORITY'; END IF;
  -- Renewal carries every installed graph; changing or removing a graph requires
  -- its own analysis/review, not a policy freshness renewal.
  IF NOT EXISTS(SELECT 1 FROM control.runtime_activation_observation observation
   JOIN control.runtime_configuration_generation previous ON previous.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
    AND previous.participant_id=observation.participant_id AND previous.privacy_domain_id=observation.privacy_domain_id
   WHERE observation.runtime_target_id=NEW.runtime_target_id AND observation.participant_id=NEW.participant_id
    AND observation.privacy_domain_id=NEW.privacy_domain_id AND observation.capsule_digest=NEW.predecessor_digest
    AND previous.state='ACTIVE' AND previous.cigl_profile_selection IS NOT NULL
    AND (SELECT jsonb_agg(value-'grantSourcesDigest' ORDER BY value->>'profileId') FROM jsonb_array_elements(previous.cigl_profile_selection->'profiles'))
      = (SELECT jsonb_agg(value-'grantSourcesDigest' ORDER BY value->>'profileId') FROM jsonb_array_elements(NEW.cigl_profile_selection->'profiles'))) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-RENEWAL-LINEAGE'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM control.runtime_target WHERE runtime_target_id=NEW.runtime_target_id
   AND policy_generation_digest=NEW.policy_generation_digest) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-RENEWAL-REQUIRED'; END IF;
 END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(NEW.cigl_profile_selection->'profiles') LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR NOT item ?& ARRAY['profileId','profileRevision','profileDigest','compilationArtifactDigest','grantSourcesDigest']
   OR item-ARRAY['profileId','profileRevision','profileDigest','compilationArtifactDigest','grantSourcesDigest']<>'{}'::jsonb
   OR EXISTS(SELECT 1 FROM jsonb_each(item) field WHERE jsonb_typeof(field.value)<>'string')
   OR (item->>'profileId' ~ '^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') IS DISTINCT FROM true
   OR (item->>'profileRevision' ~ '^[1-9][0-9]{0,19}$') IS DISTINCT FROM true
   OR (item->>'grantSourcesDigest' ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true
   OR item->>'profileId'<=last_id THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-ACTIVATION-SELECTION'; END IF;
  last_id:=item->>'profileId';
  SELECT version.* INTO selected FROM control.cigl_profile_version version
   JOIN control.cigl_analysis analysis ON analysis.analysis_id=version.analysis_id
    AND analysis.participant_id=version.participant_id AND analysis.privacy_domain_id=version.privacy_domain_id
   WHERE version.profile_id=substring(item->>'profileId' from 21)::uuid AND version.revision::text=item->>'profileRevision'
    AND version.participant_id=NEW.participant_id AND version.privacy_domain_id=NEW.privacy_domain_id
    AND version.state='COMPILED' AND version.profile_digest=item->>'profileDigest' AND version.artifact_digest=item->>'compilationArtifactDigest'
    AND version.dependency_paths_digest IS NOT NULL AND analysis.runtime_target_id=NEW.runtime_target_id
    AND openpc.cigl_profile_has_installed_lineage(version.profile_id,version.revision,
      NEW.runtime_target_id,NEW.predecessor_digest,
      (SELECT policy_generation_digest FROM control.runtime_target WHERE runtime_target_id=NEW.runtime_target_id));
  IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007-CIGL-ACTIVATION-SELECTION'; END IF;
  SELECT root_contract_method_policy_id INTO root_id FROM control.cigl_method_profile WHERE profile_id=selected.profile_id;
  IF root_id=ANY(roots) THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-ACTIVATION-ROOT'; END IF;
  roots:=array_append(roots,root_id);
 END LOOP;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_activation_selection_guard ON control.runtime_configuration_generation;
CREATE TRIGGER cigl_activation_selection_guard BEFORE INSERT OR UPDATE ON control.runtime_configuration_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_activation_selection();

CREATE OR REPLACE FUNCTION openpc.guard_cigl_activation_work()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM control.runtime_configuration_generation generation
   WHERE generation.runtime_configuration_generation_id=OLD.runtime_configuration_generation_id
    AND generation.cigl_profile_selection IS NOT NULL) AND
  ROW(NEW.configuration_work_id,NEW.participant_id,NEW.privacy_domain_id,NEW.operation_id,NEW.work_kind,NEW.resource_id,
    NEW.input_digest,NEW.configuration_digest,NEW.runtime_configuration_generation_id,NEW.runtime_target_id,
    NEW.generation_digest,NEW.predecessor_digest,NEW.policy_generation_digest,NEW.xds_version_digest,NEW.created_at)
  IS DISTINCT FROM ROW(OLD.configuration_work_id,OLD.participant_id,OLD.privacy_domain_id,OLD.operation_id,OLD.work_kind,OLD.resource_id,
    OLD.input_digest,OLD.configuration_digest,OLD.runtime_configuration_generation_id,OLD.runtime_target_id,
    OLD.generation_digest,OLD.predecessor_digest,OLD.policy_generation_digest,OLD.xds_version_digest,OLD.created_at) THEN
  RAISE EXCEPTION 'PC-DATA-6004-CIGL-ACTIVATION-WORK-IMMUTABLE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_activation_work_guard ON control.configuration_work;
CREATE TRIGGER cigl_activation_work_guard BEFORE UPDATE ON control.configuration_work
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_activation_work();

CREATE OR REPLACE FUNCTION openpc.require_cigl_activation_selection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.cigl_profile_selection IS NULL THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.configuration_work work
  JOIN control.mutation_evidence evidence ON evidence.operation_id=work.operation_id
   AND evidence.participant_id=work.participant_id AND evidence.privacy_domain_id=work.privacy_domain_id
  JOIN control.mutation_candidate candidate ON candidate.consumed_operation_id=evidence.operation_id
   AND candidate.participant_id=evidence.participant_id AND candidate.privacy_domain_id=evidence.privacy_domain_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  JOIN control.runtime_target target ON target.runtime_target_id=NEW.runtime_target_id
   AND target.participant_id=NEW.participant_id AND target.privacy_domain_id=NEW.privacy_domain_id
  WHERE work.runtime_configuration_generation_id=NEW.runtime_configuration_generation_id
   AND work.participant_id=NEW.participant_id AND work.privacy_domain_id=NEW.privacy_domain_id
   AND work.work_kind='RUNTIME_ACTIVATION' AND work.runtime_target_id=NEW.runtime_target_id AND work.resource_id=NEW.runtime_target_id
   AND work.generation_digest=NEW.generation_digest AND work.predecessor_digest=NEW.predecessor_digest
   AND work.policy_generation_digest=NEW.policy_generation_digest AND work.input_digest='sha256:'||encode(candidate.candidate_digest,'hex')
   AND evidence.catalog_operation_id='CFG-OP-ACTIVATE-CIGL-PROFILES' AND evidence.action_intent_id='ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1'
   AND evidence.aggregate_type='runtime-targets' AND evidence.aggregate_id=NEW.runtime_target_id
   AND evidence.aggregate_version=candidate.expected_revision+1 AND candidate.resource_id=NEW.runtime_target_id AND candidate.state='CONSUMED'
   AND candidate.candidate_document->>'targetRef'='urn:openpc:resource:'||NEW.runtime_target_id::text
   AND candidate.candidate_document->>'expectedGenerationDigest'=NEW.predecessor_digest
   AND (jsonb_build_object('participantEpoch',candidate.candidate_document->'participantEpoch','profiles',candidate.candidate_document->'profiles') || CASE WHEN candidate.candidate_document ? 'policyRenewal' THEN jsonb_build_object('policyRenewal',candidate.candidate_document->'policyRenewal') ELSE '{}'::jsonb END)=NEW.cigl_profile_selection
   AND NEW.generation_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
      'purpose','openpc.runtime.cigl-profile-selection.v1','baseCapsuleDigest',candidate.candidate_document->>'expectedGenerationDigest',
      'selection',NEW.cigl_profile_selection)),'UTF8')),'hex')
   AND (TG_OP<>'INSERT' OR (target.state='STAGING' AND target.revision=candidate.expected_revision+1 AND target.desired_generation_digest=NEW.generation_digest))
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id AND event.privacy_domain_id=NEW.privacy_domain_id
    AND event.aggregate_id=NEW.runtime_target_id AND event.aggregate_type='runtime-targets'
    AND event.event_type='openpc.cigl.profile.activation-requested.v1'
    AND event.payload_digest=sha256(event.payload_cbor)
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(candidate.candidate_digest,'hex')
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'revision'=evidence.aggregate_version::text
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'='sha256:'||encode(evidence.evidence_digest,'hex'))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ACTIVATION-PROVENANCE'; END IF;
 IF NEW.cigl_profile_selection ? 'policyRenewal' AND NOT EXISTS(
  SELECT 1 FROM control.policy_activation_occurrence occurrence
  JOIN control.policy_activation_occurrence_target cohort ON cohort.activation_occurrence_id=occurrence.activation_occurrence_id
   AND cohort.participant_id=occurrence.participant_id AND cohort.privacy_domain_id=occurrence.privacy_domain_id
  JOIN control.configuration_work work ON work.configuration_work_id=cohort.configuration_work_id
   AND work.participant_id=cohort.participant_id AND work.privacy_domain_id=cohort.privacy_domain_id
  WHERE occurrence.participant_id=NEW.participant_id AND occurrence.privacy_domain_id=NEW.privacy_domain_id
   AND 'urn:openpc:resource:'||occurrence.activation_occurrence_id::text=NEW.cigl_profile_selection->'policyRenewal'->>'activationOccurrenceRef'
   AND cohort.runtime_target_id=NEW.runtime_target_id AND cohort.phase='FORWARD'
   AND cohort.runtime_configuration_generation_id=NEW.runtime_configuration_generation_id
   AND work.runtime_configuration_generation_id=NEW.runtime_configuration_generation_id
   AND work.policy_generation_digest=NEW.policy_generation_digest
   AND occurrence.target_generation_digest=decode(substring(NEW.policy_generation_digest from 8),'hex')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-RENEWAL-PROVENANCE'; END IF;
 IF NEW.state='ACTIVE' AND NOT EXISTS(SELECT 1 FROM control.runtime_activation_observation observation
  JOIN control.configuration_work work ON work.configuration_work_id=observation.configuration_work_id
  JOIN control.runtime_target target ON target.runtime_target_id=NEW.runtime_target_id
  WHERE observation.runtime_configuration_generation_id=NEW.runtime_configuration_generation_id
   AND observation.generation_digest=NEW.generation_digest AND observation.capsule_digest=target.active_generation_digest
   AND target.active_generation_digest=target.desired_generation_digest AND target.state='ACTIVE_MATCHED' AND work.state='COMPLETED') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ACTIVATION-EFFECT'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_activation_selection_provenance ON control.runtime_configuration_generation;
CREATE CONSTRAINT TRIGGER cigl_activation_selection_provenance AFTER INSERT OR UPDATE ON control.runtime_configuration_generation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_activation_selection();
`;
