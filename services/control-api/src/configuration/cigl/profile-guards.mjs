/** Emitted by the existing Drizzle/security-tail owner. Profiles retain draft
 * compilation provenance only; activation is deliberately a separate owner. */
export const ciglProfileGuardsSql = `
-- Fleet needs an authority-root read fence, not Participant mutation rights.
-- Lock it before the scoped grant fence to preserve the shared authority order.
-- The definer remains subject to FORCE RLS. Permit its scoped read/lock only;
-- WITH CHECK(false) continues to prohibit Participant writes through this owner.
DROP POLICY IF EXISTS cigl_publication_participant_fence ON control.participant;
CREATE POLICY cigl_publication_participant_fence ON control.participant FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id() IN
  ('ACT-CIGL_ANALYSES_READ_RESOURCE-V1','ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1','ACT-RUNTIME_READ_RPC-V1'))
 WITH CHECK(false);
CREATE OR REPLACE FUNCTION openpc.lock_cigl_publication_participant()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF openpc.current_action_intent_id() NOT IN ('ACT-CIGL_ANALYSES_READ_RESOURCE-V1','ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1','ACT-RUNTIME_READ_RPC-V1')
  THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-PUBLICATION-PARTICIPANT'; END IF;
 PERFORM 1 FROM control.participant
  WHERE participant_id=current_setting('openpc.participant_id')::uuid
   AND state='ACTIVE' AND archived_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-PUBLICATION-PARTICIPANT'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_cigl_publication_participant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_cigl_publication_participant() TO openpc_control_runtime,openpc_control_worker;

-- Invalidation must also fence an archived/inactive authority root. It never
-- confers publication rights and is limited to the existing scoped read action.
CREATE OR REPLACE FUNCTION openpc.lock_cigl_invalidation_participant()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF openpc.current_action_intent_id()<>'ACT-CIGL_ANALYSES_READ_RESOURCE-V1'
  THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-INVALIDATION-PARTICIPANT'; END IF;
 PERFORM 1 FROM control.participant
  WHERE participant_id=current_setting('openpc.participant_id')::uuid FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-INVALIDATION-PARTICIPANT'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_cigl_invalidation_participant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_cigl_invalidation_participant() TO openpc_control_worker;

ALTER TABLE control.cigl_method_profile FORCE ROW LEVEL SECURITY;
ALTER TABLE control.cigl_profile_version FORCE ROW LEVEL SECURITY;
ALTER TABLE control.cigl_profile_grant_source FORCE ROW LEVEL SECURITY;
ALTER TABLE control.cigl_profile_method_source FORCE ROW LEVEL SECURITY;
ALTER TABLE control.cigl_profile_dependency_path FORCE ROW LEVEL SECURITY;
GRANT EXECUTE ON FUNCTION openpc.signing_canonical_json(jsonb) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_profile_owner()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1'
  OR NOT EXISTS(SELECT 1 FROM control.cigl_analysis analysis WHERE analysis.participant_id=NEW.participant_id
    AND analysis.privacy_domain_id=NEW.privacy_domain_id AND analysis.contract_method_policy_id=NEW.root_contract_method_policy_id
    AND analysis.state='REVIEWED' AND analysis.revision=3 AND analysis.publication_operation_id=current_setting('openpc.operation_id')::uuid) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-OWNER'; END IF;
 NEW.created_at:=date_trunc('milliseconds',clock_timestamp()); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_owner_guard ON control.cigl_method_profile;
CREATE TRIGGER cigl_profile_owner_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_method_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_owner();

CREATE OR REPLACE FUNCTION openpc.guard_cigl_profile_version()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE claims jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-SCOPE'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PENDING' OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1'
   OR NOT EXISTS(SELECT 1 FROM control.cigl_analysis analysis JOIN control.cigl_method_profile profile
     ON profile.participant_id=analysis.participant_id AND profile.privacy_domain_id=analysis.privacy_domain_id
      AND profile.root_contract_method_policy_id=analysis.contract_method_policy_id
     JOIN control.configuration_work work ON work.configuration_work_id=NEW.configuration_work_id
      AND work.participant_id=analysis.participant_id AND work.privacy_domain_id=analysis.privacy_domain_id
      AND work.resource_id=analysis.analysis_id AND work.operation_id=analysis.publication_operation_id
      AND work.work_kind='CIGL_PROFILE_COMPILATION' AND work.state='PENDING'
     WHERE analysis.analysis_id=NEW.analysis_id AND analysis.participant_id=NEW.participant_id
      AND analysis.privacy_domain_id=NEW.privacy_domain_id AND profile.profile_id=NEW.profile_id
      AND analysis.state='REVIEWED' AND analysis.revision=3 AND analysis.review_digest=NEW.review_digest
      AND analysis.publication_operation_id=current_setting('openpc.operation_id')::uuid)
   OR NEW.revision<>(SELECT coalesce(max(revision),0)+1 FROM control.cigl_profile_version WHERE profile_id=NEW.profile_id) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-REVIEW'; END IF;
  NEW.created_at:=date_trunc('milliseconds',clock_timestamp());
 ELSE
  IF NOT pg_has_role(current_user,'openpc_control_worker','MEMBER') OR OLD.state<>'PENDING' OR NEW.state<>'COMPILED'
   OR (to_jsonb(NEW)-ARRAY['state','profile_cbor','profile_digest','artifact_digest','compilation_receipt','compilation_signer_id','compiled_at','dependency_paths_digest'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','profile_cbor','profile_digest','artifact_digest','compilation_receipt','compilation_signer_id','compiled_at','dependency_paths_digest'])
   OR NEW.artifact_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.profile_cbor),'hex') THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-IMMUTABLE'; END IF;
  claims:=convert_from(NEW.compilation_receipt,'UTF8')::jsonb;
  IF claims->>'purpose' IS DISTINCT FROM 'openpc:cigl-profile-compilation:v1' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-RECEIPT'; END IF;
  claims:=claims->'claims';
  IF claims->>'schemaVersion' IS DISTINCT FROM '1.0' OR claims->>'profileId' IS DISTINCT FROM NEW.profile_id::text
   OR claims->>'profileRevision' IS DISTINCT FROM NEW.revision::text OR claims->>'analysisId' IS DISTINCT FROM NEW.analysis_id::text
   OR claims->>'configurationWorkId' IS DISTINCT FROM NEW.configuration_work_id::text
   OR claims->>'participantId' IS DISTINCT FROM NEW.participant_id::text OR claims->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
   OR claims->>'reviewDigest' IS DISTINCT FROM substr(NEW.review_digest,8) OR claims->>'artifactDigest' IS DISTINCT FROM substr(NEW.artifact_digest,8)
   OR claims->>'profileDigest' IS DISTINCT FROM substr(NEW.profile_digest,8) OR claims->>'signerId' IS DISTINCT FROM NEW.compilation_signer_id
   OR NEW.dependency_paths_digest IS NULL
   OR claims->>'dependencyPathsDigest' IS DISTINCT FROM substr(NEW.dependency_paths_digest,8)
   OR NEW.dependency_paths_digest IS DISTINCT FROM (SELECT 'sha256:'||encode(sha256(convert_to(
     openpc.signing_canonical_json(coalesce(jsonb_agg(path.document ORDER BY path.ordinal),'[]'::jsonb)),'UTF8')),'hex')
     FROM control.cigl_profile_dependency_path path WHERE path.profile_id=NEW.profile_id AND path.profile_revision=NEW.revision)
   OR claims->>'compiledAtMs' IS DISTINCT FROM floor(extract(epoch from NEW.compiled_at)*1000)::text
   OR NEW.compiled_at<NEW.created_at OR NEW.compiled_at>clock_timestamp()
   OR NOT EXISTS(SELECT 1 FROM control.configuration_work work JOIN control.cigl_analysis analysis ON analysis.analysis_id=NEW.analysis_id
      AND analysis.participant_id=work.participant_id AND analysis.privacy_domain_id=work.privacy_domain_id
     WHERE work.configuration_work_id=NEW.configuration_work_id AND work.state='LEASED' AND work.lease_owner=NEW.compilation_signer_id
      AND work.lease_until>clock_timestamp() AND analysis.expires_at>clock_timestamp()
      AND claims->>'operationId'=work.operation_id::text AND claims->>'targetRuntimeId'=analysis.runtime_target_id::text
      AND claims->>'capsuleDigest'=substr(analysis.capsule_digest,8) AND claims->>'analysisDigest'=substr(analysis.analysis_digest,8)
      AND claims->>'policyGenerationDigest'=substr(analysis.policy_generation_digest,8)) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-RECEIPT'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_version_guard ON control.cigl_profile_version;
CREATE TRIGGER cigl_profile_version_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_profile_version
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_version();

CREATE OR REPLACE FUNCTION openpc.guard_cigl_profile_source()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','MEMBER')
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NOT EXISTS(SELECT 1 FROM control.cigl_profile_version version JOIN control.configuration_work work
    ON work.configuration_work_id=version.configuration_work_id AND work.participant_id=version.participant_id AND work.privacy_domain_id=version.privacy_domain_id
    WHERE version.profile_id=NEW.profile_id AND version.revision=NEW.profile_revision AND version.participant_id=NEW.participant_id
     AND version.privacy_domain_id=NEW.privacy_domain_id AND version.state='PENDING' AND work.state='LEASED' AND work.lease_until>clock_timestamp()) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-SOURCE'; END IF;
 IF TG_TABLE_NAME='cigl_profile_grant_source' THEN
  IF NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants grant_row WHERE grant_row.grant_id=NEW.grant_id
   AND grant_row.participant_id=NEW.participant_id AND grant_row.privacy_domain_id=NEW.privacy_domain_id
   AND grant_row.revision=NEW.grant_revision AND grant_row.grant_digest=NEW.grant_digest) THEN RAISE EXCEPTION 'PC-DATA-6007-CIGL-PROFILE-GRANT'; END IF;
 ELSIF TG_TABLE_NAME='cigl_profile_method_source' THEN
  IF NOT EXISTS(SELECT 1 FROM control.contract_method_policy method JOIN control.contract_runtime_binding binding
   ON binding.runtime_binding_id=method.runtime_binding_id AND binding.participant_id=method.participant_id AND binding.privacy_domain_id=method.privacy_domain_id
   WHERE method.contract_method_policy_id=NEW.contract_method_policy_id AND method.participant_id=NEW.participant_id
    AND method.privacy_domain_id=NEW.privacy_domain_id AND binding.runtime_binding_id=NEW.runtime_binding_id
    AND method.revision=NEW.method_revision AND binding.revision=NEW.binding_revision) THEN RAISE EXCEPTION 'PC-DATA-6007-CIGL-PROFILE-METHOD'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM control.cigl_profile_method_source method WHERE method.profile_id=NEW.profile_id
    AND method.profile_revision=NEW.profile_revision AND method.contract_method_policy_id::text=NEW.document->>'contractMethodPolicyId'
    AND method.runtime_binding_id::text=NEW.document->>'runtimeBindingId') THEN RAISE EXCEPTION 'PC-DATA-6007-CIGL-PROFILE-PATH'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_grant_source_guard ON control.cigl_profile_grant_source;
CREATE TRIGGER cigl_profile_grant_source_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_profile_grant_source
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_source();
DROP TRIGGER IF EXISTS cigl_profile_method_source_guard ON control.cigl_profile_method_source;
CREATE TRIGGER cigl_profile_method_source_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_profile_method_source
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_source();
DROP TRIGGER IF EXISTS cigl_profile_path_guard ON control.cigl_profile_dependency_path;
CREATE TRIGGER cigl_profile_path_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_profile_dependency_path
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_source();

CREATE OR REPLACE FUNCTION openpc.guard_cigl_profile_work()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.work_kind='CIGL_PROFILE_COMPILATION' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-HISTORY'; END IF;
  RETURN OLD;
 END IF;
 IF NEW.work_kind<>'CIGL_PROFILE_COMPILATION' THEN
  IF TG_OP='UPDATE' AND OLD.work_kind='CIGL_PROFILE_COMPILATION' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-WORK'; END IF;
  RETURN NEW;
 END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.execution_started_at IS NOT NULL OR NEW.execution_attempt_id IS NOT NULL OR NEW.state='RECONCILING' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-WORK'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PENDING' OR NEW.attempt_count<>0 OR NEW.operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1' THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-WORK'; END IF;
 ELSE
  IF NOT pg_has_role(current_user,'openpc_control_worker','MEMBER') OR OLD.state IN ('COMPLETED','FAILED')
   OR ROW(NEW.configuration_work_id,NEW.participant_id,NEW.privacy_domain_id,NEW.operation_id,NEW.work_kind,NEW.resource_id,
     NEW.input_digest,NEW.configuration_digest,NEW.runtime_configuration_generation_id,NEW.runtime_target_id,NEW.generation_digest,NEW.predecessor_digest,
     NEW.policy_generation_digest,NEW.xds_version_digest,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.configuration_work_id,OLD.participant_id,OLD.privacy_domain_id,OLD.operation_id,OLD.work_kind,OLD.resource_id,
     OLD.input_digest,OLD.configuration_digest,OLD.runtime_configuration_generation_id,OLD.runtime_target_id,OLD.generation_digest,OLD.predecessor_digest,
     OLD.policy_generation_digest,OLD.xds_version_digest,OLD.created_at)
   OR (NEW.state='LEASED' AND NOT ((OLD.state='PENDING' OR (OLD.state='LEASED' AND OLD.lease_until<=clock_timestamp())) AND NEW.attempt_count=OLD.attempt_count+1))
   OR (NEW.state<>'LEASED' AND (OLD.state<>'LEASED' OR OLD.lease_until<=clock_timestamp() OR NEW.attempt_count<>OLD.attempt_count))
   OR (NEW.state IN ('COMPLETED','FAILED') AND NEW.result_receipt_digest IS DISTINCT FROM
     'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.result_receipt),'UTF8')),'hex')) THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-WORK'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_work_guard ON control.configuration_work;
CREATE TRIGGER cigl_profile_work_guard BEFORE INSERT OR UPDATE OR DELETE ON control.configuration_work
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_work();

CREATE OR REPLACE FUNCTION openpc.require_cigl_profile_work()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.work_kind<>'CIGL_PROFILE_COMPILATION' THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.cigl_analysis analysis JOIN control.cigl_profile_version version
   ON version.analysis_id=analysis.analysis_id AND version.participant_id=analysis.participant_id AND version.privacy_domain_id=analysis.privacy_domain_id
   JOIN control.mutation_evidence evidence ON evidence.operation_id=analysis.publication_operation_id
    AND evidence.participant_id=analysis.participant_id AND evidence.privacy_domain_id=analysis.privacy_domain_id
   JOIN control.mutation_candidate candidate ON candidate.consumed_operation_id=evidence.operation_id
    AND candidate.participant_id=evidence.participant_id AND candidate.privacy_domain_id=evidence.privacy_domain_id
    AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
   WHERE analysis.analysis_id=NEW.resource_id AND analysis.participant_id=NEW.participant_id AND analysis.privacy_domain_id=NEW.privacy_domain_id
    AND analysis.state='REVIEWED' AND analysis.revision=3 AND analysis.publication_operation_id=NEW.operation_id
    AND evidence.catalog_operation_id='CFG-OP-REVIEW-CIGL-ANALYSIS' AND candidate.resource_id=analysis.analysis_id
    AND candidate.state='CONSUMED' AND candidate.expected_revision=2 AND candidate.candidate_document->'review'=analysis.review_definition
    AND NEW.input_digest='sha256:'||encode(candidate.candidate_digest,'hex') AND version.configuration_work_id=NEW.configuration_work_id
    AND version.review_digest=analysis.review_digest AND NEW.runtime_target_id=analysis.runtime_target_id
    AND NEW.generation_digest=analysis.definition->>'expectedGenerationDigest' AND NEW.policy_generation_digest=analysis.policy_generation_digest
    AND EXISTS(SELECT 1 FROM control.runtime_activation_observation observation JOIN control.configuration_work prior
      ON prior.configuration_work_id=observation.configuration_work_id WHERE observation.participant_id=analysis.participant_id
      AND observation.privacy_domain_id=analysis.privacy_domain_id AND observation.runtime_target_id=analysis.runtime_target_id
      AND observation.capsule_digest=analysis.capsule_digest AND observation.capsule_digest=NEW.generation_digest
      AND prior.participant_id=observation.participant_id AND prior.privacy_domain_id=observation.privacy_domain_id
      AND prior.work_kind='RUNTIME_ACTIVATION' AND prior.runtime_target_id=observation.runtime_target_id
      AND prior.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
      AND prior.generation_digest=observation.generation_digest
      AND prior.configuration_digest=NEW.configuration_digest)) THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-PROVENANCE'; END IF;
 IF NEW.state='COMPLETED' AND NOT EXISTS(SELECT 1 FROM control.cigl_analysis analysis JOIN control.runtime_target target
   ON target.runtime_target_id=analysis.runtime_target_id AND target.participant_id=analysis.participant_id AND target.privacy_domain_id=analysis.privacy_domain_id
   WHERE analysis.analysis_id=NEW.resource_id AND analysis.expires_at>clock_timestamp()
    AND target.state='ACTIVE_MATCHED' AND target.active_generation_digest=NEW.generation_digest
    AND target.desired_generation_digest=NEW.generation_digest) THEN
  RAISE EXCEPTION 'PC-DATA-6007-CIGL-PROFILE-CURRENTNESS'; END IF;
 IF NEW.state IN ('COMPLETED','FAILED') AND NOT EXISTS(SELECT 1 FROM control.outbox_event event
    JOIN control.cigl_profile_version version ON version.configuration_work_id=NEW.configuration_work_id
    WHERE event.event_id=NEW.result_event_id AND event.participant_id=NEW.participant_id AND event.privacy_domain_id=NEW.privacy_domain_id
     AND event.aggregate_type='cigl-analysis' AND event.aggregate_id=NEW.resource_id
     AND ((NEW.state='COMPLETED' AND version.state='COMPILED' AND event.event_type='openpc.cigl.profile.compiled.v1')
       OR (NEW.state='FAILED' AND version.state='PENDING' AND event.event_type='openpc.cigl.profile.compilation-failed.v1'))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-EFFECT'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_work_provenance ON control.configuration_work;
CREATE CONSTRAINT TRIGGER cigl_profile_work_provenance AFTER INSERT OR UPDATE ON control.configuration_work
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_work();

CREATE OR REPLACE FUNCTION openpc.require_cigl_profile_owner()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.cigl_profile_version version WHERE version.profile_id=NEW.profile_id
  AND version.participant_id=NEW.participant_id AND version.privacy_domain_id=NEW.privacy_domain_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-OWNER-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_owner_provenance ON control.cigl_method_profile;
CREATE CONSTRAINT TRIGGER cigl_profile_owner_provenance AFTER INSERT ON control.cigl_method_profile
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_owner();

CREATE OR REPLACE FUNCTION openpc.require_cigl_profile_result()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE version_number bigint;
BEGIN
 IF TG_TABLE_NAME='cigl_profile_version' THEN version_number:=NEW.revision;
 ELSE version_number:=NEW.profile_revision; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.cigl_profile_version version JOIN control.configuration_work work
   ON work.configuration_work_id=version.configuration_work_id AND work.participant_id=version.participant_id AND work.privacy_domain_id=version.privacy_domain_id
   WHERE version.profile_id=NEW.profile_id AND version.revision=version_number AND version.participant_id=NEW.participant_id
    AND version.privacy_domain_id=NEW.privacy_domain_id AND version.state='COMPILED' AND work.state='COMPLETED') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-ATOMIC-RESULT'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_result_atomic ON control.cigl_profile_version;
CREATE CONSTRAINT TRIGGER cigl_profile_result_atomic AFTER UPDATE ON control.cigl_profile_version
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_result();
DROP TRIGGER IF EXISTS cigl_profile_grant_atomic ON control.cigl_profile_grant_source;
CREATE CONSTRAINT TRIGGER cigl_profile_grant_atomic AFTER INSERT ON control.cigl_profile_grant_source
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_result();
DROP TRIGGER IF EXISTS cigl_profile_method_atomic ON control.cigl_profile_method_source;
CREATE CONSTRAINT TRIGGER cigl_profile_method_atomic AFTER INSERT ON control.cigl_profile_method_source
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_result();
DROP TRIGGER IF EXISTS cigl_profile_path_atomic ON control.cigl_profile_dependency_path;
CREATE CONSTRAINT TRIGGER cigl_profile_path_atomic AFTER INSERT ON control.cigl_profile_dependency_path
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_result();
`;
