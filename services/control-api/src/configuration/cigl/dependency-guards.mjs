export const ciglDependencyGuardsSql = `
ALTER TABLE control.cigl_method_grant_dependency_claims FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_dependency_claim()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-DEPENDENCY-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 PERFORM openpc.lock_cigl_grant_sources();
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1' THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY'; END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state NOT IN ('RELEASED','INVALIDATED')
   OR NEW.released_operation_id IS DISTINCT FROM current_setting('openpc.operation_id')::uuid
   OR (to_jsonb(NEW)-ARRAY['state','released_at','released_operation_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','released_at','released_operation_id'])
   OR NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants changed
    WHERE changed.participant_id=NEW.participant_id AND changed.privacy_domain_id=NEW.privacy_domain_id
     AND changed.publication_operation_id=NEW.released_operation_id
     AND ((NEW.state='RELEASED' AND changed.grant_id=NEW.source_grant_id AND changed.revision>NEW.source_grant_revision)
       OR (NEW.state='INVALIDATED' AND changed.grant_id=NEW.required_grant_id AND changed.revision>NEW.required_grant_revision))) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-OWNER'; END IF;
  NEW.released_at:=clock_timestamp(); RETURN NEW;
 END IF;
 -- Retain the same physical/method and policy source fence for direct SQL as
 -- for the repository. The grant advisory lock alone does not lock a binding.
 PERFORM 1 FROM control.cigl_profile_method_source retained
  JOIN control.contract_method_policy method ON method.contract_method_policy_id=retained.contract_method_policy_id AND method.participant_id=retained.participant_id AND method.privacy_domain_id=retained.privacy_domain_id
  JOIN control.contract_runtime_binding binding ON binding.runtime_binding_id=retained.runtime_binding_id AND binding.participant_id=retained.participant_id AND binding.privacy_domain_id=retained.privacy_domain_id
  WHERE retained.profile_id=NEW.profile_id AND retained.profile_revision=NEW.profile_revision ORDER BY method.contract_method_policy_id FOR SHARE OF method,binding;
 PERFORM 1 FROM control.cigl_profile_version version JOIN control.cigl_analysis analysis ON analysis.analysis_id=version.analysis_id
  JOIN control.runtime_target target ON target.runtime_target_id=analysis.runtime_target_id
  JOIN control.runtime_activation_observation observation ON observation.runtime_target_id=target.runtime_target_id
   AND observation.participant_id=target.participant_id AND observation.privacy_domain_id=target.privacy_domain_id
   AND observation.capsule_digest=target.active_generation_digest
  JOIN control.runtime_configuration_generation generation ON generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
   AND generation.runtime_target_id=target.runtime_target_id
   AND generation.participant_id=target.participant_id AND generation.privacy_domain_id=target.privacy_domain_id
   AND generation.generation_digest=observation.generation_digest AND generation.state='ACTIVE'
  WHERE version.profile_id=NEW.profile_id AND version.revision=NEW.profile_revision FOR SHARE OF target,generation;
 IF NEW.state<>'ACTIVE' OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid
  OR NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants source
   JOIN control.cigl_method_access_grants required ON required.participant_id=source.participant_id AND required.privacy_domain_id=source.privacy_domain_id
   JOIN control.cigl_profile_version version ON version.profile_id=NEW.profile_id AND version.revision=NEW.profile_revision
    AND version.participant_id=source.participant_id AND version.privacy_domain_id=source.privacy_domain_id
   JOIN control.cigl_profile_dependency_path path ON path.profile_id=version.profile_id AND path.profile_revision=version.revision AND path.ordinal=NEW.ordinal
   JOIN control.cigl_analysis analysis ON analysis.analysis_id=version.analysis_id AND analysis.participant_id=source.participant_id AND analysis.privacy_domain_id=source.privacy_domain_id
   JOIN control.contract_method_policy root ON root.contract_method_policy_id=analysis.contract_method_policy_id AND root.participant_id=source.participant_id AND root.privacy_domain_id=source.privacy_domain_id
   JOIN control.runtime_target target ON target.runtime_target_id=analysis.runtime_target_id AND target.participant_id=source.participant_id AND target.privacy_domain_id=source.privacy_domain_id
   JOIN control.participant participant ON participant.participant_id=source.participant_id
   WHERE source.grant_id=NEW.source_grant_id AND source.participant_id=NEW.participant_id AND source.privacy_domain_id=NEW.privacy_domain_id
    AND source.origin='SHARED' AND source.status='ACTIVE' AND source.definition->>'effect'='ALLOW' AND source.revision=NEW.source_grant_revision
    AND source.publication_operation_id=NEW.publication_operation_id AND openpc.cigl_subject_current(source.participant_id,source.definition->'subject')
    AND required.grant_id=NEW.required_grant_id AND required.revision=NEW.required_grant_revision AND required.status='ACTIVE' AND required.definition->>'effect'='ALLOW'
    AND required.definition->'subject'=source.definition->'subject' AND required.definition->>'surface'=source.definition->>'surface'
    AND required.runtime_binding_id::text=path.document->>'runtimeBindingId'
    AND required.selector='0x'||(SELECT string_agg(lpad(to_hex(value::text::integer),2,'0'),'' ORDER BY n) FROM jsonb_array_elements(path.document->'selector') WITH ORDINALITY s(value,n))
    AND root.runtime_binding_id=source.runtime_binding_id AND root.selector=source.selector AND root.revision=source.method_revision AND root.state='ACTIVE'
    AND EXISTS(SELECT 1 FROM control.cigl_profile_method_source retained WHERE retained.profile_id=NEW.profile_id AND retained.profile_revision=NEW.profile_revision
      AND retained.contract_method_policy_id=root.contract_method_policy_id AND retained.binding_revision=source.binding_revision AND retained.method_revision=source.method_revision)
    AND EXISTS(SELECT 1 FROM control.cigl_profile_method_source retained WHERE retained.profile_id=NEW.profile_id AND retained.profile_revision=NEW.profile_revision
      AND retained.contract_method_policy_id::text=path.document->>'contractMethodPolicyId' AND retained.binding_revision=required.binding_revision AND retained.method_revision=required.method_revision)
    AND ((NEW.capability='SIMULATE_CALL' AND root.effect='READ' AND source.definition->>'surface'='ETH_CALL')
      OR (NEW.capability='EXECUTE_TRANSACTION' AND root.effect='WRITE' AND source.definition->>'surface' IN ('PREPARE_WRITE','RAW_SUBMISSION','RUNTIME_WRITE_TRACE')))
    AND version.state='COMPILED' AND version.dependency_paths_digest IS NOT NULL AND analysis.analysis_digest=NEW.graph_digest
    AND analysis.policy_generation_digest=NEW.policy_generation_digest AND target.policy_generation_digest=NEW.policy_generation_digest
    AND target.state='ACTIVE_MATCHED' AND target.active_generation_digest=target.desired_generation_digest
    AND target.active_generation_digest=analysis.definition->>'expectedGenerationDigest'
    AND participant.state='ACTIVE' AND participant.archived_at IS NULL AND participant.authority_epoch=NEW.participant_epoch
    AND EXISTS(SELECT 1 FROM control.runtime_activation_observation observation
      JOIN control.runtime_configuration_generation generation ON generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
      AND generation.participant_id=observation.participant_id AND generation.privacy_domain_id=observation.privacy_domain_id
      AND generation.runtime_target_id=observation.runtime_target_id AND generation.generation_digest=observation.generation_digest
      WHERE observation.participant_id=NEW.participant_id AND observation.privacy_domain_id=NEW.privacy_domain_id
      AND observation.capsule_digest=target.active_generation_digest
      AND generation.runtime_target_id=target.runtime_target_id AND generation.state='ACTIVE'
      AND generation.policy_generation_digest=NEW.policy_generation_digest)
    AND NOT EXISTS(SELECT 1 FROM control.cigl_profile_method_source retained
      LEFT JOIN control.contract_method_policy live ON live.contract_method_policy_id=retained.contract_method_policy_id AND live.participant_id=retained.participant_id AND live.privacy_domain_id=retained.privacy_domain_id
      LEFT JOIN control.contract_runtime_binding binding ON binding.runtime_binding_id=retained.runtime_binding_id AND binding.participant_id=retained.participant_id AND binding.privacy_domain_id=retained.privacy_domain_id
      WHERE retained.profile_id=version.profile_id AND retained.profile_revision=version.revision
       AND (live.contract_method_policy_id IS NULL OR live.state<>'ACTIVE' OR live.revision<>retained.method_revision
        OR binding.runtime_binding_id IS NULL OR binding.state<>'BOUND' OR binding.revision<>retained.binding_revision))
    AND NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants denial WHERE denial.participant_id=source.participant_id AND denial.privacy_domain_id=source.privacy_domain_id
      AND denial.runtime_binding_id=required.runtime_binding_id AND denial.selector=required.selector AND denial.status='ACTIVE'
      AND denial.definition->>'effect'='DENY' AND denial.definition->>'surface'=source.definition->>'surface'
      AND (denial.definition->'subject'=source.definition->'subject' OR denial.definition->'subject'='{"kind":"ANY_AUTHENTICATED"}'::jsonb))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-SOURCE'; END IF;
 NEW.created_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_dependency_claim_guard ON control.cigl_method_grant_dependency_claims;
CREATE TRIGGER cigl_dependency_claim_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_method_grant_dependency_claims
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_dependency_claim();

CREATE OR REPLACE FUNCTION openpc.release_cigl_dependency_claims()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  UPDATE control.cigl_method_grant_dependency_claims SET state='RELEASED',released_operation_id=NEW.publication_operation_id,released_at=clock_timestamp()
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND source_grant_id=NEW.grant_id AND state='ACTIVE' AND source_grant_revision<NEW.revision;
  UPDATE control.cigl_method_grant_dependency_claims SET state='INVALIDATED',released_operation_id=NEW.publication_operation_id,released_at=clock_timestamp()
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND required_grant_id=NEW.grant_id AND state='ACTIVE' AND required_grant_revision<NEW.revision;
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_dependency_claim_release ON control.cigl_method_access_grants;
CREATE TRIGGER cigl_dependency_claim_release AFTER UPDATE ON control.cigl_method_access_grants
 FOR EACH ROW EXECUTE FUNCTION openpc.release_cigl_dependency_claims();

-- Deferred provenance also enforces completeness: an approved bundle cannot
-- commit a subset, add a dependency, or substitute a generated/shared grant.
CREATE OR REPLACE FUNCTION openpc.require_cigl_dependency_bundle()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE document jsonb; bundle jsonb; item jsonb; selected control.cigl_method_grant_dependency_claims;
BEGIN
 IF NEW.origin<>'SHARED' OR NEW.revision=1 THEN RETURN NULL; END IF;
 SELECT candidate.candidate_document INTO STRICT document FROM control.mutation_candidate candidate
  WHERE candidate.participant_id=NEW.participant_id AND candidate.privacy_domain_id=NEW.privacy_domain_id
   AND candidate.resource_id=NEW.grant_id AND candidate.consumed_operation_id=NEW.publication_operation_id
   AND candidate.catalog_operation_id='CFG-OP-UPDATE-CIGL-GRANT' AND candidate.state='CONSUMED';
 bundle:=document->'dependencyBundle';
 IF bundle IS NULL THEN
  IF EXISTS(SELECT 1 FROM control.cigl_grant_history WHERE grant_id=NEW.grant_id AND revision=NEW.revision-1 AND status=NEW.status) THEN
   RAISE EXCEPTION 'PC-DATA-6007-CIGL-GRANT-NO-CHANGE'; END IF;
  IF EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims WHERE source_grant_id=NEW.grant_id AND publication_operation_id=NEW.publication_operation_id) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-UNREVIEWED'; END IF;
  RETURN NULL;
 END IF;
 IF NEW.status<>'ACTIVE' OR jsonb_typeof(bundle->'dependencies') IS DISTINCT FROM 'array'
  OR (SELECT count(DISTINCT value->>'actionDigest') FROM jsonb_array_elements(bundle->'dependencies'))<>jsonb_array_length(bundle->'dependencies')
  OR (SELECT count(*) FROM control.cigl_method_grant_dependency_claims WHERE source_grant_id=NEW.grant_id AND source_grant_revision=NEW.revision AND publication_operation_id=NEW.publication_operation_id)
    <>jsonb_array_length(bundle->'dependencies')
  OR jsonb_array_length(bundle->'dependencies')<>(SELECT count(*) FROM control.cigl_profile_dependency_path path
    JOIN control.cigl_profile_version version ON version.profile_id=path.profile_id AND version.revision=path.profile_revision
    WHERE version.profile_id::text=substring(bundle->>'profileId' from 21) AND version.revision::text=bundle->>'profileRevision'
     AND version.participant_id=NEW.participant_id AND version.privacy_domain_id=NEW.privacy_domain_id AND version.profile_digest=bundle->>'profileDigest') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-COMPLETENESS'; END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(bundle->'dependencies') LOOP
  SELECT claim.* INTO selected FROM control.cigl_method_grant_dependency_claims claim
   JOIN control.cigl_profile_dependency_path path_row ON path_row.profile_id=claim.profile_id AND path_row.profile_revision=claim.profile_revision AND path_row.ordinal=claim.ordinal
   WHERE claim.source_grant_id=NEW.grant_id AND claim.source_grant_revision=NEW.revision AND claim.publication_operation_id=NEW.publication_operation_id
    AND 'sha256:'||(path_row.document->>'actionDigest')=item->>'actionDigest';
  IF NOT FOUND OR selected.state<>'ACTIVE' OR selected.capability IS DISTINCT FROM bundle->>'capability'
   OR selected.graph_digest IS DISTINCT FROM bundle->>'graphDigest' OR selected.policy_generation_digest IS DISTINCT FROM bundle->>'policyGenerationDigest'
   OR selected.participant_epoch::text IS DISTINCT FROM bundle->>'participantEpoch'
   OR selected.profile_id::text IS DISTINCT FROM substring(bundle->>'profileId' from 21) OR selected.profile_revision::text IS DISTINCT FROM bundle->>'profileRevision'
   OR NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants required WHERE required.grant_id=selected.required_grant_id
    AND ((item->'grant'->>'kind'='SHARED' AND 'urn:openpc:resource:'||required.grant_id::text=item->'grant'->>'grantId'
      AND selected.required_grant_revision::text=item->'grant'->>'expectedRevision')
     OR (item->'grant'='{"kind":"GENERATE"}'::jsonb AND required.origin='GENERATED' AND required.generated_by_grant_id=NEW.grant_id
      AND required.publication_operation_id=NEW.publication_operation_id AND required.revision=1))) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-EXACT-BUNDLE'; END IF;
 END LOOP;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_dependency_bundle_provenance ON control.cigl_method_access_grants;
CREATE CONSTRAINT TRIGGER cigl_dependency_bundle_provenance AFTER UPDATE ON control.cigl_method_access_grants
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_dependency_bundle();

CREATE OR REPLACE FUNCTION openpc.require_generated_cigl_grant()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.origin<>'GENERATED' THEN RETURN NULL; END IF;
 IF NEW.status='ACTIVE' THEN
  IF NOT EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims claim
    JOIN control.cigl_profile_dependency_path path ON path.profile_id=claim.profile_id AND path.profile_revision=claim.profile_revision AND path.ordinal=claim.ordinal
    JOIN control.mutation_candidate candidate ON candidate.participant_id=claim.participant_id AND candidate.privacy_domain_id=claim.privacy_domain_id
     AND candidate.resource_id=claim.source_grant_id AND candidate.consumed_operation_id=claim.publication_operation_id AND candidate.state='CONSUMED'
     AND candidate.catalog_operation_id='CFG-OP-UPDATE-CIGL-GRANT'
    WHERE claim.required_grant_id=NEW.grant_id AND claim.state='ACTIVE'
     AND claim.publication_operation_id=NEW.publication_operation_id AND claim.source_grant_id=NEW.generated_by_grant_id
     AND EXISTS(SELECT 1 FROM jsonb_array_elements(candidate.candidate_document->'dependencyBundle'->'dependencies') item
       WHERE item->'grant'='{"kind":"GENERATE"}'::jsonb AND item->>'actionDigest'='sha256:'||(path.document->>'actionDigest'))) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GENERATED-UNOWNED'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims WHERE required_grant_id=NEW.grant_id AND state='ACTIVE')
   OR NOT EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims WHERE required_grant_id=NEW.grant_id AND released_operation_id=NEW.publication_operation_id)
   OR NOT EXISTS(SELECT 1 FROM control.mutation_evidence WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
     AND operation_id=NEW.publication_operation_id AND catalog_operation_id='CFG-OP-UPDATE-CIGL-GRANT') THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GENERATED-RELEASE'; END IF;
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_generated_grant_provenance ON control.cigl_method_access_grants;
CREATE CONSTRAINT TRIGGER cigl_generated_grant_provenance AFTER INSERT OR UPDATE ON control.cigl_method_access_grants
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_generated_cigl_grant();

CREATE OR REPLACE FUNCTION openpc.require_cigl_dependency_claim()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='INSERT' AND NOT EXISTS(SELECT 1 FROM control.mutation_candidate candidate
  JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id AND evidence.privacy_domain_id=candidate.privacy_domain_id
   AND evidence.operation_id=candidate.consumed_operation_id AND evidence.candidate_digest=candidate.candidate_digest
   AND evidence.catalog_operation_id=candidate.catalog_operation_id AND evidence.aggregate_id=candidate.resource_id
  JOIN control.cigl_profile_dependency_path path ON path.profile_id=NEW.profile_id AND path.profile_revision=NEW.profile_revision AND path.ordinal=NEW.ordinal
  JOIN control.cigl_profile_version version ON version.profile_id=path.profile_id AND version.revision=path.profile_revision
  WHERE candidate.participant_id=NEW.participant_id AND candidate.privacy_domain_id=NEW.privacy_domain_id
   AND candidate.resource_id=NEW.source_grant_id AND candidate.state='CONSUMED' AND candidate.catalog_operation_id='CFG-OP-UPDATE-CIGL-GRANT'
   AND candidate.consumed_operation_id=NEW.publication_operation_id AND evidence.aggregate_version=NEW.source_grant_revision
   AND candidate.candidate_document->'dependencyBundle'->>'profileId'='urn:openpc:resource:'||NEW.profile_id::text
   AND candidate.candidate_document->'dependencyBundle'->>'profileRevision'=NEW.profile_revision::text
   AND candidate.candidate_document->'dependencyBundle'->>'profileDigest'=version.profile_digest
   AND candidate.candidate_document->'dependencyBundle'->>'capability'=NEW.capability
   AND candidate.candidate_document->'dependencyBundle'->>'graphDigest'=NEW.graph_digest
   AND candidate.candidate_document->'dependencyBundle'->>'policyGenerationDigest'=NEW.policy_generation_digest
   AND candidate.candidate_document->'dependencyBundle'->>'participantEpoch'=NEW.participant_epoch::text
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(candidate.candidate_document->'dependencyBundle'->'dependencies') item
     WHERE item->>'actionDigest'='sha256:'||(path.document->>'actionDigest')
      AND ((item->'grant'->>'kind'='SHARED' AND item->'grant'->>'grantId'='urn:openpc:resource:'||NEW.required_grant_id::text AND item->'grant'->>'expectedRevision'=NEW.required_grant_revision::text)
       OR (item->'grant'='{"kind":"GENERATE"}'::jsonb AND EXISTS(SELECT 1 FROM control.cigl_method_access_grants required
        WHERE required.grant_id=NEW.required_grant_id AND required.origin='GENERATED' AND required.generated_by_grant_id=NEW.source_grant_id AND required.publication_operation_id=NEW.publication_operation_id))))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-PROVENANCE'; END IF;
 IF TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM control.cigl_method_access_grants required WHERE required.grant_id=NEW.required_grant_id
   AND required.origin='GENERATED' AND required.status='ACTIVE'
   AND NOT EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims claim WHERE claim.required_grant_id=required.grant_id AND claim.state='ACTIVE')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GENERATED-ORPHAN'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_dependency_claim_provenance ON control.cigl_method_grant_dependency_claims;
CREATE CONSTRAINT TRIGGER cigl_dependency_claim_provenance AFTER INSERT OR UPDATE ON control.cigl_method_grant_dependency_claims
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_dependency_claim();
`;
