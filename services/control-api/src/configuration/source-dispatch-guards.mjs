// The source reader obtains exact row fences through the non-login store owner.
// Scoped SELECT/UPDATE visibility permits locking; WITH CHECK(false) rejects
// updated rows, and these policies grant no DELETE visibility. The function
// itself contains no DML and grants no source authority.
const lockedTables = [
  'runtime_target',
  'runtime_configuration_generation',
  'configuration_work',
  'projection_plan',
  'indexer_profile',
  'provider_profile',
  'provider_probe_observation',
  'runtime_configuration_input',
];
const readTables = [...lockedTables, 'runtime_activation_observation'];
const factContractTables = [
  'contract_runtime_binding',
  'abi_artifact',
  'logical_contract_asset',
  'privacy_domain',
];
const factScope = `openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'`;
const scope = `openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')`;
export const sourceDispatchGuardsSql = `
${readTables
  .map(
    (table) => `DROP POLICY IF EXISTS indexer_source_read_fence ON control.${table};
CREATE POLICY indexer_source_read_fence ON control.${table} FOR SELECT TO openpc_control_owner USING(${scope});`,
  )
  .join('\n')}
${lockedTables
  .map(
    (table) => `DROP POLICY IF EXISTS indexer_source_lock_fence ON control.${table};
CREATE POLICY indexer_source_lock_fence ON control.${table} FOR UPDATE TO openpc_control_owner USING(${scope}) WITH CHECK(false);`,
  )
  .join('\n')}
CREATE OR REPLACE FUNCTION openpc.lock_indexer_dispatch_source(p_target_id uuid, p_capsule_digest text)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
DECLARE v_source_id uuid; v_plan_id uuid; v_provider_id uuid; v_configuration_digest text;
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_READ_RPC-V1'
   OR p_capsule_digest !~ '^sha256:[0-9a-f]{64}$' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-INDEXER-SOURCE';
 END IF;
 PERFORM openpc.lock_cigl_publication_participant();
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||
   openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0));
 SELECT generation.projection_plan_id,generation.provider_profile_id,work.configuration_digest
  INTO STRICT v_plan_id,v_provider_id,v_configuration_digest
 FROM control.runtime_target target
 JOIN control.runtime_activation_observation observation
  ON observation.runtime_target_id=target.runtime_target_id
   AND observation.participant_id=target.participant_id AND observation.privacy_domain_id=target.privacy_domain_id
   AND observation.capsule_digest=target.active_generation_digest
 JOIN control.runtime_configuration_generation generation
  ON generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
   AND generation.participant_id=target.participant_id AND generation.privacy_domain_id=target.privacy_domain_id
   AND generation.runtime_target_id=target.runtime_target_id AND generation.generation_digest=observation.generation_digest
 JOIN control.configuration_work work ON work.configuration_work_id=observation.configuration_work_id
  AND work.participant_id=target.participant_id AND work.privacy_domain_id=target.privacy_domain_id
  AND work.runtime_target_id=target.runtime_target_id
  AND work.runtime_configuration_generation_id=generation.runtime_configuration_generation_id
  AND work.generation_digest=generation.generation_digest
  AND work.policy_generation_digest=generation.policy_generation_digest
  AND work.predecessor_digest IS NOT DISTINCT FROM generation.predecessor_digest
  AND work.xds_version_digest=observation.xds_version_digest
  AND work.operation_id=observation.operation_id AND work.execution_attempt_id=observation.execution_attempt_id
  AND work.result_receipt_digest=observation.activation_receipt_digest
 WHERE target.runtime_target_id=p_target_id
  AND openpc.matches_participant(target.participant_id) AND openpc.matches_privacy(target.privacy_domain_id)
  AND target.state='ACTIVE_MATCHED' AND target.active_generation_digest=p_capsule_digest
  AND target.desired_generation_digest=p_capsule_digest AND target.xds_version_digest=observation.xds_version_digest
  AND target.policy_generation_digest=generation.policy_generation_digest
  AND generation.state='ACTIVE' AND work.state='COMPLETED' AND work.work_kind='RUNTIME_ACTIVATION'
  AND work.execution_started_at IS NOT NULL
 FOR SHARE OF target,generation,work;
 SELECT projection.indexer_profile_id INTO STRICT v_source_id FROM control.projection_plan projection
 WHERE projection.projection_plan_id=v_plan_id
  AND openpc.matches_participant(projection.participant_id) AND openpc.matches_privacy(projection.privacy_domain_id)
 FOR SHARE;
 PERFORM 1 FROM control.indexer_profile source WHERE source.indexer_profile_id=v_source_id
  AND openpc.matches_participant(source.participant_id) AND openpc.matches_privacy(source.privacy_domain_id)
 FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-INDEXER-SOURCE'; END IF;
 PERFORM 1 FROM control.provider_profile provider
 JOIN control.provider_probe_observation observation ON observation.observation_id=provider.qualification_observation_id
  AND observation.provider_profile_id=provider.provider_profile_id
  AND observation.participant_id=provider.participant_id AND observation.privacy_domain_id=provider.privacy_domain_id
 WHERE provider.provider_profile_id=v_provider_id
  AND openpc.matches_participant(provider.participant_id) AND openpc.matches_privacy(provider.privacy_domain_id)
 FOR SHARE OF provider,observation;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-INDEXER-SOURCE'; END IF;
 PERFORM 1 FROM control.runtime_configuration_input input
 WHERE openpc.matches_participant(input.participant_id) AND openpc.matches_privacy(input.privacy_domain_id)
  AND input.configuration_digest=decode(substr(v_configuration_digest,8),'hex') AND input.selected
 FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-INDEXER-SOURCE'; END IF;
 RETURN v_plan_id;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_indexer_dispatch_source(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_indexer_dispatch_source(uuid,text) TO openpc_control_reader;

-- One qualification owner for publication and each provider used by dispatch.
-- Holding all three rows prevents replacement of the live observation or its
-- completed qualification while the caller consumes it. Expiry is still a
-- time bound and must be enforced before I/O and again before response release.
CREATE OR REPLACE FUNCTION openpc.lock_indexer_qualified_provider(p_provider_id uuid,p_artifact_digest text)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
DECLARE expiry_ns bigint;
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF openpc.current_action_intent_id() NOT IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')
  OR p_artifact_digest !~ '^sha256:[0-9a-f]{64}$' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-INDEXER-PROVIDER';
 END IF;
 SELECT (extract(epoch from observation.valid_until)*1000000000)::bigint INTO STRICT expiry_ns
 FROM control.provider_profile provider
 JOIN control.provider_probe_observation observation ON observation.observation_id=provider.qualification_observation_id
  AND observation.provider_profile_id=provider.provider_profile_id
  AND observation.participant_id=provider.participant_id AND observation.privacy_domain_id=provider.privacy_domain_id
 JOIN control.configuration_work qualification ON qualification.resource_id=provider.provider_profile_id
  AND qualification.participant_id=provider.participant_id AND qualification.privacy_domain_id=provider.privacy_domain_id
  AND qualification.work_kind='PROVIDER_QUALIFICATION' AND qualification.state='COMPLETED'
 WHERE provider.provider_profile_id=p_provider_id AND provider.behavior_fingerprint=p_artifact_digest
  AND openpc.matches_participant(provider.participant_id) AND openpc.matches_privacy(provider.privacy_domain_id)
  AND provider.state IN ('QUALIFIED','ACTIVE') AND provider.revision=observation.observed_revision+2
  AND observation.state='OBSERVED' AND observation.input_digest=provider.behavior_fingerprint
  AND observation.observation_id::text=qualification.result_receipt->>'liveObservationId'
  AND observation.observation_digest=qualification.result_receipt->>'liveObservationDigest'
  AND observation.observation=qualification.result_receipt->'liveObservation'
  AND qualification.result_receipt->>'artifactDigest'=provider.behavior_fingerprint
  AND observation.valid_until>clock_timestamp()
 FOR SHARE OF provider,observation,qualification;
 RETURN expiry_ns;
EXCEPTION WHEN NO_DATA_FOUND THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_indexer_qualified_provider(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_indexer_qualified_provider(uuid,text) TO openpc_control_reader,openpc_control_worker;

-- FactBridge holds the current source owners through the separate fact-store
-- commit. Candidate publication is asynchronous and cannot establish this fence.
DROP POLICY IF EXISTS fact_source_participant_read ON control.participant;
CREATE POLICY fact_source_participant_read ON control.participant FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1');
DROP POLICY IF EXISTS fact_source_participant_lock ON control.participant;
CREATE POLICY fact_source_participant_lock ON control.participant FOR UPDATE TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1') WITH CHECK(false);
-- Custody only, not authorization. The FactBridge owner authenticates before
-- taking this root lock, then rechecks exact signed permission dependencies.
CREATE OR REPLACE FUNCTION openpc.lock_fact_workload_context(p_fail_fast boolean)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1' OR p_fail_fast IS NULL THEN
  RAISE EXCEPTION 'PC-AUTH-0005-FACT-SOURCE';
 END IF;
 IF p_fail_fast THEN
  PERFORM 1 FROM control.participant
   WHERE participant_id=openpc.current_participant_id() AND state='ACTIVE' AND archived_at IS NULL FOR UPDATE NOWAIT;
 ELSE
  PERFORM 1 FROM control.participant
   WHERE participant_id=openpc.current_participant_id() AND state='ACTIVE' AND archived_at IS NULL FOR UPDATE;
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-FACT-SOURCE'; END IF;
 IF p_fail_fast THEN
  PERFORM 1 FROM control.privacy_domain WHERE participant_id=openpc.current_participant_id()
   AND privacy_domain_id=openpc.current_privacy_domain_id() AND state='ACTIVE' FOR SHARE NOWAIT;
 ELSE
  PERFORM 1 FROM control.privacy_domain WHERE participant_id=openpc.current_participant_id()
   AND privacy_domain_id=openpc.current_privacy_domain_id() AND state='ACTIVE' FOR SHARE;
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-FACT-SOURCE'; END IF;
EXCEPTION WHEN lock_not_available THEN
 IF p_fail_fast THEN RAISE EXCEPTION 'PC-DATA-6007'; ELSE RAISE; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_fact_workload_context(boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_fact_workload_context(boolean) TO openpc_control_worker;

-- Preserve the original blocking interface for its existing callers.
CREATE OR REPLACE FUNCTION openpc.lock_fact_workload_context()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.lock_fact_workload_context(false);
END $$;
REVOKE ALL ON FUNCTION openpc.lock_fact_workload_context() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_fact_workload_context() TO openpc_control_reader,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.lock_fact_candidate_source(p_plan_id uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
DECLARE v_source_id uuid;
BEGIN
 PERFORM openpc.lock_fact_workload_context();
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||
   openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0));
 SELECT projection.indexer_profile_id INTO STRICT v_source_id FROM control.projection_plan projection
  WHERE projection.projection_plan_id=p_plan_id
   AND openpc.matches_participant(projection.participant_id) AND openpc.matches_privacy(projection.privacy_domain_id)
   AND projection.state='VALIDATED' AND projection.readiness='READY'
  FOR SHARE;
 PERFORM 1 FROM control.indexer_profile source WHERE source.indexer_profile_id=v_source_id
  AND openpc.matches_participant(source.participant_id) AND openpc.matches_privacy(source.privacy_domain_id)
  AND source.state IN ('QUALIFIED','ACTIVE') FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-FACT-SOURCE'; END IF;
 PERFORM 1 FROM control.runtime_configuration_input input
  WHERE openpc.matches_participant(input.participant_id) AND openpc.matches_privacy(input.privacy_domain_id)
   AND input.selected FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-FACT-SOURCE'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_fact_candidate_source(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_fact_candidate_source(uuid) TO openpc_control_reader,openpc_control_worker;

${factContractTables
  .map(
    (table) => `DROP POLICY IF EXISTS fact_contract_read_fence ON control.${table};
CREATE POLICY fact_contract_read_fence ON control.${table} FOR SELECT TO openpc_control_owner USING(${factScope});
DROP POLICY IF EXISTS fact_contract_lock_fence ON control.${table};
CREATE POLICY fact_contract_lock_fence ON control.${table} FOR UPDATE TO openpc_control_owner USING(${factScope}) WITH CHECK(false);`,
  )
  .join('\n')}
CREATE OR REPLACE FUNCTION openpc.lock_fact_contract_binding(p_binding_id uuid)
RETURNS TABLE(binding_revision bigint,chain_id text,network_id text,genesis_digest text,
 contract_address text,code_digest text,proxy_address text,implementation_address text,
 implementation_code_digest text,abi_artifact_id uuid,abi_version text,abi_digest text,canonical_abi_bytes bytea)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF openpc.current_action_intent_id()<>'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-FACT-CONTRACT';
 END IF;
 RETURN QUERY SELECT binding.revision,binding.chain_id,binding.network_id,binding.genesis_digest,
  binding.contract_address,binding.code_digest,binding.proxy_address,binding.implementation_address,
  binding.implementation_code_digest,binding.abi_artifact_id,binding.abi_version,abi.abi_digest,abi.canonical_abi_bytes
 FROM control.contract_runtime_binding binding
 JOIN control.abi_artifact abi ON abi.abi_artifact_id=binding.abi_artifact_id
  AND abi.participant_id=binding.participant_id AND abi.privacy_domain_id=binding.privacy_domain_id
 JOIN control.logical_contract_asset asset ON asset.logical_contract_id=binding.logical_contract_id
  AND asset.participant_id=binding.participant_id AND asset.privacy_domain_id=binding.privacy_domain_id
 WHERE binding.runtime_binding_id=p_binding_id AND binding.state='BOUND'
  AND binding.quarantined_at IS NULL AND octet_length(abi.canonical_abi_bytes) BETWEEN 2 AND 131072
  AND openpc.matches_participant(binding.participant_id) AND openpc.matches_privacy(binding.privacy_domain_id)
 FOR SHARE OF binding,abi,asset;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-FACT-CONTRACT'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_fact_contract_binding(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_fact_contract_binding(uuid) TO openpc_control_reader;
`;
