ALTER TABLE "control"."contract_runtime_binding" ADD COLUMN "transaction_policy" jsonb;
-- OPENPC CONTROL-API SECURITY TAIL

CREATE OR REPLACE FUNCTION openpc.guard_transferred_contract()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW.transaction_policy IS DISTINCT FROM OLD.transaction_policy THEN
  RAISE EXCEPTION 'PC-AUTH-0002-TRANSACTION-POLICY-IMMUTABLE';
 END IF;
 IF NEW.state='BOUND' AND EXISTS(SELECT 1 FROM control.contract_administration_transfer
   WHERE logical_contract_id=NEW.logical_contract_id AND participant_id=NEW.participant_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-ADMINISTRATION-TRANSFERRED';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS contract_administration_fence ON control.contract_runtime_binding;
CREATE TRIGGER contract_administration_fence BEFORE INSERT OR UPDATE ON control.contract_runtime_binding
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_transferred_contract();
CREATE OR REPLACE FUNCTION openpc.reject_contract_transfer_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-HISTORY'; END $$;
DROP TRIGGER IF EXISTS contract_transfer_immutable ON control.contract_administration_transfer;
CREATE TRIGGER contract_transfer_immutable BEFORE UPDATE OR DELETE ON control.contract_administration_transfer
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_contract_transfer_mutation();
CREATE OR REPLACE FUNCTION openpc.require_contract_transfer_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE mode text:=current_setting('openpc.context_mode');
 owner uuid:=nullif(current_setting('openpc.participant_id'),'')::uuid;
 privacy uuid:=nullif(current_setting('openpc.privacy_domain_id'),'')::uuid;
 op uuid:=current_setting('openpc.operation_id')::uuid;
 action text:=current_setting('openpc.action_intent_id');
 transition control.participant_lifecycle_transition%ROWTYPE; valid boolean;
BEGIN
 IF NEW.source_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.prior_definition-'contentDigest'),'UTF8')),'hex')
   OR NEW.prior_definition->>'contentDigest'<>NEW.source_digest OR jsonb_array_length(NEW.binding_map)<>jsonb_array_length(NEW.prior_definition->'bindings')
   OR (SELECT count(DISTINCT mapping->>'sourceBindingId') FROM jsonb_array_elements(NEW.binding_map) mapping)<>jsonb_array_length(NEW.binding_map)
   OR (SELECT count(DISTINCT mapping->>'successorBindingId') FROM jsonb_array_elements(NEW.binding_map) mapping)<>jsonb_array_length(NEW.binding_map) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-DEFINITION';
 END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.participant_id,NEW.privacy_domain_id,op,action,true);
 SELECT * INTO transition FROM control.participant_lifecycle_transition WHERE participant_id=NEW.participant_id
  AND operation_id=NEW.operation_id AND mutation='TRANSFER';
 IF NOT FOUND OR EXISTS(SELECT 1 FROM control.contract_runtime_binding WHERE logical_contract_id=NEW.logical_contract_id AND state='BOUND') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-SOURCE';
 END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',transition.source_participant_id,transition.source_privacy_domain_id,op,action,true);
 SELECT EXISTS(SELECT 1 FROM control.mutation_candidate c WHERE c.participant_id=transition.source_participant_id
  AND c.consumed_operation_id=NEW.operation_id AND c.state='CONSUMED' AND c.catalog_operation_id='ID-OP-PARTICIPANT-TRANSFER'
  AND c.candidate_document->>'logicalContractId'=NEW.logical_contract_id::text
  AND c.candidate_document->>'contentDigest'=NEW.source_digest
  AND c.candidate_document->>'successorParticipantId'=NEW.successor_participant_id::text
  AND c.candidate_document->>'successorPrivacyDomainId'=NEW.successor_privacy_domain_id::text
  AND c.candidate_document->>'successorLogicalContractId'=NEW.successor_logical_contract_id::text
  AND (c.candidate_document->>'expectedSuccessorEpoch')::numeric+1=NEW.successor_epoch::numeric) INTO valid;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-CANDIDATE'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.successor_participant_id,NEW.successor_privacy_domain_id,op,action,true);
 SELECT EXISTS(SELECT 1 FROM control.participant p JOIN control.logical_contract_asset asset ON asset.participant_id=p.participant_id
  WHERE p.participant_id=NEW.successor_participant_id AND p.authority_epoch=NEW.successor_epoch::numeric AND p.state='ACTIVE'
   AND asset.logical_contract_id=NEW.successor_logical_contract_id AND asset.privacy_domain_id=NEW.successor_privacy_domain_id) INTO valid;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.binding_map) mapping WHERE NOT EXISTS(
   SELECT 1 FROM control.contract_runtime_binding binding JOIN control.abi_artifact artifact ON artifact.abi_artifact_id=binding.abi_artifact_id
    JOIN jsonb_array_elements(NEW.prior_definition->'bindings') prior ON prior->>'runtime_binding_id'=mapping->>'sourceBindingId'
    JOIN jsonb_array_elements(NEW.prior_definition->'abiArtifacts') abi ON abi->>'abi_artifact_id'=prior->>'abi_artifact_id'
   WHERE binding.participant_id=NEW.successor_participant_id AND binding.privacy_domain_id=NEW.successor_privacy_domain_id
    AND binding.logical_contract_id=NEW.successor_logical_contract_id AND binding.runtime_binding_id::text=mapping->>'successorBindingId'
    AND binding.abi_artifact_id::text=mapping->>'successorAbiArtifactId' AND binding.contract_address=prior->>'contract_address'
    AND binding.chain_id=prior->>'chain_id' AND binding.network_id=prior->>'network_id' AND binding.code_digest=prior->>'code_digest'
    AND binding.genesis_digest=prior->>'genesis_digest' AND binding.abi_version=prior->>'abi_version'
    AND binding.proxy_address IS NOT DISTINCT FROM prior->>'proxy_address'
    AND binding.implementation_address IS NOT DISTINCT FROM prior->>'implementation_address'
    AND binding.implementation_code_digest IS NOT DISTINCT FROM prior->>'implementation_code_digest'
    AND coalesce(binding.transaction_policy,'null'::jsonb)=coalesce(prior->'transaction_policy','null'::jsonb)
    AND artifact.canonical_abi_bytes=(abi->>'canonical_abi_bytes')::bytea
    AND artifact.abi_digest=abi->>'abi_digest' AND artifact.canonical_abi=abi->'canonical_abi' AND binding.state='BOUND')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-BINDINGS';
 END IF;
 PERFORM openpc.set_request_context(mode,owner,privacy,op,action,privacy IS NOT NULL);
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-SUCCESSOR'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS contract_transfer_provenance ON control.contract_administration_transfer;
CREATE CONSTRAINT TRIGGER contract_transfer_provenance AFTER INSERT ON control.contract_administration_transfer
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_contract_transfer_provenance();

REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication" FROM PUBLIC;
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_activation_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."provider_probe_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_route_publication" TO "openpc_control_runtime";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication" TO "openpc_control_worker";
GRANT UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_route_publication" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."provider_probe_observation" TO "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication" TO "openpc_control_reader";
CREATE OR REPLACE FUNCTION openpc.reject_runtime_activation_observation_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
DROP TRIGGER IF EXISTS runtime_activation_observation_immutable ON "control"."runtime_activation_observation";
CREATE TRIGGER runtime_activation_observation_immutable BEFORE UPDATE OR DELETE ON "control"."runtime_activation_observation"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_runtime_activation_observation_mutation();
DROP TRIGGER IF EXISTS runtime_route_publication_immutable ON "control"."runtime_route_publication";
CREATE TRIGGER runtime_route_publication_immutable BEFORE UPDATE OR DELETE ON "control"."runtime_route_publication"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_runtime_activation_observation_mutation();
CREATE OR REPLACE FUNCTION openpc.guard_provider_probe_observation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP='DELETE' OR OLD.state<>'RUNNING' OR
    ROW(NEW.observation_id,NEW.participant_id,NEW.privacy_domain_id,NEW.provider_profile_id,
        NEW.source_revision,NEW.input_digest,NEW.configuration_digest,NEW.created_at)
    IS DISTINCT FROM
    ROW(OLD.observation_id,OLD.participant_id,OLD.privacy_domain_id,OLD.provider_profile_id,
        OLD.source_revision,OLD.input_digest,OLD.configuration_digest,OLD.created_at) THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='DATA-6020-IMMUTABLE-ROW';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS provider_probe_observation_guard ON "control"."provider_probe_observation";
CREATE TRIGGER provider_probe_observation_guard BEFORE UPDATE OR DELETE ON "control"."provider_probe_observation"
FOR EACH ROW EXECUTE FUNCTION openpc.guard_provider_probe_observation();
