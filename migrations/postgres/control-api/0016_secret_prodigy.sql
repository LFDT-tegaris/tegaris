ALTER TABLE "control"."deployment_intent" ADD COLUMN "execution_principal_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."deployment_intent" ADD COLUMN "execution_workload_id" text;--> statement-breakpoint
ALTER TABLE "control"."deployment_intent" ADD CONSTRAINT "deployment_intent_executor_ck" CHECK (("control"."deployment_intent"."execution_principal_id" is null and "control"."deployment_intent"."execution_workload_id" is null) or ("control"."deployment_intent"."execution_principal_id" is not null and "control"."deployment_intent"."execution_workload_id" is not null and "control"."deployment_intent"."execution_workload_id" ~ '^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'));
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


CREATE OR REPLACE FUNCTION openpc.guard_deployment_address_reservation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE observed_at timestamptz:=date_trunc('milliseconds',clock_timestamp());
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'RESERVED' OR NEW.handoff_at IS NOT NULL OR NEW.expired_at IS NOT NULL OR NEW.expires_at<=observed_at THEN
   RAISE EXCEPTION 'PC-DATA-6004';
  END IF;
  NEW.created_at:=observed_at;
 ELSIF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'PC-DATA-6004';
 ELSE
  IF (to_jsonb(NEW)-ARRAY['state','handoff_at','expired_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['state','handoff_at','expired_at']) OR OLD.state<>'RESERVED' THEN
   RAISE EXCEPTION 'PC-DATA-6004';
  END IF;
  IF NEW.state='HANDOFF' AND OLD.expires_at>observed_at AND NEW.expired_at IS NULL THEN
   NEW.handoff_at:=observed_at;
  ELSIF NEW.state='EXPIRED' AND OLD.expires_at<=observed_at AND NEW.handoff_at IS NULL THEN
   NEW.expired_at:=observed_at;
  ELSE
   RAISE EXCEPTION 'PC-DATA-6004';
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS deployment_address_reservation_guard ON control.deployment_address_reservation;
CREATE TRIGGER deployment_address_reservation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deployment_address_reservation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_address_reservation();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1','deployment-policy','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_POLICY_PUBLICATION'),
 ('ACT-DEPLOYMENT_POLICIES_READ_RESOURCE-V1','deployment-policy','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','DEPLOYMENT_POLICY_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1','deployment-policy','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_POLICY_PUBLICATION'),
  ('ACT-DEPLOYMENT_POLICIES_READ_RESOURCE-V1','deployment-policy','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','DEPLOYMENT_POLICY_READ')))<>2 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-ACTION-REGISTRATION';
 END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_deployment_policy()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1'
  OR NEW.definition_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.definition),'UTF8')),'hex')
  OR (NEW.definition->>'expiresAt')::timestamptz<=clock_timestamp() THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-PUBLICATION';
 END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS deployment_policy_guard ON control.deployment_policy;
CREATE TRIGGER deployment_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deployment_policy
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_policy();

CREATE OR REPLACE FUNCTION openpc.require_deployment_policy_publication()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  JOIN control.abi_artifact abi ON abi.participant_id=NEW.participant_id AND abi.privacy_domain_id=NEW.privacy_domain_id
   AND abi.abi_artifact_id=NEW.abi_artifact_id AND abi.abi_digest=NEW.abi_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.publication_operation_id AND evidence.aggregate_type='deployment-policy'
   AND evidence.aggregate_id=NEW.deployment_policy_id AND evidence.catalog_operation_id='CFG-OP-CREATE-DEPLOYMENT-POLICY'
   AND evidence.action_intent_id='ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1'
   AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.deployment_policy_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND candidate.candidate_document->'definition'=NEW.definition
   AND NEW.definition->>'abiArtifactId'='urn:openpc:resource:'||NEW.abi_artifact_id::text
   AND NEW.artifact_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
    'mode',NEW.definition->'artifact'->>'mode','initCodeHash',NEW.init_code_hash,
    'runtimeCodeHash',NEW.definition->'artifact'->>'runtimeCodeHash')),'UTF8')),'hex')
   AND ((NEW.definition->'route'->>'mechanism'='TRANSACTION_CREATE' AND NEW.factory_runtime_binding_id IS NULL)
    OR (NEW.definition->'route'->>'mechanism' IN ('CREATE','CREATE2')
     AND NEW.definition->'route'->>'runtimeBindingId'='urn:openpc:resource:'||NEW.factory_runtime_binding_id::text
     AND EXISTS(SELECT 1 FROM control.contract_runtime_binding factory WHERE factory.participant_id=NEW.participant_id
      AND factory.privacy_domain_id=NEW.privacy_domain_id AND factory.runtime_binding_id=NEW.factory_runtime_binding_id
      AND factory.state='BOUND' AND factory.chain_id=NEW.definition->>'chainId'
      AND factory.network_id=NEW.definition->>'networkId' AND factory.genesis_digest=NEW.definition->>'genesisDigest'
      AND factory.proxy_address IS NULL AND factory.implementation_address IS NULL AND factory.implementation_code_digest IS NULL)))
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.deployment_policy_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.deployment_policy_id
    AND event.aggregate_type='deployment-policy' AND event.event_type='openpc.deployment.policy.staged.v1')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-PUBLICATION-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS deployment_policy_publication ON control.deployment_policy;
CREATE CONSTRAINT TRIGGER deployment_policy_publication AFTER INSERT ON control.deployment_policy
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_deployment_policy_publication();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1','deployment-submission','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_SUBMISSION'),
 ('ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1','deployment-intent','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_INTENT_PREPARATION'),
 ('ACT-DEPLOYMENT_INTENTS_READ_RESOURCE-V1','deployment-intent','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','DEPLOYMENT_INTENT_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1','deployment-submission','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_SUBMISSION'),
  ('ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1','deployment-intent','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_INTENT_PREPARATION'),
  ('ACT-DEPLOYMENT_INTENTS_READ_RESOURCE-V1','deployment-intent','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','DEPLOYMENT_INTENT_READ'))) IS DISTINCT FROM 3 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-INTENT-ACTIONS';
 END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_deployment_intent()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE document jsonb; source jsonb; captured jsonb;
BEGIN
 IF TG_OP IS DISTINCT FROM 'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 document:=convert_from(NEW.preparation_bytes,'UTF8')::jsonb;
 source:=convert_from(NEW.publication_bytes,'UTF8')::jsonb;
 captured:=document->'context';
 IF NEW.participant_id IS DISTINCT FROM current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id IS DISTINCT FROM current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.creation_operation_id IS DISTINCT FROM current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id') IS DISTINCT FROM 'ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1'
  OR document->>'schemaVersion' IS DISTINCT FROM 'PC-DEPLOYMENT-PREPARATION-1'
  OR captured->>'intentId' IS DISTINCT FROM NEW.deployment_intent_id::text
  OR captured->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR captured->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR captured->>'actorSubjectId' IS DISTINCT FROM coalesce(NEW.execution_principal_id,NEW.actor_principal_id)::text
  OR captured->>'workloadBindingId' IS DISTINCT FROM NEW.execution_workload_id
  OR (NEW.execution_principal_id IS NOT NULL AND NOT EXISTS(
   SELECT 1 FROM control.principal principal JOIN control.credential credential USING(participant_id,principal_id)
   WHERE principal.participant_id=NEW.participant_id AND principal.principal_id=NEW.execution_principal_id
    AND principal.kind='WORKLOAD' AND principal.state='ACTIVE' AND credential.kind='WORKLOAD_MTLS'
    AND credential.audience=NEW.execution_workload_id AND credential.state='ACTIVE'
    AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp()))
  OR captured->>'walletBindingId' IS DISTINCT FROM NEW.wallet_binding_id::text
  OR captured->>'targetRuntimeId' IS DISTINCT FROM NEW.runtime_target_id::text
  OR document->>'deploymentPolicyId' IS DISTINCT FROM NEW.deployment_policy_id::text
  OR NEW.creation_authority_digest IS DISTINCT FROM 'sha256:'||(captured->>'authorityDigest')
  OR NEW.preparation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.preparation_bytes),'hex')
  OR NEW.intent_digest IS DISTINCT FROM 'sha256:'||(document->'intent'->>'semanticDigest')
  OR document->>'publicationDigest' IS DISTINCT FROM encode(sha256(NEW.publication_bytes),'hex')
  OR NEW.expires_at IS DISTINCT FROM to_timestamp((captured->>'expiresAtMs')::numeric/1000)
  OR NEW.expires_at<=clock_timestamp() THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-INTENT';
 END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS deployment_intent_guard ON control.deployment_intent;
CREATE TRIGGER deployment_intent_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deployment_intent
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_intent();

CREATE OR REPLACE FUNCTION openpc.require_deployment_intent_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE document jsonb; source jsonb; captured jsonb;
BEGIN
 document:=convert_from(NEW.preparation_bytes,'UTF8')::jsonb;
 source:=convert_from(NEW.publication_bytes,'UTF8')::jsonb;
 captured:=document->'context';
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  JOIN control.deployment_policy policy ON policy.deployment_policy_id=NEW.deployment_policy_id
   AND policy.participant_id=NEW.participant_id AND policy.privacy_domain_id=NEW.privacy_domain_id
  JOIN control.wallet_binding wallet ON wallet.wallet_binding_id=NEW.wallet_binding_id
   AND wallet.participant_id=NEW.participant_id AND wallet.privacy_domain_id=NEW.privacy_domain_id
   AND wallet.subject_id=coalesce(NEW.execution_principal_id,NEW.actor_principal_id) AND wallet.state='ACTIVE'
   AND wallet.binding_epoch::text=captured->>'walletBindingEpoch'
   AND wallet.chain_id::text=policy.definition->>'chainId' AND wallet.wallet_address=document->'intent'->>'sender'
  JOIN control.runtime_target target ON target.runtime_target_id=NEW.runtime_target_id
   AND target.participant_id=NEW.participant_id AND target.privacy_domain_id=NEW.privacy_domain_id
   AND target.state='ACTIVE_MATCHED' AND target.active_generation_digest=target.desired_generation_digest
   AND target.policy_generation_digest='sha256:'||(captured->>'policyGenerationDigest')
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.creation_operation_id AND evidence.aggregate_type='deployment-intent'
   AND evidence.aggregate_id=NEW.deployment_intent_id AND evidence.catalog_operation_id='CFG-OP-CREATE-DEPLOYMENT-INTENT'
   AND evidence.action_intent_id='ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1'
   AND NEW.creation_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.deployment_intent_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND candidate.maker_principal_id=NEW.actor_principal_id
   AND candidate.candidate_document->>'deploymentPolicyId'='urn:openpc:resource:'||NEW.deployment_policy_id::text
   AND candidate.candidate_document->>'runtimeTargetId'='urn:openpc:resource:'||NEW.runtime_target_id::text
   AND candidate.candidate_document->>'walletBindingId'='urn:openpc:resource:'||NEW.wallet_binding_id::text
   AND (candidate.candidate_document->>'executionWorkloadId') IS NOT DISTINCT FROM NEW.execution_workload_id
   AND candidate.candidate_document->>'signingPayload'=document->>'signingPayload'
   AND source=jsonb_build_object('deploymentPolicyId',policy.deployment_policy_id::text,
    'participantId',policy.participant_id::text,'privacyDomainId',policy.privacy_domain_id::text,
    'definition',policy.definition,'definitionDigest',policy.definition_digest,'artifactDigest',policy.artifact_digest,
    'initCodeHash',policy.init_code_hash,'abiDigest',policy.abi_digest,'publicationOperationId',policy.publication_operation_id::text,
    'publicationAuthorityDigest',policy.publication_authority_digest,'factoryBinding',null)
   AND policy.definition->'route'->>'mechanism'='TRANSACTION_CREATE'
   AND (policy.definition->>'expiresAt')::timestamptz>=NEW.expires_at
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.deployment_intent_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.deployment_intent_id
    AND event.aggregate_type='deployment-intent' AND event.event_type='openpc.deployment.intent.prepared.v1')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-INTENT-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS deployment_intent_provenance ON control.deployment_intent;
CREATE CONSTRAINT TRIGGER deployment_intent_provenance AFTER INSERT ON control.deployment_intent
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_deployment_intent_provenance();

REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_policy", "control"."deployment_intent" FROM PUBLIC;
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_policy", "control"."deployment_intent" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."deployment_policy", "control"."deployment_intent" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_activation_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."provider_probe_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_route_publication" TO "openpc_control_runtime";
GRANT SELECT ON "control"."deployment_address_reservation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_policy", "control"."deployment_intent" TO "openpc_control_worker";
GRANT UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."deployment_policy", "control"."deployment_intent" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_route_publication" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."provider_probe_observation" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."deployment_address_reservation" TO "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_policy", "control"."deployment_intent" TO "openpc_control_reader";
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
