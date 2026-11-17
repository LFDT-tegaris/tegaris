export const deploymentPolicyGuardsSql = `
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
    OR (NEW.definition->'route'->>'mechanism' IN ('CREATE','CREATE2','CREATE3')
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
`;
