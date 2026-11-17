export const deploymentIntentGuardsSql = `
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
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0));
 IF NEW.module_generation_digest IS NULL OR NEW.module_generation_digest IS DISTINCT FROM
   openpc.deployment_module_generation(NEW.participant_id,NEW.privacy_domain_id)
 THEN RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-MODULE-GENERATION'; END IF;
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
   AND ((candidate.candidate_document->>'nativeValueAuthorizationId' IS NULL
     AND captured->>'nativeValueAuthorizationBytes' IS NULL AND document->'intent'->>'nativeValueAuthorizationDigest' IS NULL
     AND document->'intent'->>'valueWei'='0')
    OR EXISTS(SELECT 1 FROM control.native_value_authorization issued_grant
     WHERE 'urn:openpc:resource:'||issued_grant.native_value_authorization_id::text=candidate.candidate_document->>'nativeValueAuthorizationId'
      AND issued_grant.participant_id=NEW.participant_id AND issued_grant.privacy_domain_id=NEW.privacy_domain_id
      AND issued_grant.wallet_binding_id=NEW.wallet_binding_id AND issued_grant.wallet_binding_epoch::text=captured->>'walletBindingEpoch'
      AND issued_grant.actor_principal_id=coalesce(NEW.execution_principal_id,NEW.actor_principal_id)
      AND issued_grant.execution_workload_id IS NOT DISTINCT FROM NEW.execution_workload_id
      AND '0x'||encode(issued_grant.document_bytes,'hex')=captured->>'nativeValueAuthorizationBytes'
      AND issued_grant.valid_until>clock_timestamp() AND issued_grant.valid_until>=NEW.expires_at
      AND (document->'intent'->>'valueWei'='0' OR issued_grant.semantic_digest='sha256:'||(document->'intent'->>'nativeValueAuthorizationDigest'))
      AND NOT EXISTS(SELECT 1 FROM control.deployment_address_reservation reservation
       WHERE reservation.native_value_authorization_id=issued_grant.native_value_authorization_id AND reservation.state='HANDOFF')))
   AND source=jsonb_build_object('deploymentPolicyId',policy.deployment_policy_id::text,
    'participantId',policy.participant_id::text,'privacyDomainId',policy.privacy_domain_id::text,
    'definition',policy.definition,'definitionDigest',policy.definition_digest,'artifactDigest',policy.artifact_digest,
    'initCodeHash',policy.init_code_hash,'abiDigest',policy.abi_digest,'publicationOperationId',policy.publication_operation_id::text,
    'publicationAuthorityDigest',policy.publication_authority_digest,'factoryBinding',
     (SELECT jsonb_build_object('runtimeBindingId',factory.runtime_binding_id::text,'chainId',factory.chain_id,
       'networkId',factory.network_id,'genesisDigest',factory.genesis_digest,'contractAddress',factory.contract_address,
       'codeDigest',factory.code_digest,'abiDigest',factory_abi.abi_digest,'canonicalAbi',factory_abi.canonical_abi)
      FROM control.contract_runtime_binding factory JOIN control.abi_artifact factory_abi
       ON factory_abi.participant_id=factory.participant_id AND factory_abi.privacy_domain_id=factory.privacy_domain_id
       AND factory_abi.abi_artifact_id=factory.abi_artifact_id
      WHERE factory.participant_id=policy.participant_id AND factory.privacy_domain_id=policy.privacy_domain_id
       AND factory.runtime_binding_id=policy.factory_runtime_binding_id AND factory.state='BOUND'
       AND factory.chain_id=policy.definition->>'chainId' AND factory.network_id=policy.definition->>'networkId'
       AND factory.genesis_digest=policy.definition->>'genesisDigest'
       AND factory.proxy_address IS NULL AND factory.implementation_address IS NULL
       AND factory.implementation_code_digest IS NULL))
   AND (policy.definition->'route'->>'mechanism'='TRANSACTION_CREATE')=(policy.factory_runtime_binding_id IS NULL)
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
`;
