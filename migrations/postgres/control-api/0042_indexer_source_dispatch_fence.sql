-- Custom SQL migration file, put your code below! --
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


CREATE OR REPLACE FUNCTION openpc.lock_deployment_command(command_id uuid)
RETURNS void LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT pg_advisory_xact_lock(hashtextextended('openpc:deployment-command:'||command_id::text,0))
$$;
REVOKE ALL ON FUNCTION openpc.lock_deployment_command(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_deployment_command(uuid) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.validate_deployment_rejection(result control.deployment_result)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE claims jsonb; expected jsonb; issued_at timestamptz; expires_at timestamptz;
BEGIN
 PERFORM openpc.assert_request_context(true);
 PERFORM openpc.lock_deployment_command(result.command_id);
 claims:=convert_from(result.signed_bytes,'UTF8')::jsonb->'claims';
 IF NOT openpc.matches_participant(result.participant_id) OR NOT openpc.matches_privacy(result.privacy_domain_id)
  OR result.sequence<>1 OR claims->>'schema' IS DISTINCT FROM 'PC-DEPLOYMENT-RESERVATION-REJECTION-1'
  OR NOT coalesce(claims->>'reason' IN ('CUSTODY_CONFLICT','PREPARATION_EXPIRED','MODULE_GENERATION_UNAVAILABLE'),false)
  OR NOT coalesce(claims->'binding'->>'transactionHash' ~ '^0x[0-9a-f]{64}$',false)
  OR EXISTS(SELECT 1 FROM control.deployment_address_reservation WHERE command_id=result.command_id)
  OR EXISTS(SELECT 1 FROM control.deployment_result prior WHERE prior.command_id=result.command_id)
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF claims->>'reason'='MODULE_GENERATION_UNAVAILABLE' THEN
  PERFORM pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||result.participant_id::text||':'||result.privacy_domain_id::text,0));
  IF EXISTS(SELECT 1 FROM control.deployment_intent i WHERE i.participant_id=result.participant_id
   AND i.privacy_domain_id=result.privacy_domain_id
   AND i.preparation_digest='sha256:'||(claims->'binding'->>'preparationDigest')
   AND i.module_generation_digest IS NOT NULL
   AND i.module_generation_digest=openpc.deployment_module_generation(i.participant_id,i.privacy_domain_id))
  THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 END IF;
 SELECT jsonb_build_object(
   'targetRuntimeId',intent.runtime_target_id::text,
   'owner',jsonb_build_object('participant_id',candidate.participant_id::text,
     'privacy_domain_id',candidate.privacy_domain_id::text,'actor_principal_id',intent.execution_principal_id::text,
     'workload_id',intent.execution_workload_id),
   'commandId',candidate.consumed_operation_id::text,'attemptId',candidate.resource_id::text,
   'intentDigest',substring(intent.intent_digest from 8),'preparationDigest',substring(intent.preparation_digest from 8),
   'chainId',prepared.document->'intent'->>'chainId','genesisDigest',prepared.document->'intent'->>'genesisHash',
   'transactionHash',claims->'binding'->>'transactionHash'),candidate.created_at,intent.expires_at
 INTO STRICT expected,issued_at,expires_at
 FROM control.mutation_candidate candidate
 JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id
  AND receipt.privacy_domain_id=candidate.privacy_domain_id AND receipt.operation_id=candidate.consumed_operation_id
  AND receipt.catalog_operation_id=candidate.catalog_operation_id AND receipt.input_digest=candidate.candidate_digest
  AND receipt.principal_id=candidate.maker_principal_id AND receipt.terminal_state='COMMITTED'
 JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id
  AND evidence.privacy_domain_id=candidate.privacy_domain_id AND evidence.operation_id=candidate.consumed_operation_id
  AND evidence.catalog_operation_id=candidate.catalog_operation_id AND evidence.candidate_digest=candidate.candidate_digest
  AND evidence.aggregate_id=candidate.resource_id AND evidence.aggregate_type='deployment-submission'
 JOIN control.deployment_intent intent ON intent.participant_id=candidate.participant_id
  AND intent.privacy_domain_id=candidate.privacy_domain_id AND intent.actor_principal_id=candidate.maker_principal_id
  AND candidate.candidate_document->>'deploymentIntentId'='urn:openpc:resource:'||intent.deployment_intent_id::text
 CROSS JOIN LATERAL (SELECT convert_from(intent.preparation_bytes,'UTF8')::jsonb document) prepared
 WHERE candidate.participant_id=result.participant_id AND candidate.privacy_domain_id=result.privacy_domain_id
  AND candidate.consumed_operation_id=result.command_id AND candidate.state='CONSUMED'
  AND candidate.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
  AND candidate.action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND candidate.resource_type='deployment-submission' AND candidate.operation_class='CREATE'
  AND encode(candidate.candidate_digest,'hex')=claims->>'candidateDigest'
  AND encode(evidence.evidence_digest,'hex')=claims->>'authorizationEvidenceDigest';
 IF claims->'binding' IS DISTINCT FROM expected OR claims->>'observedAt' IS NULL
  OR (claims->>'observedAt')::timestamptz<issued_at
  OR (claims->>'observedAt')::timestamptz>clock_timestamp()+interval '5 seconds'
  OR (claims->>'reason'='PREPARATION_EXPIRED' AND
    (expires_at>clock_timestamp() OR (claims->>'observedAt')::timestamptz<expires_at))
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.validate_deployment_rejection(control.deployment_result) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.validate_deployment_rejection(control.deployment_result) TO openpc_control_worker;


-- The migration owns an exclusive DDL transaction. Recover only exact immutable
-- intent nonces; unresolved historical custody remains retained and fail-closed.
DROP TRIGGER IF EXISTS deployment_address_reservation_guard ON control.deployment_address_reservation;
UPDATE control.deployment_address_reservation reservation SET sender_nonce=document.nonce
FROM control.deployment_intent intent,
 LATERAL (SELECT convert_from(intent.preparation_bytes,'UTF8')::jsonb->'intent'->>'nonce' AS nonce,
  convert_from(intent.preparation_bytes,'UTF8')::jsonb->'intent'->>'sender' AS sender) document
WHERE reservation.sender_nonce IS NULL AND reservation.participant_id=intent.participant_id
 AND reservation.privacy_domain_id=intent.privacy_domain_id
 AND reservation.prepared_record_digest=intent.preparation_digest AND reservation.intent_digest=intent.intent_digest
 AND reservation.sender_address=document.sender AND document.nonce ~ '^(0|[1-9][0-9]{0,19})$'
 AND document.nonce::numeric<2::numeric^64;

-- Only this trigger can inspect global legacy custody. It returns no foreign
-- row data and never confers a grant or performs an effect.
CREATE OR REPLACE FUNCTION openpc.guard_deployment_sender_custody()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id)
  OR NEW.sender_nonce IS NULL OR EXISTS(
   SELECT 1 FROM control.deployment_address_reservation held
   WHERE held.chain_id=NEW.chain_id AND held.genesis_digest=NEW.genesis_digest
    AND held.sender_address=NEW.sender_address AND held.sender_nonce IS NULL AND held.state<>'EXPIRED') THEN
  RAISE EXCEPTION 'PC-DATA-6004';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_deployment_sender_custody() FROM PUBLIC;
DROP TRIGGER IF EXISTS deployment_sender_custody_guard ON control.deployment_address_reservation;
CREATE TRIGGER deployment_sender_custody_guard BEFORE INSERT ON control.deployment_address_reservation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_sender_custody();

CREATE OR REPLACE FUNCTION openpc.guard_deployment_address_reservation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE observed_at timestamptz:=date_trunc('milliseconds',clock_timestamp());
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'DELETE' THEN
  PERFORM openpc.lock_deployment_command(NEW.command_id);
  IF EXISTS(SELECT 1 FROM control.deployment_result result WHERE result.command_id=NEW.command_id
   AND convert_from(result.signed_bytes,'UTF8')::jsonb->>'purpose'='openpc:deployment-reservation-rejection:v1')
  THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'RESERVED' OR NEW.handoff_at IS NOT NULL OR NEW.expired_at IS NOT NULL OR NEW.expires_at<=observed_at THEN
   RAISE EXCEPTION 'PC-DATA-6004';
  END IF;
  IF NEW.predecessor_command_id IS NOT NULL THEN
   -- A new approved command can share only the exact still-held original
   -- address/nonce custody. This is not a pending-chain or send assertion.
   PERFORM 1 FROM control.deployment_address_reservation prior
    JOIN control.mutation_candidate original ON original.consumed_operation_id=prior.command_id
     AND original.participant_id=prior.participant_id AND original.privacy_domain_id=prior.privacy_domain_id
     AND original.state='CONSUMED' AND original.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
    JOIN control.mutation_candidate successor ON successor.consumed_operation_id=NEW.command_id
     AND successor.participant_id=NEW.participant_id AND successor.privacy_domain_id=NEW.privacy_domain_id
     AND successor.state='CONSUMED' AND successor.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
     AND successor.maker_principal_id=original.maker_principal_id
     AND successor.candidate_document->>'predecessorOperationId'='urn:openpc:operation:'||prior.command_id::text
    WHERE prior.command_id=NEW.predecessor_command_id AND prior.predecessor_command_id IS NULL
     AND prior.state='HANDOFF' AND prior.participant_id=NEW.participant_id AND prior.privacy_domain_id=NEW.privacy_domain_id
     AND ROW(prior.target_runtime_id,prior.chain_id,prior.genesis_digest,prior.contract_address,prior.helper_address,
      prior.sender_address,prior.sender_nonce,prior.creator_address,prior.mechanism,prior.salt_namespace_digest,prior.effective_salt,
      prior.artifact_digest,prior.init_code_hash,prior.profile_digest,prior.generation_digest,
      prior.native_value_authorization_id,prior.native_value_authorization_digest)
      IS NOT DISTINCT FROM ROW(NEW.target_runtime_id,NEW.chain_id,NEW.genesis_digest,NEW.contract_address,NEW.helper_address,
      NEW.sender_address,NEW.sender_nonce,NEW.creator_address,NEW.mechanism,NEW.salt_namespace_digest,NEW.effective_salt,
      NEW.artifact_digest,NEW.init_code_hash,NEW.profile_digest,NEW.generation_digest,
      NEW.native_value_authorization_id,NEW.native_value_authorization_digest)
     AND prior.transaction_hash<>NEW.transaction_hash FOR SHARE OF prior;
   IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  END IF;
  NEW.created_at:=observed_at;
 ELSIF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'PC-DATA-6004';
 ELSE
  IF (to_jsonb(NEW)-ARRAY['state','handoff_at','expired_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['state','handoff_at','expired_at']) OR OLD.state<>'RESERVED' THEN
   RAISE EXCEPTION 'PC-DATA-6004';
  END IF;
  IF NEW.state='HANDOFF' AND NEW.sender_nonce IS NOT NULL AND OLD.expires_at>observed_at AND NEW.expired_at IS NULL THEN
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

-- Materialized physical keys cover every address of the same governed attempt.
-- Unique-index arbitration also sees foreign-scope rows without disclosing them.
INSERT INTO control.deployment_address_claim
 (attempt_id,participant_id,privacy_domain_id,chain_id,genesis_digest,address,active)
 SELECT reservation.attempt_id,reservation.participant_id,reservation.privacy_domain_id,
  reservation.chain_id,reservation.genesis_digest,claimed.address,reservation.state<>'EXPIRED'
 FROM control.deployment_address_reservation reservation
 CROSS JOIN LATERAL unnest(ARRAY[reservation.contract_address,reservation.helper_address]) claimed(address)
 WHERE claimed.address IS NOT NULL AND reservation.predecessor_command_id IS NULL
 ON CONFLICT (attempt_id,address) DO NOTHING;

CREATE OR REPLACE FUNCTION openpc.sync_deployment_address_claims()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id) THEN
  RAISE EXCEPTION 'PC-DATA-6004';
 END IF;
 IF TG_OP='INSERT' AND NEW.predecessor_command_id IS NULL THEN
  INSERT INTO control.deployment_address_claim
   (attempt_id,participant_id,privacy_domain_id,chain_id,genesis_digest,address,active)
   SELECT NEW.attempt_id,NEW.participant_id,NEW.privacy_domain_id,NEW.chain_id,NEW.genesis_digest,address,true
   FROM unnest(ARRAY[NEW.contract_address,NEW.helper_address]) claimed(address)
   WHERE address IS NOT NULL ORDER BY address;
 ELSIF NEW.state='EXPIRED' THEN
  UPDATE control.deployment_address_claim SET active=false
   WHERE attempt_id=NEW.attempt_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.sync_deployment_address_claims() FROM PUBLIC;
DROP TRIGGER IF EXISTS deployment_address_claim_sync ON control.deployment_address_reservation;
CREATE TRIGGER deployment_address_claim_sync AFTER INSERT OR UPDATE OF state ON control.deployment_address_reservation
 FOR EACH ROW EXECUTE FUNCTION openpc.sync_deployment_address_claims();


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


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1','native-value-authorization','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','NATIVE_VALUE_AUTHORIZATION'),
 ('ACT-NATIVE_VALUE_AUTHORIZATIONS_READ_RESOURCE-V1','native-value-authorization','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','NATIVE_VALUE_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1','native-value-authorization','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','NATIVE_VALUE_AUTHORIZATION'),
  ('ACT-NATIVE_VALUE_AUTHORIZATIONS_READ_RESOURCE-V1','native-value-authorization','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','NATIVE_VALUE_READ')))<>2 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-ACTION-REGISTRATION';
 END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_native_value_authorization()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE document jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 document:=convert_from(NEW.document_bytes,'UTF8')::jsonb;
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.creation_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1'
  OR jsonb_typeof(document)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(document))<>15
  OR convert_to(openpc.signing_canonical_json(document),'UTF8')<>NEW.document_bytes
  OR NEW.semantic_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(document-'semanticDigest'),'UTF8')),'hex')
  OR (document->>'authorizationId'='urn:openpc:resource:'||NEW.native_value_authorization_id::text
   AND document->>'participantId'=NEW.participant_id::text AND document->>'actorSubjectId'=NEW.actor_principal_id::text
   AND jsonb_typeof(document->'participantEpoch')='number' AND document->>'participantEpoch' ~ '^[1-9][0-9]{0,19}$'
   AND (document->>'participantEpoch')::numeric<=18446744073709551615
   AND document->>'purpose'='CONTRACT_CREATION_ENDOWMENT' AND document->'oneUse'='true'::jsonb AND document->'used'='false'::jsonb
   AND document->>'amountMode' IN ('EXACT','MAXIMUM') AND jsonb_typeof(document->'maxAmountWei')='string'
   AND document->>'maxAmountWei' ~ '^[1-9][0-9]{0,77}$'
   AND jsonb_typeof(document->'chainId')='string' AND document->>'chainId' ~ '^[1-9][0-9]{0,19}$'
   AND (document->>'chainId')::numeric<=18446744073709551615
   AND document->>'chainEnvironmentId' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
   AND document->>'genesisHash' ~ '^[0-9a-f]{64}$'
   AND document->>'policyDecisionDigest'=substring(NEW.creation_authority_digest,8)
   AND document->>'semanticDigest'=substring(NEW.semantic_digest,8)
   AND (document->>'validUntil')::timestamptz=NEW.valid_until) IS NOT TRUE THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-ISSUANCE';
 END IF;
 NEW.created_at:=date_trunc('milliseconds',clock_timestamp());
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS native_value_authorization_guard ON control.native_value_authorization;
CREATE TRIGGER native_value_authorization_guard BEFORE INSERT OR UPDATE OR DELETE ON control.native_value_authorization
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_native_value_authorization();

CREATE OR REPLACE FUNCTION openpc.require_native_value_issuance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE document jsonb:=convert_from(NEW.document_bytes,'UTF8')::jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  JOIN control.wallet_binding wallet ON wallet.participant_id=NEW.participant_id AND wallet.privacy_domain_id=NEW.privacy_domain_id
   AND wallet.wallet_binding_id=NEW.wallet_binding_id AND wallet.binding_epoch=NEW.wallet_binding_epoch
   AND wallet.subject_id=NEW.actor_principal_id AND wallet.state='ACTIVE' AND wallet.chain_id::text=document->>'chainId'
  JOIN control.participant participant ON participant.participant_id=NEW.participant_id
   AND participant.authority_epoch=(document->>'participantEpoch')::numeric
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.creation_operation_id AND evidence.aggregate_type='native-value-authorization'
   AND evidence.aggregate_id=NEW.native_value_authorization_id AND evidence.catalog_operation_id='CFG-OP-CREATE-NATIVE-VALUE-AUTHORIZATION'
   AND evidence.action_intent_id='ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1'
   AND NEW.creation_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.native_value_authorization_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND ((NEW.execution_workload_id IS NULL AND candidate.maker_principal_id=NEW.actor_principal_id)
    OR (NEW.execution_workload_id IS NOT NULL AND EXISTS(
     SELECT 1 FROM control.principal principal JOIN control.credential credential USING(participant_id,principal_id)
     WHERE principal.participant_id=NEW.participant_id AND principal.principal_id=NEW.actor_principal_id
      AND principal.kind='WORKLOAD' AND principal.state='ACTIVE' AND credential.kind='WORKLOAD_MTLS'
      AND credential.audience=NEW.execution_workload_id AND credential.state='ACTIVE'
      AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp())
     AND NOT EXISTS(SELECT 1 FROM control.principal other JOIN control.credential credential USING(participant_id,principal_id)
      WHERE other.participant_id=NEW.participant_id AND other.principal_id<>NEW.actor_principal_id
       AND other.kind='WORKLOAD' AND other.state='ACTIVE' AND credential.kind='WORKLOAD_MTLS'
       AND credential.audience=NEW.execution_workload_id AND credential.state='ACTIVE'
       AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp())))
   AND candidate.candidate_document->>'walletBindingId'='urn:openpc:resource:'||NEW.wallet_binding_id::text
   AND (candidate.candidate_document->>'executionWorkloadId') IS NOT DISTINCT FROM NEW.execution_workload_id
   AND candidate.candidate_document->>'chainId'=document->>'chainId'
   AND concat(candidate.candidate_document->>'chainId',':',candidate.candidate_document->>'networkId',':',candidate.candidate_document->>'genesisDigest')=document->>'chainEnvironmentId'
   AND candidate.candidate_document->>'genesisDigest'='sha256:'||(document->>'genesisHash')
   AND candidate.candidate_document->>'amountMode'=document->>'amountMode'
   AND candidate.candidate_document->>'maxAmountWei'=document->>'maxAmountWei'
   AND candidate.candidate_document->>'validUntil'=document->>'validUntil'
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.native_value_authorization_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.native_value_authorization_id
    AND event.aggregate_type='native-value-authorization' AND event.event_type='openpc.native-value.authorization.issued.v1')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS native_value_issuance ON control.native_value_authorization;
CREATE CONSTRAINT TRIGGER native_value_issuance AFTER INSERT ON control.native_value_authorization
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_native_value_issuance();

-- The reservation's global unique key is the one-use owner. Neither possession
-- of grant bytes nor a caller's used=false can replace this current-state fence.
-- The worker may read these scoped owners, but cannot UPDATE authority rows.
-- Keep provenance reads under its RLS; elevate only the row-lock operation.
DROP POLICY IF EXISTS native_value_locker_scope ON control.wallet_binding;
CREATE POLICY native_value_locker_scope ON control.wallet_binding FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND pg_trigger_depth()>0)
 WITH CHECK(false);
DROP POLICY IF EXISTS native_value_locker_scope ON control.principal;
CREATE POLICY native_value_locker_scope ON control.principal FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)
  AND openpc.current_action_intent_id()='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND pg_trigger_depth()>0)
 WITH CHECK(false);
DROP POLICY IF EXISTS native_value_locker_scope ON control.credential;
CREATE POLICY native_value_locker_scope ON control.credential FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)
  AND openpc.current_action_intent_id()='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND pg_trigger_depth()>0)
 WITH CHECK(false);
CREATE OR REPLACE FUNCTION openpc.lock_native_value_authority(wallet_id uuid,actor_id uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1' OR pg_trigger_depth()=0 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY';
 END IF;
 PERFORM 1 FROM control.wallet_binding wallet
 JOIN control.participant participant USING(participant_id)
 JOIN control.principal principal ON principal.participant_id=wallet.participant_id AND principal.principal_id=actor_id
 WHERE wallet.wallet_binding_id=wallet_id AND wallet.subject_id=actor_id
  AND openpc.matches_participant(wallet.participant_id) AND openpc.matches_privacy(wallet.privacy_domain_id)
 FOR SHARE OF wallet,participant,principal;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY'; END IF;
 PERFORM 1 FROM control.credential credential WHERE openpc.matches_participant(credential.participant_id)
  AND credential.principal_id=actor_id AND credential.kind='WORKLOAD_MTLS' FOR SHARE;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_native_value_authority(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_native_value_authority(uuid,uuid) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.fence_native_value_reservation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE admitted boolean:=false; wallet_id uuid; actor_id uuid;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY';
 END IF;
 IF NEW.native_value_authorization_id IS NULL AND NEW.native_value_authorization_digest IS NULL THEN RETURN NEW; END IF;
 IF TG_OP='UPDATE' AND NEW.state='EXPIRED' THEN RETURN NEW; END IF;
 SELECT wallet_binding_id,actor_principal_id INTO STRICT wallet_id,actor_id FROM control.native_value_authorization
 WHERE native_value_authorization_id=NEW.native_value_authorization_id;
 PERFORM openpc.lock_native_value_authority(wallet_id,actor_id);
 SELECT true INTO admitted FROM control.native_value_authorization issued_grant
 JOIN control.deployment_intent preparation ON preparation.participant_id=issued_grant.participant_id
  AND preparation.privacy_domain_id=issued_grant.privacy_domain_id AND preparation.preparation_digest=NEW.prepared_record_digest
  AND preparation.intent_digest=NEW.intent_digest AND preparation.wallet_binding_id=issued_grant.wallet_binding_id
  AND coalesce(preparation.execution_principal_id,preparation.actor_principal_id)=issued_grant.actor_principal_id
  AND preparation.execution_workload_id IS NOT DISTINCT FROM issued_grant.execution_workload_id
 JOIN control.mutation_candidate submission ON submission.participant_id=issued_grant.participant_id
  AND submission.privacy_domain_id=issued_grant.privacy_domain_id AND submission.resource_id=NEW.attempt_id
  AND submission.consumed_operation_id=NEW.command_id AND submission.maker_principal_id=preparation.actor_principal_id
  AND submission.state='CONSUMED' AND submission.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
  AND submission.action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND submission.candidate_document->>'deploymentIntentId'='urn:openpc:resource:'||preparation.deployment_intent_id::text
 JOIN control.idempotency_record receipt ON receipt.participant_id=submission.participant_id
  AND receipt.privacy_domain_id=submission.privacy_domain_id AND receipt.operation_id=submission.consumed_operation_id
  AND receipt.catalog_operation_id=submission.catalog_operation_id AND receipt.input_digest=submission.candidate_digest
  AND receipt.principal_id=submission.maker_principal_id AND receipt.terminal_state='COMMITTED'
 JOIN control.mutation_evidence evidence ON evidence.participant_id=submission.participant_id
  AND evidence.privacy_domain_id=submission.privacy_domain_id AND evidence.operation_id=submission.consumed_operation_id
  AND evidence.catalog_operation_id=submission.catalog_operation_id AND evidence.candidate_digest=submission.candidate_digest
  AND evidence.aggregate_id=submission.resource_id AND evidence.aggregate_type='deployment-submission'
 CROSS JOIN LATERAL (SELECT convert_from(preparation.preparation_bytes,'UTF8')::jsonb AS prepared,
  convert_from(issued_grant.document_bytes,'UTF8')::jsonb AS document) exact
 JOIN control.wallet_binding wallet ON wallet.participant_id=issued_grant.participant_id
  AND wallet.privacy_domain_id=issued_grant.privacy_domain_id AND wallet.wallet_binding_id=issued_grant.wallet_binding_id
  AND wallet.binding_epoch=issued_grant.wallet_binding_epoch AND wallet.subject_id=issued_grant.actor_principal_id
  AND wallet.state='ACTIVE' AND wallet.chain_id::text=NEW.chain_id AND wallet.wallet_address=NEW.sender_address
 JOIN control.participant participant ON participant.participant_id=issued_grant.participant_id
  AND participant.state='ACTIVE' AND participant.authority_epoch=(exact.document->>'participantEpoch')::numeric
 JOIN control.principal principal ON principal.participant_id=issued_grant.participant_id
  AND principal.principal_id=issued_grant.actor_principal_id AND principal.state='ACTIVE'
 WHERE issued_grant.native_value_authorization_id=NEW.native_value_authorization_id
  AND issued_grant.participant_id=NEW.participant_id AND issued_grant.privacy_domain_id=NEW.privacy_domain_id
  AND issued_grant.semantic_digest=NEW.native_value_authorization_digest
  AND issued_grant.valid_until>clock_timestamp() AND issued_grant.valid_until>=NEW.expires_at
  AND 'urn:openpc:resource:'||preparation.runtime_target_id::text=NEW.target_runtime_id AND preparation.expires_at>=NEW.expires_at
  AND exact.prepared->'context'->>'nativeValueAuthorizationBytes'='0x'||encode(issued_grant.document_bytes,'hex')
  AND exact.prepared->'context'->>'participantEpoch'=exact.document->>'participantEpoch'
  AND exact.prepared->'context'->>'walletBindingEpoch'=issued_grant.wallet_binding_epoch::text
  AND exact.prepared->'context'->>'chainEnvironmentId'=exact.document->>'chainEnvironmentId'
  AND exact.prepared->'intent'->>'nativeValueAuthorizationDigest'=substring(issued_grant.semantic_digest,8)
  AND exact.prepared->'intent'->>'chainId'=NEW.chain_id AND exact.document->>'chainId'=NEW.chain_id
  AND exact.document->>'genesisHash'=substring(NEW.genesis_digest,8)
  AND exact.prepared->'intent'->>'valueWei' ~ '^[1-9][0-9]{0,77}$'
  AND (exact.prepared->'intent'->>'valueWei')::numeric<2::numeric^256
  AND ((exact.document->>'amountMode'='EXACT' AND exact.document->>'maxAmountWei'=exact.prepared->'intent'->>'valueWei')
   OR (exact.document->>'amountMode'='MAXIMUM' AND (exact.prepared->'intent'->>'valueWei')::numeric<=(exact.document->>'maxAmountWei')::numeric))
  AND (issued_grant.execution_workload_id IS NULL OR EXISTS(SELECT 1 FROM control.credential credential
   WHERE credential.participant_id=principal.participant_id AND credential.principal_id=principal.principal_id
    AND principal.kind='WORKLOAD' AND credential.kind='WORKLOAD_MTLS' AND credential.audience=issued_grant.execution_workload_id
    AND credential.state='ACTIVE' AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp()));
 IF admitted IS DISTINCT FROM true THEN RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.fence_native_value_reservation() FROM PUBLIC;
DROP TRIGGER IF EXISTS native_value_reservation_fence ON control.deployment_address_reservation;
CREATE TRIGGER native_value_reservation_fence BEFORE INSERT OR UPDATE OF state ON control.deployment_address_reservation
 FOR EACH ROW EXECUTE FUNCTION openpc.fence_native_value_reservation();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1','cigl-settings','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_SETTINGS_PUBLICATION'),
 ('ACT-CIGL_SETTINGS_READ_RESOURCE-V1','cigl-settings','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_SETTINGS_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1','cigl-settings','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_SETTINGS_PUBLICATION'),
  ('ACT-CIGL_SETTINGS_READ_RESOURCE-V1','cigl-settings','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_SETTINGS_READ')))<>2 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-SETTINGS-ACTION';
 END IF;
END $$;
ALTER TABLE control.cigl_settings FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_settings()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1'
  OR NEW.definition_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.definition),'UTF8')),'hex') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-SETTINGS';
 END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_settings_guard ON control.cigl_settings;
CREATE TRIGGER cigl_settings_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_settings
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_settings();

CREATE OR REPLACE FUNCTION openpc.require_cigl_settings_publication()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.publication_operation_id AND evidence.aggregate_type='cigl-settings'
   AND evidence.aggregate_id=NEW.cigl_settings_id AND evidence.catalog_operation_id='CFG-OP-CREATE-CIGL-SETTINGS'
   AND evidence.action_intent_id='ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1'
   AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.cigl_settings_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND candidate.candidate_document->'definition'=NEW.definition
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.cigl_settings_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.cigl_settings_id
    AND event.aggregate_type='cigl-settings' AND event.event_type='openpc.cigl.settings.staged.v1')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-SETTINGS-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_settings_publication ON control.cigl_settings;
CREATE CONSTRAINT TRIGGER cigl_settings_publication AFTER INSERT ON control.cigl_settings
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_settings_publication();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-CIGL_GRANTS_CREATE_RESOURCE-V1','cigl-grant','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_GRANT_CREATE'),
 ('ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1','cigl-grant','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_GRANT_STATUS'),
 ('ACT-CIGL_GRANTS_READ_RESOURCE-V1','cigl-grant','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_GRANT_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-CIGL_GRANTS_CREATE_RESOURCE-V1','cigl-grant','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_GRANT_CREATE'),
  ('ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1','cigl-grant','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_GRANT_STATUS'),
  ('ACT-CIGL_GRANTS_READ_RESOURCE-V1','cigl-grant','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_GRANT_READ')))<>3 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT-ACTION';
 END IF;
END $$;
ALTER TABLE control.cigl_method_access_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE control.cigl_grant_history FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION openpc.cigl_subject_current(p_participant uuid,p_subject jsonb)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE kind text:=p_subject->>'kind'; id text:=p_subject->>'id';
BEGIN
 IF jsonb_typeof(p_subject) IS DISTINCT FROM 'object' OR (p_subject-ARRAY['kind','id']) IS DISTINCT FROM '{}'::jsonb
  OR jsonb_typeof(p_subject->'kind') IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 IF kind='ANY_AUTHENTICATED' THEN RETURN p_subject='{"kind":"ANY_AUTHENTICATED"}'::jsonb; END IF;
 IF jsonb_typeof(p_subject->'id') IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 IF kind IN ('ROLE','WORKLOAD') THEN
  IF (id ~ ('^urn:openpc:'||lower(kind)||':[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')) IS DISTINCT FROM true THEN RETURN false; END IF;
 ELSIF (id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') IS DISTINCT FROM true THEN RETURN false; END IF;
 CASE kind
 WHEN 'ANY_AUTHENTICATED' THEN RETURN p_subject='{"kind":"ANY_AUTHENTICATED"}'::jsonb;
 WHEN 'ROLE' THEN RETURN EXISTS(SELECT 1 FROM control.authority_role WHERE participant_id=p_participant AND role_id=id AND state='ACTIVE');
 WHEN 'WORKLOAD' THEN RETURN EXISTS(SELECT 1 FROM control.credential credential
  JOIN control.principal principal ON principal.participant_id=credential.participant_id AND principal.principal_id=credential.principal_id
  WHERE credential.participant_id=p_participant AND credential.audience=id AND credential.kind IN ('WORKLOAD_MTLS','WORKLOAD_OIDC')
   AND credential.state='ACTIVE' AND credential.valid_from<=clock_timestamp()
   AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp()) AND principal.kind='WORKLOAD' AND principal.state='ACTIVE');
 WHEN 'USER' THEN RETURN EXISTS(SELECT 1 FROM control.principal principal WHERE principal.participant_id=p_participant AND principal.principal_id=id::uuid AND principal.kind='USER' AND principal.state='ACTIVE');
 WHEN 'GROUP' THEN RETURN EXISTS(SELECT 1 FROM control.authority_group WHERE participant_id=p_participant AND authority_group_id=id::uuid AND state='ACTIVE');
 WHEN 'PARTICIPANT' THEN RETURN id=p_participant::text AND EXISTS(SELECT 1 FROM control.participant WHERE participant_id=p_participant AND state='ACTIVE' AND archived_at IS NULL);
 ELSE RETURN false;
 END CASE;
END $$;
REVOKE ALL ON FUNCTION openpc.cigl_subject_current(uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.cigl_subject_current(uuid,jsonb) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

-- Serialize a complete snapshot with all grant mutations, including inserts.
-- This scope-specific fence needs no grant-table write privilege at Fleet.
CREATE OR REPLACE FUNCTION openpc.lock_cigl_grant_sources()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 PERFORM pg_advisory_xact_lock(hashtextextended('openpc:cigl-grants:'||
  current_setting('openpc.participant_id')||':'||current_setting('openpc.privacy_domain_id'),0));
END $$;
REVOKE ALL ON FUNCTION openpc.lock_cigl_grant_sources() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_cigl_grant_sources() TO openpc_control_runtime,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_grant()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE canonical jsonb; bytes bytea;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT';
 END IF;
 PERFORM openpc.lock_cigl_grant_sources();
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR NOT (
   (NEW.origin='SHARED' AND current_setting('openpc.action_intent_id')='ACT-CIGL_GRANTS_CREATE_RESOURCE-V1' AND NEW.status='DISABLED')
   OR (NEW.origin='GENERATED' AND current_setting('openpc.action_intent_id')='ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1' AND NEW.status='ACTIVE'
     AND NEW.definition->>'effect'='ALLOW' AND EXISTS(SELECT 1 FROM control.cigl_method_access_grants source WHERE source.grant_id=NEW.generated_by_grant_id
      AND source.participant_id=NEW.participant_id AND source.privacy_domain_id=NEW.privacy_domain_id AND source.origin='SHARED'
      AND source.status='ACTIVE' AND source.publication_operation_id=NEW.publication_operation_id))) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT-CREATE'; END IF;
  NEW.created_at:=clock_timestamp();
 ELSE
  IF current_setting('openpc.action_intent_id')<>'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1'
   OR NEW.revision<>OLD.revision+1 OR (NEW.status=OLD.status AND NEW.status<>'ACTIVE')
   OR (OLD.origin='GENERATED' AND (OLD.status<>'ACTIVE' OR NEW.status<>'DISABLED'
     OR EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims WHERE required_grant_id=OLD.grant_id AND state='ACTIVE')
     OR NOT EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims WHERE required_grant_id=OLD.grant_id AND released_operation_id=NEW.publication_operation_id)))
   OR ROW(NEW.grant_id,NEW.participant_id,NEW.privacy_domain_id,NEW.runtime_binding_id,NEW.selector,NEW.definition,
      NEW.binding_revision,NEW.method_revision,NEW.created_at,NEW.origin,NEW.generated_by_grant_id)
    IS DISTINCT FROM ROW(OLD.grant_id,OLD.participant_id,OLD.privacy_domain_id,OLD.runtime_binding_id,OLD.selector,OLD.definition,
      OLD.binding_revision,OLD.method_revision,OLD.created_at,OLD.origin,OLD.generated_by_grant_id) THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-IMMUTABLE'; END IF;
 END IF;
 IF NEW.definition->>'runtimeBindingId' IS DISTINCT FROM 'urn:openpc:resource:'||NEW.runtime_binding_id::text
  OR NEW.definition->>'selector' IS DISTINCT FROM NEW.selector OR (NEW.definition->>'effect' IN ('ALLOW','DENY')) IS DISTINCT FROM true
  OR (NEW.definition->>'surface' IN ('ETH_CALL','ETH_ESTIMATE_GAS','PREPARE_WRITE','RAW_SUBMISSION','DEPLOYMENT_CONSTRUCTOR','RUNTIME_WRITE_TRACE')) IS DISTINCT FROM true
  OR (NEW.definition-ARRAY['runtimeBindingId','selector','subject','surface','effect']) IS DISTINCT FROM '{}'::jsonb
  OR NOT (NEW.definition ?& ARRAY['runtimeBindingId','selector','subject','surface','effect']) THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-DEFINITION'; END IF;
 IF TG_OP='INSERT' OR NEW.status='ACTIVE' THEN
  IF openpc.cigl_subject_current(NEW.participant_id,NEW.definition->'subject') IS DISTINCT FROM true
   OR NOT EXISTS(SELECT 1 FROM control.contract_runtime_binding binding JOIN control.contract_method_policy method
    ON method.participant_id=binding.participant_id AND method.privacy_domain_id=binding.privacy_domain_id AND method.runtime_binding_id=binding.runtime_binding_id
    WHERE binding.participant_id=NEW.participant_id AND binding.privacy_domain_id=NEW.privacy_domain_id
     AND binding.runtime_binding_id=NEW.runtime_binding_id AND binding.state='BOUND' AND binding.revision=NEW.binding_revision
     AND method.selector=NEW.selector AND method.revision=NEW.method_revision AND method.state IN ('PREPARED','ACTIVE')) THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-GRANT-REFERENCE'; END IF;
 END IF;
 bytes:=decode(substr(NEW.selector,3),'hex');
 canonical:=jsonb_build_object('grantId',NEW.grant_id::text,'runtimeBindingId',NEW.runtime_binding_id::text,
  'selector',jsonb_build_array(get_byte(bytes,0),get_byte(bytes,1),get_byte(bytes,2),get_byte(bytes,3)),
  'subject',NEW.definition->'subject','surface',NEW.definition->>'surface','effect',NEW.definition->>'effect','status',NEW.status);
 IF NEW.grant_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(canonical),'UTF8')),'hex') THEN
  RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-DIGEST'; END IF;
 NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_grant_guard ON control.cigl_method_access_grants;
CREATE TRIGGER cigl_grant_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_method_access_grants
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_grant();

CREATE OR REPLACE FUNCTION openpc.record_cigl_grant_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 INSERT INTO control.cigl_grant_history(grant_id,participant_id,privacy_domain_id,revision,status,grant_digest,
  publication_operation_id,publication_authority_digest) VALUES(NEW.grant_id,NEW.participant_id,NEW.privacy_domain_id,NEW.revision,NEW.status,
  NEW.grant_digest,NEW.publication_operation_id,NEW.publication_authority_digest);
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_grant_history_record ON control.cigl_method_access_grants;
CREATE TRIGGER cigl_grant_history_record AFTER INSERT OR UPDATE ON control.cigl_method_access_grants
 FOR EACH ROW EXECUTE FUNCTION openpc.record_cigl_grant_history();
CREATE OR REPLACE FUNCTION openpc.guard_cigl_grant_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-HISTORY'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants grant_row WHERE
  ROW(grant_row.grant_id,grant_row.participant_id,grant_row.privacy_domain_id,grant_row.revision,grant_row.status,grant_row.grant_digest,
   grant_row.publication_operation_id,grant_row.publication_authority_digest)
  =ROW(NEW.grant_id,NEW.participant_id,NEW.privacy_domain_id,NEW.revision,NEW.status,NEW.grant_digest,
   NEW.publication_operation_id,NEW.publication_authority_digest)) THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT-HISTORY'; END IF;
 NEW.occurred_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_grant_history_guard ON control.cigl_grant_history;
CREATE TRIGGER cigl_grant_history_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_grant_history
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_grant_history();

CREATE OR REPLACE FUNCTION openpc.require_cigl_grant_publication()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE operation text:=CASE WHEN NEW.revision=1 THEN 'CFG-OP-CREATE-CIGL-GRANT' ELSE 'CFG-OP-UPDATE-CIGL-GRANT' END;
BEGIN
 IF NEW.origin='GENERATED' THEN RETURN NULL; END IF; -- Exact derived ownership is checked by require_generated_cigl_grant.
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id AND receipt.privacy_domain_id=evidence.privacy_domain_id
   AND receipt.operation_id=evidence.operation_id AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id AND candidate.privacy_domain_id=evidence.privacy_domain_id
   AND candidate.consumed_operation_id=evidence.operation_id AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id AND evidence.operation_id=NEW.publication_operation_id
   AND evidence.aggregate_type='cigl-grant' AND evidence.aggregate_id=NEW.grant_id AND evidence.catalog_operation_id=operation
   AND evidence.aggregate_version=NEW.revision
   AND evidence.action_intent_id=CASE WHEN NEW.revision=1 THEN 'ACT-CIGL_GRANTS_CREATE_RESOURCE-V1' ELSE 'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1' END
   AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.grant_id AND candidate.state='CONSUMED' AND candidate.expected_revision=NEW.revision-1
   AND candidate.action_intent_id=evidence.action_intent_id AND receipt.action_intent_id=evidence.action_intent_id
   AND receipt.expected_aggregate_version=candidate.expected_revision
   AND ((NEW.revision=1 AND candidate.candidate_document->'definition'=NEW.definition
     AND candidate.candidate_document->>'expectedRuntimeBindingRevision'=NEW.binding_revision::text
     AND candidate.candidate_document->>'expectedMethodRevision'=NEW.method_revision::text)
    OR (NEW.revision>1 AND candidate.candidate_document->>'status'=NEW.status
      AND candidate.candidate_document->>'targetRef'='urn:openpc:resource:'||NEW.grant_id::text))
   AND receipt.terminal_state='COMMITTED' AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.grant_id::text
   AND receipt.result_payload->>'revision'=NEW.revision::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id AND event.privacy_domain_id=NEW.privacy_domain_id
     AND event.aggregate_id=NEW.grant_id AND event.aggregate_type='cigl-grant' AND event.aggregate_sequence=NEW.revision
     AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'=NEW.publication_authority_digest
     AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(candidate.candidate_digest,'hex')
     AND event.event_type=CASE WHEN NEW.revision=1 THEN 'openpc.cigl.grant.created.v1' ELSE 'openpc.cigl.grant.status.v1' END)) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_grant_publication ON control.cigl_method_access_grants;
CREATE CONSTRAINT TRIGGER cigl_grant_publication AFTER INSERT OR UPDATE ON control.cigl_method_access_grants
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_grant_publication();


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


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES('ACT-DEPLOYMENT_SUBMISSIONS_READ_RESOURCE-V1','deployment-submission','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_RESULT_READ') ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.action_intent WHERE action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_READ_RESOURCE-V1'
  AND resource_type='deployment-submission' AND operation_class='READ' AND risk_class='STANDARD'
  AND NOT maker_checker_required AND NOT step_up_required AND NOT idempotency_required
  AND existence_disclosure='AUTHORIZED_ONLY' AND payload_disclosure='REDACTED' AND evidence_class='DEPLOYMENT_RESULT_READ')
 THEN RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-READ-ACTION'; END IF;
END $$;
-- The migration owner is deliberately subject to Participant FORCE RLS.
-- This permits its association trigger to read/lock only the selected
-- Participant during result ingestion. It grants no runtime role access and
-- permits no Participant mutation, including through this definer.
DROP POLICY IF EXISTS deployment_association_owner_scope ON control.participant;
CREATE POLICY deployment_association_owner_scope ON control.participant FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)
  AND openpc.current_action_intent_id()='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND pg_trigger_depth()>0)
 WITH CHECK(false);
CREATE OR REPLACE FUNCTION openpc.deployment_flat_document(value jsonb)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT convert_to('{'||string_agg(to_jsonb(key)::text||':'||item::text,',' ORDER BY key COLLATE "C")||'}','UTF8')
 FROM jsonb_each(value) entry(key,item)
$$;
REVOKE ALL ON FUNCTION openpc.deployment_flat_document(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.deployment_flat_document(jsonb) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_deployment_result()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE reservation control.deployment_address_reservation%ROWTYPE; envelope jsonb; claims jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 envelope:=convert_from(NEW.signed_bytes,'UTF8')::jsonb; claims:=envelope->'claims';
 IF envelope->>'purpose'='openpc:deployment-reservation-rejection:v1' THEN
  PERFORM openpc.validate_deployment_rejection(NEW);
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT reservation FROM control.deployment_address_reservation
  WHERE command_id=NEW.command_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id FOR UPDATE;
 IF reservation.state<>'HANDOFF' OR envelope->>'purpose' IS DISTINCT FROM 'openpc:deployment-journal-projection:v1'
  OR claims->>'schema' IS DISTINCT FROM 'PC-DEPLOYMENT-JOURNAL-PROJECTION-1'
  OR claims->'owner'->>'participant_id' IS DISTINCT FROM NEW.participant_id::text
  OR claims->'owner'->>'privacy_domain_id' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR 'urn:openpc:resource:'||(claims->>'targetRuntimeId') IS DISTINCT FROM reservation.target_runtime_id
  OR claims->>'sequence' IS DISTINCT FROM NEW.sequence::text
  OR claims->>'intentDigest' IS DISTINCT FROM substring(reservation.intent_digest from 8)
  OR claims->>'preparationDigest' IS DISTINCT FROM substring(reservation.prepared_record_digest from 8)
  OR claims->>'chainId' IS DISTINCT FROM reservation.chain_id
  OR claims->>'genesisDigest' IS DISTINCT FROM substring(reservation.genesis_digest from 8)
  OR claims->'status'->>'operationId' IS DISTINCT FROM 'urn:openpc:operation:'||NEW.command_id::text
  OR claims->'status'->>'attemptId' IS DISTINCT FROM reservation.attempt_id::text
  OR claims->'status'->>'signedTransactionHash' IS DISTINCT FROM reservation.transaction_hash
  OR (claims->>'observedAt')::timestamptz>clock_timestamp()+interval '5 seconds'
  OR EXISTS(SELECT 1 FROM control.deployment_result result WHERE result.command_id=NEW.command_id AND result.sequence>=NEW.sequence)
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS deployment_result_guard ON control.deployment_result;
CREATE TRIGGER deployment_result_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deployment_result
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_result();

CREATE OR REPLACE FUNCTION openpc.project_deployment_association()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE claims jsonb; occurrence jsonb; invalidation jsonb; preparation jsonb;
 reservation control.deployment_address_reservation%ROWTYPE; participant control.participant%ROWTYPE;
 association control.contract_governance_association%ROWTYPE; document jsonb; encoded bytea; digest text;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id) THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 -- A Control rejection has no target occurrence and can never create or
 -- suspend an association. The result guard owns its separate proof above.
 IF convert_from(NEW.signed_bytes,'UTF8')::jsonb->>'purpose'='openpc:deployment-reservation-rejection:v1' THEN RETURN NEW; END IF;
 claims:=convert_from(NEW.signed_bytes,'UTF8')::jsonb->'claims';
 occurrence:=claims->'outcome'->'occurrence'; invalidation:=claims->'outcome'->'invalidation';
 SELECT * INTO STRICT reservation FROM control.deployment_address_reservation WHERE command_id=NEW.command_id;
 SELECT * INTO STRICT participant FROM control.participant WHERE participant_id=NEW.participant_id FOR SHARE;
 SELECT convert_from(intent.preparation_bytes,'UTF8')::jsonb INTO STRICT preparation FROM control.deployment_intent intent
  WHERE intent.participant_id=NEW.participant_id AND intent.privacy_domain_id=NEW.privacy_domain_id
   AND intent.preparation_digest=reservation.prepared_record_digest AND intent.intent_digest=reservation.intent_digest;
 SELECT * INTO association FROM control.contract_governance_association WHERE command_id=NEW.command_id FOR UPDATE;
 IF FOUND THEN
  document:=convert_from(association.document_bytes,'UTF8')::jsonb;
  IF association.state<>'ACTIVE' OR invalidation IS NULL OR invalidation='null'::jsonb
   OR invalidation->>'occurrenceId' IS DISTINCT FROM document->>'occurrenceId'
   OR invalidation->>'occurrenceDigest' IS DISTINCT FROM document->>'occurrenceDigest'
   OR invalidation->>'reason' NOT IN ('REORG','CODE_IDENTITY_MISMATCH')
   OR occurrence IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  document:=(document-'semanticDigest')||jsonb_build_object('state','SUSPENDED_REORG');
  digest:=encode(sha256(openpc.deployment_flat_document(document)),'hex');
  encoded:=openpc.deployment_flat_document(document||jsonb_build_object('semanticDigest',digest));
  UPDATE control.contract_governance_association SET state='SUSPENDED_REORG',current_sequence=NEW.sequence,
   document_bytes=encoded,semantic_digest='sha256:'||digest,updated_at=clock_timestamp() WHERE association_id=association.association_id;
 ELSIF occurrence IS NOT NULL AND occurrence<>'null'::jsonb THEN
  IF claims->'status'->>'state' IS DISTINCT FROM 'CONFIRMED' OR claims->'status'->>'truthState' IS DISTINCT FROM 'SUCCESS'
   OR occurrence->>'finality' IS DISTINCT FROM 'FINALIZED' OR occurrence->>'reorgStatus' IS DISTINCT FROM 'CANONICAL'
   OR occurrence->>'receiptStatus' IS DISTINCT FROM '1' OR occurrence->>'creationGraphComplete' IS DISTINCT FROM 'true'
   OR occurrence->>'runtimeCodePresent' IS DISTINCT FROM 'true' OR occurrence->>'internalNativeTransfers' IS DISTINCT FROM '0'
   OR invalidation IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  -- A retired/restored Participant cannot acquire new control from an older
  -- epoch's deployment. The effect remains truthful; association stays absent.
  IF participant.state<>'ACTIVE' OR participant.archived_at IS NOT NULL
   OR participant.authority_epoch::text IS DISTINCT FROM preparation->'context'->>'participantEpoch' THEN RETURN NEW; END IF;
  document:=jsonb_build_object('associationId',reservation.attempt_id::text,'occurrenceId',occurrence->>'occurrenceId',
   'occurrenceDigest',occurrence->>'semanticDigest','contractAddress',occurrence->>'derivedContractAddress',
   'chainEnvironmentId',claims->>'chainEnvironmentId','chainId',claims->>'chainId','genesisHash',claims->>'genesisDigest',
   'controllerParticipantId',NEW.participant_id::text,'controllerParticipantEpoch',participant.authority_epoch,
   'controllerGeneration',1,'state','ACTIVE','activatedAt',to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  digest:=encode(sha256(openpc.deployment_flat_document(document)),'hex');
  encoded:=openpc.deployment_flat_document(document||jsonb_build_object('semanticDigest',digest));
  INSERT INTO control.contract_governance_association(association_id,participant_id,privacy_domain_id,command_id,
   activation_sequence,current_sequence,participant_epoch,document_bytes,semantic_digest,state)
  VALUES(reservation.attempt_id,NEW.participant_id,NEW.privacy_domain_id,NEW.command_id,NEW.sequence,NEW.sequence,
   participant.authority_epoch,encoded,'sha256:'||digest,'ACTIVE');
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.project_deployment_association() FROM PUBLIC;
DROP TRIGGER IF EXISTS deployment_result_association ON control.deployment_result;
CREATE TRIGGER deployment_result_association AFTER INSERT ON control.deployment_result
 FOR EACH ROW EXECUTE FUNCTION openpc.project_deployment_association();


CREATE OR REPLACE FUNCTION openpc.runtime_configuration_bindings_current(
  p_participant uuid,p_privacy uuid,p_bindings jsonb
) RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control,openpc AS $$
 SELECT openpc.matches_participant(p_participant) AND openpc.matches_privacy(p_privacy)
   AND jsonb_typeof(p_bindings)='array' AND jsonb_array_length(p_bindings)>0
   AND NOT EXISTS (
     SELECT 1 FROM jsonb_array_elements(p_bindings) binding
     WHERE CASE binding->>'kind'
       WHEN 'ProviderProfile' THEN NOT EXISTS (
         SELECT 1 FROM control.provider_profile p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.provider_profile_id::text=binding->>'id'
           AND p.behavior_fingerprint=binding->>'digest' AND p.chain_id=binding->>'chainId' AND p.state<>'RETIRED')
       WHEN 'ClientIndexerProfile' THEN NOT EXISTS (
         SELECT 1 FROM control.indexer_profile p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.indexer_profile_id::text=binding->>'id'
           AND p.method_profile_digest=binding->>'digest' AND p.engine_version=binding->>'engineVersion' AND p.state<>'RETIRED')
       WHEN 'ProjectionPlan' THEN NOT EXISTS (
         SELECT 1 FROM control.projection_plan p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.projection_plan_id::text=binding->>'id'
           AND p.plan_digest=binding->>'digest' AND p.state<>'RETIRED')
       WHEN 'CiglSettings' THEN NOT EXISTS (
         SELECT 1 FROM control.cigl_settings p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.cigl_settings_id::text=binding->>'id')
       ELSE true END
   )
$$;
REVOKE ALL ON FUNCTION openpc.runtime_configuration_bindings_current(uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_configuration_bindings_current(uuid,uuid,jsonb)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_configuration_input()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control,openpc AS $$
BEGIN
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND
   (to_jsonb(NEW)-'selected') IS DISTINCT FROM (to_jsonb(OLD)-'selected')) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6004';
 END IF;
 IF NEW.selected AND (
   NOT openpc.runtime_configuration_bindings_current(NEW.participant_id,NEW.privacy_domain_id,NEW.resource_bindings)
   OR NOT EXISTS (
     SELECT 1 FROM control.module_configuration_generation c
       JOIN control.module_installation i ON i.module_installation_id=c.module_installation_id
       JOIN control.module_version v ON v.module_version_id=i.module_version_id
      WHERE c.generation_id=NEW.module_configuration_generation_id
        AND c.module_installation_id=NEW.module_installation_id
        AND c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
        AND i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id
        AND c.active AND i.state='ENABLED' AND i.lifecycle_operation_id IS NOT NULL
        AND v.module_id='pc.config.assets'
   )) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6007';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS runtime_configuration_input_guard ON control.runtime_configuration_input;
CREATE TRIGGER runtime_configuration_input_guard BEFORE INSERT OR UPDATE OR DELETE
 ON control.runtime_configuration_input FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_configuration_input();

-- A selected source is data only. Every consumer still needs its own approved
-- qualification/activation and this exact enabled module generation.
CREATE OR REPLACE VIEW control.runtime_configuration_input_current
 WITH (security_invoker=true) AS
 SELECT input.*,true AS active
 FROM control.runtime_configuration_input input
 JOIN control.module_configuration_generation c
   ON c.generation_id=input.module_configuration_generation_id
  AND c.module_installation_id=input.module_installation_id
  AND c.participant_id=input.participant_id AND c.privacy_domain_id=input.privacy_domain_id
 JOIN control.module_installation i ON i.module_installation_id=c.module_installation_id
  AND i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id
 JOIN control.module_version v ON v.module_version_id=i.module_version_id
 WHERE input.selected AND c.active AND i.state='ENABLED'
   AND i.lifecycle_operation_id IS NOT NULL AND v.module_id='pc.config.assets'
   AND openpc.runtime_configuration_bindings_current(input.participant_id,input.privacy_domain_id,input.resource_bindings);
REVOKE ALL ON control.runtime_configuration_input_current FROM PUBLIC;
GRANT SELECT ON control.runtime_configuration_input_current
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;


DROP POLICY IF EXISTS indexer_source_read_fence ON control.runtime_target;
CREATE POLICY indexer_source_read_fence ON control.runtime_target FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1');
DROP POLICY IF EXISTS indexer_source_read_fence ON control.runtime_configuration_generation;
CREATE POLICY indexer_source_read_fence ON control.runtime_configuration_generation FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1');
DROP POLICY IF EXISTS indexer_source_read_fence ON control.configuration_work;
CREATE POLICY indexer_source_read_fence ON control.configuration_work FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1');
DROP POLICY IF EXISTS indexer_source_read_fence ON control.projection_plan;
CREATE POLICY indexer_source_read_fence ON control.projection_plan FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1');
DROP POLICY IF EXISTS indexer_source_read_fence ON control.indexer_profile;
CREATE POLICY indexer_source_read_fence ON control.indexer_profile FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1');
DROP POLICY IF EXISTS indexer_source_read_fence ON control.provider_profile;
CREATE POLICY indexer_source_read_fence ON control.provider_profile FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1');
DROP POLICY IF EXISTS indexer_source_read_fence ON control.provider_probe_observation;
CREATE POLICY indexer_source_read_fence ON control.provider_probe_observation FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1');
DROP POLICY IF EXISTS indexer_source_read_fence ON control.runtime_configuration_input;
CREATE POLICY indexer_source_read_fence ON control.runtime_configuration_input FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1');
DROP POLICY IF EXISTS indexer_source_read_fence ON control.runtime_activation_observation;
CREATE POLICY indexer_source_read_fence ON control.runtime_activation_observation FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1');
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.runtime_target;
CREATE POLICY indexer_source_lock_fence ON control.runtime_target FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1') WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.runtime_configuration_generation;
CREATE POLICY indexer_source_lock_fence ON control.runtime_configuration_generation FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1') WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.configuration_work;
CREATE POLICY indexer_source_lock_fence ON control.configuration_work FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1') WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.projection_plan;
CREATE POLICY indexer_source_lock_fence ON control.projection_plan FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1') WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.indexer_profile;
CREATE POLICY indexer_source_lock_fence ON control.indexer_profile FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1') WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.provider_profile;
CREATE POLICY indexer_source_lock_fence ON control.provider_profile FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1') WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.provider_probe_observation;
CREATE POLICY indexer_source_lock_fence ON control.provider_probe_observation FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1') WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.runtime_configuration_input;
CREATE POLICY indexer_source_lock_fence ON control.runtime_configuration_input FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-RUNTIME_READ_RPC-V1') WITH CHECK(false);
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

REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_configuration_input", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."cigl_analysis", "control"."cigl_method_profile", "control"."cigl_profile_version", "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source", "control"."cigl_profile_dependency_path", "control"."cigl_method_grant_dependency_claims", "control"."deployment_result", "control"."contract_governance_association" FROM PUBLIC;
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_configuration_input", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."cigl_analysis", "control"."cigl_method_profile", "control"."cigl_profile_version", "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source", "control"."cigl_profile_dependency_path", "control"."cigl_method_grant_dependency_claims", "control"."deployment_result", "control"."contract_governance_association" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."deployment_policy", "control"."deployment_intent" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_activation_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."provider_probe_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_route_publication" TO "openpc_control_runtime";
GRANT SELECT ON "control"."deployment_address_reservation" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."native_value_authorization" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_settings" TO "openpc_control_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_method_access_grants" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_grant_history" TO "openpc_control_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_analysis" TO "openpc_control_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_method_profile" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_profile_version" TO "openpc_control_runtime";
GRANT SELECT ON "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source" TO "openpc_control_runtime";
GRANT UPDATE ON "control"."cigl_profile_version" TO "openpc_control_worker";
GRANT INSERT ON "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source" TO "openpc_control_worker";
GRANT SELECT ON "control"."cigl_profile_dependency_path" TO "openpc_control_runtime";
GRANT INSERT ON "control"."cigl_profile_dependency_path" TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_method_grant_dependency_claims" TO "openpc_control_runtime";
GRANT SELECT ON "control"."deployment_result", "control"."contract_governance_association" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_configuration_input" TO "openpc_control_runtime";
GRANT INSERT ON "control"."runtime_configuration_input" TO "openpc_control_worker";
GRANT UPDATE (selected) ON "control"."runtime_configuration_input" TO "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_configuration_input", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."cigl_analysis", "control"."cigl_method_profile", "control"."cigl_profile_version", "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source", "control"."cigl_profile_dependency_path", "control"."cigl_method_grant_dependency_claims", "control"."deployment_result", "control"."contract_governance_association" TO "openpc_control_worker";
GRANT UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."deployment_policy", "control"."deployment_intent" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_route_publication" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."provider_probe_observation" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."deployment_address_reservation" TO "openpc_control_worker";
GRANT INSERT ON "control"."deployment_result" TO "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_configuration_input", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."cigl_analysis", "control"."cigl_method_profile", "control"."cigl_profile_version", "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source", "control"."cigl_profile_dependency_path", "control"."cigl_method_grant_dependency_claims", "control"."deployment_result", "control"."contract_governance_association" TO "openpc_control_reader";
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
