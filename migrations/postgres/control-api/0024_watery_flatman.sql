CREATE TABLE "control"."cigl_grant_history" (
	"grant_id" uuid NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"revision" numeric(20, 0) NOT NULL,
	"status" text NOT NULL,
	"grant_digest" text NOT NULL,
	"publication_operation_id" uuid NOT NULL,
	"publication_authority_digest" text NOT NULL,
	"occurred_at" timestamp(3) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "cigl_grant_history_revision_uq" UNIQUE("participant_id","privacy_domain_id","grant_id","revision")
);
--> statement-breakpoint
ALTER TABLE "control"."cigl_grant_history" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."cigl_method_access_grants" (
	"grant_id" uuid PRIMARY KEY NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"runtime_binding_id" uuid NOT NULL,
	"selector" text NOT NULL,
	"binding_revision" numeric(20, 0) NOT NULL,
	"method_revision" numeric(20, 0) NOT NULL,
	"definition" jsonb NOT NULL,
	"status" text DEFAULT 'DISABLED' NOT NULL,
	"revision" numeric(20, 0) DEFAULT 1 NOT NULL,
	"grant_digest" text NOT NULL,
	"publication_operation_id" uuid NOT NULL,
	"publication_authority_digest" text NOT NULL,
	"created_at" timestamp(3) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(3) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "cigl_grant_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","grant_id"),
	CONSTRAINT "cigl_grant_status_ck" CHECK ("control"."cigl_method_access_grants"."status" in ('ACTIVE','DISABLED')),
	CONSTRAINT "cigl_grant_revision_ck" CHECK ("control"."cigl_method_access_grants"."revision">0 and "control"."cigl_method_access_grants"."revision"<=18446744073709551615),
	CONSTRAINT "cigl_grant_source_revision_ck" CHECK ("control"."cigl_method_access_grants"."binding_revision">0 and "control"."cigl_method_access_grants"."binding_revision"<=18446744073709551615 and "control"."cigl_method_access_grants"."method_revision">0 and "control"."cigl_method_access_grants"."method_revision"<=18446744073709551615),
	CONSTRAINT "cigl_grant_selector_ck" CHECK ("control"."cigl_method_access_grants"."selector" ~ '^0x[0-9a-f]{8}$'),
	CONSTRAINT "cigl_grant_digest_ck" CHECK ("control"."cigl_method_access_grants"."grant_digest" ~ '^sha256:[0-9a-f]{64}$' and "control"."cigl_method_access_grants"."publication_authority_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "cigl_grant_definition_ck" CHECK (jsonb_typeof("control"."cigl_method_access_grants"."definition")='object')
);
--> statement-breakpoint
ALTER TABLE "control"."cigl_method_access_grants" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."cigl_grant_history" ADD CONSTRAINT "cigl_grant_history_owner_fk" FOREIGN KEY ("participant_id","privacy_domain_id","grant_id") REFERENCES "control"."cigl_method_access_grants"("participant_id","privacy_domain_id","grant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."cigl_method_access_grants" ADD CONSTRAINT "cigl_grant_binding_fk" FOREIGN KEY ("participant_id","privacy_domain_id","runtime_binding_id") REFERENCES "control"."contract_runtime_binding"("participant_id","privacy_domain_id","runtime_binding_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."cigl_grant_history" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."cigl_grant_history"."participant_id")) WITH CHECK (openpc.matches_participant("control"."cigl_grant_history"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."cigl_grant_history" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."cigl_grant_history"."participant_id") and openpc.matches_privacy("control"."cigl_grant_history"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."cigl_grant_history"."participant_id") and openpc.matches_privacy("control"."cigl_grant_history"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."cigl_method_access_grants" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."cigl_method_access_grants"."participant_id")) WITH CHECK (openpc.matches_participant("control"."cigl_method_access_grants"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."cigl_method_access_grants" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."cigl_method_access_grants"."participant_id") and openpc.matches_privacy("control"."cigl_method_access_grants"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."cigl_method_access_grants"."participant_id") and openpc.matches_privacy("control"."cigl_method_access_grants"."privacy_domain_id"));
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
  OR NOT coalesce(claims->>'reason' IN ('CUSTODY_CONFLICT','PREPARATION_EXPIRED'),false)
  OR NOT coalesce(claims->'binding'->>'transactionHash' ~ '^0x[0-9a-f]{64}$',false)
  OR EXISTS(SELECT 1 FROM control.deployment_address_reservation WHERE command_id=result.command_id)
  OR EXISTS(SELECT 1 FROM control.deployment_result prior WHERE prior.command_id=result.command_id)
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
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
 WHERE claimed.address IS NOT NULL
 ON CONFLICT (attempt_id,address) DO NOTHING;

CREATE OR REPLACE FUNCTION openpc.sync_deployment_address_claims()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id) THEN
  RAISE EXCEPTION 'PC-DATA-6004';
 END IF;
 IF TG_OP='INSERT' THEN
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
 WHEN 'USER' THEN RETURN EXISTS(SELECT 1 FROM control.principal WHERE participant_id=p_participant AND principal_id=id::uuid AND kind='USER' AND state='ACTIVE');
 WHEN 'GROUP' THEN RETURN EXISTS(SELECT 1 FROM control.authority_group WHERE participant_id=p_participant AND authority_group_id=id::uuid AND state='ACTIVE');
 WHEN 'PARTICIPANT' THEN RETURN id=p_participant::text AND EXISTS(SELECT 1 FROM control.participant WHERE participant_id=p_participant AND state='ACTIVE' AND archived_at IS NULL);
 ELSE RETURN false;
 END CASE;
END $$;
REVOKE ALL ON FUNCTION openpc.cigl_subject_current(uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.cigl_subject_current(uuid,jsonb) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

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
 IF TG_OP='INSERT' THEN
  IF current_setting('openpc.action_intent_id')<>'ACT-CIGL_GRANTS_CREATE_RESOURCE-V1' OR NEW.revision<>1 OR NEW.status<>'DISABLED' THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT-CREATE'; END IF;
  NEW.created_at:=clock_timestamp();
 ELSE
  IF current_setting('openpc.action_intent_id')<>'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1'
   OR NEW.revision<>OLD.revision+1 OR NEW.status=OLD.status
   OR ROW(NEW.grant_id,NEW.participant_id,NEW.privacy_domain_id,NEW.runtime_binding_id,NEW.selector,NEW.definition,
      NEW.binding_revision,NEW.method_revision,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.grant_id,OLD.participant_id,OLD.privacy_domain_id,OLD.runtime_binding_id,OLD.selector,OLD.definition,
      OLD.binding_revision,OLD.method_revision,OLD.created_at) THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-IMMUTABLE'; END IF;
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

REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."deployment_result", "control"."contract_governance_association" FROM PUBLIC;
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."deployment_result", "control"."contract_governance_association" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."deployment_policy", "control"."deployment_intent" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_activation_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."provider_probe_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_route_publication" TO "openpc_control_runtime";
GRANT SELECT ON "control"."deployment_address_reservation" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."native_value_authorization" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_settings" TO "openpc_control_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_method_access_grants" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_grant_history" TO "openpc_control_runtime";
GRANT SELECT ON "control"."deployment_result", "control"."contract_governance_association" TO "openpc_control_runtime";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."deployment_result", "control"."contract_governance_association" TO "openpc_control_worker";
GRANT UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."deployment_policy", "control"."deployment_intent" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_route_publication" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."provider_probe_observation" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."deployment_address_reservation" TO "openpc_control_worker";
GRANT INSERT ON "control"."deployment_result" TO "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."deployment_result", "control"."contract_governance_association" TO "openpc_control_reader";
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
