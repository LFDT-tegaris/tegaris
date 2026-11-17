export const deploymentReservationGuardsSql = `
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
     AND prior.transaction_hash<>NEW.transaction_hash FOR UPDATE OF prior;
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
`;
