/** Generated wallet association custody; binding alone never grants invocation authority. */
export const walletBindingGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_wallet_binding_transition()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-RETAINED'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'ACTIVE' OR NEW.binding_epoch<>1 OR NEW.row_version<>1 THEN
   RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-INITIAL-STATE';
  END IF;
 ELSE
  IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR NEW.binding_epoch<>OLD.binding_epoch+1
   OR NEW.row_version<>OLD.row_version+1 OR NEW.last_operation_id=OLD.last_operation_id
   OR (to_jsonb(NEW)-ARRAY['state','binding_epoch','row_version','last_operation_id','updated_at'])
      IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','binding_epoch','row_version','last_operation_id','updated_at']) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-TRANSITION';
  END IF;
 END IF;
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.last_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' THEN
  RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-CONTEXT';
 END IF;
 IF TG_OP='INSERT' AND NOT EXISTS(SELECT 1 FROM control.principal subject JOIN control.participant participant USING(participant_id)
  JOIN control.privacy_domain privacy ON privacy.participant_id=subject.participant_id AND privacy.privacy_domain_id=NEW.privacy_domain_id
  WHERE subject.participant_id=NEW.participant_id AND subject.principal_id=NEW.subject_id
    AND subject.kind IN ('USER','WALLET','WORKLOAD') AND subject.state='ACTIVE'
    AND participant.state='ACTIVE' AND participant.archived_at IS NULL AND privacy.state='ACTIVE') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-SUBJECT';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS wallet_binding_transition ON control.wallet_binding;
CREATE TRIGGER wallet_binding_transition BEFORE INSERT OR UPDATE OR DELETE ON control.wallet_binding
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_wallet_binding_transition();

CREATE OR REPLACE FUNCTION openpc.require_wallet_binding_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE mutation text:=CASE WHEN TG_OP='INSERT' THEN 'CREATE' ELSE 'REVOKE' END;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.last_operation_id AND evidence.aggregate_type='wallet-binding'
   AND evidence.aggregate_id=NEW.wallet_binding_id AND evidence.catalog_operation_id='ID-OP-WALLET-BINDING-'||mutation
   AND evidence.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   AND candidate.resource_id=NEW.wallet_binding_id AND candidate.state='CONSUMED'
   AND candidate.expected_revision=NEW.row_version-1
   AND candidate.candidate_document->>'walletBindingId'=NEW.wallet_binding_id::text
   AND (CASE WHEN mutation='CREATE' THEN
    candidate.candidate_document->>'participantId'=NEW.participant_id::text
    AND candidate.candidate_document->>'subjectId'=NEW.subject_id::text
    AND candidate.candidate_document->>'chainId'=NEW.chain_id::text
    AND candidate.candidate_document->>'walletAddress'=NEW.wallet_address
    ELSE candidate.candidate_document->>'state'='REVOKED' END)
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'walletBindingId'=NEW.wallet_binding_id::text
   AND receipt.result_payload->>'participantId'=NEW.participant_id::text
   AND receipt.result_payload->>'privacyDomainId'=NEW.privacy_domain_id::text
   AND receipt.result_payload->>'subjectId'=NEW.subject_id::text
   AND receipt.result_payload->>'chainId'=NEW.chain_id::text
   AND receipt.result_payload->>'walletAddress'=NEW.wallet_address
   AND receipt.result_payload->>'operationId'=NEW.last_operation_id::text
   AND receipt.result_payload->>'state'=NEW.state
   AND receipt.result_payload->>'bindingEpoch'=NEW.binding_epoch::text
   AND receipt.result_payload->>'revision'=NEW.row_version::text
   AND receipt.result_payload->>'permissionEffect'='NONE_WITHOUT_EFFECTIVE_AUTHORITY') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS wallet_binding_mutation_provenance ON control.wallet_binding;
CREATE CONSTRAINT TRIGGER wallet_binding_mutation_provenance AFTER INSERT OR UPDATE ON control.wallet_binding
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_wallet_binding_mutation();
`;
