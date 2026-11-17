export const rpcProvenanceGuardsSql = `
ALTER TABLE control.evidence_rpc_provenance FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_rpc_provenance FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_rpc_provenance TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.evidence_rpc_provenance TO openpc_control_worker;
CREATE OR REPLACE FUNCTION openpc.guard_rpc_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb:=NEW.projection; a jsonb:=p->'activation'; t jsonb:=p->'transition'; deleted_source control.evidence_catalogue;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT deleted_source FROM control.evidence_catalogue WHERE participant_id=OLD.participant_id AND privacy_domain_id=OLD.privacy_domain_id
   AND stream_id=OLD.stream_id AND record_id=OLD.record_id;
  PERFORM openpc.record_projection_deletion(deleted_source,'NORMALIZED_JSON_PROJECTION',OLD.projection);RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 IF EXISTS(SELECT 1 FROM control.evidence_projection_retirement r WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
  AND r.data_class='NORMALIZED_JSON_PROJECTION' AND r.stream_id=NEW.stream_id AND r.record_id=NEW.record_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF p-ARRAY['integrity','activationIntegrity','authority','currentAuthority','providerEffect','chainFinality',
  'decisionId','targetRuntimeId','spoolId','sourceSequence','sourceDigest','capsuleDigest','reservedAtNs','occurredAtNs','transition','activation']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(p))<>16
  OR a-ARRAY['operationId','attemptId','configurationWorkId','generationId','generationDigest','receiptDigest','signerId','verificationKeyDigest']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(a))<>8
  OR t-ARRAY['phase','traceId','requestDigest','decisionDigest','responseDigest','authorityBindingDigest','sourceScopeDigest','operationId',
   'pcCode','decisionEffect','boundary','sourceSegmentId','sourceRecordDigest','admittedAtNs']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(t))<>14
  OR p->>'integrity' IS DISTINCT FROM 'AEAD_CHAIN_VERIFIED_AT_CUSTODY'
  OR p->>'activationIntegrity' IS DISTINCT FROM 'ACTIVATION_COSE_VERIFIED_AT_CUSTODY'
  OR p->>'authority' IS DISTINCT FROM 'NONE' OR p->>'currentAuthority' IS DISTINCT FROM 'NOT_ESTABLISHED'
  OR p->>'providerEffect' IS DISTINCT FROM 'NOT_ESTABLISHED' OR p->>'chainFinality' IS DISTINCT FROM 'NOT_ESTABLISHED'
  OR NEW.projection_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex')
  OR NEW.record_id<>'rpc:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_array(p->>'targetRuntimeId',p->>'spoolId')),'UTF8')),'hex')||':'||(p->>'sourceSequence')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.evidence_catalogue c WHERE c.participant_id=NEW.participant_id
  AND c.privacy_domain_id=NEW.privacy_domain_id AND c.stream_id=NEW.stream_id AND c.record_id=NEW.record_id
  AND c.evidence_class='EFFECT' AND c.source_format='OPENPC_RPC_DECISION_TRANSITION_V1'
  AND c.receipt_digest=p->>'sourceDigest' AND c.sequence::text=p->>'sourceSequence'
  AND extract(epoch FROM c.occurred_at)*1000000=floor((p->>'occurredAtNs')::numeric/1000)) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.runtime_activation_observation o JOIN control.configuration_work w
  ON w.participant_id=o.participant_id AND w.privacy_domain_id=o.privacy_domain_id AND w.configuration_work_id=o.configuration_work_id
   AND w.runtime_target_id=o.runtime_target_id AND w.runtime_configuration_generation_id=o.runtime_configuration_generation_id
   AND w.operation_id=o.operation_id AND w.execution_attempt_id=o.execution_attempt_id AND w.generation_digest=o.generation_digest AND w.state='COMPLETED'
  WHERE o.participant_id=NEW.participant_id AND o.privacy_domain_id=NEW.privacy_domain_id
   AND o.runtime_target_id::text=p->>'targetRuntimeId' AND o.capsule_digest=p->>'capsuleDigest'
   AND o.operation_id::text=a->>'operationId' AND o.execution_attempt_id::text=a->>'attemptId'
   AND o.configuration_work_id::text=a->>'configurationWorkId' AND o.runtime_configuration_generation_id::text=a->>'generationId'
   AND o.generation_digest=a->>'generationDigest'
   AND 'sha256:'||encode(sha256(decode(o.activation_receipt->>'activationReceiptCoseHex','hex')),'hex')=a->>'receiptDigest') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_rpc_provenance_guard ON control.evidence_rpc_provenance;
CREATE TRIGGER evidence_rpc_provenance_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_rpc_provenance
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_rpc_provenance();
`;
