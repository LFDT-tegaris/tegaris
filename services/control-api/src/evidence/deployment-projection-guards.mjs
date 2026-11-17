/** The verified custody producer materializes the operator observation. This is
 * neither the immutable signed result nor the historical preservation anchor. */
export const deploymentProjectionGuardsSql = `
ALTER TABLE control.evidence_deployment_provenance FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_deployment_provenance FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_deployment_provenance TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT INSERT ON control.evidence_deployment_provenance TO openpc_control_worker;
-- PostgreSQL requires UPDATE on at least one column for FOR SHARE. This
-- immutable key is sufficient for locking; the existing reservation guard
-- rejects key changes and no state/effect column is granted to the reader.
GRANT UPDATE(command_id) ON control.deployment_address_reservation TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.evidence_deployment_projection(source control.evidence_catalogue)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE lineage jsonb; r record;
BEGIN
 lineage:=openpc.evidence_deployment_lineage_projection(source);
 IF lineage IS NULL THEN RETURN NULL; END IF;
 SELECT a.*,i.deployment_intent_id,i.execution_principal_id,i.execution_workload_id INTO r
 FROM control.deployment_address_reservation a JOIN control.deployment_intent i
  ON i.participant_id=a.participant_id AND i.privacy_domain_id=a.privacy_domain_id
   AND i.preparation_digest=a.prepared_record_digest AND i.intent_digest=a.intent_digest
   AND 'urn:openpc:resource:'||i.runtime_target_id::text=a.target_runtime_id
 WHERE a.participant_id=(source).participant_id AND a.privacy_domain_id=(source).privacy_domain_id
  AND a.command_id=split_part((source).record_id,':',2)::uuid AND a.state='HANDOFF';
 IF NOT FOUND THEN RETURN NULL; END IF;
 RETURN jsonb_build_object('integrity','VERIFIED_PURPOSE_SIGNATURE','authority','OBSERVATION_ONLY',
  'operationId','urn:openpc:operation:'||r.command_id::text,'attemptId',r.attempt_id::text,
  'deploymentIntentId','urn:openpc:resource:'||r.deployment_intent_id::text,'targetRuntimeId',r.target_runtime_id,
  'executionPrincipalId',r.execution_principal_id::text,'workloadId',r.execution_workload_id,
  'intentDigest',r.intent_digest,'preparationDigest',r.prepared_record_digest,
  'chainId',r.chain_id,'genesisDigest',r.genesis_digest,'transactionHash',r.transaction_hash,
  'historical',lineage->'historical');
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_deployment_projection(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deployment_projection(control.evidence_catalogue)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_deployment_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE source control.evidence_catalogue; expected jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT source FROM control.evidence_catalogue WHERE participant_id=OLD.participant_id
   AND privacy_domain_id=OLD.privacy_domain_id AND stream_id=OLD.stream_id AND record_id=OLD.record_id;
  PERFORM openpc.record_projection_deletion(source,'NORMALIZED_JSON_PROJECTION',OLD.projection);RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF EXISTS(SELECT 1 FROM control.evidence_projection_retirement r WHERE r.participant_id=NEW.participant_id
  AND r.privacy_domain_id=NEW.privacy_domain_id AND r.stream_id=NEW.stream_id AND r.record_id=NEW.record_id
  AND r.data_class='NORMALIZED_JSON_PROJECTION') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT source FROM control.evidence_catalogue WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND record_id=NEW.record_id;
 expected:=openpc.evidence_deployment_projection(source);
 IF expected IS NULL OR NEW.projection IS DISTINCT FROM expected
  OR NEW.projection_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_deployment_provenance_guard ON control.evidence_deployment_provenance;
CREATE TRIGGER evidence_deployment_provenance_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_deployment_provenance
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_deployment_provenance();

-- The real result writer locks this same reservation FOR UPDATE before every
-- new observation, including reorg. Hold its shared row lock through deletion,
-- receipt/outbox and commit; historical age never supplies current closure.
CREATE OR REPLACE FUNCTION openpc.deployment_projection_retirement_blockers(source control.evidence_catalogue,p jsonb)
RETURNS text[] LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE reservation control.deployment_address_reservation; latest control.deployment_result;
 claims jsonb; occurrence jsonb; blockers text[]:=ARRAY[]::text[];
BEGIN
 IF current_setting('openpc.action_intent_id')='ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1' THEN
  SELECT * INTO reservation FROM control.deployment_address_reservation r
  WHERE r.participant_id=(source).participant_id AND r.privacy_domain_id=(source).privacy_domain_id
   AND r.command_id=split_part((source).record_id,':',2)::uuid FOR SHARE;
 ELSE
  SELECT * INTO reservation FROM control.deployment_address_reservation r
  WHERE r.participant_id=(source).participant_id AND r.privacy_domain_id=(source).privacy_domain_id
   AND r.command_id=split_part((source).record_id,':',2)::uuid;
 END IF;
 IF NOT FOUND OR reservation.state<>'HANDOFF' THEN RETURN ARRAY['UNRESOLVED_OPERATION']; END IF;
 SELECT * INTO latest FROM control.deployment_result r WHERE r.participant_id=reservation.participant_id
  AND r.privacy_domain_id=reservation.privacy_domain_id AND r.command_id=reservation.command_id
 ORDER BY r.sequence DESC LIMIT 1;
 IF NOT FOUND THEN RETURN ARRAY['UNRESOLVED_OPERATION']; END IF;
 claims:=convert_from(latest.signed_bytes,'UTF8')::jsonb->'claims'; occurrence:=claims->'outcome'->'occurrence';
 IF claims->'outcome'->'invalidation' IS DISTINCT FROM 'null'::jsonb
  OR claims->'status'->>'state'='REORG' OR p->'historical'->>'finality' IN ('REORG','INVALIDATED')
 THEN blockers:=array_append(blockers,'REORG_FENCED'); END IF;
 IF claims->'status'->>'state' IS DISTINCT FROM 'CONFIRMED'
  OR claims->'status'->>'truthState' IS DISTINCT FROM 'SUCCESS'
  OR occurrence->>'finality' IS DISTINCT FROM 'FINALIZED'
  OR occurrence->>'reorgStatus' IS DISTINCT FROM 'CANONICAL'
  OR occurrence->>'receiptStatus' IS DISTINCT FROM '1'
  OR occurrence->>'creationGraphComplete' IS DISTINCT FROM 'true'
  OR occurrence->>'runtimeCodePresent' IS DISTINCT FROM 'true'
  OR occurrence->>'internalNativeTransfers' IS DISTINCT FROM '0'
  OR p->'historical'->>'state' IS DISTINCT FROM 'CONFIRMED'
  OR p->'historical'->>'truthState' IS DISTINCT FROM 'SUCCESS'
  OR p->'historical'->>'finality' IS DISTINCT FROM 'FINALIZED'
 THEN blockers:=array_append(blockers,'UNRESOLVED_OPERATION'); END IF;
 IF latest.sequence::text IS DISTINCT FROM p->'historical'->>'sourceVersion'
  OR latest.result_digest IS DISTINCT FROM (source).receipt_digest
  OR latest.result_digest IS DISTINCT FROM 'sha256:'||encode(sha256(latest.signed_bytes),'hex')
  OR p IS DISTINCT FROM openpc.evidence_deployment_projection(source)
  OR EXISTS(SELECT 1 FROM control.deployment_address_reservation successor
   WHERE successor.participant_id=reservation.participant_id AND successor.privacy_domain_id=reservation.privacy_domain_id
    AND successor.predecessor_command_id=reservation.command_id)
 THEN blockers:=array_append(blockers,'REFERENCES'); END IF;
 RETURN blockers;
END $$;
REVOKE ALL ON FUNCTION openpc.deployment_projection_retirement_blockers(control.evidence_catalogue,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.deployment_projection_retirement_blockers(control.evidence_catalogue,jsonb) TO openpc_control_runtime;
`;
