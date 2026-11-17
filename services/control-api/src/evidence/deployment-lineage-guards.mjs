/** SQL independently binds the minimized projection to the original catalogue,
 * signed source bytes and reservation. Purpose cryptography remains in the
 * source owner, before the dedicated custody worker can insert this row. */
export const deploymentLineageGuardsSql = `
ALTER TABLE control.evidence_deployment_lineage FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_deployment_lineage FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_deployment_lineage TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.evidence_deployment_lineage TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.evidence_deployment_lineage_projection(source control.evidence_catalogue)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE r record; claims jsonb; occurrence jsonb; invalidation jsonb; historical jsonb;
BEGIN
 IF (source).evidence_class<>'EFFECT' OR (source).source_format<>'PC-DEPLOYMENT-JOURNAL-PROJECTION-1'
  OR (source).record_id!~'^deployment:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:[1-9][0-9]{0,19}$' THEN RETURN NULL; END IF;
 SELECT d.signed_bytes,d.result_digest,d.sequence,a.* INTO r
  FROM control.deployment_result d JOIN control.deployment_address_reservation a
   ON a.participant_id=d.participant_id AND a.privacy_domain_id=d.privacy_domain_id AND a.command_id=d.command_id
  WHERE d.participant_id=(source).participant_id AND d.privacy_domain_id=(source).privacy_domain_id
   AND d.command_id=split_part((source).record_id,':',2)::uuid AND d.sequence=split_part((source).record_id,':',3)::numeric
   AND d.result_digest=(source).receipt_digest AND d.result_digest='sha256:'||encode(sha256(d.signed_bytes),'hex')
   AND a.state='HANDOFF';
 IF NOT FOUND THEN RETURN NULL; END IF;
 claims:=convert_from(r.signed_bytes,'UTF8')::jsonb;
 IF claims->>'purpose' IS DISTINCT FROM 'openpc:deployment-journal-projection:v1' THEN RETURN NULL; END IF;
 claims:=claims->'claims';
 IF claims->>'schema' IS DISTINCT FROM (source).source_format
  OR claims->>'sequence' IS DISTINCT FROM r.sequence::text
  OR (regexp_replace(claims->>'observedAt','([.][0-9]{6})[0-9]+',chr(92)||'1'))::timestamptz IS DISTINCT FROM (source).occurred_at
  OR claims->'owner'->>'participant_id' IS DISTINCT FROM (source).participant_id::text
  OR claims->'owner'->>'privacy_domain_id' IS DISTINCT FROM (source).privacy_domain_id::text
  OR claims->'status'->>'operationId' IS DISTINCT FROM 'urn:openpc:operation:'||r.command_id::text
  OR claims->'status'->>'attemptId' IS DISTINCT FROM r.attempt_id::text
  OR claims->>'targetRuntimeId' IS DISTINCT FROM replace(r.target_runtime_id,'urn:openpc:resource:','')
  OR claims->>'intentDigest' IS DISTINCT FROM substring(r.intent_digest from 8)
  OR claims->>'preparationDigest' IS DISTINCT FROM substring(r.prepared_record_digest from 8)
  OR claims->>'chainId' IS DISTINCT FROM r.chain_id
  OR claims->>'genesisDigest' IS DISTINCT FROM substring(r.genesis_digest from 8)
  OR claims->'status'->>'signedTransactionHash' IS DISTINCT FROM r.transaction_hash THEN RETURN NULL; END IF;
 occurrence:=claims->'outcome'->'occurrence'; invalidation:=claims->'outcome'->'invalidation';
 historical:=jsonb_build_object('sourceVersion',r.sequence::text,'receiptDigest',r.result_digest,
  'observedAt',claims->>'observedAt','state',claims->'status'->>'state','truthState',claims->'status'->>'truthState',
  'journalEvidenceDigest',claims->'status'->>'evidenceDigest',
  'finality',CASE WHEN invalidation<>'null'::jsonb THEN CASE WHEN invalidation->>'reason'='REORG' THEN 'REORG' ELSE 'INVALIDATED' END
    WHEN occurrence<>'null'::jsonb THEN 'FINALIZED' ELSE 'NOT_ESTABLISHED' END,
  'occurrence',CASE WHEN occurrence='null'::jsonb THEN 'null'::jsonb ELSE jsonb_build_object(
   'occurrenceId',occurrence->>'occurrenceId','occurrenceDigest','sha256:'||(occurrence->>'semanticDigest'),
   'blockHash','sha256:'||(occurrence->>'blockHash'),'blockNumber',occurrence->>'blockNumber','reorgStatus',occurrence->>'reorgStatus') END,
  'invalidation',CASE WHEN invalidation='null'::jsonb THEN 'null'::jsonb ELSE jsonb_build_object(
   'occurrenceId',invalidation->>'occurrenceId','occurrenceDigest','sha256:'||(invalidation->>'occurrenceDigest'),
   'observationDigest','sha256:'||(invalidation->>'observationDigest'),'reason',invalidation->>'reason') END);
 RETURN jsonb_build_object('chainId',r.chain_id,'genesisDigest',r.genesis_digest,'historical',historical);
EXCEPTION WHEN insufficient_privilege OR invalid_text_representation OR datetime_field_overflow THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_deployment_lineage_projection(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deployment_lineage_projection(control.evidence_catalogue) TO openpc_control_worker,openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_deployment_lineage()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT openpc.evidence_deployment_lineage_projection(c) INTO expected FROM control.evidence_catalogue c
  WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.stream_id=NEW.stream_id AND c.record_id=NEW.record_id;
 IF expected IS NULL OR NEW.projection IS DISTINCT FROM expected
  OR NEW.projection_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_deployment_lineage_guard ON control.evidence_deployment_lineage;
CREATE TRIGGER evidence_deployment_lineage_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_deployment_lineage
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_deployment_lineage();
`;
