/** Exact committed pre-handoff sources. Crypto verification is shared with
 * deployment readback; this SQL independently binds actual rows and fences.
 */
export const evidenceDeletionSourcesSql = `
GRANT EXECUTE ON FUNCTION openpc.lock_deployment_command(uuid) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.evidence_deletion_rejections(stream text,segment uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.evidence_catalogue; source record; claims jsonb; command uuid; proofs jsonb:='[]'::jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 -- Lock order: evidence lifecycle, then unique command UUIDs in lexical order.
 -- Reservation, handoff and terminal rejection already use this command fence.
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||current_setting('openpc.participant_id'),0));
 IF EXISTS(SELECT 1 FROM control.evidence_catalogue c
  WHERE c.participant_id=current_setting('openpc.participant_id')::uuid
   AND c.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
   AND c.stream_id=stream AND c.segment_id=segment
   AND c.evidence_class NOT IN ('AUTHENTICATION','BUSINESS_TRANSITION','EFFECT'))
 THEN RETURN NULL; END IF;
 FOR item IN SELECT c.* FROM control.evidence_catalogue c
  WHERE c.participant_id=current_setting('openpc.participant_id')::uuid
   AND c.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
   AND c.stream_id=stream AND c.segment_id=segment AND c.evidence_class='EFFECT'
  ORDER BY c.record_id,c.evidence_id
 LOOP
  IF item.source_format='OPENPC_RPC_DECISION_TRANSITION_V1' THEN
   -- The separately typed RPC proof list is mandatory in the selection. Never
   -- convert a completed read or a retirement receipt into a no-send rejection.
   IF openpc.rpc_retired_catalogue_proof(item) IS NULL OR openpc.rpc_retired_catalogue_has_references(item) THEN RETURN NULL; END IF;
   CONTINUE;
  END IF;
  IF item.source_format<>'PC-DEPLOYMENT-RESERVATION-REJECTION-1'
   OR item.record_id!~'^deployment:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:1$'
  THEN RETURN NULL; END IF;
  command:=split_part(item.record_id,':',2)::uuid;
  PERFORM openpc.lock_deployment_command(command);
  SELECT *,count(*) OVER() source_count INTO source
   FROM openpc.deployment_rejection_source(command,item.participant_id,item.privacy_domain_id);
  IF NOT FOUND OR source.source_count<>1 OR source.result_digest<>item.receipt_digest
   OR source.result_digest<>'sha256:'||encode(sha256(source.signed_bytes),'hex') THEN RETURN NULL; END IF;
  claims:=convert_from(source.signed_bytes,'UTF8')::jsonb;
  IF claims->>'purpose' IS DISTINCT FROM 'openpc:deployment-reservation-rejection:v1'
   OR claims->'claims'->>'schema' IS DISTINCT FROM item.source_format
   OR claims->'claims'->'binding'->>'commandId' IS DISTINCT FROM command::text
   OR claims->'claims'->'binding'->>'attemptId' IS DISTINCT FROM source.attempt_id
   OR claims->'claims'->'binding'->'owner'->>'participant_id' IS DISTINCT FROM item.participant_id::text
   OR claims->'claims'->'binding'->'owner'->>'privacy_domain_id' IS DISTINCT FROM item.privacy_domain_id::text
   OR claims->'claims'->>'candidateDigest' IS DISTINCT FROM source.candidate_digest
   OR claims->'claims'->>'authorizationEvidenceDigest' IS DISTINCT FROM source.evidence_digest
   OR NOT coalesce(claims->'claims'->>'reason' IN ('CUSTODY_CONFLICT','PREPARATION_EXPIRED','MODULE_GENERATION_UNAVAILABLE'),false)
  THEN RETURN NULL; END IF;
  proofs:=proofs||jsonb_build_array(jsonb_build_object(
   'evidenceId','urn:openpc:resource:'||item.evidence_id::text,'commandId',command::text,
   'attemptId',source.attempt_id,'receiptDigest',source.result_digest,
   'candidateDigest','sha256:'||source.candidate_digest,'authorizationEvidenceDigest','sha256:'||source.evidence_digest,
   'externalAttemptState','NOT_STARTED','sourceFormat',item.source_format));
 END LOOP;
 RETURN proofs;
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_rejections(text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_rejections(text,uuid) TO openpc_control_runtime;
`;
