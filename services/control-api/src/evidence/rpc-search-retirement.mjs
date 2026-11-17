/** Search retirement consumes the original, independently governed normalized
 * retirement proof. It neither reconstructs RPC JSON nor re-executes RPC work. */
export const rpcSearchRetirementSql = `
CREATE OR REPLACE FUNCTION openpc.rpc_retired_catalogue_proof(source control.evidence_catalogue)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE proof jsonb;
BEGIN
 IF (source).evidence_class<>'EFFECT' OR (source).source_format<>'OPENPC_RPC_DECISION_TRANSITION_V1' THEN RETURN NULL; END IF;
 SELECT jsonb_build_object('recordId',e.evidence_record_id::text,'recordDigest','sha256:'||encode(sha256(a.cose_sign1),'hex'),
  'recordedAtNs',a.recorded_at_ns::text,'sourceEvidenceId','urn:openpc:resource:'||(source).evidence_id::text,
  'sourceRecordId',(source).record_id,'sourceReceiptDigest',(source).receipt_digest,'retirementDigest',r.retirement_digest,
  'sourceFormat',e.evidence_format,'deletionJobId',j.deletion_job_id::text,'operationId',j.operation_id::text,
  'sourceKind',j.selection->>'sourceKind','identityDigest',j.selection->'rpcClosure'->>'identityDigest') INTO STRICT proof
 FROM control.evidence_projection_retirement r
 JOIN control.deletion_job j USING(participant_id,privacy_domain_id,deletion_job_id)
 JOIN control.audit_occurrence a ON a.participant_id=j.participant_id AND a.privacy_domain_id=j.privacy_domain_id
  AND a.operation_id=j.operation_id AND a.aggregate_id=j.deletion_job_id AND a.aggregate_type='evidence-deletion'
 JOIN control.evidence_record e ON e.participant_id=a.participant_id AND e.privacy_domain_id=a.privacy_domain_id
  AND e.receipt_id=a.receipt_id AND e.receipt_digest=a.receipt_digest AND e.evidence_role='BUSINESS_TRANSITION_RECEIPT' AND e.custody='CONTROL_STORE'
 JOIN control.mutation_candidate candidate ON candidate.participant_id=j.participant_id AND candidate.privacy_domain_id=j.privacy_domain_id
  AND candidate.resource_id=j.deletion_job_id AND candidate.consumed_operation_id=j.operation_id AND candidate.candidate_digest=a.candidate_digest
 WHERE r.participant_id=(source).participant_id AND r.privacy_domain_id=(source).privacy_domain_id
  AND r.evidence_id=(source).evidence_id AND r.stream_id=(source).stream_id AND r.record_id=(source).record_id
  AND r.segment_id=(source).segment_id AND r.sequence=(source).sequence AND r.source_receipt_digest=(source).receipt_digest
  AND r.data_class='NORMALIZED_JSON_PROJECTION' AND r.retirement_digest=openpc.projection_retirement_digest(r)
  AND j.state='SUCCEEDED' AND j.revision=1 AND j.target_data_class='NORMALIZED_JSON_PROJECTION'
  AND ((j.selection->>'sourceKind'='RPC_CLOSED_TRANSITION'
    AND j.selection->'rpcClosure'->>'identityDigest' ~ '^sha256:[0-9a-f]{64}$')
   OR (j.selection->>'sourceKind'='RPC_PRE_ADMISSION_DENIAL' AND NOT j.selection ? 'rpcClosure'))
  AND openpc.projection_deletion_effect_matches(j,r)
  AND candidate.state='CONSUMED' AND candidate.candidate_document->'selection'=j.selection
  AND candidate.candidate_document->>'beforeDigest'=j.before_digest
  AND a.profile_id='pc.control.evidence-deletion.projection' AND a.profile_version=1
  AND a.action_intent_id='ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1' AND a.catalog_operation_id='CFG-OP-DELETE-PROJECTION-BATCH'
  AND a.before_existence=0 AND a.before_revision=0 AND a.after_existence=1 AND a.after_revision=1
  AND openpc.business_cbor(a.after_state_preimage)->8=openpc.evidence_deletion_state_projection(j)
  AND sha256(a.receipt_cbor)=a.receipt_digest AND sha256(a.after_state_preimage)=a.after_state_digest;
 RETURN proof;
EXCEPTION WHEN insufficient_privilege OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.rpc_retired_catalogue_proof(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.rpc_retired_catalogue_proof(control.evidence_catalogue) TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.rpc_retired_catalogue_has_references(source control.evidence_catalogue)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE proof jsonb;
BEGIN
 proof:=openpc.rpc_retired_catalogue_proof(source);
 IF proof IS NULL THEN RETURN true; END IF;
 -- A pre-admission denial had no admitted request or terminal successor. Its
 -- governed normalized-retirement owner already verified that exact phase and
 -- null request/response. Do not fabricate a closed-transition identity/witness.
 -- Preserve any still-live exact projection; the common search owner separately
 -- checks custody, export, protected-object and catalogue references.
 IF proof->>'sourceKind'='RPC_PRE_ADMISSION_DENIAL' THEN
  RETURN EXISTS(SELECT 1 FROM control.evidence_rpc_provenance sibling
   WHERE sibling.participant_id=(source).participant_id AND sibling.privacy_domain_id=(source).privacy_domain_id
    AND sibling.stream_id=(source).stream_id AND sibling.record_id=(source).record_id);
 END IF;
 RETURN EXISTS(SELECT 1 FROM control.evidence_rpc_provenance sibling WHERE sibling.participant_id=(source).participant_id
  AND sibling.privacy_domain_id=(source).privacy_domain_id AND sibling.stream_id=(source).stream_id
  AND openpc.rpc_retirement_identity(sibling.projection)=proof->>'identityDigest');
EXCEPTION WHEN insufficient_privilege THEN RETURN true;
END $$;
REVOKE ALL ON FUNCTION openpc.rpc_retired_catalogue_has_references(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.rpc_retired_catalogue_has_references(control.evidence_catalogue) TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.rpc_local_payload_retirements(stream text,segment uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE source control.evidence_catalogue; proof jsonb; proofs jsonb:='[]'::jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 FOR source IN SELECT c.* FROM control.evidence_catalogue c
  WHERE c.participant_id=current_setting('openpc.participant_id')::uuid AND c.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
   AND c.stream_id=stream AND c.segment_id=segment AND c.evidence_class='EFFECT' AND c.source_format='OPENPC_RPC_DECISION_TRANSITION_V1'
  ORDER BY c.record_id
 LOOP
  proof:=openpc.rpc_retired_catalogue_proof(source);
  IF proof IS NULL OR openpc.rpc_retired_catalogue_has_references(source) THEN RETURN NULL; END IF;
  proofs:=proofs||jsonb_build_array(jsonb_build_object('evidenceId',proof->>'sourceEvidenceId',
   'recordId',proof->>'sourceRecordId','sourceReceiptDigest',proof->>'sourceReceiptDigest',
   'retirementJobId','urn:openpc:resource:'||(proof->>'deletionJobId'),
   'retirementReceiptDigest',proof->>'recordDigest','retirementDigest',proof->>'retirementDigest'));
 END LOOP;
 RETURN proofs;
END $$;
REVOKE ALL ON FUNCTION openpc.rpc_local_payload_retirements(text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.rpc_local_payload_retirements(text,uuid) TO openpc_control_runtime;
`;
