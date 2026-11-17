/** Reuse immutable source owners. Unsupported or inaccessible lineage is
 * unknown, never an empty set of references or a deletion eligibility claim. */
export const evidenceHoldSourcesSql = `
CREATE OR REPLACE FUNCTION openpc.retention_policy_receipt_hold_metadata(source control.evidence_catalogue)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF (source).evidence_class<>'BUSINESS_TRANSITION' THEN RETURN NULL; END IF;
  -- A retention policy governs a class and references only its own policy,
  -- approval and operation identities. It does not name a Fact, projection,
  -- block or runtime generation. This statement is specific to these two
  -- admitted profiles; other business families retain UNKNOWN lineage.
  IF EXISTS(SELECT 1 FROM control.evidence_record e
   JOIN control.audit_occurrence a ON a.participant_id=e.participant_id AND a.privacy_domain_id=e.privacy_domain_id
    AND a.receipt_id=e.receipt_id AND a.receipt_digest=e.receipt_digest
   JOIN control.idempotency_record i ON i.participant_id=a.participant_id AND i.privacy_domain_id=a.privacy_domain_id
    AND i.idempotency_record_id=a.idempotency_record_id AND i.operation_id=a.operation_id
   JOIN control.retention_policy p ON p.participant_id=a.participant_id AND p.privacy_domain_id=a.privacy_domain_id
    AND p.retention_policy_id=a.aggregate_id
   WHERE e.participant_id=(source).participant_id AND e.privacy_domain_id=(source).privacy_domain_id
    AND e.evidence_record_id::text=(source).record_id AND e.evidence_role='BUSINESS_TRANSITION_RECEIPT'
    AND e.custody='CONTROL_STORE' AND e.evidence_format=(source).source_format
    AND (source).receipt_digest='sha256:'||encode(sha256(a.cose_sign1),'hex')
    AND a.receipt_digest=sha256(a.receipt_cbor)
    AND floor(a.recorded_at_ns/1000)=extract(epoch FROM (source).occurred_at)*1000000
    AND a.aggregate_type='retention-policy' AND a.profile_version=1
    AND ((a.profile_id='pc.control.retention-policy.activate' AND a.catalog_operation_id='CFG-OP-ACTIVATE-RETENTION-POLICY'
      AND a.action_intent_id='ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1' AND a.operation_id=p.activation_operation_id)
     OR (a.profile_id='pc.control.retention-policy.retire' AND a.catalog_operation_id='CFG-OP-RETIRE-RETENTION-POLICY'
      AND a.action_intent_id='ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1' AND a.operation_id=p.retirement_operation_id))
    AND i.terminal_state='COMMITTED' AND i.input_digest=a.candidate_digest
    AND i.action_intent_id=a.action_intent_id AND i.catalog_operation_id=a.catalog_operation_id
    AND sha256(a.before_state_preimage)=a.before_state_digest AND sha256(a.after_state_preimage)=a.after_state_digest
    AND sha256(a.authority_snapshot)=a.pre_commit_authority_digest) THEN
   RETURN jsonb_build_object('projections','[]'::jsonb,'facts','[]'::jsonb,'blocks','[]'::jsonb,
    'generations',jsonb_build_object('RUNTIME_CONFIGURATION','[]'::jsonb,'CANONICAL_FACT','[]'::jsonb));
  END IF;
 RETURN NULL;
EXCEPTION WHEN insufficient_privilege OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.retention_policy_receipt_hold_metadata(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.retention_policy_receipt_hold_metadata(control.evidence_catalogue) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.evidence_hold_record_metadata(source control.evidence_catalogue)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE metadata jsonb; binding record; occurrence jsonb; invalidation jsonb;
BEGIN
 IF (source).source_format='OPENPC_AUTHENTICATION_OCCURRENCE_V1' THEN
  IF EXISTS(SELECT 1 FROM control.authentication_occurrence a WHERE a.participant_id=(source).participant_id
   AND a.privacy_domain_id=(source).privacy_domain_id AND a.occurrence_id::text=(source).record_id
   AND (source).receipt_digest='sha256:'||encode(a.receipt_digest,'hex') AND a.receipt_digest=sha256(a.receipt)
   AND a.occurred_at=(source).occurred_at) THEN
   RETURN jsonb_build_object('projections','[]'::jsonb,'facts','[]'::jsonb,'blocks','[]'::jsonb,'generations',jsonb_build_object('RUNTIME_CONFIGURATION','[]'::jsonb,'CANONICAL_FACT','[]'::jsonb));
  END IF;
 ELSIF (source).evidence_class='BUSINESS_TRANSITION' THEN
  RETURN openpc.retention_policy_receipt_hold_metadata(source);
 ELSIF (source).source_format='OPENPC_CANONICAL_FACT_V1' THEN
  RETURN openpc.evidence_fact_hold_metadata(source);
 ELSIF (source).source_format IN ('OPENPC_CANDIDATE_PROJECTION_CHUNK_V1','OPENPC_CANDIDATE_PROJECTION_MANIFEST_V1') THEN
  RETURN openpc.candidate_archive_hold_metadata(source);
 ELSIF (source).source_format IN ('OPENPC_RUNTIME_ARTIFACT_CHUNK_V1','OPENPC_RUNTIME_ARTIFACT_MANIFEST_V1') THEN
  RETURN openpc.runtime_artifact_archive_hold_metadata(source);
 ELSIF (source).source_format='PC-DEPLOYMENT-JOURNAL-PROJECTION-1' THEN
  SELECT p.projection INTO metadata FROM control.evidence_deployment_lineage p
   WHERE p.participant_id=(source).participant_id AND p.privacy_domain_id=(source).privacy_domain_id
    AND p.stream_id=(source).stream_id AND p.record_id=(source).record_id
    AND (source).evidence_class='EFFECT'
    AND p.projection=openpc.evidence_deployment_lineage_projection(source)
    AND p.projection->'historical'->>'receiptDigest'=(source).receipt_digest
    AND p.projection_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p.projection),'UTF8')),'hex');
  IF NOT FOUND THEN RETURN NULL; END IF;
  occurrence:=metadata->'historical'->'occurrence';
  invalidation:=metadata->'historical'->'invalidation';
  IF invalidation<>'null'::jsonb THEN
   -- A reorg invalidates authority, not the preservation duty for its original
   -- block. Require one exact, previously verified occurrence reference.
   SELECT p.projection->'historical'->'occurrence' INTO STRICT occurrence
    FROM control.evidence_deployment_lineage p
    WHERE p.participant_id=(source).participant_id AND p.privacy_domain_id=(source).privacy_domain_id
     AND p.stream_id=(source).stream_id AND split_part(p.record_id,':',2)=split_part((source).record_id,':',2)
     AND (p.projection->'historical'->>'sourceVersion')::numeric<(metadata->'historical'->>'sourceVersion')::numeric
     AND p.projection->>'chainId'=metadata->>'chainId' AND p.projection->>'genesisDigest'=metadata->>'genesisDigest'
     AND p.projection->'historical'->'occurrence'->>'occurrenceId'=invalidation->>'occurrenceId'
     AND p.projection->'historical'->'occurrence'->>'occurrenceDigest'=invalidation->>'occurrenceDigest'
     AND p.projection_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p.projection),'UTF8')),'hex')
    GROUP BY p.projection->'historical'->'occurrence';
   IF NOT FOUND THEN RETURN NULL; END IF;
  END IF;
  IF occurrence IS NULL OR occurrence='null'::jsonb THEN RETURN NULL; END IF;
  RETURN jsonb_build_object('blocks',jsonb_build_array(jsonb_build_object('chainId',metadata->>'chainId',
   'genesisDigest',metadata->>'genesisDigest','blockNumber',occurrence->>'blockNumber')));
 ELSIF (source).source_format='OPENPC_RPC_DECISION_TRANSITION_V1' THEN
  SELECT r.preservation_metadata INTO metadata FROM control.evidence_projection_retirement r
   JOIN control.deletion_job j USING(participant_id,privacy_domain_id,deletion_job_id)
   WHERE r.participant_id=(source).participant_id AND r.privacy_domain_id=(source).privacy_domain_id
    AND r.evidence_id=(source).evidence_id AND r.stream_id=(source).stream_id AND r.record_id=(source).record_id
    AND r.data_class='NORMALIZED_JSON_PROJECTION' AND r.source_receipt_digest=(source).receipt_digest
    AND r.retirement_digest=openpc.projection_retirement_digest(r) AND j.state='SUCCEEDED';
  IF FOUND THEN RETURN metadata; END IF;
  SELECT p.projection,g.projection_plan_id,g.runtime_configuration_generation_id INTO binding
   FROM control.evidence_rpc_provenance p JOIN control.runtime_configuration_generation g
    ON g.participant_id=p.participant_id AND g.privacy_domain_id=p.privacy_domain_id
     AND g.runtime_configuration_generation_id::text=p.projection->'activation'->>'generationId'
     AND g.generation_digest=p.projection->'activation'->>'generationDigest'
   WHERE p.participant_id=(source).participant_id AND p.privacy_domain_id=(source).privacy_domain_id
    AND p.stream_id=(source).stream_id AND p.record_id=(source).record_id
    AND (source).evidence_class='EFFECT' AND p.projection->>'sourceDigest'=(source).receipt_digest
    AND p.projection->>'sourceSequence'=(source).sequence::text
    AND extract(epoch FROM (source).occurred_at)*1000000=floor((p.projection->>'occurredAtNs')::numeric/1000)
    AND p.projection_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p.projection),'UTF8')),'hex');
  IF FOUND THEN
   RETURN jsonb_build_object('projections',jsonb_build_array('urn:openpc:resource:'||binding.projection_plan_id::text),
    'generations',jsonb_build_object('RUNTIME_CONFIGURATION',jsonb_build_array(jsonb_build_object('kind','RUNTIME_CONFIGURATION',
      'generationId','urn:openpc:resource:'||binding.runtime_configuration_generation_id::text))));
  END IF;
 END IF;
 RETURN NULL;
EXCEPTION WHEN insufficient_privilege OR no_data_found OR too_many_rows THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_record_metadata(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_record_metadata(control.evidence_catalogue) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.evidence_hold_match_state(selector jsonb,participant uuid,privacy uuid,stream text,segment uuid)
RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE WHEN bool_or(matched) THEN 'MATCH' WHEN count(*)=0 OR bool_or(matched IS NULL) THEN 'UNKNOWN' ELSE 'NON_MATCH' END
 FROM (SELECT CASE selector->>'type'
  WHEN 'PARTICIPANT' THEN true WHEN 'PRIVACY_DOMAIN' THEN true
  WHEN 'SEQUENCE_RANGE' THEN selector->>'streamId'=c.stream_id AND c.sequence>=(selector->>'fromSequence')::numeric
   AND (selector->'throughSequence'='null'::jsonb OR c.sequence<=(selector->>'throughSequence')::numeric)
  WHEN 'DIGEST' THEN selector->>'recordDigest'=c.receipt_digest
  ELSE openpc.evidence_hold_source_match(selector,openpc.evidence_hold_record_metadata(c)) END matched
  FROM control.evidence_catalogue c WHERE c.participant_id=participant AND c.privacy_domain_id=privacy
   AND c.stream_id=stream AND c.segment_id=segment
  UNION ALL SELECT CASE selector->>'type'
   WHEN 'PARTICIPANT' THEN true WHEN 'PRIVACY_DOMAIN' THEN true
   WHEN 'SEQUENCE_RANGE' THEN selector->>'streamId'=r.stream_id AND r.sequence>=(selector->>'fromSequence')::numeric
    AND (selector->'throughSequence'='null'::jsonb OR r.sequence<=(selector->>'throughSequence')::numeric)
   WHEN 'DIGEST' THEN selector->>'recordDigest'=r.source_receipt_digest
   ELSE openpc.evidence_hold_source_match(selector,r.preservation_metadata) END
  FROM control.evidence_projection_retirement r JOIN control.deletion_job j USING(participant_id,privacy_domain_id,deletion_job_id)
   WHERE r.participant_id=participant AND r.privacy_domain_id=privacy AND r.stream_id=stream AND r.segment_id=segment
    AND r.data_class='SEARCH_PROJECTION' AND j.state='SUCCEEDED'
    AND r.retirement_digest=openpc.projection_retirement_digest(r)) matches
$$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_match_state(jsonb,uuid,uuid,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_match_state(jsonb,uuid,uuid,text,uuid) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
`;
