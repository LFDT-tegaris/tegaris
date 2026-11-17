-- Shared eligibility predicates, with separate writer and advisory entrypoints.
-- No new mutation, capability, signing-key or table-read grant to the reader.
-- Installed transactionally by the SQLx/psql migration owner after 0011.
SET LOCAL search_path=pg_catalog;

CREATE FUNCTION facts.store_retirement_predicates(p_attempt jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p text:=p_attempt#>>'{scope,participant_id}'; d text:=p_attempt#>>'{scope,privacy_domain_id}';
  selection jsonb:=p_attempt->'selection'; source jsonb:=selection->'source';
  selected jsonb; actual record; previous_sequence bigint:=0;
BEGIN
  IF p IS NULL OR p='' OR d IS NULL OR d=''
    OR facts.matches_context(p,d) IS DISTINCT FROM true THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_CONTEXT_REJECTED';
  END IF;
  IF p_attempt->>'store' IS DISTINCT FROM 'openpc_facts'
    OR selection->>'class' IS DISTINCT FROM 'ADMITTED_FACT'
    OR jsonb_typeof(selection->'rows') IS DISTINCT FROM 'array'
    OR jsonb_array_length(selection->'rows') NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_SELECTION_REJECTED';
  END IF;
  IF (p_attempt#>>'{governance,retention_not_before_ms}')::bigint
    >floor(extract(epoch FROM clock_timestamp())*1000)::bigint THEN RETURN 'RETENTION_NOT_ELAPSED'; END IF;
  FOR selected IN SELECT value FROM jsonb_array_elements(selection->'rows') LOOP
    IF (selected->>'candidate_feed_sequence')::bigint<=previous_sequence THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_SELECTION_REJECTED';
    END IF;
    previous_sequence:=(selected->>'candidate_feed_sequence')::bigint;
    SELECT f.*,a.fact_id,a.delta_sequence,g.canonical_generation,r.candidate_sequence,
      r.source_profile_id,r.source_generation_id,r.partition_id,r.checkpoint_digest,
      r.fact_generation_id,l.provenance_digest,i.state inbox_state,i.source_sequence,
      c.state checkpoint_state,c.last_sequence,ready.state readiness_state,ready.shard_verified,
      custody.signed_fact_digest custody_digest,retained.payload_digest retained_digest
    INTO actual FROM facts.canonical_fact f
    JOIN facts.canonical_identity_allocation a ON a.candidate_id=f.candidate_id AND a.participant_id=f.participant_id
      AND a.privacy_domain_id=f.privacy_domain_id AND a.generation_id=f.generation_id
    JOIN facts.canonical_generation g ON g.participant_id=a.participant_id AND g.privacy_domain_id=a.privacy_domain_id
      AND g.fact_profile_id=a.fact_profile_id AND g.generation_id=a.generation_id
    JOIN facts.candidate_feed_receipt r ON r.candidate_id=f.candidate_id AND r.participant_id=f.participant_id
      AND r.privacy_domain_id=f.privacy_domain_id
    JOIN facts.fact_lineage l ON l.candidate_id=f.candidate_id AND l.participant_id=f.participant_id
      AND l.privacy_domain_id=f.privacy_domain_id
    JOIN facts.admission_inbox i ON i.candidate_id=f.candidate_id AND i.participant_id=f.participant_id
      AND i.privacy_domain_id=f.privacy_domain_id
    JOIN facts.source_checkpoint c ON c.participant_id=f.participant_id AND c.privacy_domain_id=f.privacy_domain_id
      AND c.source_profile_id=i.source_profile_id
    JOIN facts.readiness_gate ready ON ready.participant_id=f.participant_id AND ready.privacy_domain_id=f.privacy_domain_id
      AND ready.generation_id=f.generation_id
    JOIN facts.signed_fact_custody custody ON custody.candidate_id=f.candidate_id AND custody.participant_id=f.participant_id
      AND custody.privacy_domain_id=f.privacy_domain_id
    JOIN facts.retained_fact_identity retained ON retained.candidate_id=f.candidate_id AND retained.participant_id=f.participant_id
      AND retained.privacy_domain_id=f.privacy_domain_id AND retained.generation_id=f.generation_id
    WHERE f.participant_id=p AND f.privacy_domain_id=d AND f.candidate_id=selected->>'candidate_id';
    IF NOT FOUND THEN RETURN 'SOURCE_CHANGED'; END IF;
    IF actual.source_profile_id IS DISTINCT FROM source->>'profile_id'
      OR actual.source_generation_id IS DISTINCT FROM source->>'generation_id'
      OR actual.partition_id::text IS DISTINCT FROM source->>'partition_id'
      OR actual.fact_generation_id IS DISTINCT FROM selection->>'fact_generation_id'
      OR actual.generation_id IS DISTINCT FROM selection->>'fact_generation_id'
      OR actual.canonical_generation::text IS DISTINCT FROM selection->>'canonical_generation'
    THEN RETURN 'GENERATION_CHANGED'; END IF;
    IF actual.fact_id::text IS DISTINCT FROM selected->>'fact_id'
      OR actual.delta_sequence::text IS DISTINCT FROM selected->>'fact_delta_sequence'
      OR actual.candidate_sequence::text IS DISTINCT FROM selected->>'candidate_feed_sequence'
      OR encode(sha256(actual.canonical_payload),'hex') IS DISTINCT FROM selected->>'payload_digest'
      OR octet_length(actual.canonical_payload)::text IS DISTINCT FROM selected->>'payload_bytes'
      OR encode(actual.signed_fact_digest,'hex') IS DISTINCT FROM selected->>'signed_fact_digest'
      OR encode(actual.provenance_digest,'hex') IS DISTINCT FROM selected->>'lineage_digest'
      OR encode(actual.checkpoint_digest,'hex') IS DISTINCT FROM selected->>'checkpoint_digest'
      OR actual.custody_digest<>actual.signed_fact_digest OR actual.retained_digest<>sha256(actual.canonical_payload)
    THEN RETURN 'SOURCE_CHANGED'; END IF;
    IF actual.state='REORG_TOMBSTONED' OR actual.checkpoint_state='REORG_FENCED'
      OR actual.readiness_state='REORG' THEN RETURN 'REORG_FENCED'; END IF;
    IF actual.inbox_state<>'APPLIED' OR actual.checkpoint_state<>'COMPLETE'
      OR actual.last_sequence<actual.source_sequence OR NOT actual.complete OR NOT actual.finality_verified
      OR actual.finalized_at IS NULL THEN RETURN 'CHECKPOINT_INCOMPLETE'; END IF;
    IF actual.state NOT IN ('RETIRED','SUPERSEDED') OR actual.readiness_state='READY'
      OR actual.shard_verified THEN RETURN 'READINESS_PROTECTED'; END IF;
    IF EXISTS(SELECT 1 FROM facts.shard_publication pub WHERE pub.participant_id=p
      AND pub.privacy_domain_id=d AND pub.generation_id=actual.generation_id
      AND pub.delivery_state<>'DELIVERED') THEN RETURN 'PUBLICATION_PROTECTED'; END IF;
    IF EXISTS(SELECT 1 FROM facts.outbox o WHERE o.participant_id=p AND o.privacy_domain_id=d
      AND o.candidate_id=actual.candidate_id AND o.delivery_state<>'DELIVERED')
      OR EXISTS(SELECT 1 FROM facts.fact_invalidation inv
        JOIN facts.canonical_fact dependent ON dependent.candidate_id=inv.candidate_id
          AND dependent.participant_id=inv.participant_id AND dependent.privacy_domain_id=inv.privacy_domain_id
        WHERE inv.participant_id=p AND inv.privacy_domain_id=d
          AND inv.replacement_candidate_id=actual.candidate_id AND dependent.state NOT IN ('RETIRED','SUPERSEDED'))
    THEN RETURN 'REFERENCES_PROTECTED'; END IF;
  END LOOP;
  RETURN NULL;
END $$;

ALTER FUNCTION facts.store_retirement_predicates(jsonb) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.store_retirement_predicates(jsonb) FROM PUBLIC;

-- Keep the original writer admission and exclusive scope lock unchanged.
CREATE OR REPLACE FUNCTION facts.check_store_retirement(p_attempt jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
  PERFORM facts.assert_lifecycle_context(p_attempt#>>'{scope,participant_id}',
    p_attempt#>>'{scope,privacy_domain_id}');
  RETURN facts.store_retirement_predicates(p_attempt);
END $$;
ALTER FUNCTION facts.check_store_retirement(jsonb) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.check_store_retirement(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.check_store_retirement(jsonb) TO openpc_fact_bridge_writer;

-- This is only the SQL half of advisory verification. A NULL blocker does not
-- authenticate source signatures/references or grant execution authority.
CREATE FUNCTION facts.preflight_store_retirement(p_attempt jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p text:=p_attempt#>>'{scope,participant_id}'; d text:=p_attempt#>>'{scope,privacy_domain_id}';
BEGIN
  IF current_database()<>'openpc_facts'
    OR NOT pg_has_role(session_user,'openpc_policy_fact_reader','MEMBER')
    OR pg_has_role(session_user,'openpc_fact_bridge_writer','MEMBER')
    OR pg_has_role(session_user,'openpc_facts_lifecycle_owner','MEMBER')
    OR pg_has_role(session_user,'openpc_facts_capability_owner','MEMBER')
    OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND (rolsuper OR rolbypassrls))
    OR current_setting('transaction_read_only')<>'on' THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_READER_REJECTED';
  END IF;
  IF jsonb_typeof(p_attempt) IS DISTINCT FROM 'object'
    OR octet_length(p_attempt::text)>1048576
    OR (p_attempt#>>'{governance,retention_not_before_ms}') IS NULL
    OR (p_attempt#>>'{governance,retention_not_before_ms}')::bigint<=0 THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_SELECTION_REJECTED';
  END IF;
  PERFORM facts.acquire_policy_read_fence(p,d);
  RETURN facts.store_retirement_predicates(p_attempt);
END $$;
ALTER FUNCTION facts.preflight_store_retirement(jsonb) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.preflight_store_retirement(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.preflight_store_retirement(jsonb) TO openpc_policy_fact_reader;

-- The verifier needs only exact retained-reference cardinality, never a broad
-- read grant on signed custody or retirement attempts/outcomes.
CREATE FUNCTION facts.retirement_reference_retained(p text,d text,reference text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
  IF p IS NULL OR p='' OR d IS NULL OR d='' OR facts.matches_context(p,d) IS DISTINCT FROM true
    OR reference IS NULL OR length(reference) NOT BETWEEN 1 AND 256
    OR NOT (pg_has_role(session_user,'openpc_fact_bridge_writer','MEMBER')
      OR pg_has_role(session_user,'openpc_policy_fact_reader','MEMBER')) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_CONTEXT_REJECTED';
  END IF;
  RETURN (SELECT count(*)=1 FROM facts.retained_fact_identity i
    JOIN facts.canonical_identity_allocation a USING(candidate_id,participant_id,privacy_domain_id,generation_id)
    WHERE i.participant_id=p AND i.privacy_domain_id=d
      AND ('sha256:'||encode(i.fact_digest,'hex')=reference OR 'urn:openpc:fact:'||a.fact_id::text=reference));
END $$;
ALTER FUNCTION facts.retirement_reference_retained(text,text,text) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.retirement_reference_retained(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.retirement_reference_retained(text,text,text)
  TO openpc_fact_bridge_writer,openpc_policy_fact_reader;
