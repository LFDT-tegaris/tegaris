SET client_min_messages = warning;

DO $persistent_context$
BEGIN
  IF pg_catalog.current_setting('openpc.participant_id', true) <> 'participant-a'
     OR pg_catalog.current_setting('openpc.privacy_domain_id', true) <> 'privacy-a' THEN
    RAISE EXCEPTION 'I05_GATE3_PERSISTENT_FORGED_GUC_CONTEXT_NOT_ACTIVE';
  END IF;
END
$persistent_context$;

DO $proof$
DECLARE
  rejected boolean := false;
BEGIN
  IF pg_catalog.current_setting('search_path') <> 'facts, public' THEN
    RAISE EXCEPTION 'I05_GATE3_HOSTILE_SEARCH_PATH_NOT_ACTIVE';
  END IF;
  BEGIN
    UPDATE facts.canonical_fact
       SET state = 'REORG_TOMBSTONED'
     WHERE candidate_id = 'candidate-1';
  EXCEPTION WHEN insufficient_privilege THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_STATE_ROLLBACK_ACCEPTED';
  END IF;

  rejected := false;
  BEGIN
    UPDATE facts.fact_invalidation
       SET replacement_candidate_id = NULL,
           replacement_generation_id = NULL,
           linked_at = NULL
     WHERE candidate_id = 'candidate-1';
  EXCEPTION WHEN insufficient_privilege THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_REPLACEMENT_UNLINK_ACCEPTED';
  END IF;

  rejected := false;
  BEGIN
    UPDATE facts.fact_invalidation
       SET replacement_candidate_id = 'candidate-1',
           replacement_generation_id = 'generation-1'
     WHERE candidate_id = 'candidate-1';
  EXCEPTION WHEN insufficient_privilege THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_REPLACEMENT_RELINK_ACCEPTED';
  END IF;

  rejected := false;
  BEGIN
    DELETE FROM facts.fact_invalidation WHERE candidate_id = 'candidate-1';
  EXCEPTION WHEN insufficient_privilege THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_INVALIDATION_DELETE_ACCEPTED';
  END IF;

  IF (SELECT count(*) FROM facts.canonical_fact WHERE octet_length(cose_sign1) > 64) <> 2 THEN
    RAISE EXCEPTION 'I05_GATE3_SIGNED_FACT_COUNT';
  END IF;
  IF (SELECT count(*) FROM facts.canonical_fact
       WHERE schema_id = 21006
         AND schema_version = '1.0.0'
         AND schema_digest = decode('b01a7c0d29f30b335aff75db0c26fea0287ea9fdd7e77b1c6f5d2de8b7ca0525', 'hex')) <> 2 THEN
    RAISE EXCEPTION 'I05_GATE3_EXACT_SCHEMA_TUPLE_COUNT';
  END IF;
  rejected := false;
  BEGIN
    UPDATE facts.canonical_fact SET schema_id = 21002 WHERE candidate_id = 'candidate-2';
  EXCEPTION WHEN insufficient_privilege OR object_not_in_prerequisite_state OR check_violation THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_DURABLE_SCHEMA_TUPLE_MUTATION_ACCEPTED';
  END IF;
  IF (SELECT count(*) FROM facts.canonical_fact WHERE state = 'FINALIZED') <> 1 THEN
    RAISE EXCEPTION 'I05_GATE3_REPLACEMENT_FINALITY_COUNT';
  END IF;
  IF (SELECT count(*) FROM facts.canonical_fact WHERE state = 'SUPERSEDED') <> 1 THEN
    RAISE EXCEPTION 'I05_GATE3_PREDECESSOR_SUPERSEDED_COUNT';
  END IF;
  IF (SELECT count(*) FROM facts.readiness_gate WHERE state = 'READY' AND shard_verified) <> 1 THEN
    RAISE EXCEPTION 'I05_GATE3_SIGNED_SHARD_READY_COUNT';
  END IF;

  IF pg_catalog.has_table_privilege(current_user, 'facts.canonical_fact', 'INSERT')
     OR pg_catalog.has_table_privilege(current_user, 'facts.canonical_fact', 'UPDATE')
     OR pg_catalog.has_table_privilege(current_user, 'facts.canonical_fact', 'DELETE')
     OR pg_catalog.has_table_privilege(current_user, 'facts.fact_invalidation', 'INSERT')
     OR pg_catalog.has_table_privilege(current_user, 'facts.fact_invalidation', 'UPDATE')
     OR pg_catalog.has_table_privilege(current_user, 'facts.fact_invalidation', 'DELETE')
     OR pg_catalog.has_table_privilege(current_user, 'facts.lineage_outbox', 'INSERT,UPDATE,DELETE') THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_DIRECT_LIFECYCLE_DML_GRANTED';
  END IF;

  IF (SELECT count(*)
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = procedure.proowner
       WHERE namespace.nspname = 'facts'
         AND procedure.proname IN (
           'admit_fact',
           'finalize_fact',
           'mark_signed_shard_ready',
           'invalidate_fact_for_reorg',
           'admit_replacement',
           'consume_candidate_feed_event',
           'bind_fact_occurrence',
           'allocate_canonical_fact_identity',
           'retire_for_source_withdrawal',
           'tombstone_for_source_reorg',
           'commit_verified_publication',
           'authorize_gap_rebootstrap'
         )
         AND procedure.prosecdef
         AND owner_role.rolname = 'openpc_facts_lifecycle_owner'
         AND procedure.proconfig @> ARRAY['search_path=pg_catalog']) <> 12 THEN
    RAISE EXCEPTION 'I05_GATE3_LIFECYCLE_FUNCTION_OWNERSHIP_OR_SEARCH_PATH';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
     WHERE rolname = 'openpc_facts_lifecycle_owner'
       AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'I05_GATE3_UNSAFE_LIFECYCLE_OWNER';
  END IF;

  rejected := false;
  PERFORM pg_catalog.set_config('openpc.participant_id', 'participant-b', true);
  PERFORM pg_catalog.set_config('openpc.privacy_domain_id', 'privacy-b', true);
  BEGIN
    PERFORM facts.finalize_fact(
      'participant-a',
      'privacy-a',
      'candidate-2',
      decode(repeat('00', 32), 'hex'),
      NULL,
      NULL
    );
  EXCEPTION WHEN insufficient_privilege THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_CROSS_TENANT_FUNCTION_CALL_ACCEPTED';
  END IF;
END
$proof$;

DO $capability$
DECLARE
  rejected boolean;
  failure_message text;
BEGIN
  IF pg_catalog.current_setting('openpc.test_capability_nonce_hex', true) IS NOT NULL
     OR pg_catalog.current_setting('openpc.test_capability_mac_hex', true) IS NOT NULL
     OR EXISTS (
       SELECT 1
         FROM pg_catalog.pg_settings
        WHERE name IN ('openpc.test_capability_nonce_hex', 'openpc.test_capability_mac_hex')
     ) THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_CAPABILITY_GUC_NAMESPACE_PRESENT';
  END IF;

  rejected := false;
  BEGIN
    PERFORM pg_catalog.current_setting('openpc.test_capability_nonce_hex');
  EXCEPTION WHEN undefined_object THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_CAPABILITY_GUC_REQUIRED_READ_ACCEPTED';
  END IF;

  IF pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_secret', 'SELECT')
     OR pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_secret', 'INSERT')
     OR pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_secret', 'UPDATE')
     OR pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_secret', 'DELETE')
     OR pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_secret', 'TRUNCATE')
     OR pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_secret', 'REFERENCES')
     OR pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_secret', 'TRIGGER')
     OR pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_replay', 'SELECT')
     OR pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_replay', 'INSERT')
     OR pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_replay', 'UPDATE')
     OR pg_catalog.has_table_privilege(current_user, 'facts.mutation_capability_replay', 'DELETE') THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_CAPABILITY_STATE_PRIVILEGE';
  END IF;
  IF pg_catalog.has_function_privilege(current_user, 'public.hmac(bytea,bytea,text)', 'EXECUTE')
     OR pg_catalog.has_function_privilege(current_user, 'public.hmac(text,text,text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_GENERIC_HMAC_SIGNER_ACCESS';
  END IF;

  rejected := false;
  BEGIN
    PERFORM verifier_secret FROM facts.mutation_capability_secret;
  EXCEPTION WHEN insufficient_privilege THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_SECRET_READ_ACCEPTED';
  END IF;

  rejected := false;
  BEGIN
    PERFORM * FROM openpc_attack.consumed_capability('ADMIT_FACT');
  EXCEPTION WHEN invalid_schema_name OR undefined_function OR insufficient_privilege THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_REPLAY_STATE_HELPER_ACCESSIBLE';
  END IF;

  IF EXISTS (
       SELECT 1
         FROM pg_catalog.pg_namespace AS namespace
        WHERE namespace.nspname = 'openpc_attack'
     )
     OR EXISTS (
       SELECT 1
         FROM pg_catalog.pg_proc AS procedure
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'openpc_attack'
     )
     OR EXISTS (
       SELECT 1
         FROM pg_catalog.pg_class AS relation
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'openpc_attack'
          AND relation.relkind IN ('m', 'v')
     )
     OR EXISTS (
       SELECT 1
         FROM pg_catalog.pg_proc AS procedure
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'facts'
          AND pg_catalog.has_function_privilege(current_user, procedure.oid, 'EXECUTE')
          AND procedure.proname NOT IN (
            'admit_fact',
            'finalize_fact',
            'mark_signed_shard_ready',
            'invalidate_fact_for_reorg',
            'admit_replacement',
            'consume_candidate_feed_event',
            'bind_fact_occurrence',
            'allocate_canonical_fact_identity',
            'retire_for_source_withdrawal',
           'tombstone_for_source_reorg',
           'commit_verified_publication',
           'authorize_gap_rebootstrap',
            'matches_context'
          )
     ) THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_ATTACK_TOPOLOGY_DISCOVERY_SURFACE';
  END IF;

  IF pg_catalog.has_function_privilege(current_user, 'facts.verify_lineage_capability(bytea,bytea,bytea)', 'EXECUTE') THEN
    RAISE EXCEPTION 'I05_GATE3_RUNTIME_LINEAGE_CAPABILITY_HELPER_GRANTED';
  END IF;
  rejected := false;
  BEGIN
    PERFORM facts.retire_for_source_withdrawal('participant-a','privacy-a','candidate-2',
      '018f0000-0000-7000-8000-000000000001','forged-source',
      '018f0000-0000-7000-8000-000000000002',1,decode(repeat('00',32),'hex'),
      '018f0000-0000-7000-8000-000000000003',decode(repeat('00',32),'hex'),decode(repeat('00',80),'hex'),
      decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'));
  EXCEPTION WHEN insufficient_privilege THEN
    GET STACKED DIAGNOSTICS failure_message = MESSAGE_TEXT;
    rejected := failure_message = 'OPENPC_FACTSTORE_CAPABILITY_INVALID';
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_FORGED_LINEAGE_CAPABILITY_ACCEPTED';
  END IF;

  rejected := false;
  BEGIN
    PERFORM facts.admit_fact(
      'direct-forgery', 'participant-a', 'privacy-a', 'profile-a', 'generation-direct',
      99, decode(repeat('01', 32), 'hex'), 21006, '1.0.0',
      decode('b01a7c0d29f30b335aff75db0c26fea0287ea9fdd7e77b1c6f5d2de8b7ca0525', 'hex'),
      decode('a1617801', 'hex'), decode(repeat('02', 32), 'hex'),
      decode(repeat('03', 32), 'hex'), 1, 2, decode(repeat('04', 65), 'hex'),
      decode(repeat('05', 32), 'hex'), decode('06', 'hex'),
      decode(repeat('07', 32), 'hex'), NULL, NULL
    );
  EXCEPTION WHEN insufficient_privilege THEN
    GET STACKED DIAGNOSTICS failure_message = MESSAGE_TEXT;
    rejected := failure_message = 'OPENPC_FACTSTORE_CAPABILITY_INVALID';
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_MISSING_CAPABILITY_DIRECT_CALL_ACCEPTED';
  END IF;

  rejected := false;
  BEGIN
    PERFORM facts.admit_fact(
      'direct-forgery', 'participant-a', 'privacy-a', 'profile-a', 'generation-direct',
      99, decode(repeat('01', 32), 'hex'), 21006, '1.0.0',
      decode('b01a7c0d29f30b335aff75db0c26fea0287ea9fdd7e77b1c6f5d2de8b7ca0525', 'hex'),
      decode('a1617801', 'hex'), decode(repeat('02', 32), 'hex'),
      decode(repeat('03', 32), 'hex'), 1, 2, decode(repeat('04', 65), 'hex'),
      decode(repeat('05', 32), 'hex'), decode('06', 'hex'),
      decode(repeat('07', 32), 'hex'), decode(repeat('08', 32), 'hex'),
      decode(repeat('09', 32), 'hex')
    );
  EXCEPTION WHEN insufficient_privilege THEN
    GET STACKED DIAGNOSTICS failure_message = MESSAGE_TEXT;
    rejected := failure_message = 'OPENPC_FACTSTORE_CAPABILITY_INVALID';
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_FORGED_CAPABILITY_DIRECT_CALL_ACCEPTED';
  END IF;

END
$capability$;

SELECT 'I05_GATE3_DATABASE_GUARDS|PASS|FTR010_TERMINAL|RUNTIME_NO_DML|FIXED_SEARCH_PATH|RLS|SIGNED_FACT|SIGNED_SHARD|PURPOSE_CAPABILITY|REPLAY|REBIND|SECRET_CUSTODY';
