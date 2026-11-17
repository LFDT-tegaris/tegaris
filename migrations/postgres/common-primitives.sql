-- OPENPC-C04-DATA-COMMON-001
-- trace-packs: TP-DATA-SCALARS, TP-DATA-RLS, TP-DATA-ASYNC-WORK
-- Included by each database's checksummed initial migration while SET ROLE is the database owner.

CREATE SCHEMA openpc;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA openpc FROM PUBLIC;

CREATE EXTENSION btree_gist WITH SCHEMA public;

CREATE DOMAIN openpc.uuid_v7 AS uuid
  CHECK (VALUE::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN openpc.sha256_bytes AS bytea
  CHECK (octet_length(VALUE) = 32);

CREATE DOMAIN openpc.uint64 AS numeric(20,0)
  CHECK (VALUE >= 0 AND VALUE <= 18446744073709551615);

CREATE DOMAIN openpc.duration_ms AS bigint
  CHECK (VALUE >= 0);

CREATE DOMAIN openpc.semantic_version AS text
  CHECK (VALUE ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$');

CREATE DOMAIN openpc.action_intent_id AS text
  CHECK (VALUE ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$');

CREATE DOMAIN openpc.idempotency_key AS text
  CHECK (length(VALUE) BETWEEN 16 AND 128 AND VALUE ~ '^[A-Za-z0-9._~-]+$');

CREATE DOMAIN openpc.openpc_urn AS text
  CHECK (VALUE ~ '^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE DOMAIN openpc.event_type AS text
  CHECK (VALUE ~ '^io\.openpc\.[a-z0-9.]+\.v[1-9][0-9]*$');

CREATE DOMAIN openpc.schema_uri AS text
  CHECK (VALUE ~ '^https://schemas\.openpc\.local/[A-Za-z0-9._~!$&''()*+,;=:@%/-]+$');

CREATE DOMAIN openpc.cbor_payload AS bytea
  CHECK (octet_length(VALUE) BETWEEN 1 AND 1048576);

CREATE DOMAIN openpc.evm_address AS bytea
  CHECK (octet_length(VALUE) = 20);

CREATE DOMAIN openpc.bytes32 AS bytea
  CHECK (octet_length(VALUE) = 32);

CREATE TYPE openpc.truth_state AS ENUM (
  'SUCCESS', 'AUTHORIZED_EMPTY', 'DENIED', 'LOADING', 'UNKNOWN', 'UNAVAILABLE', 'STALE', 'REORG', 'PARTIAL', 'CONFLICTING',
  'DEGRADED', 'FAILED', 'RETRY_ELIGIBLE', 'FAILOVER_ELIGIBLE', 'WRITE_AMBIGUITY', 'RECOVERY', 'ROLLBACK', 'RETIREMENT', 'UNINSTALL', 'DECOMMISSION'
);

CREATE TYPE openpc.operation_class AS ENUM ('READ', 'CREATE', 'UPDATE', 'DELETE', 'APPROVE', 'ACTIVATE', 'ROLLBACK', 'EXPORT', 'RECOVER', 'UNINSTALL');
CREATE TYPE openpc.risk_class AS ENUM ('LOW', 'STANDARD', 'HIGH', 'BREAK_GLASS');
CREATE TYPE openpc.context_mode AS ENUM ('PARTICIPANT', 'PLATFORM');
CREATE TYPE openpc.delivery_state AS ENUM ('PENDING', 'LEASED', 'DELIVERED', 'RETRY_WAIT', 'QUARANTINED');
CREATE TYPE openpc.external_attempt_state AS ENUM ('NOT_STARTED', 'STARTED', 'ACKNOWLEDGED', 'AMBIGUOUS', 'RECONCILED', 'FAILED_TERMINAL');
CREATE TYPE openpc.inbox_state AS ENUM ('RECEIVED', 'APPLIED', 'DUPLICATE_SAME_DIGEST', 'BLOCKED_SEQUENCE_GAP', 'QUARANTINED');
CREATE TYPE openpc.deletion_mode AS ENUM ('ROW_DELETE', 'PROJECTION_DELETE', 'IDENTIFIER_ALIAS', 'CRYPTO_SHRED');

CREATE FUNCTION openpc.uuid_to_urn(p_resource_type text, p_id openpc.uuid_v7)
RETURNS openpc.openpc_urn
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
  SELECT ('urn:openpc:' || p_resource_type || ':' || p_id::text)::openpc.openpc_urn
$$;

CREATE FUNCTION openpc.digest_to_text(p_digest openpc.sha256_bytes)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
  SELECT 'sha256:' || encode(p_digest, 'hex')
$$;

CREATE FUNCTION openpc.require_uuid_setting(p_name text)
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE
  v text;
  parsed uuid;
BEGIN
  v := current_setting(p_name, true);
  IF v IS NULL OR v = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6000-CONTEXT-MISSING', DETAIL = p_name;
  END IF;
  BEGIN
    parsed := v::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID', DETAIL = p_name;
  END;
  RETURN parsed;
END
$$;

CREATE FUNCTION openpc.current_participant_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, openpc
AS $$ SELECT openpc.require_uuid_setting('openpc.participant_id') $$;

CREATE FUNCTION openpc.current_privacy_domain_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, openpc
AS $$ SELECT openpc.require_uuid_setting('openpc.privacy_domain_id') $$;

CREATE FUNCTION openpc.current_operation_id()
RETURNS openpc.uuid_v7
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, openpc
AS $$ SELECT openpc.require_uuid_setting('openpc.operation_id')::openpc.uuid_v7 $$;

CREATE FUNCTION openpc.current_action_intent_id()
RETURNS openpc.action_intent_id
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, openpc
AS $$
DECLARE v text;
BEGIN
  v := current_setting('openpc.action_intent_id', true);
  IF v IS NULL OR v = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6000-CONTEXT-MISSING', DETAIL = 'openpc.action_intent_id';
  END IF;
  RETURN v::openpc.action_intent_id;
EXCEPTION WHEN check_violation OR invalid_text_representation THEN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID', DETAIL = 'openpc.action_intent_id';
END
$$;

CREATE FUNCTION openpc.set_request_context(
  p_mode openpc.context_mode,
  p_participant_id uuid,
  p_privacy_domain_id uuid,
  p_operation_id openpc.uuid_v7,
  p_action_intent_id openpc.action_intent_id,
  p_require_privacy boolean DEFAULT true
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, openpc
AS $$
BEGIN
  IF p_mode = 'PLATFORM' AND NOT (
    pg_has_role(current_user, 'openpc_control_platform_runtime', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_migrator', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_maintenance', 'MEMBER')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6002-PLATFORM-CONTEXT-FORBIDDEN';
  END IF;
  IF p_require_privacy AND p_privacy_domain_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6000-CONTEXT-MISSING', DETAIL = 'privacy_domain_id';
  END IF;
  PERFORM set_config('openpc.context_mode', p_mode::text, true);
  PERFORM set_config('openpc.participant_id', p_participant_id::text, true);
  PERFORM set_config('openpc.privacy_domain_id', coalesce(p_privacy_domain_id::text, ''), true);
  PERFORM set_config('openpc.operation_id', p_operation_id::text, true);
  PERFORM set_config('openpc.action_intent_id', p_action_intent_id::text, true);
END
$$;

CREATE FUNCTION openpc.assert_request_context(p_require_privacy boolean DEFAULT true)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, openpc
AS $$
DECLARE v_mode openpc.context_mode;
BEGIN
  v_mode := current_setting('openpc.context_mode', true)::openpc.context_mode;
  PERFORM openpc.current_participant_id();
  PERFORM openpc.current_operation_id();
  PERFORM openpc.current_action_intent_id();
  IF p_require_privacy THEN PERFORM openpc.current_privacy_domain_id(); END IF;
  IF v_mode = 'PLATFORM' AND NOT (
    pg_has_role(current_user, 'openpc_control_platform_runtime', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_migrator', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_maintenance', 'MEMBER')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6002-PLATFORM-CONTEXT-FORBIDDEN';
  END IF;
EXCEPTION WHEN invalid_text_representation THEN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID';
END
$$;

CREATE FUNCTION openpc.matches_participant(p_participant_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, openpc
AS $$ SELECT p_participant_id = openpc.current_participant_id() $$;

CREATE FUNCTION openpc.matches_privacy(p_privacy_domain_id uuid)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, openpc
AS $$
BEGIN
  IF p_privacy_domain_id IS NULL THEN RETURN true; END IF;
  RETURN p_privacy_domain_id = openpc.current_privacy_domain_id();
END
$$;

CREATE FUNCTION openpc.touch_versioned_row()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  NEW.row_version := OLD.row_version + 1;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END
$$;

CREATE FUNCTION openpc.reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END
$$;

CREATE FUNCTION openpc.verify_cbor_digest()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF sha256(NEW.payload_cbor) <> NEW.payload_digest THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6040-PAYLOAD-DIGEST-MISMATCH';
  END IF;
  RETURN NEW;
END
$$;

COMMENT ON SCHEMA openpc IS 'AF-08 physical scalar adapters and security-invoker transaction-context primitives; trace TP-DATA-SCALARS/TP-DATA-RLS.';
COMMENT ON DOMAIN openpc.uuid_v7 IS 'RFC 9562 UUIDv7; UUID time bits are an ordering hint, never authoritative time or authorization.';
COMMENT ON DOMAIN openpc.sha256_bytes IS 'Raw 32-byte SHA-256; interface projection is sha256:<lowercase hex>.';
COMMENT ON DOMAIN openpc.cbor_payload IS 'PC-CBOR-1 semantic payload bytes; JSON is projection only.';
