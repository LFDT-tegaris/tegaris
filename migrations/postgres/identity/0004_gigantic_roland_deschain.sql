-- OPENPC GENERATED REQUEST CONTEXT PREAMBLE; DO NOT EDIT
CREATE SCHEMA IF NOT EXISTS openpc;
CREATE OR REPLACE FUNCTION openpc.require_uuid_setting(p_name text)
RETURNS uuid LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE value text; parsed uuid;
BEGIN
  value := current_setting(p_name, true);
  IF value IS NULL OR value = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6000-CONTEXT-MISSING', DETAIL = p_name;
  END IF;
  BEGIN parsed := value::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID', DETAIL = p_name;
  END;
  RETURN parsed;
END $$;
CREATE OR REPLACE FUNCTION openpc.current_participant_id()
RETURNS uuid LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, openpc
AS $$ SELECT openpc.require_uuid_setting('openpc.participant_id') $$;
CREATE OR REPLACE FUNCTION openpc.current_privacy_domain_id()
RETURNS uuid LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, openpc
AS $$ SELECT openpc.require_uuid_setting('openpc.privacy_domain_id') $$;
CREATE OR REPLACE FUNCTION openpc.current_operation_id()
RETURNS uuid LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, openpc
AS $$ SELECT openpc.require_uuid_setting('openpc.operation_id') $$;
CREATE OR REPLACE FUNCTION openpc.current_action_intent_id()
RETURNS text LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE value text;
BEGIN
  value := current_setting('openpc.action_intent_id', true);
  IF value IS NULL OR value !~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID', DETAIL = 'openpc.action_intent_id';
  END IF;
  RETURN value;
END $$;
CREATE OR REPLACE FUNCTION openpc.set_request_context(
  p_mode text, p_participant_id uuid, p_privacy_domain_id uuid,
  p_operation_id uuid, p_action_intent_id text, p_require_privacy boolean DEFAULT true
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog, openpc AS $$
BEGIN
  IF p_mode NOT IN ('PARTICIPANT', 'PLATFORM') THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID', DETAIL = 'openpc.context_mode';
  END IF;
  IF p_operation_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_action_intent_id !~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID';
  END IF;
  IF p_mode = 'PLATFORM' AND NOT (
    current_user = 'openpc_control_platform_runtime'
    OR pg_has_role(current_user, 'openpc_control_platform_runtime', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_migrator', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_maintenance', 'MEMBER')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6002-PLATFORM-CONTEXT-FORBIDDEN';
  END IF;
  IF p_require_privacy AND p_privacy_domain_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6000-CONTEXT-MISSING', DETAIL = 'privacy_domain_id';
  END IF;
  PERFORM set_config('openpc.context_mode', p_mode, true);
  PERFORM set_config('openpc.participant_id', p_participant_id::text, true);
  PERFORM set_config('openpc.privacy_domain_id', coalesce(p_privacy_domain_id::text, ''), true);
  PERFORM set_config('openpc.operation_id', p_operation_id::text, true);
  PERFORM set_config('openpc.action_intent_id', p_action_intent_id, true);
  PERFORM set_config('openpc.context_scope', 'TRANSACTION_LOCAL', true);
END $$;
CREATE OR REPLACE FUNCTION openpc.assert_request_context(p_require_privacy boolean DEFAULT true)
RETURNS void LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = pg_catalog, openpc AS $$
DECLARE mode text;
BEGIN
  mode := current_setting('openpc.context_mode', true);
  IF current_setting('openpc.context_scope', true) <> 'TRANSACTION_LOCAL' OR mode NOT IN ('PARTICIPANT', 'PLATFORM') THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID';
  END IF;
  PERFORM openpc.current_participant_id();
  PERFORM openpc.current_operation_id();
  PERFORM openpc.current_action_intent_id();
  IF p_require_privacy THEN PERFORM openpc.current_privacy_domain_id(); END IF;
  IF mode = 'PLATFORM' AND NOT (
    current_user = 'openpc_control_platform_runtime'
    OR pg_has_role(current_user, 'openpc_control_platform_runtime', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_migrator', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_maintenance', 'MEMBER')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6002-PLATFORM-CONTEXT-FORBIDDEN';
  END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.matches_participant(p_participant_id uuid)
RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY INVOKER SET search_path = pg_catalog, openpc
AS $$ SELECT p_participant_id = openpc.current_participant_id() $$;
CREATE OR REPLACE FUNCTION openpc.matches_privacy(p_privacy_domain_id uuid)
RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY INVOKER SET search_path = pg_catalog, openpc
AS $$ SELECT p_privacy_domain_id = openpc.current_privacy_domain_id() $$;
-- END OPENPC GENERATED REQUEST CONTEXT PREAMBLE
ALTER TABLE "control"."mutation_evidence" RENAME COLUMN "bound_authority_epoch" TO "bound_principal_epoch";--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ALTER COLUMN "checker_principal_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ALTER COLUMN "approval_request_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ALTER COLUMN "mfa_challenge_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD COLUMN "row_version" numeric(20, 0) DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD COLUMN "updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "row_version" numeric(20, 0) DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "row_version" numeric(20, 0) DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."credential" ADD COLUMN "public_key_spki_der" "bytea";--> statement-breakpoint
ALTER TABLE "control"."credential" ADD COLUMN "credential_epoch" numeric(20, 0) DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."mfa_challenge" ADD COLUMN "row_version" bigint DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD COLUMN "row_version" bigint DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD COLUMN "approver_principal_epoch" bigint;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD COLUMN "approver_authority_envelope_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD COLUMN "approver_envelope_epoch" bigint;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD COLUMN "approver_assignment_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD COLUMN "signer_credential_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD COLUMN "aggregate_version" bigint;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD COLUMN "candidate_digest" "bytea";--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD COLUMN "evidence_cbor" "bytea";--> statement-breakpoint
ALTER TABLE "control"."approval_request" ADD COLUMN "subject_version" bigint DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" ADD COLUMN "catalog_operation_id" varchar(160) DEFAULT 'LEGACY' NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" ADD COLUMN "expected_aggregate_version" bigint DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" ADD COLUMN "result_aggregate_version" bigint;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD COLUMN "catalog_operation_id" varchar(160) DEFAULT 'LEGACY' NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD COLUMN "aggregate_version" bigint;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD COLUMN "bound_authority_envelope_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD COLUMN "bound_envelope_epoch" bigint;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD COLUMN "bound_assignment_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD CONSTRAINT "approval_decision_envelope_fk" FOREIGN KEY ("participant_id","approver_authority_envelope_id") REFERENCES "control"."authority_envelope"("participant_id","authority_envelope_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD CONSTRAINT "approval_decision_assignment_fk" FOREIGN KEY ("participant_id","approver_assignment_id") REFERENCES "control"."assignment"("participant_id","assignment_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD CONSTRAINT "approval_decision_signer_credential_fk" FOREIGN KEY ("signer_credential_id") REFERENCES "control"."credential"("credential_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" DROP CONSTRAINT "idempotency_record_pk";
--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" ADD CONSTRAINT "idempotency_record_pk" PRIMARY KEY("participant_id","principal_id","action_intent_id","catalog_operation_id","idempotency_key");--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD CONSTRAINT "assignment_row_version_ck" CHECK ("control"."assignment"."row_version" > 0);--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD CONSTRAINT "authority_envelope_row_version_ck" CHECK ("control"."authority_envelope"."row_version" > 0);--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD CONSTRAINT "delegation_row_version_ck" CHECK ("control"."delegation"."row_version" > 0);--> statement-breakpoint
ALTER TABLE "control"."mfa_challenge" ADD CONSTRAINT "mfa_challenge_row_version_ck" CHECK ("control"."mfa_challenge"."row_version" > 0);--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD CONSTRAINT "recovery_challenge_row_version_ck" CHECK ("control"."recovery_challenge"."row_version" > 0);--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD CONSTRAINT "approval_decision_aggregate_version_ck" CHECK ("control"."approval_decision_record"."aggregate_version" >= 0);--> statement-breakpoint
ALTER TABLE "control"."approval_request" ADD CONSTRAINT "approval_request_subject_version_ck" CHECK ("control"."approval_request"."subject_version" >= 0);--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" ADD CONSTRAINT "idempotency_catalog_operation_ck" CHECK ("control"."idempotency_record"."catalog_operation_id" = 'LEGACY' or "control"."idempotency_record"."catalog_operation_id" ~ '^ID-OP-[A-Z0-9-]+$');--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" ADD CONSTRAINT "idempotency_aggregate_version_ck" CHECK ("control"."idempotency_record"."expected_aggregate_version" >= 0 and ("control"."idempotency_record"."result_aggregate_version" is null or "control"."idempotency_record"."result_aggregate_version" >= 0));--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD CONSTRAINT "mutation_evidence_catalog_operation_ck" CHECK ("control"."mutation_evidence"."catalog_operation_id" = 'LEGACY' or "control"."mutation_evidence"."catalog_operation_id" ~ '^ID-OP-[A-Z0-9-]+$');--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD CONSTRAINT "mutation_evidence_aggregate_version_ck" CHECK ("control"."mutation_evidence"."aggregate_version" is null or "control"."mutation_evidence"."aggregate_version" >= 0);
-- OPENPC GENERATED SECURITY TAIL; DO NOT EDIT
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'openpc_backup_operator') THEN
    CREATE ROLE openpc_backup_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT BYPASSRLS;
  END IF;
END
$roles$;
ALTER ROLE "openpc_control_owner" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_migrator" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT BYPASSRLS;
ALTER ROLE "openpc_control_runtime" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_worker" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_platform_runtime" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_reader" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_maintenance" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT BYPASSRLS;
ALTER ROLE "openpc_backup_operator" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT BYPASSRLS;
GRANT "openpc_control_owner" TO "openpc_control_migrator";
ALTER DATABASE "openpc_control" OWNER TO "openpc_control_owner";
ALTER SCHEMA openpc OWNER TO "openpc_control_owner";
ALTER SCHEMA control OWNER TO "openpc_control_owner";
REVOKE ALL ON DATABASE "openpc_control" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE "openpc_control" TO "openpc_control_migrator";
GRANT CONNECT ON DATABASE "openpc_control" TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
REVOKE ALL ON SCHEMA public, openpc, control FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA openpc, control TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
ALTER TABLE "control"."approval_decision_record" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."approval_request" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."assignment" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_envelope" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_group" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_group_member" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."credential" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."delegation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."idempotency_record" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."mfa_challenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."mutation_evidence" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."outbox_aggregate_head" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."outbox_event" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."participant" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."principal" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."privacy_domain" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."recovery_challenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."revocation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."session" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."action_intent" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."approval_decision_record" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."approval_request" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."assignment" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_envelope" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_group" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_group_member" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."credential" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."delegation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."idempotency_record" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."mfa_challenge" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."mutation_evidence" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."oidc_transaction" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."outbox_aggregate_head" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."outbox_event" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."participant" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."principal" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."privacy_domain" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."recovery_challenge" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."revocation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."session" OWNER TO "openpc_control_owner";
CREATE OR REPLACE FUNCTION openpc.reject_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
CREATE OR REPLACE FUNCTION openpc.require_complete_security_record()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE row_document jsonb := to_jsonb(NEW);
BEGIN
  IF TG_TABLE_NAME = 'approval_decision_record' AND (
    row_document->>'approver_principal_epoch' IS NULL
    OR row_document->>'approver_authority_envelope_id' IS NULL
    OR row_document->>'approver_envelope_epoch' IS NULL
    OR row_document->>'approver_assignment_id' IS NULL
    OR row_document->>'signer_credential_id' IS NULL
    OR row_document->>'aggregate_version' IS NULL
    OR row_document->>'candidate_digest' IS NULL OR row_document->>'evidence_cbor' IS NULL
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  IF TG_TABLE_NAME = 'mutation_evidence' AND (
    row_document->>'catalog_operation_id' = 'LEGACY'
    OR row_document->>'aggregate_version' IS NULL
    OR row_document->>'bound_authority_envelope_id' IS NULL
    OR row_document->>'bound_envelope_epoch' IS NULL
    OR row_document->>'bound_assignment_id' IS NULL
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  IF TG_TABLE_NAME = 'credential' AND row_document->>'kind' = 'WEBAUTHN'
     AND row_document->>'state' IN ('ACTIVE','ROTATING')
     AND row_document->>'public_key_spki_der' IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS approval_decision_immutable ON "control"."approval_decision_record";
CREATE TRIGGER approval_decision_immutable BEFORE UPDATE OR DELETE ON "control"."approval_decision_record"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS mutation_evidence_immutable ON "control"."mutation_evidence";
CREATE TRIGGER mutation_evidence_immutable BEFORE UPDATE OR DELETE ON "control"."mutation_evidence"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS approval_decision_complete ON "control"."approval_decision_record";
CREATE TRIGGER approval_decision_complete BEFORE INSERT ON "control"."approval_decision_record"
FOR EACH ROW EXECUTE FUNCTION openpc.require_complete_security_record();
DROP TRIGGER IF EXISTS mutation_evidence_complete ON "control"."mutation_evidence";
CREATE TRIGGER mutation_evidence_complete BEFORE INSERT ON "control"."mutation_evidence"
FOR EACH ROW EXECUTE FUNCTION openpc.require_complete_security_record();
DROP TRIGGER IF EXISTS credential_webauthn_spki_complete ON "control"."credential";
CREATE TRIGGER credential_webauthn_spki_complete BEFORE INSERT OR UPDATE ON "control"."credential"
FOR EACH ROW EXECUTE FUNCTION openpc.require_complete_security_record();
DO $ownership$
DECLARE owned_function record;
BEGIN
  FOR owned_function IN
    SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) arguments
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('openpc', 'control')
  LOOP
    EXECUTE format('ALTER FUNCTION %I.%I(%s) OWNER TO openpc_control_owner',
      owned_function.nspname, owned_function.proname, owned_function.arguments);
  END LOOP;
END
$ownership$;
REVOKE ALL ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM PUBLIC;
REVOKE ALL ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
GRANT EXECUTE ON FUNCTION openpc.require_uuid_setting(text), openpc.set_request_context(text,uuid,uuid,uuid,text,boolean), openpc.assert_request_context(boolean), openpc.matches_participant(uuid), openpc.matches_privacy(uuid), openpc.current_participant_id(), openpc.current_privacy_domain_id(), openpc.current_operation_id(), openpc.current_action_intent_id() TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" TO "openpc_control_runtime", "openpc_control_platform_runtime", "openpc_control_reader";
GRANT INSERT, UPDATE ON "control"."approval_request", "control"."assignment", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."oidc_transaction", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."session" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."approval_decision_record" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."authority_envelope", "control"."revocation" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE (state, checker_principal_id, row_version, updated_at) ON "control"."authority_envelope" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."mutation_evidence", "control"."outbox_event" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT, UPDATE (last_sequence, updated_at) ON "control"."outbox_aggregate_head" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."idempotency_record", "control"."outbox_aggregate_head", "control"."outbox_event" TO "openpc_control_worker";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE, DELETE ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" TO "openpc_control_maintenance";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" TO "openpc_backup_operator";
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA openpc REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
