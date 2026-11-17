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
CREATE ROLE "openpc_control_maintenance" WITH NOINHERIT;--> statement-breakpoint
CREATE ROLE "openpc_control_migrator" WITH NOINHERIT;--> statement-breakpoint
CREATE TABLE "control"."mutation_evidence" (
	"mutation_evidence_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"operation_id" uuid NOT NULL,
	"principal_id" uuid NOT NULL,
	"checker_principal_id" uuid NOT NULL,
	"action_intent_id" varchar(160) NOT NULL,
	"aggregate_type" text NOT NULL,
	"aggregate_id" uuid NOT NULL,
	"candidate_digest" "bytea" NOT NULL,
	"approval_request_id" uuid NOT NULL,
	"mfa_challenge_id" uuid NOT NULL,
	"bound_participant_epoch" bigint NOT NULL,
	"bound_authority_epoch" bigint NOT NULL,
	"evidence_cbor" "bytea" NOT NULL,
	"evidence_digest" "bytea" NOT NULL,
	"cose_sign1" "bytea" NOT NULL,
	"occurred_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "mutation_evidence_evidence_digest_unique" UNIQUE("evidence_digest")
);
--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."outbox_aggregate_head" (
	"participant_id" uuid NOT NULL,
	"aggregate_type" text NOT NULL,
	"aggregate_id" uuid NOT NULL,
	"last_sequence" bigint DEFAULT 0 NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "outbox_aggregate_head_pk" PRIMARY KEY("participant_id","aggregate_type","aggregate_id"),
	CONSTRAINT "outbox_aggregate_head_sequence_ck" CHECK ("control"."outbox_aggregate_head"."last_sequence" >= 0)
);
--> statement-breakpoint
ALTER TABLE "control"."outbox_aggregate_head" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."mfa_challenge" ADD COLUMN "used_at" timestamp(6) with time zone;--> statement-breakpoint
ALTER TABLE "control"."mfa_challenge" ADD COLUMN "used_operation_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."oidc_transaction" ADD COLUMN "code_verifier_digest" "bytea" DEFAULT sha256(uuidv7()::text::bytea) NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."oidc_transaction" ADD COLUMN "browser_session_digest" "bytea" DEFAULT sha256(uuidv7()::text::bytea) NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."outbox_event" ADD COLUMN "privacy_domain_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD CONSTRAINT "mutation_evidence_participant_id_participant_participant_id_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD CONSTRAINT "mutation_evidence_action_intent_id_action_intent_action_intent_id_fk" FOREIGN KEY ("action_intent_id") REFERENCES "control"."action_intent"("action_intent_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD CONSTRAINT "mutation_evidence_privacy_domain_fk" FOREIGN KEY ("participant_id","privacy_domain_id") REFERENCES "control"."privacy_domain"("participant_id","privacy_domain_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD CONSTRAINT "mutation_evidence_principal_fk" FOREIGN KEY ("participant_id","principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD CONSTRAINT "mutation_evidence_checker_fk" FOREIGN KEY ("participant_id","checker_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."mutation_evidence" ADD CONSTRAINT "mutation_evidence_approval_fk" FOREIGN KEY ("participant_id","approval_request_id") REFERENCES "control"."approval_request"("participant_id","approval_request_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."outbox_aggregate_head" ADD CONSTRAINT "outbox_aggregate_head_participant_id_participant_participant_id_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "mutation_evidence_operation_uq" ON "control"."mutation_evidence" USING btree ("participant_id","operation_id");--> statement-breakpoint
ALTER TABLE "control"."outbox_event" ADD CONSTRAINT "outbox_event_privacy_domain_fk" FOREIGN KEY ("participant_id","privacy_domain_id") REFERENCES "control"."privacy_domain"("participant_id","privacy_domain_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."oidc_transaction" DROP COLUMN "code_verifier";--> statement-breakpoint
ALTER TABLE "control"."oidc_transaction" ADD CONSTRAINT "oidc_transaction_code_verifier_digest_unique" UNIQUE("code_verifier_digest");--> statement-breakpoint
ALTER TABLE "control"."mfa_challenge" ADD CONSTRAINT "mfa_challenge_use_ck" CHECK (("control"."mfa_challenge"."used_at" is null) = ("control"."mfa_challenge"."used_operation_id" is null));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."approval_decision_record" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      openpc.matches_participant("control"."approval_decision_record"."participant_id")
      and openpc.matches_privacy("control"."approval_decision_record"."privacy_domain_id")
    ) WITH CHECK (
      openpc.matches_participant("control"."approval_decision_record"."participant_id")
      and openpc.matches_privacy("control"."approval_decision_record"."privacy_domain_id")
    );--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."approval_request" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      openpc.matches_participant("control"."approval_request"."participant_id")
      and openpc.matches_privacy("control"."approval_request"."privacy_domain_id")
    ) WITH CHECK (
      openpc.matches_participant("control"."approval_request"."participant_id")
      and openpc.matches_privacy("control"."approval_request"."privacy_domain_id")
    );--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."outbox_event" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      openpc.matches_participant("control"."outbox_event"."participant_id")
      and openpc.matches_privacy("control"."outbox_event"."privacy_domain_id")
    ) WITH CHECK (
      openpc.matches_participant("control"."outbox_event"."participant_id")
      and openpc.matches_privacy("control"."outbox_event"."privacy_domain_id")
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."mutation_evidence" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."mutation_evidence"."participant_id")) WITH CHECK (openpc.matches_participant("control"."mutation_evidence"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."mutation_evidence" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      openpc.matches_participant("control"."mutation_evidence"."participant_id")
      and openpc.matches_privacy("control"."mutation_evidence"."privacy_domain_id")
    ) WITH CHECK (
      openpc.matches_participant("control"."mutation_evidence"."participant_id")
      and openpc.matches_privacy("control"."mutation_evidence"."privacy_domain_id")
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."outbox_aggregate_head" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."outbox_aggregate_head"."participant_id")) WITH CHECK (openpc.matches_participant("control"."outbox_aggregate_head"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."assignment" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."assignment"."participant_id")) WITH CHECK (openpc.matches_participant("control"."assignment"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."authority_envelope" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."authority_envelope"."participant_id")) WITH CHECK (openpc.matches_participant("control"."authority_envelope"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."authority_group_member" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."authority_group_member"."participant_id")) WITH CHECK (openpc.matches_participant("control"."authority_group_member"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."authority_group" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."authority_group"."participant_id")) WITH CHECK (openpc.matches_participant("control"."authority_group"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."delegation" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."delegation"."participant_id")) WITH CHECK (openpc.matches_participant("control"."delegation"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."revocation" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."revocation"."participant_id")) WITH CHECK (openpc.matches_participant("control"."revocation"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."credential" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."credential"."participant_id")) WITH CHECK (openpc.matches_participant("control"."credential"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."mfa_challenge" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."mfa_challenge"."participant_id")) WITH CHECK (openpc.matches_participant("control"."mfa_challenge"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."participant" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."participant"."participant_id")) WITH CHECK (openpc.matches_participant("control"."participant"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."principal" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."principal"."participant_id")) WITH CHECK (openpc.matches_participant("control"."principal"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."privacy_domain" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."privacy_domain"."participant_id")) WITH CHECK (openpc.matches_participant("control"."privacy_domain"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."recovery_challenge" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."recovery_challenge"."participant_id")) WITH CHECK (openpc.matches_participant("control"."recovery_challenge"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."session" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."session"."participant_id")) WITH CHECK (openpc.matches_participant("control"."session"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."approval_decision_record" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."approval_decision_record"."participant_id")) WITH CHECK (openpc.matches_participant("control"."approval_decision_record"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."approval_request" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."approval_request"."participant_id")) WITH CHECK (openpc.matches_participant("control"."approval_request"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."idempotency_record" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."idempotency_record"."participant_id")) WITH CHECK (openpc.matches_participant("control"."idempotency_record"."participant_id"));--> statement-breakpoint
ALTER POLICY "participant_isolation" ON "control"."outbox_event" TO openpc_control_platform_runtime,openpc_control_reader,openpc_control_runtime,openpc_control_worker USING (openpc.matches_participant("control"."outbox_event"."participant_id")) WITH CHECK (openpc.matches_participant("control"."outbox_event"."participant_id"));
-- OPENPC GENERATED SECURITY TAIL; DO NOT EDIT
ALTER ROLE "openpc_control_owner" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_migrator" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT BYPASSRLS;
ALTER ROLE "openpc_control_runtime" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_worker" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_platform_runtime" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_reader" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_maintenance" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT BYPASSRLS;
GRANT "openpc_control_owner" TO "openpc_control_migrator";
ALTER SCHEMA openpc OWNER TO "openpc_control_owner";
ALTER SCHEMA control OWNER TO "openpc_control_owner";
REVOKE ALL ON DATABASE "openpc_control" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE "openpc_control" TO "openpc_control_migrator";
GRANT CONNECT ON DATABASE "openpc_control" TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance";
REVOKE ALL ON SCHEMA public, openpc, control FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA openpc, control TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance";
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
REVOKE ALL ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM PUBLIC;
REVOKE ALL ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance";
GRANT EXECUTE ON FUNCTION openpc.require_uuid_setting(text), openpc.set_request_context(text,uuid,uuid,uuid,text,boolean), openpc.assert_request_context(boolean), openpc.matches_participant(uuid), openpc.matches_privacy(uuid), openpc.current_participant_id(), openpc.current_privacy_domain_id(), openpc.current_operation_id(), openpc.current_action_intent_id() TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" TO "openpc_control_runtime", "openpc_control_platform_runtime", "openpc_control_reader";
GRANT INSERT, UPDATE ON "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."oidc_transaction", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."session" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."authority_envelope", "control"."revocation" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."mutation_evidence", "control"."outbox_event" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT, UPDATE (last_sequence, updated_at) ON "control"."outbox_aggregate_head" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."idempotency_record", "control"."outbox_aggregate_head", "control"."outbox_event" TO "openpc_control_worker";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE, DELETE ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" TO "openpc_control_maintenance";
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA openpc REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
