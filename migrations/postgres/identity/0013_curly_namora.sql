-- OPENPC GENERATED REQUEST CONTEXT PREAMBLE; DO NOT EDIT
CREATE SCHEMA IF NOT EXISTS openpc;
CREATE OR REPLACE FUNCTION openpc.action_intent_semantic_digest(
  p_action_intent_id text, p_resource_type text, p_operation_class text, p_risk_class text,
  p_maker_checker_required boolean, p_step_up_required boolean, p_idempotency_required boolean,
  p_existence_disclosure text, p_payload_disclosure text, p_evidence_class text
) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog AS $$
  SELECT sha256(
    convert_to(p_action_intent_id, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_resource_type, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_operation_class, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_risk_class, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_maker_checker_required::text, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_step_up_required::text, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_idempotency_required::text, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_existence_disclosure, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_payload_disclosure, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_evidence_class, 'UTF8')
  )
$$;
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
  IF value IS NULL OR value !~ '^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$' THEN
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
     OR p_action_intent_id !~ '^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$' THEN
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
CREATE TYPE "control"."work_item_kind" AS ENUM('APPROVAL', 'REMEDIATION', 'DELIVERY_FAILURE', 'FLEET_FAILURE', 'EVIDENCE_BACKLOG');--> statement-breakpoint
CREATE TYPE "control"."work_item_state" AS ENUM('OPEN', 'CLAIMED', 'COMPLETED', 'CANCELLED');--> statement-breakpoint
CREATE TABLE "control"."work_item" (
	"work_item_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"kind" "control"."work_item_kind" NOT NULL,
	"state" "control"."work_item_state" DEFAULT 'OPEN' NOT NULL,
	"assignee_principal_id" uuid,
	"resource_ref" text NOT NULL,
	"payload_digest" "bytea" NOT NULL,
	"reason" varchar(1024) NOT NULL,
	"created_by_principal_id" uuid NOT NULL,
	"claimed_by_principal_id" uuid,
	"completed_by_principal_id" uuid,
	"row_version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "work_item_participant_id_uq" UNIQUE("participant_id","work_item_id"),
	CONSTRAINT "work_item_resource_ref_ck" CHECK ("control"."work_item"."resource_ref" ~ '^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
	CONSTRAINT "work_item_payload_digest_ck" CHECK (octet_length("control"."work_item"."payload_digest") = 32),
	CONSTRAINT "work_item_reason_ck" CHECK (length("control"."work_item"."reason") between 1 and 1024),
	CONSTRAINT "work_item_row_version_ck" CHECK ("control"."work_item"."row_version" > 0),
	CONSTRAINT "work_item_actor_state_ck" CHECK (("control"."work_item"."state" = 'OPEN' and "control"."work_item"."claimed_by_principal_id" is null and "control"."work_item"."completed_by_principal_id" is null)
          or ("control"."work_item"."state" = 'CLAIMED' and "control"."work_item"."claimed_by_principal_id" is not null and "control"."work_item"."completed_by_principal_id" is null)
          or ("control"."work_item"."state" = 'COMPLETED' and "control"."work_item"."claimed_by_principal_id" is not null and "control"."work_item"."completed_by_principal_id" is not null)
          or "control"."work_item"."state" = 'CANCELLED')
);
--> statement-breakpoint
ALTER TABLE "control"."work_item" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."work_item" ADD CONSTRAINT "work_item_participant_id_participant_participant_id_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."work_item" ADD CONSTRAINT "work_item_privacy_domain_fk" FOREIGN KEY ("participant_id","privacy_domain_id") REFERENCES "control"."privacy_domain"("participant_id","privacy_domain_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."work_item" ADD CONSTRAINT "work_item_assignee_fk" FOREIGN KEY ("participant_id","assignee_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."work_item" ADD CONSTRAINT "work_item_creator_fk" FOREIGN KEY ("participant_id","created_by_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."work_item" ADD CONSTRAINT "work_item_claimed_by_fk" FOREIGN KEY ("participant_id","claimed_by_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."work_item" ADD CONSTRAINT "work_item_completed_by_fk" FOREIGN KEY ("participant_id","completed_by_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."work_item" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."work_item"."participant_id")) WITH CHECK (openpc.matches_participant("control"."work_item"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."work_item" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      openpc.matches_participant("control"."work_item"."participant_id")
      and openpc.matches_privacy("control"."work_item"."privacy_domain_id")
    ) WITH CHECK (
      openpc.matches_participant("control"."work_item"."participant_id")
      and openpc.matches_privacy("control"."work_item"."privacy_domain_id")
    );
-- OPENPC GENERATED SECURITY TAIL; DO NOT EDIT
INSERT INTO "control"."action_intent"
  ("action_intent_id","resource_type","operation_class","risk_class",
   "maker_checker_required","step_up_required","idempotency_required",
   "existence_disclosure","payload_disclosure","evidence_class")
VALUES
  ('ACT-IDENTITY_CREATE_PENDING_DELIVERY-V1','pending-delivery','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','PENDING_DELIVERY_MUTATION'),
  ('ACT-IDENTITY_UPDATE_PENDING_DELIVERY-V1','pending-delivery','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','PENDING_DELIVERY_MUTATION')
ON CONFLICT ("action_intent_id") DO NOTHING;
DO $pending_delivery_actions$
BEGIN
  IF (SELECT count(*) FROM "control"."action_intent"
       WHERE ("action_intent_id","resource_type","operation_class","risk_class",
              "maker_checker_required","step_up_required","idempotency_required",
              "existence_disclosure","payload_disclosure","evidence_class") IN (
         ('ACT-IDENTITY_CREATE_PENDING_DELIVERY-V1','pending-delivery','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','PENDING_DELIVERY_MUTATION'),
         ('ACT-IDENTITY_UPDATE_PENDING_DELIVERY-V1','pending-delivery','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','PENDING_DELIVERY_MUTATION')
       )) <> 2 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'pending delivery internal action registration';
  END IF;
END
$pending_delivery_actions$;
CREATE OR REPLACE FUNCTION openpc.enforce_pending_delivery_lifecycle()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE captured_now timestamptz := clock_timestamp();
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.pending_delivery';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW."state" <> 'PENDING' OR NEW."lease_owner" IS NOT NULL
       OR NEW."lease_expires_at" IS NOT NULL OR NEW."next_retry_at" IS NOT NULL
       OR NEW."safe_reason" IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'pending delivery initial state';
    END IF;
    NEW."first_observed_at" := captured_now;
    NEW."last_observed_at" := captured_now;
    RETURN NEW;
  END IF;
  IF NEW."pending_delivery_id" is distinct from OLD."pending_delivery_id"
     OR row(NEW."participant_id",NEW."privacy_domain_id",NEW."chain_id",NEW."profile_id",NEW."profile_version",NEW."correlated_log_identity_hmac",NEW."entity_hmac",NEW."entity_scope_digest",NEW."delivery_surface",NEW."protected_delivery_reference_digest",NEW."subscription_reference_digest",NEW."session_reference_digest") is distinct from row(OLD."participant_id",OLD."privacy_domain_id",OLD."chain_id",OLD."profile_id",OLD."profile_version",OLD."correlated_log_identity_hmac",OLD."entity_hmac",OLD."entity_scope_digest",OLD."delivery_surface",OLD."protected_delivery_reference_digest",OLD."subscription_reference_digest",OLD."session_reference_digest") THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'pending delivery identity';
  END IF;
  IF NOT ((OLD."state" = 'PENDING' and NEW."state" = 'LEASED') or (OLD."state" = 'LEASED' and NEW."state" = 'DELIVERED') or (OLD."state" = 'LEASED' and NEW."state" = 'RETRY_WAIT') or (OLD."state" = 'RETRY_WAIT' and NEW."state" = 'LEASED') or (OLD."state" = 'PENDING' and NEW."state" = 'QUARANTINED') or (OLD."state" = 'LEASED' and NEW."state" = 'QUARANTINED') or (OLD."state" = 'RETRY_WAIT' and NEW."state" = 'QUARANTINED'))
     AND NOT (OLD."state" = 'LEASED' AND NEW."state" = 'LEASED'
              AND OLD."lease_expires_at" <= captured_now) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6022-INVALID-STATE-TRANSITION', DETAIL = 'pending delivery lifecycle';
  END IF;
  NEW."first_observed_at" := OLD."first_observed_at";
  NEW."last_observed_at" := captured_now;
  IF NEW."state" = 'LEASED' THEN
    IF NEW."lease_owner" IS NULL OR NEW."lease_expires_at" IS NULL
       OR NEW."lease_expires_at" <= captured_now THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'pending delivery lease';
    END IF;
    NEW."next_retry_at" := NULL;
    NEW."safe_reason" := NULL;
  ELSIF NEW."state" = 'RETRY_WAIT' THEN
    IF NEW."next_retry_at" IS NULL OR NEW."next_retry_at" <= captured_now THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'pending delivery retry';
    END IF;
    NEW."lease_owner" := NULL;
    NEW."lease_expires_at" := NULL;
    NEW."safe_reason" := NULL;
  ELSIF NEW."state" = 'QUARANTINED' THEN
    IF NEW."safe_reason" IS NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'pending delivery quarantine';
    END IF;
    NEW."lease_owner" := NULL;
    NEW."lease_expires_at" := NULL;
    NEW."next_retry_at" := NULL;
  ELSE
    NEW."lease_owner" := NULL;
    NEW."lease_expires_at" := NULL;
    NEW."next_retry_at" := NULL;
    NEW."safe_reason" := NULL;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS pending_delivery_lifecycle ON "control"."pending_delivery";
CREATE TRIGGER pending_delivery_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON "control"."pending_delivery"
FOR EACH ROW EXECUTE FUNCTION openpc.enforce_pending_delivery_lifecycle();
CREATE OR REPLACE FUNCTION openpc.enforce_work_item_lifecycle()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.work_item';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW."state" <> 'OPEN' OR NEW."row_version" <> 1
       OR NEW."claimed_by_principal_id" IS NOT NULL OR NEW."completed_by_principal_id" IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.work_item initial state';
    END IF;
    RETURN NEW;
  END IF;
  IF row(NEW."work_item_id",NEW."participant_id",NEW."privacy_domain_id",NEW."kind",
         NEW."resource_ref",NEW."created_by_principal_id",NEW."created_at")
     IS DISTINCT FROM
     row(OLD."work_item_id",OLD."participant_id",OLD."privacy_domain_id",OLD."kind",
         OLD."resource_ref",OLD."created_by_principal_id",OLD."created_at") THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.work_item identity';
  END IF;
  IF NOT ((OLD."state" = 'OPEN' AND NEW."state" = 'OPEN')
          OR (OLD."state" = 'OPEN' AND NEW."state" = 'CLAIMED')
          OR (OLD."state" = 'CLAIMED' AND NEW."state" = 'COMPLETED')
          OR (OLD."state" IN ('OPEN','CLAIMED') AND NEW."state" = 'CANCELLED')) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6022-INVALID-STATE-TRANSITION', DETAIL = 'control.work_item lifecycle';
  END IF;
  IF NEW."assignee_principal_id" IS DISTINCT FROM OLD."assignee_principal_id"
     AND NOT (OLD."state" = 'OPEN' AND NEW."state" = 'CLAIMED'
              AND OLD."assignee_principal_id" IS NULL) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.work_item assignee';
  END IF;
  IF NEW."row_version" <> OLD."row_version" + 1 OR NEW."updated_at" <= OLD."updated_at" THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.work_item revision';
  END IF;
  IF NEW."state" = 'OPEN' AND
     (NEW."claimed_by_principal_id" IS NOT NULL OR NEW."completed_by_principal_id" IS NOT NULL) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.work_item open actor';
  ELSIF NEW."state" = 'CLAIMED' AND
        (NEW."claimed_by_principal_id" IS NULL OR NEW."completed_by_principal_id" IS NOT NULL
         OR NEW."assignee_principal_id" IS DISTINCT FROM NEW."claimed_by_principal_id") THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.work_item claim actor';
  ELSIF NEW."state" = 'COMPLETED' AND
        (NEW."claimed_by_principal_id" IS NULL OR NEW."completed_by_principal_id" IS NULL
         OR NEW."completed_by_principal_id" IS DISTINCT FROM NEW."claimed_by_principal_id"
         OR NEW."assignee_principal_id" IS DISTINCT FROM NEW."completed_by_principal_id") THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.work_item completion actor';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS work_item_lifecycle ON "control"."work_item";
CREATE TRIGGER work_item_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON "control"."work_item"
FOR EACH ROW EXECUTE FUNCTION openpc.enforce_work_item_lifecycle();
UPDATE "control"."idempotency_record" AS idempotency
SET "webauthn_assertion_binding_digest" = evidence."webauthn_assertion_binding_digest"
FROM "control"."mutation_evidence" AS evidence
WHERE idempotency."participant_id" = evidence."participant_id"
  AND idempotency."operation_id" = evidence."operation_id"
  AND idempotency."catalog_operation_id" = 'ID-OP-WEBAUTHN-VERIFY'
  AND idempotency."webauthn_assertion_binding_digest" IS NULL
  AND evidence."catalog_operation_id" = 'ID-OP-WEBAUTHN-VERIFY'
  AND evidence."webauthn_assertion_binding_digest" IS NOT NULL;
DO $binding_upgrade$
BEGIN
  IF EXISTS (
    SELECT 1 FROM "control"."idempotency_record" AS idempotency
    WHERE idempotency."catalog_operation_id" = 'ID-OP-WEBAUTHN-VERIFY'
      AND NOT EXISTS (
        SELECT 1 FROM "control"."mutation_evidence" AS evidence
        JOIN "control"."outbox_event" AS outbox
          ON outbox."participant_id" = evidence."participant_id"
         AND outbox."aggregate_type" = 'webauthn-verification'
         AND outbox."webauthn_assertion_binding_digest" = evidence."webauthn_assertion_binding_digest"
        WHERE evidence."participant_id" = idempotency."participant_id"
          AND evidence."operation_id" = idempotency."operation_id"
          AND evidence."catalog_operation_id" = idempotency."catalog_operation_id"
          AND evidence."webauthn_assertion_binding_digest" = idempotency."webauthn_assertion_binding_digest"
          AND octet_length(evidence."webauthn_assertion_binding_digest") = 32
      )
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.idempotency_record WebAuthn binding upgrade';
  END IF;
END
$binding_upgrade$;
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
ALTER TABLE "control"."pending_delivery" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."principal" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."privacy_domain" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."recovery_challenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."revocation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."session" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."work_item" FORCE ROW LEVEL SECURITY;
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
ALTER TABLE "control"."pending_delivery" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."principal" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."privacy_domain" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."recovery_challenge" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."revocation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."session" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."work_item" OWNER TO "openpc_control_owner";
CREATE OR REPLACE FUNCTION openpc.reject_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
CREATE OR REPLACE FUNCTION openpc.require_complete_security_record()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE row_document jsonb := to_jsonb(NEW);
BEGIN
  IF TG_TABLE_NAME = 'idempotency_record' AND (
    row_document->>'catalog_operation_id' IN ('ID-OP-WEBAUTHN-VERIFY','POL-OP-ACTIVATE')
    AND row_document->>'webauthn_assertion_binding_digest' IS NULL
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  IF TG_TABLE_NAME = 'approval_decision_record' AND (
    row_document->>'approver_principal_epoch' IS NULL
    OR row_document->>'approver_authority_envelope_id' IS NULL
    OR row_document->>'approver_envelope_epoch' IS NULL
    OR row_document->>'approver_assignment_id' IS NULL
    OR row_document->>'signer_credential_id' IS NULL
    OR row_document->>'aggregate_version' IS NULL
    OR row_document->>'candidate_digest' IS NULL OR row_document->>'evidence_cbor' IS NULL
    OR (row_document->>'mfa_challenge_id' IS NOT NULL AND (
      row_document->>'approver_participant_epoch' IS NULL
      OR row_document->>'approver_assignment_row_version' IS NULL
      OR row_document->>'approver_delegation_epoch' IS NULL
    ))
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  IF TG_TABLE_NAME = 'mutation_evidence' AND (
    row_document->>'catalog_operation_id' = 'LEGACY'
    OR row_document->>'aggregate_version' IS NULL
    OR row_document->>'bound_authority_envelope_id' IS NULL
    OR row_document->>'bound_envelope_epoch' IS NULL
    OR row_document->>'bound_assignment_id' IS NULL
    OR (row_document->>'catalog_operation_id' IN ('ID-OP-WEBAUTHN-VERIFY','POL-OP-ACTIVATE')
        AND (row_document->>'webauthn_assertion_binding_digest' IS NULL
             OR row_document->>'signer_credential_id' IS NULL))
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  IF TG_TABLE_NAME = 'outbox_event' AND (
    row_document->>'aggregate_type' IN ('webauthn-verification','policy-activation')
    AND row_document->>'webauthn_assertion_binding_digest' IS NULL
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
DROP TRIGGER IF EXISTS idempotency_record_complete ON "control"."idempotency_record";
CREATE TRIGGER idempotency_record_complete BEFORE INSERT OR UPDATE ON "control"."idempotency_record"
FOR EACH ROW EXECUTE FUNCTION openpc.require_complete_security_record();
DROP TRIGGER IF EXISTS mutation_evidence_complete ON "control"."mutation_evidence";
CREATE TRIGGER mutation_evidence_complete BEFORE INSERT ON "control"."mutation_evidence"
FOR EACH ROW EXECUTE FUNCTION openpc.require_complete_security_record();
DROP TRIGGER IF EXISTS outbox_event_complete ON "control"."outbox_event";
CREATE TRIGGER outbox_event_complete BEFORE INSERT ON "control"."outbox_event"
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
REVOKE ALL ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM PUBLIC;
REVOKE ALL ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
GRANT EXECUTE ON FUNCTION openpc.require_uuid_setting(text), openpc.set_request_context(text,uuid,uuid,uuid,text,boolean), openpc.assert_request_context(boolean), openpc.matches_participant(uuid), openpc.matches_privacy(uuid), openpc.current_participant_id(), openpc.current_privacy_domain_id(), openpc.current_operation_id(), openpc.current_action_intent_id() TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" TO "openpc_control_runtime", "openpc_control_platform_runtime", "openpc_control_reader";
GRANT INSERT, UPDATE ON "control"."approval_request", "control"."assignment", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."oidc_transaction", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."session", "control"."work_item" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT (participant_id, privacy_domain_id, chain_id, profile_id, profile_version,
  correlated_log_identity_hmac, entity_hmac, entity_scope_digest, delivery_surface,
  protected_delivery_reference_digest, subscription_reference_digest,
  session_reference_digest, state) ON "control"."pending_delivery"
  TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE (state, lease_owner, lease_expires_at, next_retry_at, safe_reason)
  ON "control"."pending_delivery"
  TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."approval_decision_record" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."authority_envelope", "control"."revocation" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE (state, checker_principal_id, row_version, updated_at) ON "control"."authority_envelope" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."mutation_evidence", "control"."outbox_event" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT, UPDATE (last_sequence, updated_at) ON "control"."outbox_aggregate_head" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."idempotency_record", "control"."outbox_aggregate_head", "control"."outbox_event" TO "openpc_control_worker";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE, DELETE ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" TO "openpc_control_maintenance";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" TO "openpc_backup_operator";
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA openpc REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
