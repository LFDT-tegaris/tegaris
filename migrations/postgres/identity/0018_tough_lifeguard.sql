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
ALTER TABLE "control"."business_signing_key" DROP CONSTRAINT "business_signing_key_secret_ck";--> statement-breakpoint
ALTER TABLE "control"."business_signing_key" ADD CONSTRAINT "business_signing_key_secret_ck" CHECK ("control"."business_signing_key"."secret_class"='SECRET-SIGNING-KEY' and "control"."business_signing_key"."secret_reference" ~ '^secret://[a-z][a-z0-9-]{1,31}/[A-Za-z0-9._/-]{1,192}#[A-Za-z0-9._-]{1,96}$' and split_part("control"."business_signing_key"."secret_reference",'#',2)="control"."business_signing_key"."secret_version" and lower("control"."business_signing_key"."secret_version") not in ('latest','current'));
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
CREATE OR REPLACE FUNCTION openpc.enforce_mutation_candidate_lifecycle()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.mutation_candidate';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW."state" <> 'PROPOSED' OR NEW."consumed_operation_id" IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.mutation_candidate initial state';
    END IF;
    RETURN NEW;
  END IF;
  IF row(NEW."mutation_candidate_id",NEW."participant_id",NEW."privacy_domain_id",
         NEW."action_intent_id",NEW."catalog_operation_id",NEW."resource_type",
         NEW."operation_class",NEW."resource_id",NEW."candidate_digest",
         NEW."candidate_document",NEW."expected_revision",NEW."idempotency_key",
         NEW."maker_principal_id",NEW."maker_session_id",NEW."maker_session_epoch",
         NEW."maker_participant_epoch",NEW."maker_principal_epoch",NEW."maker_assignment_id",
         NEW."maker_assignment_row_version",NEW."maker_authority_envelope_id",
         NEW."maker_authority_epoch",NEW."maker_delegation_epoch",NEW."expires_at",NEW."created_at")
     IS DISTINCT FROM
     row(OLD."mutation_candidate_id",OLD."participant_id",OLD."privacy_domain_id",
         OLD."action_intent_id",OLD."catalog_operation_id",OLD."resource_type",
         OLD."operation_class",OLD."resource_id",OLD."candidate_digest",
         OLD."candidate_document",OLD."expected_revision",OLD."idempotency_key",
         OLD."maker_principal_id",OLD."maker_session_id",OLD."maker_session_epoch",
         OLD."maker_participant_epoch",OLD."maker_principal_epoch",OLD."maker_assignment_id",
         OLD."maker_assignment_row_version",OLD."maker_authority_envelope_id",
         OLD."maker_authority_epoch",OLD."maker_delegation_epoch",OLD."expires_at",OLD."created_at") THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.mutation_candidate identity';
  END IF;
  IF NOT ((OLD."state" = 'PROPOSED' AND NEW."state" IN ('APPROVAL_REQUESTED','CANCELLED'))
          OR (OLD."state" = 'APPROVAL_REQUESTED' AND NEW."state" IN ('APPROVAL_REQUESTED','APPROVED','CANCELLED'))
          OR (OLD."state" = 'APPROVED' AND NEW."state" = 'CONSUMED')) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6022-INVALID-STATE-TRANSITION', DETAIL = 'control.mutation_candidate lifecycle';
  END IF;
  IF NEW."updated_at" <= OLD."updated_at"
     OR ((NEW."state" = 'CONSUMED') <> (NEW."consumed_operation_id" IS NOT NULL)) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.mutation_candidate transition';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS mutation_candidate_lifecycle ON "control"."mutation_candidate";
CREATE TRIGGER mutation_candidate_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON "control"."mutation_candidate"
FOR EACH ROW EXECUTE FUNCTION openpc.enforce_mutation_candidate_lifecycle();
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
ALTER TABLE "control"."audit_occurrence" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_envelope" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_group" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_group_member" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."business_outbox_head" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."business_signing_grant" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."business_signing_key" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."business_signing_key_state" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."business_signing_selection" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."credential" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."delegation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."evidence_record" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."idempotency_record" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."mfa_challenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."mutation_candidate" FORCE ROW LEVEL SECURITY;
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
ALTER TABLE "control"."audit_occurrence" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_envelope" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_group" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_group_member" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_outbox_head" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_signing_grant" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_signing_key" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_signing_key_state" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_signing_selection" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_transition_profile" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."credential" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."delegation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."evidence_record" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."idempotency_record" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."mfa_challenge" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."mutation_candidate" OWNER TO "openpc_control_owner";
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

CREATE OR REPLACE FUNCTION openpc.business_cbor_item(data bytea, byte_offset integer, depth integer DEFAULT 0)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE
  initial integer; major integer; additional integer; width integer; cursor integer;
  argument numeric := 0; value jsonb; child jsonb; key_item jsonb; key_number numeric;
  previous_key numeric := -1; i integer; bytes bytea; decoded text;
BEGIN
  IF octet_length(data)>66560 OR byte_offset<0 OR byte_offset>=octet_length(data) OR depth>8 THEN
    RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR';
  END IF;
  initial:=get_byte(data,byte_offset); major:=initial/32; additional:=initial%32; cursor:=byte_offset+1;
  IF additional<24 THEN argument:=additional;
  ELSE
    width:=CASE additional WHEN 24 THEN 1 WHEN 25 THEN 2 WHEN 26 THEN 4 WHEN 27 THEN 8 ELSE 0 END;
    IF width=0 OR cursor+width>octet_length(data) THEN RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR'; END IF;
    FOR i IN 0..width-1 LOOP argument:=argument*256+get_byte(data,cursor+i); END LOOP;
    cursor:=cursor+width;
    IF (width=1 AND argument<24) OR (width=2 AND argument<=255) OR
       (width=4 AND argument<=65535) OR (width=8 AND argument<=4294967295) THEN
      RAISE EXCEPTION 'DATA-6021-NONCANONICAL-BUSINESS-CBOR';
    END IF;
  END IF;
  CASE major
    WHEN 0 THEN value:=to_jsonb(argument);
    WHEN 1 THEN value:=to_jsonb(-1-argument);
    WHEN 2,3 THEN
      IF argument>65536 OR cursor+argument>octet_length(data) THEN RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR'; END IF;
      bytes:=substring(data FROM cursor+1 FOR argument::integer); cursor:=cursor+argument::integer;
      IF major=2 THEN value:=jsonb_build_object('bytes',encode(bytes,'hex'));
      ELSE
        decoded:=convert_from(bytes,'UTF8');
        IF normalize(decoded,NFC)<>decoded OR convert_to(decoded,'UTF8')<>bytes THEN
          RAISE EXCEPTION 'DATA-6021-NONCANONICAL-BUSINESS-CBOR';
        END IF;
        value:=to_jsonb(decoded);
      END IF;
    WHEN 4 THEN
      IF argument>256 THEN RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR'; END IF;
      value:='[]'::jsonb;
      FOR i IN 1..argument::integer LOOP
        child:=openpc.business_cbor_item(data,cursor,depth+1);
        value:=value||jsonb_build_array(child->'value'); cursor:=(child->>'next')::integer;
      END LOOP;
    WHEN 5 THEN
      IF argument>256 THEN RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR'; END IF;
      value:='{}'::jsonb;
      FOR i IN 1..argument::integer LOOP
        IF cursor>=octet_length(data) OR get_byte(data,cursor)/32<>0 THEN
          RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR-MAP-KEY';
        END IF;
        key_item:=openpc.business_cbor_item(data,cursor,depth+1); key_number:=(key_item->>'value')::numeric;
        IF key_number<=previous_key OR key_number>4294967295 THEN RAISE EXCEPTION 'DATA-6021-NONCANONICAL-BUSINESS-CBOR-MAP'; END IF;
        previous_key:=key_number; cursor:=(key_item->>'next')::integer;
        child:=openpc.business_cbor_item(data,cursor,depth+1);
        value:=value||jsonb_build_object(key_number::text,child->'value'); cursor:=(child->>'next')::integer;
      END LOOP;
    ELSE RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR-TYPE';
  END CASE;
  RETURN jsonb_build_object('value',value,'next',cursor);
END $$;
CREATE OR REPLACE FUNCTION openpc.business_cbor(data bytea)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE decoded jsonb;
BEGIN
  IF octet_length(data)>65536 THEN RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR'; END IF;
  decoded:=openpc.business_cbor_item(data,0,0);
  IF (decoded->>'next')::integer<>octet_length(data) THEN RAISE EXCEPTION 'DATA-6021-TRAILING-BUSINESS-CBOR'; END IF;
  RETURN decoded->'value';
END $$;
CREATE OR REPLACE FUNCTION openpc.business_bytes(data bytea)
RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('bytes',encode(data,'hex'))
$$;
CREATE OR REPLACE FUNCTION openpc.business_uuid(id uuid)
RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
 SELECT openpc.business_bytes(uuid_send(id))
$$;

CREATE OR REPLACE FUNCTION openpc.business_request_digest(binding text[])
RETURNS bytea LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE preimage bytea:=convert_to('pc.control.configuration-request.v1','UTF8')||decode('00','hex'); value text; bytes bytea;
BEGIN
 IF cardinality(binding)<>10 THEN RAISE EXCEPTION 'DATA-6021-REQUEST-BINDING'; END IF;
 FOREACH value IN ARRAY binding LOOP
  IF value IS NULL OR octet_length(value) NOT BETWEEN 1 AND 256 OR normalize(value,NFC)<>value THEN
    RAISE EXCEPTION 'DATA-6021-REQUEST-BINDING'; END IF;
  bytes:=convert_to(value,'UTF8');preimage:=preimage||int4send(octet_length(bytes))||bytes;
 END LOOP;
 RETURN sha256(preimage);
END $$;

DO $role$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='openpc_control_key_governor') THEN
  CREATE ROLE openpc_control_key_governor NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
 END IF;
END $role$;
CREATE OR REPLACE FUNCTION openpc.check_business_signing_trust()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE key_row control.business_signing_key%ROWTYPE; grants jsonb; actual jsonb; expected jsonb;
BEGIN
 SELECT * INTO STRICT key_row FROM control.business_signing_key
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND signer_id=NEW.signer_id;
 SELECT jsonb_agg(jsonb_build_array(p.profile_id,p.profile_version,openpc.business_bytes(p.profile_digest),
   p.action_intent_id,p.catalog_operation_id) ORDER BY convert_to(p.profile_id,'UTF8'),p.profile_version)
 INTO grants FROM control.business_signing_grant g JOIN control.business_transition_profile p USING(profile_digest)
 WHERE g.participant_id=key_row.participant_id AND g.privacy_domain_id=key_row.privacy_domain_id AND g.signer_id=key_row.signer_id;
 IF grants IS NULL OR jsonb_array_length(grants) NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-SIGNING-GRANTS'; END IF;
 actual:=openpc.business_cbor(key_row.trust_preimage);
 expected:=jsonb_build_array('pc.control.business-signing-trust.v1',openpc.business_uuid(key_row.participant_id),
   openpc.business_uuid(key_row.privacy_domain_id),key_row.environment_id,key_row.signer_id,
   openpc.business_bytes(key_row.public_key_spki_der),openpc.business_uuid(key_row.workload_credential_id),
   key_row.workload_credential_epoch,key_row.key_epoch,key_row.valid_from_ns,key_row.valid_until_ns,
   key_row.admission_kind,key_row.admission_reference,openpc.business_bytes(key_row.admission_digest),
   key_row.secret_class,key_row.secret_reference,key_row.secret_version,24001,1,338,grants);
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-SIGNING-TRUST-BINDING'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal p USING(participant_id,principal_id)
  WHERE c.participant_id=key_row.participant_id AND c.credential_id=key_row.workload_credential_id
    AND p.kind='WORKLOAD' AND c.kind IN ('WORKLOAD_OIDC','WORKLOAD_MTLS')
    AND c.credential_epoch=key_row.workload_credential_epoch
    AND c.public_key_digest IS DISTINCT FROM sha256(key_row.public_key_spki_der)) THEN
   RAISE EXCEPTION 'DATA-6021-SIGNING-WORKLOAD-BINDING';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS business_signing_key_complete ON control.business_signing_key;
CREATE CONSTRAINT TRIGGER business_signing_key_complete AFTER INSERT ON control.business_signing_key
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_business_signing_trust();
DROP TRIGGER IF EXISTS business_signing_grant_complete ON control.business_signing_grant;
CREATE CONSTRAINT TRIGGER business_signing_grant_complete AFTER INSERT ON control.business_signing_grant
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_business_signing_trust();
CREATE OR REPLACE FUNCTION openpc.guard_business_key_lifecycle()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE key_row control.business_signing_key%ROWTYPE;
BEGIN
 IF NOT pg_has_role(current_user,'openpc_control_key_governor','MEMBER') AND
    NOT pg_has_role(current_user,'openpc_control_owner','MEMBER') THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='PC-AUTH-0005-KEY-GOVERNANCE-REQUIRED';
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-KEY-HISTORY'; END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.participant_id<>OLD.participant_id OR NEW.privacy_domain_id<>OLD.privacy_domain_id OR
     NEW.row_version<>OLD.row_version+1 OR NEW.changed_at_ns<OLD.changed_at_ns OR
     NEW.change_digest=OLD.change_digest THEN RAISE EXCEPTION 'DATA-6021-KEY-LIFECYCLE-REVISION'; END IF;
  IF TG_TABLE_NAME='business_signing_key_state' THEN
   IF NEW.signer_id<>OLD.signer_id OR NOT (
     (OLD.state='ADMITTED' AND NEW.state IN ('ACTIVE','REVOKED','COMPROMISED')) OR
     (OLD.state='ACTIVE' AND NEW.state IN ('RETIRED','REVOKED','COMPROMISED')) OR
     (OLD.state='RETIRED' AND NEW.state IN ('REVOKED','COMPROMISED')) OR
     (OLD.state='REVOKED' AND NEW.state='COMPROMISED')) THEN RAISE EXCEPTION 'DATA-6021-KEY-LIFECYCLE-TRANSITION'; END IF;
  ELSE
   IF NEW.environment_id<>OLD.environment_id OR NEW.profile_digest<>OLD.profile_digest OR
      NEW.signer_id=OLD.signer_id THEN RAISE EXCEPTION 'DATA-6021-KEY-SELECTION-TRANSITION'; END IF;
  END IF;
 ELSE
  IF NEW.row_version<>1 THEN RAISE EXCEPTION 'DATA-6021-KEY-LIFECYCLE-REVISION'; END IF;
  IF TG_TABLE_NAME='business_signing_key_state' THEN
   IF NEW.state<>'ADMITTED' THEN RAISE EXCEPTION 'DATA-6021-KEY-LIFECYCLE-TRANSITION'; END IF;
  END IF;
 END IF;
 IF TG_TABLE_NAME='business_signing_selection' THEN
  SELECT k.* INTO STRICT key_row FROM control.business_signing_key k
   JOIN control.business_signing_key_state s USING(participant_id,privacy_domain_id,signer_id)
   WHERE k.participant_id=NEW.participant_id AND k.privacy_domain_id=NEW.privacy_domain_id
    AND k.signer_id=NEW.signer_id AND k.environment_id=NEW.environment_id AND s.state='ACTIVE'
    AND k.valid_from_ns<=floor(extract(epoch FROM clock_timestamp())*1000000)*1000
    AND k.valid_until_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000 FOR SHARE OF s;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS business_signing_state_guard ON control.business_signing_key_state;
CREATE TRIGGER business_signing_state_guard BEFORE INSERT OR UPDATE OR DELETE ON control.business_signing_key_state
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_key_lifecycle();
DROP TRIGGER IF EXISTS business_signing_selection_guard ON control.business_signing_selection;
CREATE TRIGGER business_signing_selection_guard BEFORE INSERT OR UPDATE OR DELETE ON control.business_signing_selection
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_key_lifecycle();

CREATE OR REPLACE FUNCTION openpc.guard_business_profile_admission()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.definition_canonical_json NOT IN (decode('7b22616374696f6e496e74656e744964223a224143542d494e44455845525f50524f46494c45535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a22696e64657865722d70726f66696c65222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d4352454154452d494e44455845522d50524f46494c45222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e696e64657865722d70726f66696c652e637265617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22696e64657865722d70726f66696c6573222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22696e64657865725f70726f66696c655f6964225d2c226f776e6572223a22636f6e74726f6c2e696e64657865725f70726f66696c65222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22656e67696e65222c22656e756d223a5b22434c49454e545f494e4445584552222c2245585445524e414c5f454e47494e455f41444150544552225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a22656e67696e655f76657273696f6e222c227061747465726e223a225e5b412d5a612d7a302d395d5b412d5a612d7a302d392e5f2d5d7b302c36337d24222c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a226d6574686f645f70726f66696c655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b2252454749535445524544222c22534841444f57222c225155414c4946494544222c22414354495645222c2251554152414e54494e4544222c2252455449524544225d2c2274797065223a2254455854227d2c2234223a7b22636f6c756d6e223a22706f6c6963795f67656e65726174696f6e5f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f524547495354455245445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a2272657175657374656420656e67696e652c20656e67696e6556657273696f6e2c206d6574686f6450726f66696c654469676573743b2061637475616c20706f6c69637947656e65726174696f6e446967657374222c22636f6d6d616e64223a22435245415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d494e44455845525f50524f46494c45535f5550444154455f5245534f555243452d5631222c2261676772656761746554797065223a22696e64657865722d70726f66696c65222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d5550444154452d494e44455845522d50524f46494c45222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e696e64657865722d70726f66696c652e757064617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22696e64657865722d70726f66696c6573222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22696e64657865725f70726f66696c655f6964225d2c226f776e6572223a22636f6e74726f6c2e696e64657865725f70726f66696c65222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22656e67696e65222c22656e756d223a5b22434c49454e545f494e4445584552222c2245585445524e414c5f454e47494e455f41444150544552225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a22656e67696e655f76657273696f6e222c227061747465726e223a225e5b412d5a612d7a302d395d5b412d5a612d7a302d392e5f2d5d7b302c36337d24222c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a226d6574686f645f70726f66696c655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b2252454749535445524544222c22534841444f57222c225155414c4946494544222c22414354495645222c2251554152414e54494e4544222c2252455449524544225d2c2274797065223a2254455854227d2c2234223a7b22636f6c756d6e223a22706f6c6963795f67656e65726174696f6e5f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5245564953494f4e5f504c55535f4f4e45222c226265666f7265223a2250524553454e545f41545f45585045435445445f5245564953494f4e222c226368616e6765223a22726571756573746564207265706c6163656d656e74206d6574686f6450726f66696c654469676573743b20707265736572766520656e67696e652c20656e67696e6556657273696f6e2c2073746174653b206d6574686f6450726f66696c65446967657374206f7220706f6c69637947656e65726174696f6e446967657374206d757374206368616e6765222c22636f6d6d616e64223a22555044415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex')) THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-BUSINESS-PROFILE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS business_profile_admission ON control.business_transition_profile;
CREATE TRIGGER business_profile_admission BEFORE INSERT ON control.business_transition_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_profile_admission();
CREATE OR REPLACE FUNCTION openpc.guard_business_receipt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE actual jsonb; expected jsonb; before_state jsonb; after_state jsonb; proof jsonb;
 profile control.business_transition_profile%ROWTYPE; authorization_row control.mutation_evidence%ROWTYPE; runtime_payload jsonb; runtime_cose jsonb; runtime_header jsonb; outer_cose jsonb; protected_header jsonb;
BEGIN
 actual:=openpc.business_cbor(NEW.receipt_cbor);
 SELECT * INTO STRICT profile FROM control.business_transition_profile WHERE profile_digest=NEW.profile_digest;
 IF NEW.schema_definition_digest<>profile.schema_definition_digest OR NEW.action_intent_id<>profile.action_intent_id OR
    NEW.catalog_operation_id<>profile.catalog_operation_id OR NEW.aggregate_type<>profile.aggregate_type OR
    NEW.transition_kind<>profile.transition_kind THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-PROFILE-BINDING'; END IF;
 expected:=jsonb_build_object('0',openpc.business_uuid(NEW.receipt_id),'1',openpc.business_bytes(NEW.schema_definition_digest),
  '2',NEW.profile_id,'3',NEW.profile_version,'4',openpc.business_bytes(NEW.profile_digest),'5',NEW.environment_id,
  '6',openpc.business_uuid(NEW.participant_id),'7',openpc.business_uuid(NEW.privacy_domain_id),
  '8',openpc.business_uuid(NEW.operation_id),'9',NEW.action_intent_id,'10',NEW.catalog_operation_id,
  '11',NEW.aggregate_type,'12',openpc.business_uuid(NEW.aggregate_id),'13',openpc.business_bytes(NEW.actor_key_digest),
  '14',openpc.business_bytes(NEW.pre_commit_authority_digest),'15',openpc.business_bytes(NEW.action_intent_digest),
  '16',openpc.business_bytes(NEW.candidate_digest),'17',openpc.business_uuid(NEW.idempotency_record_id),
  '18',jsonb_build_object('0',NEW.before_existence,'1',NEW.before_revision,'2',openpc.business_bytes(NEW.before_state_digest)),
  '19',jsonb_build_object('0',NEW.after_existence,'1',NEW.after_revision,'2',openpc.business_bytes(NEW.after_state_digest)),
  '20',actual->'20','21',actual->'21','22',NEW.transition_kind,'23',NEW.recorded_at_ns,
  '24',NEW.signer_id,'25',openpc.business_bytes(NEW.signer_trust_snapshot_digest),'26',openpc.business_bytes(NEW.request_digest));
 IF actual IS DISTINCT FROM expected OR octet_length(NEW.actor_key_digest)<>32 OR
    octet_length(NEW.action_intent_digest)<>32 OR octet_length(NEW.candidate_digest)<>32 OR
    octet_length(NEW.request_digest)<>32 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-TYPED-BINDING'; END IF;
 IF get_byte(NEW.cose_sign1,0)<>210 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-COSE-TAG'; END IF;
 outer_cose:=openpc.business_cbor_item(NEW.cose_sign1,1,0);
 IF (outer_cose->>'next')::integer<>octet_length(NEW.cose_sign1) THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-COSE-TRAILING'; END IF;
 outer_cose:=outer_cose->'value';
 IF jsonb_typeof(outer_cose)<>'array' OR jsonb_array_length(outer_cose)<>4 OR outer_cose->1<>'{}'::jsonb OR
    outer_cose->2 IS DISTINCT FROM openpc.business_bytes(NEW.receipt_cbor) OR
    length(outer_cose->3->>'bytes') IS DISTINCT FROM 128 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-COSE-BINDING'; END IF;
 protected_header:=openpc.business_cbor(decode(outer_cose->0->>'bytes','hex'));
 IF protected_header IS DISTINCT FROM jsonb_build_object('1',-7,'2',jsonb_build_array(100,101,102,103),
  '3','application/pc+cbor','4',openpc.business_bytes(convert_to(NEW.signer_id,'UTF8')),
  '100',24001,'101',1,'102',338,'103',2) THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-COSE-CONTEXT'; END IF;
 before_state:=openpc.business_cbor(NEW.before_state_preimage);
 after_state:=openpc.business_cbor(NEW.after_state_preimage);
 IF before_state IS DISTINCT FROM jsonb_build_array('pc.control.transition-state.v1',openpc.business_bytes(NEW.profile_digest),
  openpc.business_uuid(NEW.participant_id),openpc.business_uuid(NEW.privacy_domain_id),NEW.aggregate_type,
  openpc.business_uuid(NEW.aggregate_id),NEW.before_existence,NEW.before_revision,before_state->8) OR
  after_state IS DISTINCT FROM jsonb_build_array('pc.control.transition-state.v1',openpc.business_bytes(NEW.profile_digest),
  openpc.business_uuid(NEW.participant_id),openpc.business_uuid(NEW.privacy_domain_id),NEW.aggregate_type,
  openpc.business_uuid(NEW.aggregate_id),NEW.after_existence,NEW.after_revision,after_state->8) OR
  (NEW.before_existence=0 AND before_state->8<>'{}'::jsonb) THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-STATE-BINDING'; END IF;
 IF jsonb_typeof(actual->'20') IS DISTINCT FROM 'array' OR jsonb_array_length(actual->'20')<>1 OR
    jsonb_typeof(actual->'21') IS DISTINCT FROM 'array' OR jsonb_array_length(actual->'21')<>1 THEN
  RAISE EXCEPTION 'DATA-6021-RECEIPT-PROFILE-CARDINALITY'; END IF;
 proof:=actual->'20'->0;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence e
   WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id
    AND e.operation_id=NEW.operation_id AND e.action_intent_id=NEW.action_intent_id
    AND e.catalog_operation_id=NEW.catalog_operation_id AND e.aggregate_id=NEW.aggregate_id
    AND e.candidate_digest=NEW.candidate_digest AND e.evidence_digest=sha256(e.evidence_cbor)
    AND e.evidence_role='AUTHORIZATION_INPUT' AND e.evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
    AND proof=jsonb_build_object('0',2,'1',e.mutation_evidence_id::text,'2',openpc.business_bytes(e.evidence_digest))) THEN
  RAISE EXCEPTION 'DATA-6021-RECEIPT-AUTHORIZATION-OWNER'; END IF;

 SELECT * INTO STRICT authorization_row FROM control.mutation_evidence e WHERE e.participant_id=NEW.participant_id
  AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id;
 runtime_payload:=openpc.business_cbor(authorization_row.evidence_cbor);
 IF get_byte(authorization_row.cose_sign1,0)<>210 THEN RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-TAG'; END IF;
 runtime_cose:=openpc.business_cbor_item(authorization_row.cose_sign1,1,0);
 IF (runtime_cose->>'next')::integer<>octet_length(authorization_row.cose_sign1) THEN RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-TRAILING'; END IF;
 runtime_cose:=runtime_cose->'value';
 IF jsonb_typeof(runtime_cose) IS DISTINCT FROM 'array' OR jsonb_array_length(runtime_cose)<>4 OR
    runtime_cose->1 IS DISTINCT FROM '{}'::jsonb OR runtime_cose->2 IS DISTINCT FROM openpc.business_bytes(authorization_row.evidence_cbor) OR
    length(runtime_cose->3->>'bytes') IS DISTINCT FROM 128 THEN RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-BINDING'; END IF;
 runtime_header:=openpc.business_cbor(decode(runtime_cose->0->>'bytes','hex'));
 IF runtime_header IS DISTINCT FROM jsonb_build_object('1',-7,'2',jsonb_build_array(100,101,102,103),'3','application/pc+cbor',
    '4',runtime_header->'4','100',3002,'101',2,'102',13,'103',2) OR
    length(runtime_header->'4'->>'bytes') IS DISTINCT FROM 64 OR
    'sha256:'||(runtime_header->'4'->>'bytes')=NEW.signer_id OR
    runtime_payload->'1' IS DISTINCT FROM openpc.business_bytes(NEW.actor_key_digest) OR
    jsonb_typeof(runtime_payload->'8') IS DISTINCT FROM 'number' OR jsonb_typeof(runtime_payload->'9') IS DISTINCT FROM 'number' OR
    (runtime_payload->>'8')::numeric>NEW.recorded_at_ns OR (runtime_payload->>'9')::numeric<=NEW.recorded_at_ns THEN
   RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-TYPED-PURPOSE-BINDING'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=NEW.participant_id
   AND i.privacy_domain_id=NEW.privacy_domain_id AND i.operation_id=NEW.operation_id
   AND i.idempotency_record_id=NEW.idempotency_record_id AND i.action_intent_id=NEW.action_intent_id
   AND i.catalog_operation_id=NEW.catalog_operation_id AND i.input_digest=NEW.candidate_digest
   AND NEW.request_digest=openpc.business_request_digest(ARRAY[i.participant_id::text,i.privacy_domain_id::text,i.principal_id::text,
     i.action_intent_id,i.catalog_operation_id,NEW.aggregate_type,NEW.aggregate_id::text,i.expected_aggregate_version::text,
     'sha256:'||encode(i.input_digest,'hex'),i.idempotency_key])) THEN
  RAISE EXCEPTION 'DATA-6021-RECEIPT-IDEMPOTENCY-OWNER'; END IF;

 IF NEW.aggregate_type='indexer-profile' THEN
  IF NOT EXISTS(SELECT 1 FROM control.indexer_profile i WHERE i.participant_id=NEW.participant_id
   AND i.privacy_domain_id=NEW.privacy_domain_id AND i.indexer_profile_id=NEW.aggregate_id
   AND i.revision=NEW.after_revision AND NEW.after_existence=1
   AND after_state->8=jsonb_build_object('0',i.engine,'1',i.engine_version,
    '2',openpc.business_bytes(decode(substring(i.method_profile_digest from 8),'hex')),'3',i.state,
    '4',openpc.business_bytes(decode(substring(i.policy_generation_digest from 8),'hex')))) THEN
    RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-INDEXER-STATE'; END IF;
  IF (NEW.catalog_operation_id='CFG-OP-CREATE-INDEXER-PROFILE' AND
      (NEW.before_existence<>0 OR NEW.after_revision<>1 OR after_state->8->>'3'<>'REGISTERED')) OR
     (NEW.catalog_operation_id='CFG-OP-UPDATE-INDEXER-PROFILE' AND
      (NEW.before_existence<>1 OR NEW.after_revision<>NEW.before_revision+1 OR
       before_state->8->'0' IS DISTINCT FROM after_state->8->'0' OR
       before_state->8->'1' IS DISTINCT FROM after_state->8->'1' OR
       before_state->8->'3' IS DISTINCT FROM after_state->8->'3' OR
       (before_state->8->'2'=after_state->8->'2' AND before_state->8->'4'=after_state->8->'4'))) THEN
    RAISE EXCEPTION 'DATA-6021-RECEIPT-INDEXER-TRANSITION'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.business_signing_selection s
  JOIN control.business_signing_key k USING(participant_id,privacy_domain_id,signer_id)
  JOIN control.business_signing_key_state lifecycle USING(participant_id,privacy_domain_id,signer_id)
  JOIN control.credential c ON c.participant_id=k.participant_id AND c.credential_id=k.workload_credential_id
  JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
  WHERE s.participant_id=NEW.participant_id AND s.privacy_domain_id=NEW.privacy_domain_id
   AND s.environment_id=NEW.environment_id AND s.profile_digest=NEW.profile_digest AND s.signer_id=NEW.signer_id
   AND k.trust_digest=NEW.signer_trust_snapshot_digest AND k.environment_id=NEW.environment_id
   AND lifecycle.state='ACTIVE' AND c.state='ACTIVE' AND p.kind='WORKLOAD' AND p.state='ACTIVE'
   AND c.credential_epoch=k.workload_credential_epoch
   AND c.valid_from<=clock_timestamp() AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
   AND k.valid_from_ns<=NEW.recorded_at_ns AND k.valid_until_ns>NEW.recorded_at_ns
   AND k.valid_until_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000
   FOR SHARE OF s,lifecycle,c,p) THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-LIVE-SIGNING-TRUST'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS business_receipt_typed ON control.audit_occurrence;
CREATE TRIGGER business_receipt_typed BEFORE INSERT ON control.audit_occurrence
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_receipt();
CREATE OR REPLACE FUNCTION openpc.guard_business_outbox()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.audit_occurrence%ROWTYPE; payload jsonb;
BEGIN
 IF NEW.proof_kind='LEGACY' THEN RETURN NEW; END IF;
 IF NEW.proof_kind<>'BUSINESS_RECEIPT_REFERENCE' THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-OUTBOX-PROOF'; END IF;
 SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND receipt_id=NEW.receipt_id;
 payload:=openpc.business_cbor(NEW.payload_cbor);
 IF NEW.aggregate_type<>receipt.aggregate_type OR NEW.aggregate_id<>receipt.aggregate_id OR
    NEW.payload_digest<>sha256(NEW.payload_cbor) OR NEW.event_type<>'io.openpc.control.command.committed.v1' OR
    NEW.data_schema_uri<>'https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted' OR
    payload IS DISTINCT FROM jsonb_build_object('0',openpc.business_uuid(receipt.operation_id),
      '1','urn:openpc:'||receipt.aggregate_type||':'||receipt.aggregate_id::text,
      '2',receipt.action_intent_id,'3',openpc.business_bytes(receipt.action_intent_digest)) THEN
   RAISE EXCEPTION 'DATA-6021-OUTBOX-RECEIPT-PAYLOAD'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS business_outbox_payload ON control.outbox_event;
CREATE TRIGGER business_outbox_payload BEFORE INSERT ON control.outbox_event
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_outbox();
CREATE OR REPLACE FUNCTION openpc.check_business_receipt_completion()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.audit_occurrence%ROWTYPE; event_refs jsonb;
BEGIN
 SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND receipt_id=NEW.receipt_id;
 SELECT jsonb_agg(jsonb_build_object('0',openpc.business_uuid(e.event_id),'1',e.event_type,'2',e.data_schema_uri,
   '3',e.source,'4',e.subject,'5',e.business_sequence,'6',floor(extract(epoch FROM e.occurred_at)*1000000)*1000,
   '7',openpc.business_uuid(e.correlation_id),'9',openpc.business_bytes(e.payload_digest)) ||
   CASE WHEN e.causation_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('8',openpc.business_uuid(e.causation_id)) END ||
   CASE WHEN e.authority_generation IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('10',openpc.business_bytes(e.authority_generation)) END
   ORDER BY e.business_sequence) INTO event_refs FROM control.outbox_event e
  WHERE e.participant_id=receipt.participant_id AND e.privacy_domain_id=receipt.privacy_domain_id
    AND e.receipt_id=receipt.receipt_id AND e.proof_kind='BUSINESS_RECEIPT_REFERENCE';
 IF event_refs IS DISTINCT FROM (openpc.business_cbor(receipt.receipt_cbor)->'21') OR
    EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=receipt.participant_id
      AND e.privacy_domain_id=receipt.privacy_domain_id AND e.receipt_id=receipt.receipt_id
      AND NOT EXISTS(SELECT 1 FROM control.business_outbox_head h WHERE h.participant_id=e.participant_id
        AND h.privacy_domain_id=e.privacy_domain_id AND h.sequence_namespace=e.sequence_namespace
        AND h.aggregate_type=e.aggregate_type AND h.aggregate_id=e.aggregate_id AND h.last_sequence>=e.business_sequence)) OR
    NOT EXISTS(SELECT 1 FROM control.evidence_record e WHERE e.participant_id=receipt.participant_id
      AND e.privacy_domain_id=receipt.privacy_domain_id AND e.receipt_id=receipt.receipt_id
      AND e.recorded_at_ns=receipt.recorded_at_ns) OR
    NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=receipt.participant_id
      AND i.privacy_domain_id=receipt.privacy_domain_id AND i.operation_id=receipt.operation_id
      AND i.terminal_state='COMMITTED' AND i.result_digest IS NOT NULL AND i.result_payload IS NOT NULL) THEN
   RAISE EXCEPTION 'DATA-6021-INCOMPLETE-BUSINESS-COMMIT'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS business_receipt_complete ON control.audit_occurrence;
CREATE CONSTRAINT TRIGGER business_receipt_complete AFTER INSERT ON control.audit_occurrence
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_business_receipt_completion();
DROP TRIGGER IF EXISTS business_event_complete ON control.outbox_event;
CREATE CONSTRAINT TRIGGER business_event_complete AFTER INSERT ON control.outbox_event
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.proof_kind='BUSINESS_RECEIPT_REFERENCE')
 EXECUTE FUNCTION openpc.check_business_receipt_completion();
CREATE OR REPLACE FUNCTION openpc.guard_business_head()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF (TG_OP='INSERT' AND NEW.last_sequence<>1) OR
   (TG_OP='UPDATE' AND (NEW.participant_id<>OLD.participant_id OR NEW.privacy_domain_id<>OLD.privacy_domain_id OR
     NEW.sequence_namespace<>OLD.sequence_namespace OR NEW.aggregate_type<>OLD.aggregate_type OR NEW.aggregate_id<>OLD.aggregate_id OR
     NEW.last_sequence<>OLD.last_sequence+1)) THEN RAISE EXCEPTION 'DATA-6021-BUSINESS-SEQUENCE-TRANSITION'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS business_head_monotonic ON control.business_outbox_head;
CREATE TRIGGER business_head_monotonic BEFORE INSERT OR UPDATE ON control.business_outbox_head
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_head();
CREATE OR REPLACE FUNCTION openpc.check_business_head_completion()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=NEW.participant_id
  AND e.privacy_domain_id=NEW.privacy_domain_id AND e.sequence_namespace=NEW.sequence_namespace
  AND e.aggregate_type=NEW.aggregate_type AND e.aggregate_id=NEW.aggregate_id
  AND e.business_sequence=NEW.last_sequence AND e.proof_kind='BUSINESS_RECEIPT_REFERENCE') THEN
  RAISE EXCEPTION 'DATA-6021-ORPHAN-BUSINESS-SEQUENCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS business_head_complete ON control.business_outbox_head;
CREATE CONSTRAINT TRIGGER business_head_complete AFTER INSERT OR UPDATE ON control.business_outbox_head
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_business_head_completion();

CREATE OR REPLACE FUNCTION openpc.guard_business_authority_snapshot()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE snapshot jsonb; expected jsonb; bound jsonb;
BEGIN
 IF octet_length(NEW.authority_snapshot)>65536 THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-SIZE'; END IF;
 snapshot:=convert_from(NEW.authority_snapshot,'UTF8')::jsonb;
 IF snapshot IS DISTINCT FROM jsonb_build_object('schema','pc.control.precommit-authority-snapshot.v1',
  'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'operationId',NEW.operation_id::text,
  'recordedAtNs',snapshot->'recordedAtNs','decision','ALLOW','authorities',snapshot->'authorities','dependencies',snapshot->'dependencies') OR
  jsonb_typeof(snapshot->'authorities') IS DISTINCT FROM 'array' OR jsonb_array_length(snapshot->'authorities')<>1 OR
  NOT ((snapshot->>'recordedAtNs') ~ '^[0-9]{1,20}$') OR (snapshot->>'recordedAtNs')::numeric>NEW.recorded_at_ns THEN
   RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-HEADER'; END IF;
 IF snapshot->'dependencies' IS DISTINCT FROM jsonb_build_object('assignment',snapshot->'dependencies'->'assignment','authority_envelope',snapshot->'dependencies'->'authority_envelope','credential',snapshot->'dependencies'->'credential','delegation',snapshot->'dependencies'->'delegation','participant',snapshot->'dependencies'->'participant','principal',snapshot->'dependencies'->'principal','privacy_domain',snapshot->'dependencies'->'privacy_domain','session',snapshot->'dependencies'->'session') THEN
  RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-DEPENDENCIES'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'assignment') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('assignment_id',owner.assignment_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'authority_group_id',owner.authority_group_id::text,'authority_envelope_id',owner.authority_envelope_id::text,'delegation_epoch',owner.delegation_epoch::text,'scope_digest',owner.scope_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'valid_during',owner.valid_during::text,'state',owner.state::text,'created_by_principal_id',owner.created_by_principal_id::text,'row_version',owner.row_version::text) ORDER BY owner.assignment_id),'[]'::jsonb) INTO expected
   FROM control.assignment owner WHERE owner.participant_id=NEW.participant_id AND owner.assignment_id IN
    (SELECT (dependency->>'assignment_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'assignment') dependency);
  IF snapshot->'dependencies'->'assignment' IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'authority_envelope') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('authority_envelope_id',owner.authority_envelope_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'maker_principal_id',owner.maker_principal_id::text,'checker_principal_id',owner.checker_principal_id::text,'authority_epoch',owner.authority_epoch::text,'delegation_epoch',owner.delegation_epoch::text,'state',owner.state::text,'valid_from',owner.valid_from::text,'valid_until',owner.valid_until::text,'semantic_digest',owner.semantic_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'row_version',owner.row_version::text) ORDER BY owner.authority_envelope_id),'[]'::jsonb) INTO expected
   FROM control.authority_envelope owner WHERE owner.participant_id=NEW.participant_id AND owner.authority_envelope_id IN
    (SELECT (dependency->>'authority_envelope_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'authority_envelope') dependency);
  IF snapshot->'dependencies'->'authority_envelope' IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'credential') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('credential_id',owner.credential_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'kind',owner.kind::text,'state',owner.state::text,'credential_epoch',owner.credential_epoch::text,'valid_from',owner.valid_from::text,'valid_until',owner.valid_until::text,'public_key_digest',owner.public_key_digest::text,'row_version',owner.row_version::text) ORDER BY owner.credential_id),'[]'::jsonb) INTO expected
   FROM control.credential owner WHERE owner.participant_id=NEW.participant_id AND owner.credential_id IN
    (SELECT (dependency->>'credential_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'credential') dependency);
  IF snapshot->'dependencies'->'credential' IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'delegation') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('delegation_id',owner.delegation_id::text,'participant_id',owner.participant_id::text,'parent_assignment_id',owner.parent_assignment_id::text,'parent_delegation_id',owner.parent_delegation_id::text,'grantor_principal_id',owner.grantor_principal_id::text,'delegate_principal_id',owner.delegate_principal_id::text,'delegation_epoch',owner.delegation_epoch::text,'scope_digest',owner.scope_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'valid_during',owner.valid_during::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.delegation_id),'[]'::jsonb) INTO expected
   FROM control.delegation owner WHERE owner.participant_id=NEW.participant_id AND owner.delegation_id IN
    (SELECT (dependency->>'delegation_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'delegation') dependency);
  IF snapshot->'dependencies'->'delegation' IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'participant') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('participant_id',owner.participant_id::text,'state',owner.state::text,'authority_epoch',owner.authority_epoch::text,'row_version',owner.row_version::text) ORDER BY owner.participant_id),'[]'::jsonb) INTO expected
   FROM control.participant owner WHERE owner.participant_id=NEW.participant_id AND owner.participant_id IN
    (SELECT (dependency->>'participant_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'participant') dependency);
  IF snapshot->'dependencies'->'participant' IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'principal') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('principal_id',owner.principal_id::text,'participant_id',owner.participant_id::text,'kind',owner.kind::text,'state',owner.state::text,'authority_epoch',owner.authority_epoch::text,'row_version',owner.row_version::text) ORDER BY owner.principal_id),'[]'::jsonb) INTO expected
   FROM control.principal owner WHERE owner.participant_id=NEW.participant_id AND owner.principal_id IN
    (SELECT (dependency->>'principal_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'principal') dependency);
  IF snapshot->'dependencies'->'principal' IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'privacy_domain') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('privacy_domain_id',owner.privacy_domain_id::text,'participant_id',owner.participant_id::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.privacy_domain_id),'[]'::jsonb) INTO expected
   FROM control.privacy_domain owner WHERE owner.participant_id=NEW.participant_id AND owner.privacy_domain_id IN
    (SELECT (dependency->>'privacy_domain_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'privacy_domain') dependency);
  IF snapshot->'dependencies'->'privacy_domain' IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'session') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('session_id',owner.session_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'state',owner.state::text,'participant_epoch',owner.participant_epoch::text,'authority_epoch',owner.authority_epoch::text,'delegation_epoch',owner.delegation_epoch::text,'session_epoch',owner.session_epoch::text,'issued_at',owner.issued_at::text,'idle_expires_at',owner.idle_expires_at::text,'absolute_expires_at',owner.absolute_expires_at::text,'step_up_verified_at',owner.step_up_verified_at::text,'row_version',owner.row_version::text) ORDER BY owner.session_id),'[]'::jsonb) INTO expected
   FROM control.session owner WHERE owner.participant_id=NEW.participant_id AND owner.session_id IN
    (SELECT (dependency->>'session_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'session') dependency);
  IF snapshot->'dependencies'->'session' IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;
 bound:=snapshot->'authorities'->0;
 IF bound->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text OR
    bound->>'actionIntentId' IS DISTINCT FROM NEW.action_intent_id OR bound->>'resourceId' IS DISTINCT FROM NEW.aggregate_id::text OR
    NOT (snapshot->'dependencies'->'participant' @> jsonb_build_array(jsonb_build_object('participant_id',NEW.participant_id::text,'state','ACTIVE','authority_epoch',bound->>'participantEpoch'))) OR
    NOT (snapshot->'dependencies'->'privacy_domain' @> jsonb_build_array(jsonb_build_object('privacy_domain_id',NEW.privacy_domain_id::text,'state','ACTIVE'))) OR
    NOT (snapshot->'dependencies'->'principal' @> jsonb_build_array(jsonb_build_object('principal_id',bound->>'principalId','state','ACTIVE','authority_epoch',bound->>'principalEpoch'))) OR
    NOT (snapshot->'dependencies'->'session' @> jsonb_build_array(jsonb_build_object('session_id',bound->>'sessionId','principal_id',bound->>'principalId','state','ACTIVE','session_epoch',bound->>'sessionEpoch'))) OR
    NOT (snapshot->'dependencies'->'assignment' @> jsonb_build_array(jsonb_build_object('assignment_id',bound->>'assignmentId','state','ACTIVE','row_version',bound->>'assignmentRowVersion'))) OR
    NOT (snapshot->'dependencies'->'authority_envelope' @> jsonb_build_array(jsonb_build_object('authority_envelope_id',bound->>'authorityEnvelopeId','state','ACTIVE','authority_epoch',bound->>'authorityEpoch'))) THEN
   RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-BOUND-PATH'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS business_authority_snapshot_typed ON control.audit_occurrence;
CREATE TRIGGER business_authority_snapshot_typed BEFORE INSERT ON control.audit_occurrence
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_authority_snapshot();

CREATE OR REPLACE FUNCTION openpc.guard_business_custody_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='outbox_event' THEN
  IF OLD.proof_kind<>'LEGACY' OR (TG_OP='UPDATE' AND (NEW.proof_kind<>OLD.proof_kind OR
    NEW.sequence_namespace<>OLD.sequence_namespace OR NEW.receipt_id IS DISTINCT FROM OLD.receipt_id)) THEN
    RAISE EXCEPTION 'DATA-6020-IMMUTABLE-BUSINESS-OUTBOX'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=OLD.participant_id
   AND a.privacy_domain_id=OLD.privacy_domain_id AND a.operation_id=OLD.operation_id) AND OLD.terminal_state='COMMITTED' THEN
    RAISE EXCEPTION 'DATA-6020-IMMUTABLE-BUSINESS-IDEMPOTENCY'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS business_outbox_immutable ON control.outbox_event;
CREATE TRIGGER business_outbox_immutable BEFORE UPDATE OR DELETE ON control.outbox_event
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_custody_mutation();
DROP TRIGGER IF EXISTS business_idempotency_immutable ON control.idempotency_record;
CREATE TRIGGER business_idempotency_immutable BEFORE UPDATE OR DELETE ON control.idempotency_record
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_custody_mutation();

DROP TRIGGER IF EXISTS business_transition_profile_immutable ON control.business_transition_profile;
CREATE TRIGGER business_transition_profile_immutable BEFORE UPDATE OR DELETE ON control.business_transition_profile FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS business_signing_key_immutable ON control.business_signing_key;
CREATE TRIGGER business_signing_key_immutable BEFORE UPDATE OR DELETE ON control.business_signing_key FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS business_signing_grant_immutable ON control.business_signing_grant;
CREATE TRIGGER business_signing_grant_immutable BEFORE UPDATE OR DELETE ON control.business_signing_grant FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS audit_occurrence_immutable ON control.audit_occurrence;
CREATE TRIGGER audit_occurrence_immutable BEFORE UPDATE OR DELETE ON control.audit_occurrence FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS evidence_record_immutable ON control.evidence_record;
CREATE TRIGGER evidence_record_immutable BEFORE UPDATE OR DELETE ON control.evidence_record FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
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
REVOKE ALL ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."evidence_record", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM PUBLIC;
REVOKE ALL ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."evidence_record", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
GRANT EXECUTE ON FUNCTION openpc.require_uuid_setting(text), openpc.set_request_context(text,uuid,uuid,uuid,text,boolean), openpc.assert_request_context(boolean), openpc.matches_participant(uuid), openpc.matches_privacy(uuid), openpc.current_participant_id(), openpc.current_privacy_domain_id(), openpc.current_operation_id(), openpc.current_action_intent_id() TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."evidence_record", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" TO "openpc_control_runtime", "openpc_control_platform_runtime", "openpc_control_reader";
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
GRANT INSERT ON "control"."mutation_candidate" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE (state, consumed_operation_id, updated_at) ON "control"."mutation_candidate" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT, UPDATE (last_sequence, updated_at) ON "control"."outbox_aggregate_head" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."idempotency_record", "control"."outbox_aggregate_head", "control"."outbox_event" TO "openpc_control_worker";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."evidence_record", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE, DELETE ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."evidence_record", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" TO "openpc_control_maintenance";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."evidence_record", "control"."idempotency_record", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."pending_delivery", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session", "control"."work_item" TO "openpc_backup_operator";

GRANT INSERT ON control.audit_occurrence,control.evidence_record TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT,UPDATE(last_sequence,updated_at) ON control.business_outbox_head TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT UPDATE(row_version) ON control.business_signing_selection,control.business_signing_key_state TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT ON control.business_signing_key,control.business_signing_grant,control.business_signing_key_state,control.business_signing_selection TO openpc_control_key_governor;
GRANT UPDATE(state,row_version,changed_at_ns,change_reference,change_digest) ON control.business_signing_key_state TO openpc_control_key_governor;
GRANT UPDATE(signer_id,row_version,changed_at_ns,change_reference,change_digest) ON control.business_signing_selection TO openpc_control_key_governor;
GRANT EXECUTE ON FUNCTION openpc.business_cbor_item(bytea,integer,integer),openpc.business_cbor(bytea),openpc.business_bytes(bytea),openpc.business_uuid(uuid),openpc.business_request_digest(text[])
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_key_governor;

ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA openpc REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
