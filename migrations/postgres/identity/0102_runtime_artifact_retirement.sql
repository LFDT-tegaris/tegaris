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
-- Custom SQL migration file, put your code below! --
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
    -- Public remediation creation keeps its business receipt owner. Every
    -- internal remediation insert must instead prove native completion custody;
    -- context chooses the checker, never supplies its authorization.
    IF openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
      OR (NEW.kind='REMEDIATION' AND openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-WORK_ITEMS_CREATE_RESOURCE-V1') THEN
      PERFORM openpc.check_notification_completion_remediation_effect(NEW);
    END IF;
    IF current_setting('openpc.action_intent_id',true)='ACT-EVIDENCE_EXPORT_RECORDS-V1' AND NEW.kind='DELIVERY_FAILURE' THEN
      PERFORM openpc.check_notification_delivery_failure_work(NEW);
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

CREATE OR REPLACE FUNCTION openpc.assert_mutation_resume_no_effect(candidate_id uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE c control.mutation_candidate%ROWTYPE; selected jsonb; source record; projection jsonb;
BEGIN
 SELECT * INTO STRICT c FROM control.mutation_candidate WHERE mutation_candidate_id=candidate_id;
 IF c.catalog_operation_id='CFG-OP-QUALIFY-PROVIDER-PROFILE' THEN
  -- Qualification approves an existing provider. Its reset/probe history is
  -- required input, not an effect of this unsubmitted qualification intent.
  IF c.action_intent_id<>'ACT-PROVIDER_APPROVE_QUALIFICATION-V1'
   OR c.resource_type<>'provider-profile' OR c.operation_class<>'APPROVE' OR c.expected_revision<1
   OR c.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') OR c.consumed_operation_id IS NOT NULL
   OR c.candidate_document->>'targetRef' IS DISTINCT FROM 'urn:openpc:resource:'||c.resource_id::text
   OR c.candidate_document->>'expectedRevision' IS DISTINCT FROM c.expected_revision::text
   OR current_setting('transaction_isolation')<>'serializable'
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(openpc.signing_canonical_json(jsonb_build_array(
   'mutation-intent',c.participant_id::text,c.privacy_domain_id::text,c.maker_principal_id::text,
   c.action_intent_id,c.catalog_operation_id,c.idempotency_key)),0));
  -- The actual qualification UPDATE takes this same row lock. NOWAIT avoids
  -- reversing its provider/reference lock order; SERIALIZABLE rejects a tuple
  -- newer than this transaction's snapshot before any successor can be issued.
  BEGIN
   SELECT p.* INTO source FROM control.provider_profile p
    WHERE p.participant_id=c.participant_id AND p.privacy_domain_id=c.privacy_domain_id
     AND p.provider_profile_id=c.resource_id FOR UPDATE NOWAIT;
  EXCEPTION WHEN lock_not_available THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='PC-DATA-6007';
  END;
  IF source.provider_profile_id IS NULL OR source.revision<>c.expected_revision
   OR source.state<>'SHADOW' OR source.qualification_observation_id IS NOT NULL
   OR source.behavior_fingerprint IS DISTINCT FROM c.candidate_document->>'inputDigest'
   OR EXISTS(SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=c.participant_id
    AND r.privacy_domain_id=c.privacy_domain_id AND r.principal_id=c.maker_principal_id
    AND r.action_intent_id=c.action_intent_id AND r.catalog_operation_id=c.catalog_operation_id
    AND r.idempotency_key=c.idempotency_key)
   OR EXISTS(SELECT 1 FROM control.configuration_work w WHERE w.participant_id=c.participant_id
    AND w.privacy_domain_id=c.privacy_domain_id AND w.resource_id=c.resource_id
    AND (w.state NOT IN ('COMPLETED','FAILED') OR w.created_at>=c.created_at))
   OR EXISTS(SELECT 1 FROM control.provider_probe_observation o WHERE o.participant_id=c.participant_id
    AND o.privacy_domain_id=c.privacy_domain_id AND o.provider_profile_id=c.resource_id
    AND (o.observed_revision>c.expected_revision OR (o.observed_revision=c.expected_revision AND o.state<>'OBSERVED')))
   OR EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=c.participant_id
    AND a.privacy_domain_id=c.privacy_domain_id AND a.aggregate_id=c.resource_id
    AND (a.after_revision>c.expected_revision OR a.candidate_digest=c.candidate_digest))
   OR EXISTS(SELECT 1 FROM control.mutation_evidence e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_id=c.resource_id
    AND (e.aggregate_version>c.expected_revision OR e.candidate_digest=c.candidate_digest))
   OR EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_id=c.resource_id AND e.created_at>=c.created_at)
   OR EXISTS(SELECT 1 FROM control.receipt_signing_attempt a JOIN control.business_transition_profile p USING(profile_digest)
    WHERE a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
     AND p.catalog_operation_id=c.catalog_operation_id AND NOT EXISTS(
      SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=a.participant_id
       AND r.privacy_domain_id=a.privacy_domain_id AND r.operation_id=a.operation_id AND r.terminal_state='COMMITTED'))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN;
 END IF;
 IF ((c.catalog_operation_id='MOD-OP-REGISTER' AND c.action_intent_id='ACT-MODULES_CREATE_RESOURCE-V1' AND c.resource_type='modules')
      OR (c.catalog_operation_id='ID-OP-ASSIGNMENT-CREATE' AND c.action_intent_id='ACT-PARTICIPANT_CREATE_MEMBER-V1' AND c.resource_type='principal')
      OR (c.catalog_operation_id='CFG-OP-CREATE-EVIDENCE-HOLD' AND c.action_intent_id='ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1'
          AND c.resource_type='evidence-holds' AND c.candidate_document->'selector'->>'type'<>'PARTICIPANT')
      OR (c.catalog_operation_id='CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD' AND c.action_intent_id='ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1'
          AND c.resource_type='evidence-holds' AND c.candidate_document->'selector'->>'type'='PARTICIPANT')
      OR (c.catalog_operation_id='CFG-OP-ACTIVATE-RETENTION-POLICY'
          AND c.action_intent_id='ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1' AND c.resource_type='retention-policies')
      OR (c.catalog_operation_id='CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE'
          AND c.action_intent_id='ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1' AND c.resource_type='evidence-deletions')
      OR (c.catalog_operation_id='CFG-OP-ADMIT-STORE-RETIREMENT'
          AND c.action_intent_id='ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1' AND c.resource_type='evidence-deletions')
      OR (c.catalog_operation_id='CFG-OP-DELETE-PROJECTION-BATCH'
          AND c.action_intent_id='ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1' AND c.resource_type='evidence-deletions')) IS NOT TRUE
    OR c.operation_class<>'CREATE' OR c.expected_revision<>0
    OR c.state NOT IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') OR c.consumed_operation_id IS NOT NULL
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(openpc.signing_canonical_json(jsonb_build_array(
  'mutation-intent',c.participant_id::text,c.privacy_domain_id::text,c.maker_principal_id::text,
  c.action_intent_id,c.catalog_operation_id,c.idempotency_key)),0));
 IF c.catalog_operation_id='MOD-OP-REGISTER' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('module-admission:'||c.participant_id::text||':'||c.privacy_domain_id::text,0));
 END IF;
 IF c.catalog_operation_id IN ('CFG-OP-CREATE-EVIDENCE-HOLD','CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD') THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
  IF EXISTS (SELECT 1 FROM control.retention_hold h WHERE h.participant_id=c.participant_id AND h.retention_hold_id=c.resource_id)
    OR EXISTS (SELECT 1 FROM control.evidence_hold_coverage h WHERE h.participant_id=c.participant_id AND h.retention_hold_id=c.resource_id)
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF c.catalog_operation_id='CFG-OP-ACTIVATE-RETENTION-POLICY' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
  -- Activation is atomic and local. Check both the original identity and the
  -- version's natural key; execution still rechecks the current predecessor.
  IF EXISTS (SELECT 1 FROM control.retention_policy p WHERE p.participant_id=c.participant_id
    AND p.privacy_domain_id=c.privacy_domain_id AND (p.retention_policy_id=c.resource_id
      OR (p.data_class=c.candidate_document->'policy'->>'dataClass'
        AND p.policy_version=c.candidate_document->'policy'->>'policyVersion')))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF c.catalog_operation_id='CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
  -- An admitted permanent source denial cannot be renewed or replaced by a
  -- second approval. Only the original native/operation readback may reconcile.
  IF EXISTS(SELECT 1 FROM control.runtime_artifact_source_disposition a WHERE a.participant_id=c.participant_id
    AND a.privacy_domain_id=c.privacy_domain_id AND (a.disposition_id=c.resource_id
     OR a.configuration_digest=decode(substring(c.candidate_document->'selection'->'observation'->'source'->>'configurationDigest' from 8),'hex')))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF c.catalog_operation_id='CFG-OP-ADMIT-STORE-RETIREMENT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
  -- An admitted UNKNOWN outcome must reconcile its original dispatch; absence
  -- of a terminal native receipt never permits fresh approval or re-dispatch.
  IF EXISTS (SELECT 1 FROM control.store_retirement_admission a
    WHERE a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
      AND (a.attempt_id=c.resource_id OR a.approval_request_id IN
        (SELECT r.approval_request_id FROM control.approval_request r
          WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id
            AND r.subject_type='CONFIGURATION_CANDIDATE' AND r.subject_id=c.mutation_candidate_id)))
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF c.catalog_operation_id='CFG-OP-DELETE-PROJECTION-BATCH' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
  selected:=c.candidate_document->'selection';
  IF (selected->>'version'='OPENPC_PROJECTION_DELETION_BATCH_V1'
    AND selected->>'participantId'='urn:openpc:participant:'||c.participant_id::text
    AND selected->>'privacyDomainId'=c.privacy_domain_id::text
    AND selected->>'targetDatabase'='openpc_control' AND selected->>'deletionMode'='PROJECTION_DELETE'
    AND ((selected->>'dataClass'='SEARCH_PROJECTION' AND selected->>'sourceKind' IN ('AUTHENTICATION_CATALOGUE','RETENTION_POLICY_CATALOGUE'))
      OR (selected->>'dataClass'='NORMALIZED_JSON_PROJECTION'
        AND selected->>'sourceKind' IN ('RPC_PRE_ADMISSION_DENIAL','RPC_CLOSED_TRANSITION','FACT_PROVENANCE','DEPLOYMENT_PROVENANCE')))) IS NOT TRUE
   OR EXISTS (SELECT 1 FROM control.deletion_job j WHERE j.participant_id=c.participant_id
     AND j.privacy_domain_id=c.privacy_domain_id AND (j.deletion_job_id=c.resource_id OR j.selection=selected))
   OR EXISTS (SELECT 1 FROM control.evidence_projection_retirement r WHERE r.participant_id=c.participant_id
     AND r.privacy_domain_id=c.privacy_domain_id AND r.data_class=selected->>'dataClass'
     AND 'urn:openpc:resource:'||r.evidence_id::text=selected->>'evidenceId')
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  -- Recovery proves absence of this local effect without borrowing the raw
  -- source-disclosure authority of a deletion execution. Full source, retention,
  -- hold, finality and continuation admission still runs at actual execution.
  SELECT * INTO source FROM control.evidence_catalogue e WHERE e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id AND 'urn:openpc:resource:'||e.evidence_id::text=selected->>'evidenceId'
    AND e.stream_id=selected->>'streamId' AND e.record_id=selected->>'recordId'
    AND e.segment_id::text=selected->>'segmentId' AND e.sequence::text=selected->>'sequence'
    AND e.receipt_digest=selected->>'sourceReceiptDigest';
  IF NOT FOUND THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  IF (selected->>'sourceKind'='AUTHENTICATION_CATALOGUE' AND source.source_format='OPENPC_AUTHENTICATION_OCCURRENCE_V1'
    AND source.evidence_class='AUTHENTICATION') OR (selected->>'sourceKind'='RETENTION_POLICY_CATALOGUE'
    AND source.evidence_class='BUSINESS_TRANSITION') THEN
   SELECT openpc.evidence_catalogue_projection(e) INTO projection FROM control.evidence_catalogue e
    WHERE e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id AND e.evidence_id=source.evidence_id;
  ELSIF selected->>'sourceKind'='FACT_PROVENANCE' AND source.source_format='OPENPC_CANONICAL_FACT_V1' AND source.evidence_class='EFFECT' THEN
   SELECT p.projection INTO projection FROM control.evidence_fact_provenance p WHERE p.participant_id=c.participant_id
    AND p.privacy_domain_id=c.privacy_domain_id AND p.stream_id=source.stream_id AND p.record_id=source.record_id
    AND p.projection_digest=selected->>'projectionDigest';
  ELSIF selected->>'sourceKind'='DEPLOYMENT_PROVENANCE' AND source.source_format='PC-DEPLOYMENT-JOURNAL-PROJECTION-1' AND source.evidence_class='EFFECT' THEN
   SELECT p.projection INTO projection FROM control.evidence_deployment_provenance p WHERE p.participant_id=c.participant_id
    AND p.privacy_domain_id=c.privacy_domain_id AND p.stream_id=source.stream_id AND p.record_id=source.record_id
    AND p.projection_digest=selected->>'projectionDigest';
  ELSIF selected->>'sourceKind' IN ('RPC_PRE_ADMISSION_DENIAL','RPC_CLOSED_TRANSITION')
    AND source.source_format='OPENPC_RPC_DECISION_TRANSITION_V1' AND source.evidence_class='EFFECT' THEN
   SELECT p.projection INTO projection FROM control.evidence_rpc_provenance p WHERE p.participant_id=c.participant_id
    AND p.privacy_domain_id=c.privacy_domain_id AND p.stream_id=source.stream_id AND p.record_id=source.record_id
    AND p.projection_digest=selected->>'projectionDigest';
  END IF;
  IF projection IS NULL OR ('sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(projection),'UTF8')),'hex'))
      IS DISTINCT FROM selected->>'projectionDigest'
    OR octet_length(convert_to(openpc.signing_canonical_json(projection),'UTF8'))::text IS DISTINCT FROM selected->>'projectionBytes'
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 END IF;
 IF EXISTS (SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=c.participant_id
      AND r.privacy_domain_id=c.privacy_domain_id AND r.principal_id=c.maker_principal_id
      AND r.action_intent_id=c.action_intent_id AND r.catalog_operation_id=c.catalog_operation_id
      AND r.idempotency_key=c.idempotency_key)
 OR (c.catalog_operation_id='ID-OP-ASSIGNMENT-CREATE' AND EXISTS (
      SELECT 1 FROM control.assignment a WHERE a.participant_id=c.participant_id AND a.assignment_id=c.resource_id))
 OR (c.catalog_operation_id='MOD-OP-REGISTER' AND EXISTS (SELECT 1 FROM control.module_installation i JOIN control.module_version v USING(module_version_id)
      WHERE i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id
      AND (i.module_installation_id=c.resource_id OR (v.module_id=c.candidate_document->>'name'
        AND v.semantic_version=c.candidate_document->>'semanticVersion'))))
 OR EXISTS (SELECT 1 FROM control.configuration_work w WHERE w.participant_id=c.participant_id
      AND w.privacy_domain_id=c.privacy_domain_id AND (w.resource_id=c.resource_id OR w.input_digest='sha256:'||encode(c.candidate_digest,'hex')))
 OR EXISTS (SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=c.participant_id
      AND a.privacy_domain_id=c.privacy_domain_id AND (a.aggregate_id=c.resource_id OR a.candidate_digest=c.candidate_digest))
 OR EXISTS (SELECT 1 FROM control.mutation_evidence e WHERE e.participant_id=c.participant_id
      AND e.privacy_domain_id=c.privacy_domain_id AND (e.aggregate_id=c.resource_id OR
        (e.catalog_operation_id=c.catalog_operation_id AND e.candidate_digest=c.candidate_digest)))
 OR EXISTS (SELECT 1 FROM control.outbox_event e WHERE e.participant_id=c.participant_id
      AND e.privacy_domain_id=c.privacy_domain_id AND e.aggregate_id=c.resource_id)
 OR EXISTS (SELECT 1 FROM control.receipt_signing_attempt a JOIN control.business_transition_profile p USING(profile_digest)
      WHERE a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
        AND p.catalog_operation_id=c.catalog_operation_id AND NOT EXISTS (
          SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=a.participant_id
            AND r.privacy_domain_id=a.privacy_domain_id AND r.operation_id=a.operation_id AND r.terminal_state='COMMITTED'))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.enforce_mutation_resume()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE old_attempt control.mutation_candidate%ROWTYPE; prior control.approval_request%ROWTYPE;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF row(NEW.predecessor_candidate_id,NEW.predecessor_approval_id,NEW.resume_operation_id,NEW.resume_request,NEW.attempt)
    IS DISTINCT FROM row(OLD.predecessor_candidate_id,OLD.predecessor_approval_id,OLD.resume_operation_id,OLD.resume_request,OLD.attempt)
   OR EXISTS (SELECT 1 FROM control.mutation_candidate s WHERE s.predecessor_candidate_id=OLD.mutation_candidate_id)
  THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.predecessor_candidate_id IS NULL THEN
  IF NEW.resume_request IS NOT NULL THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT old_attempt FROM control.mutation_candidate
  WHERE mutation_candidate_id=NEW.predecessor_candidate_id FOR UPDATE;
 SELECT * INTO STRICT prior FROM control.approval_request
  WHERE approval_request_id=NEW.predecessor_approval_id FOR UPDATE;
 IF row(NEW.participant_id,NEW.privacy_domain_id,NEW.action_intent_id,NEW.catalog_operation_id,
        NEW.resource_type,NEW.operation_class,NEW.resource_id,NEW.candidate_digest,NEW.candidate_document,
        NEW.expected_revision,NEW.idempotency_key,NEW.maker_principal_id)
    IS DISTINCT FROM row(old_attempt.participant_id,old_attempt.privacy_domain_id,old_attempt.action_intent_id,
        old_attempt.catalog_operation_id,old_attempt.resource_type,old_attempt.operation_class,old_attempt.resource_id,
        old_attempt.candidate_digest,old_attempt.candidate_document,old_attempt.expected_revision,
        old_attempt.idempotency_key,old_attempt.maker_principal_id)
   OR NEW.attempt<>old_attempt.attempt+1 OR NEW.expires_at<=clock_timestamp()
   OR NEW.expires_at>clock_timestamp()+interval '30 minutes'
   OR prior.participant_id<>NEW.participant_id OR prior.privacy_domain_id<>NEW.privacy_domain_id
   OR prior.subject_type<>'CONFIGURATION_CANDIDATE' OR prior.subject_id<>old_attempt.mutation_candidate_id
   OR prior.subject_digest<>NEW.candidate_digest OR prior.subject_version<>NEW.expected_revision
   OR prior.maker_principal_id<>NEW.maker_principal_id OR prior.checker_principal_id IS NULL
   OR prior.checker_principal_id=NEW.maker_principal_id
   OR NOT EXISTS(SELECT 1 FROM control.principal checker WHERE checker.participant_id=NEW.participant_id
      AND checker.principal_id=prior.checker_principal_id AND checker.state='ACTIVE') OR prior.state NOT IN ('OPEN','APPROVED','EXPIRED')
   OR EXISTS (SELECT 1 FROM control.mutation_candidate s WHERE s.predecessor_candidate_id=old_attempt.mutation_candidate_id)
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 -- A still-live approval cannot be replaced merely to obtain another authorization.
 IF old_attempt.expires_at>clock_timestamp() AND prior.expires_at>clock_timestamp() AND
    (prior.state='OPEN' OR EXISTS (SELECT 1 FROM control.approval_decision_record d
      JOIN control.mfa_challenge m ON m.participant_id=d.participant_id AND m.mfa_challenge_id=d.mfa_challenge_id
      WHERE d.participant_id=prior.participant_id AND d.approval_request_id=prior.approval_request_id
        AND d.decision='APPROVE' AND m.consumed_at>clock_timestamp()-interval '5 minutes'
        AND m.expires_at>clock_timestamp()))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF NEW.resume_request IS NULL OR jsonb_typeof(NEW.resume_request)<>'object' OR NEW.resume_request->>'command' IS DISTINCT FROM 'RESUME'
    OR NEW.resume_request->>'actionIntentId' IS DISTINCT FROM 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
    OR NEW.resume_request->>'approvalRequestId' IS DISTINCT FROM 'urn:openpc:resource:'||prior.approval_request_id::text
    OR NEW.resume_request->>'expectedRevision' IS DISTINCT FROM prior.row_version::text
    OR NEW.resume_request->>'expectedAttempt' IS DISTINCT FROM old_attempt.attempt::text
    OR NEW.resume_request->>'predecessorCandidateId' IS DISTINCT FROM old_attempt.mutation_candidate_id::text
    OR NEW.resume_request->>'candidateDigest' IS DISTINCT FROM 'sha256:'||encode(old_attempt.candidate_digest,'hex')
    OR NOT EXISTS (SELECT 1 FROM control.idempotency_record r WHERE r.participant_id=NEW.participant_id
      AND r.privacy_domain_id=NEW.privacy_domain_id AND r.operation_id=NEW.resume_operation_id
      AND r.principal_id=NEW.maker_principal_id AND r.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
      AND r.catalog_operation_id='LEGACY' AND r.expected_aggregate_version=prior.row_version
      AND r.input_digest=sha256(convert_to(openpc.signing_canonical_json(NEW.resume_request),'UTF8')))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 PERFORM openpc.assert_mutation_resume_no_effect(old_attempt.mutation_candidate_id);
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS mutation_candidate_resume ON control.mutation_candidate;
CREATE TRIGGER mutation_candidate_resume BEFORE INSERT OR UPDATE ON control.mutation_candidate
 FOR EACH ROW EXECUTE FUNCTION openpc.enforce_mutation_resume();

CREATE OR REPLACE FUNCTION openpc.require_completed_mutation_resume()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.predecessor_candidate_id IS NOT NULL AND NOT EXISTS (
   SELECT 1 FROM control.idempotency_record r JOIN control.approval_request a
    ON a.participant_id=r.participant_id AND a.privacy_domain_id=r.privacy_domain_id
    AND a.subject_id=NEW.mutation_candidate_id AND a.subject_type='CONFIGURATION_CANDIDATE'
   JOIN control.approval_request prior ON prior.approval_request_id=NEW.predecessor_approval_id
   WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
     AND r.operation_id=NEW.resume_operation_id AND r.terminal_state='COMMITTED'
     AND r.result_payload->>'resourceRef'='urn:openpc:resource:'||a.approval_request_id::text
     AND a.subject_digest=NEW.candidate_digest AND a.subject_version=NEW.expected_revision
     AND a.maker_principal_id=NEW.maker_principal_id AND a.checker_principal_id=prior.checker_principal_id
     AND a.state='OPEN' AND a.expires_at=NEW.expires_at
 ) THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS mutation_resume_completed ON control.mutation_candidate;
CREATE CONSTRAINT TRIGGER mutation_resume_completed AFTER INSERT ON control.mutation_candidate
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_completed_mutation_resume();

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
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'openpc_signing_authority_locker') THEN
    CREATE ROLE openpc_signing_authority_locker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'openpc_signing_continuation_issuer') THEN
    CREATE ROLE openpc_signing_continuation_issuer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
  END IF;
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
ALTER TABLE "control"."authentication_occurrence" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_envelope" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_group" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_group_member" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_role" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."business_outbox_head" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."business_signing_grant" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."business_signing_key" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."business_signing_key_state" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."business_signing_selection" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."credential" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."delegation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."directory_connector" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."directory_group_mapping" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."directory_member" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."evidence_record" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."hardware_authenticator" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."idempotency_record" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."identity_oidc_binding" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."identity_runtime_authority_scope" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."identity_runtime_authority_set" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."identity_runtime_snapshot" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."identity_runtime_snapshot_content" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."identity_runtime_snapshot_head" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."identity_subject" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."installed_secret_recipient" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."mfa_challenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."mutation_candidate" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."mutation_evidence" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."notification_completion_phase_admission" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."outbox_aggregate_head" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."outbox_event" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."participant" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."participant_bootstrap_custody" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."participant_invitation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."participant_invitation_acceptance" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."participant_invitation_proof" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."participant_invitation_token" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."participant_lifecycle_transition" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."participant_membership" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."pending_delivery" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."platform_context" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."principal" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."privacy_domain" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."qualified_receipt_checkpoint" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."qualified_receipt_inbox" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."receipt_signing_attempt" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."recovery_challenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."recovery_principal" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."revocation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."session" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."signing_authorization_generation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."signing_continuation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."signing_key_rotation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."signing_provider_attempt" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."signing_rotation_attestation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."signing_rotation_authority_hold" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."signing_rotation_command" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."signing_rotation_history" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."signing_rotation_observation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."signing_rotation_operation_evidence" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."wallet_binding" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."webauthn_enrollment" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."work_item" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."action_intent" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."approval_decision_record" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."approval_request" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."assignment" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."audit_occurrence" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authentication_occurrence" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_envelope" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_group" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_group_member" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_role" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_outbox_head" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_signing_grant" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_signing_key" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_signing_key_state" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_signing_selection" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."business_transition_profile" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."credential" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."delegation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."directory_connector" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."directory_group_mapping" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."directory_member" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."evidence_record" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."hardware_authenticator" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."idempotency_record" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."identity_oidc_binding" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."identity_runtime_authority_scope" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."identity_runtime_authority_set" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."identity_runtime_snapshot" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."identity_runtime_snapshot_content" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."identity_runtime_snapshot_head" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."identity_subject" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."installed_secret_recipient" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."mfa_challenge" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."mutation_candidate" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."mutation_evidence" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."notification_completion_admission_key" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."notification_completion_phase_admission" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."oidc_transaction" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."outbox_aggregate_head" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."outbox_event" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."participant" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."participant_bootstrap_custody" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."participant_invitation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."participant_invitation_acceptance" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."participant_invitation_proof" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."participant_invitation_token" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."participant_lifecycle_transition" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."participant_membership" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."pending_delivery" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."platform_context" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."principal" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."privacy_domain" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."qualified_receipt_checkpoint" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."qualified_receipt_inbox" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."receipt_signing_attempt" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."recovery_challenge" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."recovery_principal" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."revocation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."session" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."signing_authorization_generation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."signing_continuation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."signing_key_rotation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."signing_provider_attempt" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."signing_rotation_attestation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."signing_rotation_authority_hold" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."signing_rotation_command" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."signing_rotation_history" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."signing_rotation_observation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."signing_rotation_operation_evidence" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."wallet_binding" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."webauthn_enrollment" OWNER TO "openpc_control_owner";
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
    row_document->>'evidence_role'='IDENTITY_PROOF_INPUT' OR row_document->>'catalog_operation_id'='ID-OP-INVITATION-ACCEPT'
  ) THEN
    IF NOT coalesce((row_document->>'evidence_role'='IDENTITY_PROOF_INPUT'
      AND row_document->>'evidence_format'='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
      AND row_document->>'catalog_operation_id'='ID-OP-INVITATION-ACCEPT'
      AND row_document->>'action_intent_id'='ACT-PARTICIPANT_CREATE_MEMBER-V1'
      AND row_document->>'aggregate_type'='invitation-redemption'
      AND row_document->>'aggregate_version' IS NOT NULL
      AND row_document->>'bound_participant_epoch' IS NOT NULL AND row_document->>'bound_principal_epoch' IS NOT NULL
      AND octet_length((row_document->>'candidate_digest')::bytea)=32
      AND (row_document->>'evidence_digest')::bytea=sha256((row_document->>'evidence_cbor')::bytea)
      AND row_document->>'checker_principal_id' IS NULL AND row_document->>'approval_request_id' IS NULL
      AND row_document->>'mfa_challenge_id' IS NULL AND row_document->>'signer_credential_id' IS NULL
      AND row_document->>'webauthn_assertion_binding_digest' IS NULL
      AND row_document->>'bound_authority_envelope_id' IS NULL AND row_document->>'bound_envelope_epoch' IS NULL
      AND row_document->>'bound_assignment_id' IS NULL),false) THEN
      RAISE EXCEPTION 'DATA-6021-INCOMPLETE-IDENTITY-PROOF';
    END IF;
  ELSIF TG_TABLE_NAME = 'mutation_evidence' AND row_document->>'catalog_operation_id'='ID-OP-PARTICIPANT-FIRST-ADMIN-ACCEPT' THEN
    IF NOT coalesce((row_document->>'evidence_role'='AUTHORIZATION_INPUT'
      AND row_document->>'evidence_format'='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
      AND row_document->>'action_intent_id'='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
      AND row_document->>'aggregate_type'='participant'
      AND row_document->>'aggregate_id'=row_document->>'participant_id'
      AND octet_length((row_document->>'webauthn_assertion_binding_digest')::bytea)=32
      AND (row_document->>'evidence_digest')::bytea=sha256((row_document->>'evidence_cbor')::bytea)
      AND row_document->>'bound_authority_envelope_id' IS NULL AND row_document->>'bound_assignment_id' IS NULL
      AND EXISTS (
        SELECT 1 FROM control.participant_bootstrap_custody custody
        JOIN control.mfa_challenge challenge ON challenge.participant_id=custody.participant_id
          AND challenge.principal_id=custody.candidate_membership_id AND challenge.session_id=custody.candidate_session_id
          AND challenge.mfa_challenge_id=(row_document->>'mfa_challenge_id')::uuid
          AND challenge.action_intent_id=row_document->>'action_intent_id'
          AND challenge.resource_digest=(row_document->>'candidate_digest')::bytea
          AND challenge.used_at IS NULL AND challenge.consumed_at IS NULL AND challenge.expires_at>clock_timestamp()
        JOIN control.credential credential ON credential.participant_id=custody.participant_id
          AND credential.principal_id=custody.candidate_membership_id AND credential.credential_id=(row_document->>'signer_credential_id')::uuid
          AND credential.kind='WEBAUTHN' AND credential.state='ACTIVE'
        WHERE custody.participant_id=(row_document->>'participant_id')::uuid
          AND custody.candidate_membership_id=(row_document->>'principal_id')::uuid
          AND custody.state='CLAIM_PENDING' AND custody.expires_at>clock_timestamp()
          AND custody.participant_epoch=(row_document->>'bound_participant_epoch')::numeric
          AND custody.participant_epoch=(row_document->>'aggregate_version')::numeric
      )),false) THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-FIRST-ADMIN-CUSTODY'; END IF;
  ELSIF TG_TABLE_NAME = 'mutation_evidence' AND (
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
DECLARE key_row control.business_signing_key%ROWTYPE; grants jsonb; actual jsonb; expected jsonb; schema_digest text; schema_count integer; receipt_version integer;
BEGIN
 SELECT * INTO STRICT key_row FROM control.business_signing_key
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND signer_id=NEW.signer_id;
 IF NOT pg_has_role(current_user,'openpc_control_key_governor','MEMBER') AND
    NOT pg_has_role(current_user,'openpc_control_owner','MEMBER') AND key_row.admission_kind<>'GOVERNED' THEN
   RAISE EXCEPTION 'DATA-6021-SIGNING-BOOTSTRAP-AUTHORITY';
 END IF;
 SELECT jsonb_agg(jsonb_build_array(p.profile_id,p.profile_version,openpc.business_bytes(p.profile_digest),
   p.action_intent_id,p.catalog_operation_id) ORDER BY convert_to(p.profile_id,'UTF8'),p.profile_version)
 INTO grants FROM control.business_signing_grant g JOIN control.business_transition_profile p USING(profile_digest)
 WHERE g.participant_id=key_row.participant_id AND g.privacy_domain_id=key_row.privacy_domain_id AND g.signer_id=key_row.signer_id;
 IF grants IS NULL OR jsonb_array_length(grants) NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-SIGNING-GRANTS'; END IF;
 SELECT count(DISTINCT p.schema_definition_digest),min(encode(p.schema_definition_digest,'hex'))
 INTO schema_count,schema_digest FROM control.business_signing_grant g JOIN control.business_transition_profile p USING(profile_digest)
 WHERE g.participant_id=key_row.participant_id AND g.privacy_domain_id=key_row.privacy_domain_id AND g.signer_id=key_row.signer_id;
 IF schema_count<>1 THEN RAISE EXCEPTION 'DATA-6021-MIXED-SIGNING-SCHEMA-GRANTS'; END IF;
 receipt_version:=CASE schema_digest
  WHEN '41a877ca7e00e74f32c8becf8daee38f26c12ab9d9dcf6ff80ed8e75608b3c1f' THEN 1
  WHEN '4e7de36861819909275bdec8103d1df04984c03b34cb593437dfe68f5c2c1d9a' THEN 2 END;
 IF receipt_version IS NULL THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-SIGNING-SCHEMA'; END IF;
 actual:=openpc.business_cbor(key_row.trust_preimage);
 expected:=jsonb_build_array('pc.control.business-signing-trust.v1',openpc.business_uuid(key_row.participant_id),
   openpc.business_uuid(key_row.privacy_domain_id),key_row.environment_id,key_row.signer_id,
   openpc.business_bytes(key_row.public_key_spki_der),openpc.business_uuid(key_row.workload_credential_id),
   key_row.workload_credential_epoch,key_row.key_epoch,key_row.valid_from_ns,key_row.valid_until_ns,
   key_row.admission_kind,key_row.admission_reference,openpc.business_bytes(key_row.admission_digest),
   key_row.secret_class,key_row.secret_reference,key_row.secret_version,24001,receipt_version,338,grants);
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
 IF TG_TABLE_NAME='business_signing_selection' AND TG_OP='UPDATE' AND
  (to_jsonb(NEW)->>'admission_version') IS DISTINCT FROM (to_jsonb(OLD)->>'admission_version') THEN
  IF (to_jsonb(NEW)-'admission_version') IS DISTINCT FROM (to_jsonb(OLD)-'admission_version') OR
   (to_jsonb(NEW)->>'admission_version')::numeric<>(to_jsonb(OLD)->>'admission_version')::numeric+1 OR
   NOT EXISTS(SELECT 1 FROM control.signing_rotation_command c JOIN control.signing_key_rotation r
     ON r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.rotation_id=c.rotation_id
     JOIN control.signing_rotation_observation o ON o.participant_id=c.participant_id AND o.privacy_domain_id=c.privacy_domain_id AND o.operation_id=c.operation_id
    WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
     AND c.operation_id=openpc.current_operation_id() AND c.state='WRITE_AMBIGUITY' AND o.kind='UNRESOLVED'
     AND NEW.signer_id IN(r.old_signer_id,r.new_signer_id))
   THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ADMISSION-VERSION'; END IF;
  RETURN NEW;
 END IF;
 IF NOT pg_has_role(current_user,'openpc_control_key_governor','MEMBER') AND
    NOT pg_has_role(current_user,'openpc_control_owner','MEMBER') THEN
  IF openpc.current_action_intent_id()<>'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' OR
   NOT EXISTS(SELECT 1 FROM control.signing_key_rotation r
    JOIN control.signing_rotation_command command ON command.participant_id=r.participant_id AND command.privacy_domain_id=r.privacy_domain_id
     AND command.rotation_id=r.rotation_id AND command.operation_id=openpc.current_operation_id()
     AND command.action_intent_id=openpc.current_action_intent_id() AND command.state IN ('ACCEPTED','WRITE_AMBIGUITY')
    CROSS JOIN LATERAL (SELECT openpc.signing_transition_effects(command.action_intent_id,r.state,command.to_state) value) effects
    WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
    AND NEW.change_reference='urn:openpc:resource:'||r.rotation_id::text AND r.approval_request_id IS NOT NULL
    AND ((TG_TABLE_NAME='business_signing_selection' AND (effects.value->>'cutover')::boolean AND
       (NEW.signer_id=r.new_signer_id OR (NEW.signer_id=r.old_signer_id AND EXISTS(
         SELECT 1 FROM control.signing_rotation_attestation a WHERE a.participant_id=r.participant_id AND a.privacy_domain_id=r.privacy_domain_id
          AND a.rotation_id=r.rotation_id AND a.operation_id=command.operation_id AND a.from_revision=r.revision
          AND a.to_state=command.to_state AND a.history_digest=NEW.change_digest
          AND to_jsonb(NEW)->>'fenced_operation_id'=a.operation_id::text))))
      OR (TG_TABLE_NAME='business_signing_key_state' AND
       (((effects.value->>'admitTrust')::boolean AND TG_OP='INSERT' AND NEW.signer_id=r.new_signer_id AND to_jsonb(NEW)->>'state'='ADMITTED')
        OR ((effects.value->>'cutover')::boolean AND ((NEW.signer_id=r.new_signer_id AND to_jsonb(NEW)->>'state'='ACTIVE')
          OR (NEW.signer_id=r.old_signer_id AND to_jsonb(NEW)->>'state'='RETIRED')))
        OR ((effects.value->>'revoke')::boolean AND NEW.signer_id=r.old_signer_id AND to_jsonb(NEW)->>'state'='REVOKED'))))) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='PC-AUTH-0005-KEY-GOVERNANCE-REQUIRED';
  END IF;
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
   IF NEW.environment_id<>OLD.environment_id OR NEW.profile_digest<>OLD.profile_digest OR NOT (
      (NEW.signer_id=OLD.signer_id AND OLD.fenced_operation_id IS NULL AND NEW.fenced_operation_id IS NOT NULL
       AND NEW.fenced_operation_id=openpc.current_operation_id() AND NEW.fence_generation=OLD.fence_generation+1) OR
      (NEW.signer_id<>OLD.signer_id AND OLD.fenced_operation_id IS NOT NULL AND OLD.fenced_operation_id=openpc.current_operation_id()
       AND NEW.fenced_operation_id IS NULL AND NEW.fence_generation=OLD.fence_generation))
   THEN RAISE EXCEPTION 'DATA-6021-KEY-SELECTION-TRANSITION'; END IF;
  END IF;
 ELSE
  IF NEW.row_version<>1 THEN RAISE EXCEPTION 'DATA-6021-KEY-LIFECYCLE-REVISION'; END IF;
  IF TG_TABLE_NAME='business_signing_key_state' THEN
   IF NEW.state<>'ADMITTED' THEN RAISE EXCEPTION 'DATA-6021-KEY-LIFECYCLE-TRANSITION'; END IF;
  END IF;
 END IF;
 IF TG_TABLE_NAME='business_signing_selection' THEN
  IF TG_OP='INSERT' AND (NEW.fence_generation<>1 OR NEW.admission_version<>1 OR NEW.fenced_operation_id IS NOT NULL) THEN RAISE EXCEPTION 'DATA-6021-KEY-SELECTION-FENCE'; END IF;
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


CREATE OR REPLACE FUNCTION openpc.identity_runtime_cose_key_id(evidence bytea,cose bytea)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE outer_item jsonb; fields jsonb; header jsonb; envelope jsonb; key_id text;
BEGIN
 IF octet_length(cose)=0 OR get_byte(cose,0)<>210 THEN RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-TAG'; END IF;
 outer_item:=openpc.business_cbor_item(cose,1,0);
 IF (outer_item->>'next')::integer<>octet_length(cose) THEN RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-TRAILING'; END IF;
 fields:=outer_item->'value';
 IF jsonb_typeof(fields) IS DISTINCT FROM 'array' OR jsonb_array_length(fields)<>4 OR
    fields->1 IS DISTINCT FROM '{}'::jsonb OR length(fields->3->>'bytes') IS DISTINCT FROM 128 THEN
  RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-BINDING'; END IF;
 envelope:=openpc.business_cbor(decode(fields->2->>'bytes','hex'));
 IF envelope IS DISTINCT FROM jsonb_build_object('0',1,'1',3002,'2',2,'3',openpc.business_cbor(evidence)) THEN
  RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-BINDING'; END IF;
 header:=openpc.business_cbor(decode(fields->0->>'bytes','hex'));
 IF header IS DISTINCT FROM jsonb_build_object('1',-8,'2',jsonb_build_array(100,101,102,103),'3','application/pc+cbor',
    '4',header->'4','100',3002,'101',2,'102','pc.cose.identity-runtime.v2','103',2) OR
    length(header->'4'->>'bytes') IS DISTINCT FROM 142 THEN
  RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-TYPED-PURPOSE-BINDING'; END IF;
 key_id:=convert_from(decode(header->'4'->>'bytes','hex'),'UTF8');
 IF key_id !~ '^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-KEY-ID'; END IF;
 RETURN key_id;
END $$;


CREATE OR REPLACE FUNCTION openpc.check_governed_configuration_receipt(receipt control.audit_occurrence)
RETURNS control.mutation_candidate LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE actual jsonb; approval control.approval_decision_record%ROWTYPE;
 evidence control.mutation_evidence%ROWTYPE; verification control.mutation_evidence%ROWTYPE;
 candidate control.mutation_candidate%ROWTYPE; request control.approval_request%ROWTYPE; challenge control.mfa_challenge%ROWTYPE;
BEGIN
 IF receipt.catalog_operation_id NOT IN ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE','CFG-OP-CREATE-EVIDENCE-HOLD','CFG-OP-RELEASE-EVIDENCE-HOLD','CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-DELETE-LOCAL-EVIDENCE','CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH','CFG-OP-DELETE-RAW-PROOF-BATCH','CFG-OP-DELETE-PROJECTION-BATCH','CFG-OP-ADMIT-STORE-RETIREMENT','CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE','CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH','CFG-OP-ACTIVATE-RETENTION-POLICY','CFG-OP-RETIRE-RETENTION-POLICY') THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-GOVERNED-RECEIPT'; END IF;
 SELECT * INTO STRICT candidate FROM control.mutation_candidate c WHERE c.participant_id=receipt.participant_id
  AND c.privacy_domain_id=receipt.privacy_domain_id AND c.catalog_operation_id=receipt.catalog_operation_id
  AND c.action_intent_id=receipt.action_intent_id AND c.resource_id=receipt.aggregate_id
  AND c.candidate_digest=receipt.candidate_digest AND c.state='CONSUMED' AND c.consumed_operation_id=receipt.operation_id;
 SELECT * INTO STRICT evidence FROM control.mutation_evidence e WHERE e.participant_id=receipt.participant_id
  AND e.privacy_domain_id=receipt.privacy_domain_id AND e.operation_id=receipt.operation_id
  AND e.catalog_operation_id=receipt.catalog_operation_id AND e.action_intent_id=receipt.action_intent_id
  AND e.aggregate_id=receipt.aggregate_id AND e.principal_id=candidate.maker_principal_id
  AND e.candidate_digest=receipt.candidate_digest;
 SELECT * INTO STRICT request FROM control.approval_request r WHERE r.participant_id=receipt.participant_id
  AND r.privacy_domain_id=receipt.privacy_domain_id AND r.approval_request_id=evidence.approval_request_id
  AND r.subject_type='CONFIGURATION_CANDIDATE' AND r.subject_id=candidate.mutation_candidate_id
  AND r.subject_digest=candidate.candidate_digest AND r.subject_version=candidate.expected_revision
  AND r.action_intent_id=receipt.action_intent_id AND r.maker_principal_id=candidate.maker_principal_id;
 SELECT * INTO STRICT approval FROM control.approval_decision_record d WHERE d.participant_id=receipt.participant_id
  AND d.privacy_domain_id=receipt.privacy_domain_id AND d.approval_request_id=request.approval_request_id
  AND d.decision='APPROVE' AND d.approver_principal_id=evidence.checker_principal_id
  AND d.approver_principal_id<>evidence.principal_id AND d.candidate_digest=receipt.candidate_digest
  AND d.aggregate_version=candidate.expected_revision AND d.evidence_cbor=evidence.evidence_cbor
  AND sha256(d.evidence_cbor)=evidence.evidence_digest
  AND d.decision_digest=sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
   'actionIntentId','ACT-POLICY_APPROVE_REQUEST-V1',
   'approvalRequestId','urn:openpc:resource:'||request.approval_request_id::text,
   'candidateDigest','sha256:'||encode(candidate.candidate_digest,'hex'),
   'decision','APPROVE','expectedRevision','1')),'UTF8'))
  AND d.cose_sign1=evidence.cose_sign1;
 SELECT * INTO STRICT challenge FROM control.mfa_challenge c WHERE c.participant_id=receipt.participant_id
  AND c.principal_id=evidence.principal_id AND c.mfa_challenge_id=evidence.mfa_challenge_id
  AND c.action_intent_id=receipt.action_intent_id AND c.resource_digest=receipt.candidate_digest
  AND c.used_operation_id=receipt.operation_id AND c.used_at IS NOT NULL;
 SELECT * INTO STRICT verification FROM control.mutation_evidence v WHERE v.participant_id=receipt.participant_id
  AND v.privacy_domain_id=receipt.privacy_domain_id AND v.principal_id=evidence.principal_id
  AND v.mfa_challenge_id=challenge.mfa_challenge_id AND v.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
  AND v.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
  AND v.evidence_digest=sha256(v.evidence_cbor);
 actual:=openpc.business_cbor(receipt.receipt_cbor);
 IF actual->'20' IS DISTINCT FROM jsonb_build_array(
  jsonb_build_object('0',3,'1',approval.approval_decision_id::text,'2',openpc.business_bytes(sha256(approval.evidence_cbor))),
  jsonb_build_object('0',4,'1',verification.mutation_evidence_id::text,'2',openpc.business_bytes(verification.evidence_digest)))
  OR receipt.actor_key_digest<>sha256(convert_to('pc.identity.actor-key.v2','UTF8')||decode('00','hex')||
    int4send(octet_length(convert_to(receipt.participant_id::text,'UTF8')))||convert_to(receipt.participant_id::text,'UTF8')||
    int4send(octet_length(convert_to(evidence.principal_id::text,'UTF8')))||convert_to(evidence.principal_id::text,'UTF8'))
 THEN RAISE EXCEPTION 'DATA-6021-GOVERNED-EVIDENCE'; END IF;
 RETURN candidate;
END $$;
CREATE OR REPLACE FUNCTION openpc.configuration_step_up_receipt_input(receipt control.audit_occurrence,authorization_row control.mutation_evidence)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE verification control.mutation_evidence%ROWTYPE; snapshot jsonb;
BEGIN
 IF receipt.catalog_operation_id NOT IN ('CFG-OP-CREATE-NOTIFICATION-ENDPOINT','CFG-OP-UPDATE-NOTIFICATION-ENDPOINT') OR authorization_row.approval_request_id IS NOT NULL
  OR authorization_row.checker_principal_id IS NOT NULL OR authorization_row.mfa_challenge_id IS NULL
  OR authorization_row.webauthn_assertion_binding_digest IS NULL
 THEN RAISE EXCEPTION 'DATA-6021-STEP-UP-RECEIPT-ADMISSION'; END IF;
 snapshot:=convert_from(receipt.authority_snapshot,'UTF8')::jsonb;
 SELECT v.* INTO STRICT verification FROM control.mutation_evidence v
  JOIN control.mfa_challenge c ON c.participant_id=v.participant_id AND c.mfa_challenge_id=v.mfa_challenge_id
   AND c.principal_id=v.principal_id AND c.session_id=v.aggregate_id
  JOIN control.idempotency_record committed ON committed.participant_id=v.participant_id
   AND committed.privacy_domain_id=v.privacy_domain_id AND committed.principal_id=v.principal_id
   AND committed.operation_id=v.operation_id AND committed.catalog_operation_id=v.catalog_operation_id
   AND committed.input_digest=v.candidate_digest AND committed.terminal_state='COMMITTED'
   AND committed.webauthn_assertion_binding_digest=v.webauthn_assertion_binding_digest
  WHERE v.participant_id=receipt.participant_id AND v.privacy_domain_id=receipt.privacy_domain_id
   AND v.principal_id=authorization_row.principal_id AND v.mfa_challenge_id=authorization_row.mfa_challenge_id
   AND v.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1' AND v.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
   AND v.aggregate_type='webauthn-verification' AND v.evidence_digest=sha256(v.evidence_cbor)
   AND v.webauthn_assertion_binding_digest=authorization_row.webauthn_assertion_binding_digest
   AND c.action_intent_id=receipt.action_intent_id
   AND c.resource_digest=receipt.candidate_digest AND c.used_operation_id=receipt.operation_id
   AND c.used_at IS NOT NULL AND c.consumed_at IS NOT NULL
   AND extract(epoch from c.consumed_at)*1000000000<=receipt.recorded_at_ns
   AND extract(epoch from c.consumed_at)*1000000000>receipt.recorded_at_ns-300000000000
   AND (SELECT count(*) FROM jsonb_array_elements(snapshot->'authorities') a
    WHERE a->>'principalId'=v.principal_id::text AND a->>'sessionId'=c.session_id::text
     AND a->>'actionIntentId'=receipt.action_intent_id AND a->>'resourceId'=receipt.aggregate_id::text)=1
   AND EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=v.participant_id
    AND e.privacy_domain_id=v.privacy_domain_id AND e.aggregate_type=v.aggregate_type AND e.aggregate_id=v.aggregate_id
    AND e.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
    AND e.payload_cbor=v.evidence_cbor AND e.payload_digest=v.evidence_digest AND e.cose_sign1=v.cose_sign1
    AND e.webauthn_assertion_binding_digest=v.webauthn_assertion_binding_digest);
 RETURN jsonb_build_object('0',4,'1',verification.mutation_evidence_id::text,'2',openpc.business_bytes(verification.evidence_digest));
END $$;
REVOKE ALL ON FUNCTION openpc.configuration_step_up_receipt_input(control.audit_occurrence,control.mutation_evidence) FROM PUBLIC;


CREATE OR REPLACE FUNCTION openpc.check_module_admission_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE projection jsonb; candidate control.mutation_candidate%ROWTYPE;
BEGIN
 IF receipt.catalog_operation_id NOT IN ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE') OR receipt.aggregate_type<>'module-registration'
  OR receipt.after_existence<>1 OR (receipt.catalog_operation_id='MOD-OP-REGISTER' AND
   (receipt.before_existence<>0 OR receipt.before_revision<>0 OR receipt.after_revision<>1))
  OR (receipt.catalog_operation_id<>'MOD-OP-REGISTER' AND
   (receipt.before_existence<>1 OR receipt.before_revision<1 OR receipt.after_revision<>receipt.before_revision+1))
 THEN RAISE EXCEPTION 'DATA-6021-MODULE-TRANSITION'; END IF;
 candidate:=openpc.check_governed_configuration_receipt(receipt);
 projection:=openpc.business_cbor(receipt.after_state_preimage)->8;
 IF receipt.catalog_operation_id<>'MOD-OP-REGISTER' THEN
  PERFORM openpc.check_module_lifecycle_state(receipt);
  RETURN;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.module_installation m JOIN control.module_version v USING(module_version_id)
  JOIN control.module_configuration_generation c USING(module_installation_id)
  WHERE m.participant_id=receipt.participant_id AND m.privacy_domain_id=receipt.privacy_domain_id
   AND m.module_installation_id=receipt.aggregate_id AND c.participant_id=m.participant_id AND c.privacy_domain_id=m.privacy_domain_id
   AND m.state='ADMITTED' AND m.aggregate_version=1 AND m.active_manifest_digest IS NULL
   AND c.generation=1 AND c.active=false AND v.release_payload_cbor IS NOT NULL
   AND v.module_id=candidate.candidate_document->>'name'
   AND v.semantic_version=candidate.candidate_document->>'semanticVersion'
   AND 'sha256:'||encode(v.manifest_digest,'hex')=candidate.candidate_document->>'manifestDigest'
   AND projection=jsonb_build_object('0',v.module_id,'1',v.semantic_version,'2',openpc.business_bytes(v.manifest_digest),
    '3',openpc.business_bytes(m.admission_dependency_digest),'4',openpc.business_bytes(c.configuration_digest),
    '5','ADMITTED','6',0,'7',1,'8',0))
 THEN RAISE EXCEPTION 'DATA-6021-MODULE-DURABLE-STATE'; END IF;
END $$;


CREATE OR REPLACE FUNCTION openpc.work_item_business_projection(item control.work_item)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',(item).kind,'1',(item).state,
  '2',(item).resource_ref,'3',openpc.business_bytes((item).payload_digest),
  '4',openpc.business_bytes(sha256(convert_to((item).reason,'UTF8'))),
  '5',openpc.business_uuid((item).created_by_principal_id),
  '6',CASE WHEN (item).assignee_principal_id IS NULL THEN 0 ELSE 1 END,
  '8',CASE WHEN (item).claimed_by_principal_id IS NULL THEN 0 ELSE 1 END,
  '10',CASE WHEN (item).completed_by_principal_id IS NULL THEN 0 ELSE 1 END)
  || CASE WHEN (item).assignee_principal_id IS NULL THEN '{}'::jsonb
     ELSE jsonb_build_object('7',openpc.business_uuid((item).assignee_principal_id)) END
  || CASE WHEN (item).claimed_by_principal_id IS NULL THEN '{}'::jsonb
     ELSE jsonb_build_object('9',openpc.business_uuid((item).claimed_by_principal_id)) END
  || CASE WHEN (item).completed_by_principal_id IS NULL THEN '{}'::jsonb
     ELSE jsonb_build_object('11',openpc.business_uuid((item).completed_by_principal_id)) END
$$;
CREATE OR REPLACE FUNCTION openpc.assert_work_item_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.work_item%ROWTYPE; before_state jsonb; after_state jsonb;
 before_projection jsonb; after_projection jsonb; actor uuid;
BEGIN
 IF receipt.profile_version<>1 OR receipt.catalog_operation_id NOT IN
  ('CFG-OP-CREATE-WORK-ITEM','CFG-OP-UPDATE-WORK-ITEM','CFG-OP-CLAIM-WORK-ITEM','CFG-OP-COMPLETE-WORK-ITEM')
 THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-PROFILE'; END IF;
 SELECT * INTO STRICT item FROM control.work_item w WHERE w.participant_id=receipt.participant_id
  AND w.privacy_domain_id=receipt.privacy_domain_id AND w.work_item_id=receipt.aggregate_id;
 SELECT principal_id INTO STRICT actor FROM control.mutation_evidence e
  WHERE e.participant_id=receipt.participant_id AND e.privacy_domain_id=receipt.privacy_domain_id
   AND e.operation_id=receipt.operation_id AND e.action_intent_id=receipt.action_intent_id
   AND e.catalog_operation_id=receipt.catalog_operation_id AND e.aggregate_id=receipt.aggregate_id
   AND e.candidate_digest=receipt.candidate_digest;
 before_state:=openpc.business_cbor(receipt.before_state_preimage);
 after_state:=openpc.business_cbor(receipt.after_state_preimage);
 before_projection:=before_state->8; after_projection:=after_state->8;
 IF receipt.after_existence<>1 OR receipt.after_revision<>item.row_version
  OR after_projection IS DISTINCT FROM openpc.work_item_business_projection(item)
 THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-ACTUAL-STATE'; END IF;
 IF receipt.catalog_operation_id='CFG-OP-CREATE-WORK-ITEM' THEN
  IF receipt.before_existence<>0 OR receipt.before_revision<>0 OR receipt.after_revision<>1
   OR item.state<>'OPEN' OR item.created_by_principal_id<>actor
   OR item.claimed_by_principal_id IS NOT NULL OR item.completed_by_principal_id IS NOT NULL
   OR (item.assignee_principal_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM control.principal p
    WHERE p.participant_id=item.participant_id AND p.principal_id=item.assignee_principal_id AND p.state='ACTIVE'))
  THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-CREATE'; END IF;
 ELSE
  IF receipt.before_existence<>1 OR receipt.after_revision<>receipt.before_revision+1
   OR jsonb_typeof(before_projection) IS DISTINCT FROM 'object'
   OR NOT before_projection ?& ARRAY['0','1','2','3','4','5','6','8','10']
   OR before_projection-ARRAY['0','1','2','3','4','5','6','7','8','9','10','11']<>'{}'::jsonb
   OR EXISTS (SELECT 1 FROM (VALUES ('6','7'),('8','9'),('10','11')) AS presence(marker,value)
     WHERE before_projection->marker NOT IN ('0'::jsonb,'1'::jsonb)
       OR (before_projection->marker='1'::jsonb) IS DISTINCT FROM (before_projection ? value))
  THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-BEFORE-STATE'; END IF;
  IF receipt.catalog_operation_id='CFG-OP-UPDATE-WORK-ITEM' THEN
   IF before_projection->>'1'<>'OPEN' OR item.state<>'OPEN'
    OR before_projection-ARRAY['3','4'] IS DISTINCT FROM after_projection-ARRAY['3','4']
    OR before_projection->'3'=after_projection->'3'
   THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-UPDATE'; END IF;
  ELSIF receipt.catalog_operation_id='CFG-OP-CLAIM-WORK-ITEM' THEN
   IF before_projection->>'1'<>'OPEN' OR item.state<>'CLAIMED'
    OR before_projection-ARRAY['1','6','7','8','9'] IS DISTINCT FROM after_projection-ARRAY['1','6','7','8','9']
    OR (before_projection->'6'='1'::jsonb AND before_projection->'7' IS DISTINCT FROM openpc.business_uuid(actor))
    OR before_projection->'8' IS DISTINCT FROM '0'::jsonb
    OR item.assignee_principal_id IS DISTINCT FROM actor OR item.claimed_by_principal_id IS DISTINCT FROM actor
    OR item.completed_by_principal_id IS NOT NULL
   THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-CLAIM'; END IF;
  ELSE
   IF before_projection->>'1'<>'CLAIMED' OR item.state<>'COMPLETED'
    OR before_projection-ARRAY['1','10','11'] IS DISTINCT FROM after_projection-ARRAY['1','10','11']
    OR before_projection->'10' IS DISTINCT FROM '0'::jsonb
    OR item.assignee_principal_id IS DISTINCT FROM actor OR item.claimed_by_principal_id IS DISTINCT FROM actor
    OR item.completed_by_principal_id IS DISTINCT FROM actor
   THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-COMPLETE'; END IF;
  END IF;
 END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_work_item_effect_receipt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.audit_occurrence%ROWTYPE; before_projection jsonb;
BEGIN
 -- WHEN is evaluated when the row changes, so later context changes cannot
 -- remove the queued check. Internal source-owned effects retain their owners.
 SELECT * INTO STRICT receipt FROM control.audit_occurrence r WHERE r.participant_id=NEW.participant_id
  AND r.privacy_domain_id=NEW.privacy_domain_id AND r.aggregate_type='work-item'
  AND r.aggregate_id=NEW.work_item_id AND r.after_revision=NEW.row_version
  AND r.catalog_operation_id IN ('CFG-OP-CREATE-WORK-ITEM','CFG-OP-UPDATE-WORK-ITEM',
   'CFG-OP-CLAIM-WORK-ITEM','CFG-OP-COMPLETE-WORK-ITEM');
 IF TG_OP='INSERT' THEN before_projection:='{}'::jsonb;
 ELSE before_projection:=openpc.work_item_business_projection(OLD); END IF;
 IF openpc.business_cbor(receipt.before_state_preimage)->8 IS DISTINCT FROM before_projection
  OR openpc.business_cbor(receipt.after_state_preimage)->8 IS DISTINCT FROM openpc.work_item_business_projection(NEW)
  OR receipt.before_revision IS DISTINCT FROM (CASE WHEN TG_OP='INSERT' THEN 0 ELSE OLD.row_version END)
 THEN RAISE EXCEPTION 'DATA-6021-WORK-ITEM-EFFECT-RECEIPT'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS work_item_effect_receipt ON control.work_item;
DROP TRIGGER IF EXISTS work_item_effect_receipt ON control.work_item;
CREATE CONSTRAINT TRIGGER work_item_effect_receipt AFTER INSERT OR UPDATE ON control.work_item
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
 WHEN (current_setting('openpc.action_intent_id',true) IN ('ACT-WORK_ITEMS_CREATE_RESOURCE-V1',
  'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1','ACT-OPERATIONS_UPDATE_CLAIM-V1','ACT-OPERATIONS_UPDATE_COMPLETE-V1'))
 EXECUTE FUNCTION openpc.check_work_item_effect_receipt();

CREATE OR REPLACE FUNCTION openpc.guard_business_profile_admission()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.definition_canonical_json NOT IN (decode('7b22616374696f6e496e74656e744964223a224143542d4e4f54494649434154494f4e5f454e44504f494e54535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a226e6f74696669636174696f6e2d656e64706f696e74222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d2c7b2262696e64696e67223a2273616d652072756e74696d652d617574686f72697a6564206163746f7220616e642073657373696f6e3b20657861637420616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f4143544f525f574542415554484e5f424f554e445f544f5f5448455f53414d455f53455353494f4e5f414354494f4e5f43414e4449444154455f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d4352454154452d4e4f54494649434154494f4e2d454e44504f494e54222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a22656e64706f696e74206d65746164617461206f7220766572696669636174696f6e206973206e6f74206e6f74696669636174696f6e2064656c69766572792061646d697373696f6e3b2063757272656e742064656c69766572792d737065636966696320617574686f7269747920616e64207265666572656e6365732072656d61696e206d616e6461746f7279222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2272656164206f726967696e616c206f7065726174696f6e20616e642064757261626c6520766572696669636174696f6e20617474656d70743b2044495350415443484544206f7220554e4b4e4f574e206e6576657220617574686f72697a6573206175746f6d617469632065787465726e616c2072657375626d697373696f6e222c22726f6c6c6261636b223a22656e64706f696e742073746174652c20766572696669636174696f6e206174746163686d656e742c20636f6e73756d6564206163746f72206368616c6c656e67652c20617574686f726974792c207369676e696e6720617474656d70742c20726563656970742c206f7574626f7820616e64206f7065726174696f6e20726573756c7420726f6c6c206261636b20746f6765746865723b2065787465726e616c20766572696669636174696f6e206f62736572766174696f6e2072656d61696e732072657461696e6564227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e6e6f74696669636174696f6e2d656e64706f696e742e637265617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a226e6f74696669636174696f6e2d656e64706f696e7473222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b2065696768742072657175697265642070726f6a656374696f6e206b65797320616e6420766572696669636174696f6e205555494420746578742065786163746c79207768656e206974732070726573656e6365206d61726b6572206973206f6e65222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22656e64706f696e745f6964225d2c226f776e6572223a22636f6e74726f6c2e6e6f74696669636174696f6e5f656e64706f696e74222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226368616e6e656c222c22656e756d223a5b22574542484f4f4b222c22454d41494c222c224f5045524154494f4e535f5155455545225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b22414354495645222c2244495341424c4544222c2251554152414e54494e4544222c2252455449524544225d2c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a2264657374696e6174696f6e5f726566222c22656e636f64696e67223a2265786163742061646d69747465642064657374696e6174696f6e2055524e3b206e6576657220616e20617262697472617279206e6574776f726b2061646472657373222c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a226368616e6e656c5f70726f66696c655f646967657374222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2263726564656e7469616c5f726566222c22656e636f64696e67223a2265786163742061646d697474656420696d6d757461626c652063726564656e7469616c206d657461646174612055524e3b206e6f20736563726574206279746573222c2274797065223a2254455854227d2c2235223a7b22636f6c756d6e223a226172626974726172795f656772657373222c22656e636f64696e67223a226d757374206265207a65726f222c2274797065223a22553634227d2c2236223a7b22636f6c756d6e223a2263616e6469646174655f646967657374222c2274797065223a22483332227d2c2237223a7b22636f6c756d6e223a22766572696669636174696f6e5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e7420555549442074657874222c2274797065223a22553634227d2c2238223a7b22636f6c756d6e223a22766572696669636174696f6e5f6964222c22656e636f64696e67223a2265786163742073746f7265642063616e6f6e6963616c205555494476372074657874222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203720697320313b20616273656e74207768656e206b657920372069732030222c2274797065223a2254455854227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f44495341424c45445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a22436f6e73747275637420612064697361626c656420656e64706f696e742066726f6d2063757272656e746c792061646d6974746564206368616e6e656c2c2064657374696e6174696f6e20616e642063726564656e7469616c206d657461646174613b206e6f2064656c69766572792e222c22636f6d6d616e64223a22435245415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d4e4f54494649434154494f4e5f454e44504f494e54535f5550444154455f5245534f555243452d5631222c2261676772656761746554797065223a226e6f74696669636174696f6e2d656e64706f696e74222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d2c7b2262696e64696e67223a2273616d652072756e74696d652d617574686f72697a6564206163746f7220616e642073657373696f6e3b20657861637420616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f4143544f525f574542415554484e5f424f554e445f544f5f5448455f53414d455f53455353494f4e5f414354494f4e5f43414e4449444154455f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d5550444154452d4e4f54494649434154494f4e2d454e44504f494e54222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a22656e64706f696e74206d65746164617461206f7220766572696669636174696f6e206973206e6f74206e6f74696669636174696f6e2064656c69766572792061646d697373696f6e3b2063757272656e742064656c69766572792d737065636966696320617574686f7269747920616e64207265666572656e6365732072656d61696e206d616e6461746f7279222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2272656164206f726967696e616c206f7065726174696f6e20616e642064757261626c6520766572696669636174696f6e20617474656d70743b2044495350415443484544206f7220554e4b4e4f574e206e6576657220617574686f72697a6573206175746f6d617469632065787465726e616c2072657375626d697373696f6e222c22726f6c6c6261636b223a22656e64706f696e742073746174652c20766572696669636174696f6e206174746163686d656e742c20636f6e73756d6564206163746f72206368616c6c656e67652c20617574686f726974792c207369676e696e6720617474656d70742c20726563656970742c206f7574626f7820616e64206f7065726174696f6e20726573756c7420726f6c6c206261636b20746f6765746865723b2065787465726e616c20766572696669636174696f6e206f62736572766174696f6e2072656d61696e732072657461696e6564227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e6e6f74696669636174696f6e2d656e64706f696e742e757064617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a226e6f74696669636174696f6e2d656e64706f696e7473222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b2065696768742072657175697265642070726f6a656374696f6e206b65797320616e6420766572696669636174696f6e205555494420746578742065786163746c79207768656e206974732070726573656e6365206d61726b6572206973206f6e65222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22656e64706f696e745f6964225d2c226f776e6572223a22636f6e74726f6c2e6e6f74696669636174696f6e5f656e64706f696e74222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226368616e6e656c222c22656e756d223a5b22574542484f4f4b222c22454d41494c222c224f5045524154494f4e535f5155455545225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b22414354495645222c2244495341424c4544222c2251554152414e54494e4544222c2252455449524544225d2c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a2264657374696e6174696f6e5f726566222c22656e636f64696e67223a2265786163742061646d69747465642064657374696e6174696f6e2055524e3b206e6576657220616e20617262697472617279206e6574776f726b2061646472657373222c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a226368616e6e656c5f70726f66696c655f646967657374222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2263726564656e7469616c5f726566222c22656e636f64696e67223a2265786163742061646d697474656420696d6d757461626c652063726564656e7469616c206d657461646174612055524e3b206e6f20736563726574206279746573222c2274797065223a2254455854227d2c2235223a7b22636f6c756d6e223a226172626974726172795f656772657373222c22656e636f64696e67223a226d757374206265207a65726f222c2274797065223a22553634227d2c2236223a7b22636f6c756d6e223a2263616e6469646174655f646967657374222c2274797065223a22483332227d2c2237223a7b22636f6c756d6e223a22766572696669636174696f6e5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e7420555549442074657874222c2274797065223a22553634227d2c2238223a7b22636f6c756d6e223a22766572696669636174696f6e5f6964222c22656e636f64696e67223a2265786163742073746f7265642063616e6f6e6963616c205555494476372074657874222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203720697320313b20616273656e74207768656e206b657920372069732030222c2274797065223a2254455854227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f44495341424c45445f4f525f5052455345525645445f51554152414e54494e455f5245564953494f4e5f504c55535f31222c226265666f7265223a2250524553454e545f4e4f545f52455449524544222c226368616e6765223a22436f6e73756d652074686520696d6d757461626c652061646d6974746564207265706c6163656d656e7420626f756e6420746f207468652063757272656e74207072656465636573736f723b20636c65617220766572696669636174696f6e2c2070726573657276652071756172616e74696e6520616e642072656a65637420756e6368616e676564207265706c6163656d656e742e222c22636f6d6d616e64223a22555044415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d4e4f54494649434154494f4e5f5550444154455f5645524946592d5631222c2261676772656761746554797065223a226e6f74696669636174696f6e2d656e64706f696e74222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d5645524946592d4e4f54494649434154494f4e2d454e44504f494e54222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a22656e64706f696e74206d65746164617461206f7220766572696669636174696f6e206973206e6f74206e6f74696669636174696f6e2064656c69766572792061646d697373696f6e3b2063757272656e742064656c69766572792d737065636966696320617574686f7269747920616e64207265666572656e6365732072656d61696e206d616e6461746f7279222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2272656164206f726967696e616c206f7065726174696f6e20616e642064757261626c6520766572696669636174696f6e20617474656d70743b2044495350415443484544206f7220554e4b4e4f574e206e6576657220617574686f72697a6573206175746f6d617469632065787465726e616c2072657375626d697373696f6e222c22726f6c6c6261636b223a22656e64706f696e742073746174652c20766572696669636174696f6e206174746163686d656e742c20636f6e73756d6564206163746f72206368616c6c656e67652c20617574686f726974792c207369676e696e6720617474656d70742c20726563656970742c206f7574626f7820616e64206f7065726174696f6e20726573756c7420726f6c6c206261636b20746f6765746865723b2065787465726e616c20766572696669636174696f6e206f62736572766174696f6e2072656d61696e732072657461696e6564227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e6e6f74696669636174696f6e2d656e64706f696e742e766572696679222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a226e6f74696669636174696f6e2d656e64706f696e74222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b2065696768742072657175697265642070726f6a656374696f6e206b65797320616e6420766572696669636174696f6e205555494420746578742065786163746c79207768656e206974732070726573656e6365206d61726b6572206973206f6e65222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22656e64706f696e745f6964225d2c226f776e6572223a22636f6e74726f6c2e6e6f74696669636174696f6e5f656e64706f696e74222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226368616e6e656c222c22656e756d223a5b22574542484f4f4b222c22454d41494c222c224f5045524154494f4e535f5155455545225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b22414354495645222c2244495341424c4544222c2251554152414e54494e4544222c2252455449524544225d2c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a2264657374696e6174696f6e5f726566222c22656e636f64696e67223a2265786163742061646d69747465642064657374696e6174696f6e2055524e3b206e6576657220616e20617262697472617279206e6574776f726b2061646472657373222c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a226368616e6e656c5f70726f66696c655f646967657374222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2263726564656e7469616c5f726566222c22656e636f64696e67223a2265786163742061646d697474656420696d6d757461626c652063726564656e7469616c206d657461646174612055524e3b206e6f20736563726574206279746573222c2274797065223a2254455854227d2c2235223a7b22636f6c756d6e223a226172626974726172795f656772657373222c22656e636f64696e67223a226d757374206265207a65726f222c2274797065223a22553634227d2c2236223a7b22636f6c756d6e223a2263616e6469646174655f646967657374222c2274797065223a22483332227d2c2237223a7b22636f6c756d6e223a22766572696669636174696f6e5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e7420555549442074657874222c2274797065223a22553634227d2c2238223a7b22636f6c756d6e223a22766572696669636174696f6e5f6964222c22656e636f64696e67223a2265786163742073746f7265642063616e6f6e6963616c205555494476372074657874222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203720697320313b20616273656e74207768656e206b657920372069732030222c2274797065223a2254455854227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f4143544956455f5245564953494f4e5f504c55535f31222c226265666f7265223a2250524553454e545f44495341424c45445f4f525f414354495645222c226368616e6765223a2241746f6d6963616c6c7920617474616368206f6e652066726573682061757468656e74696361746564206e6f6e2d64656c69766572792050524f564544206f62736572766174696f6e20746f2074686973206f7065726174696f6e3b207072657365727665206578616374207072656465636573736f722062696e64696e672c2063726564656e7469616c206d6574616461746120616e64206f726967696e616c207369676e656420726573706f6e73652062797465732e222c22636f6d6d616e64223a22564552494659222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d4e4f54494649434154494f4e535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a226e6f74696669636174696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d4352454154452d4e4f54494649434154494f4e222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f74696669636174696f6e206d657461646174612c20617574686f726974792c207369676e696e6720617474656d70742c20726563656970742c206f7574626f7820616e64206f7065726174696f6e20726573756c7420726f6c6c206261636b20746f676574686572227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e6e6f74696669636174696f6e2e637265617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a226e6f74696669636174696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b20666976652062617365206669656c647320616e64207265736f757263652055524e2065786163746c79207768656e2070726573656e6365206d61726b657220332069732031222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c226e6f74696669636174696f6e5f6964225d2c226f776e6572223a22636f6e74726f6c2e6e6f74696669636174696f6e222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a227365766572697479222c22656e756d223a5b22494e464f222c225741524e494e47222c224552524f52222c22435249544943414c225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b22554e52454144222c2252454144222c2241434b4e4f574c4544474544225d2c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a226d6573736167655f6b6579222c22656e636f64696e67223a2272656769737465726564206d657373616765206b65793b206e657665722072656e6465726564206f72207072697661746520626f6479222c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a227265736f757263655f726566222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742065786163742055524e222c2274797065223a22553634227d2c2234223a7b22636f6c756d6e223a227265736f757263655f726566222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203320697320313b20616273656e74207768656e206b657920332069732030222c2274797065223a2254455854227d2c2235223a7b22636f6c756d6e223a2263616e6469646174655f646967657374222c22656e636f64696e67223a225348412d323536206f66206f726967696e616c2072657461696e6564206372656174696f6e2063616e6469646174653b207072657365727665206163726f73732061636b6e6f776c656467656d656e74222c2274797065223a22483332227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f554e524541445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a226372656174652065786163742073636f706564207075626c6963206d657461646174613b206e6f2064656c69766572792c20726563697069656e742073656c656374696f6e206f722061636b6e6f776c656467656d656e74222c22636f6d6d616e64223a22435245415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d4e4f54494649434154494f4e5f5550444154455f41434b4e4f574c454447452d5631222c2261676772656761746554797065223a226e6f74696669636174696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d41434b4e4f574c454447452d4e4f54494649434154494f4e222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f74696669636174696f6e206d657461646174612c20617574686f726974792c207369676e696e6720617474656d70742c20726563656970742c206f7574626f7820616e64206f7065726174696f6e20726573756c7420726f6c6c206261636b20746f676574686572227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e6e6f74696669636174696f6e2e61636b6e6f776c65646765222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a226e6f74696669636174696f6e222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b20666976652062617365206669656c647320616e64207265736f757263652055524e2065786163746c79207768656e2070726573656e6365206d61726b657220332069732031222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c226e6f74696669636174696f6e5f6964225d2c226f776e6572223a22636f6e74726f6c2e6e6f74696669636174696f6e222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a227365766572697479222c22656e756d223a5b22494e464f222c225741524e494e47222c224552524f52222c22435249544943414c225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b22554e52454144222c2252454144222c2241434b4e4f574c4544474544225d2c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a226d6573736167655f6b6579222c22656e636f64696e67223a2272656769737465726564206d657373616765206b65793b206e657665722072656e6465726564206f72207072697661746520626f6479222c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a227265736f757263655f726566222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742065786163742055524e222c2274797065223a22553634227d2c2234223a7b22636f6c756d6e223a227265736f757263655f726566222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203320697320313b20616273656e74207768656e206b657920332069732030222c2274797065223a2254455854227d2c2235223a7b22636f6c756d6e223a2263616e6469646174655f646967657374222c22656e636f64696e67223a225348412d323536206f66206f726967696e616c2072657461696e6564206372656174696f6e2063616e6469646174653b207072657365727665206163726f73732061636b6e6f776c656467656d656e74222c2274797065223a22483332227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f41434b4e4f574c45444745445f5245564953494f4e5f504c55535f31222c226265666f7265223a2250524553454e545f554e524541445f4f525f52454144222c226368616e6765223a2261636b6e6f776c6564676520756e6465722063757272656e74207573657220617574686f726974793b2070726573657276652073657665726974792c206d657373616765206b65792c207265736f7572636520616e64206f726967696e616c2063616e6469646174652062696e64696e673b207472616e73706f7274207375636365737320646f6573206e6f742061636b6e6f776c65646765222c22636f6d6d616e64223a2241434b4e4f574c45444745222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d574f524b5f4954454d535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a22776f726b2d6974656d222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d4352454154452d574f524b2d4954454d222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a22776f726b206974656d2c20617574686f72697a6174696f6e2065766964656e63652c207369676e696e6720617474656d70742c20726563656970742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420726f6c6c206261636b20746f676574686572227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e776f726b2d6974656d2e637265617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22776f726b2d6974656d73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b20636c6f736564206d61702077697468207369782072657175697265642062617365206669656c64732c2074687265652072657175697265642070726573656e6365206d61726b65727320616e642055554944206669656c64732065786163746c79207768656e2070726573656e74222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22776f726b5f6974656d5f6964225d2c226f776e6572223a22636f6e74726f6c2e776f726b5f6974656d222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226b696e64222c22656e756d223a5b22415050524f56414c222c2252454d4544494154494f4e222c2244454c49564552595f4641494c555245222c22464c4545545f4641494c555245222c2245564944454e43455f4241434b4c4f47225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b224f50454e222c22434c41494d4544222c22434f4d504c45544544222c2243414e43454c4c4544225d2c2274797065223a2254455854227d2c223130223a7b22636f6c756d6e223a22636f6d706c657465645f62795f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22636f6d706c657465645f62795f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b657920313020697320313b20616273656e74207768656e206b65792031302069732030222c2274797065223a22555549445f4259544553227d2c2232223a7b22636f6c756d6e223a227265736f757263655f726566222c22656e636f64696e67223a2265786163742073746f726564204f70656e5043207265736f757263652055524e222c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a227061796c6f61645f646967657374222c22656e636f64696e67223a2265786163742073746f726564203332206279746573222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a22726561736f6e222c22656e636f64696e67223a225348412d323536206f662065786163742073746f726564205554462d382062797465733b206e6f20726561736f6e207465787420696e207468652072656365697074222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22637265617465645f62795f7072696e636970616c5f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a2261737369676e65655f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c2237223a7b22636f6c756d6e223a2261737369676e65655f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203620697320313b20616273656e74207768656e206b657920362069732030222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a22636c61696d65645f62795f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a22636c61696d65645f62795f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203820697320313b20616273656e74207768656e206b657920382069732030222c2274797065223a22555549445f4259544553227d7d2c227265766973696f6e223a22726f775f76657273696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f4f50454e5f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a22637265617465207468652073636f70656420776f726b206974656d2077697468206974732061637475616c2063726561746f723b206f7074696f6e616c206163746976652061737369676e65653b206e6f20636c61696d206f7220636f6d706c6574696f6e206163746f72222c22636f6d6d616e64223a22435245415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d574f524b5f4954454d535f5550444154455f5245534f555243452d5631222c2261676772656761746554797065223a22776f726b2d6974656d222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d5550444154452d574f524b2d4954454d222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a22776f726b206974656d2c20617574686f72697a6174696f6e2065766964656e63652c207369676e696e6720617474656d70742c20726563656970742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420726f6c6c206261636b20746f676574686572227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e776f726b2d6974656d2e757064617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22776f726b2d6974656d73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b20636c6f736564206d61702077697468207369782072657175697265642062617365206669656c64732c2074687265652072657175697265642070726573656e6365206d61726b65727320616e642055554944206669656c64732065786163746c79207768656e2070726573656e74222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22776f726b5f6974656d5f6964225d2c226f776e6572223a22636f6e74726f6c2e776f726b5f6974656d222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226b696e64222c22656e756d223a5b22415050524f56414c222c2252454d4544494154494f4e222c2244454c49564552595f4641494c555245222c22464c4545545f4641494c555245222c2245564944454e43455f4241434b4c4f47225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b224f50454e222c22434c41494d4544222c22434f4d504c45544544222c2243414e43454c4c4544225d2c2274797065223a2254455854227d2c223130223a7b22636f6c756d6e223a22636f6d706c657465645f62795f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22636f6d706c657465645f62795f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b657920313020697320313b20616273656e74207768656e206b65792031302069732030222c2274797065223a22555549445f4259544553227d2c2232223a7b22636f6c756d6e223a227265736f757263655f726566222c22656e636f64696e67223a2265786163742073746f726564204f70656e5043207265736f757263652055524e222c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a227061796c6f61645f646967657374222c22656e636f64696e67223a2265786163742073746f726564203332206279746573222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a22726561736f6e222c22656e636f64696e67223a225348412d323536206f662065786163742073746f726564205554462d382062797465733b206e6f20726561736f6e207465787420696e207468652072656365697074222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22637265617465645f62795f7072696e636970616c5f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a2261737369676e65655f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c2237223a7b22636f6c756d6e223a2261737369676e65655f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203620697320313b20616273656e74207768656e206b657920362069732030222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a22636c61696d65645f62795f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a22636c61696d65645f62795f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203820697320313b20616273656e74207768656e206b657920382069732030222c2274797065223a22555549445f4259544553227d7d2c227265766973696f6e223a22726f775f76657273696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f4f50454e5f5245564953494f4e5f504c55535f31222c226265666f7265223a2250524553454e545f4f50454e222c226368616e6765223a227265706c61636520746865207061796c6f61642064696765737420616e6420726561736f6e206f6e6c793b20746865207265706c6163656d656e7420646967657374206d757374206469666665723b2072657461696e206964656e746974792c206b696e642c207265736f7572636520616e6420616c6c206163746f7273222c22636f6d6d616e64223a22555044415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d4f5045524154494f4e535f5550444154455f434c41494d2d5631222c2261676772656761746554797065223a22776f726b2d6974656d222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d434c41494d2d574f524b2d4954454d222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a22776f726b206974656d2c20617574686f72697a6174696f6e2065766964656e63652c207369676e696e6720617474656d70742c20726563656970742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420726f6c6c206261636b20746f676574686572227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e776f726b2d6974656d2e636c61696d222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22776f726b2d6974656d222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b20636c6f736564206d61702077697468207369782072657175697265642062617365206669656c64732c2074687265652072657175697265642070726573656e6365206d61726b65727320616e642055554944206669656c64732065786163746c79207768656e2070726573656e74222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22776f726b5f6974656d5f6964225d2c226f776e6572223a22636f6e74726f6c2e776f726b5f6974656d222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226b696e64222c22656e756d223a5b22415050524f56414c222c2252454d4544494154494f4e222c2244454c49564552595f4641494c555245222c22464c4545545f4641494c555245222c2245564944454e43455f4241434b4c4f47225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b224f50454e222c22434c41494d4544222c22434f4d504c45544544222c2243414e43454c4c4544225d2c2274797065223a2254455854227d2c223130223a7b22636f6c756d6e223a22636f6d706c657465645f62795f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22636f6d706c657465645f62795f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b657920313020697320313b20616273656e74207768656e206b65792031302069732030222c2274797065223a22555549445f4259544553227d2c2232223a7b22636f6c756d6e223a227265736f757263655f726566222c22656e636f64696e67223a2265786163742073746f726564204f70656e5043207265736f757263652055524e222c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a227061796c6f61645f646967657374222c22656e636f64696e67223a2265786163742073746f726564203332206279746573222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a22726561736f6e222c22656e636f64696e67223a225348412d323536206f662065786163742073746f726564205554462d382062797465733b206e6f20726561736f6e207465787420696e207468652072656365697074222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22637265617465645f62795f7072696e636970616c5f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a2261737369676e65655f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c2237223a7b22636f6c756d6e223a2261737369676e65655f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203620697320313b20616273656e74207768656e206b657920362069732030222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a22636c61696d65645f62795f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a22636c61696d65645f62795f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203820697320313b20616273656e74207768656e206b657920382069732030222c2274797065223a22555549445f4259544553227d7d2c227265766973696f6e223a22726f775f76657273696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f434c41494d45445f5245564953494f4e5f504c55535f31222c226265666f7265223a2250524553454e545f4f50454e222c226368616e6765223a227468652061757468656e74696361746564206163746f7220636c61696d7320616e20756e61737369676e6564206f722073656c662d61737369676e6564206974656d3b207265636f726420746861742073616d65206163746f722061732061737369676e656520616e6420636c61696d616e743b2072657461696e207061796c6f616420616e6420726561736f6e222c22636f6d6d616e64223a22434c41494d222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d4f5045524154494f4e535f5550444154455f434f4d504c4554452d5631222c2261676772656761746554797065223a22776f726b2d6974656d222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d434f4d504c4554452d574f524b2d4954454d222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a22776f726b206974656d2c20617574686f72697a6174696f6e2065766964656e63652c207369676e696e6720617474656d70742c20726563656970742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420726f6c6c206261636b20746f676574686572227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e776f726b2d6974656d2e636f6d706c657465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22776f726b2d6974656d222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b20636c6f736564206d61702077697468207369782072657175697265642062617365206669656c64732c2074687265652072657175697265642070726573656e6365206d61726b65727320616e642055554944206669656c64732065786163746c79207768656e2070726573656e74222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22776f726b5f6974656d5f6964225d2c226f776e6572223a22636f6e74726f6c2e776f726b5f6974656d222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226b696e64222c22656e756d223a5b22415050524f56414c222c2252454d4544494154494f4e222c2244454c49564552595f4641494c555245222c22464c4545545f4641494c555245222c2245564944454e43455f4241434b4c4f47225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b224f50454e222c22434c41494d4544222c22434f4d504c45544544222c2243414e43454c4c4544225d2c2274797065223a2254455854227d2c223130223a7b22636f6c756d6e223a22636f6d706c657465645f62795f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22636f6d706c657465645f62795f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b657920313020697320313b20616273656e74207768656e206b65792031302069732030222c2274797065223a22555549445f4259544553227d2c2232223a7b22636f6c756d6e223a227265736f757263655f726566222c22656e636f64696e67223a2265786163742073746f726564204f70656e5043207265736f757263652055524e222c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a227061796c6f61645f646967657374222c22656e636f64696e67223a2265786163742073746f726564203332206279746573222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a22726561736f6e222c22656e636f64696e67223a225348412d323536206f662065786163742073746f726564205554462d382062797465733b206e6f20726561736f6e207465787420696e207468652072656365697074222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22637265617465645f62795f7072696e636970616c5f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a2261737369676e65655f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c2237223a7b22636f6c756d6e223a2261737369676e65655f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203620697320313b20616273656e74207768656e206b657920362069732030222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a22636c61696d65645f62795f7072696e636970616c5f6964222c22656e636f64696e67223a223020666f72204e554c4c3b203120666f722070726573656e742055554944222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a22636c61696d65645f62795f7072696e636970616c5f6964222c2270726573656e6365223a2272657175697265642065786163746c79207768656e206b6579203820697320313b20616273656e74207768656e206b657920382069732030222c2274797065223a22555549445f4259544553227d7d2c227265766973696f6e223a22726f775f76657273696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f434f4d504c455445445f5245564953494f4e5f504c55535f31222c226265666f7265223a2250524553454e545f434c41494d4544222c226368616e6765223a226f6e6c7920746865206578697374696e672061757468656e7469636174656420636c61696d616e7420636f6d706c657465733b2072657461696e2061737369676e65652c20636c61696d616e742c207061796c6f616420616e6420726561736f6e20616e642062696e642074686174206163746f7220617320636f6d706c65746572222c22636f6d6d616e64223a22434f4d504c455445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d494e44455845525f50524f46494c45535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a22696e64657865722d70726f66696c65222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d4352454154452d494e44455845522d50524f46494c45222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e696e64657865722d70726f66696c652e637265617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22696e64657865722d70726f66696c6573222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22696e64657865725f70726f66696c655f6964225d2c226f776e6572223a22636f6e74726f6c2e696e64657865725f70726f66696c65222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22656e67696e65222c22656e756d223a5b22434c49454e545f494e4445584552222c2245585445524e414c5f454e47494e455f41444150544552225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a22656e67696e655f76657273696f6e222c227061747465726e223a225e5b412d5a612d7a302d395d5b412d5a612d7a302d392e5f2d5d7b302c36337d24222c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a226d6574686f645f70726f66696c655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b2252454749535445524544222c22534841444f57222c225155414c4946494544222c22414354495645222c2251554152414e54494e4544222c2252455449524544225d2c2274797065223a2254455854227d2c2234223a7b22636f6c756d6e223a22706f6c6963795f67656e65726174696f6e5f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f524547495354455245445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a2272657175657374656420656e67696e652c20656e67696e6556657273696f6e2c206d6574686f6450726f66696c654469676573743b2061637475616c20706f6c69637947656e65726174696f6e446967657374222c22636f6d6d616e64223a22435245415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d494e44455845525f50524f46494c45535f5550444154455f5245534f555243452d5631222c2261676772656761746554797065223a22696e64657865722d70726f66696c65222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d5550444154452d494e44455845522d50524f46494c45222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e696e64657865722d70726f66696c652e757064617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22696e64657865722d70726f66696c6573222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22696e64657865725f70726f66696c655f6964225d2c226f776e6572223a22636f6e74726f6c2e696e64657865725f70726f66696c65222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22656e67696e65222c22656e756d223a5b22434c49454e545f494e4445584552222c2245585445524e414c5f454e47494e455f41444150544552225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a22656e67696e655f76657273696f6e222c227061747465726e223a225e5b412d5a612d7a302d395d5b412d5a612d7a302d392e5f2d5d7b302c36337d24222c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a226d6574686f645f70726f66696c655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b2252454749535445524544222c22534841444f57222c225155414c4946494544222c22414354495645222c2251554152414e54494e4544222c2252455449524544225d2c2274797065223a2254455854227d2c2234223a7b22636f6c756d6e223a22706f6c6963795f67656e65726174696f6e5f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5245564953494f4e5f504c55535f4f4e45222c226265666f7265223a2250524553454e545f41545f45585045435445445f5245564953494f4e222c226368616e6765223a22726571756573746564207265706c6163656d656e74206d6574686f6450726f66696c654469676573743b20707265736572766520656e67696e652c20656e67696e6556657273696f6e2c2073746174653b206d6574686f6450726f66696c65446967657374206f7220706f6c69637947656e65726174696f6e446967657374206d757374206368616e6765222c22636f6d6d616e64223a22555044415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d494e44455845525f50524f46494c45535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a22696e64657865722d70726f66696c65222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d4352454154452d494e44455845522d50524f46494c45222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b22626f6f747374726170223a22416273656e7420706f6c6963792070726f76656e616e6365206973207065726d6974746564206f6e6c7920666f7220676f7665726e6564206e6f6e2d73657276696e67207072657061726174696f6e20696e2061207072697661637920646f6d61696e2077697468206e6f20706f6c6963792d67656e65726174696f6e20686973746f72793b206e6569746865722074686973207374617465206e6f72206974732072656365697074206772616e74732072756e74696d6520617574686f726974792e222c2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e696e64657865722d70726f66696c652e637265617465222c2270726f66696c6556657273696f6e223a322c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22696e64657865722d70726f66696c6573222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206669656c6420352070726573656e742065786163746c79207768656e206669656c6420342069732031222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22696e64657865725f70726f66696c655f6964225d2c226f776e6572223a22636f6e74726f6c2e696e64657865725f70726f66696c65222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22656e67696e65222c22656e756d223a5b22434c49454e545f494e4445584552222c2245585445524e414c5f454e47494e455f41444150544552225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a22656e67696e655f76657273696f6e222c227061747465726e223a225e5b412d5a612d7a302d395d5b412d5a612d7a302d392e5f2d5d7b302c36337d24222c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a226d6574686f645f70726f66696c655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b2252454749535445524544222c22534841444f57222c225155414c4946494544222c22414354495645222c2251554152414e54494e4544222c2252455449524544225d2c2274797065223a2254455854227d2c2234223a7b22636f6c756d6e223a22706f6c6963795f67656e65726174696f6e5f646967657374222c22656e636f64696e67223a2250726573656e63653a203020616273656e742c20312070726573656e743b206669656c6420352072657175697265642065786163746c79207768656e2070726573656e74222c2274797065223a22553634227d2c2235223a7b22636f6c756d6e223a22706f6c6963795f67656e65726174696f6e5f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2270726573656e6365223a22726571756972656420696666206669656c6420342069732031222c2274797065223a22483332227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f524547495354455245445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a2272657175657374656420656e67696e652c20656e67696e6556657273696f6e2c206d6574686f6450726f66696c654469676573743b2061637475616c20706f6c69637947656e65726174696f6e446967657374222c22636f6d6d616e64223a22435245415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d494e44455845525f50524f46494c45535f5550444154455f5245534f555243452d5631222c2261676772656761746554797065223a22696e64657865722d70726f66696c65222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a224e4f545f5245515549524544222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c206f7065726174696f6e2c206163746f722c2073657373696f6e2c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c20636174616c6f67206f7065726174696f6e2c2063616e64696461746520616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a224e4f545f5245515549524544227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d5550444154452d494e44455845522d50524f46494c45222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b22626f6f747374726170223a22416273656e7420706f6c6963792070726f76656e616e6365206973207065726d6974746564206f6e6c7920666f7220676f7665726e6564206e6f6e2d73657276696e67207072657061726174696f6e20696e2061207072697661637920646f6d61696e2077697468206e6f20706f6c6963792d67656e65726174696f6e20686973746f72793b206e6569746865722074686973207374617465206e6f72206974732072656365697074206772616e74732072756e74696d6520617574686f726974792e222c2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e696e64657865722d70726f66696c652e757064617465222c2270726f66696c6556657273696f6e223a322c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22696e64657865722d70726f66696c6573222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206669656c6420352070726573656e742065786163746c79207768656e206669656c6420342069732031222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22696e64657865725f70726f66696c655f6964225d2c226f776e6572223a22636f6e74726f6c2e696e64657865725f70726f66696c65222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22656e67696e65222c22656e756d223a5b22434c49454e545f494e4445584552222c2245585445524e414c5f454e47494e455f41444150544552225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a22656e67696e655f76657273696f6e222c227061747465726e223a225e5b412d5a612d7a302d395d5b412d5a612d7a302d392e5f2d5d7b302c36337d24222c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a226d6574686f645f70726f66696c655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b2252454749535445524544222c22534841444f57222c225155414c4946494544222c22414354495645222c2251554152414e54494e4544222c2252455449524544225d2c2274797065223a2254455854227d2c2234223a7b22636f6c756d6e223a22706f6c6963795f67656e65726174696f6e5f646967657374222c22656e636f64696e67223a2250726573656e63653a203020616273656e742c20312070726573656e743b206669656c6420352072657175697265642065786163746c79207768656e2070726573656e74222c2274797065223a22553634227d2c2235223a7b22636f6c756d6e223a22706f6c6963795f67656e65726174696f6e5f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2270726573656e6365223a22726571756972656420696666206669656c6420342069732031222c2274797065223a22483332227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5245564953494f4e5f504c55535f4f4e45222c226265666f7265223a2250524553454e545f41545f45585045435445445f5245564953494f4e222c226368616e6765223a22726571756573746564207265706c6163656d656e74206d6574686f6450726f66696c654469676573743b20707265736572766520656e67696e652c20656e67696e6556657273696f6e2c2073746174653b206d6574686f6450726f66696c65446967657374206f7220706f6c69637947656e65726174696f6e446967657374206d757374206368616e6765222c22636f6d6d616e64223a22555044415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f484f4c44535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a2265766964656e63652d686f6c64222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d4352454154452d45564944454e43452d484f4c44222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d686f6c642e637265617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d686f6c6473222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22726574656e74696f6e5f686f6c645f6964225d2c226f776e6572223a22636f6e74726f6c2e726574656e74696f6e5f686f6c64222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22686f6c645f6b696e64222c22656e756d223a5b224c4547414c222c22524547554c41544f5259222c22494e434944454e54225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a2273656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2232223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b22414354495645222c2252454c4541534544225d2c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2234223a7b22636f6c756d6e223a226372656174696f6e5f6f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2235223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a2272656c656173655f617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2236223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a2272656c656173655f6f7065726174696f6e5f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2237223a7b22636f6c756d6e223a226566666563746976655f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c2238223a7b22636f6c756d6e223a22757064617465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c69656420627920313030303b207465726d696e616c2072656c65617365206375746f6666222c2274797065223a225536345f4e414e4f5345434f4e4453227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f4143544956455f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a2265786163742063616e6f6e6963616c2073656c6563746f722064696765737420616e64206b696e642c20636f6e73756d656420617070726f76616c2c206372656174696f6e206f7065726174696f6e20616e642061637475616c206566666563746976652074696d65222c22636f6d6d616e64223a22435245415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f484f4c44535f52454c454153455f5245534f555243452d5631222c2261676772656761746554797065223a2265766964656e63652d686f6c64222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d52454c454153452d45564944454e43452d484f4c44222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d686f6c642e72656c65617365222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d686f6c6473222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22726574656e74696f6e5f686f6c645f6964225d2c226f776e6572223a22636f6e74726f6c2e726574656e74696f6e5f686f6c64222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22686f6c645f6b696e64222c22656e756d223a5b224c4547414c222c22524547554c41544f5259222c22494e434944454e54225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a2273656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2232223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b22414354495645222c2252454c4541534544225d2c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2234223a7b22636f6c756d6e223a226372656174696f6e5f6f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2235223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a2272656c656173655f617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2236223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a2272656c656173655f6f7065726174696f6e5f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2237223a7b22636f6c756d6e223a226566666563746976655f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c2238223a7b22636f6c756d6e223a22757064617465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c69656420627920313030303b207465726d696e616c2072656c65617365206375746f6666222c2274797065223a225536345f4e414e4f5345434f4e4453227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f52454c45415345445f5245564953494f4e5f32222c226265666f7265223a2250524553454e545f4143544956455f5245564953494f4e5f31222c226368616e6765223a2272657461696e20696d6d757461626c652073656c6563746f722f6b696e642f6372656174696f6e2070726f76656e616e63653b2062696e6420736570617261746520636f6e73756d656420617070726f76616c2c2072656c65617365206f7065726174696f6e20616e642061637475616c2072656c65617365206375746f6666222c22636f6d6d616e64223a2252454c45415345222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f484f4c44535f4352454154455f5041525449434950414e542d5631222c2261676772656761746554797065223a2265766964656e63652d686f6c64222c22617574686f72697479223a7b22616374696f6e223a224578706c69636974205061727469636970616e742d7769646520707265736572766174696f6e20616374696f6e207468726f75676820746865206f7264696e617279206c69766520656e76656c6f70652f61737369676e6d656e742f726f6c6520616e6420696e646570656e64656e7420636865636b65722066656e6365733b20676f7665726e616e6365206f6363757273206f6e6c7920696e20746865205061727469636970616e7420726f6f74207072697661637920646f6d61696e2e204120707269766163792d646f6d61696e20686f6c6420616374696f6e20697320696e73756666696369656e742e222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d4352454154452d5041525449434950414e542d45564944454e43452d484f4c44222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a22476f7665726e616e636520726563656970742072656d61696e7320696e20746865205061727469636970616e7420726f6f74207072697661637920646f6d61696e2e20546865205041525449434950414e542073656c6563746f7220707265736572766573206578697374696e6720616e6420667574757265206d61746368696e67207265636f72647320696e206576657279207072697661637920646f6d61696e206f662074686973205061727469636970616e74206f6e6c792e20436f76657261676520726563656970747320616e6420736f75726365207265616473207374617920696e2065616368206578706c6963697420746172676574207072697661637920646f6d61696e2e222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d7061727469636970616e742d686f6c642e637265617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d686f6c6473222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22726574656e74696f6e5f686f6c645f6964225d2c226f776e6572223a22636f6e74726f6c2e726574656e74696f6e5f686f6c64222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22686f6c645f6b696e64222c22656e756d223a5b224c4547414c222c22524547554c41544f5259222c22494e434944454e54225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a2273656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2232223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b22414354495645222c2252454c4541534544225d2c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2234223a7b22636f6c756d6e223a226372656174696f6e5f6f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2235223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a2272656c656173655f617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2236223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a2272656c656173655f6f7065726174696f6e5f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2237223a7b22636f6c756d6e223a226566666563746976655f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c2238223a7b22636f6c756d6e223a22757064617465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c69656420627920313030303b207465726d696e616c2072656c65617365206375746f6666222c2274797065223a225536345f4e414e4f5345434f4e4453227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f4143544956455f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a2265786163742063616e6f6e6963616c2073656c6563746f722064696765737420616e64206b696e642c20636f6e73756d656420617070726f76616c2c206372656174696f6e206f7065726174696f6e20616e642061637475616c206566666563746976652074696d65222c22636f6d6d616e64223a22435245415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f484f4c44535f52454c454153455f5041525449434950414e542d5631222c2261676772656761746554797065223a2265766964656e63652d686f6c64222c22617574686f72697479223a7b22616374696f6e223a224578706c69636974205061727469636970616e742d7769646520707265736572766174696f6e20616374696f6e207468726f75676820746865206f7264696e617279206c69766520656e76656c6f70652f61737369676e6d656e742f726f6c6520616e6420696e646570656e64656e7420636865636b65722066656e6365733b20676f7665726e616e6365206f6363757273206f6e6c7920696e20746865205061727469636970616e7420726f6f74207072697661637920646f6d61696e2e204120707269766163792d646f6d61696e20686f6c6420616374696f6e20697320696e73756666696369656e742e222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d52454c454153452d5041525449434950414e542d45564944454e43452d484f4c44222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a22476f7665726e616e636520726563656970742072656d61696e7320696e20746865205061727469636970616e7420726f6f74207072697661637920646f6d61696e2e20546865205041525449434950414e542073656c6563746f7220707265736572766573206578697374696e6720616e6420667574757265206d61746368696e67207265636f72647320696e206576657279207072697661637920646f6d61696e206f662074686973205061727469636970616e74206f6e6c792e20436f76657261676520726563656970747320616e6420736f75726365207265616473207374617920696e2065616368206578706c6963697420746172676574207072697661637920646f6d61696e2e222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d7061727469636970616e742d686f6c642e72656c65617365222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d686f6c6473222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22726574656e74696f6e5f686f6c645f6964225d2c226f776e6572223a22636f6e74726f6c2e726574656e74696f6e5f686f6c64222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22686f6c645f6b696e64222c22656e756d223a5b224c4547414c222c22524547554c41544f5259222c22494e434944454e54225d2c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a2273656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2232223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b22414354495645222c2252454c4541534544225d2c2274797065223a2254455854227d2c2233223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2234223a7b22636f6c756d6e223a226372656174696f6e5f6f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2235223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a2272656c656173655f617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2236223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a2272656c656173655f6f7065726174696f6e5f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2237223a7b22636f6c756d6e223a226566666563746976655f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c2238223a7b22636f6c756d6e223a22757064617465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c69656420627920313030303b207465726d696e616c2072656c65617365206375746f6666222c2274797065223a225536345f4e414e4f5345434f4e4453227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f52454c45415345445f5245564953494f4e5f32222c226265666f7265223a2250524553454e545f4143544956455f5245564953494f4e5f31222c226368616e6765223a2272657461696e20696d6d757461626c652073656c6563746f722f6b696e642f6372656174696f6e2070726f76656e616e63653b2062696e6420736570617261746520636f6e73756d656420617070726f76616c2c2072656c65617365206f7065726174696f6e20616e642061637475616c2072656c65617365206375746f6666222c22636f6d6d616e64223a2252454c45415345222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a2265766964656e63652d64656c6574696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d44454c4554452d4c4f43414c2d45564944454e4345222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e6520626f756e646564206c6f63616c20506f737467726553514c2063697068657274657874207061796c6f61642064656c6574696f6e3b206f746865722065766964656e63652073746f72616765206c6f636174696f6e7320616e6420736f75726365207265636f7264732072657461696e20696e646570656e64656e74206c69666574696d6573222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d657267653b206f6e6520696e697469616c20626f756e646564206f626a6563742073656c6563746f722077697468207072696f72437572736f723d6e756c6c2069732066696e616c20696e207468697320636f6d6d6974222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a227061796c6f61642c206163636f756e74696e672c2064656c6574696f6e206a6f622c20656666656374206974656d2c2065766964656e63652c207369676e696e6720617474656d70742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d64656c6574696f6e2e6c6f63616c222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c2264656c6574696f6e5f6a6f625f6964225d2c226f776e6572223a22636f6e74726f6c2e64656c6574696f6e5f6a6f62222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22726574656e74696f6e5f706f6c6963795f6964222c2274797065223a22555549445f4259544553227d2c2231223a7b22636f6c756d6e223a227461726765745f73656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c223130223a7b22636f6c756d6e223a2272657461696e65645f616c6961735f636f756e74222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22737461727465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223132223a7b22636f6c756d6e223a22636f6d706c657465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223133223a7b22636f6c756d6e223a226265666f72655f757365645f6279746573222c2274797065223a22553634227d2c223134223a7b22636f6c756d6e223a2261667465725f757365645f6279746573222c2274797065223a22553634227d2c2232223a7b22636f6c756d6e223a22656c69676962696c6974795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a226265666f72655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2261667465725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22617474656d70745f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2237223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a2264656c657465645f636f756e74222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a2264656c657465645f6279746573222c2274797065223a22553634227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5355434345454445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a226f6e6520657861637420617070726f766564206c6f63616c2063697068657274657874206f626a6563742072656d6f766564206279207072696d617279206b65793b2061637475616c204f4c44207061796c6f6164206566666563742c2073747265616d206163636f756e74696e672c20706f6c69637920616e6420656c69676962696c6974792062696e64696e672c2072657461696e656420696d6d757461626c6520637573746f6479206d6574616461746120616e64207369676e656420726573756c7420636f6d6d69742061746f6d6963616c6c79222c22636f6d6d616e64223a2244454c4554455f4c4f43414c5f5041594c4f4144222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f4352454154455f42415443482d5631222c2261676772656761746554797065223a2265766964656e63652d64656c6574696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d44454c4554452d4c4f43414c2d45564944454e43452d4241544348222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e6520626f756e646564206c6f63616c20506f737467726553514c2063697068657274657874207061796c6f61642064656c6574696f6e3b206f746865722065766964656e63652073746f72616765206c6f636174696f6e7320616e6420736f75726365207265636f7264732072657461696e20696e646570656e64656e74206c69666574696d6573222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a22656163682062617463682068617320696e646570656e64656e74206d616b65722d636865636b657220617070726f76616c20616e6420667265736820576562417574686e3b206f6e65206f626a656374207065722061746f6d69632062617463682c206f72646572656420627920696d6d757461626c65207365676d656e74207072696d617279206b65793b2074686520707265636564696e6720636f6d6d6974746564206a6f6220616e64207369676e656420726563656970742062696e6420746865206578616374206e657874207461726765742f636f756e742f6265666f7265206469676573743b206c69766520706f6c6963792c20686f6c642c2071756f72756d2c20636865636b706f696e742c20736f7572636520616e64207265666572656e636520676174657320617265207265636865636b65643b20636f6e63757272656e7420636f6e74696e756174696f6e20686173206f6e652064757261626c6520737563636573736f723b207061727469616c2070726f67726573732069732072657461696e65642c20616e642066696e616c20637572736f72207265706f72747320434f4d504c455445206f6e6c7920616674657220746865206c61737420636f6d6d6974746564207369676e6564206261746368222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a227061796c6f61642c206163636f756e74696e672c2064656c6574696f6e206a6f622c20656666656374206974656d2c2065766964656e63652c207369676e696e6720617474656d70742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d64656c6574696f6e2e6261746368222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c2264656c6574696f6e5f6a6f625f6964225d2c226f776e6572223a22636f6e74726f6c2e64656c6574696f6e5f6a6f62222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22726574656e74696f6e5f706f6c6963795f6964222c2274797065223a22555549445f4259544553227d2c2231223a7b22636f6c756d6e223a227461726765745f73656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c223130223a7b22636f6c756d6e223a2272657461696e65645f616c6961735f636f756e74222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22737461727465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223132223a7b22636f6c756d6e223a22636f6d706c657465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223133223a7b22636f6c756d6e223a226265666f72655f757365645f6279746573222c2274797065223a22553634227d2c223134223a7b22636f6c756d6e223a2261667465725f757365645f6279746573222c2274797065223a22553634227d2c2232223a7b22636f6c756d6e223a22656c69676962696c6974795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a226265666f72655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2261667465725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22617474656d70745f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2237223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a2264656c657465645f636f756e74222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a2264656c657465645f6279746573222c2274797065223a22553634227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5355434345454445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a226f6e6520657861637420617070726f766564206c6f63616c2063697068657274657874206f626a6563742072656d6f766564206279207072696d617279206b65792066726f6d20616e20696d6d757461626c65206f7264657265642073656c656374696f6e206f66206174206d6f7374203136206f626a656374733b2074686520656c69676962696c697479206469676573742062696e64732065766572792074617267657420616e6420697473206265666f7265206469676573742c2074686520626174636820696e64657820616e642074686520707265636564696e67207369676e656420726563656970743b2061637475616c204f4c44207061796c6f61642c206163636f756e74696e672c207369676e656420726573756c7420616e64206f7574626f7820636f6d6d69742061746f6d6963616c6c79222c22636f6d6d616e64223a2244454c4554455f4c4f43414c5f5041594c4f41445f4241544348222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a2265766964656e63652d64656c6574696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d44454c4554452d4c4f43414c2d45564944454e4345222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e6520626f756e646564206c6f63616c20506f737467726553514c2063697068657274657874207061796c6f61642064656c6574696f6e3b206f746865722065766964656e63652073746f72616765206c6f636174696f6e7320616e6420736f75726365207265636f7264732072657461696e20696e646570656e64656e74206c69666574696d6573222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d657267653b206f6e6520696e697469616c20626f756e646564206f626a6563742073656c6563746f722077697468207072696f72437572736f723d6e756c6c2069732066696e616c20696e207468697320636f6d6d6974222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a227061796c6f61642c206163636f756e74696e672c2064656c6574696f6e206a6f622c20656666656374206974656d2c2065766964656e63652c207369676e696e6720617474656d70742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b222c22736f757263655265746972656d656e74223a22466f7220616e2052504320736f757263652c2074686520636f6d706c6574652073656c656374696f6e20696e636c7564657320736f757263655270635265746972656d656e7473207769746820657861637420736f757263652065766964656e63652f7265636f72642f726563656970742064696765737420616e64206f726967696e616c206e6f726d616c697a6564207265746972656d656e74206a6f622f726563656970742f7265746972656d656e74206469676573742e20496e646570656e64656e746c79207665726966792069747320686973746f726963616c207369676e656420627573696e65737320726563656970742c20636f6e73756d65642063616e6469646174652c20747970656420636f6d6d697474656420737461746520616e64206f7574626f783b2072657175697265206e6f206c697665206e6f726d616c697a6564207369626c696e6720666f722074686520636c6f73656420525043206964656e746974792e205072657365727665206f726967696e616c20736f757263652c207369676e65642062797465732c20696d6d757461626c65207365676d656e74206d6574616461746120616e6420696e646570656e64656e742061726368697665732e205468697320697320686973746f726963616c20706879736963616c2d7265746972656d656e742070726f6f662c206e657665722061206e6f2d73656e642072656a656374696f6e206f7220617574686f7269747920746f207265706c617920616e205250432e205265636865636b206c69766520706f6c6963792c20686f6c642c20636865636b706f696e7420616e64207265666572656e636520676174657320756e646572207468652065766964656e6365206c6966656379636c652066656e63652e227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d64656c6574696f6e2e6c6f63616c222c2270726f66696c6556657273696f6e223a322c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c2264656c6574696f6e5f6a6f625f6964225d2c226f776e6572223a22636f6e74726f6c2e64656c6574696f6e5f6a6f62222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22726574656e74696f6e5f706f6c6963795f6964222c2274797065223a22555549445f4259544553227d2c2231223a7b22636f6c756d6e223a227461726765745f73656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c223130223a7b22636f6c756d6e223a2272657461696e65645f616c6961735f636f756e74222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22737461727465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223132223a7b22636f6c756d6e223a22636f6d706c657465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223133223a7b22636f6c756d6e223a226265666f72655f757365645f6279746573222c2274797065223a22553634227d2c223134223a7b22636f6c756d6e223a2261667465725f757365645f6279746573222c2274797065223a22553634227d2c2232223a7b22636f6c756d6e223a22656c69676962696c6974795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a226265666f72655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2261667465725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22617474656d70745f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2237223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a2264656c657465645f636f756e74222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a2264656c657465645f6279746573222c2274797065223a22553634227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5355434345454445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a226f6e6520657861637420617070726f766564206c6f63616c2063697068657274657874206f626a6563742072656d6f766564206279207072696d617279206b65793b2061637475616c204f4c44207061796c6f6164206566666563742c2073747265616d206163636f756e74696e672c20706f6c69637920616e6420656c69676962696c6974792062696e64696e672c2072657461696e656420696d6d757461626c6520637573746f6479206d6574616461746120616e64207369676e656420726573756c7420636f6d6d69742061746f6d6963616c6c79222c22636f6d6d616e64223a2244454c4554455f4c4f43414c5f5041594c4f4144222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f4352454154455f42415443482d5631222c2261676772656761746554797065223a2265766964656e63652d64656c6574696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d44454c4554452d4c4f43414c2d45564944454e43452d4241544348222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e6520626f756e646564206c6f63616c20506f737467726553514c2063697068657274657874207061796c6f61642064656c6574696f6e3b206f746865722065766964656e63652073746f72616765206c6f636174696f6e7320616e6420736f75726365207265636f7264732072657461696e20696e646570656e64656e74206c69666574696d6573222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a22656163682062617463682068617320696e646570656e64656e74206d616b65722d636865636b657220617070726f76616c20616e6420667265736820576562417574686e3b206f6e65206f626a656374207065722061746f6d69632062617463682c206f72646572656420627920696d6d757461626c65207365676d656e74207072696d617279206b65793b2074686520707265636564696e6720636f6d6d6974746564206a6f6220616e64207369676e656420726563656970742062696e6420746865206578616374206e657874207461726765742f636f756e742f6265666f7265206469676573743b206c69766520706f6c6963792c20686f6c642c2071756f72756d2c20636865636b706f696e742c20736f7572636520616e64207265666572656e636520676174657320617265207265636865636b65643b20636f6e63757272656e7420636f6e74696e756174696f6e20686173206f6e652064757261626c6520737563636573736f723b207061727469616c2070726f67726573732069732072657461696e65642c20616e642066696e616c20637572736f72207265706f72747320434f4d504c455445206f6e6c7920616674657220746865206c61737420636f6d6d6974746564207369676e6564206261746368222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a227061796c6f61642c206163636f756e74696e672c2064656c6574696f6e206a6f622c20656666656374206974656d2c2065766964656e63652c207369676e696e6720617474656d70742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b222c22736f757263655265746972656d656e74223a22466f7220616e2052504320736f757263652c2074686520636f6d706c6574652073656c656374696f6e20696e636c7564657320736f757263655270635265746972656d656e7473207769746820657861637420736f757263652065766964656e63652f7265636f72642f726563656970742064696765737420616e64206f726967696e616c206e6f726d616c697a6564207265746972656d656e74206a6f622f726563656970742f7265746972656d656e74206469676573742e20496e646570656e64656e746c79207665726966792069747320686973746f726963616c207369676e656420627573696e65737320726563656970742c20636f6e73756d65642063616e6469646174652c20747970656420636f6d6d697474656420737461746520616e64206f7574626f783b2072657175697265206e6f206c697665206e6f726d616c697a6564207369626c696e6720666f722074686520636c6f73656420525043206964656e746974792e205072657365727665206f726967696e616c20736f757263652c207369676e65642062797465732c20696d6d757461626c65207365676d656e74206d6574616461746120616e6420696e646570656e64656e742061726368697665732e205468697320697320686973746f726963616c20706879736963616c2d7265746972656d656e742070726f6f662c206e657665722061206e6f2d73656e642072656a656374696f6e206f7220617574686f7269747920746f207265706c617920616e205250432e205265636865636b206c69766520706f6c6963792c20686f6c642c20636865636b706f696e7420616e64207265666572656e636520676174657320756e646572207468652065766964656e6365206c6966656379636c652066656e63652e227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d64656c6574696f6e2e6261746368222c2270726f66696c6556657273696f6e223a322c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c2264656c6574696f6e5f6a6f625f6964225d2c226f776e6572223a22636f6e74726f6c2e64656c6574696f6e5f6a6f62222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22726574656e74696f6e5f706f6c6963795f6964222c2274797065223a22555549445f4259544553227d2c2231223a7b22636f6c756d6e223a227461726765745f73656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c223130223a7b22636f6c756d6e223a2272657461696e65645f616c6961735f636f756e74222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22737461727465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223132223a7b22636f6c756d6e223a22636f6d706c657465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223133223a7b22636f6c756d6e223a226265666f72655f757365645f6279746573222c2274797065223a22553634227d2c223134223a7b22636f6c756d6e223a2261667465725f757365645f6279746573222c2274797065223a22553634227d2c2232223a7b22636f6c756d6e223a22656c69676962696c6974795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a226265666f72655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2261667465725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22617474656d70745f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2237223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a2264656c657465645f636f756e74222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a2264656c657465645f6279746573222c2274797065223a22553634227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5355434345454445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a226f6e6520657861637420617070726f766564206c6f63616c2063697068657274657874206f626a6563742072656d6f766564206279207072696d617279206b65792066726f6d20616e20696d6d757461626c65206f7264657265642073656c656374696f6e206f66206174206d6f7374203136206f626a656374733b2074686520656c69676962696c697479206469676573742062696e64732065766572792074617267657420616e6420697473206265666f7265206469676573742c2074686520626174636820696e64657820616e642074686520707265636564696e67207369676e656420726563656970743b2061637475616c204f4c44207061796c6f61642c206163636f756e74696e672c207369676e656420726573756c7420616e64206f7574626f7820636f6d6d69742061746f6d6963616c6c79222c22636f6d6d616e64223a2244454c4554455f4c4f43414c5f5041594c4f41445f4241544348222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f4352454154455f5241575f42415443482d5631222c2261676772656761746554797065223a2265766964656e63652d64656c6574696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d44454c4554452d5241572d50524f4f462d4241544348222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e6520626f756e646564206c6f63616c2070726f7465637465642070726f6f6620636970686572746578742064656c6574696f6e20696e206f70656e70635f636f6e74726f6c3b206f726967696e616c204964656e7469747920617373657274696f6e732c206175646974207365676d656e74732c20696d6d757461626c652070726f6f662f616363657373206d6574616461746120616e642065786163742d76657273696f6e207261772061726368697665732072657461696e20696e646570656e64656e74206c69666574696d6573222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a2265616368207261772d70726f6f662062617463682068617320696e646570656e64656e74206d616b65722d636865636b657220617070726f76616c20616e6420667265736820576562417574686e3b206f6e6520656e63727970746564206f626a656374207065722061746f6d69632062617463682c206f72646572656420627920696d6d757461626c65206f626a656374207072696d617279206b65793b2074686520707265636564696e6720636f6d6d6974746564206a6f6220616e64207369676e656420726563656970742062696e6420746865206578616374206e657874207461726765742f636f756e742f6265666f7265206469676573743b205061727469636970616e742f707269766163792f736f7572636520686f6c647320696e636c7564696e6720554e4b4e4f574e2c20696e646570656e64656e742072617720706f6c6963792f726574656e74696f6e2f67726163652c206578616374207261772073696e6b2071756f72756d2f636865636b706f696e7420616e64207061796c6f6164207265666572656e63657320617265207265636865636b65643b20636f6e63757272656e7420636f6e74696e756174696f6e20686173206f6e652064757261626c6520737563636573736f7220616e64207061727469616c2070726f6772657373207065727369737473206163726f737320726573746172743b206e6f2065787465726e616c20646573747275637469766520617474656d7074206f6363757273222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a2270726f746563746564207061796c6f61642c2065786163742073636f7065642070726f7465637465642d7661756c74206163636f756e74696e672c2064656c6574696f6e206a6f622f656666656374206974656d2c2065766964656e63652c207369676e696e6720617474656d70742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d64656c6574696f6e2e7261772d70726f6f66222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c2264656c6574696f6e5f6a6f625f6964225d2c226f776e6572223a22636f6e74726f6c2e64656c6574696f6e5f6a6f62222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22726574656e74696f6e5f706f6c6963795f6964222c2274797065223a22555549445f4259544553227d2c2231223a7b22636f6c756d6e223a227461726765745f73656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c223130223a7b22636f6c756d6e223a2272657461696e65645f616c6961735f636f756e74222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22737461727465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223132223a7b22636f6c756d6e223a22636f6d706c657465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223133223a7b22636f6c756d6e223a226265666f72655f757365645f6279746573222c2274797065223a22553634227d2c223134223a7b22636f6c756d6e223a2261667465725f757365645f6279746573222c2274797065223a22553634227d2c2232223a7b22636f6c756d6e223a22656c69676962696c6974795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a226265666f72655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2261667465725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22617474656d70745f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2237223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a2264656c657465645f636f756e74222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a2264656c657465645f6279746573222c2274797065223a22553634227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5355434345454445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a226f6e6520657861637420617070726f766564205241575f534f555243455f424f44592070726f7465637465642070726f6f66206369706865727465787420636f70792072656d6f766564206279207072696d617279206b65792066726f6d20616e20696d6d757461626c65206f7264657265642073656c656374696f6e206f66206174206d6f7374203136206f626a6563742076657273696f6e733b206c69766520696e646570656e64656e742072617720726574656e74696f6e2c2065786163742072617720637573746f64792c20736f757263652f5061727469636970616e742f7072697661637920686f6c64732c207265666572656e63657320616e64207072696f72207369676e656420637572736f7220617265207265636865636b65642061742074686520646573747275637469766520626f756e646172793b2061637475616c204f4c44207061796c6f61642c2073636f7065642070726f7465637465642d7661756c74206163636f756e74696e672c207369676e656420726573756c7420616e64206f7574626f7820636f6d6d69742061746f6d6963616c6c79222c22636f6d6d616e64223a2244454c4554455f5241575f50524f4f465f5041594c4f41445f4241544348222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f4352454154455f50524f4a454354494f4e5f42415443482d5631222c2261676772656761746554797065223a2265766964656e63652d64656c6574696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d44454c4554452d50524f4a454354494f4e2d4241544348222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e652050524f4a454354494f4e5f44454c45544520696e206f70656e70635f636f6e74726f6c3b20696d6d757461626c65206f726967696e616c2072656365697074732c207365676d656e7420636861696e20616e6420617263686976652062797465732072656d61696e3b207468652064656c6574696f6e206566666563742072657461696e73206f6e6c79206964656e746974792f64696765737420616e6420707265736572766174696f6e206d6574616461746120616e6420626c6f636b73206e6f726d616c207265636f6e737472756374696f6e222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a226561636820626174636820726571756972657320696e646570656e64656e74206d616b65722f636865636b657220617070726f76616c20616e6420667265736820576562417574686e3b206f6e6520706879736963616c2070726f6a656374696f6e2066726f6d2061206669786564206f72646572656420736f757263652d7072696d6172792d6b65792073656c656374696f6e206f66206174206d6f73742031363b2074686520707265636564696e67207369676e6564206a6f622062696e647320657861637420636c6173732c206e6578742074617267657420616e64206265666f7265206469676573743b206e6f2072656d6f746520646573747275637469766520617474656d7074206f63637572733b205345415243485f50524f4a454354494f4e206164646974696f6e616c6c79207265717569726573206c6f63616c2063697068657274657874207265746972656d656e7420616e6420636c656172616e6365206f662070726f7465637465642d70726f6f662c206578706f727420616e642070726f76656e616e6365207265666572656e6365733b206e6f726d616c697a6564205250432073636f70652070726f766573205052455f41444d495353494f4e5f44454e49414c3b20756e6b6e6f776e206f7220756e7265736f6c76656420736f7572636520656666656374732072656d61696e20626c6f636b65643b20746f6d6273746f6e652d617761726520637573746f64792063616e6e6f7420726573757272656374206120726574697265642070726f6a656374696f6e20616e64207072657365727665732066757475726520686f6c642073656d616e74696373222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a2270726f6a656374696f6e20726f772c20696d6d757461626c65207265746972656d656e742f6566666563742c2064656c6574696f6e206a6f622c2065766964656e63652c207369676e696e6720617474656d70742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d64656c6574696f6e2e70726f6a656374696f6e222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c2264656c6574696f6e5f6a6f625f6964225d2c226f776e6572223a22636f6e74726f6c2e64656c6574696f6e5f6a6f62222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22726574656e74696f6e5f706f6c6963795f6964222c2274797065223a22555549445f4259544553227d2c2231223a7b22636f6c756d6e223a227461726765745f73656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c223130223a7b22636f6c756d6e223a2272657461696e65645f616c6961735f636f756e74222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22737461727465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223132223a7b22636f6c756d6e223a22636f6d706c657465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223133223a7b22636f6c756d6e223a226265666f72655f757365645f6279746573222c2274797065223a22553634227d2c223134223a7b22636f6c756d6e223a2261667465725f757365645f6279746573222c2274797065223a22553634227d2c2232223a7b22636f6c756d6e223a22656c69676962696c6974795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a226265666f72655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2261667465725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22617474656d70745f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2237223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a2264656c657465645f636f756e74222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a2264656c657465645f6279746573222c2274797065223a22553634227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5355434345454445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a226f6e6520657861637420696e646570656e64656e746c7920617070726f766564204e4f524d414c495a45445f4a534f4e5f50524f4a454354494f4e20525043207072652d61646d697373696f6e2d64656e69616c20646f63756d656e74206f72205345415243485f50524f4a454354494f4e2061757468656e7469636174696f6e20636174616c6f67756520726f7720706879736963616c6c792072656d6f76656420627920696e646578656420736f75726365207072696d617279206b65793b206c69766520636c61737320726574656e74696f6e2c20617263686976652071756f72756d2c20686f6c64732c207265666572656e636520636c656172616e636520616e64207072696f72207369676e656420637572736f7220617265207265636865636b65643b2061637475616c204f4c442070726f6a656374696f6e20616e6420707265736572766174696f6e2f64656475706c69636174696f6e206d696e696d756d20636f6d6d6974207769746820746865207369676e656420726573756c7420616e64206f7574626f78222c22636f6d6d616e64223a2244454c4554455f50524f4a454354494f4e5f4241544348222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f41444d49545f53544f52455f42415443482d5631222c2261676772656761746554797065223a2273746f72652d7265746972656d656e74222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d41444d49542d53544f52452d5245544952454d454e54222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e652064757261626c6520436f6e74726f6c2061646d697373696f6e206265666f72652074617267657420492f4f3b20746172676574207369676e617475726520766572696669636174696f6e2c2063757272656e742074617267657420707265646963617465732c20706879736963616c206566666563742c2063616e63656c6c6174696f6e20616e64206f7574636f6d65207265636f6e63696c696174696f6e2072656d61696e207365706172617465206f626c69676174696f6e73222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a226f6e6c7920636f6d6d6974746564207072696d61727920726561646261636b206d6179206973737565207468652066696e69746520686f73742f73636f70652f73746f72652d626f756e6420726571756573743b206120686f6c64206f7220706f6c696379206368616e676520626c6f636b73206e657720646973706174636820616e642072657175697265732064757261626c652063616e63656c6c6174696f6e206f6620756e7265736f6c76656420617474656d7074733b20616273656e74206f7220616d626967756f75732074617267657420726561646261636b2072656d61696e7320554e4b4e4f574e3b206120737563636573736f722070726573657276657320657861637420627573696e65737320696e74656e7420616e642073656c656374696f6e20616e64207265717569726573206f726967696e616c2061757468656e74696361746564207465726d696e616c206e6f2d656666656374206f7574636f6d6520706c757320696e646570656e64656e7420617070726f76616c20616e6420667265736820737465702d75702044697370617463682063616e6e6f74206f75746c6976652074686520726563656970742d626f756e6420646561646c696e652c206174206d6f7374203630207365636f6e64732061667465722061646d697373696f6e3b206578706972792072657175697265732063616e63656c6c6174696f6e2f726561646261636b20616e6420667265736820696e646570656e64656e7420737563636573736f7220617070726f76616c2c206e657665722072656e6577656420657865637574696f6e20617574686f726974792e222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a2261646d697373696f6e2c2065766964656e63652c207369676e696e6720617474656d70742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b3b206e6f2074617267657420492f4f20697320616c6c6f7765642066726f6d20616e20756e636f6d6d6974746564207472616e73616374696f6e227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e73746f72652d7265746972656d656e742e61646d6974222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22617474656d70745f6964225d2c226f776e6572223a22636f6e74726f6c2e73746f72655f7265746972656d656e745f61646d697373696f6e222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22686f73745f646967657374222c22656e636f64696e67223a226c6f776572636173652d686578222c2274797065223a22483332227d2c2231223a7b22636f6c756d6e223a22617474656d70745f646967657374222c22656e636f64696e67223a226c6f776572636173652d686578222c2274797065223a22483332227d2c223130223a7b22636f6c756d6e223a2261646d69747465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223131223a7b22636f6c756d6e223a2264697370617463685f6e6f745f61667465725f6d73222c2274797065223a225536345f4d494c4c495345434f4e4453227d2c2232223a7b22636f6c756d6e223a2273656c656374696f6e5f646967657374222c22656e636f64696e67223a226c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a22736f757263655f62696e64696e675f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a22726574656e74696f6e5f706f6c6963795f6964222c2274797065223a22555549445f4259544553227d2c2235223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2237223a7b22636f6c756d6e223a227265746972656d656e745f6964222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a2270726576696f75735f617474656d70745f6964222c22656e636f64696e67223a22656d70747920627974657320666f7220696e697469616c2061646d697373696f6e3b206f726967696e616c207072656465636573736f72205555494420666f72206120696e646570656e64656e746c7920617070726f76656420737563636573736f72222c2274797065223a224f5054494f4e414c5f555549445f4259544553227d2c2239223a7b22636f6c756d6e223a226c6966656379636c655f7265766973696f6e222c2274797065223a22553634227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f41444d49545445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a226f6e6520696d6d757461626c6520626f756e6465642046616374206f722063616e6469646174652073656c656374696f6e2c20657861637420696e7374616c6c65642074617267657420686f73742c20736f7572636520616e6420617263686976652062696e64696e672c20696e646570656e64656e7420617070726f76616c2c20617474656d707420616e6420627573696e65737320696e74656e7420636f6d6d69742077697468207468652061646d697373696f6e207265636569707420616e64206f7574626f783b206e6f20706879736963616c20656666656374206f72207472616e73706f72742073756363657373206973206173736572746564222c22636f6d6d616e64223a2241444d49545f53544f52455f5245544952454d454e54222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f444953504f53455f52554e54494d455f534f555243452d5631222c2261676772656761746554797065223a2272756e74696d652d61727469666163742d646973706f736974696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d444953504f53452d52554e54494d452d41525449464143542d534f55524345222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e652064757261626c65207065726d616e656e7420736f75726365206e65772d7573652064656e69616c2061646d697373696f6e206265666f7265206e6174697665207265636f6e63696c696174696f6e3b206e6f206e61746976652064656e69616c20636f6d706c6574696f6e2c20706879736963616c2064656c6574696f6e206f72207265636f7665727920636c656172616e6365206973206173736572746564222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a226f6e6c7920736570617261746520636f6d6d6974746564207072696d61727920726561646261636b206f6620746869732065786163742061646d697373696f6e206d6179207265636f6e63696c6520746865206e6174697665207065726d616e656e742064656e69616c2061667465722061757468656e74696361746564206f726967696e616c206172636869766520616e6420736f7572636520686973746f727920636865636b733b206d697373696e672c206c65676163792c2075736564206f7220756e6b6e6f776e20637573746f64792073746179732064656e696564206f722070656e64696e673b20617070726f76616c20616e6420737465702d7570206578706972792061726520636865636b6564206265666f7265207468652061746f6d69632061646d697373696f6e2e2054686520636f6d6d6974746564207065726d616e656e74206e65772d7573652064656e69616c206973206e657665722072656e657765642c207265706c61636564206f72206572617365642e20506879736963616c2064656c6574696f6e20726571756972657320612073657061726174652063757272656e7420676f7665726e6564206f7065726174696f6e20616e64206672657368206566666563742d74696d6520656c69676962696c6974792e222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a22736f757263652064656e69616c2061646d697373696f6e2c2065766964656e63652c207369676e696e6720617474656d70742c2073746174652c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b3b206e61746976652064656e69616c20697320666f7262696464656e2066726f6d20616e20756e636f6d6d6974746564207472616e73616374696f6e227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e72756e74696d652d61727469666163742e646973706f736974696f6e222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22646973706f736974696f6e5f6964225d2c226f776e6572223a22636f6e74726f6c2e72756e74696d655f61727469666163745f736f757263655f646973706f736974696f6e222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22736f757263655f6f776e65725f6964222c2274797065223a22555549445f4259544553227d2c2231223a7b22636f6c756d6e223a2272756e74696d655f636f6e66696775726174696f6e5f696e7075745f6964222c2274797065223a22555549445f4259544553227d2c2232223a7b22636f6c756d6e223a22636f6e66696775726174696f6e5f646967657374222c22656e636f64696e67223a226c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a2273656c656374696f6e5f646967657374222c22656e636f64696e67223a226c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2235223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a2261646d69747465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f41444d49545445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a226f6e6520696d6d757461626c6520657861637420736f757263652f696e7075742f636f6e74656e742f726f6f742f617263686976652f7265666572656e63652073656c656374696f6e20636f6d6d6974732061207065726d616e656e74206e65772d7573652064656e69616c20756e6465722063757272656e7420696e646570656e64656e7420617070726f76616c20616e6420667265736820737465702d75703b206e61746976652064656e69616c2c20706879736963616c207265746972656d656e7420616e64206974732073657061726174652063757272656e7420676f7665726e616e63652072656d61696e20756e70726f76656e222c22636f6d6d616e64223a22444953504f53455f52554e54494d455f41525449464143545f534f55524345222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f4352454154455f52554e54494d455f42415443482d5631222c2261676772656761746554797065223a2265766964656e63652d64656c6574696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d44454c4554452d52554e54494d452d41525449464143542d4241544348222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e6520626f756e64656420524f575f44454c455445206f6620616e206f726967696e616c2072756e74696d6520636f6e66696775726174696f6e20696e70757420696e206f70656e70635f636f6e74726f6c3b20696d6d757461626c65207265746972656d656e74206d657461646174612070726576656e7473206e6f726d616c2072652d73656c656374696f6e206f72207265636f6e737472756374696f6e206f66207468652073616d652064696765737420696e20697473205061727469636970616e742f707269766163792073636f70652c20696e636c7564696e67207468726f75676820616e6f74686572206d6f64756c652067656e65726174696f6e3b206f726967696e616c20776f726b2c2061637469766174696f6e2c206f62736572766174696f6e2c20726f7574652c207265636569707420616e642061726368697665207265636f7264732072657461696e20746865697220696e646570656e64656e74206c69666574696d6573222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a226561636820626f756e64656420626174636820726571756972657320696e646570656e64656e74206d616b65722f636865636b657220617070726f76616c20616e6420667265736820576562417574686e3b206f6e65206f726967696e616c2072756e74696d6520696e707574206f66206174206d6f73742034313934333034206279746573207065722061746f6d69632062617463682c2073656c656374656420696e20696d6d757461626c65207072696d6172792d6b6579206f726465723b2074686520707265636564696e67207369676e6564206a6f622062696e647320746865206578616374206e65787420696e70757420616e64206265666f7265206469676573743b20736f7572636520696e746567726974792c20657861637420636c61737320706f6c6963792f726574656e74696f6e2f67726163652c2061727469666163742073696e6b2071756f72756d2f636865636b706f696e742c206d61746368696e67205061727469636970616e742f707269766163792f67656e65726174696f6e2f64696765737420686f6c647320616e6420617574686f7269746174697665207265666572656e636520646973706f736974696f6e20617265207265636865636b65642061742074686520646573747275637469766520626f756e646172793b20646573656c656374696f6e2c206d6f64756c652064697361626c656d656e742c20636f6d706c6574656420776f726b2c2074617267657420646973636f6e6e656374696f6e20616e6420616273656e63652066726f6d20612063757272656e742076696577206e6576657220696d706c79207265666572656e636520636c656172616e63653b206d697373696e67206f72207472756e636174656420637573746f64792f7265666572656e6365206f62736572766174696f6e732072656d61696e20626c6f636b65643b2072657461696e6564207369676e65642073656d616e7469637320616e6420636f6e73756d656420627573696e657373206566666563747320617265206e657665722072657772697474656e206f72207265706c617965643b206e6f2065787465726e616c20646573747275637469766520617474656d7074206f6363757273222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a22696e7075742064656c6574696f6e2c20696d6d757461626c65207265746972656d656e74206d657461646174612c2064656c6574696f6e206a6f622f656666656374206163636f756e74696e672c2065766964656e63652c207369676e696e6720617474656d70742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d64656c6574696f6e2e72756e74696d652d6172746966616374222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c2264656c6574696f6e5f6a6f625f6964225d2c226f776e6572223a22636f6e74726f6c2e64656c6574696f6e5f6a6f62222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22726574656e74696f6e5f706f6c6963795f6964222c2274797065223a22555549445f4259544553227d2c2231223a7b22636f6c756d6e223a227461726765745f73656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c223130223a7b22636f6c756d6e223a2272657461696e65645f616c6961735f636f756e74222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22737461727465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223132223a7b22636f6c756d6e223a22636f6d706c657465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223133223a7b22636f6c756d6e223a226265666f72655f757365645f6279746573222c2274797065223a22553634227d2c223134223a7b22636f6c756d6e223a2261667465725f757365645f6279746573222c2274797065223a22553634227d2c2232223a7b22636f6c756d6e223a22656c69676962696c6974795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a226265666f72655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2261667465725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22617474656d70745f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2237223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a2264656c657465645f636f756e74222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a2264656c657465645f6279746573222c2274797065223a22553634227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5355434345454445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a226f6e6520657861637420617070726f7665642052554e54494d455f41525449464143542072756e74696d6520636f6e66696775726174696f6e20696e7075742072656d6f76656420627920696e6465786564207072696d617279206b65793b2061637475616c204f4c4420696e707574206964656e746974792c2073636f70652c206d6f64756c652067656e65726174696f6e2c206372656174696f6e2074696d652c2064696765737420616e64206279746520636f756e74206172652070726573657276656420696e20696d6d757461626c65207265746972656d656e74206d657461646174613b20696e646570656e64656e7420636c61737320726574656e74696f6e20616e642067726163652c20657861637420617274696661637420637573746f647920616e6420636865636b706f696e742071756f72756d2c20616c6c206d61746368696e6720686f6c64732c20636f6d706c657465207265666572656e636520646973706f736974696f6e20616e6420746865207072696f72207369676e656420637572736f7220617265207265636865636b656420756e646572207368617265642070726f64756365722066656e6365733b2073656c65637465642c206c6976652c207265636f766572792d646570656e64656e742c20756e6b6e6f776e206f7220756e7265736f6c76656420696e707574732063616e6e6f742062652072656d6f7665643b2074686520706879736963616c206566666563742c207265746972656d656e74206d657461646174612c207369676e656420726573756c7420616e64206f7574626f7820636f6d6d69742061746f6d6963616c6c79222c22636f6d6d616e64223a2244454c4554455f52554e54494d455f434f4e46494755524154494f4e5f494e5055545f4241544348222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d524554454e54494f4e5f504f4c49434945535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a22726574656e74696f6e2d706f6c696379222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d41435449564154452d524554454e54494f4e2d504f4c494359222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e726574656e74696f6e2d706f6c6963792e6163746976617465222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22726574656e74696f6e2d706f6c6963696573222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22726574656e74696f6e5f706f6c6963795f6964225d2c226f776e6572223a22636f6e74726f6c2e726574656e74696f6e5f706f6c696379222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22706f6c6963795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2231223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a227072656465636573736f725f706f6c6963795f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2232223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2233223a7b22636f6c756d6e223a2261637469766174696f6e5f6f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2234223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a227265746972656d656e745f617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2235223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a227265746972656d656e745f6f7065726174696f6e5f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2236223a7b22636f6c756d6e223a226163746976655f66726f6d222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c2237223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a226163746976655f756e74696c222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c69656420627920313030303b207465726d696e616c20696e74657276616c20656e64222c2274797065223a225536345f4e414e4f5345434f4e44535f4f525f454d5054595f42535452227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f4143544956455f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a22696d6d757461626c652063616e6f6e6963616c20706f6c69637920646566696e6974696f6e2c206578616374207072656465636573736f722c20636f6e73756d656420617070726f76616c20616e642061637475616c2061637469766174696f6e2074696d65222c22636f6d6d616e64223a224143544956415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f4352454154455f50524f4a454354494f4e5f42415443482d5631222c2261676772656761746554797065223a2265766964656e63652d64656c6574696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d44454c4554452d50524f4a454354494f4e2d4241544348222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e652050524f4a454354494f4e5f44454c45544520696e206f70656e70635f636f6e74726f6c3b20696d6d757461626c65206f726967696e616c2072656365697074732c207365676d656e7420636861696e20616e6420617263686976652062797465732072656d61696e3b207468652064656c6574696f6e206566666563742072657461696e73206f6e6c79206964656e746974792f64696765737420616e6420707265736572766174696f6e206d6574616461746120616e6420626c6f636b73206e6f726d616c207265636f6e737472756374696f6e222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a226561636820626174636820726571756972657320696e646570656e64656e74206d616b65722f636865636b657220617070726f76616c20616e6420667265736820576562417574686e3b206f6e6520706879736963616c2070726f6a656374696f6e2066726f6d2061206669786564206f72646572656420736f757263652d7072696d6172792d6b65792073656c656374696f6e206f66206174206d6f73742031363b2074686520707265636564696e67207369676e6564206a6f622062696e647320657861637420636c6173732c206e6578742074617267657420616e64206265666f7265206469676573743b206e6f2072656d6f746520646573747275637469766520617474656d7074206f63637572733b205345415243485f50524f4a454354494f4e206164646974696f6e616c6c79207265717569726573206c6f63616c2063697068657274657874207265746972656d656e7420616e6420636c656172616e6365206f662070726f7465637465642d70726f6f662c206578706f727420616e642070726f76656e616e6365207265666572656e6365733b206e6f726d616c697a6564205250432073636f70652070726f766573205052455f41444d495353494f4e5f44454e49414c3b20756e6b6e6f776e206f7220756e7265736f6c76656420736f7572636520656666656374732072656d61696e20626c6f636b65643b20746f6d6273746f6e652d617761726520637573746f64792063616e6e6f7420726573757272656374206120726574697265642070726f6a656374696f6e20616e64207072657365727665732066757475726520686f6c642073656d616e74696373222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a2270726f6a656374696f6e20726f772c20696d6d757461626c65207265746972656d656e742f6566666563742c2064656c6574696f6e206a6f622c2065766964656e63652c207369676e696e6720617474656d70742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d64656c6574696f6e2e70726f6a656374696f6e222c2270726f66696c6556657273696f6e223a322c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c2264656c6574696f6e5f6a6f625f6964225d2c226f776e6572223a22636f6e74726f6c2e64656c6574696f6e5f6a6f62222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22726574656e74696f6e5f706f6c6963795f6964222c2274797065223a22555549445f4259544553227d2c2231223a7b22636f6c756d6e223a227461726765745f73656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c223130223a7b22636f6c756d6e223a2272657461696e65645f616c6961735f636f756e74222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22737461727465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223132223a7b22636f6c756d6e223a22636f6d706c657465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223133223a7b22636f6c756d6e223a226265666f72655f757365645f6279746573222c2274797065223a22553634227d2c223134223a7b22636f6c756d6e223a2261667465725f757365645f6279746573222c2274797065223a22553634227d2c2232223a7b22636f6c756d6e223a22656c69676962696c6974795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a226265666f72655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2261667465725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22617474656d70745f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2237223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a2264656c657465645f636f756e74222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a2264656c657465645f6279746573222c2274797065223a22553634227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5355434345454445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a224f6e6520657861637420696e646570656e64656e746c7920617070726f766564205345415243485f50524f4a454354494f4e20726574656e74696f6e2d706f6c69637920627573696e657373207265636569707420636174616c6f67756520726f7720706879736963616c6c792072656d6f76656420627920696e646578656420736f75726365207072696d617279206b65792e20546865206f726967696e616c2070632e636f6e74726f6c2e726574656e74696f6e2d706f6c6963792e6163746976617465206f722070632e636f6e74726f6c2e726574656e74696f6e2d706f6c6963792e7265746972652076657273696f6e203120726563656970742c2072657461696e6564207369676e696e672074727573742c20636f6d6d69747465642061756469742f6964656d706f74656e63792f6f7574626f782062696e64696e6720616e6420706f6c696379206f7065726174696f6e206964656e746974792061726520696e646570656e64656e746c792076657269666965642e204c6976652073656172636820726574656e74696f6e2c20617263686976652071756f72756d2c20686f6c64732c207265666572656e636520636c656172616e636520616e64207072696f72207369676e656420637572736f7220617265207265636865636b65642e204f726967696e616c207369676e65642072656365697074732c20706f6c69637920616e6420617070726f76616c20737461746520616e642061726368697665732072657461696e20696e646570656e64656e74206c69666574696d65732e204f7468657220627573696e65737320726563656970742066616d696c69657320617265206e6f742061646d697474656420627920746869732076657273696f6e2e222c22636f6d6d616e64223a2244454c4554455f50524f4a454354494f4e5f4241544348222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d45564944454e43455f44454c4554494f4e535f4352454154455f50524f4a454354494f4e5f42415443482d5631222c2261676772656761746554797065223a2265766964656e63652d64656c6574696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d44454c4554452d50524f4a454354494f4e2d4241544348222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226f6e652050524f4a454354494f4e5f44454c45544520696e206f70656e70635f636f6e74726f6c3b20696d6d757461626c65206f726967696e616c2072656365697074732c207365676d656e7420636861696e20616e6420617263686976652062797465732072656d61696e3b207468652064656c6574696f6e206566666563742072657461696e73206f6e6c79206964656e746974792f64696765737420616e6420707265736572766174696f6e206d6574616461746120616e6420626c6f636b73206e6f726d616c207265636f6e737472756374696f6e222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a225250435f524554495245445f434154414c4f47554520736561726368207265746972656d656e74206f6e6c793a20657861637420636c6f7365642052504320736f7572636520616c726561647920706879736963616c6c7920726574697265642066726f6d204e4f524d414c495a45445f4a534f4e5f50524f4a454354494f4e207468726f75676820616e20696e646570656e64656e746c79207665726966696564206f726967696e616c2070726f66696c652d763120434f534520726563656970742c20636f6e73756d65642063616e6469646174652c207369676e656420737461746520616e64206f7574626f782e204576657279207365617263682062617463682068617320697473206f776e20636c61737320706f6c6963792c2073696e6b2071756f72756d2f67726163652c206d616b65722f636865636b657220617070726f76616c2c20667265736820576562417574686e2c206669786564206f7264657265642073656c6563746f7220616e64207369676e656420636f6e74696e756174696f6e2e204c697665206e6f726d616c697a6564207369626c696e67732073686172696e6720746865206f726967696e616c20525043206964656e746974792c206c6f63616c20636970686572746578742c2070726f74656374656420646973636c6f737572652c206578706f72747320616e64206f746865722072656769737465726564207265666572656e63657320626c6f636b2064656c6574696f6e2e20546865206f726967696e616c207265746972656d656e74207769746e6573732c20736f757263652f6172636869766520627974657320616e6420707265736572766174696f6e206d657461646174612072656d61696e20696d6d757461626c653b206e6f2063757272656e742052504320617574686f726974792c207265706c61792c20736f75726365207265636f6e737472756374696f6e206f722072656d6f74652064657374727563746976652065666665637420697320636f6e6665727265642e20556e6b6e6f776e2c20616d626967756f7573206f7220756e726574697265642052504320686973746f726965732072656d61696e20626c6f636b65642e222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a2270726f6a656374696f6e20726f772c20696d6d757461626c65207265746972656d656e742f6566666563742c2064656c6574696f6e206a6f622c2065766964656e63652c207369676e696e6720617474656d70742c20686561642c206576656e7420616e64206f7065726174696f6e20726573756c7420616c6c20726f6c6c206261636b227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e65766964656e63652d64656c6574696f6e2e70726f6a656374696f6e222c2270726f66696c6556657273696f6e223a332c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a2265766964656e63652d64656c6574696f6e73222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c2264656c6574696f6e5f6a6f625f6964225d2c226f776e6572223a22636f6e74726f6c2e64656c6574696f6e5f6a6f62222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22726574656e74696f6e5f706f6c6963795f6964222c2274797065223a22555549445f4259544553227d2c2231223a7b22636f6c756d6e223a227461726765745f73656c6563746f725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c223130223a7b22636f6c756d6e223a2272657461696e65645f616c6961735f636f756e74222c2274797065223a22553634227d2c223131223a7b22636f6c756d6e223a22737461727465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223132223a7b22636f6c756d6e223a22636f6d706c657465645f6174222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c223133223a7b22636f6c756d6e223a226265666f72655f757365645f6279746573222c2274797065223a22553634227d2c223134223a7b22636f6c756d6e223a2261667465725f757365645f6279746573222c2274797065223a22553634227d2c2232223a7b22636f6c756d6e223a22656c69676962696c6974795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a226265666f72655f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a2261667465725f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a22617474656d70745f6964222c2274797065223a22555549445f4259544553227d2c2236223a7b22636f6c756d6e223a226f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2237223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2238223a7b22636f6c756d6e223a2264656c657465645f636f756e74222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a2264656c657465645f6279746573222c2274797065223a22553634227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5355434345454445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a224f6e6520657861637420696e646570656e64656e746c7920617070726f766564205345415243485f50524f4a454354494f4e20726574656e74696f6e2d706f6c69637920627573696e657373207265636569707420636174616c6f67756520726f7720706879736963616c6c792072656d6f76656420627920696e646578656420736f75726365207072696d617279206b65792e20546865206f726967696e616c2070632e636f6e74726f6c2e726574656e74696f6e2d706f6c6963792e6163746976617465206f722070632e636f6e74726f6c2e726574656e74696f6e2d706f6c6963792e7265746972652076657273696f6e203120726563656970742c2072657461696e6564207369676e696e672074727573742c20636f6d6d69747465642061756469742f6964656d706f74656e63792f6f7574626f782062696e64696e6720616e6420706f6c696379206f7065726174696f6e206964656e746974792061726520696e646570656e64656e746c792076657269666965642e204c6976652073656172636820726574656e74696f6e2c20617263686976652071756f72756d2c20686f6c64732c207265666572656e636520636c656172616e636520616e64207072696f72207369676e656420637572736f7220617265207265636865636b65642e204f726967696e616c207369676e65642072656365697074732c20706f6c69637920616e6420617070726f76616c20737461746520616e642061726368697665732072657461696e20696e646570656e64656e74206c69666574696d65732e204f7468657220627573696e65737320726563656970742066616d696c69657320617265206e6f742061646d697474656420627920746869732076657273696f6e2e222c22636f6d6d616e64223a2244454c4554455f50524f4a454354494f4e5f4241544348222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d524554454e54494f4e5f504f4c49434945535f5245544952455f5245534f555243452d5631222c2261676772656761746554797065223a22726574656e74696f6e2d706f6c696379222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2245584143545f434f4e53554d45445f43414e4449444154455f574954485f494e444550454e44454e545f4d414b45525f434845434b45523b206465666572726564206f776e696e672d726f7720747269676765722062696e647320617070726f76616c20616e64206265666f72652f6166746572207374617465222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a2246524553485f574542415554484e5f424f554e445f544f5f5448455f53414d455f415050524f56414c5f414e445f4f5045524154494f4e227d2c22636174616c6f674f7065726174696f6e4964223a224346472d4f502d5245544952452d524554454e54494f4e2d504f4c494359222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e726574656e74696f6e2d706f6c6963792e726574697265222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a22726574656e74696f6e2d706f6c6963696573222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22726574656e74696f6e5f706f6c6963795f6964225d2c226f776e6572223a22636f6e74726f6c2e726574656e74696f6e5f706f6c696379222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a22706f6c6963795f646967657374222c22656e636f64696e67223a227368613235362d70726566697865642d6c6f776572636173652d686578222c2274797065223a22483332227d2c2231223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a227072656465636573736f725f706f6c6963795f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2232223a7b22636f6c756d6e223a22617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f4259544553227d2c2233223a7b22636f6c756d6e223a2261637469766174696f6e5f6f7065726174696f6e5f6964222c2274797065223a22555549445f4259544553227d2c2234223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a227265746972656d656e745f617070726f76616c5f726571756573745f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2235223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a227265746972656d656e745f6f7065726174696f6e5f6964222c2274797065223a22555549445f42595445535f4f525f454d5054595f42535452227d2c2236223a7b22636f6c756d6e223a226163746976655f66726f6d222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c6965642062792031303030222c2274797065223a225536345f4e414e4f5345434f4e4453227d2c2237223a7b22616273656e6365223a227a65726f2d6c656e677468206279746520737472696e67222c22636f6c756d6e223a226163746976655f756e74696c222c22656e636f64696e67223a2265786163742073746f72656420555443206d6963726f7365636f6e6473206d756c7469706c69656420627920313030303b207465726d696e616c20696e74657276616c20656e64222c2274797065223a225536345f4e414e4f5345434f4e44535f4f525f454d5054595f42535452227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f524554495245445f5245564953494f4e5f32222c226265666f7265223a2250524553454e545f4143544956455f5245564953494f4e5f31222c226368616e6765223a22736570617261746520636f6e73756d656420617070726f76616c20616e64206f7065726174696f6e20636c6f7365207468652061637475616c2061637469766520696e74657276616c207768696c652070726573657276696e6720616c6c2076657273696f6e20636f6e74656e7473222c22636f6d6d616e64223a22524554495245222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d4d4f44554c45535f4352454154455f5245534f555243452d5631222c2261676772656761746554797065223a226d6f64756c652d726567697374726174696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2264697374696e637420617574686f72697a656420636865636b657220617070726f766573207468652065786163742063616e6469646174653b206c697665206465636973696f6e20616e6420617574686f726974792066656e63656420616e6420636f6e73756d656420696e2074686520636f6d6d6974222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a226672657368206163746f7220576562417574686e20737465702d757020626f756e6420746f2074686520657861637420616374696f6e20616e642063616e6469646174653b20636f6e73756d6564206f6e636520696e2074686520636f6d6d6974227d2c22636174616c6f674f7065726174696f6e4964223a224d4f442d4f502d5245474953544552222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e6d6f64756c652e7265676973746572222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a226d6f64756c6573222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206576657279206d6170206669656c64207265717569726564222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c226d6f64756c655f696e7374616c6c6174696f6e5f6964225d2c226f776e6572223a22636f6e74726f6c2e6d6f64756c655f696e7374616c6c6174696f6e202b20696d6d757461626c6520636f6e74726f6c2e6d6f64756c655f76657273696f6e202b20636f6e74726f6c2e6d6f64756c655f636f6e66696775726174696f6e5f67656e65726174696f6e222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226d6f64756c655f6964222c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a2273656d616e7469635f76657273696f6e222c2274797065223a2254455854227d2c2232223a7b22636f6c756d6e223a226d616e69666573745f646967657374222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a2261646d697373696f6e5f646570656e64656e63795f646967657374222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a22636f6e66696775726174696f6e5f646967657374222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b2241444d4954544544225d2c2274797065223a2254455854227d2c2236223a7b22636f6c756d6e223a226163746976655f6d616e69666573745f646967657374222c22656e636f64696e67223a2230206d65616e7320616273656e743b2061646d697373696f6e207265717569726573204e554c4c20696e207468652064757261626c6520636f6c756d6e222c2274797065223a22553634227d2c2237223a7b22636f6c756d6e223a22636f6e66696775726174696f6e2e67656e65726174696f6e222c2274797065223a22553634227d2c2238223a7b22636f6c756d6e223a22636f6e66696775726174696f6e2e616374697665222c22656e636f64696e67223a2230206d65616e7320696e6163746976653b2061646d697373696f6e2072657175697265732066616c736520696e207468652064757261626c6520636f6c756d6e222c2274797065223a22553634227d7d2c227265766973696f6e223a226167677265676174655f76657273696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f41444d49545445445f5245564953494f4e5f31222c226265666f7265223a22414253454e54222c226368616e6765223a2276657269666965642072657461696e6564207369676e65642072656c656173652c2065786163742073636f70656420646570656e64656e637920636c6f737572652c20696e61637469766520636f6e66696775726174696f6e2067656e65726174696f6e20313b206e6f20616374697665206d616e6966657374206f722072756e74696d6520617574686f72697479222c22636f6d6d616e64223a22435245415445222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d4d4f44554c455f4352454154455f494e5354414c4c2d5631222c2261676772656761746554797065223a226d6f64756c652d726567697374726174696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2264697374696e637420617574686f72697a656420636865636b657220617070726f766573207468652065786163742063616e6469646174653b206c697665206465636973696f6e20616e6420617574686f726974792066656e63656420616e6420636f6e73756d656420696e2074686520636f6d6d6974222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a226672657368206163746f7220576562417574686e20737465702d757020626f756e6420746f2074686520657861637420616374696f6e20616e642063616e6469646174653b20636f6e73756d6564206f6e636520696e2074686520636f6d6d6974227d2c22636174616c6f674f7065726174696f6e4964223a224d4f442d4f502d494e5354414c4c222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b22636f6e73756d6572223a225265717569726520657861637420656e61626c6564206d616e69666573742f636f6e66696775726174696f6e2f67656e65726174696f6e2c2063757272656e742072656c65617365207369676e696e672074727573742c2063757272656e742073636f70652065706f63687320616e6420636f6d6d697474656420656e61626c6520726563656970742e2041207265636569707420616c6f6e65206772616e7473206e6f207472616e73616374696f6e20617574686f726974792e222c2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e6d6f64756c652e696e7374616c6c222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a226d6f64756c65222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206f7074696f6e616c206669656c64732068617665206578706c696369742070726573656e63652072756c6573222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c226d6f64756c655f696e7374616c6c6174696f6e5f6964225d2c226f776e6572223a22636f6e74726f6c2e6d6f64756c655f696e7374616c6c6174696f6e202b20696d6d757461626c6520636f6e74726f6c2e6d6f64756c655f76657273696f6e202b20636f6e74726f6c2e6d6f64756c655f636f6e66696775726174696f6e5f67656e65726174696f6e222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226d6f64756c655f6964222c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a2273656d616e7469635f76657273696f6e222c2274797065223a2254455854227d2c223130223a7b22636f6c756d6e223a226163746976655f6d616e69666573745f646967657374222c2270726573656e6365223a22726571756972656420696666206669656c6420362069732031222c2274797065223a22483332227d2c2232223a7b22636f6c756d6e223a226d616e69666573745f646967657374222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a2261646d697373696f6e5f646570656e64656e63795f646967657374222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a22636f6e66696775726174696f6e5f646967657374222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b2241444d4954544544222c22494e5354414c4c45445f44495341424c4544222c22454e41424c4544225d2c2274797065223a2254455854227d2c2236223a7b22636f6c756d6e223a226163746976655f6d616e69666573745f646967657374222c22656e636f64696e67223a2250726573656e63653a203020616273656e742c20312070726573656e743b206669656c642031302072657175697265642065786163746c79207768656e2070726573656e74222c2274797065223a22553634227d2c2237223a7b22636f6c756d6e223a22636f6e66696775726174696f6e2e67656e65726174696f6e222c2274797065223a22553634227d2c2238223a7b22636f6c756d6e223a22636f6e66696775726174696f6e2e616374697665222c22656e636f64696e67223a223020696e6163746976652c2031206163746976653b206163746976652065786163746c7920696e20454e41424c4544222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a226c6966656379636c655f6576616c756174696f6e5f646967657374222c2270726573656e6365223a22726571756972656420616674657220696e7374616c6c20616e6420656e61626c653b20616273656e74206f6e6c79206265666f726520696e697469616c20696e7374616c6c222c2274797065223a22483332227d7d2c227265766973696f6e223a226167677265676174655f76657273696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a22494e5354414c4c45445f44495341424c45445f5245564953494f4e5f504c55535f4f4e45222c226265666f7265223a2241444d4954544544222c226368616e6765223a2245786163742076657269666965642072656c656173652c20696e7374616c6c656420646570656e64656e637920636c6f737572652c2070726f64756374696f6e20736964652d6566666563742d667265652073696d756c6174696f6e20616e6420696e697469616c2067656e65726174696f6e20312e2041444d49545445442072657365727665732072656c656173652f636f6e66696775726174696f6e206964656e746974792062757420686173206e6f20696e7374616c6c656420636f6e747269627574696f6e3b20696e7374616c6c206d6174657269616c697a657320697420696e6572746c792e20456e61626c65206d616b6573206f6e6c792074686520657861637420636f6e747269627574696f6e20617661696c61626c653b206974206772616e7473206e6f206163746f72207065726d697373696f6e2e222c22636f6d6d616e64223a22494e5354414c4c222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d4d4f44554c455f41435449564154455f5245534f555243452d5631222c2261676772656761746554797065223a226d6f64756c652d726567697374726174696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2264697374696e637420617574686f72697a656420636865636b657220617070726f766573207468652065786163742063616e6469646174653b206c697665206465636973696f6e20616e6420617574686f726974792066656e63656420616e6420636f6e73756d656420696e2074686520636f6d6d6974222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a226672657368206163746f7220576562417574686e20737465702d757020626f756e6420746f2074686520657861637420616374696f6e20616e642063616e6469646174653b20636f6e73756d6564206f6e636520696e2074686520636f6d6d6974227d2c22636174616c6f674f7065726174696f6e4964223a224d4f442d4f502d454e41424c45222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b22636f6e73756d6572223a225265717569726520657861637420656e61626c6564206d616e69666573742f636f6e66696775726174696f6e2f67656e65726174696f6e2c2063757272656e742072656c65617365207369676e696e672074727573742c2063757272656e742073636f70652065706f63687320616e6420636f6d6d697474656420656e61626c6520726563656970742e2041207265636569707420616c6f6e65206772616e7473206e6f207472616e73616374696f6e20617574686f726974792e222c2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e6d6f64756c652e656e61626c65222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a226d6f64756c65222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206f7074696f6e616c206669656c64732068617665206578706c696369742070726573656e63652072756c6573222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c226d6f64756c655f696e7374616c6c6174696f6e5f6964225d2c226f776e6572223a22636f6e74726f6c2e6d6f64756c655f696e7374616c6c6174696f6e202b20696d6d757461626c6520636f6e74726f6c2e6d6f64756c655f76657273696f6e202b20636f6e74726f6c2e6d6f64756c655f636f6e66696775726174696f6e5f67656e65726174696f6e222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226d6f64756c655f6964222c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a2273656d616e7469635f76657273696f6e222c2274797065223a2254455854227d2c223130223a7b22636f6c756d6e223a226163746976655f6d616e69666573745f646967657374222c2270726573656e6365223a22726571756972656420696666206669656c6420362069732031222c2274797065223a22483332227d2c2232223a7b22636f6c756d6e223a226d616e69666573745f646967657374222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a2261646d697373696f6e5f646570656e64656e63795f646967657374222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a22636f6e66696775726174696f6e5f646967657374222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b2241444d4954544544222c22494e5354414c4c45445f44495341424c4544222c22454e41424c4544225d2c2274797065223a2254455854227d2c2236223a7b22636f6c756d6e223a226163746976655f6d616e69666573745f646967657374222c22656e636f64696e67223a2250726573656e63653a203020616273656e742c20312070726573656e743b206669656c642031302072657175697265642065786163746c79207768656e2070726573656e74222c2274797065223a22553634227d2c2237223a7b22636f6c756d6e223a22636f6e66696775726174696f6e2e67656e65726174696f6e222c2274797065223a22553634227d2c2238223a7b22636f6c756d6e223a22636f6e66696775726174696f6e2e616374697665222c22656e636f64696e67223a223020696e6163746976652c2031206163746976653b206163746976652065786163746c7920696e20454e41424c4544222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a226c6966656379636c655f6576616c756174696f6e5f646967657374222c2270726573656e6365223a22726571756972656420616674657220696e7374616c6c20616e6420656e61626c653b20616273656e74206f6e6c79206265666f726520696e697469616c20696e7374616c6c222c2274797065223a22483332227d7d2c227265766973696f6e223a226167677265676174655f76657273696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a22454e41424c45445f5245564953494f4e5f504c55535f4f4e45222c226265666f7265223a22494e5354414c4c45445f44495341424c4544222c226368616e6765223a2245786163742076657269666965642072656c656173652c20696e7374616c6c656420646570656e64656e637920636c6f737572652c2070726f64756374696f6e20736964652d6566666563742d667265652073696d756c6174696f6e20616e6420696e697469616c2067656e65726174696f6e20312e2041444d49545445442072657365727665732072656c656173652f636f6e66696775726174696f6e206964656e746974792062757420686173206e6f20696e7374616c6c656420636f6e747269627574696f6e3b20696e7374616c6c206d6174657269616c697a657320697420696e6572746c792e20456e61626c65206d616b6573206f6e6c792074686520657861637420636f6e747269627574696f6e20617661696c61626c653b206974206772616e7473206e6f206163746f72207065726d697373696f6e2e222c22636f6d6d616e64223a22454e41424c45222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d4d4f44554c45535f5550444154455f5245534f555243452d5631222c2261676772656761746554797065223a226d6f64756c652d726567697374726174696f6e222c22617574686f72697479223a7b22616374696f6e223a22657861637420616374696f6e2072656769737472792c206c6976652073636f70656420617574686f726974792066656e6365222c226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e222c22617070726f76616c223a2264697374696e637420617574686f72697a656420636865636b657220617070726f766573207468652065786163742063616e6469646174653b206c697665206465636973696f6e20616e6420617574686f726974792066656e63656420616e6420636f6e73756d656420696e2074686520636f6d6d6974222c2265766964656e6365223a5b7b2262696e64696e67223a22657861637420696d6d757461626c652063616e6469646174652c20616374696f6e2c2073636f70652c206578706563746564207265766973696f6e20616e642064697374696e637420636865636b65723b20636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e746974792063726564656e7469616c207369676e65642062792074686520617574686f72697a656420636865636b6572222c226b696e64223a332c226f776e6572223a22636f6e74726f6c2e617070726f76616c5f6465636973696f6e5f7265636f7264227d2c7b2262696e64696e67223a2261637475616c206f70657261746f722c2073657373696f6e2c20616374696f6e2c2063616e6469646174652064696765737420616e64206f6e652d74696d65206368616c6c656e676520636f6e73756d65642062792074686973206f7065726174696f6e222c22666f726d6174223a226964656e74697479206f776e657220766572696669656420576562417574686e20737465702d7570222c226b696e64223a342c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e636520666f722049442d4f502d574542415554484e2d564552494659227d5d2c22736e617073686f74223a2272657461696e656420657861637420707265636f6d6d697420617574686f72697479207061746820616e64206c6976652065706f6368732f76616c69646974793b206e6f2073657373696f6e206f722063726564656e7469616c2073656372657473222c22737465705570223a226672657368206163746f7220576562417574686e20737465702d757020626f756e6420746f2074686520657861637420616374696f6e20616e642063616e6469646174653b20636f6e73756d6564206f6e636520696e2074686520636f6d6d6974227d2c22636174616c6f674f7065726174696f6e4964223a224d4f442d4f502d44495341424c45222c226576656e7473223a5b7b2263617264696e616c697479223a312c2264617461536368656d61557269223a2268747470733a2f2f736368656d61732e6f70656e70632e6c6f63616c2f6576656e742d7061796c6f6164732e736368656d612e6a736f6e232f24646566732f436f6d6d616e64436f6d6d6974746564222c22656666656374223a226c6f63616c2064757261626c6520636f6e74726f6c2d7374617465207472616e736974696f6e206f6e6c79222c226576656e7454797065223a22696f2e6f70656e70632e636f6e74726f6c2e636f6d6d616e642e636f6d6d69747465642e7631222c227061796c6f6164223a2263616e6f6e6963616c20666f75722d6b657920436f6d6d616e64436f6d6d69747465642043424f523b20636f6d6d616e6449643d6f7065726174696f6e49642c206167677265676174655265663d63616e6f6e6963616c206167677265676174652055524e2c20616374696f6e496e74656e7449642c20696e74656e744469676573743d616374696f6e496e74656e74446967657374227d5d2c226c6966656379636c65223a7b22636f6e73756d6572223a2244697361626c656420636f6e747269627574696f6e20697320756e617661696c61626c6520746f206e657720636f6e73756d6572732e204578697374696e672067656e65726174696f6e2c2072656c65617365206964656e746974792c207072696f7220726563656970747320616e642065766964656e63652072656d61696e2072657461696e65643b20636f6e73756d657273206d75737420726576616c6964617465207468652063757272656e7420656e61626c656420737461746520756e64657220746865697220617574686f72697461746976652066656e63652e20412064697361626c652072656365697074206973206e6f7420617574686f7269747920746f2072657573652061207374616c6520656e61626c656420636f6e747269627574696f6e2e222c2264656c6976657279223a227175616c6966696564206e616d65737061636520616e642070726f66696c652072657175697265643b206e6f206c656761637920637572736f72206d65726765222c226964656d706f74656e6379223a226578616374207265706c61792072657475726e73206f726967696e616c206f7065726174696f6e2c20726563656970742c2065766964656e636520616e64206576656e74204944732f62797465732f73657175656e636573222c2272657374617274223a2273636f706564207072696d617279206f7065726174696f6e207265636f6e63696c696174696f6e3b20707265736572766520554e4b4e4f574e20666f7220756e7265736f6c76656420434f4d4d4954222c22726f6c6c6261636b223a226e6f20646f6d61696e2c2065766964656e63652c20686561642c206576656e74206f7220726573756c742065666665637473227d2c2270726976616379223a7b22706c6163656d656e74223a2273616d65207061727469636970616e7420616e64207072697661637920646f6d61696e20617320617574686f726974617469766520616767726567617465222c2272656164223a2263757272656e74207265616420617574686f72697a6174696f6e2072657175697265643b2072656365697074206973206e6576657220617574686f72697a6174696f6e222c22726574656e74696f6e223a2272657461696e20726563656970742c2074797065642073746174652f617574686f7269747920696e707574732c20617574686f72697a6174696f6e2065766964656e63652c207075626c696320747275737420616e64206f7065726174696f6e206c696e6b7320756e64657220636f6e74726f6c20617564697420726574656e74696f6e3b206e6f206175746f6d617469632064656c6574696f6e227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e6d6f64756c652e64697361626c65222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b2263616e646964617465223a22433137207570646174654d6f64756c6520666976652d6669656c6420626f64793b207265706c6163656d656e7444696765737420757365732074686520736f6c65206d6f64756c652d636f6d6d616e642d636f6e7472616374206d6f64756c6544697361626c655265706c6163656d656e74446967657374206f776e6572206f766572204d4f442d4f502d44495341424c452c2063616e6f6e6963616c207461726765742055524e2c2063616e6f6e6963616c2075696e743634206578706563746564207265766973696f6e20616e64206578616374206d616e6966657374206469676573742e20436f6e66696775726174696f6e20616e642067656e65726174696f6e2072656d61696e20696e646570656e64656e746c7920626f756e6420627920746865207369676e6564206265666f72652f616674657220737461746520616e642070726f64756374696f6e206576616c7561746f7220726573756c742e222c22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a226d6f64756c6573222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34316138373763613765303065373466333263386265636638646165653338663236633132616239643964636636666638306564386537353630386233633166222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227374617465223a7b22616273656e6365223a7b226578697374656e6365223a302c2270726f6a656374696f6e223a7b7d2c227265766973696f6e223a307d2c22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f523b206f7074696f6e616c206669656c64732068617665206578706c696369742070726573656e63652072756c6573222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c226d6f64756c655f696e7374616c6c6174696f6e5f6964225d2c226f776e6572223a22636f6e74726f6c2e6d6f64756c655f696e7374616c6c6174696f6e202b20696d6d757461626c6520636f6e74726f6c2e6d6f64756c655f76657273696f6e202b20636f6e74726f6c2e6d6f64756c655f636f6e66696775726174696f6e5f67656e65726174696f6e222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a226d6f64756c655f6964222c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a2273656d616e7469635f76657273696f6e222c2274797065223a2254455854227d2c223130223a7b22636f6c756d6e223a226163746976655f6d616e69666573745f646967657374222c2270726573656e6365223a22726571756972656420696666206669656c6420362069732031222c2274797065223a22483332227d2c2232223a7b22636f6c756d6e223a226d616e69666573745f646967657374222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a2261646d697373696f6e5f646570656e64656e63795f646967657374222c2274797065223a22483332227d2c2234223a7b22636f6c756d6e223a22636f6e66696775726174696f6e5f646967657374222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a227374617465222c22656e756d223a5b2241444d4954544544222c22494e5354414c4c45445f44495341424c4544222c22454e41424c4544225d2c2274797065223a2254455854227d2c2236223a7b22636f6c756d6e223a226163746976655f6d616e69666573745f646967657374222c22656e636f64696e67223a2250726573656e63653a203020616273656e742c20312070726573656e743b206669656c642031302072657175697265642065786163746c79207768656e2070726573656e74222c2274797065223a22553634227d2c2237223a7b22636f6c756d6e223a22636f6e66696775726174696f6e2e67656e65726174696f6e222c2274797065223a22553634227d2c2238223a7b22636f6c756d6e223a22636f6e66696775726174696f6e2e616374697665222c22656e636f64696e67223a223020696e6163746976652c2031206163746976653b206163746976652065786163746c7920696e20454e41424c4544222c2274797065223a22553634227d2c2239223a7b22636f6c756d6e223a226c6966656379636c655f6576616c756174696f6e5f646967657374222c2270726573656e6365223a227265717569726564206265666f726520616e642061667465722064697361626c653b2062696e6473207468652065786163742070726f64756374696f6e206576616c7561746f7220726573756c74222c2274797065223a22483332227d7d2c227265766973696f6e223a226167677265676174655f76657273696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a22494e5354414c4c45445f44495341424c45445f5245564953494f4e5f504c55535f4f4e45222c226265666f7265223a22454e41424c4544222c226368616e6765223a2252657461696e20746865206578616374206d6f64756c652c20696d6d757461626c652072656c656173652c20636f6e66696775726174696f6e2064696765737420616e642066756c6c2d77696474682067656e65726174696f6e2e2044656163746976617465206f6e6c79207468652073656c656374656420696e7374616c6c656420636f6e747269627574696f6e2061667465722063757272656e7420646570656e64656e637920616e6420726576657273652d7265666572656e63652066656e63657320616e6420736964652d6566666563742d667265652070726f64756374696f6e206576616c756174696f6e3b20636c65617220616374697665206d616e69666573742070726573656e636520616e6420636f6e66696775726174696f6e206163746976652073746174652061746f6d6963616c6c792e204d75746174696f6e206c6f636b73206f6e20746865206d6f64756c6520616e64206166666563746564207265666572656e636520646570656e64656e636965732073757276697665207468726f75676820636f6d6d69742e204e6f206163746f72207065726d697373696f6e206973206772616e74656420616e64206e6f2065787465726e616c2072756e74696d652065666665637420697320636c61696d65642e222c22636f6d6d616e64223a2244495341424c45222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d5349474e494e475f4b45595f524f544154494f4e535f414456414e43455f5245534f555243452d5631222c2261676772656761746554797065223a227369676e696e672d6b65792d726f746174696f6e222c22617574686f72697479223a7b226163746f72223a2241757468656e74696361746564207061727469636970616e74207573657220666f72206e657720656666656374733b20646973706174636865642070726f7669646572207472757468206d61792062652066696e616c697a6564206f6e6c79206279207468652041504920776f726b6c6f6164207573696e6720746865206964656e746974792d697373756564205349474e494e475f524f544154494f4e5f415454454d50545f5245434f4e43494c455f5631206361706162696c6974792e222c22617070726f76616c223a22457861637420696d6d757461626c65206372656174696f6e20617070726f76616c206f7220656666656374697665207265706c6163656d656e7420617574686f72697a6174696f6e2067656e65726174696f6e3b207265706c6163656d656e7420726571756972657320697473206f776e207365727665722d646572697665642063616e6469646174652c2063757272656e74206d616b657220616e642064697374696e6374206c69766520636865636b6572207468726f75676820746865206578697374696e6720576562417574686e20617070726f76616c206f776e65722e20486973746f726963616c20617070726f76616c73206e6576657220617574686f72697a65206e65772065666665637473206166746572207265766f636174696f6e2e222c22636f6e74696e756174696f6e223a224578616374206f726967696e616c206f7065726174696f6e2c207461726765742c20726571756573742c20646566696e6974697665206f62736572766174696f6e2c206f726967696e616c206163746f722f6d616b65722f636865636b65722f617070726f76616c20616e642063757272656e7420776f726b6c6f61642f617574686f726974792062696e64696e673b2070696e6e65642045533235362c2066696e616c697a65722061756469656e63652c206f6e652d757365204a544920616e642033302d7365636f6e642054544c2e204e6f20726564697370617463682c206375746f7665722c2074727573742061646d697373696f6e206f72206361706162696c69747920776964656e696e672e2053746f726520617373657274696f6e206469676573742f636f6e74657874206f6e6c792e204368616e676564206f726967696e616c20617574686f72697479206372656174657320612064757261626c6520686f6c642e222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c2073657373696f6e2c206163746f722c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c206f7065726174696f6e2c20726f746174696f6e2c20696e70757420616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2263757272656e742063616c6c657220616e64206f726967696e616c206d616b65722f636865636b65722070617468732c20776f726b6c6f6164206964656e74697469657320616e64206c6976652065706f636873227d2c22636174616c6f674f7065726174696f6e4964223a224f50532d4f502d414456414e43452d5349474e494e472d4b45592d524f544154494f4e222c226576656e745061796c6f6164223a2263616e6f6e6963616c206964656e74697469657320616e642066696e6765727072696e7473206f6e6c793b206e6f20736563726574207265666572656e636573206f722070726f766964657220626f64696573222c226576656e7473223a5b7b2263617264696e616c697479223a2265786163746c792031206f6e6c79206174204f4c445f5245564f4b45442c206f74686572776973652030222c226576656e7454797065223a22696f2e6f70656e70632e6f70732e7365637265742e7265766f6b65642e7631227d2c7b2263617264696e616c697479223a2265786163746c792031206f6e6c7920617420434f4d504c4554452c206f74686572776973652030222c226576656e7454797065223a22696f2e6f70656e70632e6f70732e7365637265742e726f74617465642e7631227d5d2c226c6966656379636c65223a7b22636f6e73756d6572223a22766572696679206578616374203234303031403220726563656970742f434f53452f70726f66696c652f747275737420616e6420636f6e746967756f757320434f4e54524f4c5f5349474e494e475f4c4946454359434c455f56312072656365697074206f7264696e616c2c20696e646570656e64656e746c79206f66206f7574626f78206167677265676174652073657175656e6365733b207065727369737420696e626f78206265666f726520636865636b706f696e74222c226661696c757265223a22556e6469737061746368656420617574686f72697479206c6f7373206661696c7320746865206f726967696e616c206f7065726174696f6e20776974682070726f7465637465642064656e69616c2065766964656e63652c206e6f2070726f76696465722063616c6c206f72207369676e6564207265766973696f6e2c20616e64207265717569726573206120667265736820626f756e6420617070726f76616c2e2054727573746564204e4f545f4150504c494544206661696c73204e4f5f4546464543545f524554525941424c4520776974686f75742061206c6966656379636c65207265766973696f6e206f72206576656e742e204f7468657220646566696e69746976652072656a656374696f6e20636f6d6d697473207369676e6564204641494c454420616e642070726573657276657320657665727920636f6d706c65746564206375746f76657220616e642073656c6563746564206b65792e222c226964656d706f74656e6379223a227265706c617920707265736572766573206f726967696e616c206f7065726174696f6e2c20686973746f72792c207265636569707420616e64206576656e74206964656e7469666965727320616e64206279746573222c2270726f7669646572223a22776f726b65722d6f776e6564206c6966656379636c65206d75746174696f6e733b20636f6d6d697420617474656d7074206265666f72652064697370617463683b206c6f6f6b75702d6f6e6c79207265636f6e63696c696174696f6e20616674657220756e6365727461696e7479222c22726f6c6c6261636b223a2265766964656e63652f686973746f72792f6f7574626f78206661696c75726520726f6c6c73206261636b206c6f63616c207472616e736974696f6e3b2072657461696e20696e646570656e64656e742070726f7669646572206f62736572766174696f6e3b206e6576657220726576697665207265766f6b6564206b6579227d2c226f7065726174696f6e456666656374223a225349474e494e475f524f544154494f4e5f414456414e4345222c2270726976616379223a7b22706c6163656d656e74223a2273616d65206578706c69636974207061727469636970616e7420616e64207072697661637920646f6d61696e20617320726f746174696f6e222c2272656164223a2263757272656e742073636f70656420617574686f72697a6174696f6e3b207265636569707473206e65766572206772616e7420617574686f72697479222c22726574656e74696f6e223a22696d6d757461626c65206c6966656379636c6520686973746f72792c207075626c69632074727573742c20726563656970742f65766964656e63652f6f7574626f7820616e64206f726967696e616c2070726f7669646572206f62736572766174696f6e733b206e6f2070726976617465206b6579206279746573227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e7369676e696e672d726f746174696f6e2e616476616e6365222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a227369676e696e672d6b65792d726f746174696f6e222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34653764653336383631383139393039323735626465633831303364316466303439383463303362333463623539333433376466653638663563326331643961222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227369676e6572223a7b226772616e7473223a22657861637420414456414e43452f5245434f5645522070726f66696c6573206f6e6c79222c22707572706f7365223a2270632e636f73652e636f6e74726f6c2d627573696e6573732d7472616e736974696f6e2e7631222c22726f6c65223a224c4946454359434c455f45564944454e4345222c2273656c66526f746174696f6e223a226f6c64206c6966656379636c65207369676e657220617474657374732061746f6d6963204355544f5645525f46454e4345443b206e6577207369676e657220617474657374732073756273657175656e74207374617465733b206f6c64207075626c69632074727573742072657461696e6564222c2274617267657442696e64696e67223a22686973746f72792073657061726174656c792062696e647320746172676574207369676e657220726f6c652f494420616e642074686520617474657374696e67206c6966656379636c652065766964656e6365207369676e65722f65706f6368227d2c227374617465223a7b22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f52222c22686973746f72794f776e6572223a22636f6e74726f6c2e7369676e696e675f726f746174696f6e5f686973746f7279222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22726f746174696f6e5f6964225d2c226f776e6572223a22636f6e74726f6c2e7369676e696e675f6b65795f726f746174696f6e222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a227374617465222c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a2263616e6469646174655f646967657374222c2274797065223a22483332227d2c2232223a7b22636f6c756d6e223a22686973746f72795f646967657374222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a22726571756573742e7369676e6572526f6c65222c2274797065223a2254455854227d2c2234223a7b22636f6c756d6e223a226f6c645f7369676e65725f6964222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a226e65775f7369676e65725f69642070726573656e6365222c2274797065223a2255494e545f454e554d222c2276616c756573223a7b2230223a22414253454e54222c2231223a2250524553454e54227d7d2c2236223a7b22636f6c756d6e223a226e65775f7369676e65725f6964222c2270726573656e6365223a22726571756972656420696666206669656c64203520697320313b206f6d697474656420696666206669656c64203520697320303b206e756c6c2c20656d70747920616e6420616c6c2d7a65726f2073656e74696e656c732072656a6563746564222c2274797065223a22483332227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5245564953494f4e5f504c55535f4f4e45222c226265666f7265223a2250524553454e545f41545f43555252454e545f4c4946454359434c455f5245564953494f4e222c2262696e64696e67223a22617070656e642d6f6e6c7920686973746f72792062696e6473207072696f722073746174652f6469676573742c20617070726f76616c20617574686f726974792c206f726967696e616c2070656e64696e67206f7065726174696f6e2c2070726f766964657220617474656d707420616e64206f62736572766174696f6e20646967657374732c20746172676574207369676e657220726f6c652f49442c206c6966656379636c652065766964656e6365207369676e65722f65706f63682c2073656c6563746564207461726765742074727573742f65706f63682c20636f6e73756d65722061636b6e6f776c656467656d656e7420616e64206576656e742f65766964656e6365206964656e74696669657273222c22636f6d6d616e64223a22414456414e4345222c226e6f4f70223a2252454a4543545f574954484f55545f45464645435453227d2c227472616e736974696f6e4b696e64223a317d','hex'),decode('7b22616374696f6e496e74656e744964223a224143542d5349474e494e475f4b45595f524f544154494f4e535f5245434f5645525f5245534f555243452d5631222c2261676772656761746554797065223a227369676e696e672d6b65792d726f746174696f6e222c22617574686f72697479223a7b226163746f72223a2261757468656e74696361746564207061727469636970616e7420757365722073657373696f6e3b2063757272656e74206f7065726174696f6e20617574686f726974792069732066656e636564222c22617070726f76616c223a22457861637420696d6d757461626c65206372656174696f6e20617070726f76616c206f7220656666656374697665207265706c6163656d656e7420617574686f72697a6174696f6e2067656e65726174696f6e3b207265706c6163656d656e7420726571756972657320697473206f776e207365727665722d646572697665642063616e6469646174652c2063757272656e74206d616b657220616e642064697374696e6374206c69766520636865636b6572207468726f75676820746865206578697374696e6720576562417574686e20617070726f76616c206f776e65722e20486973746f726963616c20617070726f76616c73206e6576657220617574686f72697a65206e65772065666665637473206166746572207265766f636174696f6e2e222c2265766964656e6365223a5b7b2262696e64696e67223a2261637475616c2073657373696f6e2c206163746f722c207061727469636970616e742c207072697661637920646f6d61696e2c20616374696f6e2c206f7065726174696f6e2c20726f746174696f6e2c20696e70757420616e64206578706563746564207265766973696f6e222c22666f726d6174223a224944454e544954595f52554e54494d455f415353455254494f4e5f333030325f325f3133222c226b696e64223a322c226f776e6572223a22636f6e74726f6c2e6d75746174696f6e5f65766964656e6365227d5d2c22736e617073686f74223a2263757272656e742063616c6c657220616e64206f726967696e616c206d616b65722f636865636b65722070617468732c20776f726b6c6f6164206964656e74697469657320616e64206c6976652065706f636873227d2c22636174616c6f674f7065726174696f6e4964223a224f50532d4f502d5245434f5645522d5349474e494e472d4b45592d524f544154494f4e222c226576656e745061796c6f6164223a2263616e6f6e6963616c206964656e74697469657320616e642066696e6765727072696e7473206f6e6c793b206e6f20736563726574207265666572656e636573206f722070726f766964657220626f64696573222c226576656e7473223a5b5d2c226c6966656379636c65223a7b22636f6e73756d6572223a22766572696679206578616374203234303031403220726563656970742f434f53452f70726f66696c652f747275737420616e6420636f6e746967756f757320434f4e54524f4c5f5349474e494e475f4c4946454359434c455f56312072656365697074206f7264696e616c2c20696e646570656e64656e746c79206f66206f7574626f78206167677265676174652073657175656e6365733b207065727369737420696e626f78206265666f726520636865636b706f696e74222c22676f7665726e616e6365223a22417070726f76616c20616c6f6e65206368616e676573206e656974686572207369676e6564207374617465206e6f722065666665637469766520617574686f726974792e20436c656172206120686f6c64206f6e6c79207769746820746865206578616374207369676e6564207265636f766572792c20617070726f76616c20636f6e73756d7074696f6e20616e642070726f7465637465642065766964656e63652e205072657365727665206f726967696e616c206163746f72732f63616e646964617465732f617070726f76616c732f617474656d7074732f72656365697074732e2052656a6563742073656c6620617070726f76616c2c2063726f73732d707269766163792072657573652c207374616c652067656e65726174696f6e7320616e6420706f73742d6375746f76657220726f6c6c6261636b2e2052656e6577616c7320656d6974207a65726f20736563726574206c6966656379636c65206576656e74732e222c226964656d706f74656e6379223a225245434f56455220757365732061206e6577206b65793b206964656e746963616c2d6b6579207265706c61792072657475726e73207468652073746f7265642073756363657373206f7220726574727961626c65206661696c75726520776974686f75742070726f7669646572206c6f6f6b75702e20467265736820706f6c6c696e6720757365732061206672657368206b65792e204c6f6f6b757020756e617661696c6162696c697479206f7220696e76616c6964206f62736572766174696f6e73206e6576657220696d706c79204e4f5f4e45575f4f42534552564154494f4e2e222c2270726f7669646572223a22776f726b65722d6f776e6564206c6966656379636c65206d75746174696f6e733b20636f6d6d697420617474656d7074206265666f72652064697370617463683b206c6f6f6b75702d6f6e6c79207265636f6e63696c696174696f6e20616674657220756e6365727461696e7479222c22726f6c6c6261636b223a2241206d697373696e67207265636f76657279207369676e6174757265206c656176657320746865207369676e656420737461746520756e6368616e6765642c2072657461696e732070726f7669646572206b6e6f776c6564676520616e6420746865206f726967696e616c2061646d697373696f6e2066656e63652c20616e64206661696c73206f6e6c7920746865207265636f76657279206f7065726174696f6e2e20436f6d6d6974746564207265636f76657279207375706572736564657320756e7369676e6564207072696f722d7265766973696f6e20726563656970742070726f706f73616c73207768696c652072657461696e696e6720746865697220696d6d757461626c652062797465732e204e6f2070726f7669646572206d75746174696f6e206973207265646973706174636865642e227d2c226f7065726174696f6e456666656374223a225349474e494e475f524f544154494f4e5f5245434f564552222c2270726976616379223a7b22706c6163656d656e74223a2273616d65206578706c69636974207061727469636970616e7420616e64207072697661637920646f6d61696e20617320726f746174696f6e222c2272656164223a2263757272656e742073636f70656420617574686f72697a6174696f6e3b207265636569707473206e65766572206772616e7420617574686f72697479222c22726574656e74696f6e223a22696d6d757461626c65206c6966656379636c6520686973746f72792c207075626c69632074727573742c20726563656970742f65766964656e63652f6f7574626f7820616e64206f726967696e616c2070726f7669646572206f62736572766174696f6e733b206e6f2070726976617465206b6579206279746573227d2c2270726f66696c654964223a2270632e636f6e74726f6c2e7369676e696e672d726f746174696f6e2e7265636f766572222c2270726f66696c6556657273696f6e223a312c227265717565737442696e64696e67223a7b22646f6d61696e223a2270632e636f6e74726f6c2e636f6e66696775726174696f6e2d726571756573742e7631222c22656e636f64696e67223a225554462d3820646f6d61696e20706c7573204e554c3b2065616368206669656c642070726566697865642062792075696e743332206269672d656e6469616e205554462d382062797465206c656e6774683b205348412d323536222c226669656c6473223a5b227061727469636970616e744964222c2270726976616379446f6d61696e4964222c227072696e636970616c4964222c22616374696f6e496e74656e744964222c22636174616c6f674f7065726174696f6e4964222c2261676772656761746554797065222c226167677265676174654964222c2265787065637465645265766973696f6e202863616e6f6e6963616c2075363420646563696d616c29222c2263616e64696461746544696765737420287368613235363a206c6f776572636173652068657829222c226964656d706f74656e63794b6579225d7d2c227265736f7572636554797065223a227369676e696e672d6b65792d726f746174696f6e222c22736368656d61446566696e6974696f6e446967657374223a227368613235363a34653764653336383631383139393039323735626465633831303364316466303439383463303362333463623539333433376466653638663563326331643961222c2273657175656e63654e616d657370616365223a22434f4e54524f4c5f425553494e4553535f5452414e534954494f4e5f5631222c227369676e6572223a7b226772616e7473223a22657861637420414456414e43452f5245434f5645522070726f66696c6573206f6e6c79222c22707572706f7365223a2270632e636f73652e636f6e74726f6c2d627573696e6573732d7472616e736974696f6e2e7631222c22726f6c65223a224c4946454359434c455f45564944454e4345222c2273656c66526f746174696f6e223a226f6c64206c6966656379636c65207369676e657220617474657374732061746f6d6963204355544f5645525f46454e4345443b206e6577207369676e657220617474657374732073756273657175656e74207374617465733b206f6c64207075626c69632074727573742072657461696e6564222c2274617267657442696e64696e67223a22686973746f72792073657061726174656c792062696e647320746172676574207369676e657220726f6c652f494420616e642074686520617474657374696e67206c6966656379636c652065766964656e6365207369676e65722f65706f6368227d2c227374617465223a7b22646967657374223a2270632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76313b205348412d323536206f7665722063616e6f6e6963616c2074797065642043424f52222c22686973746f72794f776e6572223a22636f6e74726f6c2e7369676e696e675f726f746174696f6e5f686973746f7279222c226964656e74697479223a5b227061727469636970616e745f6964222c22707269766163795f646f6d61696e5f6964222c22726f746174696f6e5f6964225d2c226f776e6572223a22636f6e74726f6c2e7369676e696e675f6b65795f726f746174696f6e222c2270726f6a656374696f6e223a7b2230223a7b22636f6c756d6e223a227374617465222c2274797065223a2254455854227d2c2231223a7b22636f6c756d6e223a2263616e6469646174655f646967657374222c2274797065223a22483332227d2c2232223a7b22636f6c756d6e223a22686973746f72795f646967657374222c2274797065223a22483332227d2c2233223a7b22636f6c756d6e223a22726571756573742e7369676e6572526f6c65222c2274797065223a2254455854227d2c2234223a7b22636f6c756d6e223a226f6c645f7369676e65725f6964222c2274797065223a22483332227d2c2235223a7b22636f6c756d6e223a226e65775f7369676e65725f69642070726573656e6365222c2274797065223a2255494e545f454e554d222c2276616c756573223a7b2230223a22414253454e54222c2231223a2250524553454e54227d7d2c2236223a7b22636f6c756d6e223a226e65775f7369676e65725f6964222c2270726573656e6365223a22726571756972656420696666206669656c64203520697320313b206f6d697474656420696666206669656c64203520697320303b206e756c6c2c20656d70747920616e6420616c6c2d7a65726f2073656e74696e656c732072656a6563746564222c2274797065223a22483332227d7d2c227265766973696f6e223a227265766973696f6e3a753634227d2c227472616e736974696f6e223a7b226166746572223a2250524553454e545f5245564953494f4e5f504c55535f4f4e45222c226265666f7265223a2250524553454e545f41545f43555252454e545f4c4946454359434c455f5245564953494f4e222c2262696e64696e67223a2241206672657368206f62736572766174696f6e205245434f5645522062696e647320746865206f726967696e616c2070656e64696e6720414456414e43452c2065786163742070726f766964657220617474656d707420616e64207072696f72206f62736572766174696f6e206469676573742e204e65772074727573746564206b6e6f776c6564676520636f6d6d697473205245434f564552494e4720776974686f757420616e20616476616e6365206566666563742e20466f7220616e20617574686f7269747920686f6c64206f72207369676e6564204641494c45442073746174652c207468652066697273742072657175657374207374616765732061207365727665722d646572697665642063616e6469646174652062696e64696e672063757272656e742073746174652f7265766973696f6e2c20686f6c642c206f726967696e616c206f7065726174696f6e20616e6420617574686f726974792c206f62736572766174696f6e732c2073656c656374696f6e2f66656e636520616e64207072696f7220617574686f72697a6174696f6e2067656e65726174696f6e2e204578616374207265706c61792061667465722064697374696e63742d636865636b657220617070726f76616c207369676e7320612073616d652d737461746520617574686f726974792072656e6577616c206f72204641494c45442d746f2d5245434f564552494e4720666f727761726420706c616e20616e642061746f6d6963616c6c792061637469766174657320746865207265706c6163656d656e742067656e65726174696f6e2e205468652063616c6c65722063616e6e6f742073656c6563742061207461726765743b20696e74657276656e696e672073746174652c20617574686f726974792c20686f6c64206f72206f62736572766174696f6e206368616e6765207265717569726573206120667265736820726571756573742e222c22636f6d6d616e64223a225245434f564552222c226e6f4f70223a225355434345454445445f4e4f5f4e45575f4f42534552564154494f4e5f574954484f55545f5245564953494f4e5f484953544f52595f524543454950545f4f525f4556454e54227d2c227472616e736974696f6e4b696e64223a317d','hex')) THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-BUSINESS-PROFILE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS business_profile_admission ON control.business_transition_profile;
CREATE TRIGGER business_profile_admission BEFORE INSERT ON control.business_transition_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_profile_admission();
CREATE OR REPLACE FUNCTION openpc.guard_business_receipt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE actual jsonb; expected jsonb; before_state jsonb; after_state jsonb; proof jsonb; receipt_version integer; continuation control.signing_continuation%ROWTYPE; continuation_used boolean:=false; authorization_time numeric;
 profile control.business_transition_profile%ROWTYPE; authorization_row control.mutation_evidence%ROWTYPE; runtime_payload jsonb; runtime_key_id text; outer_cose jsonb; protected_header jsonb;
BEGIN
 actual:=openpc.business_cbor(NEW.receipt_cbor);
 SELECT * INTO STRICT profile FROM control.business_transition_profile WHERE profile_digest=NEW.profile_digest;
 receipt_version:=CASE encode(profile.schema_definition_digest,'hex')
  WHEN '41a877ca7e00e74f32c8becf8daee38f26c12ab9d9dcf6ff80ed8e75608b3c1f' THEN 1
  WHEN '4e7de36861819909275bdec8103d1df04984c03b34cb593437dfe68f5c2c1d9a' THEN 2 END;
 IF receipt_version IS NULL OR (receipt_version=2 AND profile.catalog_operation_id NOT IN
  ('OPS-OP-ADVANCE-SIGNING-KEY-ROTATION','OPS-OP-RECOVER-SIGNING-KEY-ROTATION'))
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-SCHEMA-VERSION'; END IF;
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
  '100',24001,'101',receipt_version,'102',338,'103',2) THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-COSE-CONTEXT'; END IF;
 before_state:=openpc.business_cbor(NEW.before_state_preimage);
 after_state:=openpc.business_cbor(NEW.after_state_preimage);
 IF before_state IS DISTINCT FROM jsonb_build_array('pc.control.transition-state.v1',openpc.business_bytes(NEW.profile_digest),
  openpc.business_uuid(NEW.participant_id),openpc.business_uuid(NEW.privacy_domain_id),NEW.aggregate_type,
  openpc.business_uuid(NEW.aggregate_id),NEW.before_existence,NEW.before_revision,before_state->8) OR
  after_state IS DISTINCT FROM jsonb_build_array('pc.control.transition-state.v1',openpc.business_bytes(NEW.profile_digest),
  openpc.business_uuid(NEW.participant_id),openpc.business_uuid(NEW.privacy_domain_id),NEW.aggregate_type,
  openpc.business_uuid(NEW.aggregate_id),NEW.after_existence,NEW.after_revision,after_state->8) OR
  (NEW.before_existence=0 AND before_state->8<>'{}'::jsonb) THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-STATE-BINDING'; END IF;
 IF receipt_version=2 AND convert_from(NEW.authority_snapshot,'UTF8')::jsonb->>'schema'='pc.control.signing-rotation-continuation-snapshot.v1' THEN
  SELECT * INTO STRICT continuation FROM control.signing_continuation WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id AND state='CONSUMED'
   AND consumed_receipt_id=NEW.receipt_id;
  continuation_used:=true;
 END IF;
 IF jsonb_typeof(actual->'20') IS DISTINCT FROM 'array' OR jsonb_array_length(actual->'20')<>(CASE WHEN continuation_used OR NEW.catalog_operation_id IN ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE','CFG-OP-CREATE-EVIDENCE-HOLD','CFG-OP-RELEASE-EVIDENCE-HOLD','CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-DELETE-LOCAL-EVIDENCE','CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH','CFG-OP-DELETE-RAW-PROOF-BATCH','CFG-OP-DELETE-PROJECTION-BATCH','CFG-OP-ADMIT-STORE-RETIREMENT','CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE','CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH','CFG-OP-ACTIVATE-RETENTION-POLICY','CFG-OP-RETIRE-RETENTION-POLICY') OR NEW.catalog_operation_id IN ('CFG-OP-CREATE-NOTIFICATION-ENDPOINT','CFG-OP-UPDATE-NOTIFICATION-ENDPOINT') THEN 2 ELSE 1 END) OR
    jsonb_typeof(actual->'21') IS DISTINCT FROM 'array' OR
    (receipt_version=1 AND jsonb_array_length(actual->'21')<>1) OR
    (receipt_version=2 AND jsonb_array_length(actual->'21') NOT BETWEEN 0 AND 1) THEN
  RAISE EXCEPTION 'DATA-6021-RECEIPT-PROFILE-CARDINALITY'; END IF;
 IF NEW.catalog_operation_id IN ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE') THEN
  PERFORM openpc.check_module_admission_receipt(NEW);
 ELSIF NEW.catalog_operation_id IN ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE','CFG-OP-CREATE-EVIDENCE-HOLD','CFG-OP-RELEASE-EVIDENCE-HOLD','CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-DELETE-LOCAL-EVIDENCE','CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH','CFG-OP-DELETE-RAW-PROOF-BATCH','CFG-OP-DELETE-PROJECTION-BATCH','CFG-OP-ADMIT-STORE-RETIREMENT','CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE','CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH','CFG-OP-ACTIVATE-RETENTION-POLICY','CFG-OP-RETIRE-RETENTION-POLICY') THEN
  PERFORM openpc.check_governed_configuration_receipt(NEW);
 ELSE
 SELECT * INTO STRICT authorization_row FROM control.mutation_evidence e WHERE e.participant_id=NEW.participant_id
  AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id
  AND e.action_intent_id=NEW.action_intent_id AND e.catalog_operation_id=NEW.catalog_operation_id AND e.aggregate_id=NEW.aggregate_id
  AND e.candidate_digest=NEW.candidate_digest AND e.evidence_digest=sha256(e.evidence_cbor)
  AND e.evidence_role='AUTHORIZATION_INPUT' AND e.evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13';
 proof:=jsonb_build_object('0',2,'1',authorization_row.mutation_evidence_id::text,'2',openpc.business_bytes(authorization_row.evidence_digest));
 IF continuation_used THEN
  SELECT jsonb_agg(p ORDER BY p->>'1') INTO expected FROM jsonb_array_elements(jsonb_build_array(proof,
   jsonb_build_object('0',2,'1',continuation.assertion_id::text,'2',openpc.business_bytes(continuation.assertion_digest)))) p;
  SELECT (convert_from(c.authorization_snapshot,'UTF8')::jsonb->>'recordedAtNs')::numeric INTO STRICT authorization_time
   FROM control.signing_rotation_command c WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
    AND c.operation_id=NEW.operation_id AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1';
 ELSIF NEW.catalog_operation_id IN ('CFG-OP-CREATE-NOTIFICATION-ENDPOINT','CFG-OP-UPDATE-NOTIFICATION-ENDPOINT') THEN
  expected:=jsonb_build_array(proof,openpc.configuration_step_up_receipt_input(NEW,authorization_row));
  authorization_time:=NEW.recorded_at_ns;
 ELSE expected:=jsonb_build_array(proof); authorization_time:=NEW.recorded_at_ns;
 END IF;
 IF actual->'20' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-AUTHORIZATION-OWNER'; END IF;
 runtime_payload:=openpc.business_cbor(authorization_row.evidence_cbor);
 runtime_key_id:=openpc.identity_runtime_cose_key_id(authorization_row.evidence_cbor,authorization_row.cose_sign1);
 IF runtime_key_id=NEW.signer_id OR
    runtime_payload->'1' IS DISTINCT FROM openpc.business_bytes(NEW.actor_key_digest) OR
    jsonb_typeof(runtime_payload->'8') IS DISTINCT FROM 'number' OR jsonb_typeof(runtime_payload->'9') IS DISTINCT FROM 'number' OR
    (runtime_payload->>'8')::numeric>authorization_time OR (runtime_payload->>'9')::numeric<=authorization_time THEN
   RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-TYPED-PURPOSE-BINDING'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=NEW.participant_id
   AND i.privacy_domain_id=NEW.privacy_domain_id AND i.operation_id=NEW.operation_id
   AND i.idempotency_record_id=NEW.idempotency_record_id AND i.action_intent_id=NEW.action_intent_id
   AND i.catalog_operation_id=NEW.catalog_operation_id AND i.input_digest=NEW.candidate_digest
   AND NEW.request_digest=openpc.business_request_digest(ARRAY[i.participant_id::text,i.privacy_domain_id::text,i.principal_id::text,
     i.action_intent_id,i.catalog_operation_id,NEW.aggregate_type,NEW.aggregate_id::text,i.expected_aggregate_version::text,
     'sha256:'||encode(i.input_digest,'hex'),i.idempotency_key])) THEN
  RAISE EXCEPTION 'DATA-6021-RECEIPT-IDEMPOTENCY-OWNER'; END IF;

 IF NEW.aggregate_type='evidence-hold' THEN
  PERFORM openpc.assert_evidence_hold_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='evidence-deletion' THEN
  PERFORM openpc.assert_evidence_deletion_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='runtime-artifact-disposition' THEN
  PERFORM openpc.assert_runtime_artifact_disposition_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='store-retirement' THEN
  PERFORM openpc.assert_store_retirement_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='retention-policy' THEN
  PERFORM openpc.assert_retention_policy_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='work-item' THEN
  PERFORM openpc.assert_work_item_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='notification' THEN
  PERFORM openpc.assert_notification_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='notification-endpoint' THEN
  PERFORM openpc.assert_notification_endpoint_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='indexer-profile' THEN
  IF profile.profile_version NOT IN (1,2) OR (profile.profile_version=2 AND (
    (NEW.before_existence=1 AND (NOT (before_state->8 ?& ARRAY['0','1','2','3','4']) OR
      before_state->8->'4' NOT IN ('0'::jsonb,'1'::jsonb) OR
      (before_state->8 ? '5') IS DISTINCT FROM (before_state->8->'4'='1'::jsonb) OR
      ((before_state->8)-ARRAY['0','1','2','3','4','5'])<>'{}'::jsonb OR
      (before_state->8->'4'='1'::jsonb AND (before_state->8->'5' IS DISTINCT FROM
        jsonb_build_object('bytes',before_state->8->'5'->>'bytes') OR
        coalesce(before_state->8->'5'->>'bytes','')!~'^[0-9a-f]{64}$')))) OR
    after_state->8->'4' NOT IN ('0'::jsonb,'1'::jsonb)))
  THEN RAISE EXCEPTION 'DATA-6021-INDEXER-PROVENANCE-PROFILE'; END IF;
  IF NOT EXISTS(SELECT 1 FROM control.indexer_profile i WHERE i.participant_id=NEW.participant_id
   AND i.privacy_domain_id=NEW.privacy_domain_id AND i.indexer_profile_id=NEW.aggregate_id
   AND i.revision=NEW.after_revision AND NEW.after_existence=1
   AND (profile.profile_version=2 OR i.policy_generation_digest IS NOT NULL)
   AND after_state->8=(jsonb_build_object('0',i.engine,'1',i.engine_version,
    '2',openpc.business_bytes(decode(substring(i.method_profile_digest from 8),'hex')),'3',i.state) ||
    CASE WHEN profile.profile_version=1 THEN jsonb_build_object('4',openpc.business_bytes(decode(substring(i.policy_generation_digest from 8),'hex')))
    WHEN i.policy_generation_digest IS NULL THEN jsonb_build_object('4',0)
    ELSE jsonb_build_object('4',1,'5',openpc.business_bytes(decode(substring(i.policy_generation_digest from 8),'hex'))) END)) THEN
    RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-INDEXER-STATE'; END IF;
  IF (NEW.catalog_operation_id='CFG-OP-CREATE-INDEXER-PROFILE' AND
      (NEW.before_existence<>0 OR NEW.after_revision<>1 OR after_state->8->>'3'<>'REGISTERED')) OR
     (NEW.catalog_operation_id='CFG-OP-UPDATE-INDEXER-PROFILE' AND
      (NEW.before_existence<>1 OR NEW.after_revision<>NEW.before_revision+1 OR
       before_state->8->'0' IS DISTINCT FROM after_state->8->'0' OR
       before_state->8->'1' IS DISTINCT FROM after_state->8->'1' OR
       before_state->8->'3' IS DISTINCT FROM after_state->8->'3' OR
       (before_state->8->'2'=after_state->8->'2' AND before_state->8->'4'=after_state->8->'4'
        AND before_state->8->'5' IS NOT DISTINCT FROM after_state->8->'5'))) THEN
    RAISE EXCEPTION 'DATA-6021-RECEIPT-INDEXER-TRANSITION'; END IF;
 END IF;
 IF receipt_version=2 THEN
  PERFORM openpc.check_signing_rotation_receipt(NEW);
  RETURN NEW;
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
 -- This distinct namespace is fail-closed until the Control export owner installs
 -- its exact receipt/source/outbox checker. It cannot enter command receipt admission.
 IF NEW.proof_kind='EVIDENCE_EXPORT_COMPLETION_REFERENCE' THEN
  PERFORM openpc.check_evidence_export_completion_event(NEW);
  RETURN NEW;
 END IF;
 -- A distinct registered family: the owning checker must exist and validate
 -- actual original receipts, source, occurrence, payload references and cursors.
 -- Any missing owner or denial propagates; there is no command-receipt fallback.
 IF NEW.proof_kind='NOTIFICATION_DELIVERY_REQUEST_REFERENCE' THEN
  PERFORM openpc.check_notification_delivery_requested_event(NEW);
  RETURN NEW;
 END IF;
 -- Terminal native outcomes have a separate source-owned proof. A request
 -- receipt cannot authorize completion; missing final publication stays closed.
 IF NEW.proof_kind='NOTIFICATION_DELIVERY_COMPLETION_REFERENCE' THEN
  PERFORM openpc.check_notification_delivery_completed_event(NEW);
  RETURN NEW;
 END IF;
 IF NEW.proof_kind<>'BUSINESS_RECEIPT_REFERENCE' THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-OUTBOX-PROOF'; END IF;
 SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND receipt_id=NEW.receipt_id;
 payload:=openpc.business_cbor(NEW.payload_cbor);
 IF receipt.aggregate_type='signing-key-rotation' THEN
  PERFORM openpc.check_signing_rotation_event(NEW,receipt);
  RETURN NEW;
 END IF;
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
 IF coalesce(event_refs,'[]'::jsonb) IS DISTINCT FROM (openpc.business_cbor(receipt.receipt_cbor)->'21') OR
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
 IF snapshot->>'schema'='pc.control.signing-rotation-continuation-snapshot.v1' THEN
  IF NEW.aggregate_type<>'signing-key-rotation' THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-RECEIPT-PURPOSE'; END IF;
  PERFORM openpc.check_signing_continuation_snapshot(NEW.authority_snapshot,NEW.participant_id,NEW.privacy_domain_id,
   NEW.operation_id,NEW.receipt_id,NEW.recorded_at_ns,true);
  RETURN NEW;
 END IF;
 IF snapshot IS DISTINCT FROM jsonb_build_object('schema','pc.control.precommit-authority-snapshot.v1',
  'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'operationId',NEW.operation_id::text,
  'recordedAtNs',snapshot->'recordedAtNs','decision','ALLOW','authorities',snapshot->'authorities','dependencies',snapshot->'dependencies') OR
  jsonb_typeof(snapshot->'authorities') IS DISTINCT FROM 'array' OR
  jsonb_array_length(snapshot->'authorities')<>(CASE WHEN NEW.aggregate_type='signing-key-rotation' OR NEW.catalog_operation_id IN ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE','CFG-OP-CREATE-EVIDENCE-HOLD','CFG-OP-RELEASE-EVIDENCE-HOLD','CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-DELETE-LOCAL-EVIDENCE','CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH','CFG-OP-DELETE-RAW-PROOF-BATCH','CFG-OP-DELETE-PROJECTION-BATCH','CFG-OP-ADMIT-STORE-RETIREMENT','CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE','CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH','CFG-OP-ACTIVATE-RETENTION-POLICY','CFG-OP-RETIRE-RETENTION-POLICY') THEN 3 ELSE 1 END) OR
  NOT ((snapshot->>'recordedAtNs') ~ '^[0-9]{1,20}$') OR (snapshot->>'recordedAtNs')::numeric>NEW.recorded_at_ns THEN
   RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-HEADER'; END IF;
 IF snapshot->'dependencies' IS DISTINCT FROM jsonb_build_object('assignment',snapshot->'dependencies'->'assignment','authority_envelope',snapshot->'dependencies'->'authority_envelope','authority_role',snapshot->'dependencies'->'authority_role','credential',snapshot->'dependencies'->'credential','delegation',snapshot->'dependencies'->'delegation','participant',snapshot->'dependencies'->'participant','principal',snapshot->'dependencies'->'principal','privacy_domain',snapshot->'dependencies'->'privacy_domain','session',snapshot->'dependencies'->'session') THEN
  RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-DEPENDENCIES'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'assignment') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('assignment_id',owner.assignment_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'authority_group_id',owner.authority_group_id::text,'role_id',owner.role_id::text,'authority_envelope_id',owner.authority_envelope_id::text,'delegation_epoch',owner.delegation_epoch::text,'scope_digest',owner.scope_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'runtime_capability_ids',owner.runtime_capability_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'valid_during',owner.valid_during::text,'state',owner.state::text,'created_by_principal_id',owner.created_by_principal_id::text,'row_version',owner.row_version::text) ORDER BY owner.assignment_id),'[]'::jsonb) INTO expected
   FROM control.assignment owner WHERE owner.participant_id=NEW.participant_id AND owner.assignment_id IN
    (SELECT (dependency->>'assignment_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'assignment') dependency);
  IF snapshot->'dependencies'->'assignment' IS DISTINCT FROM expected  THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'authority_envelope') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('authority_envelope_id',owner.authority_envelope_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'maker_principal_id',owner.maker_principal_id::text,'checker_principal_id',owner.checker_principal_id::text,'authority_epoch',owner.authority_epoch::text,'delegation_epoch',owner.delegation_epoch::text,'state',owner.state::text,'valid_from',owner.valid_from::text,'valid_until',owner.valid_until::text,'semantic_digest',owner.semantic_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'runtime_capability_ids',owner.runtime_capability_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'row_version',owner.row_version::text) ORDER BY owner.authority_envelope_id),'[]'::jsonb) INTO expected
   FROM control.authority_envelope owner WHERE owner.participant_id=NEW.participant_id AND owner.authority_envelope_id IN
    (SELECT (dependency->>'authority_envelope_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'authority_envelope') dependency);
  IF snapshot->'dependencies'->'authority_envelope' IS DISTINCT FROM expected  THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'authority_role') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('authority_role_id',owner.authority_role_id::text,'participant_id',owner.participant_id::text,'role_id',owner.role_id::text,'action_intent_ids',owner.action_intent_ids::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.authority_role_id),'[]'::jsonb) INTO expected
   FROM control.authority_role owner WHERE owner.participant_id=NEW.participant_id AND owner.authority_role_id IN
    (SELECT (dependency->>'authority_role_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'authority_role') dependency);
  IF snapshot->'dependencies'->'authority_role' IS DISTINCT FROM expected  THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'credential') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('credential_id',owner.credential_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'kind',owner.kind::text,'state',owner.state::text,'credential_epoch',owner.credential_epoch::text,'valid_from',owner.valid_from::text,'valid_until',owner.valid_until::text,'public_key_digest',owner.public_key_digest::text,'row_version',owner.row_version::text) ORDER BY owner.credential_id),'[]'::jsonb) INTO expected
   FROM control.credential owner WHERE owner.participant_id=NEW.participant_id AND owner.credential_id IN
    (SELECT (dependency->>'credential_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'credential') dependency);
  IF snapshot->'dependencies'->'credential' IS DISTINCT FROM expected  THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'delegation') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('delegation_id',owner.delegation_id::text,'participant_id',owner.participant_id::text,'parent_assignment_id',owner.parent_assignment_id::text,'parent_delegation_id',owner.parent_delegation_id::text,'grantor_principal_id',owner.grantor_principal_id::text,'delegate_principal_id',owner.delegate_principal_id::text,'delegation_epoch',owner.delegation_epoch::text,'scope_digest',owner.scope_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'runtime_capability_ids',owner.runtime_capability_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'valid_during',owner.valid_during::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.delegation_id),'[]'::jsonb) INTO expected
   FROM control.delegation owner WHERE owner.participant_id=NEW.participant_id AND owner.delegation_id IN
    (SELECT (dependency->>'delegation_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'delegation') dependency);
  IF snapshot->'dependencies'->'delegation' IS DISTINCT FROM expected  THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'participant') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('participant_id',owner.participant_id::text,'state',owner.state::text,'authority_epoch',owner.authority_epoch::text,'row_version',owner.row_version::text) ORDER BY owner.participant_id),'[]'::jsonb) INTO expected
   FROM control.participant owner WHERE owner.participant_id=NEW.participant_id AND owner.participant_id IN
    (SELECT (dependency->>'participant_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'participant') dependency);
  IF snapshot->'dependencies'->'participant' IS DISTINCT FROM expected  THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'principal') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('principal_id',owner.principal_id::text,'participant_id',owner.participant_id::text,'kind',owner.kind::text,'state',owner.state::text,'authority_epoch',owner.authority_epoch::text,'row_version',owner.row_version::text) ORDER BY owner.principal_id),'[]'::jsonb) INTO expected
   FROM control.principal owner WHERE owner.participant_id=NEW.participant_id AND owner.principal_id IN
    (SELECT (dependency->>'principal_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'principal') dependency);
  IF snapshot->'dependencies'->'principal' IS DISTINCT FROM expected  THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'privacy_domain') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('privacy_domain_id',owner.privacy_domain_id::text,'participant_id',owner.participant_id::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.privacy_domain_id),'[]'::jsonb) INTO expected
   FROM control.privacy_domain owner WHERE owner.participant_id=NEW.participant_id AND owner.privacy_domain_id IN
    (SELECT (dependency->>'privacy_domain_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'privacy_domain') dependency);
  IF snapshot->'dependencies'->'privacy_domain' IS DISTINCT FROM expected  THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;

  IF jsonb_typeof(snapshot->'dependencies'->'session') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('session_id',owner.session_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'state',owner.state::text,'participant_epoch',owner.participant_epoch::text,'authority_epoch',owner.authority_epoch::text,'delegation_epoch',owner.delegation_epoch::text,'session_epoch',owner.session_epoch::text,'issued_at',owner.issued_at::text,'idle_expires_at',owner.idle_expires_at::text,'absolute_expires_at',owner.absolute_expires_at::text,'step_up_verified_at',owner.step_up_verified_at::text,'row_version',owner.row_version::text) ORDER BY owner.session_id),'[]'::jsonb) INTO expected
   FROM control.session owner WHERE owner.participant_id=NEW.participant_id AND owner.session_id IN
    (SELECT (dependency->>'session_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'session') dependency);
  IF snapshot->'dependencies'->'session' IS DISTINCT FROM expected AND NOT (
    NEW.aggregate_type='signing-key-rotation'
    AND jsonb_array_length(snapshot->'dependencies'->'session')=jsonb_array_length(expected)
    AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot->'dependencies'->'session') retained
      WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(expected) current_row
       WHERE (retained-'idle_expires_at')=(current_row-'idle_expires_at')
        AND (retained->>'idle_expires_at')::timestamptz<=(current_row->>'idle_expires_at')::timestamptz
        AND (extract(epoch FROM (retained->>'idle_expires_at')::timestamptz)*1000000000)>NEW.recorded_at_ns
        AND (current_row->>'idle_expires_at')::timestamptz>clock_timestamp()))
  ) THEN
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

CREATE OR REPLACE FUNCTION openpc.guard_receipt_signing_attempt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE payload jsonb; profile control.business_transition_profile%ROWTYPE;
BEGIN
 payload:=openpc.business_cbor(NEW.payload_cbor);
 SELECT * INTO STRICT profile FROM control.business_transition_profile WHERE profile_digest=NEW.profile_digest;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR
    NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id() OR
    NEW.operation_id IS DISTINCT FROM openpc.current_operation_id() OR
    profile.action_intent_id IS DISTINCT FROM openpc.current_action_intent_id() OR
    payload->'0' IS DISTINCT FROM openpc.business_uuid(NEW.attempt_id) OR
    payload->'1' IS DISTINCT FROM openpc.business_bytes(profile.schema_definition_digest) OR
    payload->>'2' IS DISTINCT FROM profile.profile_id OR payload->'3' IS DISTINCT FROM to_jsonb(profile.profile_version) OR
    payload->'4' IS DISTINCT FROM openpc.business_bytes(NEW.profile_digest) OR
    payload->'6' IS DISTINCT FROM openpc.business_uuid(NEW.participant_id) OR
    payload->'7' IS DISTINCT FROM openpc.business_uuid(NEW.privacy_domain_id) OR
    payload->'8' IS DISTINCT FROM openpc.business_uuid(NEW.operation_id) OR
    payload->>'9' IS DISTINCT FROM profile.action_intent_id OR payload->>'10' IS DISTINCT FROM profile.catalog_operation_id OR
    payload->>'11' IS DISTINCT FROM profile.aggregate_type OR
    payload->>'24' IS DISTINCT FROM NEW.signer_id OR
    payload->'25' IS DISTINCT FROM openpc.business_bytes(NEW.signer_trust_digest) OR
    jsonb_typeof(payload->'23') IS DISTINCT FROM 'number' OR (payload->>'23')::numeric>NEW.reserved_at_ns OR
    NEW.reserved_at_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000 OR
    NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=NEW.participant_id
     AND i.privacy_domain_id=NEW.privacy_domain_id AND i.operation_id=NEW.operation_id AND i.terminal_state IS NULL
     AND payload->'17'=openpc.business_uuid(i.idempotency_record_id) AND payload->'16'=openpc.business_bytes(i.input_digest)
     AND i.action_intent_id=profile.action_intent_id AND i.catalog_operation_id=profile.catalog_operation_id)
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-PAYLOAD'; END IF;
 IF (NEW.reservation_kind='ORDINARY_ATOMIC' AND
     (NEW.schema_version<>1 OR profile.profile_digest NOT IN (decode('d542e56d6db3fe17fed5e5872c850fd4c9a8115077e75941fd477b78729a7b26','hex'),decode('946fcea402d8a83d11bbc68f962729bbafcab59d70bb9c0184da7441f904ea0d','hex'),decode('0153b58a620f9c81e27622a714add5a155ae443b9d18d43e4aaacc2a3c6ca2a9','hex'),decode('0531ef64f2f4aee45bd8ca4d07baaef7ee40b6fceeee117c3797e70118ba218a','hex'),decode('dd31b618e1b8df721fcc23a39214b4731b7fbb18bee13e00902a7abe6e06902b','hex'),decode('c619642e3beda311a511be6d44ad26ead0cdae68e692e883a4a7ac3e63741a55','hex'),decode('fe1906fe240af7e54d5900905af784cac684f6543589d54c0b8cf952d0437445','hex'),decode('fe27d7409b2442ba50a24f46697d8d3e6cef75df2251eceb7ceaa672519f6817','hex'),decode('5ce4897d55b58c268e0fe074eaf583fe7474f5003ae35259128eecd4cae64d44','hex'),decode('d1a1871de2c1f4a2384cc084eb65523ce39c15b968c413e0578c66e177482348','hex'),decode('c5e4dddece0f5e1132cc2df0bcaad338b5e12a7021589f62f292e2962503b672','hex'),decode('47f934877eef5446cf1879d06842209e6512174274d39810ef832c2982a7c938','hex'),decode('0d9012e193c3610a6923cb050b8391b4d697785ff8ec2161ea475d04482940a5','hex'),decode('ea3c533260127e981fe6101d8694c317e37bc8d0d6a7de649af802f4ed9ccd34','hex'),decode('2d087de15c84a6516407ee619cc3f68273916cd9f1cbf86ce16104b452626c5c','hex'),decode('8004afb64e5469e566d7e30fff676124c769732356d7d315ebb115fb73617244','hex'),decode('b976628ecb1267a9dc37bb00aa2e3eaf2ff4651110d88a0964fccd283440dbdc','hex'),decode('303fcd4983bb2c1cac3786bc515a8c864e3dd8e69db32c1913a506674fc266af','hex'),decode('707a618dc0195f8d42560646a148fa6d86cc9194ab64aa2859f7c0e255a71981','hex'),decode('50311f1a2bfc10ca1950ee49d3f432d2ac42310c23104a6f13b8ffd89bfa3979','hex'),decode('7e5b8098c114e840c4f7ece48830ddd7a1201941f54409d14d6b9b97cb04c2f5','hex'),decode('f781ba69e6bc55e070c11e44105508be530a1c32cf6a486474a0baf58e113bac','hex'),decode('a36ada5edf71d8aeb88ce00182e9beb71da3774efcb34b9e793094cf4bdd1b78','hex'),decode('938120e0cd02b01e01632058ca7d73fe2acc07d13f3184c10812597a6ec66d60','hex'),decode('638dfaa2fde289bfd2be4996c59be041c64beb04a2cc52dfc08fa5286f4b6ceb','hex'),decode('d1f1c8ccfbd049063197e8511e1b0604888963b29cc40fec7ca8e72f539d85c5','hex'),decode('c7dd85f469fd74d8f750c1c04d037f5d809696d64eac91175e5c20eb16030016','hex'),decode('c17924c198e473950f12495e87b38676217114aff67408b332aee96fc618fe51','hex'),decode('f9b51989335315afc016422d711f639dfd3ae0dcbb86498f9170ebe1e2a59875','hex'),decode('1061d0df60e81533f20a776034df61d3325446fd9ba5024f607d1852c736f351','hex'),decode('66b61e0cf06a4c986d6d7935122840e6ae1daea4d6ad0ef228d497a18011b720','hex'),decode('32eb97df80806f25376f657606b0bce8f2434156f6ef45764622111e6e875b5d','hex'),decode('f909db987a850e8bae75825af7fb3420adbac6af2ee3a0a07a04379d225c238f','hex'),decode('1750d142c98240306871e641587a6dddf68586fd377c7b3010a18c3c0b59a3ce','hex')))) OR
    (NEW.reservation_kind='LIFECYCLE_DURABLE' AND (NEW.schema_version<>2 OR profile.aggregate_type<>'signing-key-rotation')) THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-OWNER'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.business_signing_selection s
  JOIN control.business_signing_key k USING(participant_id,privacy_domain_id,signer_id)
  JOIN control.business_signing_key_state ks USING(participant_id,privacy_domain_id,signer_id)
  WHERE s.participant_id=NEW.participant_id AND s.privacy_domain_id=NEW.privacy_domain_id
   AND s.environment_id=payload->>'5' AND s.profile_digest=NEW.profile_digest AND s.signer_id=NEW.signer_id
   AND s.row_version=NEW.selection_version AND s.admission_version=NEW.admission_version AND s.fence_generation=NEW.fence_generation
   AND s.fenced_operation_id IS NULL
   AND k.trust_digest=NEW.signer_trust_digest AND k.key_epoch=NEW.key_epoch AND ks.state='ACTIVE'
   AND k.valid_from_ns<=(payload->>'23')::numeric AND k.valid_until_ns>NEW.reserved_at_ns
   FOR SHARE OF s,ks) THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-FENCE'; END IF;
 IF NOT openpc.signing_admission_open(NEW.participant_id,NEW.privacy_domain_id,NEW.signer_id,NEW.operation_id)
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-UNRESOLVED-ADMISSION'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS receipt_signing_attempt_typed ON control.receipt_signing_attempt;
CREATE TRIGGER receipt_signing_attempt_typed BEFORE INSERT ON control.receipt_signing_attempt
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_receipt_signing_attempt();
CREATE OR REPLACE FUNCTION openpc.check_receipt_signing_attempt_completion()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.reservation_kind='ORDINARY_ATOMIC' THEN
  IF NOT EXISTS(SELECT 1 FROM control.audit_occurrence r WHERE r.participant_id=NEW.participant_id
   AND r.privacy_domain_id=NEW.privacy_domain_id AND r.operation_id=NEW.operation_id
   AND r.receipt_id=NEW.attempt_id AND r.receipt_cbor=NEW.payload_cbor AND r.receipt_digest=NEW.payload_digest)
  THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-ATOMIC-SIGNING-ATTEMPT'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM control.signing_rotation_attestation a JOIN control.signing_provider_attempt p USING(attempt_id)
   WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id
    AND a.operation_id=NEW.operation_id AND a.attempt_id=NEW.attempt_id AND a.receipt_cbor=NEW.payload_cbor
    AND a.signer_id=NEW.signer_id AND a.signer_trust_digest=NEW.signer_trust_digest
    AND a.selection_version=NEW.selection_version AND p.request->>'method'='SIGN_RECEIPT'
    AND p.request->>'payloadHex'=encode(NEW.payload_cbor,'hex') AND p.request->>'attemptId'=NEW.attempt_id::text)
  THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-LIFECYCLE-SIGNING-ATTEMPT'; END IF;
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS receipt_signing_attempt_complete ON control.receipt_signing_attempt;
CREATE CONSTRAINT TRIGGER receipt_signing_attempt_complete AFTER INSERT ON control.receipt_signing_attempt
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_receipt_signing_attempt_completion();
CREATE OR REPLACE FUNCTION openpc.guard_receipt_attempt_reference()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.receipt_signing_attempt a WHERE a.participant_id=NEW.participant_id
  AND a.privacy_domain_id=NEW.privacy_domain_id AND a.operation_id=NEW.operation_id AND a.attempt_id=NEW.receipt_id
  AND a.payload_cbor=NEW.receipt_cbor AND a.payload_digest=NEW.receipt_digest AND a.signer_id=NEW.signer_id
  AND a.signer_trust_digest=NEW.signer_trust_snapshot_digest AND a.profile_digest=NEW.profile_digest)
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-SIGNING-ATTEMPT-REQUIRED'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS receipt_attempt_reference ON control.audit_occurrence;
CREATE TRIGGER receipt_attempt_reference BEFORE INSERT ON control.audit_occurrence
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_receipt_attempt_reference();

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
DROP TRIGGER IF EXISTS receipt_signing_attempt_immutable ON control.receipt_signing_attempt;
CREATE TRIGGER receipt_signing_attempt_immutable BEFORE UPDATE OR DELETE ON control.receipt_signing_attempt FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS signing_rotation_attestation_immutable ON control.signing_rotation_attestation;
CREATE TRIGGER signing_rotation_attestation_immutable BEFORE UPDATE OR DELETE ON control.signing_rotation_attestation FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS signing_rotation_observation_immutable ON control.signing_rotation_observation;
CREATE TRIGGER signing_rotation_observation_immutable BEFORE UPDATE OR DELETE ON control.signing_rotation_observation FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();

CREATE OR REPLACE FUNCTION openpc.assignment_role_permits(owner_id uuid, role_ref text, action_id text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT role_ref IS NULL OR EXISTS (
  SELECT 1 FROM control.authority_role role WHERE role.participant_id=owner_id
   AND role.role_id=role_ref AND role.state='ACTIVE' AND action_id=ANY(role.action_intent_ids))
$$;

CREATE OR REPLACE FUNCTION openpc.guard_authority_role()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-ROLE-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'creator_participant_id'-'state'-'row_version'-'updated_at') IS DISTINCT FROM
     (to_jsonb(OLD)-'creator_participant_id'-'state'-'row_version'-'updated_at') OR
     OLD.state<>'ACTIVE' OR NEW.state<>'ARCHIVED' OR NEW.row_version<>OLD.row_version+1 OR
     EXISTS(SELECT 1 FROM control.assignment a WHERE a.participant_id=NEW.participant_id
       AND a.role_id=NEW.role_id AND a.state IN ('ACTIVE','SUSPENDED')) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-ROLE-TRANSITION';
  END IF;
 ELSIF NEW.state<>'ACTIVE' OR EXISTS(
   SELECT 1 FROM unnest(NEW.action_intent_ids) capability
    WHERE NOT EXISTS (SELECT 1 FROM control.action_intent registered WHERE registered.action_intent_id=capability)
 ) THEN RAISE EXCEPTION 'PC-IDENTITY-1002-ROLE-CAPABILITY';
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_assignment_role()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE role_row control.authority_role%ROWTYPE;
BEGIN
 IF NEW.role_id IS NULL OR NEW.state NOT IN ('ACTIVE','SUSPENDED') THEN RETURN NEW; END IF;
 SELECT * INTO role_row FROM control.authority_role role
  WHERE role.participant_id=NEW.participant_id AND role.role_id=NEW.role_id FOR SHARE;
 IF NOT FOUND OR role_row.state<>'ACTIVE' OR NOT NEW.action_intent_ids <@ role_row.action_intent_ids THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-ASSIGNMENT-ROLE';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authority_role_lifecycle ON control.authority_role;
CREATE TRIGGER authority_role_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.authority_role
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_authority_role();
DROP TRIGGER IF EXISTS assignment_role_bound ON control.assignment;
CREATE TRIGGER assignment_role_bound BEFORE INSERT OR UPDATE ON control.assignment
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_assignment_role();


CREATE OR REPLACE FUNCTION openpc.directory_group_permits(owner_id uuid, group_ref uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT NOT EXISTS (SELECT FROM control.directory_group_mapping WHERE participant_id=owner_id AND authority_group_id=group_ref)
 OR EXISTS (SELECT FROM control.directory_group_mapping m JOIN control.directory_connector c ON c.participant_id=m.participant_id AND c.connector_id=m.connector_id
 WHERE m.participant_id=owner_id AND m.authority_group_id=group_ref AND c.state='ACTIVE' AND c.profile_digest=m.profile_digest
 AND m.observed_at<=clock_timestamp() AND least(m.fresh_until,m.observed_at+make_interval(secs=>c.external_group_freshness_seconds))>clock_timestamp())
$$;
CREATE OR REPLACE FUNCTION openpc.guard_directory_group_mapping()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-GROUP-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'provider_version'-'provider_modified_at'-'source_digest'-'source_member_ids'-'observed_at'-'fresh_until'-'row_version'-'last_mutation_operation_id'-'updated_at') IS DISTINCT FROM
     (to_jsonb(OLD)-'provider_version'-'provider_modified_at'-'source_digest'-'source_member_ids'-'observed_at'-'fresh_until'-'row_version'-'last_mutation_operation_id'-'updated_at') OR
     NEW.row_version<>OLD.row_version+1 OR NEW.observed_at<OLD.observed_at OR NEW.provider_modified_at<OLD.provider_modified_at OR
     (NEW.provider_version=OLD.provider_version AND NEW.source_digest<>OLD.source_digest) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-GROUP-TRANSITION';
  END IF;
 ELSE
  IF NEW.row_version<>1 OR EXISTS (SELECT FROM control.authority_group_member WHERE participant_id=NEW.participant_id AND authority_group_id=NEW.authority_group_id AND state IN ('ACTIVE','SUSPENDED'))
   OR EXISTS (SELECT FROM control.assignment WHERE participant_id=NEW.participant_id AND authority_group_id=NEW.authority_group_id AND state IN ('ACTIVE','SUSPENDED')) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-GROUP-INITIAL-STATE';
  END IF;
 END IF;
 IF NEW.observed_at>clock_timestamp() OR NEW.provider_modified_at>clock_timestamp() OR
  (SELECT count(DISTINCT value) FROM unnest(NEW.source_member_ids) value)<>cardinality(NEW.source_member_ids) OR
  NOT EXISTS (SELECT FROM control.directory_connector c JOIN control.authority_group g ON g.participant_id=c.participant_id
    WHERE c.participant_id=NEW.participant_id AND c.connector_id=NEW.connector_id AND c.state='ACTIVE' AND c.profile_digest=NEW.profile_digest
      AND g.authority_group_id=NEW.authority_group_id AND g.state='ACTIVE'
      AND NEW.fresh_until=NEW.observed_at+make_interval(secs=>c.external_group_freshness_seconds)
      AND NEW.observed_at>=clock_timestamp()-make_interval(secs=>least(300,c.external_group_freshness_seconds))) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-GROUP-SOURCE';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_directory_group_member()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF EXISTS (SELECT FROM control.directory_group_mapping WHERE participant_id=NEW.participant_id AND authority_group_id=NEW.authority_group_id) AND
  NOT EXISTS (SELECT FROM control.directory_group_mapping g JOIN control.directory_member m ON m.participant_id=g.participant_id AND m.connector_id=g.connector_id
   WHERE g.participant_id=NEW.participant_id AND g.authority_group_id=NEW.authority_group_id AND m.principal_id=NEW.principal_id AND m.state='LINKED'
    AND m.external_id=ANY(g.source_member_ids) AND openpc.directory_group_permits(g.participant_id,g.authority_group_id)) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-GROUP-MEMBER';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.invalidate_directory_group_context()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF ((OLD.state='ACTIVE' AND NEW.state<>'ACTIVE') OR NEW.external_group_freshness_seconds<OLD.external_group_freshness_seconds)
  AND EXISTS (SELECT FROM control.directory_group_mapping g JOIN control.assignment a ON a.participant_id=g.participant_id AND a.authority_group_id=g.authority_group_id
    WHERE g.participant_id=NEW.participant_id AND g.connector_id=NEW.connector_id AND a.state IN ('ACTIVE','SUSPENDED')) THEN
  UPDATE control.participant SET authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() WHERE participant_id=NEW.participant_id;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS directory_group_lifecycle ON control.directory_group_mapping;
CREATE TRIGGER directory_group_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.directory_group_mapping FOR EACH ROW EXECUTE FUNCTION openpc.guard_directory_group_mapping();
DROP TRIGGER IF EXISTS directory_group_member_bound ON control.authority_group_member;
CREATE TRIGGER directory_group_member_bound BEFORE INSERT ON control.authority_group_member FOR EACH ROW EXECUTE FUNCTION openpc.guard_directory_group_member();
DROP TRIGGER IF EXISTS directory_group_context_invalidated ON control.directory_connector;
CREATE TRIGGER directory_group_context_invalidated AFTER UPDATE ON control.directory_connector FOR EACH ROW EXECUTE FUNCTION openpc.invalidate_directory_group_context();


CREATE OR REPLACE FUNCTION openpc.assignment_group_permits(owner_id uuid, group_ref uuid, principal_ref uuid, grant_validity tstzrange)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT group_ref IS NULL OR EXISTS (
  SELECT 1 FROM control.authority_group g
   JOIN control.authority_group_member m ON m.participant_id=g.participant_id AND m.authority_group_id=g.authority_group_id
   JOIN control.participant_membership binding ON binding.participant_id=m.participant_id AND binding.membership_id=m.principal_id
   JOIN control.principal p ON p.participant_id=m.participant_id AND p.principal_id=m.principal_id
  WHERE g.participant_id=owner_id AND g.authority_group_id=group_ref AND g.state='ACTIVE'
   AND m.principal_id=principal_ref AND m.state='ACTIVE' AND m.valid_during @> clock_timestamp()
   AND grant_validity <@ m.valid_during AND p.state='ACTIVE' AND p.kind IN ('USER','PLATFORM_OPERATOR')
   AND openpc.directory_group_permits(owner_id,group_ref))
$$;
CREATE OR REPLACE FUNCTION openpc.guard_authority_group()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'group_name'-'state'-'row_version'-'updated_at'-'last_mutation_operation_id') IS DISTINCT FROM
     (to_jsonb(OLD)-'group_name'-'state'-'row_version'-'updated_at'-'last_mutation_operation_id') OR
     OLD.state<>'ACTIVE' OR NEW.state NOT IN ('ACTIVE','RETIRED') OR NEW.row_version<>OLD.row_version+1 THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-TRANSITION';
  END IF;
  IF NEW.state='RETIRED' AND (EXISTS(SELECT FROM control.authority_group_member m WHERE m.participant_id=NEW.participant_id AND m.authority_group_id=NEW.authority_group_id AND m.state IN ('ACTIVE','SUSPENDED'))
    OR EXISTS(SELECT FROM control.assignment a WHERE a.participant_id=NEW.participant_id AND a.authority_group_id=NEW.authority_group_id AND a.state IN ('ACTIVE','SUSPENDED'))) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-DEPENDENTS';
  END IF;
 ELSIF NEW.state<>'ACTIVE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-STATE';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_authority_group_member()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-MEMBER-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'state'-'revoked_at') IS DISTINCT FROM (to_jsonb(OLD)-'state'-'revoked_at') OR
     OLD.state IN ('REVOKED','EXPIRED','RETIRED') OR NEW.state NOT IN ('REVOKED','EXPIRED') OR NEW.revoked_at IS NULL THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-MEMBER-TRANSITION';
  END IF;
 ELSE
  IF NEW.state<>'ACTIVE' OR NEW.revoked_at IS NOT NULL OR isempty(NEW.valid_during) OR lower_inf(NEW.valid_during) OR NOT lower_inc(NEW.valid_during) OR upper_inc(NEW.valid_during)
    OR NOT EXISTS (SELECT FROM control.authority_group g WHERE g.participant_id=NEW.participant_id AND g.authority_group_id=NEW.authority_group_id AND g.state='ACTIVE')
    OR NOT EXISTS (SELECT FROM control.principal p JOIN control.participant_membership m ON m.participant_id=p.participant_id AND m.membership_id=p.principal_id
      WHERE p.participant_id=NEW.participant_id AND p.principal_id=NEW.principal_id AND p.state='ACTIVE' AND p.kind IN ('USER','PLATFORM_OPERATOR')) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-MEMBER-SCOPE';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_assignment_group()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.authority_group_id IS NULL OR NEW.state NOT IN ('ACTIVE','SUSPENDED') THEN RETURN NEW; END IF;
 IF NOT EXISTS (SELECT FROM control.authority_group g JOIN control.authority_group_member m
    ON m.participant_id=g.participant_id AND m.authority_group_id=g.authority_group_id
    JOIN control.participant_membership binding ON binding.participant_id=m.participant_id AND binding.membership_id=m.principal_id
    JOIN control.principal p ON p.participant_id=m.participant_id AND p.principal_id=m.principal_id
    WHERE g.participant_id=NEW.participant_id AND g.authority_group_id=NEW.authority_group_id AND g.state='ACTIVE'
      AND m.principal_id=NEW.principal_id AND m.state='ACTIVE' AND NEW.valid_during <@ m.valid_during
      AND p.state='ACTIVE' AND p.kind IN ('USER','PLATFORM_OPERATOR')
      AND openpc.directory_group_permits(NEW.participant_id,NEW.authority_group_id)) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-ASSIGNMENT-GROUP';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authority_group_lifecycle ON control.authority_group;
CREATE TRIGGER authority_group_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.authority_group FOR EACH ROW EXECUTE FUNCTION openpc.guard_authority_group();
DROP TRIGGER IF EXISTS authority_group_member_lifecycle ON control.authority_group_member;
CREATE TRIGGER authority_group_member_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.authority_group_member FOR EACH ROW EXECUTE FUNCTION openpc.guard_authority_group_member();
DROP TRIGGER IF EXISTS assignment_group_bound ON control.assignment;
CREATE TRIGGER assignment_group_bound BEFORE INSERT OR UPDATE ON control.assignment FOR EACH ROW EXECUTE FUNCTION openpc.guard_assignment_group();


CREATE OR REPLACE FUNCTION openpc.guard_directory_connector()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'display_name'-'state'-'mass_change_threshold'-'external_group_freshness_seconds'-'row_version'-'updated_at'-'last_mutation_operation_id') IS DISTINCT FROM
     (to_jsonb(OLD)-'display_name'-'state'-'mass_change_threshold'-'external_group_freshness_seconds'-'row_version'-'updated_at'-'last_mutation_operation_id') OR
     OLD.state='RETIRED' OR NEW.row_version<>OLD.row_version+1 THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-TRANSITION';
  END IF;
 ELSIF NEW.state<>'ACTIVE' OR NEW.row_version<>1 THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-INITIAL-STATE';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_directory_member()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-MEMBER-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'state'-'provider_version'-'provider_modified_at'-'observed_at'-'source_digest'-'row_version'-'updated_at'-'last_mutation_operation_id') IS DISTINCT FROM
     (to_jsonb(OLD)-'state'-'provider_version'-'provider_modified_at'-'observed_at'-'source_digest'-'row_version'-'updated_at'-'last_mutation_operation_id') OR
     OLD.state='OFFBOARDED' OR NEW.row_version<>OLD.row_version+1 OR NEW.provider_modified_at<OLD.provider_modified_at OR NEW.observed_at<OLD.observed_at OR
     (NEW.provider_version=OLD.provider_version AND NEW.source_digest<>OLD.source_digest) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-MEMBER-TRANSITION';
  END IF;
 ELSIF NEW.state<>'LINKED' OR NEW.row_version<>1 THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-MEMBER-INITIAL-STATE';
 END IF;
 IF NOT EXISTS (SELECT FROM control.principal p JOIN control.participant_membership m ON m.participant_id=p.participant_id AND m.membership_id=p.principal_id
    JOIN control.credential c ON c.participant_id=p.participant_id AND c.principal_id=p.principal_id
    WHERE p.participant_id=NEW.participant_id AND p.principal_id=NEW.principal_id AND p.kind='USER' AND c.credential_id=NEW.oidc_credential_id AND c.kind='OIDC_SUBJECT') THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-MEMBER-BINDING';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS directory_connector_lifecycle ON control.directory_connector;
CREATE TRIGGER directory_connector_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.directory_connector FOR EACH ROW EXECUTE FUNCTION openpc.guard_directory_connector();
DROP TRIGGER IF EXISTS directory_member_lifecycle ON control.directory_member;
CREATE TRIGGER directory_member_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.directory_member FOR EACH ROW EXECUTE FUNCTION openpc.guard_directory_member();


CREATE OR REPLACE FUNCTION openpc.guard_invitation_oidc_custody()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.purpose IS DISTINCT FROM OLD.purpose OR
  (OLD.purpose='INVITATION' AND
   ((to_jsonb(NEW)-'consumed_at') IS DISTINCT FROM (to_jsonb(OLD)-'consumed_at') OR
    OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL OR NEW.consumed_at>=OLD.expires_at)) THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS invitation_oidc_custody ON control.oidc_transaction;
CREATE TRIGGER invitation_oidc_custody BEFORE UPDATE ON control.oidc_transaction
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_invitation_oidc_custody();
DROP TRIGGER IF EXISTS invitation_token_immutable ON control.participant_invitation_token;
CREATE TRIGGER invitation_token_immutable BEFORE UPDATE OR DELETE ON control.participant_invitation_token
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE OR REPLACE FUNCTION openpc.guard_participant_invitation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-INVITATION-TOMBSTONE'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PENDING' OR NEW.row_version<>1 OR NEW.token_version<>1 THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-INVITATION-INITIAL';
  END IF;
 ELSE
  IF OLD.state<>'PENDING' OR NEW.row_version<>OLD.row_version+1 OR
     NEW.last_mutation_operation_id=OLD.last_mutation_operation_id OR
     (to_jsonb(NEW)-'creator_participant_id'-'state'-'token_version'-'expires_at'-'row_version'-'updated_at'-'last_mutation_operation_id') IS DISTINCT FROM
     (to_jsonb(OLD)-'creator_participant_id'-'state'-'token_version'-'expires_at'-'row_version'-'updated_at'-'last_mutation_operation_id') OR
     NOT ((NEW.state='PENDING' AND NEW.token_version=OLD.token_version+1 AND NEW.expires_at>clock_timestamp()) OR
          (NEW.state='REVOKED' AND NEW.token_version=OLD.token_version AND NEW.expires_at=OLD.expires_at) OR
          (NEW.state='ACCEPTED' AND NEW.token_version=OLD.token_version AND NEW.expires_at=OLD.expires_at AND OLD.expires_at>clock_timestamp())) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-INVITATION-TRANSITION';
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS participant_invitation_lifecycle ON control.participant_invitation;
CREATE TRIGGER participant_invitation_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.participant_invitation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_invitation();
CREATE OR REPLACE FUNCTION openpc.guard_invitation_token()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 -- Pre-upgrade expired history can retain missing provenance, but can never be
 -- revived: token history is immutable and renewal inserts a new governed version.
 IF NEW.issuance_authority IS NULL AND NEW.expires_at>clock_timestamp() AND NOT EXISTS (
  SELECT 1 FROM control.participant_bootstrap_custody custody WHERE custody.participant_id=NEW.participant_id
    AND custody.invitation_id=NEW.invitation_id AND custody.state='ACTIVE' AND custody.custody_generation=NEW.token_version
    AND custody.expires_at=NEW.expires_at AND ((NEW.token_version=1 AND custody.created_operation_id=NEW.operation_id
      AND custody.candidate->>'tokenDigest'='sha256:'||encode(NEW.token_digest,'hex')) OR NEW.token_version>1)) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1005-INVITATION-ISSUANCE-AUTHORITY';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM control.participant_invitation invitation
   WHERE invitation.participant_id=NEW.participant_id AND invitation.privacy_domain_id=NEW.privacy_domain_id
     AND invitation.invitation_id=NEW.invitation_id AND invitation.state='PENDING'
     AND invitation.token_version=NEW.token_version AND invitation.expires_at=NEW.expires_at
     AND invitation.last_mutation_operation_id=NEW.operation_id) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-INVITATION-TOKEN';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS invitation_token_binding ON control.participant_invitation_token;
CREATE TRIGGER invitation_token_binding BEFORE INSERT ON control.participant_invitation_token
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_invitation_token();
CREATE OR REPLACE FUNCTION openpc.require_invitation_current_token()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM control.participant_invitation invitation
   JOIN control.participant_invitation_token token
    ON token.participant_id=invitation.participant_id AND token.privacy_domain_id=invitation.privacy_domain_id
     AND token.invitation_id=invitation.invitation_id AND token.token_version=invitation.token_version
     AND token.expires_at=invitation.expires_at
   WHERE invitation.participant_id=NEW.participant_id AND invitation.privacy_domain_id=NEW.privacy_domain_id
    AND invitation.invitation_id=NEW.invitation_id) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-INVITATION-CURRENT-TOKEN';
 END IF;
 IF EXISTS (SELECT 1 FROM control.participant_invitation invitation WHERE invitation.invitation_id=NEW.invitation_id AND invitation.state='ACCEPTED'
   AND NOT EXISTS (SELECT 1 FROM control.participant_invitation_acceptance acceptance
    WHERE acceptance.participant_id=invitation.participant_id AND acceptance.privacy_domain_id=invitation.privacy_domain_id
      AND acceptance.invitation_id=invitation.invitation_id AND acceptance.token_version=invitation.token_version
      AND (acceptance.operation_id=invitation.last_mutation_operation_id OR EXISTS (
        SELECT 1 FROM control.participant_bootstrap_custody custody WHERE custody.participant_id=invitation.participant_id
          AND custody.invitation_id=invitation.invitation_id AND custody.mandate_id=invitation.bootstrap_mandate_id
          AND custody.state='ACCEPTED' AND custody.accepted_membership_id=acceptance.membership_id
          AND custody.accepted_operation_id=invitation.last_mutation_operation_id)))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS invitation_current_token ON control.participant_invitation;
CREATE CONSTRAINT TRIGGER invitation_current_token AFTER INSERT OR UPDATE ON control.participant_invitation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_invitation_current_token();

CREATE OR REPLACE FUNCTION openpc.guard_invitation_proof()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM control.participant_invitation invitation
   JOIN control.participant_invitation_token token ON token.invitation_id=invitation.invitation_id AND token.token_version=invitation.token_version
   JOIN control.oidc_transaction oidc ON oidc.transaction_id=NEW.transaction_id AND oidc.purpose='INVITATION'
     AND oidc.selected_participant_id=invitation.participant_id AND oidc.issuer=invitation.recipient_issuer AND oidc.client_id=invitation.recipient_audience
     AND oidc.consumed_at IS NULL AND oidc.expires_at>clock_timestamp()
   WHERE invitation.participant_id=NEW.participant_id AND invitation.privacy_domain_id=NEW.privacy_domain_id
     AND invitation.invitation_id=NEW.invitation_id AND invitation.state='PENDING' AND invitation.expires_at>clock_timestamp()
     AND token.token_version=NEW.token_version AND token.token_digest=NEW.token_digest AND (token.issuance_authority IS NOT NULL OR EXISTS (
       SELECT 1 FROM control.participant_bootstrap_custody custody WHERE custody.participant_id=invitation.participant_id AND custody.invitation_id=invitation.invitation_id
         AND custody.mandate_id=invitation.bootstrap_mandate_id AND custody.state='ACTIVE' AND custody.expires_at>clock_timestamp()))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS invitation_proof_binding ON control.participant_invitation_proof;
CREATE TRIGGER invitation_proof_binding BEFORE INSERT ON control.participant_invitation_proof FOR EACH ROW EXECUTE FUNCTION openpc.guard_invitation_proof();
DROP TRIGGER IF EXISTS invitation_proof_immutable ON control.participant_invitation_proof;
CREATE TRIGGER invitation_proof_immutable BEFORE UPDATE OR DELETE ON control.participant_invitation_proof FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();

CREATE OR REPLACE FUNCTION openpc.guard_invitation_acceptance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM control.participant_invitation invitation
   JOIN control.participant_invitation_proof proof ON proof.invitation_id=invitation.invitation_id AND proof.token_version=invitation.token_version
   JOIN control.oidc_transaction oidc ON oidc.transaction_id=proof.transaction_id AND oidc.purpose='INVITATION' AND oidc.consumed_at IS NOT NULL
   JOIN control.participant_membership membership ON membership.participant_id=invitation.participant_id AND membership.membership_id=NEW.membership_id AND membership.identity_subject_id=NEW.identity_subject_id
   WHERE invitation.participant_id=NEW.participant_id AND invitation.privacy_domain_id=NEW.privacy_domain_id AND invitation.invitation_id=NEW.invitation_id
     AND invitation.token_version=NEW.token_version AND ((invitation.state='ACCEPTED' AND invitation.last_mutation_operation_id=NEW.operation_id) OR
       (invitation.state='PENDING' AND EXISTS (SELECT 1 FROM control.participant_bootstrap_custody custody
         WHERE custody.participant_id=invitation.participant_id AND custody.invitation_id=invitation.invitation_id
           AND custody.mandate_id=invitation.bootstrap_mandate_id AND custody.state='CLAIM_PENDING' AND custody.candidate_membership_id=NEW.membership_id)))
     AND proof.participant_id=NEW.participant_id AND proof.privacy_domain_id=NEW.privacy_domain_id AND proof.transaction_id=NEW.proof_transaction_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS invitation_acceptance_binding ON control.participant_invitation_acceptance;
CREATE TRIGGER invitation_acceptance_binding BEFORE INSERT ON control.participant_invitation_acceptance FOR EACH ROW EXECUTE FUNCTION openpc.guard_invitation_acceptance();
DROP TRIGGER IF EXISTS invitation_acceptance_immutable ON control.participant_invitation_acceptance;
CREATE TRIGGER invitation_acceptance_immutable BEFORE UPDATE OR DELETE ON control.participant_invitation_acceptance FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();

CREATE OR REPLACE FUNCTION openpc.require_invitation_acceptance_evidence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM control.mutation_evidence evidence
   JOIN control.participant_invitation invitation ON invitation.invitation_id=NEW.invitation_id
   JOIN control.outbox_event event ON event.participant_id=evidence.participant_id AND event.privacy_domain_id=evidence.privacy_domain_id
    AND event.aggregate_type='invitation-redemption' AND event.aggregate_id=NEW.invitation_id
    AND event.event_type='openpc.identity.invitation.accepted.v1'
    AND event.payload_cbor=NEW.evidence_cbor AND event.payload_digest=NEW.evidence_digest AND event.cose_sign1=NEW.cose_sign1
   WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
    AND evidence.operation_id=NEW.operation_id AND evidence.principal_id=NEW.membership_id
    AND evidence.action_intent_id='ACT-PARTICIPANT_CREATE_MEMBER-V1' AND evidence.catalog_operation_id='ID-OP-INVITATION-ACCEPT'
    AND evidence.aggregate_type='invitation-redemption' AND evidence.aggregate_id=NEW.invitation_id
    AND evidence.aggregate_version=invitation.row_version-CASE WHEN invitation.bootstrap_mandate_id IS NULL THEN 1 ELSE 0 END
    AND evidence.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(NEW.result),'UTF8'))
    AND evidence.evidence_role='IDENTITY_PROOF_INPUT' AND evidence.evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
    AND evidence.evidence_cbor=NEW.evidence_cbor AND evidence.evidence_digest=NEW.evidence_digest AND evidence.cose_sign1=NEW.cose_sign1) THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS invitation_acceptance_evidence ON control.participant_invitation_acceptance;
CREATE CONSTRAINT TRIGGER invitation_acceptance_evidence AFTER INSERT ON control.participant_invitation_acceptance
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_invitation_acceptance_evidence();


CREATE OR REPLACE FUNCTION openpc.require_bootstrap_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE original_mode text:=current_setting('openpc.context_mode');
 original_participant uuid:=nullif(current_setting('openpc.participant_id'),'')::uuid;
 original_privacy uuid:=nullif(current_setting('openpc.privacy_domain_id'),'')::uuid;
 original_operation uuid:=current_setting('openpc.operation_id')::uuid;
 original_action text:=current_setting('openpc.action_intent_id');
 valid_source boolean; valid_target boolean;
BEGIN
 IF NEW.candidate_digest<>sha256(convert_to(openpc.signing_canonical_json(NEW.candidate),'UTF8'))
   OR NEW.configuration_digest<>sha256(convert_to(openpc.signing_canonical_json(NEW.candidate->'configuration'),'UTF8'))
   OR NEW.first_admin_invite_ttl_ms<>(NEW.candidate#>>'{configuration,participant.first_admin_invite_ttl}')::integer
   OR NEW.platform_participant_id::text IS DISTINCT FROM NEW.issuance_authority->>'participantId'
   OR NEW.maker_principal_id::text IS DISTINCT FROM NEW.issuance_authority#>>'{signers,0,principalId}'
   OR NEW.checker_principal_id::text IS DISTINCT FROM NEW.issuance_authority#>>'{signers,1,principalId}'
   OR NEW.created_operation_id::text IS DISTINCT FROM NEW.issuance_authority->>'operationId'
   OR NEW.mandate_id::text IS DISTINCT FROM NEW.candidate->>'mandateId'
   OR NEW.invitation_id::text IS DISTINCT FROM NEW.candidate->>'invitationId' THEN RAISE EXCEPTION 'PC-AUTH-0002-BOOTSTRAP-PROVENANCE'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.platform_participant_id,(NEW.issuance_authority->>'privacyDomainId')::uuid,original_operation,original_action,true);
 SELECT EXISTS(
  SELECT 1 FROM control.mutation_candidate candidate
  JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id AND evidence.privacy_domain_id=candidate.privacy_domain_id
    AND evidence.operation_id=candidate.consumed_operation_id AND evidence.candidate_digest=candidate.candidate_digest
    AND evidence.principal_id=NEW.maker_principal_id AND evidence.checker_principal_id=NEW.checker_principal_id
    AND evidence.approval_request_id=(NEW.issuance_authority->>'approvalRequestId')::uuid
  JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id AND receipt.operation_id=candidate.consumed_operation_id
    AND receipt.terminal_state='COMMITTED' AND receipt.result_payload#>>'{result,bootstrap,issuanceAuthorityDigest}'=
      'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.issuance_authority),'UTF8')),'hex')
  WHERE candidate.participant_id=NEW.platform_participant_id AND candidate.resource_id=NEW.participant_id
    AND candidate.candidate_document->>'participantId'=NEW.participant_id::text
    AND candidate.candidate_document->'firstAdministrator'=NEW.candidate
    AND candidate.candidate_digest=decode(substr(NEW.issuance_authority->>'candidateDigest',8),'hex')
    AND candidate.consumed_operation_id=NEW.created_operation_id AND candidate.state='CONSUMED'
    AND candidate.catalog_operation_id='ID-OP-PARTICIPANT-CREATE'
 ) INTO valid_source;
 IF NOT coalesce(valid_source,false) THEN
  PERFORM openpc.set_request_context(original_mode,original_participant,original_privacy,original_operation,original_action,original_privacy IS NOT NULL);
  RAISE EXCEPTION 'PC-AUTH-0002-BOOTSTRAP-SOURCE-PROVENANCE';
 END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.participant_id,(NEW.candidate->>'privacyDomainId')::uuid,original_operation,original_action,true);
 SELECT EXISTS(
  SELECT 1 FROM control.participant_invitation invitation JOIN control.authority_role role
    ON role.participant_id=invitation.participant_id AND role.authority_role_id=invitation.intended_role_id
      AND role.authority_role_id=(NEW.candidate->>'roleId')::uuid AND role.bootstrap_mandate_id=NEW.mandate_id
      AND role.bootstrap_platform_participant_id=NEW.platform_participant_id
      AND to_jsonb(role.action_intent_ids)=NEW.candidate->'actionIntentIds'
  WHERE invitation.participant_id=NEW.participant_id AND invitation.invitation_id=NEW.invitation_id
    AND invitation.bootstrap_mandate_id=NEW.mandate_id AND invitation.bootstrap_platform_participant_id=NEW.platform_participant_id
    AND invitation.privacy_domain_id=(NEW.candidate->>'privacyDomainId')::uuid
    AND invitation.recipient_issuer=NEW.candidate->>'recipientIssuer'
    AND invitation.recipient_subject=NEW.candidate->>'recipientSubject'
    AND invitation.recipient_audience=NEW.candidate->>'recipientAudience'
 ) INTO valid_target;
 PERFORM openpc.set_request_context(original_mode,original_participant,original_privacy,original_operation,original_action,original_privacy IS NOT NULL);
 IF NOT coalesce(valid_source AND valid_target,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-BOOTSTRAP-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS bootstrap_provenance ON control.participant_bootstrap_custody;
CREATE CONSTRAINT TRIGGER bootstrap_provenance AFTER INSERT OR UPDATE ON control.participant_bootstrap_custody
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_bootstrap_provenance();
CREATE OR REPLACE FUNCTION openpc.guard_bootstrap_custody()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0002'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'ACTIVE' OR NEW.participant_epoch<>0 OR NEW.custody_generation<>1 OR NEW.row_version<>1
    OR NEW.candidate_membership_id IS NOT NULL OR NEW.accepted_membership_id IS NOT NULL
    OR NOT EXISTS(SELECT 1 FROM control.participant WHERE participant_id=NEW.participant_id AND state='PROVISIONING' AND authority_epoch=0)
    OR EXISTS(SELECT 1 FROM control.principal WHERE participant_id=NEW.participant_id AND state='ACTIVE') THEN
   RAISE EXCEPTION 'PC-AUTH-0002';
  END IF;
 ELSE
  IF OLD.state NOT IN ('ACTIVE','CLAIM_PENDING') OR NEW.row_version<>OLD.row_version+1
    OR (to_jsonb(NEW)-'custody_generation'-'state'-'candidate_membership_id'-'candidate_session_id'-'accepted_membership_id'-'accepted_operation_id'-'accepted_intent_digest'-'acceptance_result'-'closed_at'-'row_version')
      IS DISTINCT FROM (to_jsonb(OLD)-'custody_generation'-'state'-'candidate_membership_id'-'candidate_session_id'-'accepted_membership_id'-'accepted_operation_id'-'accepted_intent_digest'-'acceptance_result'-'closed_at'-'row_version')
    OR NOT ((OLD.state='ACTIVE' AND NEW.state='CLAIM_PENDING' AND NEW.custody_generation=OLD.custody_generation AND NEW.candidate_membership_id IS NOT NULL AND NEW.expires_at>clock_timestamp())
      OR (OLD.state='CLAIM_PENDING' AND NEW.state='ACCEPTED' AND NEW.custody_generation=OLD.custody_generation AND NEW.candidate_membership_id=OLD.candidate_membership_id
        AND NEW.candidate_session_id=OLD.candidate_session_id AND NEW.accepted_membership_id=OLD.candidate_membership_id AND NEW.expires_at>clock_timestamp())
      OR (NEW.state='ACTIVE' AND NEW.custody_generation=OLD.custody_generation+1 AND NEW.candidate_membership_id IS NULL AND NEW.candidate_session_id IS NULL AND NEW.expires_at>clock_timestamp())
      OR (NEW.state IN ('CANCELLED','RECOVERY_REQUIRED') AND NEW.custody_generation=OLD.custody_generation AND NEW.candidate_membership_id IS NOT DISTINCT FROM OLD.candidate_membership_id AND NEW.candidate_session_id IS NOT DISTINCT FROM OLD.candidate_session_id)) THEN RAISE EXCEPTION 'PC-AUTH-0002'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS bootstrap_custody_lifecycle ON control.participant_bootstrap_custody;
CREATE TRIGGER bootstrap_custody_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.participant_bootstrap_custody
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_bootstrap_custody();

CREATE OR REPLACE FUNCTION openpc.require_bootstrap_custody_change()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE original_mode text:=current_setting('openpc.context_mode');
 original_participant uuid:=nullif(current_setting('openpc.participant_id'),'')::uuid;
 original_privacy uuid:=nullif(current_setting('openpc.privacy_domain_id'),'')::uuid;
 operation uuid:=current_setting('openpc.operation_id')::uuid;
 action text:=current_setting('openpc.action_intent_id');
 candidate_document jsonb; changed boolean:=NEW.custody_generation<>OLD.custody_generation;
BEGIN
 IF NOT changed AND NEW.state<>'CANCELLED' THEN RETURN NULL; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.platform_participant_id,(NEW.issuance_authority->>'privacyDomainId')::uuid,operation,action,true);
 SELECT candidate.candidate_document INTO candidate_document
 FROM control.mutation_candidate candidate
 JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id AND evidence.operation_id=candidate.consumed_operation_id
   AND evidence.candidate_digest=candidate.candidate_digest AND evidence.principal_id=NEW.maker_principal_id AND evidence.checker_principal_id=NEW.checker_principal_id
 JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id AND receipt.operation_id=candidate.consumed_operation_id
   AND receipt.terminal_state='COMMITTED' AND receipt.result_payload->>'operationId'=operation::text
   AND receipt.result_payload#>>'{result,mandateId}'=NEW.mandate_id::text
   AND receipt.result_payload#>>'{result,custodyGeneration}'=NEW.custody_generation::text
 WHERE candidate.participant_id=NEW.platform_participant_id AND candidate.resource_id=NEW.participant_id
   AND candidate.consumed_operation_id=operation AND candidate.state='CONSUMED'
   AND candidate.catalog_operation_id=CASE WHEN changed THEN 'ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE' ELSE 'ID-OP-PARTICIPANT-FIRST-ADMIN-REVOKE' END
   AND candidate.candidate_document->>'participantId'=NEW.participant_id::text
   AND candidate.candidate_document->>'mandateId'=NEW.mandate_id::text
   AND candidate.candidate_document->>'invitationId'=NEW.invitation_id::text
   AND candidate.candidate_document->>'custodyGeneration'=OLD.custody_generation::text
   AND candidate.candidate_document->>'tokenVersion'=OLD.custody_generation::text
   AND candidate.candidate_document->>'expectedRevision'=evidence.aggregate_version::text
   AND candidate.candidate_document#>>'{change,mutation}'=CASE WHEN changed THEN 'ROTATE' ELSE 'REVOKE' END;
 IF candidate_document IS NULL THEN RAISE EXCEPTION 'PC-AUTH-0002-BOOTSTRAP-CHANGE-PROVENANCE'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.participant_id,(NEW.candidate->>'privacyDomainId')::uuid,operation,action,true);
 IF NOT EXISTS(SELECT 1 FROM control.participant_invitation invitation JOIN control.participant_invitation_token token
   ON token.participant_id=invitation.participant_id AND token.invitation_id=invitation.invitation_id AND token.token_version=invitation.token_version
   WHERE invitation.participant_id=NEW.participant_id AND invitation.invitation_id=NEW.invitation_id
     AND invitation.expires_at=NEW.expires_at AND invitation.last_mutation_operation_id=operation
     AND invitation.token_version=NEW.custody_generation
     AND ((changed AND invitation.state='PENDING' AND token.operation_id=operation
       AND 'sha256:'||encode(token.token_digest,'hex')=candidate_document#>>'{change,tokenDigest}')
       OR (NOT changed AND invitation.state='REVOKED')))
   OR (OLD.candidate_session_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM control.session WHERE participant_id=NEW.participant_id
      AND session_id=OLD.candidate_session_id AND state='REVOKED'
      AND revoked_reason=CASE WHEN changed THEN 'first-administrator-custody-rotated' ELSE 'first-administrator-custody-revoked' END))
 THEN RAISE EXCEPTION 'PC-AUTH-0002-BOOTSTRAP-CHANGE-EFFECT'; END IF;
 PERFORM openpc.set_request_context(original_mode,original_participant,original_privacy,operation,action,original_privacy IS NOT NULL);
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS bootstrap_custody_change ON control.participant_bootstrap_custody;
CREATE CONSTRAINT TRIGGER bootstrap_custody_change AFTER UPDATE ON control.participant_bootstrap_custody
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_bootstrap_custody_change();
CREATE OR REPLACE FUNCTION openpc.require_first_admin_handoff()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.state='ACCEPTED' AND NOT EXISTS (
  SELECT 1 FROM control.participant participant
  JOIN control.principal principal ON principal.participant_id=participant.participant_id AND principal.principal_id=NEW.accepted_membership_id AND principal.state='ACTIVE'
  JOIN control.participant_membership member ON member.participant_id=principal.participant_id AND member.membership_id=principal.principal_id
  JOIN control.assignment assignment ON assignment.participant_id=participant.participant_id AND assignment.principal_id=principal.principal_id
    AND assignment.bootstrap_mandate_id=NEW.mandate_id AND assignment.state='ACTIVE' AND assignment.last_mutation_operation_id=NEW.accepted_operation_id
  JOIN control.authority_envelope envelope ON envelope.participant_id=assignment.participant_id AND envelope.authority_envelope_id=assignment.authority_envelope_id
    AND envelope.state='ACTIVE' AND envelope.bootstrap_mandate_id=NEW.mandate_id AND envelope.last_mutation_operation_id=NEW.accepted_operation_id
  JOIN control.mutation_evidence evidence ON evidence.participant_id=participant.participant_id AND evidence.operation_id=NEW.accepted_operation_id
    AND evidence.principal_id=NEW.accepted_membership_id AND evidence.catalog_operation_id='ID-OP-PARTICIPANT-FIRST-ADMIN-ACCEPT'
    AND evidence.candidate_digest=NEW.accepted_intent_digest
  JOIN control.outbox_event event ON event.participant_id=participant.participant_id AND event.aggregate_id=participant.participant_id
    AND event.event_type='openpc.identity.first-administrator.accepted.v1' AND event.payload_digest=evidence.evidence_digest
  WHERE participant.participant_id=NEW.participant_id AND participant.state='ACTIVE' AND participant.authority_epoch=NEW.participant_epoch+1
    AND NEW.acceptance_result IS NOT NULL AND NEW.closed_at IS NOT NULL
 ) THEN RAISE EXCEPTION 'PC-AUTH-0002'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS first_admin_handoff ON control.participant_bootstrap_custody;
CREATE CONSTRAINT TRIGGER first_admin_handoff AFTER INSERT OR UPDATE ON control.participant_bootstrap_custody
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_first_admin_handoff();


CREATE OR REPLACE FUNCTION openpc.guard_participant_authority_creation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE p control.participant%ROWTYPE;
BEGIN
 -- Revocation remains possible while fenced; no insertion or live-state write does.
 IF TG_OP='UPDATE' AND coalesce(to_jsonb(NEW)->>'state','') IN ('REVOKED','EXPIRED','CANCELLED','ARCHIVED','REMOVED','OFFBOARDED') THEN RETURN NEW; END IF;
 SELECT * INTO p FROM control.participant WHERE participant_id=NEW.participant_id FOR SHARE;
 IF NOT FOUND OR p.archived_at IS NOT NULL OR p.state NOT IN ('ACTIVE','PROVISIONING') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-FENCED';
 END IF;
 RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.principal;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.principal
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.participant_membership;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.participant_membership
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.privacy_domain;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.privacy_domain
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.authority_envelope;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.authority_envelope
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.authority_role;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.authority_role
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.authority_group;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.authority_group
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.authority_group_member;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.authority_group_member
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.assignment;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.assignment
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.delegation;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.delegation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.session;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.session
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.credential;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.credential
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.participant_invitation;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.participant_invitation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.participant_invitation_token;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.participant_invitation_token
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.participant_invitation_proof;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.participant_invitation_proof
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.participant_invitation_acceptance;
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.participant_invitation_acceptance
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();

CREATE OR REPLACE FUNCTION openpc.guard_participant_lifecycle_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-HISTORY-IMMUTABLE';
END $$;
DROP TRIGGER IF EXISTS participant_lifecycle_history ON control.participant_lifecycle_transition;
CREATE TRIGGER participant_lifecycle_history BEFORE UPDATE OR DELETE ON control.participant_lifecycle_transition
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_lifecycle_history();

CREATE OR REPLACE FUNCTION openpc.require_participant_lifecycle_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE mode text:=current_setting('openpc.context_mode');
 owner uuid:=nullif(current_setting('openpc.participant_id'),'')::uuid;
 privacy uuid:=nullif(current_setting('openpc.privacy_domain_id'),'')::uuid;
 op uuid:=current_setting('openpc.operation_id')::uuid;
 action text:=current_setting('openpc.action_intent_id'); valid boolean;
BEGIN
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.participant_id,NEW.privacy_domain_id,op,action,true);
 SELECT EXISTS(SELECT 1 FROM control.participant p JOIN control.outbox_event event ON event.participant_id=p.participant_id
   AND event.event_id=NEW.operation_id AND event.event_type='openpc.identity.participant.epoch.advanced.v1'
   WHERE p.participant_id=NEW.participant_id AND p.authority_epoch=NEW.new_epoch AND p.row_version=NEW.revision
    AND p.root_privacy_domain_id=NEW.privacy_domain_id
    AND (p.archived_at IS NOT NULL)=(NEW.mutation='ARCHIVE')) INTO valid;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-EFFECT'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.source_participant_id,NEW.source_privacy_domain_id,op,action,true);
 SELECT EXISTS(SELECT 1 FROM control.mutation_candidate candidate JOIN control.mutation_evidence evidence
   ON evidence.participant_id=candidate.participant_id AND evidence.operation_id=candidate.consumed_operation_id
    AND evidence.candidate_digest=candidate.candidate_digest AND evidence.catalog_operation_id=candidate.catalog_operation_id
   JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id
    AND receipt.operation_id=NEW.operation_id AND receipt.terminal_state='COMMITTED'
   WHERE candidate.participant_id=NEW.source_participant_id AND candidate.privacy_domain_id=NEW.source_privacy_domain_id
    AND candidate.state='CONSUMED' AND candidate.consumed_operation_id=NEW.operation_id
    AND candidate.catalog_operation_id='ID-OP-PARTICIPANT-'||NEW.mutation AND candidate.resource_id=NEW.participant_id
    AND candidate.candidate_document->>'privacyDomainId'=NEW.privacy_domain_id::text
    AND candidate.candidate_document->>'expectedEpoch'=NEW.prior_epoch::text
    AND candidate.expected_revision=NEW.revision-1 AND receipt.result_payload#>>'{result,epoch}'=NEW.new_epoch::text)
 INTO valid;
 PERFORM openpc.set_request_context(mode,owner,privacy,op,action,privacy IS NOT NULL);
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS participant_lifecycle_history_provenance ON control.participant_lifecycle_transition;
CREATE CONSTRAINT TRIGGER participant_lifecycle_history_provenance AFTER INSERT ON control.participant_lifecycle_transition
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_participant_lifecycle_history();

CREATE OR REPLACE FUNCTION openpc.require_participant_lifecycle_transition()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE transition control.participant_lifecycle_transition%ROWTYPE;
 mode text; owner uuid; privacy uuid; op uuid; action text;
 valid boolean;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-HISTORY-RETAINED'; END IF;
 IF NEW.archived_at IS NOT DISTINCT FROM OLD.archived_at THEN RETURN NULL; END IF;
 mode:=current_setting('openpc.context_mode');
 owner:=nullif(current_setting('openpc.participant_id'),'')::uuid;
 privacy:=nullif(current_setting('openpc.privacy_domain_id'),'')::uuid;
 op:=current_setting('openpc.operation_id')::uuid;
 action:=current_setting('openpc.action_intent_id');
 IF NOT ((OLD.state='ACTIVE' AND NEW.state='SUSPENDED' AND OLD.archived_at IS NULL AND NEW.archived_at IS NOT NULL)
      OR (OLD.state='SUSPENDED' AND NEW.state='ACTIVE' AND OLD.archived_at IS NOT NULL AND NEW.archived_at IS NULL))
    OR NEW.authority_epoch<>OLD.authority_epoch+1 OR NEW.row_version<>OLD.row_version+1 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-TRANSITION';
 END IF;
 PERFORM openpc.set_request_context('PLATFORM',NEW.participant_id,null,op,action,false);
 SELECT * INTO transition FROM control.participant_lifecycle_transition
  WHERE participant_id=NEW.participant_id AND new_epoch=NEW.authority_epoch AND prior_epoch=OLD.authority_epoch
   AND revision=NEW.row_version AND mutation=CASE WHEN NEW.archived_at IS NULL THEN 'RESTORE' ELSE 'ARCHIVE' END;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-HISTORY'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',transition.source_participant_id,transition.source_privacy_domain_id,op,action,true);
 SELECT EXISTS(
  SELECT 1 FROM control.mutation_candidate candidate
  JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id
   AND evidence.operation_id=candidate.consumed_operation_id AND evidence.candidate_digest=candidate.candidate_digest
   AND evidence.catalog_operation_id=candidate.catalog_operation_id AND evidence.principal_id<>evidence.checker_principal_id
  JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id
   AND receipt.operation_id=candidate.consumed_operation_id AND receipt.terminal_state='COMMITTED'
  WHERE candidate.participant_id=transition.source_participant_id AND candidate.privacy_domain_id=transition.source_privacy_domain_id
   AND candidate.consumed_operation_id=transition.operation_id AND candidate.state='CONSUMED'
   AND candidate.catalog_operation_id='ID-OP-PARTICIPANT-'||transition.mutation
   AND candidate.resource_id=NEW.participant_id AND candidate.candidate_document->>'participantId'=NEW.participant_id::text
   AND candidate.candidate_document->>'expectedEpoch'=OLD.authority_epoch::text
   AND candidate.expected_revision=OLD.row_version
   AND receipt.result_payload#>>'{result,epoch}'=NEW.authority_epoch::text
 ) INTO valid;
 PERFORM openpc.set_request_context(mode,owner,privacy,op,action,privacy IS NOT NULL);
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS participant_lifecycle_transition ON control.participant;
CREATE CONSTRAINT TRIGGER participant_lifecycle_transition AFTER UPDATE OR DELETE ON control.participant
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_participant_lifecycle_transition();


CREATE OR REPLACE FUNCTION openpc.guard_platform_context()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-CONTEXT'; END IF;
 IF NEW.platform_context_id<>OLD.platform_context_id OR NEW.owner_participant_id<>OLD.owner_participant_id
   OR NEW.created_at<>OLD.created_at OR OLD.state='RETIRED'
   OR NEW.authority_epoch<>OLD.authority_epoch+1 OR NEW.row_version<>OLD.row_version+1
   OR NEW.updated_at<=OLD.updated_at THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-CONTEXT';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS platform_context_monotonic ON control.platform_context;
CREATE TRIGGER platform_context_monotonic BEFORE UPDATE OR DELETE ON control.platform_context
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_context();

CREATE OR REPLACE FUNCTION openpc.guard_envelope_platform_binding()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.platform_context_id IS DISTINCT FROM OLD.platform_context_id
   OR NEW.platform_authority_epoch IS DISTINCT FROM OLD.platform_authority_epoch THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-CONTEXT';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authority_envelope_platform_immutable ON control.authority_envelope;
CREATE TRIGGER authority_envelope_platform_immutable BEFORE UPDATE ON control.authority_envelope
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_envelope_platform_binding();

DROP POLICY IF EXISTS envelope_platform_custody_read ON control.authority_envelope;
CREATE POLICY envelope_platform_custody_read ON control.authority_envelope FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id));
DROP POLICY IF EXISTS platform_context_custody_lock ON control.platform_context;
CREATE POLICY platform_context_custody_lock ON control.platform_context FOR UPDATE TO openpc_control_owner
 USING(exists(select 1 from control.authority_envelope envelope
   where envelope.platform_context_id=platform_context.platform_context_id
     and openpc.matches_participant(envelope.participant_id))) WITH CHECK(false);

-- This returns custody, not permission. Callers must first verify and retain
-- their selected current envelope/grant path under the Participant fence.
CREATE OR REPLACE FUNCTION openpc.lock_authority_envelope_platform_context(p_envelope_id uuid)
RETURNS TABLE(platform_context_id uuid,platform_authority_epoch text,delegation_epoch text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 RETURN QUERY SELECT platform.platform_context_id,platform.authority_epoch::text,envelope.delegation_epoch::text
 FROM control.authority_envelope envelope JOIN control.platform_context platform
   ON platform.platform_context_id=envelope.platform_context_id
 WHERE envelope.participant_id=openpc.current_participant_id()
   AND envelope.authority_envelope_id=p_envelope_id AND envelope.state='ACTIVE'
   AND envelope.valid_from<=clock_timestamp() AND (envelope.valid_until IS NULL OR envelope.valid_until>clock_timestamp())
   AND platform.state='ACTIVE' AND platform.authority_epoch=envelope.platform_authority_epoch
 FOR SHARE OF platform;
END $$;


CREATE OR REPLACE FUNCTION openpc.guard_wallet_binding_transition()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-RETAINED'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'ACTIVE' OR NEW.binding_epoch<>1 OR NEW.row_version<>1 THEN
   RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-INITIAL-STATE';
  END IF;
 ELSE
  IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR NEW.binding_epoch<>OLD.binding_epoch+1
   OR NEW.row_version<>OLD.row_version+1 OR NEW.last_operation_id=OLD.last_operation_id
   OR (to_jsonb(NEW)-ARRAY['state','binding_epoch','row_version','last_operation_id','updated_at'])
      IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','binding_epoch','row_version','last_operation_id','updated_at']) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-TRANSITION';
  END IF;
 END IF;
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.last_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' THEN
  RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-CONTEXT';
 END IF;
 IF TG_OP='INSERT' AND NOT EXISTS(SELECT 1 FROM control.principal subject JOIN control.participant participant USING(participant_id)
  JOIN control.privacy_domain privacy ON privacy.participant_id=subject.participant_id AND privacy.privacy_domain_id=NEW.privacy_domain_id
  WHERE subject.participant_id=NEW.participant_id AND subject.principal_id=NEW.subject_id
    AND subject.kind IN ('USER','WALLET','WORKLOAD') AND subject.state='ACTIVE'
    AND participant.state='ACTIVE' AND participant.archived_at IS NULL AND privacy.state='ACTIVE') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-SUBJECT';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS wallet_binding_transition ON control.wallet_binding;
CREATE TRIGGER wallet_binding_transition BEFORE INSERT OR UPDATE OR DELETE ON control.wallet_binding
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_wallet_binding_transition();

CREATE OR REPLACE FUNCTION openpc.require_wallet_binding_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE mutation text:=CASE WHEN TG_OP='INSERT' THEN 'CREATE' ELSE 'REVOKE' END;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.last_operation_id AND evidence.aggregate_type='wallet-binding'
   AND evidence.aggregate_id=NEW.wallet_binding_id AND evidence.catalog_operation_id='ID-OP-WALLET-BINDING-'||mutation
   AND evidence.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
   AND candidate.resource_id=NEW.wallet_binding_id AND candidate.state='CONSUMED'
   AND candidate.expected_revision=NEW.row_version-1
   AND candidate.candidate_document->>'walletBindingId'=NEW.wallet_binding_id::text
   AND (CASE WHEN mutation='CREATE' THEN
    candidate.candidate_document->>'participantId'=NEW.participant_id::text
    AND candidate.candidate_document->>'subjectId'=NEW.subject_id::text
    AND candidate.candidate_document->>'chainId'=NEW.chain_id::text
    AND candidate.candidate_document->>'walletAddress'=NEW.wallet_address
    ELSE candidate.candidate_document->>'state'='REVOKED' END)
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'walletBindingId'=NEW.wallet_binding_id::text
   AND receipt.result_payload->>'participantId'=NEW.participant_id::text
   AND receipt.result_payload->>'privacyDomainId'=NEW.privacy_domain_id::text
   AND receipt.result_payload->>'subjectId'=NEW.subject_id::text
   AND receipt.result_payload->>'chainId'=NEW.chain_id::text
   AND receipt.result_payload->>'walletAddress'=NEW.wallet_address
   AND receipt.result_payload->>'operationId'=NEW.last_operation_id::text
   AND receipt.result_payload->>'state'=NEW.state
   AND receipt.result_payload->>'bindingEpoch'=NEW.binding_epoch::text
   AND receipt.result_payload->>'revision'=NEW.row_version::text
   AND receipt.result_payload->>'permissionEffect'='NONE_WITHOUT_EFFECTIVE_AUTHORITY') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-WALLET-BINDING-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS wallet_binding_mutation_provenance ON control.wallet_binding;
CREATE CONSTRAINT TRIGGER wallet_binding_mutation_provenance AFTER INSERT OR UPDATE ON control.wallet_binding
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_wallet_binding_mutation();


CREATE OR REPLACE FUNCTION openpc.guard_human_membership()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM control.principal principal
   WHERE principal.participant_id=NEW.participant_id AND principal.principal_id=NEW.membership_id
     AND principal.kind IN ('USER','PLATFORM_OPERATOR')) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-MEMBERSHIP-KIND';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS membership_human_identity ON control.participant_membership;
CREATE TRIGGER membership_human_identity BEFORE INSERT ON control.participant_membership
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_human_membership();
CREATE OR REPLACE FUNCTION openpc.guard_member_principal_kind()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.kind<>OLD.kind AND EXISTS (SELECT 1 FROM control.participant_membership membership
   WHERE membership.participant_id=OLD.participant_id AND membership.membership_id=OLD.principal_id) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-MEMBERSHIP-KIND';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS member_principal_kind ON control.principal;
CREATE TRIGGER member_principal_kind BEFORE UPDATE OF kind ON control.principal
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_member_principal_kind();
CREATE OR REPLACE FUNCTION openpc.guard_removed_membership()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF OLD.state='OFFBOARDED' AND NEW.state<>OLD.state AND EXISTS (
   SELECT 1 FROM control.participant_membership membership
    WHERE membership.participant_id=OLD.participant_id AND membership.membership_id=OLD.principal_id) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-MEMBERSHIP-TERMINAL';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS removed_membership_terminal ON control.principal;
CREATE TRIGGER removed_membership_terminal BEFORE UPDATE OF state ON control.principal
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_removed_membership();
DROP TRIGGER IF EXISTS identity_subject_immutable ON control.identity_subject;
CREATE TRIGGER identity_subject_immutable BEFORE UPDATE OR DELETE ON control.identity_subject
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS membership_binding_immutable ON control.participant_membership;
CREATE TRIGGER membership_binding_immutable BEFORE UPDATE OR DELETE ON control.participant_membership
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();


CREATE OR REPLACE FUNCTION openpc.guard_identity_oidc_reservation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' OR current_user<>'openpc_identity_binding_owner' THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-IDENTITY-RESERVATION';
 END IF;
 IF TG_OP='UPDATE' AND (OLD.state<>'UNVERIFIED_LEGACY' OR
   (NEW.issuer,NEW.subject,NEW.audience,NEW.created_at) IS DISTINCT FROM (OLD.issuer,OLD.subject,OLD.audience,OLD.created_at) OR
   NOT ((NEW.state='BOUND' AND NEW.identity_subject_id=OLD.identity_subject_id) OR
        (NEW.state='AMBIGUOUS_LEGACY' AND NEW.identity_subject_id IS NULL))) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-IDENTITY-RESERVATION';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_oidc_reservation_immutable ON control.identity_oidc_binding;
CREATE TRIGGER identity_oidc_reservation_immutable BEFORE UPDATE OR DELETE ON control.identity_oidc_binding
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_oidc_reservation();

CREATE OR REPLACE FUNCTION openpc.observe_oidc_identity_claim()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
DECLARE local_subject uuid; existing control.identity_oidc_binding%ROWTYPE; qualified boolean;
BEGIN
 IF TG_OP='UPDATE' AND OLD.kind='OIDC_SUBJECT' AND
   (OLD.kind,OLD.participant_id,OLD.principal_id,OLD.issuer,OLD.subject,OLD.audience) IS DISTINCT FROM
   (NEW.kind,NEW.participant_id,NEW.principal_id,NEW.issuer,NEW.subject,NEW.audience) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-OIDC-CLAIM-IMMUTABLE';
 END IF;
 -- Invalid legacy accounts remain unusable for proof resolution; ordinary scoped login retains its checks.
 IF NEW.kind<>'OIDC_SUBJECT' OR NEW.issuer IS NULL OR NEW.subject IS NULL OR NEW.audience IS NULL
   OR length(NEW.issuer)=0 OR length(NEW.subject) NOT BETWEEN 1 AND 255 OR length(NEW.audience)=0 THEN RETURN NEW; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(NEW.issuer,NEW.subject,NEW.audience)::text,713));
 SELECT membership.identity_subject_id INTO local_subject FROM control.participant_membership membership
  WHERE membership.participant_id=NEW.participant_id AND membership.membership_id=NEW.principal_id;
 qualified:=local_subject IS NOT NULL AND NEW.state='ACTIVE' AND NEW.credential_epoch>0
   AND NEW.valid_from<=clock_timestamp() AND (NEW.valid_until IS NULL OR NEW.valid_until>clock_timestamp());
 SELECT * INTO existing FROM control.identity_oidc_binding
  WHERE issuer=NEW.issuer AND subject=NEW.subject AND audience=NEW.audience FOR UPDATE;
 IF NOT FOUND THEN
  INSERT INTO control.identity_oidc_binding(issuer,subject,audience,identity_subject_id,state)
   VALUES(NEW.issuer,NEW.subject,NEW.audience,CASE WHEN qualified THEN local_subject ELSE NULL END,
    CASE WHEN qualified THEN 'UNVERIFIED_LEGACY' ELSE 'AMBIGUOUS_LEGACY' END);
 ELSIF existing.state='BOUND' THEN
  -- Local revocation cannot revoke a global identity. A different local subject cannot claim it.
  IF existing.identity_subject_id IS DISTINCT FROM local_subject THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-OIDC-IDENTITY-CONFLICT';
  END IF;
 ELSIF existing.state='UNVERIFIED_LEGACY' AND (NOT qualified OR existing.identity_subject_id IS DISTINCT FROM local_subject) THEN
  UPDATE control.identity_oidc_binding SET state='AMBIGUOUS_LEGACY',identity_subject_id=NULL
   WHERE issuer=NEW.issuer AND subject=NEW.subject AND audience=NEW.audience;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS credential_oidc_identity_reservation ON control.credential;
CREATE TRIGGER credential_oidc_identity_reservation BEFORE INSERT OR UPDATE OF kind,participant_id,principal_id,issuer,subject,audience,state,credential_epoch,valid_from,valid_until ON control.credential
 FOR EACH ROW EXECUTE FUNCTION openpc.observe_oidc_identity_claim();

-- Internal proof consumer only. Possession of these arguments is not proof; the Identity
-- invitation owner verifies signed OIDC, token/version, custody and durable issuance authority first.
CREATE OR REPLACE FUNCTION openpc.resolve_proved_oidc_identity(issuer_value text,subject_value text,audience_value text)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
DECLARE existing control.identity_oidc_binding%ROWTYPE; resolved uuid;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANT_CREATE_MEMBER-V1' OR issuer_value IS NULL OR subject_value IS NULL OR audience_value IS NULL
   OR length(issuer_value)=0 OR length(subject_value) NOT BETWEEN 1 AND 255 OR length(audience_value)=0 THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(issuer_value,subject_value,audience_value)::text,713));
 SELECT * INTO existing FROM control.identity_oidc_binding
  WHERE issuer=issuer_value AND subject=subject_value AND audience=audience_value FOR UPDATE;
 IF NOT FOUND THEN
  resolved:=uuidv7();
  INSERT INTO control.identity_subject(identity_subject_id) VALUES(resolved);
  INSERT INTO control.identity_oidc_binding(issuer,subject,audience,identity_subject_id,state)
   VALUES(issuer_value,subject_value,audience_value,resolved,'BOUND');
  RETURN resolved;
 END IF;
 IF existing.state='AMBIGUOUS_LEGACY' THEN RAISE EXCEPTION 'PC-AUTH-0002'; END IF;
 IF existing.state='UNVERIFIED_LEGACY' THEN
  IF EXISTS (SELECT 1 FROM control.credential credential
    LEFT JOIN control.participant_membership membership ON membership.participant_id=credential.participant_id AND membership.membership_id=credential.principal_id
    WHERE credential.kind='OIDC_SUBJECT' AND credential.issuer=issuer_value AND credential.subject=subject_value AND credential.audience=audience_value
      AND (membership.identity_subject_id IS DISTINCT FROM existing.identity_subject_id OR credential.state<>'ACTIVE' OR credential.credential_epoch<=0
        OR credential.valid_from>clock_timestamp() OR credential.valid_until<=clock_timestamp())) THEN
   RAISE EXCEPTION 'PC-AUTH-0002';
  END IF;
  UPDATE control.identity_oidc_binding SET state='BOUND' WHERE issuer=issuer_value AND subject=subject_value AND audience=audience_value;
 END IF;
 RETURN existing.identity_subject_id;
END $$;



CREATE OR REPLACE FUNCTION openpc.signing_transition_effects(p_action text,p_prior text,p_target text)
RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT effects::jsonb FROM (VALUES ('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','APPROVED','PREPARED','{"kind":"ADVANCE","providerSteps":[["new","PREPARE"]],"prepare":true,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','RECOVERING','PREPARED','{"kind":"ADVANCE","providerSteps":[["new","PREPARE"]],"prepare":true,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":"APPROVED"}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','APPROVED','APPROVED','{"kind":"RENEWAL","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','APPROVED','RECOVERING','{"kind":"RECOVERY","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','PREPARED','DISTRIBUTED','{"kind":"ADVANCE","providerSteps":[["new","DISTRIBUTE"]],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','RECOVERING','DISTRIBUTED','{"kind":"ADVANCE","providerSteps":[["new","DISTRIBUTE"]],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":"PREPARED"}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','PREPARED','PREPARED','{"kind":"RENEWAL","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','PREPARED','RECOVERING','{"kind":"RECOVERY","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','DISTRIBUTED','VERIFIED','{"kind":"ADVANCE","providerSteps":[["old","PROVE"],["new","PROVE"]],"prepare":false,"admitTrust":true,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','RECOVERING','VERIFIED','{"kind":"ADVANCE","providerSteps":[["old","PROVE"],["new","PROVE"]],"prepare":false,"admitTrust":true,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":"DISTRIBUTED"}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','DISTRIBUTED','DISTRIBUTED','{"kind":"RENEWAL","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','DISTRIBUTED','RECOVERING','{"kind":"RECOVERY","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','VERIFIED','CUTOVER_FENCED','{"kind":"ADVANCE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":true,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','RECOVERING','CUTOVER_FENCED','{"kind":"ADVANCE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":true,"revoke":false,"eventType":null,"resumeFrom":"VERIFIED"}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','VERIFIED','VERIFIED','{"kind":"RENEWAL","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','VERIFIED','RECOVERING','{"kind":"RECOVERY","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','CUTOVER_FENCED','OBSERVING','{"kind":"ADVANCE","providerSteps":[["effective","PROVE"]],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','RECOVERING','OBSERVING','{"kind":"ADVANCE","providerSteps":[["effective","PROVE"]],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":"CUTOVER_FENCED"}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','CUTOVER_FENCED','CUTOVER_FENCED','{"kind":"RENEWAL","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','CUTOVER_FENCED','RECOVERING','{"kind":"RECOVERY","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','OBSERVING','OLD_REVOKED','{"kind":"ADVANCE","providerSteps":[["old","REVOKE"]],"prepare":false,"admitTrust":false,"cutover":false,"revoke":true,"eventType":"io.openpc.ops.secret.revoked.v1","resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','RECOVERING','OLD_REVOKED','{"kind":"ADVANCE","providerSteps":[["old","REVOKE"]],"prepare":false,"admitTrust":false,"cutover":false,"revoke":true,"eventType":"io.openpc.ops.secret.revoked.v1","resumeFrom":"OBSERVING"}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','OBSERVING','OBSERVING','{"kind":"RENEWAL","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','OBSERVING','RECOVERING','{"kind":"RECOVERY","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','OLD_REVOKED','OLD_RETIRED','{"kind":"ADVANCE","providerSteps":[["old","RETIRE"]],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','RECOVERING','OLD_RETIRED','{"kind":"ADVANCE","providerSteps":[["old","RETIRE"]],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":"OLD_REVOKED"}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','OLD_REVOKED','OLD_REVOKED','{"kind":"RENEWAL","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','OLD_REVOKED','RECOVERING','{"kind":"RECOVERY","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','OLD_RETIRED','COMPLETE','{"kind":"ADVANCE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":"io.openpc.ops.secret.rotated.v1","resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','RECOVERING','COMPLETE','{"kind":"ADVANCE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":"io.openpc.ops.secret.rotated.v1","resumeFrom":"OLD_RETIRED"}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','OLD_RETIRED','OLD_RETIRED','{"kind":"RENEWAL","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','OLD_RETIRED','RECOVERING','{"kind":"RECOVERY","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','APPROVED','FAILED','{"kind":"FAILURE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','PREPARED','FAILED','{"kind":"FAILURE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','DISTRIBUTED','FAILED','{"kind":"FAILURE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','VERIFIED','FAILED','{"kind":"FAILURE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','CUTOVER_FENCED','FAILED','{"kind":"FAILURE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','OBSERVING','FAILED','{"kind":"FAILURE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','OLD_REVOKED','FAILED','{"kind":"FAILURE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','OLD_RETIRED','FAILED','{"kind":"FAILURE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','RECOVERING','FAILED','{"kind":"FAILURE","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','RECOVERING','RECOVERING','{"kind":"RECOVERY","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','FAILED','RECOVERING','{"kind":"FORWARD_RECOVERY","providerSteps":[],"prepare":false,"admitTrust":false,"cutover":false,"revoke":false,"eventType":null,"resumeFrom":null}')) matrix(action,prior,target,effects)
 WHERE action=p_action AND prior=p_prior AND target=p_target
$$;

INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,
 step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1','signing-key-rotation','CREATE','HIGH',true,false,true,'AUTHORIZED_ONLY','REDACTED','SIGNING_KEY_LIFECYCLE'),
('ACT-SIGNING_KEY_ROTATIONS_READ_COLLECTION-V1','signing-key-rotation','READ','LOW',false,false,false,'AUTHORIZED_ONLY','REDACTED','SIGNING_KEY_LIFECYCLE'),
('ACT-SIGNING_KEY_ROTATIONS_READ_RESOURCE-V1','signing-key-rotation','READ','LOW',false,false,false,'AUTHORIZED_ONLY','REDACTED','SIGNING_KEY_LIFECYCLE'),
('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','signing-key-rotation','UPDATE','HIGH',false,false,true,'AUTHORIZED_ONLY','REDACTED','SIGNING_KEY_LIFECYCLE'),
('ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','signing-key-rotation','RECOVER','HIGH',false,false,true,'AUTHORIZED_ONLY','REDACTED','SIGNING_KEY_LIFECYCLE'),
('ACT-SIGNING_KEYS_READ_COLLECTION-V1','signing-key','READ','LOW',false,false,false,'AUTHORIZED_ONLY','REDACTED','SIGNING_KEY_LIFECYCLE') ON CONFLICT(action_intent_id) DO NOTHING;
CREATE OR REPLACE FUNCTION openpc.guard_signing_rotation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE governed boolean:=false; generation control.signing_authorization_generation%ROWTYPE; effects jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROTATION'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'REQUESTED' OR NEW.revision<>1 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-INITIAL-STATE'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','revision','updated_at','approval_request_id','approved_operation_id','new_signer_id','cutover_at_ns','recovery_from_state','recovery_from_revision'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','revision','updated_at','approval_request_id','approved_operation_id','new_signer_id','cutover_at_ns','recovery_from_state','recovery_from_revision'])
   OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<=OLD.updated_at THEN RAISE EXCEPTION 'DATA-6020-ROTATION-IDENTITY'; END IF;
 SELECT g.* INTO generation FROM control.signing_rotation_command c JOIN control.signing_authorization_generation g
  ON g.generation_id=c.authorization_generation_id WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
   AND c.rotation_id=NEW.rotation_id AND c.operation_id=openpc.current_operation_id()
   AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND g.state='STAGED';
 IF FOUND THEN
  PERFORM openpc.check_signing_generation_current(generation.generation_id);
  governed:=NEW.state=generation.target_state AND NEW.revision=generation.from_revision+1 AND OLD.state<>'COMPLETE'
   AND (NEW.state=OLD.state OR (OLD.state='FAILED' AND NEW.state='RECOVERING'
    AND NEW.recovery_from_state=generation.resume_state AND NEW.recovery_from_revision=generation.resume_revision));
  IF NOT governed THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GOVERNED-TARGET'; END IF;
 END IF;
 IF NOT governed AND NEW.state<>'RECOVERING' AND EXISTS(SELECT 1 FROM control.signing_rotation_command recovery
  WHERE recovery.participant_id=NEW.participant_id AND recovery.privacy_domain_id=NEW.privacy_domain_id
   AND recovery.rotation_id=NEW.rotation_id AND recovery.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1'
   AND recovery.state='ACCEPTED')
 THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-IN-PROGRESS'; END IF;
 IF OLD.approval_request_id IS NOT NULL AND (NEW.approval_request_id IS DISTINCT FROM OLD.approval_request_id OR
    NEW.approved_operation_id IS DISTINCT FROM OLD.approved_operation_id) THEN RAISE EXCEPTION 'DATA-6020-ROTATION-APPROVAL'; END IF;
 IF OLD.new_signer_id IS NOT NULL AND NEW.new_signer_id IS DISTINCT FROM OLD.new_signer_id THEN RAISE EXCEPTION 'DATA-6020-ROTATION-KEY'; END IF;
 IF OLD.cutover_at_ns IS NOT NULL AND NEW.cutover_at_ns IS DISTINCT FROM OLD.cutover_at_ns THEN RAISE EXCEPTION 'DATA-6020-ROTATION-CUTOVER'; END IF;
 IF NOT (OLD.state='REQUESTED' AND NEW.state='APPROVED') THEN
  effects:=openpc.signing_transition_effects(openpc.current_action_intent_id(),OLD.state,NEW.state);
  IF effects IS NULL OR (effects->>'resumeFrom' IS NOT NULL AND effects->>'resumeFrom' IS DISTINCT FROM OLD.recovery_from_state)
   OR (effects->>'kind' IN ('RENEWAL','FORWARD_RECOVERY') AND NOT governed)
   OR (effects->>'kind'='RECOVERY' AND NOT governed AND
     (NEW.recovery_from_state IS DISTINCT FROM coalesce(OLD.recovery_from_state,OLD.state)
      OR NEW.recovery_from_revision IS DISTINCT FROM coalesce(OLD.recovery_from_revision,OLD.revision)))
  THEN RAISE EXCEPTION 'DATA-6022-ROTATION-TRANSITION'; END IF;
 END IF;
 IF NEW.state='APPROVED' AND NOT governed AND (openpc.current_action_intent_id()<>'ACT-POLICY_APPROVE_REQUEST-V1' OR NOT EXISTS(
  SELECT 1 FROM control.approval_request a JOIN control.mutation_candidate c ON c.participant_id=a.participant_id
   AND c.privacy_domain_id=a.privacy_domain_id AND c.mutation_candidate_id=a.subject_id
  JOIN control.approval_decision_record d ON d.participant_id=a.participant_id AND d.privacy_domain_id=a.privacy_domain_id
   AND d.approval_request_id=a.approval_request_id AND d.decision='APPROVE' AND d.approver_principal_id<>a.maker_principal_id
  WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id AND a.approval_request_id=NEW.approval_request_id
   AND a.state='APPROVED' AND c.state='CONSUMED' AND c.consumed_operation_id=NEW.approved_operation_id
   AND c.resource_id=NEW.rotation_id AND c.expected_revision=OLD.revision AND c.candidate_digest=NEW.candidate_digest
   AND a.subject_digest=c.candidate_digest AND d.candidate_digest=c.candidate_digest)) THEN RAISE EXCEPTION 'DATA-6021-ROTATION-CONSUMPTION'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_rotation_guard ON control.signing_key_rotation;
CREATE TRIGGER signing_rotation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_key_rotation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_rotation();

CREATE OR REPLACE FUNCTION openpc.signing_attempt_authority_status(p_attempt uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE command control.signing_rotation_command%ROWTYPE; snapshot jsonb; dependency record;
 actual jsonb; current_rows jsonb:='{}'::jsonb; unchanged boolean:=true; live boolean; approval jsonb; locked_count bigint;
BEGIN
 SELECT c.* INTO STRICT command FROM control.signing_rotation_command c JOIN control.signing_provider_attempt a
  ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id AND a.operation_id=c.operation_id
  WHERE a.attempt_id=p_attempt AND c.participant_id=openpc.current_participant_id()
   AND c.privacy_domain_id=openpc.current_privacy_domain_id()
   AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1';
 snapshot:=convert_from(command.authorization_snapshot,'UTF8')::jsonb;
 IF sha256(command.authorization_snapshot)<>command.authorization_snapshot_digest
  OR snapshot->>'schema'<>'pc.control.precommit-authority-snapshot.v1'
  OR snapshot->>'operationId'<>command.operation_id::text OR snapshot->>'decision'<>'ALLOW'
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-RETAINED-AUTHORITY'; END IF;
 FOR dependency IN SELECT * FROM (SELECT 'assignment'::text table_name,'assignment_id'::text column_name,
 2 rank,(d->>'assignment_id')::uuid id
 FROM jsonb_array_elements(snapshot->'dependencies'->'assignment') d
UNION ALL
SELECT 'authority_envelope'::text table_name,'authority_envelope_id'::text column_name,
 2 rank,(d->>'authority_envelope_id')::uuid id
 FROM jsonb_array_elements(snapshot->'dependencies'->'authority_envelope') d
UNION ALL
SELECT 'authority_role'::text table_name,'authority_role_id'::text column_name,
 undefined rank,(d->>'authority_role_id')::uuid id
 FROM jsonb_array_elements(snapshot->'dependencies'->'authority_role') d
UNION ALL
SELECT 'credential'::text table_name,'credential_id'::text column_name,
 3 rank,(d->>'credential_id')::uuid id
 FROM jsonb_array_elements(snapshot->'dependencies'->'credential') d
UNION ALL
SELECT 'delegation'::text table_name,'delegation_id'::text column_name,
 3 rank,(d->>'delegation_id')::uuid id
 FROM jsonb_array_elements(snapshot->'dependencies'->'delegation') d
UNION ALL
SELECT 'participant'::text table_name,'participant_id'::text column_name,
 0 rank,(d->>'participant_id')::uuid id
 FROM jsonb_array_elements(snapshot->'dependencies'->'participant') d
UNION ALL
SELECT 'principal'::text table_name,'principal_id'::text column_name,
 2 rank,(d->>'principal_id')::uuid id
 FROM jsonb_array_elements(snapshot->'dependencies'->'principal') d
UNION ALL
SELECT 'privacy_domain'::text table_name,'privacy_domain_id'::text column_name,
 1 rank,(d->>'privacy_domain_id')::uuid id
 FROM jsonb_array_elements(snapshot->'dependencies'->'privacy_domain') d
UNION ALL
SELECT 'session'::text table_name,'session_id'::text column_name,
 3 rank,(d->>'session_id')::uuid id
 FROM jsonb_array_elements(snapshot->'dependencies'->'session') d) dependencies ORDER BY rank,id,table_name LOOP
  EXECUTE format('SELECT %I FROM control.%I WHERE participant_id=$1 AND %I=$2 FOR SHARE',
   dependency.column_name,dependency.table_name,dependency.column_name) USING command.participant_id,dependency.id;
  GET DIAGNOSTICS locked_count=ROW_COUNT;
  IF locked_count<>1 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-MISSING-AUTHORITY'; END IF;
 END LOOP;

 SELECT coalesce(jsonb_agg(jsonb_build_object('assignment_id',owner.assignment_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'authority_group_id',owner.authority_group_id::text,'role_id',owner.role_id::text,'authority_envelope_id',owner.authority_envelope_id::text,'delegation_epoch',owner.delegation_epoch::text,'scope_digest',owner.scope_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'runtime_capability_ids',owner.runtime_capability_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'valid_during',owner.valid_during::text,'state',owner.state::text,'created_by_principal_id',owner.created_by_principal_id::text,'row_version',owner.row_version::text) ORDER BY owner.assignment_id),'[]'::jsonb)
 INTO actual FROM control.assignment owner WHERE owner.participant_id=command.participant_id
 AND owner.assignment_id IN(SELECT (d->>'assignment_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'assignment') d);

 -- An immutable pre-migration snapshot omitted runtime grants. Preserve its
 -- comparison/digest shape only while the actual owner still grants none.
 SELECT coalesce(jsonb_agg(CASE WHEN current_row->>'runtime_capability_ids'='{}'
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot->'dependencies'->'assignment') retained
     WHERE retained->>'assignment_id'=current_row->>'assignment_id' AND NOT retained ? 'runtime_capability_ids')
   THEN current_row-'runtime_capability_ids' ELSE current_row END ORDER BY current_row->>'assignment_id'),'[]'::jsonb)
 INTO actual FROM jsonb_array_elements(actual) current_row;

 current_rows:=current_rows||jsonb_build_object('assignment',actual);
 IF actual IS DISTINCT FROM snapshot->'dependencies'->'assignment'
 THEN unchanged:=false; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('authority_envelope_id',owner.authority_envelope_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'maker_principal_id',owner.maker_principal_id::text,'checker_principal_id',owner.checker_principal_id::text,'authority_epoch',owner.authority_epoch::text,'delegation_epoch',owner.delegation_epoch::text,'state',owner.state::text,'valid_from',owner.valid_from::text,'valid_until',owner.valid_until::text,'semantic_digest',owner.semantic_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'runtime_capability_ids',owner.runtime_capability_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'row_version',owner.row_version::text) ORDER BY owner.authority_envelope_id),'[]'::jsonb)
 INTO actual FROM control.authority_envelope owner WHERE owner.participant_id=command.participant_id
 AND owner.authority_envelope_id IN(SELECT (d->>'authority_envelope_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'authority_envelope') d);

 -- An immutable pre-migration snapshot omitted runtime grants. Preserve its
 -- comparison/digest shape only while the actual owner still grants none.
 SELECT coalesce(jsonb_agg(CASE WHEN current_row->>'runtime_capability_ids'='{}'
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot->'dependencies'->'authority_envelope') retained
     WHERE retained->>'authority_envelope_id'=current_row->>'authority_envelope_id' AND NOT retained ? 'runtime_capability_ids')
   THEN current_row-'runtime_capability_ids' ELSE current_row END ORDER BY current_row->>'authority_envelope_id'),'[]'::jsonb)
 INTO actual FROM jsonb_array_elements(actual) current_row;

 current_rows:=current_rows||jsonb_build_object('authority_envelope',actual);
 IF actual IS DISTINCT FROM snapshot->'dependencies'->'authority_envelope'
 THEN unchanged:=false; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('authority_role_id',owner.authority_role_id::text,'participant_id',owner.participant_id::text,'role_id',owner.role_id::text,'action_intent_ids',owner.action_intent_ids::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.authority_role_id),'[]'::jsonb)
 INTO actual FROM control.authority_role owner WHERE owner.participant_id=command.participant_id
 AND owner.authority_role_id IN(SELECT (d->>'authority_role_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'authority_role') d);

 current_rows:=current_rows||jsonb_build_object('authority_role',actual);
 IF actual IS DISTINCT FROM snapshot->'dependencies'->'authority_role'
 THEN unchanged:=false; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('credential_id',owner.credential_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'kind',owner.kind::text,'state',owner.state::text,'credential_epoch',owner.credential_epoch::text,'valid_from',owner.valid_from::text,'valid_until',owner.valid_until::text,'public_key_digest',owner.public_key_digest::text,'row_version',owner.row_version::text) ORDER BY owner.credential_id),'[]'::jsonb)
 INTO actual FROM control.credential owner WHERE owner.participant_id=command.participant_id
 AND owner.credential_id IN(SELECT (d->>'credential_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'credential') d);

 current_rows:=current_rows||jsonb_build_object('credential',actual);
 IF actual IS DISTINCT FROM snapshot->'dependencies'->'credential' AND NOT (
  jsonb_array_length(actual)=jsonb_array_length(snapshot->'dependencies'->'credential') AND NOT EXISTS(
   SELECT 1 FROM jsonb_array_elements(snapshot->'dependencies'->'credential') retained WHERE NOT EXISTS(
    SELECT 1 FROM jsonb_array_elements(actual) current_row WHERE (retained-'row_version')=(current_row-'row_version')
     AND (current_row->>'row_version')::bigint>=(retained->>'row_version')::bigint)))
 THEN unchanged:=false; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('delegation_id',owner.delegation_id::text,'participant_id',owner.participant_id::text,'parent_assignment_id',owner.parent_assignment_id::text,'parent_delegation_id',owner.parent_delegation_id::text,'grantor_principal_id',owner.grantor_principal_id::text,'delegate_principal_id',owner.delegate_principal_id::text,'delegation_epoch',owner.delegation_epoch::text,'scope_digest',owner.scope_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'runtime_capability_ids',owner.runtime_capability_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'valid_during',owner.valid_during::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.delegation_id),'[]'::jsonb)
 INTO actual FROM control.delegation owner WHERE owner.participant_id=command.participant_id
 AND owner.delegation_id IN(SELECT (d->>'delegation_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'delegation') d);

 -- An immutable pre-migration snapshot omitted runtime grants. Preserve its
 -- comparison/digest shape only while the actual owner still grants none.
 SELECT coalesce(jsonb_agg(CASE WHEN current_row->>'runtime_capability_ids'='{}'
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot->'dependencies'->'delegation') retained
     WHERE retained->>'delegation_id'=current_row->>'delegation_id' AND NOT retained ? 'runtime_capability_ids')
   THEN current_row-'runtime_capability_ids' ELSE current_row END ORDER BY current_row->>'delegation_id'),'[]'::jsonb)
 INTO actual FROM jsonb_array_elements(actual) current_row;

 current_rows:=current_rows||jsonb_build_object('delegation',actual);
 IF actual IS DISTINCT FROM snapshot->'dependencies'->'delegation'
 THEN unchanged:=false; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('participant_id',owner.participant_id::text,'state',owner.state::text,'authority_epoch',owner.authority_epoch::text,'row_version',owner.row_version::text) ORDER BY owner.participant_id),'[]'::jsonb)
 INTO actual FROM control.participant owner WHERE owner.participant_id=command.participant_id
 AND owner.participant_id IN(SELECT (d->>'participant_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'participant') d);

 current_rows:=current_rows||jsonb_build_object('participant',actual);
 IF actual IS DISTINCT FROM snapshot->'dependencies'->'participant'
 THEN unchanged:=false; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('principal_id',owner.principal_id::text,'participant_id',owner.participant_id::text,'kind',owner.kind::text,'state',owner.state::text,'authority_epoch',owner.authority_epoch::text,'row_version',owner.row_version::text) ORDER BY owner.principal_id),'[]'::jsonb)
 INTO actual FROM control.principal owner WHERE owner.participant_id=command.participant_id
 AND owner.principal_id IN(SELECT (d->>'principal_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'principal') d);

 current_rows:=current_rows||jsonb_build_object('principal',actual);
 IF actual IS DISTINCT FROM snapshot->'dependencies'->'principal'
 THEN unchanged:=false; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('privacy_domain_id',owner.privacy_domain_id::text,'participant_id',owner.participant_id::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.privacy_domain_id),'[]'::jsonb)
 INTO actual FROM control.privacy_domain owner WHERE owner.participant_id=command.participant_id
 AND owner.privacy_domain_id IN(SELECT (d->>'privacy_domain_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'privacy_domain') d);

 current_rows:=current_rows||jsonb_build_object('privacy_domain',actual);
 IF actual IS DISTINCT FROM snapshot->'dependencies'->'privacy_domain'
 THEN unchanged:=false; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('session_id',owner.session_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'state',owner.state::text,'participant_epoch',owner.participant_epoch::text,'authority_epoch',owner.authority_epoch::text,'delegation_epoch',owner.delegation_epoch::text,'session_epoch',owner.session_epoch::text,'issued_at',owner.issued_at::text,'idle_expires_at',owner.idle_expires_at::text,'absolute_expires_at',owner.absolute_expires_at::text,'step_up_verified_at',owner.step_up_verified_at::text,'row_version',owner.row_version::text) ORDER BY owner.session_id),'[]'::jsonb)
 INTO actual FROM control.session owner WHERE owner.participant_id=command.participant_id
 AND owner.session_id IN(SELECT (d->>'session_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'session') d);

 current_rows:=current_rows||jsonb_build_object('session',actual);
 IF actual IS DISTINCT FROM snapshot->'dependencies'->'session' AND NOT (
  jsonb_array_length(actual)=jsonb_array_length(snapshot->'dependencies'->'session') AND NOT EXISTS(
   SELECT 1 FROM jsonb_array_elements(snapshot->'dependencies'->'session') retained WHERE NOT EXISTS(
    SELECT 1 FROM jsonb_array_elements(actual) current_row WHERE
     (retained-ARRAY['idle_expires_at','row_version'])=(current_row-ARRAY['idle_expires_at','row_version'])
     AND (current_row->>'row_version')::bigint>=(retained->>'row_version')::bigint
     AND (current_row->>'idle_expires_at')::timestamptz>=(retained->>'idle_expires_at')::timestamptz)))
 THEN unchanged:=false; END IF;
 SELECT NOT EXISTS(
  SELECT 1 FROM control.session s WHERE s.participant_id=command.participant_id
   AND s.session_id IN(SELECT (d->>'session_id')::uuid FROM jsonb_array_elements(current_rows->'session') d)
   AND (s.state<>'ACTIVE' OR s.issued_at>clock_timestamp() OR s.idle_expires_at<=clock_timestamp() OR s.absolute_expires_at<=clock_timestamp())
  UNION ALL SELECT 1 FROM control.authority_envelope e WHERE e.participant_id=command.participant_id
   AND e.authority_envelope_id IN(SELECT (d->>'authority_envelope_id')::uuid FROM jsonb_array_elements(current_rows->'authority_envelope') d)
   AND (e.state<>'ACTIVE' OR e.valid_from>clock_timestamp() OR e.valid_until<=clock_timestamp())
  UNION ALL SELECT 1 FROM control.assignment a WHERE a.participant_id=command.participant_id
   AND a.assignment_id IN(SELECT (d->>'assignment_id')::uuid FROM jsonb_array_elements(current_rows->'assignment') d)
   AND (a.state<>'ACTIVE' OR NOT a.valid_during @> clock_timestamp())
  UNION ALL SELECT 1 FROM control.delegation d WHERE d.participant_id=command.participant_id
   AND d.delegation_id IN(SELECT (r->>'delegation_id')::uuid FROM jsonb_array_elements(current_rows->'delegation') r)
   AND (d.state<>'ACTIVE' OR NOT d.valid_during @> clock_timestamp())
  UNION ALL SELECT 1 FROM control.credential c WHERE c.participant_id=command.participant_id
   AND c.credential_id IN(SELECT (d->>'credential_id')::uuid FROM jsonb_array_elements(current_rows->'credential') d)
   AND (c.state<>'ACTIVE' OR c.valid_from>clock_timestamp() OR c.valid_until<=clock_timestamp())
 ) INTO live;
 SELECT jsonb_build_object('approvalRequestId',a.approval_request_id::text,'state',a.state,
  'expiresAt',a.expires_at::text,'candidateDigest',encode(a.subject_digest,'hex'),
  'live',a.state='APPROVED' AND a.expires_at>clock_timestamp()) INTO STRICT approval
 FROM control.approval_request a
 WHERE a.participant_id=command.participant_id AND a.privacy_domain_id=command.privacy_domain_id
  AND a.approval_request_id=command.approval_request_id AND a.subject_digest=command.approval_candidate_digest
 FOR SHARE OF a;
 RETURN jsonb_build_object('unchangedLive',unchanged AND live AND (approval->>'live')::boolean,
  'dependencies',current_rows,'approval',approval);
END $$;
CREATE OR REPLACE FUNCTION openpc.signing_continuation_authority_digest(p_status jsonb)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT sha256(convert_to(jsonb_set(jsonb_set(p_status,'{dependencies,session}',
  (SELECT coalesce(jsonb_agg(value-ARRAY['idle_expires_at','row_version'] ORDER BY value->>'session_id'),'[]'::jsonb)
   FROM jsonb_array_elements(p_status->'dependencies'->'session') value)),'{dependencies,credential}',
  (SELECT coalesce(jsonb_agg(value-'row_version' ORDER BY value->>'credential_id'),'[]'::jsonb)
   FROM jsonb_array_elements(p_status->'dependencies'->'credential') value))::text,'UTF8'))
$$;

CREATE OR REPLACE FUNCTION openpc.guard_signing_provider_attempt()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE command control.signing_rotation_command%ROWTYPE; rotation control.signing_key_rotation%ROWTYPE; effects jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-PROVIDER-ATTEMPT'; END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT command FROM control.signing_rotation_command WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND operation_id=NEW.operation_id AND state IN ('ACCEPTED','WRITE_AMBIGUITY');
  SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND revision=NEW.from_revision AND state=NEW.from_state;
  effects:=openpc.signing_transition_effects(command.action_intent_id,NEW.from_state,NEW.to_state);
  IF effects IS NULL OR (effects->>'resumeFrom' IS NOT NULL AND effects->>'resumeFrom' IS DISTINCT FROM rotation.recovery_from_state)
   OR (NEW.request->>'method'<>'SIGN_RECEIPT' AND NOT (effects->'providerSteps' @> jsonb_build_array(jsonb_build_array(NEW.slot,NEW.request->>'method'))))
   OR (NEW.request->>'method'<>'SIGN_RECEIPT' AND NEW.to_state<>command.to_state)
  THEN RAISE EXCEPTION 'DATA-6022-SIGNING-PROVIDER-MATRIX'; END IF;
  IF NEW.dispatched_at_ns IS NOT NULL THEN RAISE EXCEPTION 'DATA-6021-ATTEMPT-DISPATCH-TIME'; END IF;
  IF NEW.state='DISPATCHING' AND NEW.request->>'method' IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') THEN RAISE EXCEPTION 'DATA-6021-ATTEMPT-RESERVE-BEFORE-DISPATCH'; END IF;
  IF NEW.state NOT IN ('READY','DISPATCHING') OR NEW.observation IS NOT NULL THEN RAISE EXCEPTION 'DATA-6021-ATTEMPT-INITIAL'; END IF;
  IF NEW.state='DISPATCHING' THEN NEW.dispatched_at_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000; END IF;
  RETURN NEW;
 END IF;
 IF NEW.dispatched_at_ns IS DISTINCT FROM OLD.dispatched_at_ns THEN RAISE EXCEPTION 'DATA-6020-ATTEMPT-DISPATCH-TIME'; END IF;
 IF (to_jsonb(NEW)-ARRAY['state','observation','observation_digest']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['state','observation','observation_digest']) THEN RAISE EXCEPTION 'DATA-6020-ATTEMPT-IDENTITY'; END IF;
 IF pg_has_role(current_user,'openpc_control_worker','MEMBER') AND
  (OLD.request->>'method' NOT IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') OR NEW.state NOT IN ('DISPATCHING','OBSERVED','CANCELLED'))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-WORKER-OWNER'; END IF;
 IF NOT pg_has_role(current_user,'openpc_control_worker','MEMBER') AND NEW.state='DISPATCHING'
  AND OLD.request->>'method' NOT IN ('PROVE','SIGN_RECEIPT')
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-DISPATCH-OWNER'; END IF;
 IF OLD.state='READY' AND NEW.state='DISPATCHING' AND EXISTS(SELECT 1 FROM control.signing_rotation_command recovery
  WHERE recovery.participant_id=NEW.participant_id AND recovery.privacy_domain_id=NEW.privacy_domain_id
   AND recovery.original_operation_id=NEW.operation_id AND recovery.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1'
   AND recovery.state='ACCEPTED')
 THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-IN-PROGRESS'; END IF;
 IF OLD.state='READY' AND NEW.state='DISPATCHING' AND OLD.request->>'method' IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') AND EXISTS(
  SELECT 1 FROM control.signing_rotation_command c WHERE c.operation_id=NEW.operation_id AND c.state='WRITE_AMBIGUITY')
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-UNRESOLVED-FENCE'; END IF;
 IF OLD.state='READY' AND NEW.state='DISPATCHING' THEN
  IF OLD.request->>'method' IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') AND
   NOT coalesce((openpc.signing_attempt_authority_status(OLD.attempt_id)->>'unchangedLive')::boolean,false)
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-DISPATCH-AUTHORITY-CHANGED'; END IF;
  NEW.dispatched_at_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
 END IF;
 IF OLD.observation IS NOT NULL AND (NEW.observation IS DISTINCT FROM OLD.observation OR
    NEW.observation_digest IS DISTINCT FROM OLD.observation_digest) THEN RAISE EXCEPTION 'DATA-6020-ATTEMPT-OBSERVATION'; END IF;
 IF NEW.state='CANCELLED' THEN
  IF OLD.state<>'READY' OR OLD.dispatched_at_ns IS NOT NULL OR OLD.observation IS NOT NULL OR NOT EXISTS(
   SELECT 1 FROM control.signing_rotation_operation_evidence e WHERE e.participant_id=NEW.participant_id
    AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id AND e.kind='AUTHORITY_CHANGED_BEFORE_DISPATCH')
  THEN RAISE EXCEPTION 'DATA-6021-UNDISPATCHED-CANCELLATION'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.state='SUPERSEDED' THEN
  IF OLD.state NOT IN ('READY','DISPATCHING','OBSERVED') OR OLD.request->>'method'<>'SIGN_RECEIPT' OR NOT (EXISTS(
   SELECT 1 FROM control.signing_rotation_command c JOIN control.signing_rotation_history h
    ON h.participant_id=c.participant_id AND h.privacy_domain_id=c.privacy_domain_id AND h.operation_id=c.operation_id
   WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
    AND c.operation_id=openpc.current_operation_id() AND c.original_operation_id=NEW.operation_id
    AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND h.state='RECOVERING'
    AND h.receipt_id IS NOT NULL AND h.revision>NEW.from_revision) OR EXISTS(SELECT 1 FROM control.signing_continuation capability
     WHERE capability.participant_id=NEW.participant_id AND capability.privacy_domain_id=NEW.privacy_domain_id
      AND capability.operation_id=NEW.operation_id AND capability.operation_id=openpc.current_operation_id()
      AND capability.state='ISSUED' AND capability.expires_at_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000
      AND NOT EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=NEW.participant_id
       AND a.privacy_domain_id=NEW.privacy_domain_id AND a.receipt_id=NEW.attempt_id)))
  THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-SUPERSESSION'; END IF;
  RETURN NEW;
 END IF;
 IF NOT ((OLD.state='READY' AND NEW.state='DISPATCHING') OR (OLD.state='DISPATCHING' AND NEW.state='OBSERVED') OR (OLD.state='OBSERVED' AND NEW.state IN ('ACCEPTED','REJECTED')))
   THEN RAISE EXCEPTION 'DATA-6022-ATTEMPT-TRANSITION'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_attempt_guard ON control.signing_provider_attempt;
CREATE TRIGGER signing_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_provider_attempt
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_provider_attempt();
CREATE OR REPLACE FUNCTION openpc.guard_signing_command()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROTATION-COMMAND'; END IF;
 IF TG_OP='UPDATE' AND NEW.state='WRITE_AMBIGUITY' AND NOT EXISTS(
  SELECT 1 FROM control.signing_rotation_observation o WHERE o.participant_id=NEW.participant_id
   AND o.privacy_domain_id=NEW.privacy_domain_id AND o.operation_id=NEW.operation_id AND o.kind='UNRESOLVED')
 THEN RAISE EXCEPTION 'DATA-6021-AMBIGUITY-OBSERVATION-REQUIRED'; END IF;
 IF pg_has_role(current_user,'openpc_control_worker','MEMBER') AND
  (TG_OP<>'UPDATE' OR OLD.state<>'ACCEPTED' OR (NEW.state<>'WRITE_AMBIGUITY' AND NOT (NEW.state='FAILED' AND NEW.result_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH')))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-COMMAND-OWNER'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'ACCEPTED' THEN RAISE EXCEPTION 'DATA-6021-COMMAND-INITIAL'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' AND NEW.state IN ('SUCCEEDED','FAILED') AND EXISTS(
  SELECT 1 FROM control.signing_rotation_command recovery WHERE recovery.participant_id=NEW.participant_id
   AND recovery.privacy_domain_id=NEW.privacy_domain_id AND recovery.original_operation_id=NEW.operation_id
   AND recovery.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND recovery.state='ACCEPTED')
 THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-IN-PROGRESS'; END IF;
 IF OLD.recovery_observation_digest IS NOT NULL AND NEW.recovery_observation_digest IS DISTINCT FROM OLD.recovery_observation_digest
 THEN RAISE EXCEPTION 'DATA-6020-RECOVERY-OBSERVATION'; END IF;
 IF NEW.recovery_observation_digest IS NOT NULL AND NOT EXISTS(SELECT 1 FROM control.signing_rotation_observation o
  WHERE o.participant_id=NEW.participant_id AND o.privacy_domain_id=NEW.privacy_domain_id
   AND o.operation_id=NEW.original_operation_id AND o.attempt_id=NEW.recovery_attempt_id
   AND o.observation_digest=NEW.recovery_observation_digest AND o.kind IN ('NOT_FOUND','PROVIDER_RESULT'))
 THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-OBSERVATION'; END IF;
 IF NEW.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND NEW.state IN ('SUCCEEDED','FAILED') THEN
  IF NEW.operation_id IS DISTINCT FROM openpc.current_operation_id() OR
   (NEW.state='SUCCEEDED' AND (NEW.result_kind NOT IN ('NO_NEW_OBSERVATION','NEW_OBSERVATION','AUTHORITY_RENEWED','FORWARD_RECOVERY') OR NEW.result_kind IS NULL)) OR
   (NEW.state='FAILED' AND (NEW.result_kind NOT IN ('LOOKUP_UNAVAILABLE','SIGNATURE_UNAVAILABLE') OR NEW.result_kind IS NULL)) OR
   (NEW.result_kind='NO_NEW_OBSERVATION' AND (NEW.recovery_observation_digest IS DISTINCT FROM NEW.prior_observation_digest OR NEW.result_revision<>NEW.from_revision)) OR
   (NEW.result_kind='NEW_OBSERVATION' AND (NEW.recovery_observation_digest IS NULL OR NEW.recovery_observation_digest=NEW.prior_observation_digest
    OR NEW.result_revision<>NEW.from_revision+1 OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_history h
      WHERE h.participant_id=NEW.participant_id AND h.privacy_domain_id=NEW.privacy_domain_id
       AND h.operation_id=NEW.operation_id AND h.revision=NEW.result_revision AND h.state='RECOVERING' AND h.receipt_id IS NOT NULL))) OR
   (NEW.result_kind IN ('LOOKUP_UNAVAILABLE','SIGNATURE_UNAVAILABLE','NO_NEW_OBSERVATION') AND EXISTS(
    SELECT 1 FROM control.signing_rotation_history h WHERE h.participant_id=NEW.participant_id AND h.privacy_domain_id=NEW.privacy_domain_id AND h.operation_id=NEW.operation_id))
  THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-RESULT'; END IF;
  IF NEW.result_kind IN ('AUTHORITY_RENEWED','FORWARD_RECOVERY') AND NOT EXISTS(SELECT 1 FROM control.signing_authorization_generation g
   JOIN control.signing_rotation_history h ON h.participant_id=g.participant_id AND h.privacy_domain_id=g.privacy_domain_id
    AND h.operation_id=g.consumed_operation_id AND h.revision=g.result_revision
   WHERE g.generation_id=NEW.authorization_generation_id AND g.state='CONSUMED' AND g.consumed_operation_id=NEW.operation_id
    AND h.receipt_id IS NOT NULL AND h.event_id IS NULL AND NEW.result_revision=NEW.from_revision+1
    AND ((NEW.result_kind='AUTHORITY_RENEWED' AND h.state=h.prior_state) OR (NEW.result_kind='FORWARD_RECOVERY' AND h.state='RECOVERING')))
  THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-GENERATION-RESULT'; END IF;
 END IF;
 IF NEW.result_kind IN ('AUTHORITY_CHANGED_BEFORE_DISPATCH','NO_EFFECT_RETRYABLE') AND (NEW.state<>'FAILED'
  OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_operation_evidence e
   WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id AND e.kind=NEW.result_kind AND NEW.result_revision=(convert_from(e.preimage,'UTF8')::jsonb->>'currentRevision')::bigint))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-NO-EFFECT-EVIDENCE'; END IF;
 IF NEW.result_kind='PROVIDER_REJECTED' AND (NEW.state<>'FAILED' OR NOT EXISTS(
  SELECT 1 FROM control.signing_rotation_history h JOIN control.signing_provider_attempt p
   ON p.participant_id=h.participant_id AND p.privacy_domain_id=h.privacy_domain_id AND p.operation_id=h.operation_id
  WHERE h.participant_id=NEW.participant_id AND h.privacy_domain_id=NEW.privacy_domain_id AND h.operation_id=NEW.operation_id
   AND h.state='FAILED' AND h.revision=NEW.result_revision AND h.receipt_id IS NOT NULL
   AND p.request->>'method'<>'SIGN_RECEIPT' AND p.state='REJECTED' AND p.observation->>'outcome'='REJECTED'))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-FAILED-RECEIPT'; END IF;
 IF OLD.state IN ('SUCCEEDED','FAILED') OR
  (to_jsonb(NEW)-ARRAY['state','result_revision','updated_at','recovery_observation_digest','result_kind']) IS DISTINCT FROM
  (to_jsonb(OLD)-ARRAY['state','result_revision','updated_at','recovery_observation_digest','result_kind']) THEN RAISE EXCEPTION 'DATA-6020-COMMAND-IDENTITY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_command_guard ON control.signing_rotation_command;
CREATE TRIGGER signing_command_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_rotation_command
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_command();
DROP TRIGGER IF EXISTS qualified_inbox_immutable ON control.qualified_receipt_inbox;
CREATE TRIGGER qualified_inbox_immutable BEFORE UPDATE OR DELETE ON control.qualified_receipt_inbox
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE OR REPLACE FUNCTION openpc.guard_qualified_checkpoint()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-CHECKPOINT'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.last_sequence<>0 THEN RAISE EXCEPTION 'DATA-6021-CHECKPOINT-INITIAL'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['last_sequence','last_receipt_id']) IS DISTINCT FROM
  (to_jsonb(OLD)-ARRAY['last_sequence','last_receipt_id']) OR NEW.last_sequence<>OLD.last_sequence+1 OR NOT EXISTS(
  SELECT 1 FROM control.qualified_receipt_inbox i WHERE i.participant_id=NEW.participant_id AND i.privacy_domain_id=NEW.privacy_domain_id
   AND i.namespace=NEW.namespace AND i.aggregate_type=NEW.aggregate_type AND i.aggregate_id=NEW.aggregate_id
   AND i.sequence=NEW.last_sequence AND i.receipt_id=NEW.last_receipt_id) THEN RAISE EXCEPTION 'DATA-6021-CHECKPOINT-ACCEPTANCE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS qualified_checkpoint_guard ON control.qualified_receipt_checkpoint;
CREATE TRIGGER qualified_checkpoint_guard BEFORE INSERT OR UPDATE OR DELETE ON control.qualified_receipt_checkpoint
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_qualified_checkpoint();
CREATE OR REPLACE FUNCTION openpc.check_rotation_trust_admission()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE rotation control.signing_key_rotation%ROWTYPE; old_key control.business_signing_key%ROWTYPE; proofs integer;
BEGIN
 IF NEW.admission_kind<>'GOVERNED' THEN RETURN NULL; END IF;
 SELECT r.* INTO STRICT rotation FROM control.signing_key_rotation r
 WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
  AND NEW.admission_reference='urn:openpc:resource:'||r.rotation_id::text AND r.new_signer_id=NEW.signer_id
  AND r.state='VERIFIED' AND r.approval_request_id IS NOT NULL;
 SELECT * INTO STRICT old_key FROM control.business_signing_key
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND signer_id=rotation.old_signer_id;
 IF old_key.trust_digest<>rotation.old_trust_digest OR NEW.key_epoch<>old_key.key_epoch+1
  OR NEW.workload_credential_id<>old_key.workload_credential_id OR NEW.workload_credential_epoch<>old_key.workload_credential_epoch
  OR NEW.environment_id<>old_key.environment_id OR NEW.secret_reference<>rotation.request->>'newReference'
  OR NEW.environment_id<>rotation.environment_id OR NEW.workload_credential_id<>rotation.workload_credential_id
  OR NOT EXISTS(SELECT 1 FROM control.signing_provider_attempt a WHERE a.participant_id=NEW.participant_id
    AND a.privacy_domain_id=NEW.privacy_domain_id AND a.rotation_id=rotation.rotation_id AND a.to_state='PREPARED'
    AND a.state='ACCEPTED' AND a.observation->'descriptor'->>'fingerprint'=NEW.signer_id
    AND a.observation->'descriptor'->>'publicKeySpkiHex'=encode(NEW.public_key_spki_der,'hex')
    AND (a.observation->'descriptor'->>'validFromNs')::numeric=NEW.valid_from_ns
    AND (a.observation->'descriptor'->>'validUntilNs')::numeric=NEW.valid_until_ns)
 THEN RAISE EXCEPTION 'DATA-6021-GOVERNED-TRUST-BINDING'; END IF;
 SELECT count(*) INTO proofs FROM control.signing_provider_attempt a
 WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id
  AND a.rotation_id=rotation.rotation_id AND a.to_state='VERIFIED' AND a.state='ACCEPTED'
  AND a.request->>'method'='PROVE' AND a.request->>'rotationId'=rotation.rotation_id::text
  AND a.request->>'participantId'=NEW.participant_id::text AND a.request->>'privacyDomainId'=NEW.privacy_domain_id::text
  AND a.request->>'workloadCredentialId'=NEW.workload_credential_id::text
  AND a.request->>'environmentId'=NEW.environment_id AND a.request->>'challengeHex'=encode(NEW.trust_digest,'hex')
  AND a.request->>'expectedFingerprint'=CASE a.slot WHEN 'old' THEN old_key.signer_id WHEN 'new' THEN NEW.signer_id END
  AND a.observation->>'outcome'='SUCCEEDED' AND a.observation->>'attemptId'=a.attempt_id::text
  AND a.observation->>'requestDigest'='sha256:'||encode(a.request_digest,'hex')
  AND a.observation->'descriptor'->>'publicKeySpkiHex'=CASE a.slot WHEN 'old' THEN encode(old_key.public_key_spki_der,'hex') WHEN 'new' THEN encode(NEW.public_key_spki_der,'hex') END;
 IF proofs<>2 THEN RAISE EXCEPTION 'DATA-6021-GOVERNED-DUAL-PROOF'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS business_rotation_admission ON control.business_signing_key;
CREATE CONSTRAINT TRIGGER business_rotation_admission AFTER INSERT ON control.business_signing_key
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_rotation_trust_admission();

CREATE OR REPLACE FUNCTION openpc.signing_observation_preimage(a control.signing_provider_attempt,p_kind text)
RETURNS bytea LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT convert_to(jsonb_build_object('schema','pc.control.signing-observation.v1',
  'participantId',a.participant_id,'privacyDomainId',a.privacy_domain_id,'rotationId',a.rotation_id,
  'operationId',a.operation_id,'attemptId',a.attempt_id,'method',a.request->>'method',
  'requestDigest',encode(a.request_digest,'hex'),'kind',p_kind,
  'providerObservationDigest',CASE WHEN p_kind='PROVIDER_RESULT' THEN encode(a.observation_digest,'hex') ELSE NULL END)::text,'UTF8')
$$;
CREATE OR REPLACE FUNCTION openpc.guard_signing_observation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.signing_provider_attempt%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM control.signing_provider_attempt WHERE attempt_id=NEW.attempt_id
  AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
  AND rotation_id=NEW.rotation_id AND operation_id=NEW.operation_id;
 IF (NEW.operation_id IS DISTINCT FROM openpc.current_operation_id() AND NOT EXISTS(
  SELECT 1 FROM control.signing_rotation_command c WHERE c.participant_id=NEW.participant_id
   AND c.privacy_domain_id=NEW.privacy_domain_id AND c.operation_id=openpc.current_operation_id()
   AND c.original_operation_id=NEW.operation_id AND c.recovery_attempt_id=NEW.attempt_id
   AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND c.state='ACCEPTED')) OR
  openpc.current_action_intent_id() NOT IN ('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1') OR
  (NEW.kind='NOT_FOUND' AND openpc.current_action_intent_id()<>'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1')
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-OBSERVATION-CONTEXT'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR
  NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id() OR
  NEW.observation_preimage IS DISTINCT FROM openpc.signing_observation_preimage(a,NEW.kind) OR
  NEW.observed_at_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000 OR
  (NEW.kind IN ('UNRESOLVED','NOT_FOUND') AND (a.state<>'DISPATCHING' OR a.observation IS NOT NULL)) OR
  (NEW.kind='PROVIDER_RESULT' AND (a.state NOT IN ('OBSERVED','ACCEPTED','REJECTED') OR a.observation IS NULL))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-OBSERVATION-BINDING'; END IF;
 IF pg_has_role(current_user,'openpc_control_worker','MEMBER') AND
  (a.request->>'method' NOT IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') OR NEW.kind='NOT_FOUND')
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-OBSERVATION-OWNER'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_observation_binding ON control.signing_rotation_observation;
CREATE TRIGGER signing_observation_binding BEFORE INSERT ON control.signing_rotation_observation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_observation();
CREATE OR REPLACE FUNCTION openpc.record_signing_observation(p_attempt uuid,p_kind text)
RETURNS TABLE(observation_id uuid,observation_digest bytea) LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.signing_provider_attempt%ROWTYPE; preimage bytea;
BEGIN
 SELECT * INTO STRICT a FROM control.signing_provider_attempt WHERE attempt_id=p_attempt
  AND participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id();
 preimage:=openpc.signing_observation_preimage(a,p_kind);
 INSERT INTO control.signing_rotation_observation(participant_id,privacy_domain_id,rotation_id,operation_id,attempt_id,kind,observation_preimage,observation_digest)
 VALUES(a.participant_id,a.privacy_domain_id,a.rotation_id,a.operation_id,a.attempt_id,p_kind,preimage,sha256(preimage))
 ON CONFLICT ON CONSTRAINT signing_observation_material_uq DO NOTHING;
 RETURN QUERY SELECT o.observation_id,o.observation_digest FROM control.signing_rotation_observation o
 WHERE o.participant_id=a.participant_id AND o.privacy_domain_id=a.privacy_domain_id AND o.attempt_id=a.attempt_id
  AND o.observation_digest=sha256(preimage);
END $$;
CREATE OR REPLACE FUNCTION openpc.record_signing_provider_result()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.record_signing_observation(NEW.attempt_id,'PROVIDER_RESULT');
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS signing_provider_result_observation ON control.signing_provider_attempt;
CREATE TRIGGER signing_provider_result_observation AFTER UPDATE ON control.signing_provider_attempt
 FOR EACH ROW WHEN (OLD.observation IS NULL AND NEW.observation IS NOT NULL
  AND NEW.request->>'method'<>'SIGN_RECEIPT') EXECUTE FUNCTION openpc.record_signing_provider_result();
CREATE OR REPLACE FUNCTION openpc.signing_admission_open(p_participant uuid,p_privacy uuid,p_signer text,p_operation uuid)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT NOT EXISTS(SELECT 1 FROM control.signing_key_rotation r JOIN control.signing_rotation_command c
  ON c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id AND c.rotation_id=r.rotation_id
  WHERE r.participant_id=p_participant AND r.privacy_domain_id=p_privacy AND p_signer IN(r.old_signer_id,r.new_signer_id)
   AND c.state='WRITE_AMBIGUITY' AND c.operation_id<>p_operation AND NOT EXISTS(
    SELECT 1 FROM control.signing_rotation_command recovery WHERE recovery.participant_id=c.participant_id
     AND recovery.privacy_domain_id=c.privacy_domain_id AND recovery.rotation_id=c.rotation_id
     AND recovery.operation_id=p_operation AND recovery.original_operation_id=c.operation_id
     AND recovery.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND recovery.state='ACCEPTED'))
$$;
-- A retained exact attempt may record its own pre-fence result. This never admits a new attempt.
CREATE OR REPLACE FUNCTION openpc.retained_signing_admission_matches(
 p_participant uuid,p_privacy uuid,p_signer text,p_operation uuid,p_reserved numeric,p_current numeric)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT p_reserved>0 AND (p_current=p_reserved OR (p_current=p_reserved+1 AND EXISTS(
  SELECT 1 FROM control.signing_rotation_command c JOIN control.signing_key_rotation r
   ON r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.rotation_id=c.rotation_id
  WHERE c.participant_id=p_participant AND c.privacy_domain_id=p_privacy AND c.operation_id=p_operation
   AND c.state IN ('WRITE_AMBIGUITY','SUCCEEDED','FAILED') AND p_signer IN(r.old_signer_id,r.new_signer_id)
   AND EXISTS(SELECT 1 FROM control.signing_rotation_observation o WHERE o.participant_id=c.participant_id
    AND o.privacy_domain_id=c.privacy_domain_id AND o.operation_id=c.operation_id AND o.kind='UNRESOLVED'))))
$$;
CREATE OR REPLACE FUNCTION openpc.record_signing_ambiguity(p_attempt uuid)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.signing_provider_attempt%ROWTYPE; c control.signing_rotation_command%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM control.signing_provider_attempt WHERE attempt_id=p_attempt
  AND participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id();
 -- Match receipt-writer lock order, so a preceding synchronous signature commits before this fence.
 PERFORM 1 FROM control.business_signing_selection s JOIN control.business_signing_key k USING(participant_id,privacy_domain_id,signer_id)
 WHERE s.participant_id=a.participant_id AND s.privacy_domain_id=a.privacy_domain_id
  AND s.environment_id=a.request->>'environmentId' AND k.workload_credential_id=(a.request->>'workloadCredentialId')::uuid
 ORDER BY s.profile_digest FOR UPDATE OF s;
 SELECT * INTO STRICT c FROM control.signing_rotation_command WHERE operation_id=a.operation_id FOR UPDATE;
 SELECT * INTO STRICT a FROM control.signing_provider_attempt WHERE attempt_id=p_attempt FOR UPDATE;
 IF c.state IN ('SUCCEEDED','FAILED') OR a.state<>'DISPATCHING' THEN RETURN; END IF;
 PERFORM openpc.record_signing_observation(p_attempt,'UNRESOLVED');
 IF c.state='ACCEPTED' THEN
  UPDATE control.signing_rotation_command SET state='WRITE_AMBIGUITY',updated_at=clock_timestamp() WHERE operation_id=c.operation_id;
  UPDATE control.business_signing_selection s SET admission_version=s.admission_version+1
   FROM control.signing_key_rotation r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id
    AND r.rotation_id=c.rotation_id AND s.participant_id=r.participant_id AND s.privacy_domain_id=r.privacy_domain_id
    AND s.signer_id IN(r.old_signer_id,r.new_signer_id);
 END IF;
END $$;


CREATE OR REPLACE FUNCTION openpc.guard_signing_command_authorization()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE snapshot jsonb; bound jsonb; expected jsonb; rotation control.signing_key_rotation%ROWTYPE;
 evidence control.mutation_evidence%ROWTYPE; runtime_payload jsonb; approval control.approval_request%ROWTYPE;
 checker control.approval_decision_record%ROWTYPE; now_ns numeric;
 generation control.signing_authorization_generation%ROWTYPE; effects jsonb;
BEGIN
 snapshot:=convert_from(NEW.authorization_snapshot,'UTF8')::jsonb;
 now_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND revision=NEW.from_revision;
 effects:=openpc.signing_transition_effects(NEW.action_intent_id,rotation.state,NEW.to_state);
 IF effects IS NULL OR (effects->>'resumeFrom' IS NOT NULL AND effects->>'resumeFrom' IS DISTINCT FROM rotation.recovery_from_state)
 THEN RAISE EXCEPTION 'DATA-6022-SIGNING-COMMAND-MATRIX'; END IF;
 IF NEW.authorization_generation_id IS NULL THEN
  SELECT generation_id INTO NEW.authorization_generation_id FROM control.signing_authorization_generation
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id
    AND state='CONSUMED' ORDER BY result_revision DESC LIMIT 1;
 END IF;
 IF NEW.authorization_generation_id IS NULL THEN
  NEW.approval_request_id:=rotation.approval_request_id;
  NEW.approval_candidate_digest:=rotation.candidate_digest;
 ELSE
  SELECT * INTO STRICT generation FROM control.signing_authorization_generation WHERE generation_id=NEW.authorization_generation_id
   AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id;
  IF generation.state='STAGED' THEN
   IF generation.action_intent_id<>NEW.action_intent_id OR generation.from_revision<>NEW.from_revision OR generation.input_digest<>NEW.input_digest
    OR generation.target_state<>NEW.to_state OR NOT EXISTS(SELECT 1 FROM control.mutation_candidate candidate
     WHERE candidate.mutation_candidate_id=generation.candidate_id AND candidate.state='APPROVED'
      AND candidate.candidate_document->'context'=openpc.signing_governance_context(NEW.rotation_id,NEW.action_intent_id))
   THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GOVERNANCE-STALE'; END IF;
  ELSIF generation.generation_id IS DISTINCT FROM (SELECT generation_id FROM control.signing_authorization_generation
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id
    AND state='CONSUMED' ORDER BY result_revision DESC LIMIT 1)
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GENERATION-STALE'; END IF;
  SELECT a.approval_request_id,a.subject_digest INTO STRICT NEW.approval_request_id,NEW.approval_candidate_digest
   FROM control.approval_request a WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id
    AND a.subject_id=generation.candidate_id AND a.subject_digest=generation.candidate_digest
    AND a.state='APPROVED' AND a.expires_at>clock_timestamp();
 END IF;
 IF NEW.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND generation.state='STAGED' THEN
  IF NEW.original_operation_id IS DISTINCT FROM generation.original_operation_id
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GOVERNANCE-ORIGINAL'; END IF;
 ELSIF NEW.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' THEN
  IF NEW.to_state<>'RECOVERING' OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_command original
   JOIN control.signing_provider_attempt attempt ON attempt.operation_id=original.operation_id
    AND attempt.participant_id=original.participant_id AND attempt.privacy_domain_id=original.privacy_domain_id
   JOIN LATERAL (SELECT o.observation_digest FROM control.signing_rotation_observation o
    WHERE o.participant_id=attempt.participant_id AND o.privacy_domain_id=attempt.privacy_domain_id AND o.attempt_id=attempt.attempt_id
    ORDER BY o.observed_at_ns DESC,o.observation_id DESC LIMIT 1) prior ON true
   WHERE original.participant_id=NEW.participant_id AND original.privacy_domain_id=NEW.privacy_domain_id
    AND original.rotation_id=NEW.rotation_id AND original.operation_id=NEW.original_operation_id
    AND original.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' AND original.state='WRITE_AMBIGUITY'
    AND attempt.attempt_id=NEW.recovery_attempt_id AND attempt.state IN ('DISPATCHING','OBSERVED')
    AND prior.observation_digest=NEW.prior_observation_digest)
  THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-EXACT-PENDING-ATTEMPT'; END IF;
 ELSE
  IF generation.state IS DISTINCT FROM 'STAGED' AND EXISTS(SELECT 1 FROM control.signing_rotation_command denied WHERE denied.participant_id=NEW.participant_id
   AND denied.privacy_domain_id=NEW.privacy_domain_id AND denied.rotation_id=NEW.rotation_id AND denied.from_revision=NEW.from_revision
   AND denied.state='FAILED' AND denied.result_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH')
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-FRESH-APPROVAL-REQUIRED'; END IF;
  IF EXISTS(SELECT 1 FROM control.signing_rotation_authority_hold h WHERE h.participant_id=NEW.participant_id
   AND h.privacy_domain_id=NEW.privacy_domain_id AND h.rotation_id=NEW.rotation_id AND h.state='ACTIVE')
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-AUTHORITY-HOLD'; END IF;
  IF NOT openpc.signing_admission_open(NEW.participant_id,NEW.privacy_domain_id,rotation.old_signer_id,NEW.operation_id)
   OR NOT openpc.signing_admission_open(NEW.participant_id,NEW.privacy_domain_id,rotation.new_signer_id,NEW.operation_id)
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-UNRESOLVED-ADMISSION'; END IF;
 END IF;
 SELECT * INTO STRICT evidence FROM control.mutation_evidence WHERE mutation_evidence_id=NEW.authorization_evidence_id
  AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id
  AND principal_id=NEW.principal_id AND action_intent_id=NEW.action_intent_id AND candidate_digest=NEW.input_digest
  AND aggregate_type='signing-key-rotation' AND aggregate_id=NEW.rotation_id AND aggregate_version=NEW.from_revision
  AND evidence_role='AUTHORIZATION_INPUT' AND evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
  AND evidence_digest=sha256(evidence_cbor);
 IF NEW.action_intent_id NOT IN ('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1')
  OR openpc.current_action_intent_id() IS DISTINCT FROM NEW.action_intent_id
  OR openpc.current_operation_id() IS DISTINCT FROM NEW.operation_id
  OR evidence.catalog_operation_id IS DISTINCT FROM (CASE NEW.action_intent_id
   WHEN 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' THEN 'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION'
   ELSE 'OPS-OP-RECOVER-SIGNING-KEY-ROTATION' END) THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORIZATION-ACTION'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=NEW.participant_id
  AND i.privacy_domain_id=NEW.privacy_domain_id AND i.operation_id=NEW.operation_id AND i.principal_id=NEW.principal_id
  AND i.idempotency_key=NEW.idempotency_key AND i.input_digest=NEW.input_digest AND i.expected_aggregate_version=NEW.from_revision
  AND i.catalog_operation_id=evidence.catalog_operation_id AND i.action_intent_id=NEW.action_intent_id AND i.terminal_state IS NULL)
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-IDEMPOTENCY-AUTHORIZATION'; END IF;
 IF (effects->>'revoke')::boolean AND NOT EXISTS(
  SELECT 1 FROM control.qualified_receipt_inbox i JOIN control.audit_occurrence a
   ON a.participant_id=i.participant_id AND a.privacy_domain_id=i.privacy_domain_id AND a.receipt_id=i.receipt_id
  JOIN control.business_signing_grant g ON g.participant_id=a.participant_id AND g.privacy_domain_id=a.privacy_domain_id
   AND g.signer_id=a.signer_id AND g.profile_digest=a.profile_digest
  WHERE i.participant_id=NEW.participant_id AND i.privacy_domain_id=NEW.privacy_domain_id AND i.receipt_id=NEW.consumer_receipt_id
   AND i.signer_id=rotation.new_signer_id AND a.signer_id=rotation.new_signer_id
   AND a.environment_id=rotation.environment_id AND a.recorded_at_ns>=rotation.cutover_at_ns
   AND ((rotation.request->>'signerRole'='BUSINESS_EFFECT' AND i.namespace='CONTROL_BUSINESS_TRANSITION_V1' AND a.aggregate_type IN ('indexer-profile','evidence-hold','retention-policy','evidence-deletion','store-retirement','runtime-artifact-disposition','work-item','notification','notification-endpoint')) OR
    (rotation.request->>'signerRole'='LIFECYCLE_EVIDENCE' AND i.namespace='CONTROL_SIGNING_LIFECYCLE_V1'
      AND a.aggregate_type='signing-key-rotation' AND a.aggregate_id=NEW.rotation_id
      AND openpc.business_cbor(a.after_state_preimage)->8->>'0'='OBSERVING')))
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-REVOKE-REQUIRES-CONSUMER'; END IF;
 IF snapshot IS DISTINCT FROM jsonb_build_object('schema','pc.control.precommit-authority-snapshot.v1',
  'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'operationId',NEW.operation_id::text,
  'recordedAtNs',snapshot->'recordedAtNs','decision','ALLOW','authorities',snapshot->'authorities','dependencies',snapshot->'dependencies')
  OR jsonb_typeof(snapshot->'authorities') IS DISTINCT FROM 'array' OR jsonb_array_length(snapshot->'authorities')<>3
  OR jsonb_typeof(snapshot->'recordedAtNs') IS DISTINCT FROM 'string'
  OR NOT ((snapshot->>'recordedAtNs') ~ '^[0-9]{1,20}$') OR (snapshot->>'recordedAtNs')::numeric>now_ns
  OR snapshot->'dependencies' IS DISTINCT FROM jsonb_build_object('assignment',snapshot->'dependencies'->'assignment','authority_envelope',snapshot->'dependencies'->'authority_envelope','authority_role',snapshot->'dependencies'->'authority_role','credential',snapshot->'dependencies'->'credential','delegation',snapshot->'dependencies'->'delegation','participant',snapshot->'dependencies'->'participant','principal',snapshot->'dependencies'->'principal','privacy_domain',snapshot->'dependencies'->'privacy_domain','session',snapshot->'dependencies'->'session')
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORIZATION-SNAPSHOT'; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('assignment_id',owner.assignment_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'authority_group_id',owner.authority_group_id::text,'role_id',owner.role_id::text,'authority_envelope_id',owner.authority_envelope_id::text,'delegation_epoch',owner.delegation_epoch::text,'scope_digest',owner.scope_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'runtime_capability_ids',owner.runtime_capability_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'valid_during',owner.valid_during::text,'state',owner.state::text,'created_by_principal_id',owner.created_by_principal_id::text,'row_version',owner.row_version::text) ORDER BY owner.assignment_id),'[]'::jsonb)
 INTO expected FROM control.assignment owner WHERE owner.participant_id=NEW.participant_id
  AND owner.assignment_id IN(SELECT (d->>'assignment_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'assignment') d);
 IF snapshot->'dependencies'->'assignment' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-ACTUAL-ROW'; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('authority_envelope_id',owner.authority_envelope_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'maker_principal_id',owner.maker_principal_id::text,'checker_principal_id',owner.checker_principal_id::text,'authority_epoch',owner.authority_epoch::text,'delegation_epoch',owner.delegation_epoch::text,'state',owner.state::text,'valid_from',owner.valid_from::text,'valid_until',owner.valid_until::text,'semantic_digest',owner.semantic_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'runtime_capability_ids',owner.runtime_capability_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'row_version',owner.row_version::text) ORDER BY owner.authority_envelope_id),'[]'::jsonb)
 INTO expected FROM control.authority_envelope owner WHERE owner.participant_id=NEW.participant_id
  AND owner.authority_envelope_id IN(SELECT (d->>'authority_envelope_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'authority_envelope') d);
 IF snapshot->'dependencies'->'authority_envelope' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-ACTUAL-ROW'; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('authority_role_id',owner.authority_role_id::text,'participant_id',owner.participant_id::text,'role_id',owner.role_id::text,'action_intent_ids',owner.action_intent_ids::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.authority_role_id),'[]'::jsonb)
 INTO expected FROM control.authority_role owner WHERE owner.participant_id=NEW.participant_id
  AND owner.authority_role_id IN(SELECT (d->>'authority_role_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'authority_role') d);
 IF snapshot->'dependencies'->'authority_role' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-ACTUAL-ROW'; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('credential_id',owner.credential_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'kind',owner.kind::text,'state',owner.state::text,'credential_epoch',owner.credential_epoch::text,'valid_from',owner.valid_from::text,'valid_until',owner.valid_until::text,'public_key_digest',owner.public_key_digest::text,'row_version',owner.row_version::text) ORDER BY owner.credential_id),'[]'::jsonb)
 INTO expected FROM control.credential owner WHERE owner.participant_id=NEW.participant_id
  AND owner.credential_id IN(SELECT (d->>'credential_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'credential') d);
 IF snapshot->'dependencies'->'credential' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-ACTUAL-ROW'; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('delegation_id',owner.delegation_id::text,'participant_id',owner.participant_id::text,'parent_assignment_id',owner.parent_assignment_id::text,'parent_delegation_id',owner.parent_delegation_id::text,'grantor_principal_id',owner.grantor_principal_id::text,'delegate_principal_id',owner.delegate_principal_id::text,'delegation_epoch',owner.delegation_epoch::text,'scope_digest',owner.scope_digest::text,'privacy_domain_ids',owner.privacy_domain_ids::text,'action_intent_ids',owner.action_intent_ids::text,'runtime_capability_ids',owner.runtime_capability_ids::text,'resource_ids',owner.resource_ids::text,'risk_classes',owner.risk_classes::text,'maker_checker_required',owner.maker_checker_required::text,'step_up_required',owner.step_up_required::text,'onward_delegation_depth',owner.onward_delegation_depth::text,'valid_during',owner.valid_during::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.delegation_id),'[]'::jsonb)
 INTO expected FROM control.delegation owner WHERE owner.participant_id=NEW.participant_id
  AND owner.delegation_id IN(SELECT (d->>'delegation_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'delegation') d);
 IF snapshot->'dependencies'->'delegation' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-ACTUAL-ROW'; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('participant_id',owner.participant_id::text,'state',owner.state::text,'authority_epoch',owner.authority_epoch::text,'row_version',owner.row_version::text) ORDER BY owner.participant_id),'[]'::jsonb)
 INTO expected FROM control.participant owner WHERE owner.participant_id=NEW.participant_id
  AND owner.participant_id IN(SELECT (d->>'participant_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'participant') d);
 IF snapshot->'dependencies'->'participant' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-ACTUAL-ROW'; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('principal_id',owner.principal_id::text,'participant_id',owner.participant_id::text,'kind',owner.kind::text,'state',owner.state::text,'authority_epoch',owner.authority_epoch::text,'row_version',owner.row_version::text) ORDER BY owner.principal_id),'[]'::jsonb)
 INTO expected FROM control.principal owner WHERE owner.participant_id=NEW.participant_id
  AND owner.principal_id IN(SELECT (d->>'principal_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'principal') d);
 IF snapshot->'dependencies'->'principal' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-ACTUAL-ROW'; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('privacy_domain_id',owner.privacy_domain_id::text,'participant_id',owner.participant_id::text,'state',owner.state::text,'row_version',owner.row_version::text) ORDER BY owner.privacy_domain_id),'[]'::jsonb)
 INTO expected FROM control.privacy_domain owner WHERE owner.participant_id=NEW.participant_id
  AND owner.privacy_domain_id IN(SELECT (d->>'privacy_domain_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'privacy_domain') d);
 IF snapshot->'dependencies'->'privacy_domain' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-ACTUAL-ROW'; END IF;

 SELECT coalesce(jsonb_agg(jsonb_build_object('session_id',owner.session_id::text,'participant_id',owner.participant_id::text,'principal_id',owner.principal_id::text,'state',owner.state::text,'participant_epoch',owner.participant_epoch::text,'authority_epoch',owner.authority_epoch::text,'delegation_epoch',owner.delegation_epoch::text,'session_epoch',owner.session_epoch::text,'issued_at',owner.issued_at::text,'idle_expires_at',owner.idle_expires_at::text,'absolute_expires_at',owner.absolute_expires_at::text,'step_up_verified_at',owner.step_up_verified_at::text,'row_version',owner.row_version::text) ORDER BY owner.session_id),'[]'::jsonb)
 INTO expected FROM control.session owner WHERE owner.participant_id=NEW.participant_id
  AND owner.session_id IN(SELECT (d->>'session_id')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'session') d);
 IF snapshot->'dependencies'->'session' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-ACTUAL-ROW'; END IF;
 runtime_payload:=openpc.business_cbor(evidence.evidence_cbor);
 IF jsonb_typeof(runtime_payload->'8') IS DISTINCT FROM 'number' OR jsonb_typeof(runtime_payload->'9') IS DISTINCT FROM 'number' OR
    (runtime_payload->>'8')::numeric>(snapshot->>'recordedAtNs')::numeric OR
    (runtime_payload->>'9')::numeric<=now_ns THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORIZATION-EXPIRED'; END IF;
 bound:=snapshot->'authorities'->0;
 IF bound->>'principalId' IS DISTINCT FROM NEW.principal_id::text OR bound->>'actionIntentId' IS DISTINCT FROM NEW.action_intent_id
  OR bound->>'resourceId' IS DISTINCT FROM NEW.rotation_id::text OR bound->>'assignmentId' IS DISTINCT FROM evidence.bound_assignment_id::text
  OR bound->>'authorityEnvelopeId' IS DISTINCT FROM evidence.bound_authority_envelope_id::text
  OR bound->>'authorityEpoch' IS DISTINCT FROM evidence.bound_envelope_epoch::text
  OR bound->>'principalEpoch' IS DISTINCT FROM evidence.bound_principal_epoch::text
  OR bound->>'participantEpoch' IS DISTINCT FROM evidence.bound_participant_epoch::text
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-CALLER-AUTHORIZATION'; END IF;
 SELECT * INTO STRICT approval FROM control.approval_request WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND approval_request_id=NEW.approval_request_id AND state='APPROVED' AND expires_at>clock_timestamp();
 SELECT jsonb_object_agg(key,value) INTO expected FROM jsonb_each(approval.maker_authority)
  WHERE key=ANY(ARRAY['principalId','sessionId','sessionEpoch','participantEpoch','principalEpoch','assignmentId','assignmentRowVersion',
   'authorityEnvelopeId','authorityEpoch','delegationEpoch','privacyDomainId','actionIntentId','resourceId']);
 IF snapshot->'authorities'->1 IS DISTINCT FROM expected OR
  (approval.maker_authority ? 'participantId' AND approval.maker_authority->>'participantId' IS DISTINCT FROM NEW.participant_id::text)
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-MAKER-AUTHORIZATION'; END IF;
 SELECT * INTO STRICT checker FROM control.approval_decision_record WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND approval_request_id=approval.approval_request_id AND decision='APPROVE'
  AND approver_principal_id<>approval.maker_principal_id AND candidate_digest=NEW.approval_candidate_digest;
 IF snapshot->'authorities'->2 IS DISTINCT FROM jsonb_build_object('principalId',checker.approver_principal_id::text,
  'sessionId',checker.approver_session_id::text,'sessionEpoch',checker.approver_session_epoch::text,
  'participantEpoch',checker.approver_participant_epoch::text,'principalEpoch',checker.approver_principal_epoch::text,
  'assignmentId',checker.approver_assignment_id::text,'assignmentRowVersion',checker.approver_assignment_row_version::text,
  'authorityEnvelopeId',checker.approver_authority_envelope_id::text,'authorityEpoch',checker.approver_envelope_epoch::text,
  'delegationEpoch',checker.approver_delegation_epoch::text,'privacyDomainId',NEW.privacy_domain_id::text,
  'actionIntentId','ACT-POLICY_APPROVE_REQUEST-V1','resourceId',approval.approval_request_id::text)
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-CHECKER-AUTHORIZATION'; END IF;
 FOR bound IN SELECT * FROM jsonb_array_elements(snapshot->'authorities') LOOP
  IF bound->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text OR
    NOT (snapshot->'dependencies'->'participant' @> jsonb_build_array(jsonb_build_object('participant_id',NEW.participant_id::text,'state','ACTIVE','authority_epoch',bound->>'participantEpoch'))) OR
    NOT (snapshot->'dependencies'->'privacy_domain' @> jsonb_build_array(jsonb_build_object('privacy_domain_id',NEW.privacy_domain_id::text,'state','ACTIVE'))) OR
    NOT (snapshot->'dependencies'->'principal' @> jsonb_build_array(jsonb_build_object('principal_id',bound->>'principalId','state','ACTIVE','authority_epoch',bound->>'principalEpoch'))) OR
    NOT (snapshot->'dependencies'->'session' @> jsonb_build_array(jsonb_build_object('session_id',bound->>'sessionId','principal_id',bound->>'principalId','state','ACTIVE','session_epoch',bound->>'sessionEpoch'))) OR
    NOT (snapshot->'dependencies'->'assignment' @> jsonb_build_array(jsonb_build_object('assignment_id',bound->>'assignmentId','state','ACTIVE','row_version',bound->>'assignmentRowVersion'))) OR
    NOT (snapshot->'dependencies'->'authority_envelope' @> jsonb_build_array(jsonb_build_object('authority_envelope_id',bound->>'authorityEnvelopeId','state','ACTIVE','authority_epoch',bound->>'authorityEpoch')))
   THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-LIVE-PATH'; END IF;
 END LOOP;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_command_authorization ON control.signing_rotation_command;
CREATE TRIGGER signing_command_authorization BEFORE INSERT ON control.signing_rotation_command
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_command_authorization();


CREATE OR REPLACE FUNCTION openpc.rotation_history_preimage(
 p_rotation control.signing_key_rotation,p_prior_state text,p_operation uuid,p_event uuid,p_receipt uuid,p_evidence uuid,
 p_attester jsonb DEFAULT NULL,p_receipt_ordinal numeric DEFAULT NULL)
RETURNS bytea LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE prior bytea; candidate jsonb; approval jsonb; attempts jsonb; selections jsonb; acknowledgements jsonb; command jsonb; retained_selections jsonb; effects jsonb;
BEGIN
 IF p_receipt IS NOT NULL AND p_attester IS NULL THEN
  SELECT jsonb_build_object('signerId',a.signer_id,'keyEpoch',a.key_epoch,'trustDigest',encode(a.signer_trust_digest,'hex'),
   'selectionVersion',a.selection_version,'admissionVersion',a.admission_version,'fenceGeneration',a.fence_generation),s.receipt_ordinal
  INTO STRICT p_attester,p_receipt_ordinal FROM control.receipt_signing_attempt a
  JOIN control.signing_rotation_attestation s ON s.attempt_id=a.attempt_id
  WHERE a.participant_id=p_rotation.participant_id AND a.privacy_domain_id=p_rotation.privacy_domain_id
   AND a.operation_id=p_operation AND a.attempt_id=p_receipt AND s.from_revision=p_rotation.revision-1;
 END IF;
 SELECT jsonb_build_object('operationId',c.operation_id,'actionIntentId',c.action_intent_id,'actionIntentDigest',encode(c.action_intent_digest,'hex'),
  'inputDigest',encode(c.input_digest,'hex'),'fromRevision',c.from_revision,'toState',c.to_state,
  'authorizationEvidenceId',c.authorization_evidence_id,'authorizationSnapshotDigest',encode(c.authorization_snapshot_digest,'hex'),
  'consumerReceiptId',c.consumer_receipt_id,'originalOperationId',c.original_operation_id,'recoveryAttemptId',c.recovery_attempt_id,
  'authorizationGenerationId',c.authorization_generation_id,'approvalRequestId',c.approval_request_id,'approvalCandidateDigest',encode(c.approval_candidate_digest,'hex'),
  'priorObservationDigest',encode(c.prior_observation_digest,'hex'),'recoveryObservationDigest',encode(c.recovery_observation_digest,'hex'))
 INTO command FROM control.signing_rotation_command c WHERE c.participant_id=p_rotation.participant_id AND c.privacy_domain_id=p_rotation.privacy_domain_id AND c.operation_id=p_operation;
 IF command IS NOT NULL THEN
  effects:=openpc.signing_transition_effects(command->>'actionIntentId',p_prior_state,p_rotation.state);
  IF effects IS NULL THEN RAISE EXCEPTION 'DATA-6022-SIGNING-HISTORY-MATRIX'; END IF;
 END IF;
 SELECT history_digest INTO prior FROM control.signing_rotation_history
 WHERE participant_id=p_rotation.participant_id AND privacy_domain_id=p_rotation.privacy_domain_id
  AND rotation_id=p_rotation.rotation_id AND revision=p_rotation.revision-1;
 SELECT jsonb_build_object('id',c.mutation_candidate_id,'digest',encode(c.candidate_digest,'hex'),
  'maker',c.maker_principal_id,'session',c.maker_session_id,'sessionEpoch',c.maker_session_epoch,
  'participantEpoch',c.maker_participant_epoch,'principalEpoch',c.maker_principal_epoch,
  'assignment',c.maker_assignment_id,'assignmentVersion',c.maker_assignment_row_version,
  'envelope',c.maker_authority_envelope_id,'authorityEpoch',c.maker_authority_epoch,'delegationEpoch',c.maker_delegation_epoch)
 INTO STRICT candidate FROM control.mutation_candidate c WHERE c.participant_id=p_rotation.participant_id
  AND c.privacy_domain_id=p_rotation.privacy_domain_id AND c.resource_id=p_rotation.rotation_id
  AND c.candidate_digest=p_rotation.candidate_digest AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1';
 IF p_rotation.approval_request_id IS NOT NULL THEN
  SELECT jsonb_build_object('id',a.approval_request_id,'candidateDigest',encode(a.subject_digest,'hex'),
   'maker',a.maker_principal_id,'makerAuthority',a.maker_authority,'approvedOperation',p_rotation.approved_operation_id,
   'checker',d.approver_principal_id,'decision',d.approval_decision_id,'session',d.approver_session_id,
   'sessionEpoch',d.approver_session_epoch,'participantEpoch',d.approver_participant_epoch,
   'principalEpoch',d.approver_principal_epoch,'assignment',d.approver_assignment_id,
   'assignmentVersion',d.approver_assignment_row_version,'envelope',d.approver_authority_envelope_id,
   'authorityEpoch',d.approver_envelope_epoch,'delegationEpoch',d.approver_delegation_epoch,
   'signerCredential',d.signer_credential_id,'signerEpoch',d.signer_credential_epoch)
  INTO STRICT approval FROM control.approval_request a JOIN control.approval_decision_record d
   ON d.participant_id=a.participant_id AND d.privacy_domain_id=a.privacy_domain_id AND d.approval_request_id=a.approval_request_id
  WHERE a.participant_id=p_rotation.participant_id AND a.privacy_domain_id=p_rotation.privacy_domain_id
   AND a.approval_request_id=p_rotation.approval_request_id AND d.decision='APPROVE';
 END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('attemptId',a.attempt_id,'operationId',a.operation_id,'revision',a.from_revision,
  'fromState',a.from_state,'toState',a.to_state,'slot',a.slot,'method',a.request->>'method',
  'requestDigest',encode(a.request_digest,'hex'),'observationDigest',encode(a.observation_digest,'hex'),
  'state',CASE WHEN a.operation_id=p_operation AND a.state='OBSERVED' AND effects->>'kind' IN ('ADVANCE','FAILURE')
   THEN CASE WHEN effects->>'kind'='FAILURE' THEN 'REJECTED' ELSE 'ACCEPTED' END ELSE a.state END)
  ORDER BY a.from_revision,a.slot),'[]'::jsonb) INTO attempts FROM control.signing_provider_attempt a
 WHERE a.participant_id=p_rotation.participant_id AND a.privacy_domain_id=p_rotation.privacy_domain_id AND a.rotation_id=p_rotation.rotation_id
  AND a.request->>'method'<>'SIGN_RECEIPT';
 SELECT coalesce(jsonb_agg(jsonb_build_object('profileDigest',encode(s.profile_digest,'hex'),'fingerprint',k.signer_id,
  'epoch',k.key_epoch,'selectionVersion',s.row_version+CASE WHEN s.signer_id<>k.signer_id THEN CASE WHEN s.fenced_operation_id IS NULL THEN 2 ELSE 1 END ELSE 0 END,
  'admissionVersion',s.admission_version,'fenceGeneration',s.fence_generation+CASE WHEN s.signer_id<>k.signer_id AND s.fenced_operation_id IS NULL THEN 1 ELSE 0 END,'trustDigest',encode(k.trust_digest,'hex'),
  'admissionReference',k.admission_reference,'admissionDigest',encode(k.admission_digest,'hex')) ORDER BY s.profile_digest),'[]'::jsonb)
 INTO selections FROM control.business_signing_selection s JOIN control.business_signing_key k
  ON k.participant_id=s.participant_id AND k.privacy_domain_id=s.privacy_domain_id
   AND k.signer_id=CASE WHEN coalesce((effects->>'cutover')::boolean,false) AND s.signer_id=p_rotation.old_signer_id THEN p_rotation.new_signer_id ELSE s.signer_id END
 WHERE s.participant_id=p_rotation.participant_id AND s.privacy_domain_id=p_rotation.privacy_domain_id
  AND s.environment_id=p_rotation.environment_id AND k.workload_credential_id=p_rotation.workload_credential_id;
 -- Preserve the already signed admission snapshot across this operation's own ambiguity fence.
 -- Every other selection field must still match the actual/prospective selected key exactly.
 IF p_receipt IS NOT NULL THEN
  SELECT convert_from(a.history_preimage,'UTF8')::jsonb->'selections' INTO STRICT retained_selections
   FROM control.signing_rotation_attestation a WHERE a.participant_id=p_rotation.participant_id
    AND a.privacy_domain_id=p_rotation.privacy_domain_id AND a.operation_id=p_operation AND a.attempt_id=p_receipt;
  IF jsonb_typeof(retained_selections) IS DISTINCT FROM 'array' OR
   jsonb_array_length(retained_selections)<>jsonb_array_length(selections) OR EXISTS(
    SELECT 1 FROM jsonb_array_elements(selections) WITH ORDINALITY live(value,ordinal)
    LEFT JOIN jsonb_array_elements(retained_selections) WITH ORDINALITY retained(value,ordinal) USING(ordinal)
    WHERE (live.value-'admissionVersion') IS DISTINCT FROM (retained.value-'admissionVersion') OR
     NOT coalesce(openpc.retained_signing_admission_matches(p_rotation.participant_id,p_rotation.privacy_domain_id,
      live.value->>'fingerprint',p_operation,(retained.value->>'admissionVersion')::numeric,
      (live.value->>'admissionVersion')::numeric),false))
  THEN RAISE EXCEPTION 'DATA-6021-ROTATION-HISTORY-ADMISSION'; END IF;
  selections:=retained_selections;
 END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('namespace',i.namespace,'aggregateType',i.aggregate_type,'aggregateId',i.aggregate_id,
  'sequence',i.sequence,'receiptId',i.receipt_id,'receiptDigest',encode(i.receipt_digest,'hex'),'fingerprint',i.signer_id,'keyEpoch',i.key_epoch)
  ORDER BY i.receipt_id),'[]'::jsonb) INTO acknowledgements FROM control.qualified_receipt_inbox i
  JOIN control.signing_rotation_command c ON c.participant_id=i.participant_id AND c.privacy_domain_id=i.privacy_domain_id
   AND c.consumer_receipt_id=i.receipt_id
  WHERE c.participant_id=p_rotation.participant_id AND c.privacy_domain_id=p_rotation.privacy_domain_id AND c.operation_id=p_operation;
 RETURN convert_to(jsonb_build_object('schema','pc.control.signing-rotation-history.v1','participantId',p_rotation.participant_id,
  'privacyDomainId',p_rotation.privacy_domain_id,'rotationId',p_rotation.rotation_id,'revision',p_rotation.revision,
  'priorState',p_prior_state,'state',p_rotation.state,'operationId',p_operation,'priorDigest',encode(prior,'hex'),
  'candidate',candidate,'approval',approval,'command',command,'signerRole',p_rotation.request->>'signerRole','attempts',attempts,'selections',selections,'consumerAcknowledgements',acknowledgements,
  'oldTrustDigest',encode(p_rotation.old_trust_digest,'hex'),'newFingerprint',p_rotation.new_signer_id,
  'cutoverAtNs',p_rotation.cutover_at_ns,'recoveryFromState',p_rotation.recovery_from_state,
  'recoveryFromRevision',p_rotation.recovery_from_revision,'eventId',p_event,'evidenceId',p_evidence,
  'attester',p_attester,'receiptNamespace',CASE WHEN p_receipt_ordinal IS NULL THEN NULL ELSE 'CONTROL_SIGNING_LIFECYCLE_V1' END,
  'receiptOrdinal',p_receipt_ordinal)::text,'UTF8');
END $$;
CREATE OR REPLACE FUNCTION openpc.append_rotation_history()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE previous_state text; previous_digest bytea; operation uuid; event uuid; receipt uuid; evidence uuid; preimage bytea; ordinal numeric;
BEGIN
 previous_state:=CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.state END;
 SELECT history_digest INTO previous_digest FROM control.signing_rotation_history
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND revision=NEW.revision-1;
 IF NEW.revision>1 AND previous_digest IS NULL THEN RAISE EXCEPTION 'DATA-6021-ROTATION-HISTORY-GAP'; END IF;
 IF NEW.state='REQUESTED' THEN operation:=openpc.current_operation_id();
 ELSIF NEW.state='APPROVED' AND OLD.state='REQUESTED' THEN operation:=NEW.approved_operation_id;
 ELSE
  SELECT operation_id INTO STRICT operation FROM control.signing_rotation_command
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id
   AND operation_id=openpc.current_operation_id()
   AND (from_revision=OLD.revision OR (OLD.state='RECOVERING'
    AND openpc.current_action_intent_id()='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' AND from_revision=OLD.recovery_from_revision));
 END IF;
 IF NEW.state<>'REQUESTED' AND NOT (NEW.state='APPROVED' AND OLD.state='REQUESTED') THEN
  SELECT a.event_id,a.attempt_id,a.evidence_record_id,a.receipt_ordinal INTO STRICT event,receipt,evidence,ordinal
  FROM control.signing_rotation_attestation a JOIN control.signing_provider_attempt p USING(attempt_id)
  WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id AND a.operation_id=operation
   AND a.rotation_id=NEW.rotation_id AND a.from_revision=OLD.revision AND a.to_state=NEW.state
   AND p.state IN ('OBSERVED','ACCEPTED') AND p.observation->>'outcome'='SUCCEEDED';
  IF ordinal<>1+coalesce((SELECT max(receipt_ordinal) FROM control.signing_rotation_history
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id),0)
  THEN RAISE EXCEPTION 'DATA-6021-ROTATION-RECEIPT-ORDINAL'; END IF;
 END IF;
 preimage:=openpc.rotation_history_preimage(NEW,previous_state,operation,event,receipt,evidence);
 INSERT INTO control.signing_rotation_history(participant_id,privacy_domain_id,rotation_id,revision,prior_state,state,operation_id,
  prior_digest,history_preimage,history_digest,event_id,receipt_id,evidence_id,receipt_namespace,receipt_ordinal)
 VALUES(NEW.participant_id,NEW.privacy_domain_id,NEW.rotation_id,NEW.revision,previous_state,NEW.state,operation,
  previous_digest,preimage,sha256(preimage),event,receipt,evidence,
  CASE WHEN receipt IS NULL THEN NULL ELSE 'CONTROL_SIGNING_LIFECYCLE_V1' END,ordinal);
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS signing_history_append ON control.signing_key_rotation;
CREATE TRIGGER signing_history_append AFTER INSERT OR UPDATE ON control.signing_key_rotation
 FOR EACH ROW EXECUTE FUNCTION openpc.append_rotation_history();
CREATE OR REPLACE FUNCTION openpc.guard_rotation_history()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE rotation control.signing_key_rotation%ROWTYPE; previous control.signing_rotation_history%ROWTYPE;
BEGIN
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id
  AND revision=NEW.revision AND state=NEW.state;
 IF NEW.revision>1 THEN
  SELECT * INTO STRICT previous FROM control.signing_rotation_history WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND revision=NEW.revision-1;
  IF NEW.prior_state<>previous.state OR NEW.prior_digest<>previous.history_digest THEN RAISE EXCEPTION 'DATA-6021-ROTATION-HISTORY-CHAIN'; END IF;
 END IF;
 IF NEW.history_preimage<>openpc.rotation_history_preimage(rotation,NEW.prior_state,NEW.operation_id,NEW.event_id,NEW.receipt_id,NEW.evidence_id)
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-HISTORY-BINDING'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_history_binding ON control.signing_rotation_history;
CREATE TRIGGER signing_history_binding BEFORE INSERT ON control.signing_rotation_history
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_rotation_history();
DROP TRIGGER IF EXISTS signing_history_immutable ON control.signing_rotation_history;
CREATE TRIGGER signing_history_immutable BEFORE UPDATE OR DELETE ON control.signing_rotation_history
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE OR REPLACE FUNCTION openpc.check_rotation_history_completion()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.state IN ('REQUESTED','APPROVED') AND NEW.revision<=2 THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.signing_rotation_attestation a
  JOIN control.signing_provider_attempt p USING(attempt_id)
  JOIN control.audit_occurrence r ON r.participant_id=a.participant_id AND r.privacy_domain_id=a.privacy_domain_id AND r.receipt_id=a.attempt_id
  JOIN control.evidence_record e ON e.participant_id=r.participant_id AND e.privacy_domain_id=r.privacy_domain_id AND e.receipt_id=r.receipt_id
  WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id AND a.rotation_id=NEW.rotation_id
   AND a.operation_id=NEW.operation_id AND a.attempt_id=NEW.receipt_id AND a.from_revision=NEW.revision-1 AND a.to_state=NEW.state
   AND a.history_preimage=NEW.history_preimage AND a.history_digest=NEW.history_digest AND a.receipt_ordinal=NEW.receipt_ordinal
   AND a.receipt_cbor=r.receipt_cbor AND a.event_id IS NOT DISTINCT FROM NEW.event_id AND a.evidence_record_id=NEW.evidence_id
   AND e.evidence_record_id=NEW.evidence_id AND r.before_revision=NEW.revision-1 AND r.after_revision=NEW.revision
   AND p.state='ACCEPTED' AND p.observation->>'outcome'='SUCCEEDED'
   AND p.observation->>'resultHex'=encode(r.cose_sign1,'hex'))
 THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-SIGNED-ROTATION-HISTORY'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS signing_history_complete ON control.signing_rotation_history;
CREATE CONSTRAINT TRIGGER signing_history_complete AFTER INSERT ON control.signing_rotation_history
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_rotation_history_completion();


CREATE OR REPLACE FUNCTION openpc.guard_signing_attestation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE rotation control.signing_key_rotation%ROWTYPE; command control.signing_rotation_command%ROWTYPE;
 attempt control.receipt_signing_attempt%ROWTYPE; provider control.signing_provider_attempt%ROWTYPE;
 payload jsonb; after_state jsonb; prospective control.signing_key_rotation%ROWTYPE; attester jsonb; expected bytea; expected_authorization jsonb; effects jsonb;
BEGIN
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND revision=NEW.from_revision;
 SELECT * INTO STRICT command FROM control.signing_rotation_command WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND operation_id=NEW.operation_id
  AND state IN ('ACCEPTED','WRITE_AMBIGUITY');
 SELECT * INTO STRICT attempt FROM control.receipt_signing_attempt WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id AND attempt_id=NEW.attempt_id
  AND reservation_kind='LIFECYCLE_DURABLE' AND schema_version=2;
 SELECT * INTO STRICT provider FROM control.signing_provider_attempt WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id AND attempt_id=NEW.attempt_id AND state='READY';
 IF command.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' AND EXISTS(
  SELECT 1 FROM control.signing_rotation_command recovery WHERE recovery.participant_id=NEW.participant_id
   AND recovery.privacy_domain_id=NEW.privacy_domain_id AND recovery.original_operation_id=NEW.operation_id
   AND recovery.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND recovery.state='ACCEPTED')
 THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-IN-PROGRESS'; END IF;
 effects:=openpc.signing_transition_effects(command.action_intent_id,rotation.state,NEW.to_state);
 IF effects IS NULL OR (effects->>'resumeFrom' IS NOT NULL AND effects->>'resumeFrom' IS DISTINCT FROM rotation.recovery_from_state)
 THEN RAISE EXCEPTION 'DATA-6022-SIGNING-TRANSITION-MATRIX'; END IF;
 payload:=openpc.business_cbor(NEW.receipt_cbor);
 IF NEW.continuation_assertion_id IS NOT NULL THEN
  PERFORM openpc.check_signing_continuation_snapshot(NEW.authority_snapshot,NEW.participant_id,NEW.privacy_domain_id,
   NEW.operation_id,NEW.attempt_id,(payload->>'23')::numeric,false);
  SELECT jsonb_agg(proof ORDER BY proof->>'1') INTO expected_authorization FROM control.signing_continuation c
   JOIN control.mutation_evidence e ON e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
    AND e.operation_id=c.operation_id AND e.mutation_evidence_id=command.authorization_evidence_id
   CROSS JOIN LATERAL jsonb_array_elements(jsonb_build_array(
    jsonb_build_object('0',2,'1',c.assertion_id::text,'2',openpc.business_bytes(c.assertion_digest)),
    jsonb_build_object('0',2,'1',e.mutation_evidence_id::text,'2',openpc.business_bytes(e.evidence_digest)))) proof
   WHERE c.assertion_id=NEW.continuation_assertion_id;
  IF payload->'20' IS DISTINCT FROM expected_authorization OR
   convert_from(NEW.authority_snapshot,'UTF8')::jsonb->>'continuationAssertionId' IS DISTINCT FROM NEW.continuation_assertion_id::text
  THEN RAISE EXCEPTION 'DATA-6021-ATTESTATION-CONTINUATION'; END IF;
 END IF;
 after_state:=openpc.business_cbor(NEW.after_state_preimage);
 IF NEW.operation_id IS DISTINCT FROM openpc.current_operation_id() OR command.action_intent_id IS DISTINCT FROM openpc.current_action_intent_id()
  OR NEW.receipt_cbor<>attempt.payload_cbor OR NEW.signer_id<>attempt.signer_id OR NEW.signer_trust_digest<>attempt.signer_trust_digest
  OR NEW.selection_version<>attempt.selection_version OR
    (NEW.continuation_assertion_id IS NULL AND (convert_from(NEW.authority_snapshot,'UTF8')::jsonb->'authorities') IS DISTINCT FROM
    (convert_from(command.authorization_snapshot,'UTF8')::jsonb->'authorities'))
  OR payload->'14' IS DISTINCT FROM openpc.business_bytes(sha256(NEW.authority_snapshot))
  OR payload->'18'->'2' IS DISTINCT FROM openpc.business_bytes(sha256(NEW.before_state_preimage))
  OR payload->'19'->'2' IS DISTINCT FROM openpc.business_bytes(sha256(NEW.after_state_preimage))
  OR payload->'19'->'1' IS DISTINCT FROM to_jsonb(NEW.from_revision+1)
  OR provider.from_revision<>NEW.from_revision OR provider.from_state<>rotation.state OR provider.to_state<>NEW.to_state
  OR provider.rotation_id<>NEW.rotation_id OR provider.request->>'method' IS DISTINCT FROM 'SIGN_RECEIPT'
  OR provider.request->>'payloadHex' IS DISTINCT FROM encode(NEW.receipt_cbor,'hex')
  OR provider.request->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text OR provider.request->>'operationId' IS DISTINCT FROM NEW.operation_id::text
  OR (effects->>'eventType' IS NOT NULL) IS DISTINCT FROM (NEW.event_id IS NOT NULL)
  OR (NEW.to_state<>command.to_state AND NEW.to_state NOT IN ('FAILED','RECOVERING'))
 THEN RAISE EXCEPTION 'DATA-6021-ATTESTATION-EXACT-ATTEMPT'; END IF;
 IF EXISTS(SELECT 1 FROM control.signing_rotation_attestation a JOIN control.signing_provider_attempt p USING(attempt_id)
  WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id
   AND a.operation_id=NEW.operation_id AND p.state NOT IN ('REJECTED','SUPERSEDED'))
 THEN RAISE EXCEPTION 'DATA-6021-ATTESTATION-ALREADY-PENDING'; END IF;
 IF NEW.receipt_ordinal<>1+coalesce((SELECT max(receipt_ordinal) FROM control.signing_rotation_history
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id),0)
 THEN RAISE EXCEPTION 'DATA-6021-ATTESTATION-ORDINAL'; END IF;
 prospective:=rotation;
 prospective.state:=NEW.to_state;
 prospective.revision:=NEW.from_revision+1;
 IF (effects->>'prepare')::boolean THEN
  SELECT observation->'descriptor'->>'fingerprint' INTO STRICT prospective.new_signer_id
  FROM control.signing_provider_attempt WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
   AND operation_id=NEW.operation_id AND request->>'method'='PREPARE' AND state='OBSERVED' AND observation->>'outcome'='SUCCEEDED';
 END IF;
 IF (effects->>'cutover')::boolean
 THEN prospective.cutover_at_ns:=(payload->>'23')::bigint; END IF;
 IF effects->>'kind' IN ('RECOVERY','FORWARD_RECOVERY') THEN
  IF command.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND command.authorization_generation_id IS NOT NULL THEN
   SELECT resume_state,resume_revision INTO STRICT prospective.recovery_from_state,prospective.recovery_from_revision
    FROM control.signing_authorization_generation WHERE generation_id=command.authorization_generation_id AND state='STAGED';
  ELSE
   prospective.recovery_from_state:=coalesce(rotation.recovery_from_state,rotation.state);
   prospective.recovery_from_revision:=coalesce(rotation.recovery_from_revision,rotation.revision);
  END IF;
 ELSE prospective.recovery_from_state:=NULL; prospective.recovery_from_revision:=NULL; END IF;
 attester:=jsonb_build_object('signerId',attempt.signer_id,'keyEpoch',attempt.key_epoch,'trustDigest',encode(attempt.signer_trust_digest,'hex'),
  'selectionVersion',attempt.selection_version,'admissionVersion',attempt.admission_version,'fenceGeneration',attempt.fence_generation);
 expected:=openpc.rotation_history_preimage(prospective,rotation.state,NEW.operation_id,NEW.event_id,NULL,NEW.evidence_record_id,attester,NEW.receipt_ordinal);
 IF expected<>NEW.history_preimage OR after_state->8->'2' IS DISTINCT FROM openpc.business_bytes(sha256(expected))
 THEN RAISE EXCEPTION 'DATA-6021-ATTESTATION-HISTORY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_attestation_typed ON control.signing_rotation_attestation;
CREATE TRIGGER signing_attestation_typed BEFORE INSERT ON control.signing_rotation_attestation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_attestation();
CREATE OR REPLACE FUNCTION openpc.check_signing_rotation_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE rotation control.signing_key_rotation%ROWTYPE; history control.signing_rotation_history%ROWTYPE;
 previous control.signing_rotation_history%ROWTYPE; attestation control.signing_rotation_attestation%ROWTYPE;
 before_new text; before_projection jsonb; after_projection jsonb; self_cutover boolean; effects jsonb;
BEGIN
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=receipt.participant_id
  AND privacy_domain_id=receipt.privacy_domain_id AND rotation_id=receipt.aggregate_id AND revision=receipt.after_revision;
 SELECT * INTO STRICT history FROM control.signing_rotation_history WHERE participant_id=receipt.participant_id
  AND privacy_domain_id=receipt.privacy_domain_id AND rotation_id=receipt.aggregate_id AND revision=receipt.after_revision
  AND receipt_id=receipt.receipt_id AND operation_id=receipt.operation_id;
 SELECT * INTO STRICT previous FROM control.signing_rotation_history WHERE participant_id=receipt.participant_id
  AND privacy_domain_id=receipt.privacy_domain_id AND rotation_id=receipt.aggregate_id AND revision=receipt.before_revision;
 SELECT * INTO STRICT attestation FROM control.signing_rotation_attestation WHERE participant_id=receipt.participant_id
  AND privacy_domain_id=receipt.privacy_domain_id AND rotation_id=receipt.aggregate_id AND operation_id=receipt.operation_id
  AND attempt_id=receipt.receipt_id AND from_revision=receipt.before_revision AND to_state=rotation.state;
 effects:=openpc.signing_transition_effects(receipt.action_intent_id,previous.state,rotation.state);
 IF effects IS NULL THEN RAISE EXCEPTION 'DATA-6022-SIGNING-TRANSITION-MATRIX'; END IF;
 IF attestation.receipt_cbor<>receipt.receipt_cbor OR attestation.authority_snapshot<>receipt.authority_snapshot
  OR attestation.before_state_preimage<>receipt.before_state_preimage OR attestation.after_state_preimage<>receipt.after_state_preimage
  OR attestation.history_digest<>history.history_digest OR receipt.after_revision<>receipt.before_revision+1
  OR jsonb_array_length(openpc.business_cbor(receipt.receipt_cbor)->'21')<>(CASE WHEN effects->>'eventType' IS NOT NULL THEN 1 ELSE 0 END)
  OR (effects->>'eventType' IS NOT NULL AND
    openpc.business_cbor(receipt.receipt_cbor)->'21'->0->'0' IS DISTINCT FROM openpc.business_uuid(attestation.event_id))
 THEN RAISE EXCEPTION 'DATA-6021-LIFECYCLE-RECEIPT-HISTORY'; END IF;
 before_new:=convert_from(previous.history_preimage,'UTF8')::jsonb->>'newFingerprint';
 before_projection:=jsonb_build_object('0',previous.state,'1',openpc.business_bytes(rotation.candidate_digest),
  '2',openpc.business_bytes(previous.history_digest),'3',rotation.request->>'signerRole',
  '4',openpc.business_bytes(decode(substring(rotation.old_signer_id from 8),'hex')),'5',CASE WHEN before_new IS NULL THEN 0 ELSE 1 END)
  ||CASE WHEN before_new IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('6',openpc.business_bytes(decode(substring(before_new from 8),'hex'))) END;
 after_projection:=jsonb_build_object('0',rotation.state,'1',openpc.business_bytes(rotation.candidate_digest),
  '2',openpc.business_bytes(history.history_digest),'3',rotation.request->>'signerRole',
  '4',openpc.business_bytes(decode(substring(rotation.old_signer_id from 8),'hex')),'5',CASE WHEN rotation.new_signer_id IS NULL THEN 0 ELSE 1 END)
  ||CASE WHEN rotation.new_signer_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('6',openpc.business_bytes(decode(substring(rotation.new_signer_id from 8),'hex'))) END;
 IF openpc.business_cbor(receipt.before_state_preimage)->8 IS DISTINCT FROM before_projection OR
  openpc.business_cbor(receipt.after_state_preimage)->8 IS DISTINCT FROM after_projection
 THEN RAISE EXCEPTION 'DATA-6021-LIFECYCLE-ACTUAL-STATE'; END IF;
 self_cutover:=rotation.request->>'signerRole'='LIFECYCLE_EVIDENCE' AND (effects->>'cutover')::boolean
  AND receipt.signer_id=rotation.old_signer_id AND receipt.recorded_at_ns=rotation.cutover_at_ns;
 IF NOT EXISTS(SELECT 1 FROM control.receipt_signing_attempt a
  JOIN control.business_signing_key k ON k.participant_id=a.participant_id AND k.privacy_domain_id=a.privacy_domain_id AND k.signer_id=a.signer_id
  JOIN control.business_signing_key_state ks ON ks.participant_id=a.participant_id AND ks.privacy_domain_id=a.privacy_domain_id AND ks.signer_id=a.signer_id
  JOIN control.business_signing_selection s ON s.participant_id=a.participant_id AND s.privacy_domain_id=a.privacy_domain_id
   AND s.environment_id=k.environment_id AND s.profile_digest=a.profile_digest
  JOIN control.credential c ON c.participant_id=k.participant_id AND c.credential_id=k.workload_credential_id
  JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
  WHERE a.participant_id=receipt.participant_id AND a.privacy_domain_id=receipt.privacy_domain_id AND a.attempt_id=receipt.receipt_id
   AND a.reservation_kind='LIFECYCLE_DURABLE' AND a.payload_cbor=receipt.receipt_cbor AND a.operation_id=receipt.operation_id
   AND k.trust_digest=receipt.signer_trust_snapshot_digest AND k.key_epoch=a.key_epoch AND k.environment_id=receipt.environment_id
   AND k.valid_from_ns<=receipt.recorded_at_ns AND k.valid_until_ns>receipt.recorded_at_ns
   AND c.credential_epoch=k.workload_credential_epoch AND c.state='ACTIVE' AND p.state='ACTIVE' AND p.kind='WORKLOAD'
   AND c.valid_from<=clock_timestamp() AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
   AND openpc.retained_signing_admission_matches(a.participant_id,a.privacy_domain_id,a.signer_id,a.operation_id,a.admission_version,s.admission_version)
   AND s.fenced_operation_id IS NULL AND ((NOT self_cutover AND ks.state='ACTIVE' AND s.signer_id=a.signer_id
    AND s.row_version=a.selection_version AND s.fence_generation=a.fence_generation
    AND k.valid_until_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000)
    OR (self_cutover AND ks.state='RETIRED' AND s.signer_id=rotation.new_signer_id
     AND s.row_version=a.selection_version+2 AND s.fence_generation=a.fence_generation+1))
   FOR SHARE OF s,ks,c,p)
 THEN RAISE EXCEPTION 'DATA-6021-LIFECYCLE-SIGNER-FENCE'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_signing_rotation_event(event control.outbox_event,receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE state jsonb; expected_type text; expected_schema text; effects jsonb;
BEGIN
 state:=openpc.business_cbor(receipt.after_state_preimage)->8;
 effects:=openpc.signing_transition_effects(receipt.action_intent_id,openpc.business_cbor(receipt.before_state_preimage)->8->>'0',state->>'0');
 expected_type:=effects->>'eventType';
 expected_schema:=CASE expected_type WHEN 'io.openpc.ops.secret.revoked.v1' THEN 'SecretRevoked' WHEN 'io.openpc.ops.secret.rotated.v1' THEN 'SecretRotated' END;
 IF expected_type IS NULL OR receipt.catalog_operation_id<>'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION'
  OR event.event_type IS DISTINCT FROM expected_type
  OR event.data_schema_uri IS DISTINCT FROM 'https://schemas.openpc.local/event-payloads.schema.json#/$defs/'||expected_schema
  OR event.aggregate_type<>receipt.aggregate_type OR event.aggregate_id<>receipt.aggregate_id
  OR event.payload_digest<>sha256(event.payload_cbor) OR state->>'5'<>'1'
  OR openpc.business_cbor(event.payload_cbor) IS DISTINCT FROM jsonb_build_object('0',openpc.business_uuid(receipt.aggregate_id),
    '1',state->>'3','2',state->'4','3',state->'6')
 THEN RAISE EXCEPTION 'DATA-6021-LIFECYCLE-STATE-EVENT'; END IF;
END $$;


CREATE OR REPLACE FUNCTION openpc.check_signing_continuation_context(context jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE command control.signing_rotation_command%ROWTYPE; attempt control.signing_provider_attempt%ROWTYPE;
 rotation control.signing_key_rotation%ROWTYPE; workload control.credential%ROWTYPE; snapshot jsonb;
 authority jsonb; evidence control.mutation_evidence%ROWTYPE; expected jsonb;
BEGIN
 SELECT * INTO STRICT attempt FROM control.signing_provider_attempt WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND attempt_id=(context->>'providerAttemptId')::uuid
  AND state='OBSERVED' AND dispatched_at_ns IS NOT NULL AND request->>'method' IN ('PREPARE','DISTRIBUTE','REVOKE','RETIRE');
 authority:=openpc.signing_attempt_authority_status(attempt.attempt_id);
 SELECT * INTO STRICT command FROM control.signing_rotation_command WHERE participant_id=attempt.participant_id
  AND privacy_domain_id=attempt.privacy_domain_id AND operation_id=attempt.operation_id AND state IN ('ACCEPTED','WRITE_AMBIGUITY')
  AND action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1';
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=attempt.participant_id
  AND privacy_domain_id=attempt.privacy_domain_id AND rotation_id=attempt.rotation_id AND approval_request_id IS NOT NULL;
 SELECT * INTO STRICT workload FROM control.credential c WHERE c.participant_id=attempt.participant_id
  AND c.credential_id=rotation.workload_credential_id AND c.state='ACTIVE' AND c.kind='WORKLOAD_MTLS'
  AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
  AND EXISTS(SELECT 1 FROM control.principal p WHERE p.participant_id=c.participant_id AND p.principal_id=c.principal_id
   AND p.kind='WORKLOAD' AND p.state='ACTIVE');
 SELECT * INTO STRICT evidence FROM control.mutation_evidence WHERE participant_id=command.participant_id
  AND privacy_domain_id=command.privacy_domain_id AND mutation_evidence_id=command.authorization_evidence_id
  AND operation_id=command.operation_id;
 IF NOT ((rotation.revision=attempt.from_revision AND rotation.state=attempt.from_state) OR
  (rotation.state='RECOVERING' AND rotation.recovery_from_revision=attempt.from_revision AND rotation.recovery_from_state=attempt.from_state))
  OR command.from_revision<>attempt.from_revision OR command.to_state<>attempt.to_state
  OR attempt.observation->>'attemptId'<>attempt.attempt_id::text OR attempt.observation->>'operationId'<>attempt.operation_id::text
  OR attempt.observation->>'method'<>attempt.request->>'method'
  OR attempt.observation->>'requestDigest'<>'sha256:'||encode(attempt.request_digest,'hex')
  OR attempt.observation->>'outcome' NOT IN ('SUCCEEDED','REJECTED')
  OR command.to_state IS DISTINCT FROM (CASE attempt.request->>'method' WHEN 'PREPARE' THEN 'PREPARED'
   WHEN 'DISTRIBUTE' THEN 'DISTRIBUTED' WHEN 'REVOKE' THEN 'OLD_REVOKED' WHEN 'RETIRE' THEN 'OLD_RETIRED' END)
  OR EXISTS(SELECT 1 FROM control.signing_rotation_command recovery WHERE recovery.participant_id=command.participant_id
   AND recovery.privacy_domain_id=command.privacy_domain_id AND recovery.original_operation_id=command.operation_id AND recovery.state='ACCEPTED')
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-EXACT-DISPATCHED-ATTEMPT'; END IF;
 snapshot:=convert_from(command.authorization_snapshot,'UTF8')::jsonb;
 expected:=jsonb_build_object('version',1,'purpose','SIGNING_ROTATION_ATTEMPT_RECONCILE_V1',
  'effect','FINALIZE_EXISTING_SIGNING_ROTATION_ATTEMPT','participantId',attempt.participant_id::text,
  'privacyDomainId',attempt.privacy_domain_id::text,'rotationId',rotation.rotation_id::text,'rotationRevision',rotation.revision::text,
  'operationId',command.operation_id::text,'actionIntentId',command.action_intent_id,'targetState',command.to_state,
  'candidateDigest','sha256:'||encode(command.approval_candidate_digest,'hex'),'approvalRequestId',command.approval_request_id::text,
  'originalActorKeyDigest','sha256:'||(openpc.business_cbor(evidence.evidence_cbor)->'1'->>'bytes'),
  'originalAuthoritySnapshotDigest','sha256:'||encode(command.authorization_snapshot_digest,'hex'),
  'originalMakerSnapshotDigest','sha256:'||encode(sha256(convert_to((snapshot->'authorities'->1)::text,'UTF8')),'hex'),
  'originalCheckerSnapshotDigest','sha256:'||encode(sha256(convert_to((snapshot->'authorities'->2)::text,'UTF8')),'hex'),
  'providerAttemptId',attempt.attempt_id::text,'providerMethod',attempt.request->>'method',
  'providerRequestDigest','sha256:'||encode(attempt.request_digest,'hex'),
  'providerObservationDigest','sha256:'||encode(attempt.observation_digest,'hex'),
  'resultDisposition',CASE WHEN attempt.observation->>'outcome'='SUCCEEDED' THEN 'APPLY_RESERVED_TARGET'
   WHEN attempt.observation->>'reason'='NOT_APPLIED' THEN 'NO_EFFECT_RETRYABLE' ELSE 'ENTER_FAILED_STATE' END,
  'workloadPrincipalId',workload.principal_id::text,'workloadCredentialId',workload.credential_id::text,
  'workloadCredentialEpoch',workload.credential_epoch::text,'workloadKeyDigest','sha256:'||encode(workload.public_key_digest,'hex'),
  'currentAuthorityStatus',CASE WHEN (authority->>'unchangedLive')::boolean THEN 'UNCHANGED_LIVE' ELSE 'CHANGED' END,
  'currentAuthorityDigest','sha256:'||encode(openpc.signing_continuation_authority_digest(authority),'hex'));
 IF context IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-CONTEXT'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_signing_continuation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE context jsonb; now_ns numeric;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-CONTINUATION-IMMUTABLE'; END IF;
 now_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
 context:=convert_from(NEW.context_preimage,'UTF8')::jsonb;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR NEW.operation_id IS DISTINCT FROM openpc.current_operation_id()
  OR openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'
  OR context->>'operationId' IS DISTINCT FROM NEW.operation_id::text OR context->>'providerAttemptId' IS DISTINCT FROM NEW.provider_attempt_id::text
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-SCOPE'; END IF;
 IF TG_OP='INSERT' THEN
  IF NOT pg_has_role(current_user,'openpc_signing_continuation_issuer','MEMBER') OR NEW.state<>'ISSUED'
   OR NEW.issued_at_ns>now_ns OR NEW.issued_at_ns<now_ns-1000000000 OR NEW.expires_at_ns<=now_ns
  THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-ISSUER'; END IF;
  PERFORM openpc.check_signing_continuation_context(context);
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','consumed_at_ns','consumed_receipt_id']) IS DISTINCT FROM
  (to_jsonb(OLD)-ARRAY['state','consumed_at_ns','consumed_receipt_id']) OR OLD.state<>'ISSUED'
 THEN RAISE EXCEPTION 'DATA-6020-CONTINUATION-IDENTITY'; END IF;
 IF NEW.state='EXPIRED' THEN
  IF NOT pg_has_role(current_user,'openpc_signing_continuation_issuer','MEMBER') OR OLD.expires_at_ns>now_ns
  THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-EXPIRY'; END IF;
 ELSIF NEW.state='CONSUMED' THEN
  IF pg_has_role(current_user,'openpc_control_worker','MEMBER') OR OLD.expires_at_ns<=now_ns OR NEW.consumed_at_ns IS NOT NULL
  THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-CONSUMPTION'; END IF;
  IF context->>'resultDisposition'='NO_EFFECT_RETRYABLE' THEN
   IF NEW.consumed_receipt_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_operation_evidence e
    WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id
     AND e.continuation_assertion_id=NEW.assertion_id AND e.kind='NO_EFFECT_RETRYABLE')
   THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-NO-EFFECT'; END IF;
  ELSE
   IF NEW.consumed_receipt_id IS NULL OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_attestation a JOIN control.signing_provider_attempt p USING(attempt_id)
    WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id AND a.operation_id=NEW.operation_id
     AND a.continuation_assertion_id=NEW.assertion_id AND a.attempt_id=NEW.consumed_receipt_id
     AND p.state='OBSERVED' AND p.observation->>'outcome'='SUCCEEDED')
   THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-CONSUMPTION'; END IF;
  END IF;
  PERFORM openpc.check_signing_continuation_context(context);
  NEW.consumed_at_ns:=now_ns;
 ELSE RAISE EXCEPTION 'DATA-6021-CONTINUATION-TRANSITION';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_continuation_guard ON control.signing_continuation;
CREATE TRIGGER signing_continuation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_continuation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_continuation();

CREATE OR REPLACE FUNCTION openpc.check_signing_continuation_snapshot(
 p_snapshot bytea,p_participant uuid,p_privacy uuid,p_operation uuid,p_receipt uuid,p_recorded_ns numeric,p_consumed boolean)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE snapshot jsonb; capability control.signing_continuation%ROWTYPE; expected jsonb;
BEGIN
 snapshot:=convert_from(p_snapshot,'UTF8')::jsonb;
 SELECT * INTO STRICT capability FROM control.signing_continuation WHERE participant_id=p_participant AND privacy_domain_id=p_privacy
  AND operation_id=p_operation AND assertion_id=(snapshot->>'continuationAssertionId')::uuid
  AND state=CASE WHEN p_consumed THEN 'CONSUMED' ELSE 'ISSUED' END;
 expected:=jsonb_build_object('schema','pc.control.signing-rotation-continuation-snapshot.v1',
  'participantId',p_participant::text,'privacyDomainId',p_privacy::text,'operationId',p_operation::text,
  'recordedAtNs',snapshot->'recordedAtNs','decision','RECORD_DISPATCHED_TRUTH','continuationAssertionId',capability.assertion_id::text,
  'continuationAssertionDigest','sha256:'||encode(capability.assertion_digest,'hex'),'context',convert_from(capability.context_preimage,'UTF8')::jsonb);
 IF snapshot IS DISTINCT FROM expected OR jsonb_typeof(snapshot->'recordedAtNs') IS DISTINCT FROM 'string'
  OR NOT ((snapshot->>'recordedAtNs') ~ '^[0-9]{1,20}$') OR (snapshot->>'recordedAtNs')::numeric>p_recorded_ns
  OR p_recorded_ns<capability.issued_at_ns OR p_recorded_ns>=capability.expires_at_ns
  OR (p_consumed AND (capability.consumed_receipt_id IS DISTINCT FROM p_receipt OR capability.consumed_at_ns<p_recorded_ns))
  OR (NOT p_consumed AND capability.expires_at_ns<=floor(extract(epoch FROM clock_timestamp())*1000000)*1000)
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-RECEIPT-SNAPSHOT'; END IF;
 IF NOT p_consumed THEN PERFORM openpc.check_signing_continuation_context(snapshot->'context'); END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_consumed_signing_continuation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE context jsonb;
BEGIN
 IF NEW.state<>'CONSUMED' THEN RETURN NULL; END IF;
 context:=convert_from(NEW.context_preimage,'UTF8')::jsonb;
 IF context->>'resultDisposition'='NO_EFFECT_RETRYABLE' THEN
  IF NOT EXISTS(SELECT 1 FROM control.signing_rotation_operation_evidence e JOIN control.signing_rotation_command c USING(participant_id,privacy_domain_id,operation_id)
   WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id
    AND e.continuation_assertion_id=NEW.assertion_id AND e.kind='NO_EFFECT_RETRYABLE' AND c.state='FAILED' AND c.result_kind=e.kind)
  THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-ATOMIC-NO-EFFECT'; END IF;
 ELSIF NOT EXISTS(SELECT 1 FROM control.signing_rotation_command c JOIN control.signing_provider_attempt p
  ON p.participant_id=c.participant_id AND p.privacy_domain_id=c.privacy_domain_id AND p.operation_id=c.operation_id
  JOIN control.audit_occurrence a ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id AND a.operation_id=c.operation_id
  WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.operation_id=NEW.operation_id
   AND c.state IN ('SUCCEEDED','FAILED') AND p.attempt_id=NEW.provider_attempt_id AND p.state IN ('ACCEPTED','REJECTED')
   AND a.receipt_id=NEW.consumed_receipt_id AND a.aggregate_type='signing-key-rotation' AND a.before_revision=(context->>'rotationRevision')::bigint
   AND convert_from(a.authority_snapshot,'UTF8')::jsonb->>'continuationAssertionId'=NEW.assertion_id::text)
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-ATOMIC-EFFECT'; END IF;
 IF context->>'currentAuthorityStatus'='CHANGED' AND NOT EXISTS(SELECT 1 FROM control.signing_rotation_authority_hold h
  WHERE h.participant_id=NEW.participant_id AND h.privacy_domain_id=NEW.privacy_domain_id AND h.operation_id=NEW.operation_id
   AND h.continuation_assertion_id=NEW.assertion_id AND h.reason='AUTHORITY_CHANGED_AFTER_DISPATCH')
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-AUTHORITY-HOLD'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS signing_continuation_atomic ON control.signing_continuation;
CREATE CONSTRAINT TRIGGER signing_continuation_atomic AFTER UPDATE ON control.signing_continuation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_consumed_signing_continuation();
CREATE OR REPLACE FUNCTION openpc.guard_signing_authority_hold()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state<>'CLEARED' OR NEW.cleared_by_operation_id IS DISTINCT FROM openpc.current_operation_id()
   OR openpc.current_action_intent_id()<>'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1'
   OR (to_jsonb(NEW)-ARRAY['state','cleared_by_operation_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','cleared_by_operation_id'])
   OR NOT EXISTS(SELECT 1 FROM control.signing_authorization_generation g JOIN control.signing_rotation_history h
    ON h.participant_id=g.participant_id AND h.privacy_domain_id=g.privacy_domain_id AND h.operation_id=g.consumed_operation_id
     AND h.revision=g.result_revision WHERE g.participant_id=NEW.participant_id AND g.privacy_domain_id=NEW.privacy_domain_id
      AND g.hold_id=NEW.hold_id AND g.state='CONSUMED' AND g.consumed_operation_id=NEW.cleared_by_operation_id
      AND h.receipt_id IS NOT NULL AND h.event_id IS NULL)
  THEN RAISE EXCEPTION 'DATA-6021-HOLD-GOVERNED-RECOVERY-REQUIRED'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-AUTHORITY-HOLD'; END IF;
 IF NEW.state<>'ACTIVE' OR NEW.operation_id IS DISTINCT FROM openpc.current_operation_id()
  OR NOT EXISTS(SELECT 1 FROM control.signing_continuation c WHERE c.participant_id=NEW.participant_id
   AND c.privacy_domain_id=NEW.privacy_domain_id AND c.operation_id=NEW.operation_id AND c.assertion_id=NEW.continuation_assertion_id
   AND c.state='CONSUMED' AND convert_from(c.context_preimage,'UTF8')::jsonb->>'currentAuthorityStatus'='CHANGED'
   AND convert_from(c.context_preimage,'UTF8')::jsonb->>'rotationId'=NEW.rotation_id::text)
 THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-HOLD-OWNER'; END IF;
 NEW.created_at_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_authority_hold_guard ON control.signing_rotation_authority_hold;
CREATE TRIGGER signing_authority_hold_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_rotation_authority_hold
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_authority_hold();


CREATE OR REPLACE FUNCTION openpc.signing_operation_failure_preimage(p_attempt uuid,p_kind text,p_assertion uuid)
RETURNS bytea LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.signing_provider_attempt%ROWTYPE; c control.signing_rotation_command%ROWTYPE;
 authority jsonb; assertion control.signing_continuation%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM control.signing_provider_attempt WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND attempt_id=p_attempt;
 SELECT * INTO STRICT c FROM control.signing_rotation_command WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND operation_id=a.operation_id;
 IF c.operation_id IS DISTINCT FROM openpc.current_operation_id() OR c.action_intent_id<>'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'
  OR openpc.current_action_intent_id()<>c.action_intent_id THEN RAISE EXCEPTION 'DATA-6021-NO-EFFECT-CONTEXT'; END IF;
 IF p_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH' THEN
  authority:=openpc.signing_attempt_authority_status(p_attempt);
  IF p_assertion IS NOT NULL OR (authority->>'unchangedLive')::boolean OR a.dispatched_at_ns IS NOT NULL
   OR EXISTS(SELECT 1 FROM control.signing_provider_attempt other WHERE other.participant_id=a.participant_id
    AND other.privacy_domain_id=a.privacy_domain_id AND other.operation_id=a.operation_id
    AND (other.state NOT IN ('READY','CANCELLED') OR other.dispatched_at_ns IS NOT NULL OR other.observation IS NOT NULL))
  THEN RAISE EXCEPTION 'DATA-6021-UNDISPATCHED-AUTHORITY-FAILURE'; END IF;
 ELSIF p_kind='NO_EFFECT_RETRYABLE' THEN
  SELECT * INTO STRICT assertion FROM control.signing_continuation WHERE participant_id=a.participant_id
   AND privacy_domain_id=a.privacy_domain_id AND operation_id=a.operation_id AND provider_attempt_id=a.attempt_id
   AND assertion_id=p_assertion AND state IN ('ISSUED','CONSUMED');
  IF a.state NOT IN ('OBSERVED','REJECTED') OR a.dispatched_at_ns IS NULL OR a.observation->>'outcome' IS DISTINCT FROM 'REJECTED'
   OR a.observation->>'reason' IS DISTINCT FROM 'NOT_APPLIED'
   OR convert_from(assertion.context_preimage,'UTF8')::jsonb->>'resultDisposition' IS DISTINCT FROM 'NO_EFFECT_RETRYABLE'
  THEN RAISE EXCEPTION 'DATA-6021-PROVIDER-NO-EFFECT-GUARANTEE'; END IF;
 ELSE RAISE EXCEPTION 'DATA-6021-NO-EFFECT-KIND'; END IF;
 RETURN convert_to(jsonb_build_object('schema','pc.control.signing-rotation-operation-result.v1','participantId',a.participant_id,
  'privacyDomainId',a.privacy_domain_id,'rotationId',a.rotation_id,'operationId',c.operation_id,'kind',p_kind,
  'candidateDigest',encode(c.input_digest,'hex'),'revision',c.from_revision,'currentRevision',(SELECT r.revision FROM control.signing_key_rotation r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.rotation_id=c.rotation_id),'providerAttemptId',a.attempt_id,
  'providerRequestDigest',encode(a.request_digest,'hex'),'dispatchedAtNs',a.dispatched_at_ns,
  'providerObservationDigest',encode(a.observation_digest,'hex'),'originalAuthoritySnapshotDigest',encode(c.authorization_snapshot_digest,'hex'),
  'currentAuthority',authority,'continuationAssertionId',p_assertion,'continuationAssertionDigest',encode(assertion.assertion_digest,'hex'))::text,'UTF8');
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_signing_operation_evidence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-SIGNING-OPERATION-EVIDENCE'; END IF;
 IF NEW.preimage IS DISTINCT FROM openpc.signing_operation_failure_preimage(NEW.provider_attempt_id,NEW.kind,NEW.continuation_assertion_id)
  OR NOT EXISTS(SELECT 1 FROM control.signing_provider_attempt a WHERE a.participant_id=NEW.participant_id
   AND a.privacy_domain_id=NEW.privacy_domain_id AND a.rotation_id=NEW.rotation_id AND a.operation_id=NEW.operation_id AND a.attempt_id=NEW.provider_attempt_id)
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-OPERATION-EVIDENCE'; END IF;
 NEW.recorded_at_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_operation_evidence_guard ON control.signing_rotation_operation_evidence;
CREATE TRIGGER signing_operation_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_rotation_operation_evidence
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_operation_evidence();
CREATE OR REPLACE FUNCTION openpc.check_signing_no_effect_completion()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.signing_rotation_command c JOIN control.idempotency_record i USING(participant_id,privacy_domain_id,operation_id)
  WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.operation_id=NEW.operation_id
   AND c.state='FAILED' AND c.result_kind=NEW.kind AND c.result_revision=(convert_from(NEW.preimage,'UTF8')::jsonb->>'currentRevision')::bigint AND i.terminal_state='COMMITTED'
   AND i.result_payload->>'state'='FAILED' AND i.result_payload->'signingResult'->>'kind'=NEW.kind)
  OR EXISTS(SELECT 1 FROM control.signing_rotation_history h WHERE h.participant_id=NEW.participant_id
   AND h.privacy_domain_id=NEW.privacy_domain_id AND h.operation_id=NEW.operation_id)
  OR EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=NEW.participant_id
   AND a.privacy_domain_id=NEW.privacy_domain_id AND a.operation_id=NEW.operation_id)
  OR EXISTS(SELECT 1 FROM control.signing_provider_attempt a WHERE a.participant_id=NEW.participant_id
   AND a.privacy_domain_id=NEW.privacy_domain_id AND a.operation_id=NEW.operation_id
   AND ((NEW.kind='AUTHORITY_CHANGED_BEFORE_DISPATCH' AND a.state<>'CANCELLED') OR
    (NEW.kind='NO_EFFECT_RETRYABLE' AND a.state NOT IN ('REJECTED','SUPERSEDED'))))
 THEN RAISE EXCEPTION 'DATA-6021-NO-EFFECT-ATOMIC-COMPLETION'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS signing_no_effect_complete ON control.signing_rotation_operation_evidence;
CREATE CONSTRAINT TRIGGER signing_no_effect_complete AFTER INSERT ON control.signing_rotation_operation_evidence
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_signing_no_effect_completion();

CREATE OR REPLACE FUNCTION openpc.signing_governance_required(p_participant uuid,p_privacy uuid,p_rotation uuid,p_action text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.signing_key_rotation r WHERE r.participant_id=p_participant AND r.privacy_domain_id=p_privacy
  AND r.rotation_id=p_rotation AND ((p_action='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND
   (r.state='FAILED' OR EXISTS(SELECT 1 FROM control.signing_rotation_authority_hold h
     WHERE h.participant_id=r.participant_id AND h.privacy_domain_id=r.privacy_domain_id AND h.rotation_id=r.rotation_id AND h.state='ACTIVE')))
   OR (p_action='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' AND EXISTS(SELECT 1 FROM control.signing_rotation_command c
    WHERE c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id AND c.rotation_id=r.rotation_id
     AND c.from_revision=r.revision AND c.state='FAILED' AND c.result_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH'))))
$$;
CREATE OR REPLACE FUNCTION openpc.signing_governance_context(p_rotation uuid,p_action text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE rotation control.signing_key_rotation%ROWTYPE; original control.signing_rotation_command%ROWTYPE;
 hold control.signing_rotation_authority_hold%ROWTYPE; prior_generation uuid; attempts jsonb; selections jsonb;
 authority jsonb; session_rows jsonb; first_attempt uuid; target text; resume_state text; resume_revision bigint; effects jsonb;
BEGIN
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND rotation_id=p_rotation;
 IF NOT openpc.signing_governance_required(rotation.participant_id,rotation.privacy_domain_id,p_rotation,p_action)
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GOVERNANCE-NOT-REQUIRED'; END IF;
 SELECT * INTO hold FROM control.signing_rotation_authority_hold WHERE participant_id=rotation.participant_id
  AND privacy_domain_id=rotation.privacy_domain_id AND rotation_id=p_rotation AND state='ACTIVE';
 SELECT c.* INTO STRICT original FROM control.signing_rotation_command c WHERE c.participant_id=rotation.participant_id
  AND c.privacy_domain_id=rotation.privacy_domain_id AND c.rotation_id=p_rotation AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'
  AND ((hold.hold_id IS NOT NULL AND c.operation_id=hold.operation_id) OR
   (hold.hold_id IS NULL AND rotation.state='FAILED' AND c.state='FAILED' AND c.result_revision=rotation.revision AND c.result_kind='PROVIDER_REJECTED') OR
   (hold.hold_id IS NULL AND p_action='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'
    AND c.state='FAILED' AND c.from_revision=rotation.revision AND c.result_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH'))
  ORDER BY c.updated_at DESC,c.operation_id DESC LIMIT 1;
 SELECT attempt_id INTO STRICT first_attempt FROM control.signing_provider_attempt WHERE participant_id=rotation.participant_id
  AND privacy_domain_id=rotation.privacy_domain_id AND operation_id=original.operation_id AND request->>'method'<>'SIGN_RECEIPT'
  ORDER BY attempt_id LIMIT 1;
 authority:=openpc.signing_attempt_authority_status(first_attempt);
 SELECT coalesce(jsonb_agg(value-ARRAY['idle_expires_at','row_version'] ORDER BY value->>'session_id'),'[]'::jsonb)
  INTO session_rows FROM jsonb_array_elements(authority->'dependencies'->'session') value;
 authority:=jsonb_set(authority,'{dependencies,session}',session_rows);
 SELECT coalesce(jsonb_agg(value-'row_version' ORDER BY value->>'credential_id'),'[]'::jsonb)
  INTO session_rows FROM jsonb_array_elements(authority->'dependencies'->'credential') value;
 authority:=jsonb_set(authority,'{dependencies,credential}',session_rows);
 SELECT generation_id INTO prior_generation FROM control.signing_authorization_generation WHERE participant_id=rotation.participant_id
  AND privacy_domain_id=rotation.privacy_domain_id AND rotation_id=p_rotation AND state='CONSUMED' ORDER BY result_revision DESC LIMIT 1;
 SELECT jsonb_agg(jsonb_build_object('attemptId',a.attempt_id,'method',a.request->>'method','state',a.state,
  'requestDigest',encode(a.request_digest,'hex'),'observationDigest',encode(a.observation_digest,'hex'),
  'dispatchedAtNs',a.dispatched_at_ns::text,'latestObservationDigest',encode(o.observation_digest,'hex')) ORDER BY a.attempt_id)
 INTO attempts FROM control.signing_provider_attempt a LEFT JOIN LATERAL(SELECT observation_digest FROM control.signing_rotation_observation
  WHERE participant_id=a.participant_id AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id
  ORDER BY observed_at_ns DESC,observation_id DESC LIMIT 1) o ON true
 WHERE a.participant_id=rotation.participant_id AND a.privacy_domain_id=rotation.privacy_domain_id AND a.operation_id=original.operation_id
  AND a.request->>'method'<>'SIGN_RECEIPT';
 SELECT jsonb_agg(jsonb_build_object('profileDigest',encode(s.profile_digest,'hex'),'signerId',s.signer_id,
  'selectionVersion',s.row_version::text,'admissionVersion',s.admission_version::text,'fenceGeneration',s.fence_generation::text,'fencedOperationId',s.fenced_operation_id)
  ORDER BY s.profile_digest) INTO selections FROM control.business_signing_selection s JOIN control.business_signing_key k
  USING(participant_id,privacy_domain_id,signer_id) WHERE s.participant_id=rotation.participant_id AND s.privacy_domain_id=rotation.privacy_domain_id
  AND s.environment_id=rotation.environment_id AND k.workload_credential_id=rotation.workload_credential_id;
 IF p_action='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' THEN target:=original.to_state;
 ELSIF rotation.state='FAILED' THEN
  target:='RECOVERING';
  SELECT from_state,from_revision INTO STRICT resume_state,resume_revision FROM control.signing_provider_attempt
   WHERE attempt_id=first_attempt;
 ELSE target:=rotation.state; resume_state:=rotation.recovery_from_state; resume_revision:=rotation.recovery_from_revision;
 END IF;
 effects:=openpc.signing_transition_effects(p_action,rotation.state,target);
 IF effects IS NULL THEN RAISE EXCEPTION 'DATA-6022-SIGNING-GOVERNANCE-MATRIX'; END IF;
 RETURN jsonb_build_object('schema','pc.control.signing-governance-context.v1','participantId',rotation.participant_id,
  'privacyDomainId',rotation.privacy_domain_id,'rotationId',p_rotation,'actionIntentId',p_action,'revision',rotation.revision::text,
  'state',rotation.state,'cutoverAtNs',rotation.cutover_at_ns::text,'newFingerprint',rotation.new_signer_id,
  'holdId',hold.hold_id,'holdReason',hold.reason,'originalOperationId',original.operation_id,
  'originalInputDigest',encode(original.input_digest,'hex'),'originalAuthorityDigest',encode(original.authorization_snapshot_digest,'hex'),
  'originalApprovalId',original.approval_request_id,'originalApprovalDigest',encode(original.approval_candidate_digest,'hex'),
  'originalAuthority',authority,'attempts',attempts,'selections',selections,'priorGenerationId',prior_generation,
  'targetState',target,'resumeState',resume_state,'resumeRevision',resume_revision::text);
END $$;
CREATE OR REPLACE FUNCTION openpc.signing_canonical_json(p_value jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE encoded text;
BEGIN
 CASE jsonb_typeof(p_value)
 WHEN 'object' THEN SELECT '{'||coalesce(string_agg(to_jsonb(key)::text||':'||openpc.signing_canonical_json(value),',' ORDER BY key COLLATE "C"),'')||'}'
  INTO encoded FROM jsonb_each(p_value);
 WHEN 'array' THEN SELECT '['||coalesce(string_agg(openpc.signing_canonical_json(value),',' ORDER BY ordinal),'')||']'
  INTO encoded FROM jsonb_array_elements(p_value) WITH ORDINALITY entries(value,ordinal);
 ELSE encoded:=p_value::text;
 END CASE;
 RETURN encoded;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_signing_generation_current(p_generation uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE generation control.signing_authorization_generation%ROWTYPE; candidate control.mutation_candidate%ROWTYPE;
BEGIN
 SELECT * INTO STRICT generation FROM control.signing_authorization_generation WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND generation_id=p_generation AND state='STAGED';
 SELECT * INTO STRICT candidate FROM control.mutation_candidate WHERE participant_id=generation.participant_id
  AND privacy_domain_id=generation.privacy_domain_id AND mutation_candidate_id=generation.candidate_id
  AND candidate_digest=generation.candidate_digest AND state='APPROVED' AND expires_at>clock_timestamp();
 IF candidate.candidate_document->'context' IS DISTINCT FROM openpc.signing_governance_context(generation.rotation_id,generation.action_intent_id)
  OR NOT EXISTS(SELECT 1 FROM control.approval_request a JOIN control.approval_decision_record d
   USING(participant_id,privacy_domain_id,approval_request_id) WHERE a.participant_id=generation.participant_id
    AND a.privacy_domain_id=generation.privacy_domain_id AND a.subject_id=generation.candidate_id AND a.subject_digest=generation.candidate_digest
    AND a.subject_version=generation.from_revision AND a.state='APPROVED' AND a.expires_at>clock_timestamp()
    AND d.decision='APPROVE' AND d.approver_principal_id<>a.maker_principal_id AND d.candidate_digest=generation.candidate_digest)
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GOVERNANCE-STALE'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_signing_generation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE candidate control.mutation_candidate%ROWTYPE; context jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-SIGNING-GENERATION'; END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT candidate FROM control.mutation_candidate WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
   AND mutation_candidate_id=NEW.candidate_id AND candidate_digest=NEW.candidate_digest AND action_intent_id=NEW.action_intent_id
   AND resource_id=NEW.rotation_id AND expected_revision=NEW.from_revision AND state IN ('PROPOSED','APPROVAL_REQUESTED','APPROVED') AND expires_at>clock_timestamp();
  context:=openpc.signing_governance_context(NEW.rotation_id,NEW.action_intent_id);
  IF NEW.state<>'STAGED' OR NEW.consumed_operation_id IS NOT NULL OR NEW.result_revision IS NOT NULL
   OR NEW.action_intent_id IS DISTINCT FROM openpc.current_action_intent_id()
   OR candidate.candidate_document IS DISTINCT FROM jsonb_build_object('schema','pc.control.signing-governance-candidate.v1',
    'context',context,'input',candidate.candidate_document->'input','maker',candidate.candidate_document->'maker')
   OR NEW.candidate_digest<>sha256(convert_to(openpc.signing_canonical_json(candidate.candidate_document),'UTF8'))
   OR NEW.input_digest<>sha256(convert_to(openpc.signing_canonical_json(candidate.candidate_document->'input'),'UTF8'))
   OR NEW.original_operation_id::text IS DISTINCT FROM context->>'originalOperationId'
   OR NEW.prior_generation_id::text IS DISTINCT FROM context->>'priorGenerationId'
   OR NEW.hold_id::text IS DISTINCT FROM context->>'holdId' OR NEW.target_state IS DISTINCT FROM context->>'targetState'
   OR NEW.resume_state IS DISTINCT FROM context->>'resumeState' OR NEW.resume_revision::text IS DISTINCT FROM context->>'resumeRevision'
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GENERATION-CANDIDATE'; END IF;
 ELSE
  IF OLD.state<>'STAGED' OR NEW.state<>'CONSUMED' OR NEW.consumed_operation_id IS DISTINCT FROM openpc.current_operation_id()
   OR NEW.result_revision<>NEW.from_revision+1
   OR (to_jsonb(NEW)-ARRAY['state','consumed_operation_id','result_revision']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','consumed_operation_id','result_revision'])
   OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_history h JOIN control.signing_rotation_command c USING(participant_id,privacy_domain_id,operation_id)
    WHERE h.participant_id=NEW.participant_id AND h.privacy_domain_id=NEW.privacy_domain_id AND h.rotation_id=NEW.rotation_id
     AND h.operation_id=NEW.consumed_operation_id AND h.revision=NEW.result_revision AND h.receipt_id IS NOT NULL
     AND c.authorization_generation_id=NEW.generation_id AND c.from_revision=NEW.from_revision AND c.input_digest=NEW.input_digest)
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GENERATION-SIGNED-COMMIT'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS signing_generation_guard ON control.signing_authorization_generation;
CREATE TRIGGER signing_generation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_authorization_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_generation();
CREATE OR REPLACE FUNCTION openpc.check_signing_generation_completion()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.state<>'CONSUMED' THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_candidate candidate JOIN control.signing_rotation_command command
  ON command.participant_id=candidate.participant_id AND command.privacy_domain_id=candidate.privacy_domain_id
   AND command.operation_id=candidate.consumed_operation_id JOIN control.audit_occurrence receipt
   ON receipt.participant_id=command.participant_id AND receipt.privacy_domain_id=command.privacy_domain_id AND receipt.operation_id=command.operation_id
  WHERE candidate.mutation_candidate_id=NEW.candidate_id AND candidate.state='CONSUMED' AND candidate.consumed_operation_id=NEW.consumed_operation_id
   AND command.authorization_generation_id=NEW.generation_id AND command.state IN ('SUCCEEDED','FAILED') AND command.result_revision=NEW.result_revision
   AND receipt.after_revision=NEW.result_revision AND receipt.before_revision=NEW.from_revision
   AND (NEW.hold_id IS NULL OR EXISTS(SELECT 1 FROM control.signing_rotation_authority_hold h WHERE h.hold_id=NEW.hold_id
    AND h.state='CLEARED' AND h.cleared_by_operation_id=NEW.consumed_operation_id)))
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GENERATION-INCOMPLETE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS signing_generation_complete ON control.signing_authorization_generation;
CREATE CONSTRAINT TRIGGER signing_generation_complete AFTER UPDATE ON control.signing_authorization_generation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_signing_generation_completion();


CREATE OR REPLACE FUNCTION openpc.authentication_occurrence_receipt(
 p_id uuid,p_participant uuid,p_privacy uuid,p_principal uuid,p_session uuid,p_operation uuid,
 p_method text,p_source uuid,p_credential uuid,p_context text,p_proof bytea,p_occurred timestamptz)
RETURNS bytea LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,openpc,control AS $$
 SELECT convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'version','OPENPC_AUTHENTICATION_OCCURRENCE_V1','occurrenceId',p_id::text,
  'participantId',p_participant::text,'privacyDomainId',p_privacy::text,'principalId',p_principal::text,
  'operationId',p_operation::text,'method',p_method,'sourceId',p_source::text,
  'credentialDigest','sha256:'||encode(sha256(convert_to(p_credential::text,'UTF8')),'hex'),
  'contextMode',p_context,'proofDigest','sha256:'||encode(p_proof,'hex'),
  'occurredAt',to_char(p_occurred at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'authorityEffect','NONE','integrity','CONTROL_DATABASE_IMMUTABLE') ||
  CASE WHEN p_method='TLS13_MTLS' THEN jsonb_build_object('transportBindingDigest','sha256:'||encode(p_proof,'hex'))
  ELSE jsonb_build_object('sessionBindingDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
    'domain','openpc.authentication.session.v1','participantId',p_participant::text,'sessionId',p_session::text)),'UTF8')),'hex')) END),'UTF8')
$$;
CREATE OR REPLACE FUNCTION openpc.check_authentication_occurrence()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,openpc,control AS $$
DECLARE s record; c record; source record; expected_proof bytea;
BEGIN
 IF NEW.operation_id<>openpc.current_operation_id() OR NOT openpc.matches_participant(NEW.participant_id)
  OR NEW.occurred_at>clock_timestamp()+interval '5 seconds'
  OR NEW.occurred_at<clock_timestamp()-interval '5 minutes' THEN
  RAISE EXCEPTION 'IDENTITY-1004-AUTHENTICATION-OCCURRENCE-CONTEXT'; END IF;
 SELECT * INTO c FROM control.credential WHERE participant_id=NEW.participant_id AND credential_id=NEW.credential_id;
 IF NEW.method='TLS13_MTLS' THEN
  SELECT principal.*,participant.root_privacy_domain_id,participant.state participant_state INTO s
   FROM control.principal principal JOIN control.participant participant USING(participant_id)
   WHERE principal.participant_id=NEW.participant_id AND principal.principal_id=NEW.principal_id;
  IF c.credential_id IS NULL OR s.principal_id IS NULL OR c.principal_id<>NEW.principal_id
   OR c.kind<>'WORKLOAD_MTLS' OR c.state<>'ACTIVE' OR s.kind<>'WORKLOAD' OR s.state<>'ACTIVE' OR s.participant_state<>'ACTIVE'
   OR NEW.session_id IS NOT NULL OR NEW.context_mode<>'WORKLOAD' OR NEW.source_id<>NEW.operation_id
   OR NEW.occurred_at<>c.last_used_at OR c.valid_from>NEW.occurred_at OR c.valid_until<=NEW.occurred_at
   OR NEW.privacy_domain_id IS DISTINCT FROM coalesce(nullif(current_setting('openpc.privacy_domain_id',true),'')::uuid,s.root_privacy_domain_id)
   OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' THEN
   RAISE EXCEPTION 'IDENTITY-1006-AUTHENTICATION-MTLS-SOURCE'; END IF;
  expected_proof:=NEW.proof_digest;
 ELSE
 SELECT session.*,p.root_privacy_domain_id INTO s FROM control.session session
  JOIN control.participant p USING(participant_id)
  WHERE session.participant_id=NEW.participant_id AND session.session_id=NEW.session_id;
 IF s.session_id IS NULL OR c.credential_id IS NULL OR s.principal_id<>NEW.principal_id
  OR c.principal_id<>NEW.principal_id OR s.context_mode::text<>NEW.context_mode
  OR NEW.privacy_domain_id IS DISTINCT FROM coalesce(s.privacy_domain_id,s.root_privacy_domain_id)
  OR s.state<>'ACTIVE' OR c.state<>'ACTIVE' THEN
  RAISE EXCEPTION 'IDENTITY-1004-AUTHENTICATION-OCCURRENCE-SCOPE'; END IF;
 IF NEW.method='OIDC_CODE_PKCE_S256' THEN
  SELECT * INTO source FROM control.oidc_transaction WHERE transaction_id=NEW.source_id;
  IF source.transaction_id IS NULL OR source.consumed_at IS NULL OR source.purpose<>'SESSION'
   OR c.kind<>'OIDC_SUBJECT' OR c.issuer<>source.issuer OR c.audience<>source.client_id
   OR (source.selected_participant_id IS NOT NULL AND source.selected_participant_id<>NEW.participant_id)
   OR NEW.context_mode<>'PLATFORM' OR NEW.occurred_at<>s.issued_at
   OR openpc.current_action_intent_id()<>'ACT-IDENTITY_CREATE_SESSION-V1' THEN
   RAISE EXCEPTION 'IDENTITY-1004-AUTHENTICATION-OIDC-SOURCE'; END IF;
  expected_proof:=sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
   'version','OPENPC_OIDC_VERIFIED_V1','sourceId',source.transaction_id::text,'credentialId',NEW.credential_id::text,
   'stateDigest',encode(source.state_digest,'hex'),'nonceDigest',encode(source.nonce_digest,'hex'),
   'pkceDigest',encode(source.code_verifier_digest,'hex'),'browserDigest',encode(source.browser_session_digest,'hex'))),'UTF8'));
 ELSE
  SELECT challenge.* INTO source FROM control.mfa_challenge challenge
   WHERE challenge.participant_id=NEW.participant_id AND challenge.mfa_challenge_id=NEW.source_id;
  IF source.mfa_challenge_id IS NULL OR source.consumed_at IS NULL
   OR source.session_id<>NEW.session_id OR source.principal_id<>NEW.principal_id OR c.kind<>'WEBAUTHN'
   OR openpc.current_action_intent_id()<>'ACT-IDENTITY_UPDATE_STEP_UP-V1' THEN
   RAISE EXCEPTION 'IDENTITY-1004-AUTHENTICATION-WEBAUTHN-SOURCE'; END IF;
  SELECT evidence.webauthn_assertion_binding_digest INTO expected_proof FROM control.mutation_evidence evidence
   WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
    AND evidence.operation_id=NEW.operation_id AND evidence.principal_id=NEW.principal_id
    AND evidence.aggregate_id=NEW.session_id AND evidence.mfa_challenge_id=NEW.source_id
    AND evidence.signer_credential_id=NEW.credential_id AND evidence.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY';
 END IF;
 END IF;
 IF expected_proof IS NULL OR NEW.proof_digest<>expected_proof
  OR NEW.receipt<>openpc.authentication_occurrence_receipt(NEW.occurrence_id,NEW.participant_id,NEW.privacy_domain_id,
    NEW.principal_id,NEW.session_id,NEW.operation_id,NEW.method,NEW.source_id,NEW.credential_id,NEW.context_mode,
    NEW.proof_digest,NEW.occurred_at) THEN
  RAISE EXCEPTION 'IDENTITY-1004-AUTHENTICATION-OCCURRENCE-INTEGRITY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authentication_occurrence_verified ON control.authentication_occurrence;
CREATE CONSTRAINT TRIGGER authentication_occurrence_verified AFTER INSERT ON control.authentication_occurrence
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_authentication_occurrence();
DROP TRIGGER IF EXISTS authentication_occurrence_immutable ON control.authentication_occurrence;
CREATE TRIGGER authentication_occurrence_immutable BEFORE UPDATE OR DELETE ON control.authentication_occurrence
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();


CREATE OR REPLACE FUNCTION openpc.guard_installed_secret_recipient() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,openpc,control AS $$
BEGIN
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE') THEN
   RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secret-recipient:'||coalesce(NEW.participant_id,OLD.participant_id)::text||':'||coalesce(NEW.privacy_domain_id,OLD.privacy_domain_id)::text,0));
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND
   (OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR
    (to_jsonb(OLD)-'state') IS DISTINCT FROM (to_jsonb(NEW)-'state'))) THEN
   RAISE EXCEPTION 'OPS-SECRET-INSTALLATION-IMMUTABLE';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS installed_secret_recipient_guard ON control.installed_secret_recipient;
CREATE TRIGGER installed_secret_recipient_guard BEFORE INSERT OR UPDATE OR DELETE ON control.installed_secret_recipient
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_installed_secret_recipient();


CREATE OR REPLACE FUNCTION openpc.check_notification_completion_phase_proof(proof jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE now_ms numeric; p uuid; privacy uuid; installation record;
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 PERFORM openpc.assert_request_context(true);
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF current_setting('transaction_isolation')<>'read committed'
  OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
  OR jsonb_typeof(proof) IS DISTINCT FROM 'object'
  OR proof IS DISTINCT FROM jsonb_build_object('version',2,'receiptBinding',proof->'receiptBinding','transactionId',pg_current_xact_id()::text,
   'backendPid',pg_backend_pid(),'databaseRole',session_user,
   'participantId',openpc.current_participant_id()::text,'privacyDomainId',openpc.current_privacy_domain_id()::text,
   'eventId',proof->'eventId','phase',proof->'phase','installationDigest',proof->'installationDigest',
   'authorityDigest',proof->'authorityDigest','principalId',proof->'principalId','credentialId',proof->'credentialId',
   'participantEpoch',proof->'participantEpoch','principalEpoch',proof->'principalEpoch','workloadEpoch',proof->'workloadEpoch',
   'workloadId',proof->'workloadId','uriSan',proof->'uriSan','keyId',proof->'keyId',
   'issuedAtMs',proof->'issuedAtMs','expiresAtMs',proof->'expiresAtMs')
  OR coalesce(proof->>'phase','') NOT IN ('SOURCE','CLAIM','LIMIT','FINISH','PREPARE','SIGN_CLAIM','OBSERVE','PUBLISH')
  OR EXISTS(SELECT 1 FROM (VALUES('eventId'),('principalId'),('credentialId')) f(name)
   WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM 'string' OR coalesce(proof->>f.name,'') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
  OR EXISTS(SELECT 1 FROM (VALUES('installationDigest'),('authorityDigest'),('keyId')) f(name)
   WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM 'string' OR coalesce(proof->>f.name,'') !~ '^sha256:[0-9a-f]{64}$')
  OR EXISTS(SELECT 1 FROM (VALUES('participantEpoch'),('principalEpoch'),('workloadEpoch')) f(name)
   WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM 'string' OR coalesce(proof->>f.name,'') !~ '^[1-9][0-9]{0,19}$')
  OR jsonb_typeof(proof->'issuedAtMs') IS DISTINCT FROM 'number'
  OR jsonb_typeof(proof->'expiresAtMs') IS DISTINCT FROM 'number'
  OR (proof->>'issuedAtMs')::numeric<>trunc((proof->>'issuedAtMs')::numeric)
  OR (proof->>'expiresAtMs')::numeric<>trunc((proof->>'expiresAtMs')::numeric)
  OR (proof->>'issuedAtMs')::numeric>now_ms OR (proof->>'issuedAtMs')::numeric<now_ms-5000
  OR (proof->>'expiresAtMs')::numeric<=now_ms
  OR (proof->>'expiresAtMs')::numeric>(proof->>'issuedAtMs')::numeric+5000
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-PROOF'; END IF;
 IF proof->'receiptBinding' IS DISTINCT FROM 'null'::jsonb THEN
  IF proof->>'phase' NOT IN ('OBSERVE','PUBLISH') OR jsonb_typeof(proof->'receiptBinding') IS DISTINCT FROM 'object'
   OR proof->'receiptBinding' IS DISTINCT FROM jsonb_build_object(
    'schema','pc.notification.completion-verified-receipt.v1','purpose','pc.cose.notification-completion-disposition-receipt.v1',
    'requestDigest',proof->'receiptBinding'->'requestDigest','preparationDigest',proof->'receiptBinding'->'preparationDigest',
    'payloadDigest',proof->'receiptBinding'->'payloadDigest','coseDigest',proof->'receiptBinding'->'coseDigest',
    'observationDigest',proof->'receiptBinding'->'observationDigest','signerInstallationDigest',proof->'receiptBinding'->'signerInstallationDigest',
    'signerKeyId',proof->'receiptBinding'->'signerKeyId','originalWorkerInstallationDigest',proof->'receiptBinding'->'originalWorkerInstallationDigest',
    'producerTrustDigest',proof->'receiptBinding'->'producerTrustDigest','environmentId',proof->'receiptBinding'->'environmentId')
   OR EXISTS(SELECT 1 FROM (VALUES('requestDigest'),('preparationDigest'),('payloadDigest'),('coseDigest'),('observationDigest'),
     ('signerInstallationDigest'),('signerKeyId'),('originalWorkerInstallationDigest'),('producerTrustDigest')) f(name)
     WHERE jsonb_typeof(proof->'receiptBinding'->f.name) IS DISTINCT FROM 'string'
      OR coalesce(proof->'receiptBinding'->>f.name,'') !~ '^sha256:[0-9a-f]{64}$')
   OR jsonb_typeof(proof->'receiptBinding'->'environmentId') IS DISTINCT FROM 'string'
   OR length(proof->'receiptBinding'->>'environmentId') NOT BETWEEN 1 AND 160
  THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-RECEIPT'; END IF;
 END IF;
 p:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 -- The Identity callback holds the authority fences. These exact row locks
 -- also prevent a direct verifier invocation racing a committed withdrawal.
 PERFORM 1 FROM control.participant x WHERE x.participant_id=p AND x.state='ACTIVE'
  AND x.authority_epoch::text=proof->>'participantEpoch' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-CURRENT'; END IF;
 PERFORM 1 FROM control.privacy_domain x WHERE x.participant_id=p AND x.privacy_domain_id=privacy
  AND x.state='ACTIVE' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-CURRENT'; END IF;
 PERFORM 1 FROM control.principal x WHERE x.participant_id=p AND x.principal_id=(proof->>'principalId')::uuid
  AND x.kind='WORKLOAD' AND x.state='ACTIVE' AND x.authority_epoch::text=proof->>'principalEpoch' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-CURRENT'; END IF;
 PERFORM 1 FROM control.credential x WHERE x.participant_id=p AND x.credential_id=(proof->>'credentialId')::uuid
  AND x.principal_id=(proof->>'principalId')::uuid AND x.kind='WORKLOAD_MTLS' AND x.state='ACTIVE'
  AND x.credential_epoch::text=proof->>'workloadEpoch' AND x.audience=proof->>'workloadId'
  AND x.subject=proof->>'uriSan' AND x.public_key_digest=decode(substring(proof->>'keyId' from 8),'hex')
  AND x.valid_from<=clock_timestamp() AND x.valid_until>clock_timestamp()
  AND extract(epoch from x.valid_until)*1000>=(proof->>'expiresAtMs')::numeric FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-CURRENT'; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('notification-completion-worker:'||p::text||':'||privacy::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM openpc.assert_notification_completion_worker_installation_owner();
 SELECT * INTO STRICT installation FROM control.installed_notification_completion_worker x
  WHERE x.participant_id=p AND x.privacy_domain_id=privacy AND x.installation_digest=proof->>'installationDigest'
   AND x.state='ACTIVE' AND x.principal_id=(proof->>'principalId')::uuid
   AND x.workload_credential_id=(proof->>'credentialId')::uuid
   AND x.service_id='LS-CONTROL-WORK' AND x.subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1' FOR SHARE NOWAIT;
 IF installation.installation->'pins'->>'workloadEpoch' IS DISTINCT FROM proof->>'workloadEpoch'
  OR installation.installation->'pins'->>'workloadId' IS DISTINCT FROM proof->>'workloadId'
  OR installation.installation->'pins'->>'workloadKeyDigest' IS DISTINCT FROM proof->>'keyId'
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-WORKER'; END IF;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'PC-DATA-6007';
END $$;

CREATE OR REPLACE FUNCTION openpc.admit_notification_completion_phase(wire bytea,nonce bytea,mac bytea) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE proof jsonb; secret bytea; expected bytea; different integer:=0;
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 IF wire IS NULL OR octet_length(wire) NOT BETWEEN 1 AND 8192 OR nonce IS NULL OR octet_length(nonce)<>32
  OR mac IS NULL OR octet_length(mac)<>32 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.notification_completion_admission_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to('OPENPC_NOTIFICATION_COMPLETION_PHASE_ADMISSION_V1','UTF8')||sha256(wire)||nonce,secret,'sha256');
 FOR i IN 0..31 LOOP different:=different | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 proof:=convert_from(wire,'UTF8')::jsonb;
 PERFORM openpc.check_notification_completion_phase_proof(proof);
 INSERT INTO control.notification_completion_phase_admission(database_role,transaction_id,backend_pid,
  participant_id,privacy_domain_id,event_id,phase,proof,receipt_binding)
 VALUES(session_user,pg_current_xact_id()::text,pg_backend_pid(),openpc.current_participant_id(),
  openpc.current_privacy_domain_id(),(proof->>'eventId')::uuid,proof->>'phase',proof,nullif(proof->'receiptBinding','null'::jsonb))
 ON CONFLICT(database_role,transaction_id,event_id,phase) DO UPDATE SET proof=excluded.proof,receipt_binding=excluded.receipt_binding
 WHERE notification_completion_phase_admission.participant_id=excluded.participant_id
  AND notification_completion_phase_admission.privacy_domain_id=excluded.privacy_domain_id
  AND notification_completion_phase_admission.backend_pid=excluded.backend_pid
  AND notification_completion_phase_admission.proof->>'installationDigest'=excluded.proof->>'installationDigest'
  AND notification_completion_phase_admission.proof->>'authorityDigest'=excluded.proof->>'authorityDigest'
  AND (notification_completion_phase_admission.receipt_binding IS NULL
   OR notification_completion_phase_admission.receipt_binding=excluded.receipt_binding);
 IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-CONFLICT'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.require_notification_completion_disposition_authority(event uuid,phase text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE original jsonb;
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 SELECT a.proof INTO STRICT original FROM control.notification_completion_phase_admission a
 WHERE a.database_role=session_user AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
  AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id()
  AND a.event_id=event AND a.phase=$2;
 PERFORM openpc.check_notification_completion_phase_proof(original);
END $$;

CREATE OR REPLACE FUNCTION openpc.clear_notification_completion_phases() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 PERFORM openpc.assert_request_context(true);
 DELETE FROM control.notification_completion_phase_admission a WHERE a.database_role=session_user
  AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
  AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id();
END $$;

CREATE OR REPLACE FUNCTION openpc.notification_completion_verified_receipt(event uuid,phase text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE verified jsonb;
BEGIN
 PERFORM openpc.require_notification_completion_disposition_authority(event,phase);
 IF phase IS NULL OR phase NOT IN ('OBSERVE','PUBLISH') THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-RECEIPT'; END IF;
 SELECT a.receipt_binding INTO STRICT verified FROM control.notification_completion_phase_admission a
  WHERE a.database_role=session_user AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
   AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id()
   AND a.event_id=event AND a.phase=$2 AND a.receipt_binding=a.proof->'receiptBinding';
 IF verified IS NULL THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-RECEIPT'; END IF;
 RETURN verified;
END $$;

CREATE OR REPLACE FUNCTION openpc.notification_completion_phase_binding(event uuid,phase text)
RETURNS TABLE(installation_digest text,authority_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
BEGIN
 PERFORM openpc.require_notification_completion_disposition_authority(event,phase);
 RETURN QUERY SELECT a.proof->>'installationDigest',a.proof->>'authorityDigest'
 FROM control.notification_completion_phase_admission a WHERE a.database_role=session_user
  AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
  AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id()
  AND a.event_id=event AND a.phase=$2;
END $$;

CREATE OR REPLACE FUNCTION openpc.assert_notification_completion_admission_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF current_setting('row_security')<>'on' OR current_setting('session_replication_role')<>'origin'
 OR NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
   WHERE p.oid=to_regprocedure('openpc.check_notification_completion_phase_proof(jsonb)') AND r.rolname='openpc_control_owner'
   AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='v'
   AND p.proconfig=ARRAY['search_path=pg_catalog','row_security=on'] AND p.prosrc='
DECLARE now_ms numeric; p uuid; privacy uuid; installation record;
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 PERFORM openpc.assert_request_context(true);
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF current_setting(''transaction_isolation'')<>''read committed''
  OR openpc.current_action_intent_id()<>''ACT-POLICY_READ_EFFECTIVE_ACCESS-V1''
  OR jsonb_typeof(proof) IS DISTINCT FROM ''object''
  OR proof IS DISTINCT FROM jsonb_build_object(''version'',2,''receiptBinding'',proof->''receiptBinding'',''transactionId'',pg_current_xact_id()::text,
   ''backendPid'',pg_backend_pid(),''databaseRole'',session_user,
   ''participantId'',openpc.current_participant_id()::text,''privacyDomainId'',openpc.current_privacy_domain_id()::text,
   ''eventId'',proof->''eventId'',''phase'',proof->''phase'',''installationDigest'',proof->''installationDigest'',
   ''authorityDigest'',proof->''authorityDigest'',''principalId'',proof->''principalId'',''credentialId'',proof->''credentialId'',
   ''participantEpoch'',proof->''participantEpoch'',''principalEpoch'',proof->''principalEpoch'',''workloadEpoch'',proof->''workloadEpoch'',
   ''workloadId'',proof->''workloadId'',''uriSan'',proof->''uriSan'',''keyId'',proof->''keyId'',
   ''issuedAtMs'',proof->''issuedAtMs'',''expiresAtMs'',proof->''expiresAtMs'')
  OR coalesce(proof->>''phase'','''') NOT IN (''SOURCE'',''CLAIM'',''LIMIT'',''FINISH'',''PREPARE'',''SIGN_CLAIM'',''OBSERVE'',''PUBLISH'')
  OR EXISTS(SELECT 1 FROM (VALUES(''eventId''),(''principalId''),(''credentialId'')) f(name)
   WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM ''string'' OR coalesce(proof->>f.name,'''') !~ ''^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'')
  OR EXISTS(SELECT 1 FROM (VALUES(''installationDigest''),(''authorityDigest''),(''keyId'')) f(name)
   WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM ''string'' OR coalesce(proof->>f.name,'''') !~ ''^sha256:[0-9a-f]{64}$'')
  OR EXISTS(SELECT 1 FROM (VALUES(''participantEpoch''),(''principalEpoch''),(''workloadEpoch'')) f(name)
   WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM ''string'' OR coalesce(proof->>f.name,'''') !~ ''^[1-9][0-9]{0,19}$'')
  OR jsonb_typeof(proof->''issuedAtMs'') IS DISTINCT FROM ''number''
  OR jsonb_typeof(proof->''expiresAtMs'') IS DISTINCT FROM ''number''
  OR (proof->>''issuedAtMs'')::numeric<>trunc((proof->>''issuedAtMs'')::numeric)
  OR (proof->>''expiresAtMs'')::numeric<>trunc((proof->>''expiresAtMs'')::numeric)
  OR (proof->>''issuedAtMs'')::numeric>now_ms OR (proof->>''issuedAtMs'')::numeric<now_ms-5000
  OR (proof->>''expiresAtMs'')::numeric<=now_ms
  OR (proof->>''expiresAtMs'')::numeric>(proof->>''issuedAtMs'')::numeric+5000
 THEN RAISE EXCEPTION ''NOTIFICATION-COMPLETION-NATIVE-PROOF''; END IF;
 IF proof->''receiptBinding'' IS DISTINCT FROM ''null''::jsonb THEN
  IF proof->>''phase'' NOT IN (''OBSERVE'',''PUBLISH'') OR jsonb_typeof(proof->''receiptBinding'') IS DISTINCT FROM ''object''
   OR proof->''receiptBinding'' IS DISTINCT FROM jsonb_build_object(
    ''schema'',''pc.notification.completion-verified-receipt.v1'',''purpose'',''pc.cose.notification-completion-disposition-receipt.v1'',
    ''requestDigest'',proof->''receiptBinding''->''requestDigest'',''preparationDigest'',proof->''receiptBinding''->''preparationDigest'',
    ''payloadDigest'',proof->''receiptBinding''->''payloadDigest'',''coseDigest'',proof->''receiptBinding''->''coseDigest'',
    ''observationDigest'',proof->''receiptBinding''->''observationDigest'',''signerInstallationDigest'',proof->''receiptBinding''->''signerInstallationDigest'',
    ''signerKeyId'',proof->''receiptBinding''->''signerKeyId'',''originalWorkerInstallationDigest'',proof->''receiptBinding''->''originalWorkerInstallationDigest'',
    ''producerTrustDigest'',proof->''receiptBinding''->''producerTrustDigest'',''environmentId'',proof->''receiptBinding''->''environmentId'')
   OR EXISTS(SELECT 1 FROM (VALUES(''requestDigest''),(''preparationDigest''),(''payloadDigest''),(''coseDigest''),(''observationDigest''),
     (''signerInstallationDigest''),(''signerKeyId''),(''originalWorkerInstallationDigest''),(''producerTrustDigest'')) f(name)
     WHERE jsonb_typeof(proof->''receiptBinding''->f.name) IS DISTINCT FROM ''string''
      OR coalesce(proof->''receiptBinding''->>f.name,'''') !~ ''^sha256:[0-9a-f]{64}$'')
   OR jsonb_typeof(proof->''receiptBinding''->''environmentId'') IS DISTINCT FROM ''string''
   OR length(proof->''receiptBinding''->>''environmentId'') NOT BETWEEN 1 AND 160
  THEN RAISE EXCEPTION ''NOTIFICATION-COMPLETION-NATIVE-RECEIPT''; END IF;
 END IF;
 p:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 -- The Identity callback holds the authority fences. These exact row locks
 -- also prevent a direct verifier invocation racing a committed withdrawal.
 PERFORM 1 FROM control.participant x WHERE x.participant_id=p AND x.state=''ACTIVE''
  AND x.authority_epoch::text=proof->>''participantEpoch'' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION ''NOTIFICATION-COMPLETION-NATIVE-CURRENT''; END IF;
 PERFORM 1 FROM control.privacy_domain x WHERE x.participant_id=p AND x.privacy_domain_id=privacy
  AND x.state=''ACTIVE'' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION ''NOTIFICATION-COMPLETION-NATIVE-CURRENT''; END IF;
 PERFORM 1 FROM control.principal x WHERE x.participant_id=p AND x.principal_id=(proof->>''principalId'')::uuid
  AND x.kind=''WORKLOAD'' AND x.state=''ACTIVE'' AND x.authority_epoch::text=proof->>''principalEpoch'' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION ''NOTIFICATION-COMPLETION-NATIVE-CURRENT''; END IF;
 PERFORM 1 FROM control.credential x WHERE x.participant_id=p AND x.credential_id=(proof->>''credentialId'')::uuid
  AND x.principal_id=(proof->>''principalId'')::uuid AND x.kind=''WORKLOAD_MTLS'' AND x.state=''ACTIVE''
  AND x.credential_epoch::text=proof->>''workloadEpoch'' AND x.audience=proof->>''workloadId''
  AND x.subject=proof->>''uriSan'' AND x.public_key_digest=decode(substring(proof->>''keyId'' from 8),''hex'')
  AND x.valid_from<=clock_timestamp() AND x.valid_until>clock_timestamp()
  AND extract(epoch from x.valid_until)*1000>=(proof->>''expiresAtMs'')::numeric FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION ''NOTIFICATION-COMPLETION-NATIVE-CURRENT''; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended(''notification-completion-worker:''||p::text||'':''||privacy::text,0))
 THEN RAISE EXCEPTION ''PC-DATA-6007''; END IF;
 PERFORM openpc.assert_notification_completion_worker_installation_owner();
 SELECT * INTO STRICT installation FROM control.installed_notification_completion_worker x
  WHERE x.participant_id=p AND x.privacy_domain_id=privacy AND x.installation_digest=proof->>''installationDigest''
   AND x.state=''ACTIVE'' AND x.principal_id=(proof->>''principalId'')::uuid
   AND x.workload_credential_id=(proof->>''credentialId'')::uuid
   AND x.service_id=''LS-CONTROL-WORK'' AND x.subscription_id=''SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'' FOR SHARE NOWAIT;
 IF installation.installation->''pins''->>''workloadEpoch'' IS DISTINCT FROM proof->>''workloadEpoch''
  OR installation.installation->''pins''->>''workloadId'' IS DISTINCT FROM proof->>''workloadId''
  OR installation.installation->''pins''->>''workloadKeyDigest'' IS DISTINCT FROM proof->>''keyId''
 THEN RAISE EXCEPTION ''NOTIFICATION-COMPLETION-NATIVE-WORKER''; END IF;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION ''PC-DATA-6007'';
END ')
 OR NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
   WHERE p.oid=to_regprocedure('openpc.admit_notification_completion_phase(bytea,bytea,bytea)') AND r.rolname='openpc_control_owner'
   AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='v'
   AND p.proconfig=ARRAY['search_path=pg_catalog','row_security=on'] AND p.prosrc='
DECLARE proof jsonb; secret bytea; expected bytea; different integer:=0;
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 IF wire IS NULL OR octet_length(wire) NOT BETWEEN 1 AND 8192 OR nonce IS NULL OR octet_length(nonce)<>32
  OR mac IS NULL OR octet_length(mac)<>32 THEN RAISE EXCEPTION ''PC-AUTH-0005''; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.notification_completion_admission_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to(''OPENPC_NOTIFICATION_COMPLETION_PHASE_ADMISSION_V1'',''UTF8'')||sha256(wire)||nonce,secret,''sha256'');
 FOR i IN 0..31 LOOP different:=different | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION ''PC-AUTH-0005''; END IF;
 proof:=convert_from(wire,''UTF8'')::jsonb;
 PERFORM openpc.check_notification_completion_phase_proof(proof);
 INSERT INTO control.notification_completion_phase_admission(database_role,transaction_id,backend_pid,
  participant_id,privacy_domain_id,event_id,phase,proof,receipt_binding)
 VALUES(session_user,pg_current_xact_id()::text,pg_backend_pid(),openpc.current_participant_id(),
  openpc.current_privacy_domain_id(),(proof->>''eventId'')::uuid,proof->>''phase'',proof,nullif(proof->''receiptBinding'',''null''::jsonb))
 ON CONFLICT(database_role,transaction_id,event_id,phase) DO UPDATE SET proof=excluded.proof,receipt_binding=excluded.receipt_binding
 WHERE notification_completion_phase_admission.participant_id=excluded.participant_id
  AND notification_completion_phase_admission.privacy_domain_id=excluded.privacy_domain_id
  AND notification_completion_phase_admission.backend_pid=excluded.backend_pid
  AND notification_completion_phase_admission.proof->>''installationDigest''=excluded.proof->>''installationDigest''
  AND notification_completion_phase_admission.proof->>''authorityDigest''=excluded.proof->>''authorityDigest''
  AND (notification_completion_phase_admission.receipt_binding IS NULL
   OR notification_completion_phase_admission.receipt_binding=excluded.receipt_binding);
 IF NOT FOUND THEN RAISE EXCEPTION ''NOTIFICATION-COMPLETION-NATIVE-CONFLICT''; END IF;
END ')
 OR NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
   WHERE p.oid=to_regprocedure('openpc.require_notification_completion_disposition_authority(uuid,text)') AND r.rolname='openpc_control_owner'
   AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='v'
   AND p.proconfig=ARRAY['search_path=pg_catalog','row_security=on'] AND p.prosrc='
DECLARE original jsonb;
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 SELECT a.proof INTO STRICT original FROM control.notification_completion_phase_admission a
 WHERE a.database_role=session_user AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
  AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id()
  AND a.event_id=event AND a.phase=$2;
 PERFORM openpc.check_notification_completion_phase_proof(original);
END ')
 OR NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
   WHERE p.oid=to_regprocedure('openpc.clear_notification_completion_phases()') AND r.rolname='openpc_control_owner'
   AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='v'
   AND p.proconfig=ARRAY['search_path=pg_catalog','row_security=on'] AND p.prosrc='
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 PERFORM openpc.assert_request_context(true);
 DELETE FROM control.notification_completion_phase_admission a WHERE a.database_role=session_user
  AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
  AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id();
END ')
 OR NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
   WHERE p.oid=to_regprocedure('openpc.notification_completion_phase_binding(uuid,text)') AND r.rolname='openpc_control_owner'
   AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='v'
   AND p.proconfig=ARRAY['search_path=pg_catalog','row_security=on'] AND p.prosrc='
BEGIN
 PERFORM openpc.require_notification_completion_disposition_authority(event,phase);
 RETURN QUERY SELECT a.proof->>''installationDigest'',a.proof->>''authorityDigest''
 FROM control.notification_completion_phase_admission a WHERE a.database_role=session_user
  AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
  AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id()
  AND a.event_id=event AND a.phase=$2;
END ')
 OR NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
   WHERE p.oid=to_regprocedure('openpc.notification_completion_verified_receipt(uuid,text)') AND r.rolname='openpc_control_owner'
   AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='v'
   AND p.proconfig=ARRAY['search_path=pg_catalog','row_security=on'] AND p.prosrc='
DECLARE verified jsonb;
BEGIN
 PERFORM openpc.require_notification_completion_disposition_authority(event,phase);
 IF phase IS NULL OR phase NOT IN (''OBSERVE'',''PUBLISH'') THEN RAISE EXCEPTION ''NOTIFICATION-COMPLETION-NATIVE-RECEIPT''; END IF;
 SELECT a.receipt_binding INTO STRICT verified FROM control.notification_completion_phase_admission a
  WHERE a.database_role=session_user AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
   AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id()
   AND a.event_id=event AND a.phase=$2 AND a.receipt_binding=a.proof->''receiptBinding'';
 IF verified IS NULL THEN RAISE EXCEPTION ''NOTIFICATION-COMPLETION-NATIVE-RECEIPT''; END IF;
 RETURN verified;
END ')
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['notification_completion_admission_key','notification_completion_phase_admission']) n(name)
  WHERE NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
   WHERE c.oid=to_regclass('control.'||n.name) AND c.relkind='r' AND NOT c.relispartition AND r.rolname='openpc_control_owner'
    AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid))
   OR EXISTS(SELECT 1 FROM unnest(ARRAY['openpc_control_runtime','openpc_control_platform_runtime','openpc_control_worker','openpc_control_reader']) role(name)
    WHERE has_table_privilege(role.name,'control.'||n.name,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
     OR has_any_column_privilege(role.name,'control.'||n.name,'SELECT,INSERT,UPDATE'))
   OR EXISTS(SELECT 1 FROM pg_class c,aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
    WHERE c.oid=to_regclass('control.'||n.name) AND a.grantee=0))
 OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_completion_phase_admission'::regclass AND relrowsecurity AND relforcerowsecurity)
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-OWNER'; END IF;
END $$;

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
REVOKE ALL ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authentication_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."authority_role", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."directory_connector", "control"."directory_group_mapping", "control"."directory_member", "control"."evidence_record", "control"."hardware_authenticator", "control"."idempotency_record", "control"."identity_oidc_binding", "control"."identity_runtime_authority_scope", "control"."identity_runtime_authority_set", "control"."identity_runtime_snapshot", "control"."identity_runtime_snapshot_content", "control"."identity_runtime_snapshot_head", "control"."identity_subject", "control"."installed_secret_recipient", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."notification_completion_admission_key", "control"."notification_completion_phase_admission", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."participant_bootstrap_custody", "control"."participant_invitation", "control"."participant_invitation_acceptance", "control"."participant_invitation_proof", "control"."participant_invitation_token", "control"."participant_lifecycle_transition", "control"."participant_membership", "control"."pending_delivery", "control"."platform_context", "control"."principal", "control"."privacy_domain", "control"."qualified_receipt_checkpoint", "control"."qualified_receipt_inbox", "control"."receipt_signing_attempt", "control"."recovery_challenge", "control"."recovery_principal", "control"."revocation", "control"."session", "control"."signing_authorization_generation", "control"."signing_continuation", "control"."signing_key_rotation", "control"."signing_provider_attempt", "control"."signing_rotation_attestation", "control"."signing_rotation_authority_hold", "control"."signing_rotation_command", "control"."signing_rotation_history", "control"."signing_rotation_observation", "control"."signing_rotation_operation_evidence", "control"."wallet_binding", "control"."webauthn_enrollment", "control"."work_item" FROM PUBLIC;
REVOKE ALL ON FUNCTION openpc.action_intent_semantic_digest(text,text,text,text,boolean,boolean,boolean,text,text,text),openpc.admit_notification_completion_phase(bytea,bytea,bytea),openpc.append_rotation_history(),openpc.assert_mutation_resume_no_effect(uuid),openpc.assert_notification_completion_admission_owner(),openpc.assert_request_context(boolean),openpc.assert_work_item_receipt(control.audit_occurrence),openpc.assignment_group_permits(uuid,uuid,uuid,tstzrange),openpc.assignment_role_permits(uuid,text,text),openpc.authentication_occurrence_receipt(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,text,bytea,timestamptz),openpc.business_bytes(bytea),openpc.business_cbor(bytea),openpc.business_cbor_item(bytea,integer,integer),openpc.business_request_digest(text[]),openpc.business_uuid(uuid),openpc.check_authentication_occurrence(),openpc.check_business_head_completion(),openpc.check_business_receipt_completion(),openpc.check_business_signing_trust(),openpc.check_consumed_signing_continuation(),openpc.check_governed_configuration_receipt(control.audit_occurrence),openpc.check_module_admission_receipt(control.audit_occurrence),openpc.check_notification_completion_phase_proof(jsonb),openpc.check_receipt_signing_attempt_completion(),openpc.check_rotation_history_completion(),openpc.check_rotation_trust_admission(),openpc.check_signing_continuation_context(jsonb),openpc.check_signing_continuation_snapshot(bytea,uuid,uuid,uuid,uuid,numeric,boolean),openpc.check_signing_generation_completion(),openpc.check_signing_generation_current(uuid),openpc.check_signing_no_effect_completion(),openpc.check_signing_rotation_event(control.outbox_event,control.audit_occurrence),openpc.check_signing_rotation_receipt(control.audit_occurrence),openpc.check_work_item_effect_receipt(),openpc.clear_notification_completion_phases(),openpc.configuration_step_up_receipt_input(control.audit_occurrence,control.mutation_evidence),openpc.current_action_intent_id(),openpc.current_operation_id(),openpc.current_participant_id(),openpc.current_privacy_domain_id(),openpc.directory_group_permits(uuid,uuid),openpc.enforce_mutation_candidate_lifecycle(),openpc.enforce_mutation_resume(),openpc.enforce_pending_delivery_lifecycle(),openpc.enforce_work_item_lifecycle(),openpc.guard_assignment_group(),openpc.guard_assignment_role(),openpc.guard_authority_group(),openpc.guard_authority_group_member(),openpc.guard_authority_role(),openpc.guard_bootstrap_custody(),openpc.guard_business_authority_snapshot(),openpc.guard_business_custody_mutation(),openpc.guard_business_head(),openpc.guard_business_key_lifecycle(),openpc.guard_business_outbox(),openpc.guard_business_profile_admission(),openpc.guard_business_receipt(),openpc.guard_directory_connector(),openpc.guard_directory_group_mapping(),openpc.guard_directory_group_member(),openpc.guard_directory_member(),openpc.guard_envelope_platform_binding(),openpc.guard_human_membership(),openpc.guard_identity_oidc_reservation(),openpc.guard_identity_runtime_scope_version(),openpc.guard_installed_secret_recipient(),openpc.guard_invitation_acceptance(),openpc.guard_invitation_oidc_custody(),openpc.guard_invitation_proof(),openpc.guard_invitation_token(),openpc.guard_member_principal_kind(),openpc.guard_participant_authority_creation(),openpc.guard_participant_invitation(),openpc.guard_participant_lifecycle_history(),openpc.guard_platform_context(),openpc.guard_qualified_checkpoint(),openpc.guard_receipt_attempt_reference(),openpc.guard_receipt_signing_attempt(),openpc.guard_removed_membership(),openpc.guard_rotation_history(),openpc.guard_signing_attestation(),openpc.guard_signing_authority_hold(),openpc.guard_signing_command(),openpc.guard_signing_command_authorization(),openpc.guard_signing_continuation(),openpc.guard_signing_generation(),openpc.guard_signing_observation(),openpc.guard_signing_operation_evidence(),openpc.guard_signing_provider_attempt(),openpc.guard_signing_rotation(),openpc.guard_wallet_binding_transition(),openpc.identity_runtime_cose_key_id(bytea,bytea),openpc.invalidate_directory_group_context(),openpc.lock_authority_envelope_platform_context(uuid),openpc.matches_participant(uuid),openpc.matches_privacy(uuid),openpc.notification_completion_phase_binding(uuid,text),openpc.notification_completion_verified_receipt(uuid,text),openpc.observe_oidc_identity_claim(),openpc.record_signing_ambiguity(uuid),openpc.record_signing_observation(uuid,text),openpc.record_signing_provider_result(),openpc.reject_mutation(),openpc.require_bootstrap_custody_change(),openpc.require_bootstrap_provenance(),openpc.require_complete_security_record(),openpc.require_completed_mutation_resume(),openpc.require_first_admin_handoff(),openpc.require_invitation_acceptance_evidence(),openpc.require_invitation_current_token(),openpc.require_notification_completion_disposition_authority(uuid,text),openpc.require_participant_lifecycle_history(),openpc.require_participant_lifecycle_transition(),openpc.require_uuid_setting(text),openpc.require_wallet_binding_mutation(),openpc.resolve_proved_oidc_identity(text,text,text),openpc.retained_signing_admission_matches(uuid,uuid,text,uuid,numeric,numeric),openpc.rotation_history_preimage(control.signing_key_rotation,text,uuid,uuid,uuid,uuid,jsonb,numeric),openpc.set_request_context(text,uuid,uuid,uuid,text,boolean),openpc.signing_admission_open(uuid,uuid,text,uuid),openpc.signing_attempt_authority_status(uuid),openpc.signing_canonical_json(jsonb),openpc.signing_continuation_authority_digest(jsonb),openpc.signing_governance_context(uuid,text),openpc.signing_governance_required(uuid,uuid,uuid,text),openpc.signing_observation_preimage(control.signing_provider_attempt,text),openpc.signing_operation_failure_preimage(uuid,text,uuid),openpc.signing_transition_effects(text,text,text),openpc.work_item_business_projection(control.work_item) FROM PUBLIC;
REVOKE ALL ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authentication_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."authority_role", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."directory_connector", "control"."directory_group_mapping", "control"."directory_member", "control"."evidence_record", "control"."hardware_authenticator", "control"."idempotency_record", "control"."identity_oidc_binding", "control"."identity_runtime_authority_scope", "control"."identity_runtime_authority_set", "control"."identity_runtime_snapshot", "control"."identity_runtime_snapshot_content", "control"."identity_runtime_snapshot_head", "control"."identity_subject", "control"."installed_secret_recipient", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."notification_completion_admission_key", "control"."notification_completion_phase_admission", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."participant_bootstrap_custody", "control"."participant_invitation", "control"."participant_invitation_acceptance", "control"."participant_invitation_proof", "control"."participant_invitation_token", "control"."participant_lifecycle_transition", "control"."participant_membership", "control"."pending_delivery", "control"."platform_context", "control"."principal", "control"."privacy_domain", "control"."qualified_receipt_checkpoint", "control"."qualified_receipt_inbox", "control"."receipt_signing_attempt", "control"."recovery_challenge", "control"."recovery_principal", "control"."revocation", "control"."session", "control"."signing_authorization_generation", "control"."signing_continuation", "control"."signing_key_rotation", "control"."signing_provider_attempt", "control"."signing_rotation_attestation", "control"."signing_rotation_authority_hold", "control"."signing_rotation_command", "control"."signing_rotation_history", "control"."signing_rotation_observation", "control"."signing_rotation_operation_evidence", "control"."wallet_binding", "control"."webauthn_enrollment", "control"."work_item" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
REVOKE ALL ON FUNCTION openpc.action_intent_semantic_digest(text,text,text,text,boolean,boolean,boolean,text,text,text),openpc.admit_notification_completion_phase(bytea,bytea,bytea),openpc.append_rotation_history(),openpc.assert_mutation_resume_no_effect(uuid),openpc.assert_notification_completion_admission_owner(),openpc.assert_request_context(boolean),openpc.assert_work_item_receipt(control.audit_occurrence),openpc.assignment_group_permits(uuid,uuid,uuid,tstzrange),openpc.assignment_role_permits(uuid,text,text),openpc.authentication_occurrence_receipt(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,text,bytea,timestamptz),openpc.business_bytes(bytea),openpc.business_cbor(bytea),openpc.business_cbor_item(bytea,integer,integer),openpc.business_request_digest(text[]),openpc.business_uuid(uuid),openpc.check_authentication_occurrence(),openpc.check_business_head_completion(),openpc.check_business_receipt_completion(),openpc.check_business_signing_trust(),openpc.check_consumed_signing_continuation(),openpc.check_governed_configuration_receipt(control.audit_occurrence),openpc.check_module_admission_receipt(control.audit_occurrence),openpc.check_notification_completion_phase_proof(jsonb),openpc.check_receipt_signing_attempt_completion(),openpc.check_rotation_history_completion(),openpc.check_rotation_trust_admission(),openpc.check_signing_continuation_context(jsonb),openpc.check_signing_continuation_snapshot(bytea,uuid,uuid,uuid,uuid,numeric,boolean),openpc.check_signing_generation_completion(),openpc.check_signing_generation_current(uuid),openpc.check_signing_no_effect_completion(),openpc.check_signing_rotation_event(control.outbox_event,control.audit_occurrence),openpc.check_signing_rotation_receipt(control.audit_occurrence),openpc.check_work_item_effect_receipt(),openpc.clear_notification_completion_phases(),openpc.configuration_step_up_receipt_input(control.audit_occurrence,control.mutation_evidence),openpc.current_action_intent_id(),openpc.current_operation_id(),openpc.current_participant_id(),openpc.current_privacy_domain_id(),openpc.directory_group_permits(uuid,uuid),openpc.enforce_mutation_candidate_lifecycle(),openpc.enforce_mutation_resume(),openpc.enforce_pending_delivery_lifecycle(),openpc.enforce_work_item_lifecycle(),openpc.guard_assignment_group(),openpc.guard_assignment_role(),openpc.guard_authority_group(),openpc.guard_authority_group_member(),openpc.guard_authority_role(),openpc.guard_bootstrap_custody(),openpc.guard_business_authority_snapshot(),openpc.guard_business_custody_mutation(),openpc.guard_business_head(),openpc.guard_business_key_lifecycle(),openpc.guard_business_outbox(),openpc.guard_business_profile_admission(),openpc.guard_business_receipt(),openpc.guard_directory_connector(),openpc.guard_directory_group_mapping(),openpc.guard_directory_group_member(),openpc.guard_directory_member(),openpc.guard_envelope_platform_binding(),openpc.guard_human_membership(),openpc.guard_identity_oidc_reservation(),openpc.guard_identity_runtime_scope_version(),openpc.guard_installed_secret_recipient(),openpc.guard_invitation_acceptance(),openpc.guard_invitation_oidc_custody(),openpc.guard_invitation_proof(),openpc.guard_invitation_token(),openpc.guard_member_principal_kind(),openpc.guard_participant_authority_creation(),openpc.guard_participant_invitation(),openpc.guard_participant_lifecycle_history(),openpc.guard_platform_context(),openpc.guard_qualified_checkpoint(),openpc.guard_receipt_attempt_reference(),openpc.guard_receipt_signing_attempt(),openpc.guard_removed_membership(),openpc.guard_rotation_history(),openpc.guard_signing_attestation(),openpc.guard_signing_authority_hold(),openpc.guard_signing_command(),openpc.guard_signing_command_authorization(),openpc.guard_signing_continuation(),openpc.guard_signing_generation(),openpc.guard_signing_observation(),openpc.guard_signing_operation_evidence(),openpc.guard_signing_provider_attempt(),openpc.guard_signing_rotation(),openpc.guard_wallet_binding_transition(),openpc.identity_runtime_cose_key_id(bytea,bytea),openpc.invalidate_directory_group_context(),openpc.lock_authority_envelope_platform_context(uuid),openpc.matches_participant(uuid),openpc.matches_privacy(uuid),openpc.notification_completion_phase_binding(uuid,text),openpc.notification_completion_verified_receipt(uuid,text),openpc.observe_oidc_identity_claim(),openpc.record_signing_ambiguity(uuid),openpc.record_signing_observation(uuid,text),openpc.record_signing_provider_result(),openpc.reject_mutation(),openpc.require_bootstrap_custody_change(),openpc.require_bootstrap_provenance(),openpc.require_complete_security_record(),openpc.require_completed_mutation_resume(),openpc.require_first_admin_handoff(),openpc.require_invitation_acceptance_evidence(),openpc.require_invitation_current_token(),openpc.require_notification_completion_disposition_authority(uuid,text),openpc.require_participant_lifecycle_history(),openpc.require_participant_lifecycle_transition(),openpc.require_uuid_setting(text),openpc.require_wallet_binding_mutation(),openpc.resolve_proved_oidc_identity(text,text,text),openpc.retained_signing_admission_matches(uuid,uuid,text,uuid,numeric,numeric),openpc.rotation_history_preimage(control.signing_key_rotation,text,uuid,uuid,uuid,uuid,jsonb,numeric),openpc.set_request_context(text,uuid,uuid,uuid,text,boolean),openpc.signing_admission_open(uuid,uuid,text,uuid),openpc.signing_attempt_authority_status(uuid),openpc.signing_canonical_json(jsonb),openpc.signing_continuation_authority_digest(jsonb),openpc.signing_governance_context(uuid,text),openpc.signing_governance_required(uuid,uuid,uuid,text),openpc.signing_observation_preimage(control.signing_provider_attempt,text),openpc.signing_operation_failure_preimage(uuid,text,uuid),openpc.signing_transition_effects(text,text,text),openpc.work_item_business_projection(control.work_item) FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
GRANT EXECUTE ON FUNCTION openpc.require_uuid_setting(text), openpc.set_request_context(text,uuid,uuid,uuid,text,boolean), openpc.assert_request_context(boolean), openpc.matches_participant(uuid), openpc.matches_privacy(uuid), openpc.current_participant_id(), openpc.current_privacy_domain_id(), openpc.current_operation_id(), openpc.current_action_intent_id() TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authentication_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."authority_role", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."directory_connector", "control"."directory_group_mapping", "control"."directory_member", "control"."evidence_record", "control"."hardware_authenticator", "control"."idempotency_record", "control"."identity_oidc_binding", "control"."identity_runtime_authority_scope", "control"."identity_runtime_authority_set", "control"."identity_runtime_snapshot", "control"."identity_runtime_snapshot_content", "control"."identity_runtime_snapshot_head", "control"."identity_subject", "control"."installed_secret_recipient", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."notification_completion_admission_key", "control"."notification_completion_phase_admission", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."participant_bootstrap_custody", "control"."participant_invitation", "control"."participant_invitation_acceptance", "control"."participant_invitation_proof", "control"."participant_invitation_token", "control"."participant_lifecycle_transition", "control"."participant_membership", "control"."pending_delivery", "control"."platform_context", "control"."principal", "control"."privacy_domain", "control"."qualified_receipt_checkpoint", "control"."qualified_receipt_inbox", "control"."receipt_signing_attempt", "control"."recovery_challenge", "control"."recovery_principal", "control"."revocation", "control"."session", "control"."signing_authorization_generation", "control"."signing_continuation", "control"."signing_key_rotation", "control"."signing_provider_attempt", "control"."signing_rotation_attestation", "control"."signing_rotation_authority_hold", "control"."signing_rotation_command", "control"."signing_rotation_history", "control"."signing_rotation_observation", "control"."signing_rotation_operation_evidence", "control"."wallet_binding", "control"."webauthn_enrollment", "control"."work_item" TO "openpc_control_runtime", "openpc_control_platform_runtime", "openpc_control_reader";

GRANT EXECUTE ON FUNCTION openpc.lock_authority_envelope_platform_context(uuid)
 TO openpc_control_reader,openpc_control_runtime,openpc_control_platform_runtime;


GRANT EXECUTE ON FUNCTION openpc.assignment_role_permits(uuid,text,text)
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader,openpc_control_worker;


GRANT EXECUTE ON FUNCTION openpc.assignment_group_permits(uuid,uuid,uuid,tstzrange)
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader,openpc_control_worker;


GRANT EXECUTE ON FUNCTION openpc.directory_group_permits(uuid,uuid)
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader,openpc_control_worker;

GRANT INSERT, UPDATE ON "control"."approval_request", "control"."assignment", "control"."authentication_occurrence", "control"."authority_group", "control"."authority_group_member", "control"."authority_role", "control"."credential", "control"."delegation", "control"."directory_connector", "control"."directory_group_mapping", "control"."directory_member", "control"."hardware_authenticator", "control"."idempotency_record", "control"."identity_oidc_binding", "control"."identity_runtime_authority_scope", "control"."identity_runtime_snapshot_head", "control"."identity_subject", "control"."installed_secret_recipient", "control"."mfa_challenge", "control"."notification_completion_admission_key", "control"."notification_completion_phase_admission", "control"."oidc_transaction", "control"."participant", "control"."participant_bootstrap_custody", "control"."participant_invitation", "control"."participant_invitation_acceptance", "control"."participant_invitation_proof", "control"."participant_invitation_token", "control"."participant_lifecycle_transition", "control"."participant_membership", "control"."principal", "control"."privacy_domain", "control"."qualified_receipt_checkpoint", "control"."qualified_receipt_inbox", "control"."recovery_challenge", "control"."recovery_principal", "control"."session", "control"."signing_key_rotation", "control"."signing_provider_attempt", "control"."signing_rotation_command", "control"."signing_rotation_history", "control"."wallet_binding", "control"."webauthn_enrollment", "control"."work_item" TO "openpc_control_runtime", "openpc_control_platform_runtime";
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
GRANT UPDATE (state, checker_principal_id, last_mutation_operation_id, row_version, updated_at) ON "control"."authority_envelope" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."mutation_evidence", "control"."outbox_event" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."mutation_candidate" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE (state, consumed_operation_id, updated_at) ON "control"."mutation_candidate" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT, UPDATE (last_sequence, updated_at) ON "control"."outbox_aggregate_head" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."idempotency_record", "control"."outbox_aggregate_head", "control"."outbox_event" TO "openpc_control_worker";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authentication_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."authority_role", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."directory_connector", "control"."directory_group_mapping", "control"."directory_member", "control"."evidence_record", "control"."hardware_authenticator", "control"."idempotency_record", "control"."identity_oidc_binding", "control"."identity_runtime_authority_scope", "control"."identity_runtime_authority_set", "control"."identity_runtime_snapshot", "control"."identity_runtime_snapshot_content", "control"."identity_runtime_snapshot_head", "control"."identity_subject", "control"."installed_secret_recipient", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."notification_completion_admission_key", "control"."notification_completion_phase_admission", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."participant_bootstrap_custody", "control"."participant_invitation", "control"."participant_invitation_acceptance", "control"."participant_invitation_proof", "control"."participant_invitation_token", "control"."participant_lifecycle_transition", "control"."participant_membership", "control"."pending_delivery", "control"."platform_context", "control"."principal", "control"."privacy_domain", "control"."qualified_receipt_checkpoint", "control"."qualified_receipt_inbox", "control"."receipt_signing_attempt", "control"."recovery_challenge", "control"."recovery_principal", "control"."revocation", "control"."session", "control"."signing_authorization_generation", "control"."signing_continuation", "control"."signing_key_rotation", "control"."signing_provider_attempt", "control"."signing_rotation_attestation", "control"."signing_rotation_authority_hold", "control"."signing_rotation_command", "control"."signing_rotation_history", "control"."signing_rotation_observation", "control"."signing_rotation_operation_evidence", "control"."wallet_binding", "control"."webauthn_enrollment", "control"."work_item" TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE, DELETE ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authentication_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."authority_role", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."directory_connector", "control"."directory_group_mapping", "control"."directory_member", "control"."evidence_record", "control"."hardware_authenticator", "control"."idempotency_record", "control"."identity_oidc_binding", "control"."identity_runtime_authority_scope", "control"."identity_runtime_authority_set", "control"."identity_runtime_snapshot", "control"."identity_runtime_snapshot_content", "control"."identity_runtime_snapshot_head", "control"."identity_subject", "control"."installed_secret_recipient", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."notification_completion_admission_key", "control"."notification_completion_phase_admission", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."participant_bootstrap_custody", "control"."participant_invitation", "control"."participant_invitation_acceptance", "control"."participant_invitation_proof", "control"."participant_invitation_token", "control"."participant_lifecycle_transition", "control"."participant_membership", "control"."pending_delivery", "control"."platform_context", "control"."principal", "control"."privacy_domain", "control"."qualified_receipt_checkpoint", "control"."qualified_receipt_inbox", "control"."receipt_signing_attempt", "control"."recovery_challenge", "control"."recovery_principal", "control"."revocation", "control"."session", "control"."signing_authorization_generation", "control"."signing_continuation", "control"."signing_key_rotation", "control"."signing_provider_attempt", "control"."signing_rotation_attestation", "control"."signing_rotation_authority_hold", "control"."signing_rotation_command", "control"."signing_rotation_history", "control"."signing_rotation_observation", "control"."signing_rotation_operation_evidence", "control"."wallet_binding", "control"."webauthn_enrollment", "control"."work_item" TO "openpc_control_maintenance";
GRANT SELECT ON "control"."action_intent", "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."audit_occurrence", "control"."authentication_occurrence", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."authority_role", "control"."business_outbox_head", "control"."business_signing_grant", "control"."business_signing_key", "control"."business_signing_key_state", "control"."business_signing_selection", "control"."business_transition_profile", "control"."credential", "control"."delegation", "control"."directory_connector", "control"."directory_group_mapping", "control"."directory_member", "control"."evidence_record", "control"."hardware_authenticator", "control"."idempotency_record", "control"."identity_oidc_binding", "control"."identity_runtime_authority_scope", "control"."identity_runtime_authority_set", "control"."identity_runtime_snapshot", "control"."identity_runtime_snapshot_content", "control"."identity_runtime_snapshot_head", "control"."identity_subject", "control"."installed_secret_recipient", "control"."mfa_challenge", "control"."mutation_candidate", "control"."mutation_evidence", "control"."notification_completion_admission_key", "control"."notification_completion_phase_admission", "control"."oidc_transaction", "control"."outbox_aggregate_head", "control"."outbox_event", "control"."participant", "control"."participant_bootstrap_custody", "control"."participant_invitation", "control"."participant_invitation_acceptance", "control"."participant_invitation_proof", "control"."participant_invitation_token", "control"."participant_lifecycle_transition", "control"."participant_membership", "control"."pending_delivery", "control"."platform_context", "control"."principal", "control"."privacy_domain", "control"."qualified_receipt_checkpoint", "control"."qualified_receipt_inbox", "control"."receipt_signing_attempt", "control"."recovery_challenge", "control"."recovery_principal", "control"."revocation", "control"."session", "control"."signing_authorization_generation", "control"."signing_continuation", "control"."signing_key_rotation", "control"."signing_provider_attempt", "control"."signing_rotation_attestation", "control"."signing_rotation_authority_hold", "control"."signing_rotation_command", "control"."signing_rotation_history", "control"."signing_rotation_observation", "control"."signing_rotation_operation_evidence", "control"."wallet_binding", "control"."webauthn_enrollment", "control"."work_item" TO "openpc_backup_operator";

GRANT INSERT ON control.audit_occurrence,control.evidence_record,control.receipt_signing_attempt,control.signing_rotation_attestation TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT,UPDATE(last_sequence,updated_at) ON control.business_outbox_head TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT UPDATE(row_version) ON control.business_signing_selection,control.business_signing_key_state TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT ON control.business_signing_key,control.business_signing_grant,control.business_signing_key_state,control.business_signing_selection TO openpc_control_key_governor;
GRANT UPDATE(state,row_version,changed_at_ns,change_reference,change_digest) ON control.business_signing_key_state TO openpc_control_key_governor;
GRANT UPDATE(signer_id,row_version,fence_generation,fenced_operation_id,changed_at_ns,change_reference,change_digest) ON control.business_signing_selection TO openpc_control_key_governor;
GRANT EXECUTE ON FUNCTION openpc.work_item_business_projection(control.work_item),openpc.assert_work_item_receipt(control.audit_occurrence)
 TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.configuration_step_up_receipt_input(control.audit_occurrence,control.mutation_evidence) TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.identity_runtime_cose_key_id(bytea,bytea),openpc.check_module_admission_receipt(control.audit_occurrence),openpc.check_governed_configuration_receipt(control.audit_occurrence) TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.business_cbor_item(bytea,integer,integer),openpc.business_cbor(bytea),openpc.business_bytes(bytea),openpc.business_uuid(uuid),openpc.business_request_digest(text[])
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_key_governor;

GRANT EXECUTE ON FUNCTION openpc.assert_mutation_resume_no_effect(uuid)
 TO openpc_control_runtime, openpc_control_platform_runtime;
REVOKE INSERT,UPDATE ON control.qualified_receipt_inbox,control.qualified_receipt_checkpoint FROM openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT ON control.qualified_receipt_inbox TO openpc_control_worker;
GRANT INSERT ON control.signing_rotation_observation TO openpc_control_runtime,openpc_control_worker;
GRANT UPDATE(admission_version) ON control.business_signing_selection TO openpc_control_runtime,openpc_control_worker;
GRANT UPDATE(state,result_kind,result_revision,updated_at) ON control.signing_rotation_command TO openpc_control_worker;
GRANT INSERT ON control.signing_rotation_operation_evidence TO openpc_control_runtime,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.signing_operation_failure_preimage(uuid,text,uuid) TO openpc_control_runtime,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.signing_observation_preimage(control.signing_provider_attempt,text),
 openpc.record_signing_observation(uuid,text),openpc.record_signing_ambiguity(uuid),
 openpc.signing_admission_open(uuid,uuid,text,uuid),
 openpc.retained_signing_admission_matches(uuid,uuid,text,uuid,numeric,numeric) TO openpc_control_runtime,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.rotation_history_preimage(control.signing_key_rotation,text,uuid,uuid,uuid,uuid,jsonb,numeric),
 openpc.check_signing_rotation_receipt(control.audit_occurrence),openpc.check_signing_rotation_event(control.outbox_event,control.audit_occurrence)
 TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.signing_transition_effects(text,text,text) TO openpc_control_runtime,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.signing_attempt_authority_status(uuid) TO openpc_control_runtime,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.signing_continuation_authority_digest(jsonb) TO openpc_control_runtime,openpc_control_worker;
GRANT UPDATE(state,observation,observation_digest) ON control.signing_provider_attempt TO openpc_control_worker;
GRANT INSERT,UPDATE(last_sequence,last_receipt_id) ON control.qualified_receipt_checkpoint TO openpc_control_worker;
GRANT INSERT ON control.business_signing_key,control.business_signing_grant,control.business_signing_key_state TO openpc_control_runtime;
GRANT UPDATE(state,row_version,changed_at_ns,change_reference,change_digest) ON control.business_signing_key_state TO openpc_control_runtime;
GRANT UPDATE(signer_id,row_version,fence_generation,fenced_operation_id,changed_at_ns,change_reference,change_digest) ON control.business_signing_selection TO openpc_control_runtime;


GRANT INSERT,UPDATE(state) ON control.signing_continuation TO openpc_signing_continuation_issuer;
GRANT UPDATE(state,consumed_at_ns,consumed_receipt_id) ON control.signing_continuation TO openpc_control_runtime;
GRANT INSERT ON control.signing_rotation_authority_hold TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.check_signing_continuation_context(jsonb),
 openpc.check_signing_continuation_snapshot(bytea,uuid,uuid,uuid,uuid,numeric,boolean) TO openpc_control_runtime;


GRANT EXECUTE ON FUNCTION openpc.signing_governance_required(uuid,uuid,uuid,text),openpc.signing_governance_context(uuid,text)
 TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.check_signing_generation_current(uuid),openpc.signing_canonical_json(jsonb)
 TO openpc_control_runtime,openpc_control_platform_runtime;
-- The shared pure encoder is also consumed by Control custody/checkpoint guards.
-- Its owning migration must preserve that consumer across populated upgrades.
GRANT EXECUTE ON FUNCTION openpc.signing_canonical_json(jsonb) TO openpc_control_worker;
GRANT INSERT,UPDATE(state,consumed_operation_id,result_revision) ON control.signing_authorization_generation TO openpc_control_runtime;
GRANT UPDATE(state,cleared_by_operation_id) ON control.signing_rotation_authority_hold TO openpc_control_runtime;


GRANT USAGE ON SCHEMA openpc,control TO openpc_signing_authority_locker;
GRANT EXECUTE ON FUNCTION openpc.require_uuid_setting(text),openpc.current_participant_id(),openpc.current_privacy_domain_id(),
 openpc.matches_participant(uuid),openpc.matches_privacy(uuid) TO openpc_signing_authority_locker;
GRANT SELECT ON control.assignment TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.assignment;
CREATE POLICY signing_authority_locker_scope ON control.assignment FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id))
 WITH CHECK(false);
GRANT SELECT ON control.authority_envelope TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.authority_envelope;
CREATE POLICY signing_authority_locker_scope ON control.authority_envelope FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id))
 WITH CHECK(false);
GRANT SELECT ON control.authority_role TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.authority_role;
CREATE POLICY signing_authority_locker_scope ON control.authority_role FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id))
 WITH CHECK(false);
GRANT SELECT ON control.credential TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.credential;
CREATE POLICY signing_authority_locker_scope ON control.credential FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id))
 WITH CHECK(false);
GRANT SELECT ON control.delegation TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.delegation;
CREATE POLICY signing_authority_locker_scope ON control.delegation FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id))
 WITH CHECK(false);
GRANT SELECT ON control.participant TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.participant;
CREATE POLICY signing_authority_locker_scope ON control.participant FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id))
 WITH CHECK(false);
GRANT SELECT ON control.principal TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.principal;
CREATE POLICY signing_authority_locker_scope ON control.principal FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id))
 WITH CHECK(false);
GRANT SELECT ON control.privacy_domain TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.privacy_domain;
CREATE POLICY signing_authority_locker_scope ON control.privacy_domain FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(false);
GRANT SELECT ON control.session TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.session;
CREATE POLICY signing_authority_locker_scope ON control.session FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id))
 WITH CHECK(false);
GRANT SELECT ON control.approval_request TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.approval_request;
CREATE POLICY signing_authority_locker_scope ON control.approval_request FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(false);
GRANT SELECT ON control.signing_rotation_command TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.signing_rotation_command;
CREATE POLICY signing_authority_locker_scope ON control.signing_rotation_command FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(false);
GRANT SELECT ON control.signing_provider_attempt TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.signing_provider_attempt;
CREATE POLICY signing_authority_locker_scope ON control.signing_provider_attempt FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(false);
GRANT SELECT ON control.signing_key_rotation TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.signing_key_rotation;
CREATE POLICY signing_authority_locker_scope ON control.signing_key_rotation FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(false);
GRANT UPDATE(assignment_id) ON control.assignment TO openpc_signing_authority_locker;
GRANT UPDATE(authority_envelope_id) ON control.authority_envelope TO openpc_signing_authority_locker;
GRANT UPDATE(authority_role_id) ON control.authority_role TO openpc_signing_authority_locker;
GRANT UPDATE(credential_id) ON control.credential TO openpc_signing_authority_locker;
GRANT UPDATE(delegation_id) ON control.delegation TO openpc_signing_authority_locker;
GRANT UPDATE(participant_id) ON control.participant TO openpc_signing_authority_locker;
GRANT UPDATE(principal_id) ON control.principal TO openpc_signing_authority_locker;
GRANT UPDATE(privacy_domain_id) ON control.privacy_domain TO openpc_signing_authority_locker;
GRANT UPDATE(session_id) ON control.session TO openpc_signing_authority_locker;
GRANT UPDATE(approval_request_id) ON control.approval_request TO openpc_signing_authority_locker;
ALTER FUNCTION openpc.signing_attempt_authority_status(uuid) OWNER TO openpc_signing_authority_locker;


REVOKE UPDATE, DELETE ON control.hardware_authenticator FROM openpc_control_runtime, openpc_control_platform_runtime;
DROP TRIGGER IF EXISTS hardware_authenticator_immutable ON control.hardware_authenticator;
CREATE TRIGGER hardware_authenticator_immutable BEFORE UPDATE OR DELETE ON control.hardware_authenticator FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();


GRANT INSERT ON control.identity_runtime_snapshot, control.identity_runtime_snapshot_content, control.identity_runtime_authority_set TO openpc_control_runtime, openpc_control_platform_runtime;
DROP TRIGGER IF EXISTS identity_runtime_snapshot_immutable ON control.identity_runtime_snapshot;
CREATE TRIGGER identity_runtime_snapshot_immutable BEFORE UPDATE OR DELETE ON control.identity_runtime_snapshot FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS identity_runtime_snapshot_content_immutable ON control.identity_runtime_snapshot_content;
CREATE TRIGGER identity_runtime_snapshot_content_immutable BEFORE UPDATE OR DELETE ON control.identity_runtime_snapshot_content FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS identity_runtime_authority_set_immutable ON control.identity_runtime_authority_set;
CREATE TRIGGER identity_runtime_authority_set_immutable BEFORE UPDATE OR DELETE ON control.identity_runtime_authority_set FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE OR REPLACE FUNCTION openpc.guard_identity_runtime_scope_version() RETURNS trigger LANGUAGE plpgsql AS $scope_version$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'identity authority scope versions cannot be reset'; END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.version<>1 THEN RAISE EXCEPTION 'identity authority scopes start at version one'; END IF;
    RETURN NEW;
  END IF;
  IF (NEW.participant_id,NEW.domain_code,NEW.scope_digest,NEW.scope_cbor) IS DISTINCT FROM (OLD.participant_id,OLD.domain_code,OLD.scope_digest,OLD.scope_cbor)
    OR (NEW.source_state_digest=OLD.source_state_digest AND NEW.version<>OLD.version)
    OR (NEW.source_state_digest<>OLD.source_state_digest AND NEW.version<>OLD.version+1)
  THEN RAISE EXCEPTION 'identity authority scope version transition rejected'; END IF;
  RETURN NEW;
END $scope_version$;
ALTER FUNCTION openpc.guard_identity_runtime_scope_version() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.guard_identity_runtime_scope_version() FROM PUBLIC;
DROP TRIGGER IF EXISTS identity_runtime_scope_version_guard ON control.identity_runtime_authority_scope;
CREATE TRIGGER identity_runtime_scope_version_guard BEFORE INSERT OR UPDATE OR DELETE ON control.identity_runtime_authority_scope FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_runtime_scope_version();

ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA openpc REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;

ALTER ROLE openpc_identity_binding_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE openpc_identity_binding_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
GRANT USAGE ON SCHEMA openpc,control TO openpc_identity_binding_owner;
GRANT USAGE ON SCHEMA openpc TO openpc_identity_binding_resolver;
GRANT SELECT ON control.credential,control.participant_membership TO openpc_identity_binding_owner;
GRANT SELECT,INSERT ON control.identity_subject,control.identity_oidc_binding TO openpc_identity_binding_owner;
GRANT UPDATE ON control.identity_oidc_binding TO openpc_identity_binding_owner;
GRANT EXECUTE ON FUNCTION openpc.assert_request_context(boolean),openpc.current_action_intent_id(),openpc.current_participant_id(),openpc.current_privacy_domain_id(),openpc.current_operation_id(),openpc.require_uuid_setting(text) TO openpc_identity_binding_owner;
ALTER FUNCTION openpc.observe_oidc_identity_claim() OWNER TO openpc_identity_binding_owner;
ALTER FUNCTION openpc.resolve_proved_oidc_identity(text,text,text) OWNER TO openpc_identity_binding_owner;
GRANT EXECUTE ON FUNCTION openpc.resolve_proved_oidc_identity(text,text,text) TO openpc_identity_binding_resolver;


REVOKE ALL ON control.authentication_occurrence FROM openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance;
GRANT INSERT ON control.authentication_occurrence TO openpc_control_runtime,openpc_control_platform_runtime;
-- The owning schema's protected/preservation RLS policies admit only exact
-- source actions. Keep their table grant through later Identity-only upgrades.
GRANT SELECT ON control.authentication_occurrence TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT EXECUTE ON FUNCTION openpc.authentication_occurrence_receipt(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,text,bytea,timestamptz),openpc.check_authentication_occurrence()
 TO openpc_control_runtime,openpc_control_platform_runtime;


DROP POLICY IF EXISTS secret_recipient_installation ON control.installed_secret_recipient;
CREATE POLICY secret_recipient_installation ON control.installed_secret_recipient
 TO openpc_control_owner USING(true) WITH CHECK(true);
REVOKE ALL ON control.installed_secret_recipient FROM PUBLIC,openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance;
GRANT SELECT ON control.installed_secret_recipient TO openpc_control_runtime;


REVOKE ALL ON control.notification_completion_admission_key,control.notification_completion_phase_admission
 FROM PUBLIC,openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance,openpc_backup_operator;
ALTER TABLE control.notification_completion_phase_admission FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS notification_completion_native_owner ON control.notification_completion_phase_admission;
CREATE POLICY notification_completion_native_owner ON control.notification_completion_phase_admission TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
REVOKE ALL ON FUNCTION openpc.check_notification_completion_phase_proof(jsonb),openpc.admit_notification_completion_phase(bytea,bytea,bytea),openpc.require_notification_completion_disposition_authority(uuid,text),openpc.clear_notification_completion_phases(),openpc.notification_completion_phase_binding(uuid,text),openpc.notification_completion_verified_receipt(uuid,text),openpc.assert_notification_completion_admission_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.admit_notification_completion_phase(bytea,bytea,bytea),
 openpc.require_notification_completion_disposition_authority(uuid,text),openpc.clear_notification_completion_phases(),
 openpc.notification_completion_phase_binding(uuid,text),openpc.notification_completion_verified_receipt(uuid,text),
 openpc.assert_notification_completion_admission_owner() TO openpc_control_runtime;
SELECT openpc.assert_notification_completion_admission_owner();

ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

DO $function_grant_acceptance$
DECLARE expected record; matched oid;
BEGIN
 FOR expected IN SELECT * FROM (VALUES ('openpc.require_uuid_setting(text)','openpc_control_runtime'),
('openpc.require_uuid_setting(text)','openpc_control_worker'),
('openpc.require_uuid_setting(text)','openpc_control_platform_runtime'),
('openpc.require_uuid_setting(text)','openpc_control_reader'),
('openpc.require_uuid_setting(text)','openpc_signing_authority_locker'),
('openpc.require_uuid_setting(text)','openpc_identity_binding_owner'),
('openpc.set_request_context(text,uuid,uuid,uuid,text,boolean)','openpc_control_runtime'),
('openpc.set_request_context(text,uuid,uuid,uuid,text,boolean)','openpc_control_worker'),
('openpc.set_request_context(text,uuid,uuid,uuid,text,boolean)','openpc_control_platform_runtime'),
('openpc.set_request_context(text,uuid,uuid,uuid,text,boolean)','openpc_control_reader'),
('openpc.assert_request_context(boolean)','openpc_control_runtime'),
('openpc.assert_request_context(boolean)','openpc_control_worker'),
('openpc.assert_request_context(boolean)','openpc_control_platform_runtime'),
('openpc.assert_request_context(boolean)','openpc_control_reader'),
('openpc.assert_request_context(boolean)','openpc_identity_binding_owner'),
('openpc.matches_participant(uuid)','openpc_control_runtime'),
('openpc.matches_participant(uuid)','openpc_control_worker'),
('openpc.matches_participant(uuid)','openpc_control_platform_runtime'),
('openpc.matches_participant(uuid)','openpc_control_reader'),
('openpc.matches_participant(uuid)','openpc_signing_authority_locker'),
('openpc.matches_privacy(uuid)','openpc_control_runtime'),
('openpc.matches_privacy(uuid)','openpc_control_worker'),
('openpc.matches_privacy(uuid)','openpc_control_platform_runtime'),
('openpc.matches_privacy(uuid)','openpc_control_reader'),
('openpc.matches_privacy(uuid)','openpc_signing_authority_locker'),
('openpc.current_participant_id()','openpc_control_runtime'),
('openpc.current_participant_id()','openpc_control_worker'),
('openpc.current_participant_id()','openpc_control_platform_runtime'),
('openpc.current_participant_id()','openpc_control_reader'),
('openpc.current_participant_id()','openpc_signing_authority_locker'),
('openpc.current_participant_id()','openpc_identity_binding_owner'),
('openpc.current_privacy_domain_id()','openpc_control_runtime'),
('openpc.current_privacy_domain_id()','openpc_control_worker'),
('openpc.current_privacy_domain_id()','openpc_control_platform_runtime'),
('openpc.current_privacy_domain_id()','openpc_control_reader'),
('openpc.current_privacy_domain_id()','openpc_signing_authority_locker'),
('openpc.current_privacy_domain_id()','openpc_identity_binding_owner'),
('openpc.current_operation_id()','openpc_control_runtime'),
('openpc.current_operation_id()','openpc_control_worker'),
('openpc.current_operation_id()','openpc_control_platform_runtime'),
('openpc.current_operation_id()','openpc_control_reader'),
('openpc.current_operation_id()','openpc_identity_binding_owner'),
('openpc.current_action_intent_id()','openpc_control_runtime'),
('openpc.current_action_intent_id()','openpc_control_worker'),
('openpc.current_action_intent_id()','openpc_control_platform_runtime'),
('openpc.current_action_intent_id()','openpc_control_reader'),
('openpc.current_action_intent_id()','openpc_identity_binding_owner'),
('openpc.lock_authority_envelope_platform_context(uuid)','openpc_control_reader'),
('openpc.lock_authority_envelope_platform_context(uuid)','openpc_control_runtime'),
('openpc.lock_authority_envelope_platform_context(uuid)','openpc_control_platform_runtime'),
('openpc.assignment_role_permits(uuid,text,text)','openpc_control_runtime'),
('openpc.assignment_role_permits(uuid,text,text)','openpc_control_platform_runtime'),
('openpc.assignment_role_permits(uuid,text,text)','openpc_control_reader'),
('openpc.assignment_role_permits(uuid,text,text)','openpc_control_worker'),
('openpc.assignment_group_permits(uuid,uuid,uuid,tstzrange)','openpc_control_runtime'),
('openpc.assignment_group_permits(uuid,uuid,uuid,tstzrange)','openpc_control_platform_runtime'),
('openpc.assignment_group_permits(uuid,uuid,uuid,tstzrange)','openpc_control_reader'),
('openpc.assignment_group_permits(uuid,uuid,uuid,tstzrange)','openpc_control_worker'),
('openpc.directory_group_permits(uuid,uuid)','openpc_control_runtime'),
('openpc.directory_group_permits(uuid,uuid)','openpc_control_platform_runtime'),
('openpc.directory_group_permits(uuid,uuid)','openpc_control_reader'),
('openpc.directory_group_permits(uuid,uuid)','openpc_control_worker'),
('openpc.work_item_business_projection(control.work_item)','openpc_control_runtime'),
('openpc.assert_work_item_receipt(control.audit_occurrence)','openpc_control_runtime'),
('openpc.configuration_step_up_receipt_input(control.audit_occurrence,control.mutation_evidence)','openpc_control_runtime'),
('openpc.identity_runtime_cose_key_id(bytea,bytea)','openpc_control_runtime'),
('openpc.identity_runtime_cose_key_id(bytea,bytea)','openpc_control_platform_runtime'),
('openpc.check_module_admission_receipt(control.audit_occurrence)','openpc_control_runtime'),
('openpc.check_module_admission_receipt(control.audit_occurrence)','openpc_control_platform_runtime'),
('openpc.check_governed_configuration_receipt(control.audit_occurrence)','openpc_control_runtime'),
('openpc.check_governed_configuration_receipt(control.audit_occurrence)','openpc_control_platform_runtime'),
('openpc.business_cbor_item(bytea,integer,integer)','openpc_control_runtime'),
('openpc.business_cbor_item(bytea,integer,integer)','openpc_control_platform_runtime'),
('openpc.business_cbor_item(bytea,integer,integer)','openpc_control_worker'),
('openpc.business_cbor_item(bytea,integer,integer)','openpc_control_reader'),
('openpc.business_cbor_item(bytea,integer,integer)','openpc_control_key_governor'),
('openpc.business_cbor(bytea)','openpc_control_runtime'),
('openpc.business_cbor(bytea)','openpc_control_platform_runtime'),
('openpc.business_cbor(bytea)','openpc_control_worker'),
('openpc.business_cbor(bytea)','openpc_control_reader'),
('openpc.business_cbor(bytea)','openpc_control_key_governor'),
('openpc.business_bytes(bytea)','openpc_control_runtime'),
('openpc.business_bytes(bytea)','openpc_control_platform_runtime'),
('openpc.business_bytes(bytea)','openpc_control_worker'),
('openpc.business_bytes(bytea)','openpc_control_reader'),
('openpc.business_bytes(bytea)','openpc_control_key_governor'),
('openpc.business_uuid(uuid)','openpc_control_runtime'),
('openpc.business_uuid(uuid)','openpc_control_platform_runtime'),
('openpc.business_uuid(uuid)','openpc_control_worker'),
('openpc.business_uuid(uuid)','openpc_control_reader'),
('openpc.business_uuid(uuid)','openpc_control_key_governor'),
('openpc.business_request_digest(text[])','openpc_control_runtime'),
('openpc.business_request_digest(text[])','openpc_control_platform_runtime'),
('openpc.business_request_digest(text[])','openpc_control_worker'),
('openpc.business_request_digest(text[])','openpc_control_reader'),
('openpc.business_request_digest(text[])','openpc_control_key_governor'),
('openpc.assert_mutation_resume_no_effect(uuid)','openpc_control_runtime'),
('openpc.assert_mutation_resume_no_effect(uuid)','openpc_control_platform_runtime'),
('openpc.signing_operation_failure_preimage(uuid,text,uuid)','openpc_control_runtime'),
('openpc.signing_operation_failure_preimage(uuid,text,uuid)','openpc_control_worker'),
('openpc.signing_observation_preimage(control.signing_provider_attempt,text)','openpc_control_runtime'),
('openpc.signing_observation_preimage(control.signing_provider_attempt,text)','openpc_control_worker'),
('openpc.record_signing_observation(uuid,text)','openpc_control_runtime'),
('openpc.record_signing_observation(uuid,text)','openpc_control_worker'),
('openpc.record_signing_ambiguity(uuid)','openpc_control_runtime'),
('openpc.record_signing_ambiguity(uuid)','openpc_control_worker'),
('openpc.signing_admission_open(uuid,uuid,text,uuid)','openpc_control_runtime'),
('openpc.signing_admission_open(uuid,uuid,text,uuid)','openpc_control_worker'),
('openpc.retained_signing_admission_matches(uuid,uuid,text,uuid,numeric,numeric)','openpc_control_runtime'),
('openpc.retained_signing_admission_matches(uuid,uuid,text,uuid,numeric,numeric)','openpc_control_worker'),
('openpc.rotation_history_preimage(control.signing_key_rotation,text,uuid,uuid,uuid,uuid,jsonb,numeric)','openpc_control_runtime'),
('openpc.check_signing_rotation_receipt(control.audit_occurrence)','openpc_control_runtime'),
('openpc.check_signing_rotation_event(control.outbox_event,control.audit_occurrence)','openpc_control_runtime'),
('openpc.signing_transition_effects(text,text,text)','openpc_control_runtime'),
('openpc.signing_transition_effects(text,text,text)','openpc_control_worker'),
('openpc.signing_attempt_authority_status(uuid)','openpc_control_runtime'),
('openpc.signing_attempt_authority_status(uuid)','openpc_control_worker'),
('openpc.signing_continuation_authority_digest(jsonb)','openpc_control_runtime'),
('openpc.signing_continuation_authority_digest(jsonb)','openpc_control_worker'),
('openpc.check_signing_continuation_context(jsonb)','openpc_control_runtime'),
('openpc.check_signing_continuation_snapshot(bytea,uuid,uuid,uuid,uuid,numeric,boolean)','openpc_control_runtime'),
('openpc.signing_governance_required(uuid,uuid,uuid,text)','openpc_control_runtime'),
('openpc.signing_governance_required(uuid,uuid,uuid,text)','openpc_control_platform_runtime'),
('openpc.signing_governance_context(uuid,text)','openpc_control_runtime'),
('openpc.signing_governance_context(uuid,text)','openpc_control_platform_runtime'),
('openpc.check_signing_generation_current(uuid)','openpc_control_runtime'),
('openpc.check_signing_generation_current(uuid)','openpc_control_platform_runtime'),
('openpc.signing_canonical_json(jsonb)','openpc_control_runtime'),
('openpc.signing_canonical_json(jsonb)','openpc_control_platform_runtime'),
('openpc.signing_canonical_json(jsonb)','openpc_control_worker'),
('openpc.resolve_proved_oidc_identity(text,text,text)','openpc_identity_binding_resolver'),
('openpc.authentication_occurrence_receipt(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,text,bytea,timestamptz)','openpc_control_runtime'),
('openpc.authentication_occurrence_receipt(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,text,bytea,timestamptz)','openpc_control_platform_runtime'),
('openpc.check_authentication_occurrence()','openpc_control_runtime'),
('openpc.check_authentication_occurrence()','openpc_control_platform_runtime'),
('openpc.admit_notification_completion_phase(bytea,bytea,bytea)','openpc_control_runtime'),
('openpc.require_notification_completion_disposition_authority(uuid,text)','openpc_control_runtime'),
('openpc.clear_notification_completion_phases()','openpc_control_runtime'),
('openpc.notification_completion_phase_binding(uuid,text)','openpc_control_runtime'),
('openpc.notification_completion_verified_receipt(uuid,text)','openpc_control_runtime'),
('openpc.assert_notification_completion_admission_owner()','openpc_control_runtime')) AS required(signature,grantee) LOOP
  matched:=to_regprocedure(expected.signature);
  IF matched IS NULL OR (SELECT count(*) FROM pg_catalog.pg_proc WHERE oid=matched)<>1
   OR NOT has_function_privilege(expected.grantee,matched,'EXECUTE') THEN
   RAISE EXCEPTION 'Generated function grant failed: % to %',expected.signature,expected.grantee;
  END IF;
 END LOOP;
END $function_grant_acceptance$;
