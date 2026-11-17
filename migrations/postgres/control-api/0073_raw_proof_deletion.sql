ALTER TABLE "control"."deletion_job" DROP CONSTRAINT "deletion_job_target_ck";--> statement-breakpoint
ALTER TABLE "control"."evidence_deletion_item" ALTER COLUMN "segment_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."deletion_job" ALTER COLUMN "stream_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."deletion_job" ALTER COLUMN "segment_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."evidence_deletion_item" ADD COLUMN "protected_object_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."deletion_job" ADD COLUMN "protected_object_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."deletion_job" ADD CONSTRAINT "deletion_job_protected_object_fk" FOREIGN KEY ("participant_id","privacy_domain_id","protected_object_id") REFERENCES "control"."protected_proof_object"("participant_id","privacy_domain_id","object_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."evidence_deletion_item" ADD CONSTRAINT "evidence_deletion_item_protected_object_id_unique" UNIQUE("protected_object_id");--> statement-breakpoint
ALTER TABLE "control"."evidence_deletion_item" ADD CONSTRAINT "evidence_deletion_item_target_ck" CHECK (("control"."evidence_deletion_item"."segment_id" is null)<>("control"."evidence_deletion_item"."protected_object_id" is null));--> statement-breakpoint
ALTER TABLE "control"."deletion_job" ADD CONSTRAINT "deletion_job_target_ck" CHECK ("control"."deletion_job"."target_database"='openpc_control' and "control"."deletion_job"."external_attempt_state"='NOT_STARTED' and "control"."deletion_job"."retained_alias_count"=0 and
        (("control"."deletion_job"."target_data_class"='AUDIT_EVIDENCE' and "control"."deletion_job"."stream_id" is not null and "control"."deletion_job"."segment_id" is not null and "control"."deletion_job"."protected_object_id" is null)
        or ("control"."deletion_job"."target_data_class"='RAW_SOURCE_BODY' and "control"."deletion_job"."stream_id" is null and "control"."deletion_job"."segment_id" is null and "control"."deletion_job"."protected_object_id" is not null)));
-- OPENPC CONTROL-API SECURITY TAIL


CREATE OR REPLACE FUNCTION openpc.guard_policy_generation_fence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 PERFORM pg_advisory_xact_lock(hashtextextended('openpc-policy-generations:'||
  current_setting('openpc.participant_id')||':'||current_setting('openpc.privacy_domain_id'),0));
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS policy_generation_mutation_fence ON control.policy_generation;
CREATE TRIGGER policy_generation_mutation_fence BEFORE INSERT OR UPDATE OR DELETE ON control.policy_generation
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();

CREATE OR REPLACE FUNCTION openpc.guard_policy_generation_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6007-POLICY-HISTORY-IMMUTABLE'; END IF;
 IF TG_OP='UPDATE' AND (NEW.participant_id IS DISTINCT FROM OLD.participant_id OR
   NEW.privacy_domain_id IS DISTINCT FROM OLD.privacy_domain_id OR NEW.policy_generation_id IS DISTINCT FROM OLD.policy_generation_id)
 THEN RAISE EXCEPTION 'DATA-6007-POLICY-HISTORY-IMMUTABLE'; END IF;
 IF TG_OP='INSERT' AND to_regclass('control.configuration_work') IS NOT NULL THEN
  IF EXISTS(SELECT 1 FROM control.configuration_work WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND policy_generation_digest IS NULL
    AND state IN ('PENDING','LEASED','RECONCILING'))
  THEN RAISE EXCEPTION 'DATA-6007-INITIAL-PREPARATION-INCOMPLETE'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS policy_generation_history ON control.policy_generation;
CREATE TRIGGER policy_generation_history BEFORE INSERT OR UPDATE OR DELETE ON control.policy_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_policy_generation_history();

-- Public policy-set readback derives its active digest from these generations.
-- Advance the parent revision in the same transaction, including retirement and
-- rollback, so an unchanged ETag can never hide a changed active version.
CREATE OR REPLACE FUNCTION openpc.advance_policy_set_generation_revision()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NOT (NEW.active AND NEW.state='ACTIVE') THEN RETURN NEW; END IF;
 ELSIF (NEW.active AND NEW.state='ACTIVE') IS NOT DISTINCT FROM
       (OLD.active AND OLD.state='ACTIVE') AND NEW.policy_version_id=OLD.policy_version_id THEN
  RETURN NEW;
 END IF;
 UPDATE control.policy SET row_version=row_version+1,updated_at=clock_timestamp()
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
    AND policy_id IN (SELECT policy_id FROM control.policy_version
      WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
        AND (policy_version_id=NEW.policy_version_id OR
             (TG_OP='UPDATE' AND policy_version_id=OLD.policy_version_id)));
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS policy_set_generation_revision ON control.policy_generation;
CREATE TRIGGER policy_set_generation_revision AFTER INSERT OR UPDATE ON control.policy_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.advance_policy_set_generation_revision();

CREATE OR REPLACE FUNCTION openpc.configuration_policy_provenance(pid uuid, privacy uuid)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE selected text; cardinality bigint;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF pid IS DISTINCT FROM openpc.current_participant_id() OR privacy IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'DATA-6001-CONTEXT-INVALID'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('openpc-policy-generations:'||pid::text||':'||privacy::text,0));
 SELECT count(*),min('sha256:'||encode(generation_digest,'hex')) INTO cardinality,selected
 FROM control.policy_generation WHERE participant_id=pid AND privacy_domain_id=privacy AND active AND state='ACTIVE';
 IF cardinality=1 THEN RETURN selected; END IF;
 IF cardinality<>0 OR EXISTS(SELECT 1 FROM control.policy_generation WHERE participant_id=pid AND privacy_domain_id=privacy)
 THEN RAISE EXCEPTION 'DATA-6007-CONFIGURATION-POLICY-UNAVAILABLE'; END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.configuration_policy_provenance(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.configuration_policy_provenance(uuid,uuid) TO openpc_control_runtime,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_configuration_preparation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'DATA-6001-CONTEXT-INVALID'; END IF;
 IF TG_OP='UPDATE' AND (NEW.participant_id IS DISTINCT FROM OLD.participant_id OR NEW.privacy_domain_id IS DISTINCT FROM OLD.privacy_domain_id)
 THEN RAISE EXCEPTION 'DATA-6007-PREPARATION-SCOPE-IMMUTABLE'; END IF;
 IF NEW.policy_generation_digest IS NULL THEN
  IF TG_TABLE_NAME='configuration_work' THEN
   IF NEW.work_kind NOT IN ('PROVIDER_QUALIFICATION','INDEXER_ADMISSION','PROJECTION_VALIDATION')
   THEN RAISE EXCEPTION 'DATA-6007-SERVING-POLICY-REQUIRED'; END IF;
  END IF;
  IF TG_OP='INSERT' OR OLD.policy_generation_digest IS NOT NULL THEN
   IF openpc.configuration_policy_provenance(NEW.participant_id,NEW.privacy_domain_id) IS NOT NULL
   THEN RAISE EXCEPTION 'DATA-6007-PREPARATION-PROVENANCE-REQUIRED'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS configuration_preparation_fence ON control.provider_profile;
CREATE TRIGGER configuration_preparation_fence BEFORE INSERT OR UPDATE OR DELETE ON control.provider_profile
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();
DROP TRIGGER IF EXISTS configuration_preparation_provenance ON control.provider_profile;
CREATE TRIGGER configuration_preparation_provenance BEFORE INSERT OR UPDATE ON control.provider_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_configuration_preparation();

DROP TRIGGER IF EXISTS configuration_preparation_fence ON control.indexer_profile;
CREATE TRIGGER configuration_preparation_fence BEFORE INSERT OR UPDATE OR DELETE ON control.indexer_profile
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();
DROP TRIGGER IF EXISTS configuration_preparation_provenance ON control.indexer_profile;
CREATE TRIGGER configuration_preparation_provenance BEFORE INSERT OR UPDATE ON control.indexer_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_configuration_preparation();

DROP TRIGGER IF EXISTS configuration_preparation_fence ON control.projection_plan;
CREATE TRIGGER configuration_preparation_fence BEFORE INSERT OR UPDATE OR DELETE ON control.projection_plan
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();
DROP TRIGGER IF EXISTS configuration_preparation_provenance ON control.projection_plan;
CREATE TRIGGER configuration_preparation_provenance BEFORE INSERT OR UPDATE ON control.projection_plan
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_configuration_preparation();

DROP TRIGGER IF EXISTS configuration_preparation_fence ON control.runtime_target;
CREATE TRIGGER configuration_preparation_fence BEFORE INSERT OR UPDATE OR DELETE ON control.runtime_target
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();
DROP TRIGGER IF EXISTS configuration_preparation_provenance ON control.runtime_target;
CREATE TRIGGER configuration_preparation_provenance BEFORE INSERT OR UPDATE ON control.runtime_target
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_configuration_preparation();

DROP TRIGGER IF EXISTS configuration_preparation_fence ON control.configuration_work;
CREATE TRIGGER configuration_preparation_fence BEFORE INSERT OR UPDATE OR DELETE ON control.configuration_work
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();
DROP TRIGGER IF EXISTS configuration_preparation_provenance ON control.configuration_work;
CREATE TRIGGER configuration_preparation_provenance BEFORE INSERT OR UPDATE ON control.configuration_work
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_configuration_preparation();


ALTER TABLE control.runtime_target_connection FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_discovery_target_read ON control.runtime_target;
CREATE POLICY runtime_discovery_target_read ON control.runtime_target FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1');

DROP POLICY IF EXISTS runtime_discovery_read_fence ON control.participant;
CREATE POLICY runtime_discovery_read_fence ON control.participant FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1')
 WITH CHECK(false);

DROP POLICY IF EXISTS runtime_discovery_read_fence ON control.privacy_domain;
CREATE POLICY runtime_discovery_read_fence ON control.privacy_domain FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1')
 WITH CHECK(false);

DROP POLICY IF EXISTS runtime_discovery_read_fence ON control.principal;
CREATE POLICY runtime_discovery_read_fence ON control.principal FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1')
 WITH CHECK(false);

DROP POLICY IF EXISTS runtime_discovery_read_fence ON control.credential;
CREATE POLICY runtime_discovery_read_fence ON control.credential FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1')
 WITH CHECK(false);
-- A transport owner can retain exact read locks without gaining Identity write rights.
CREATE OR REPLACE FUNCTION openpc.lock_runtime_discovery_authority(target uuid, certificate_digest text)
RETURNS TABLE(credential_id uuid, credential_epoch bigint, principal_epoch bigint, valid_until timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE pid uuid; privacy uuid; selected_credential uuid; selected_principal uuid; candidates uuid[];
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR current_setting('transaction_isolation')<>'read committed'
  OR certificate_digest !~ '^sha256:[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-CONTEXT-INVALID'; END IF;
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 PERFORM 1 FROM control.participant p WHERE p.participant_id=pid AND p.state='ACTIVE' AND p.archived_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-PARTICIPANT-INVALID'; END IF;
 PERFORM 1 FROM control.privacy_domain p WHERE p.participant_id=pid AND p.privacy_domain_id=privacy AND p.state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-PRIVACY-INVALID'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.runtime_target t WHERE t.participant_id=pid AND t.privacy_domain_id=privacy
  AND t.runtime_target_id=target AND t.requires_authenticated_discovery)
 THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-TARGET-INVALID'; END IF;
 SELECT array_agg(c.credential_id ORDER BY c.credential_id) INTO candidates FROM control.credential c
  WHERE c.participant_id=pid AND c.kind='WORKLOAD_MTLS' AND c.state='ACTIVE'
   AND c.subject='urn:openpc:participant:'||pid::text||':workload:'||target::text
   AND c.audience='urn:openpc:workload:'||target::text
   AND c.secret_fingerprint=decode(substring(certificate_digest from 8),'hex');
 IF coalesce(cardinality(candidates),0)<>1 THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-CREDENTIAL-CARDINALITY'; END IF;
 selected_credential:=candidates[1];
 SELECT c.principal_id INTO selected_principal FROM control.credential c WHERE c.credential_id=selected_credential AND c.participant_id=pid;
 PERFORM 1 FROM control.principal p WHERE p.participant_id=pid AND p.principal_id=selected_principal
  AND p.kind='WORKLOAD' AND p.state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-PRINCIPAL-INVALID'; END IF;
 PERFORM 1 FROM control.credential c WHERE c.participant_id=pid AND c.credential_id=selected_credential FOR SHARE;
 RETURN QUERY SELECT c.credential_id,c.credential_epoch::bigint,p.authority_epoch::bigint,c.valid_until
  FROM control.credential c JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
  WHERE c.participant_id=pid AND c.credential_id=selected_credential AND c.principal_id=selected_principal
   AND c.kind='WORKLOAD_MTLS' AND c.state='ACTIVE' AND c.credential_epoch>0
   AND c.subject='urn:openpc:participant:'||pid::text||':workload:'||target::text
   AND c.audience='urn:openpc:workload:'||target::text
   AND c.secret_fingerprint=decode(substring(certificate_digest from 8),'hex')
   AND c.certificate_der IS NOT NULL AND sha256(c.certificate_der)=c.secret_fingerprint
   AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
   AND p.kind='WORKLOAD' AND p.state='ACTIVE' AND p.authority_epoch>0;
 IF NOT FOUND THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-CREDENTIAL-INVALID'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_runtime_discovery_authority(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_runtime_discovery_authority(uuid,text) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.runtime_target_discovery_current(pid uuid, privacy uuid, target uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT coalesce((SELECT NOT t.requires_authenticated_discovery OR EXISTS(
  SELECT 1 FROM control.runtime_target_connection observation
  JOIN control.credential credential ON credential.participant_id=observation.participant_id
   AND credential.credential_id=observation.credential_id
  JOIN control.principal principal ON principal.participant_id=credential.participant_id
   AND principal.principal_id=credential.principal_id
  JOIN control.participant participant ON participant.participant_id=principal.participant_id
  JOIN control.privacy_domain privacy_domain ON privacy_domain.participant_id=observation.participant_id
   AND privacy_domain.privacy_domain_id=observation.privacy_domain_id
  WHERE observation.participant_id=pid AND observation.privacy_domain_id=privacy
   AND observation.runtime_target_id=target AND observation.connected
   AND observation.observed_at<=clock_timestamp() AND observation.valid_until>clock_timestamp()
   AND credential.kind='WORKLOAD_MTLS' AND credential.state='ACTIVE'
   AND credential.credential_epoch=observation.credential_epoch
   AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp()
   AND credential.subject='urn:openpc:participant:'||pid::text||':workload:'||target::text
   AND credential.audience='urn:openpc:workload:'||target::text
   AND credential.secret_fingerprint=decode(substring(observation.certificate_digest from 8),'hex')
   AND credential.certificate_der IS NOT NULL AND sha256(credential.certificate_der)=credential.secret_fingerprint
   AND principal.kind='WORKLOAD' AND principal.state='ACTIVE' AND principal.authority_epoch=observation.principal_epoch
   AND participant.state='ACTIVE' AND participant.archived_at IS NULL AND privacy_domain.state='ACTIVE')
  FROM control.runtime_target t WHERE t.participant_id=pid AND t.privacy_domain_id=privacy
   AND t.runtime_target_id=target AND pid=openpc.current_participant_id() AND privacy=openpc.current_privacy_domain_id()),false)
$$;
REVOKE ALL ON FUNCTION openpc.runtime_target_discovery_current(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_target_discovery_current(uuid,uuid,uuid)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_target_connection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','MEMBER') OR
  NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR
  NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id() OR
  (TG_OP='UPDATE' AND (NEW.participant_id<>OLD.participant_id OR NEW.privacy_domain_id<>OLD.privacy_domain_id OR NEW.runtime_target_id<>OLD.runtime_target_id))
 THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-OWNER-INVALID'; END IF;
 IF NEW.connected AND (NEW.observed_at>clock_timestamp() OR NEW.valid_until<=clock_timestamp() OR NOT EXISTS(SELECT 1 FROM control.runtime_target t JOIN control.credential c
  ON c.participant_id=t.participant_id AND c.credential_id=NEW.credential_id
  JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
  WHERE t.runtime_target_id=NEW.runtime_target_id AND t.participant_id=NEW.participant_id
   AND t.privacy_domain_id=NEW.privacy_domain_id AND t.requires_authenticated_discovery
   AND c.kind='WORKLOAD_MTLS' AND c.state='ACTIVE' AND c.credential_epoch=NEW.credential_epoch
   AND c.subject='urn:openpc:participant:'||t.participant_id::text||':workload:'||t.runtime_target_id::text
   AND c.audience='urn:openpc:workload:'||t.runtime_target_id::text
   AND c.certificate_der IS NOT NULL AND sha256(c.certificate_der)=c.secret_fingerprint
   AND c.secret_fingerprint=decode(substring(NEW.certificate_digest from 8),'hex')
   AND c.valid_from<=NEW.observed_at AND c.valid_until>=NEW.valid_until
   AND p.kind='WORKLOAD' AND p.state='ACTIVE' AND p.authority_epoch=NEW.principal_epoch))
 THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-CREDENTIAL-INVALID'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS runtime_target_connection_fence ON control.runtime_target_connection;
CREATE TRIGGER runtime_target_connection_fence BEFORE INSERT OR UPDATE OR DELETE ON control.runtime_target_connection
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();
DROP TRIGGER IF EXISTS runtime_target_connection_owner ON control.runtime_target_connection;
CREATE TRIGGER runtime_target_connection_owner BEFORE INSERT OR UPDATE ON control.runtime_target_connection
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_target_connection();

CREATE OR REPLACE FUNCTION openpc.guard_initial_target_discovery()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW.requires_authenticated_discovery IS DISTINCT FROM OLD.requires_authenticated_discovery
 THEN RAISE EXCEPTION 'DATA-6007-TARGET-ENROLLMENT-IMMUTABLE'; END IF;
 IF NEW.requires_authenticated_discovery AND NEW.state='DISCOVERED' AND
  (NOT pg_has_role(current_user,'openpc_control_worker','MEMBER') OR
   NOT openpc.runtime_target_discovery_current(NEW.participant_id,NEW.privacy_domain_id,NEW.runtime_target_id))
 THEN RAISE EXCEPTION 'DATA-6007-TARGET-DISCOVERY-REQUIRED'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS initial_target_discovery ON control.runtime_target;
CREATE TRIGGER initial_target_discovery BEFORE INSERT OR UPDATE ON control.runtime_target
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_initial_target_discovery();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1','privacy-explorer-profile','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EXPLORER_PROFILE_PUBLICATION'),
 ('ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1','privacy-explorer-profile','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EXPLORER_PROFILE_REVOCATION'),
 ('ACT-PRIVACY_EXPLORER_PROFILES_READ_RESOURCE-V1','privacy-explorer-profile','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EXPLORER_PROFILE_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
 (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
  idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
 ('ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1','privacy-explorer-profile','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EXPLORER_PROFILE_PUBLICATION'),
 ('ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1','privacy-explorer-profile','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EXPLORER_PROFILE_REVOCATION'),
 ('ACT-PRIVACY_EXPLORER_PROFILES_READ_RESOURCE-V1','privacy-explorer-profile','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EXPLORER_PROFILE_READ')))<>3 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-PROFILE-ACTION';
 END IF;
END $$;
ALTER TABLE control.privacy_explorer_profile FORCE ROW LEVEL SECURITY;
CREATE OR REPLACE FUNCTION openpc.guard_explorer_profile()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.profile_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.profile-'digest'),'UTF8')),'hex') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-PROFILE';
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'REGISTERED' OR NEW.revision<>1 OR NEW.revocation_operation_id IS NOT NULL
   OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>'ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1' THEN
   RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-PROFILE';
  END IF;
  NEW.created_at:=clock_timestamp();
 ELSE
  PERFORM pg_advisory_xact_lock(hashtextextended('privacy-explorer-profile:'||OLD.registration_id::text,0));
  IF (to_jsonb(NEW)-ARRAY['state','revision','revocation_operation_id']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['state','revision','revocation_operation_id'])
   OR OLD.state<>'REGISTERED' OR NEW.state<>'REVOKED' OR NEW.revision<>OLD.revision+1
   OR NEW.revocation_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>'ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1' THEN
   RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-PROFILE';
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS explorer_profile_guard ON control.privacy_explorer_profile;
CREATE TRIGGER explorer_profile_guard BEFORE INSERT OR UPDATE OR DELETE ON control.privacy_explorer_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_explorer_profile();

CREATE OR REPLACE FUNCTION openpc.require_explorer_profile_evidence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE
 operation uuid; catalog text; action text; expected_event_type text; expected bigint;
BEGIN
 IF TG_OP='INSERT' THEN
  operation:=NEW.publication_operation_id; catalog:='CFG-OP-CREATE-EXPLORER-PROFILE';
  action:='ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1'; expected_event_type:='openpc.privacy-explorer.profile.registered.v1'; expected:=0;
 ELSE
  operation:=NEW.revocation_operation_id; catalog:='CFG-OP-REVOKE-EXPLORER-PROFILE';
  action:='ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1'; expected_event_type:='openpc.privacy-explorer.profile.revoked.v1'; expected:=OLD.revision;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=operation AND evidence.aggregate_type='privacy-explorer-profile'
   AND evidence.aggregate_id=NEW.registration_id AND evidence.catalog_operation_id=catalog AND evidence.action_intent_id=action
   AND candidate.resource_id=NEW.registration_id AND candidate.state='CONSUMED' AND candidate.expected_revision=expected
   AND (TG_OP<>'INSERT' OR (candidate.candidate_document->'profile'=NEW.profile
    AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')))
   AND receipt.terminal_state='COMMITTED' AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.registration_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.registration_id
    AND event.aggregate_type='privacy-explorer-profile' AND event.event_type=expected_event_type)) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-PROFILE-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS explorer_profile_evidence ON control.privacy_explorer_profile;
CREATE CONSTRAINT TRIGGER explorer_profile_evidence AFTER INSERT OR UPDATE ON control.privacy_explorer_profile
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_explorer_profile_evidence();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1','privacy-explorer-profile','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','EXPLORER_DISCLOSURE'),
 ('ACT-PRIVACY_EXPLORER_READ_OCCURRENCE-V1','privacy-explorer-occurrence','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','EXPLORER_DISCLOSURE_STATUS')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
 (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
  idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
 ('ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1','privacy-explorer-profile','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','EXPLORER_DISCLOSURE'),
 ('ACT-PRIVACY_EXPLORER_READ_OCCURRENCE-V1','privacy-explorer-occurrence','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','EXPLORER_DISCLOSURE_STATUS')))<>2 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-DISCLOSURE-ACTION';
 END IF;
END $$;
ALTER TABLE control.privacy_explorer_execution FORCE ROW LEVEL SECURITY;
ALTER TABLE control.privacy_explorer_continuation FORCE ROW LEVEL SECURITY;
ALTER TABLE control.privacy_explorer_route_audit FORCE ROW LEVEL SECURITY;
GRANT SELECT ON control.privacy_explorer_route_audit TO openpc_control_maintenance;
CREATE OR REPLACE FUNCTION openpc.guard_explorer_custody()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' OR current_setting('openpc.action_intent_id')<>'ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN
  RAISE EXCEPTION 'PC-AUTH-0002-EXPLORER-CUSTODY';
 END IF;
 IF TG_TABLE_NAME='privacy_explorer_execution' THEN
  IF TG_OP='INSERT' THEN
   IF NEW.revision<>0 OR NEW.disposition<>'OPEN' OR NEW.evidence IS NOT NULL
    OR NEW.deadline_at<=clock_timestamp() THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
   NEW.created_at:=clock_timestamp();
  ELSE
   IF OLD.disposition<>'OPEN' OR
    (to_jsonb(NEW)-ARRAY['snapshot','revision','disposition','evidence','evidence_digest','release_claim_id','release_authorized_at','updated_at'])
      IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['snapshot','revision','disposition','evidence','evidence_digest','release_claim_id','release_authorized_at','updated_at']) THEN
    RAISE EXCEPTION 'PC-DATA-6007';
   END IF;
   IF NEW.revision=OLD.revision THEN
    IF NEW.snapshot IS DISTINCT FROM OLD.snapshot OR NEW.evidence IS DISTINCT FROM OLD.evidence
     OR NEW.evidence_digest IS DISTINCT FROM OLD.evidence_digest
     OR NEW.disposition NOT IN ('RELEASE_AUTHORIZED','INTERRUPTED') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   ELSIF NEW.revision<>OLD.revision+1 OR NEW.disposition NOT IN ('OPEN','SUPPRESSED')
     OR OLD.evidence IS NOT NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   IF NEW.disposition='RELEASE_AUTHORIZED' AND NEW.deadline_at<=clock_timestamp() THEN
    RAISE EXCEPTION 'PC-OPS-9003';
   END IF;
  END IF;
  NEW.updated_at:=clock_timestamp();
 ELSE
  IF TG_OP='INSERT' AND NEW.consumed_by IS NOT NULL THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  IF TG_OP='UPDATE' AND (OLD.consumed_by IS NOT NULL OR NEW.consumed_by IS NULL
    OR (to_jsonb(NEW)-'consumed_by') IS DISTINCT FROM (to_jsonb(OLD)-'consumed_by')) THEN
    RAISE EXCEPTION 'PC-DATA-6007';
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS explorer_execution_guard ON control.privacy_explorer_execution;
CREATE TRIGGER explorer_execution_guard BEFORE INSERT OR UPDATE OR DELETE ON control.privacy_explorer_execution
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_explorer_custody();
DROP TRIGGER IF EXISTS explorer_continuation_guard ON control.privacy_explorer_continuation;
CREATE TRIGGER explorer_continuation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.privacy_explorer_continuation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_explorer_custody();


CREATE OR REPLACE FUNCTION openpc.guard_transferred_contract()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW.transaction_policy IS DISTINCT FROM OLD.transaction_policy THEN
  RAISE EXCEPTION 'PC-AUTH-0002-TRANSACTION-POLICY-IMMUTABLE';
 END IF;
 IF NEW.state='BOUND' AND EXISTS(SELECT 1 FROM control.contract_administration_transfer
   WHERE logical_contract_id=NEW.logical_contract_id AND participant_id=NEW.participant_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-ADMINISTRATION-TRANSFERRED';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS contract_administration_fence ON control.contract_runtime_binding;
CREATE TRIGGER contract_administration_fence BEFORE INSERT OR UPDATE ON control.contract_runtime_binding
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_transferred_contract();
CREATE OR REPLACE FUNCTION openpc.reject_contract_transfer_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-HISTORY'; END $$;
DROP TRIGGER IF EXISTS contract_transfer_immutable ON control.contract_administration_transfer;
CREATE TRIGGER contract_transfer_immutable BEFORE UPDATE OR DELETE ON control.contract_administration_transfer
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_contract_transfer_mutation();
CREATE OR REPLACE FUNCTION openpc.require_contract_transfer_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE mode text:=current_setting('openpc.context_mode');
 owner uuid:=nullif(current_setting('openpc.participant_id'),'')::uuid;
 privacy uuid:=nullif(current_setting('openpc.privacy_domain_id'),'')::uuid;
 op uuid:=current_setting('openpc.operation_id')::uuid;
 action text:=current_setting('openpc.action_intent_id');
 transition control.participant_lifecycle_transition%ROWTYPE; valid boolean;
BEGIN
 IF NEW.source_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.prior_definition-'contentDigest'),'UTF8')),'hex')
   OR NEW.prior_definition->>'contentDigest'<>NEW.source_digest OR jsonb_array_length(NEW.binding_map)<>jsonb_array_length(NEW.prior_definition->'bindings')
   OR (SELECT count(DISTINCT mapping->>'sourceBindingId') FROM jsonb_array_elements(NEW.binding_map) mapping)<>jsonb_array_length(NEW.binding_map)
   OR (SELECT count(DISTINCT mapping->>'successorBindingId') FROM jsonb_array_elements(NEW.binding_map) mapping)<>jsonb_array_length(NEW.binding_map) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-DEFINITION';
 END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.participant_id,NEW.privacy_domain_id,op,action,true);
 SELECT * INTO transition FROM control.participant_lifecycle_transition WHERE participant_id=NEW.participant_id
  AND operation_id=NEW.operation_id AND mutation='TRANSFER';
 IF NOT FOUND OR EXISTS(SELECT 1 FROM control.contract_runtime_binding WHERE logical_contract_id=NEW.logical_contract_id AND state='BOUND') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-SOURCE';
 END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',transition.source_participant_id,transition.source_privacy_domain_id,op,action,true);
 SELECT EXISTS(SELECT 1 FROM control.mutation_candidate c WHERE c.participant_id=transition.source_participant_id
  AND c.consumed_operation_id=NEW.operation_id AND c.state='CONSUMED' AND c.catalog_operation_id='ID-OP-PARTICIPANT-TRANSFER'
  AND c.candidate_document->>'logicalContractId'=NEW.logical_contract_id::text
  AND c.candidate_document->>'contentDigest'=NEW.source_digest
  AND c.candidate_document->>'successorParticipantId'=NEW.successor_participant_id::text
  AND c.candidate_document->>'successorPrivacyDomainId'=NEW.successor_privacy_domain_id::text
  AND c.candidate_document->>'successorLogicalContractId'=NEW.successor_logical_contract_id::text
  AND (c.candidate_document->>'expectedSuccessorEpoch')::numeric+1=NEW.successor_epoch::numeric) INTO valid;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-CANDIDATE'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.successor_participant_id,NEW.successor_privacy_domain_id,op,action,true);
 SELECT EXISTS(SELECT 1 FROM control.participant p JOIN control.logical_contract_asset asset ON asset.participant_id=p.participant_id
  WHERE p.participant_id=NEW.successor_participant_id AND p.authority_epoch=NEW.successor_epoch::numeric AND p.state='ACTIVE'
   AND asset.logical_contract_id=NEW.successor_logical_contract_id AND asset.privacy_domain_id=NEW.successor_privacy_domain_id) INTO valid;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.binding_map) mapping WHERE NOT EXISTS(
   SELECT 1 FROM control.contract_runtime_binding binding JOIN control.abi_artifact artifact ON artifact.abi_artifact_id=binding.abi_artifact_id
    JOIN jsonb_array_elements(NEW.prior_definition->'bindings') prior ON prior->>'runtime_binding_id'=mapping->>'sourceBindingId'
    JOIN jsonb_array_elements(NEW.prior_definition->'abiArtifacts') abi ON abi->>'abi_artifact_id'=prior->>'abi_artifact_id'
   WHERE binding.participant_id=NEW.successor_participant_id AND binding.privacy_domain_id=NEW.successor_privacy_domain_id
    AND binding.logical_contract_id=NEW.successor_logical_contract_id AND binding.runtime_binding_id::text=mapping->>'successorBindingId'
    AND binding.abi_artifact_id::text=mapping->>'successorAbiArtifactId' AND binding.contract_address=prior->>'contract_address'
    AND binding.chain_id=prior->>'chain_id' AND binding.network_id=prior->>'network_id' AND binding.code_digest=prior->>'code_digest'
    AND binding.genesis_digest=prior->>'genesis_digest' AND binding.abi_version=prior->>'abi_version'
    AND binding.proxy_address IS NOT DISTINCT FROM prior->>'proxy_address'
    AND binding.implementation_address IS NOT DISTINCT FROM prior->>'implementation_address'
    AND binding.implementation_code_digest IS NOT DISTINCT FROM prior->>'implementation_code_digest'
    AND coalesce(binding.transaction_policy,'null'::jsonb)=coalesce(prior->'transaction_policy','null'::jsonb)
    AND artifact.canonical_abi_bytes=(abi->>'canonical_abi_bytes')::bytea
    AND artifact.abi_digest=abi->>'abi_digest' AND artifact.canonical_abi=abi->'canonical_abi' AND binding.state='BOUND')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-BINDINGS';
 END IF;
 PERFORM openpc.set_request_context(mode,owner,privacy,op,action,privacy IS NOT NULL);
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-CONTRACT-TRANSFER-SUCCESSOR'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS contract_transfer_provenance ON control.contract_administration_transfer;
CREATE CONSTRAINT TRIGGER contract_transfer_provenance AFTER INSERT ON control.contract_administration_transfer
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_contract_transfer_provenance();



CREATE OR REPLACE FUNCTION openpc.deployment_rejection_source(command uuid,participant uuid,privacy uuid)
RETURNS TABLE(signed_bytes bytea,result_digest text,created_at text,preparation_bytes bytea,
 publication_bytes bytea,signed_transaction text,candidate_digest text,evidence_digest text,
 attempt_id text,actor_principal_id text)
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
-- Shared immutable rejection source: signed command completion, never absence alone.
select result.signed_bytes,result.result_digest,result.created_at::text,
      intent.preparation_bytes,intent.publication_bytes,candidate.candidate_document->>'signedTransaction' signed_transaction,
      encode(candidate.candidate_digest,'hex') candidate_digest,encode(evidence.evidence_digest,'hex') evidence_digest,
      candidate.resource_id::text attempt_id,intent.actor_principal_id::text
     from control.deployment_result result
     join control.mutation_candidate candidate on candidate.participant_id=result.participant_id
      and candidate.privacy_domain_id=result.privacy_domain_id and candidate.consumed_operation_id=result.command_id
      and candidate.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT' and candidate.state='CONSUMED'
      and candidate.action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
      and candidate.resource_type='deployment-submission' and candidate.operation_class='CREATE'
     join control.idempotency_record receipt on receipt.participant_id=candidate.participant_id
      and receipt.privacy_domain_id=candidate.privacy_domain_id and receipt.operation_id=candidate.consumed_operation_id
      and receipt.catalog_operation_id=candidate.catalog_operation_id and receipt.input_digest=candidate.candidate_digest
      and receipt.principal_id=candidate.maker_principal_id and receipt.terminal_state='COMMITTED'
     join control.mutation_evidence evidence on evidence.participant_id=candidate.participant_id
      and evidence.privacy_domain_id=candidate.privacy_domain_id and evidence.operation_id=candidate.consumed_operation_id
      and evidence.catalog_operation_id=candidate.catalog_operation_id and evidence.candidate_digest=candidate.candidate_digest
      and evidence.aggregate_id=candidate.resource_id and evidence.aggregate_type='deployment-submission'
     join control.deployment_intent intent on intent.participant_id=candidate.participant_id
      and intent.privacy_domain_id=candidate.privacy_domain_id and intent.actor_principal_id=candidate.maker_principal_id
      and candidate.candidate_document->>'deploymentIntentId'='urn:openpc:resource:'||intent.deployment_intent_id::text
     where result.command_id=$1 and result.participant_id=$2 and result.privacy_domain_id=$3 and result.sequence=1
      and not exists(select 1 from control.deployment_address_reservation reservation where reservation.command_id=result.command_id)

$$;
REVOKE ALL ON FUNCTION openpc.deployment_rejection_source(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.deployment_rejection_source(uuid,uuid,uuid)
 TO openpc_control_worker,openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.lock_deployment_command(command_id uuid)
RETURNS void LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT pg_advisory_xact_lock(hashtextextended('openpc:deployment-command:'||command_id::text,0))
$$;
REVOKE ALL ON FUNCTION openpc.lock_deployment_command(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_deployment_command(uuid) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.validate_deployment_rejection(result control.deployment_result)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE claims jsonb; expected jsonb; issued_at timestamptz; expires_at timestamptz;
BEGIN
 PERFORM openpc.assert_request_context(true);
 PERFORM openpc.lock_deployment_command(result.command_id);
 claims:=convert_from(result.signed_bytes,'UTF8')::jsonb->'claims';
 IF NOT openpc.matches_participant(result.participant_id) OR NOT openpc.matches_privacy(result.privacy_domain_id)
  OR result.sequence<>1 OR claims->>'schema' IS DISTINCT FROM 'PC-DEPLOYMENT-RESERVATION-REJECTION-1'
  OR NOT coalesce(claims->>'reason' IN ('CUSTODY_CONFLICT','PREPARATION_EXPIRED','MODULE_GENERATION_UNAVAILABLE'),false)
  OR NOT coalesce(claims->'binding'->>'transactionHash' ~ '^0x[0-9a-f]{64}$',false)
  OR EXISTS(SELECT 1 FROM control.deployment_address_reservation WHERE command_id=result.command_id)
  OR EXISTS(SELECT 1 FROM control.deployment_result prior WHERE prior.command_id=result.command_id)
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF claims->>'reason'='MODULE_GENERATION_UNAVAILABLE' THEN
  PERFORM pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||result.participant_id::text||':'||result.privacy_domain_id::text,0));
  IF EXISTS(SELECT 1 FROM control.deployment_intent i WHERE i.participant_id=result.participant_id
   AND i.privacy_domain_id=result.privacy_domain_id
   AND i.preparation_digest='sha256:'||(claims->'binding'->>'preparationDigest')
   AND i.module_generation_digest IS NOT NULL
   AND i.module_generation_digest=openpc.deployment_module_generation(i.participant_id,i.privacy_domain_id))
  THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 END IF;
 SELECT jsonb_build_object(
   'targetRuntimeId',intent.runtime_target_id::text,
   'owner',jsonb_build_object('participant_id',candidate.participant_id::text,
     'privacy_domain_id',candidate.privacy_domain_id::text,'actor_principal_id',intent.execution_principal_id::text,
     'workload_id',intent.execution_workload_id),
   'commandId',candidate.consumed_operation_id::text,'attemptId',candidate.resource_id::text,
   'intentDigest',substring(intent.intent_digest from 8),'preparationDigest',substring(intent.preparation_digest from 8),
   'chainId',prepared.document->'intent'->>'chainId','genesisDigest',prepared.document->'intent'->>'genesisHash',
   'transactionHash',claims->'binding'->>'transactionHash'),candidate.created_at,intent.expires_at
 INTO STRICT expected,issued_at,expires_at
 FROM control.mutation_candidate candidate
 JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id
  AND receipt.privacy_domain_id=candidate.privacy_domain_id AND receipt.operation_id=candidate.consumed_operation_id
  AND receipt.catalog_operation_id=candidate.catalog_operation_id AND receipt.input_digest=candidate.candidate_digest
  AND receipt.principal_id=candidate.maker_principal_id AND receipt.terminal_state='COMMITTED'
 JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id
  AND evidence.privacy_domain_id=candidate.privacy_domain_id AND evidence.operation_id=candidate.consumed_operation_id
  AND evidence.catalog_operation_id=candidate.catalog_operation_id AND evidence.candidate_digest=candidate.candidate_digest
  AND evidence.aggregate_id=candidate.resource_id AND evidence.aggregate_type='deployment-submission'
 JOIN control.deployment_intent intent ON intent.participant_id=candidate.participant_id
  AND intent.privacy_domain_id=candidate.privacy_domain_id AND intent.actor_principal_id=candidate.maker_principal_id
  AND candidate.candidate_document->>'deploymentIntentId'='urn:openpc:resource:'||intent.deployment_intent_id::text
 CROSS JOIN LATERAL (SELECT convert_from(intent.preparation_bytes,'UTF8')::jsonb document) prepared
 WHERE candidate.participant_id=result.participant_id AND candidate.privacy_domain_id=result.privacy_domain_id
  AND candidate.consumed_operation_id=result.command_id AND candidate.state='CONSUMED'
  AND candidate.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
  AND candidate.action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND candidate.resource_type='deployment-submission' AND candidate.operation_class='CREATE'
  AND encode(candidate.candidate_digest,'hex')=claims->>'candidateDigest'
  AND encode(evidence.evidence_digest,'hex')=claims->>'authorizationEvidenceDigest';
 IF claims->'binding' IS DISTINCT FROM expected OR claims->>'observedAt' IS NULL
  OR (claims->>'observedAt')::timestamptz<issued_at
  OR (claims->>'observedAt')::timestamptz>clock_timestamp()+interval '5 seconds'
  OR (claims->>'reason'='PREPARATION_EXPIRED' AND
    (expires_at>clock_timestamp() OR (claims->>'observedAt')::timestamptz<expires_at))
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.validate_deployment_rejection(control.deployment_result) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.validate_deployment_rejection(control.deployment_result) TO openpc_control_worker;


-- The migration owns an exclusive DDL transaction. Recover only exact immutable
-- intent nonces; unresolved historical custody remains retained and fail-closed.
DROP TRIGGER IF EXISTS deployment_address_reservation_guard ON control.deployment_address_reservation;
UPDATE control.deployment_address_reservation reservation SET sender_nonce=document.nonce
FROM control.deployment_intent intent,
 LATERAL (SELECT convert_from(intent.preparation_bytes,'UTF8')::jsonb->'intent'->>'nonce' AS nonce,
  convert_from(intent.preparation_bytes,'UTF8')::jsonb->'intent'->>'sender' AS sender) document
WHERE reservation.sender_nonce IS NULL AND reservation.participant_id=intent.participant_id
 AND reservation.privacy_domain_id=intent.privacy_domain_id
 AND reservation.prepared_record_digest=intent.preparation_digest AND reservation.intent_digest=intent.intent_digest
 AND reservation.sender_address=document.sender AND document.nonce ~ '^(0|[1-9][0-9]{0,19})$'
 AND document.nonce::numeric<2::numeric^64;

-- Only this trigger can inspect global legacy custody. It returns no foreign
-- row data and never confers a grant or performs an effect.
CREATE OR REPLACE FUNCTION openpc.guard_deployment_sender_custody()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id)
  OR NEW.sender_nonce IS NULL OR EXISTS(
   SELECT 1 FROM control.deployment_address_reservation held
   WHERE held.chain_id=NEW.chain_id AND held.genesis_digest=NEW.genesis_digest
    AND held.sender_address=NEW.sender_address AND held.sender_nonce IS NULL AND held.state<>'EXPIRED') THEN
  RAISE EXCEPTION 'PC-DATA-6004';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_deployment_sender_custody() FROM PUBLIC;
DROP TRIGGER IF EXISTS deployment_sender_custody_guard ON control.deployment_address_reservation;
CREATE TRIGGER deployment_sender_custody_guard BEFORE INSERT ON control.deployment_address_reservation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_sender_custody();

CREATE OR REPLACE FUNCTION openpc.guard_deployment_address_reservation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE observed_at timestamptz:=date_trunc('milliseconds',clock_timestamp());
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'DELETE' THEN
  PERFORM openpc.lock_deployment_command(NEW.command_id);
  IF EXISTS(SELECT 1 FROM control.deployment_result result WHERE result.command_id=NEW.command_id
   AND convert_from(result.signed_bytes,'UTF8')::jsonb->>'purpose'='openpc:deployment-reservation-rejection:v1')
  THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'RESERVED' OR NEW.handoff_at IS NOT NULL OR NEW.expired_at IS NOT NULL OR NEW.expires_at<=observed_at THEN
   RAISE EXCEPTION 'PC-DATA-6004';
  END IF;
  IF NEW.predecessor_command_id IS NOT NULL THEN
   -- A new approved command can share only the exact still-held original
   -- address/nonce custody. This is not a pending-chain or send assertion.
   PERFORM 1 FROM control.deployment_address_reservation prior
    JOIN control.mutation_candidate original ON original.consumed_operation_id=prior.command_id
     AND original.participant_id=prior.participant_id AND original.privacy_domain_id=prior.privacy_domain_id
     AND original.state='CONSUMED' AND original.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
    JOIN control.mutation_candidate successor ON successor.consumed_operation_id=NEW.command_id
     AND successor.participant_id=NEW.participant_id AND successor.privacy_domain_id=NEW.privacy_domain_id
     AND successor.state='CONSUMED' AND successor.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
     AND successor.maker_principal_id=original.maker_principal_id
     AND successor.candidate_document->>'predecessorOperationId'='urn:openpc:operation:'||prior.command_id::text
    WHERE prior.command_id=NEW.predecessor_command_id AND prior.predecessor_command_id IS NULL
     AND prior.state='HANDOFF' AND prior.participant_id=NEW.participant_id AND prior.privacy_domain_id=NEW.privacy_domain_id
     AND ROW(prior.target_runtime_id,prior.chain_id,prior.genesis_digest,prior.contract_address,prior.helper_address,
      prior.sender_address,prior.sender_nonce,prior.creator_address,prior.mechanism,prior.salt_namespace_digest,prior.effective_salt,
      prior.artifact_digest,prior.init_code_hash,prior.profile_digest,prior.generation_digest,
      prior.native_value_authorization_id,prior.native_value_authorization_digest)
      IS NOT DISTINCT FROM ROW(NEW.target_runtime_id,NEW.chain_id,NEW.genesis_digest,NEW.contract_address,NEW.helper_address,
      NEW.sender_address,NEW.sender_nonce,NEW.creator_address,NEW.mechanism,NEW.salt_namespace_digest,NEW.effective_salt,
      NEW.artifact_digest,NEW.init_code_hash,NEW.profile_digest,NEW.generation_digest,
      NEW.native_value_authorization_id,NEW.native_value_authorization_digest)
     AND prior.transaction_hash<>NEW.transaction_hash FOR SHARE OF prior;
   IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  END IF;
  NEW.created_at:=observed_at;
 ELSIF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'PC-DATA-6004';
 ELSE
  IF (to_jsonb(NEW)-ARRAY['state','handoff_at','expired_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['state','handoff_at','expired_at']) OR OLD.state<>'RESERVED' THEN
   RAISE EXCEPTION 'PC-DATA-6004';
  END IF;
  IF NEW.state='HANDOFF' AND NEW.sender_nonce IS NOT NULL AND OLD.expires_at>observed_at AND NEW.expired_at IS NULL THEN
   NEW.handoff_at:=observed_at;
  ELSIF NEW.state='EXPIRED' AND OLD.expires_at<=observed_at AND NEW.handoff_at IS NULL THEN
   NEW.expired_at:=observed_at;
  ELSE
   RAISE EXCEPTION 'PC-DATA-6004';
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS deployment_address_reservation_guard ON control.deployment_address_reservation;
CREATE TRIGGER deployment_address_reservation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deployment_address_reservation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_address_reservation();

-- Materialized physical keys cover every address of the same governed attempt.
-- Unique-index arbitration also sees foreign-scope rows without disclosing them.
INSERT INTO control.deployment_address_claim
 (attempt_id,participant_id,privacy_domain_id,chain_id,genesis_digest,address,active)
 SELECT reservation.attempt_id,reservation.participant_id,reservation.privacy_domain_id,
  reservation.chain_id,reservation.genesis_digest,claimed.address,reservation.state<>'EXPIRED'
 FROM control.deployment_address_reservation reservation
 CROSS JOIN LATERAL unnest(ARRAY[reservation.contract_address,reservation.helper_address]) claimed(address)
 WHERE claimed.address IS NOT NULL AND reservation.predecessor_command_id IS NULL
 ON CONFLICT (attempt_id,address) DO NOTHING;

CREATE OR REPLACE FUNCTION openpc.sync_deployment_address_claims()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id) THEN
  RAISE EXCEPTION 'PC-DATA-6004';
 END IF;
 IF TG_OP='INSERT' AND NEW.predecessor_command_id IS NULL THEN
  INSERT INTO control.deployment_address_claim
   (attempt_id,participant_id,privacy_domain_id,chain_id,genesis_digest,address,active)
   SELECT NEW.attempt_id,NEW.participant_id,NEW.privacy_domain_id,NEW.chain_id,NEW.genesis_digest,address,true
   FROM unnest(ARRAY[NEW.contract_address,NEW.helper_address]) claimed(address)
   WHERE address IS NOT NULL ORDER BY address;
 ELSIF NEW.state='EXPIRED' THEN
  UPDATE control.deployment_address_claim SET active=false
   WHERE attempt_id=NEW.attempt_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.sync_deployment_address_claims() FROM PUBLIC;
DROP TRIGGER IF EXISTS deployment_address_claim_sync ON control.deployment_address_reservation;
CREATE TRIGGER deployment_address_claim_sync AFTER INSERT OR UPDATE OF state ON control.deployment_address_reservation
 FOR EACH ROW EXECUTE FUNCTION openpc.sync_deployment_address_claims();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1','deployment-policy','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_POLICY_PUBLICATION'),
 ('ACT-DEPLOYMENT_POLICIES_READ_RESOURCE-V1','deployment-policy','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','DEPLOYMENT_POLICY_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1','deployment-policy','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_POLICY_PUBLICATION'),
  ('ACT-DEPLOYMENT_POLICIES_READ_RESOURCE-V1','deployment-policy','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','DEPLOYMENT_POLICY_READ')))<>2 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-ACTION-REGISTRATION';
 END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_deployment_policy()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1'
  OR NEW.definition_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.definition),'UTF8')),'hex')
  OR (NEW.definition->>'expiresAt')::timestamptz<=clock_timestamp() THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-PUBLICATION';
 END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS deployment_policy_guard ON control.deployment_policy;
CREATE TRIGGER deployment_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deployment_policy
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_policy();

CREATE OR REPLACE FUNCTION openpc.require_deployment_policy_publication()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  JOIN control.abi_artifact abi ON abi.participant_id=NEW.participant_id AND abi.privacy_domain_id=NEW.privacy_domain_id
   AND abi.abi_artifact_id=NEW.abi_artifact_id AND abi.abi_digest=NEW.abi_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.publication_operation_id AND evidence.aggregate_type='deployment-policy'
   AND evidence.aggregate_id=NEW.deployment_policy_id AND evidence.catalog_operation_id='CFG-OP-CREATE-DEPLOYMENT-POLICY'
   AND evidence.action_intent_id='ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1'
   AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.deployment_policy_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND candidate.candidate_document->'definition'=NEW.definition
   AND NEW.definition->>'abiArtifactId'='urn:openpc:resource:'||NEW.abi_artifact_id::text
   AND NEW.artifact_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
    'mode',NEW.definition->'artifact'->>'mode','initCodeHash',NEW.init_code_hash,
    'runtimeCodeHash',NEW.definition->'artifact'->>'runtimeCodeHash')),'UTF8')),'hex')
   AND ((NEW.definition->'route'->>'mechanism'='TRANSACTION_CREATE' AND NEW.factory_runtime_binding_id IS NULL)
    OR (NEW.definition->'route'->>'mechanism' IN ('CREATE','CREATE2','CREATE3')
     AND NEW.definition->'route'->>'runtimeBindingId'='urn:openpc:resource:'||NEW.factory_runtime_binding_id::text
     AND EXISTS(SELECT 1 FROM control.contract_runtime_binding factory WHERE factory.participant_id=NEW.participant_id
      AND factory.privacy_domain_id=NEW.privacy_domain_id AND factory.runtime_binding_id=NEW.factory_runtime_binding_id
      AND factory.state='BOUND' AND factory.chain_id=NEW.definition->>'chainId'
      AND factory.network_id=NEW.definition->>'networkId' AND factory.genesis_digest=NEW.definition->>'genesisDigest'
      AND factory.proxy_address IS NULL AND factory.implementation_address IS NULL AND factory.implementation_code_digest IS NULL)))
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.deployment_policy_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.deployment_policy_id
    AND event.aggregate_type='deployment-policy' AND event.event_type='openpc.deployment.policy.staged.v1')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-PUBLICATION-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS deployment_policy_publication ON control.deployment_policy;
CREATE CONSTRAINT TRIGGER deployment_policy_publication AFTER INSERT ON control.deployment_policy
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_deployment_policy_publication();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1','deployment-submission','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_SUBMISSION'),
 ('ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1','deployment-intent','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_INTENT_PREPARATION'),
 ('ACT-DEPLOYMENT_INTENTS_READ_RESOURCE-V1','deployment-intent','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','DEPLOYMENT_INTENT_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1','deployment-submission','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_SUBMISSION'),
  ('ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1','deployment-intent','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_INTENT_PREPARATION'),
  ('ACT-DEPLOYMENT_INTENTS_READ_RESOURCE-V1','deployment-intent','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','DEPLOYMENT_INTENT_READ'))) IS DISTINCT FROM 3 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-INTENT-ACTIONS';
 END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_deployment_intent()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE document jsonb; source jsonb; captured jsonb;
BEGIN
 IF TG_OP IS DISTINCT FROM 'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 document:=convert_from(NEW.preparation_bytes,'UTF8')::jsonb;
 source:=convert_from(NEW.publication_bytes,'UTF8')::jsonb;
 captured:=document->'context';
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0));
 IF NEW.module_generation_digest IS NULL OR NEW.module_generation_digest IS DISTINCT FROM
   openpc.deployment_module_generation(NEW.participant_id,NEW.privacy_domain_id)
 THEN RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-MODULE-GENERATION'; END IF;
 IF NEW.participant_id IS DISTINCT FROM current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id IS DISTINCT FROM current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.creation_operation_id IS DISTINCT FROM current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id') IS DISTINCT FROM 'ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1'
  OR document->>'schemaVersion' IS DISTINCT FROM 'PC-DEPLOYMENT-PREPARATION-1'
  OR captured->>'intentId' IS DISTINCT FROM NEW.deployment_intent_id::text
  OR captured->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR captured->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR captured->>'actorSubjectId' IS DISTINCT FROM coalesce(NEW.execution_principal_id,NEW.actor_principal_id)::text
  OR captured->>'workloadBindingId' IS DISTINCT FROM NEW.execution_workload_id
  OR (NEW.execution_principal_id IS NOT NULL AND NOT EXISTS(
   SELECT 1 FROM control.principal principal JOIN control.credential credential USING(participant_id,principal_id)
   WHERE principal.participant_id=NEW.participant_id AND principal.principal_id=NEW.execution_principal_id
    AND principal.kind='WORKLOAD' AND principal.state='ACTIVE' AND credential.kind='WORKLOAD_MTLS'
    AND credential.audience=NEW.execution_workload_id AND credential.state='ACTIVE'
    AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp()))
  OR captured->>'walletBindingId' IS DISTINCT FROM NEW.wallet_binding_id::text
  OR captured->>'targetRuntimeId' IS DISTINCT FROM NEW.runtime_target_id::text
  OR document->>'deploymentPolicyId' IS DISTINCT FROM NEW.deployment_policy_id::text
  OR NEW.creation_authority_digest IS DISTINCT FROM 'sha256:'||(captured->>'authorityDigest')
  OR NEW.preparation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.preparation_bytes),'hex')
  OR NEW.intent_digest IS DISTINCT FROM 'sha256:'||(document->'intent'->>'semanticDigest')
  OR document->>'publicationDigest' IS DISTINCT FROM encode(sha256(NEW.publication_bytes),'hex')
  OR NEW.expires_at IS DISTINCT FROM to_timestamp((captured->>'expiresAtMs')::numeric/1000)
  OR NEW.expires_at<=clock_timestamp() THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-INTENT';
 END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS deployment_intent_guard ON control.deployment_intent;
CREATE TRIGGER deployment_intent_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deployment_intent
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_intent();

CREATE OR REPLACE FUNCTION openpc.require_deployment_intent_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE document jsonb; source jsonb; captured jsonb;
BEGIN
 document:=convert_from(NEW.preparation_bytes,'UTF8')::jsonb;
 source:=convert_from(NEW.publication_bytes,'UTF8')::jsonb;
 captured:=document->'context';
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  JOIN control.deployment_policy policy ON policy.deployment_policy_id=NEW.deployment_policy_id
   AND policy.participant_id=NEW.participant_id AND policy.privacy_domain_id=NEW.privacy_domain_id
  JOIN control.wallet_binding wallet ON wallet.wallet_binding_id=NEW.wallet_binding_id
   AND wallet.participant_id=NEW.participant_id AND wallet.privacy_domain_id=NEW.privacy_domain_id
   AND wallet.subject_id=coalesce(NEW.execution_principal_id,NEW.actor_principal_id) AND wallet.state='ACTIVE'
   AND wallet.binding_epoch::text=captured->>'walletBindingEpoch'
   AND wallet.chain_id::text=policy.definition->>'chainId' AND wallet.wallet_address=document->'intent'->>'sender'
  JOIN control.runtime_target target ON target.runtime_target_id=NEW.runtime_target_id
   AND target.participant_id=NEW.participant_id AND target.privacy_domain_id=NEW.privacy_domain_id
   AND target.state='ACTIVE_MATCHED' AND target.active_generation_digest=target.desired_generation_digest
   AND target.policy_generation_digest='sha256:'||(captured->>'policyGenerationDigest')
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.creation_operation_id AND evidence.aggregate_type='deployment-intent'
   AND evidence.aggregate_id=NEW.deployment_intent_id AND evidence.catalog_operation_id='CFG-OP-CREATE-DEPLOYMENT-INTENT'
   AND evidence.action_intent_id='ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1'
   AND NEW.creation_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.deployment_intent_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND candidate.maker_principal_id=NEW.actor_principal_id
   AND candidate.candidate_document->>'deploymentPolicyId'='urn:openpc:resource:'||NEW.deployment_policy_id::text
   AND candidate.candidate_document->>'runtimeTargetId'='urn:openpc:resource:'||NEW.runtime_target_id::text
   AND candidate.candidate_document->>'walletBindingId'='urn:openpc:resource:'||NEW.wallet_binding_id::text
   AND (candidate.candidate_document->>'executionWorkloadId') IS NOT DISTINCT FROM NEW.execution_workload_id
   AND candidate.candidate_document->>'signingPayload'=document->>'signingPayload'
   AND ((candidate.candidate_document->>'nativeValueAuthorizationId' IS NULL
     AND captured->>'nativeValueAuthorizationBytes' IS NULL AND document->'intent'->>'nativeValueAuthorizationDigest' IS NULL
     AND document->'intent'->>'valueWei'='0')
    OR EXISTS(SELECT 1 FROM control.native_value_authorization issued_grant
     WHERE 'urn:openpc:resource:'||issued_grant.native_value_authorization_id::text=candidate.candidate_document->>'nativeValueAuthorizationId'
      AND issued_grant.participant_id=NEW.participant_id AND issued_grant.privacy_domain_id=NEW.privacy_domain_id
      AND issued_grant.wallet_binding_id=NEW.wallet_binding_id AND issued_grant.wallet_binding_epoch::text=captured->>'walletBindingEpoch'
      AND issued_grant.actor_principal_id=coalesce(NEW.execution_principal_id,NEW.actor_principal_id)
      AND issued_grant.execution_workload_id IS NOT DISTINCT FROM NEW.execution_workload_id
      AND '0x'||encode(issued_grant.document_bytes,'hex')=captured->>'nativeValueAuthorizationBytes'
      AND issued_grant.valid_until>clock_timestamp() AND issued_grant.valid_until>=NEW.expires_at
      AND (document->'intent'->>'valueWei'='0' OR issued_grant.semantic_digest='sha256:'||(document->'intent'->>'nativeValueAuthorizationDigest'))
      AND NOT EXISTS(SELECT 1 FROM control.deployment_address_reservation reservation
       WHERE reservation.native_value_authorization_id=issued_grant.native_value_authorization_id AND reservation.state='HANDOFF')))
   AND source=jsonb_build_object('deploymentPolicyId',policy.deployment_policy_id::text,
    'participantId',policy.participant_id::text,'privacyDomainId',policy.privacy_domain_id::text,
    'definition',policy.definition,'definitionDigest',policy.definition_digest,'artifactDigest',policy.artifact_digest,
    'initCodeHash',policy.init_code_hash,'abiDigest',policy.abi_digest,'publicationOperationId',policy.publication_operation_id::text,
    'publicationAuthorityDigest',policy.publication_authority_digest,'factoryBinding',
     (SELECT jsonb_build_object('runtimeBindingId',factory.runtime_binding_id::text,'chainId',factory.chain_id,
       'networkId',factory.network_id,'genesisDigest',factory.genesis_digest,'contractAddress',factory.contract_address,
       'codeDigest',factory.code_digest,'abiDigest',factory_abi.abi_digest,'canonicalAbi',factory_abi.canonical_abi)
      FROM control.contract_runtime_binding factory JOIN control.abi_artifact factory_abi
       ON factory_abi.participant_id=factory.participant_id AND factory_abi.privacy_domain_id=factory.privacy_domain_id
       AND factory_abi.abi_artifact_id=factory.abi_artifact_id
      WHERE factory.participant_id=policy.participant_id AND factory.privacy_domain_id=policy.privacy_domain_id
       AND factory.runtime_binding_id=policy.factory_runtime_binding_id AND factory.state='BOUND'
       AND factory.chain_id=policy.definition->>'chainId' AND factory.network_id=policy.definition->>'networkId'
       AND factory.genesis_digest=policy.definition->>'genesisDigest'
       AND factory.proxy_address IS NULL AND factory.implementation_address IS NULL
       AND factory.implementation_code_digest IS NULL))
   AND (policy.definition->'route'->>'mechanism'='TRANSACTION_CREATE')=(policy.factory_runtime_binding_id IS NULL)
   AND (policy.definition->>'expiresAt')::timestamptz>=NEW.expires_at
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.deployment_intent_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.deployment_intent_id
    AND event.aggregate_type='deployment-intent' AND event.event_type='openpc.deployment.intent.prepared.v1')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-INTENT-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS deployment_intent_provenance ON control.deployment_intent;
CREATE CONSTRAINT TRIGGER deployment_intent_provenance AFTER INSERT ON control.deployment_intent
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_deployment_intent_provenance();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1','native-value-authorization','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','NATIVE_VALUE_AUTHORIZATION'),
 ('ACT-NATIVE_VALUE_AUTHORIZATIONS_READ_RESOURCE-V1','native-value-authorization','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','NATIVE_VALUE_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1','native-value-authorization','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','NATIVE_VALUE_AUTHORIZATION'),
  ('ACT-NATIVE_VALUE_AUTHORIZATIONS_READ_RESOURCE-V1','native-value-authorization','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','NATIVE_VALUE_READ')))<>2 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-ACTION-REGISTRATION';
 END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_native_value_authorization()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE document jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 document:=convert_from(NEW.document_bytes,'UTF8')::jsonb;
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.creation_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1'
  OR jsonb_typeof(document)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(document))<>15
  OR convert_to(openpc.signing_canonical_json(document),'UTF8')<>NEW.document_bytes
  OR NEW.semantic_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(document-'semanticDigest'),'UTF8')),'hex')
  OR (document->>'authorizationId'='urn:openpc:resource:'||NEW.native_value_authorization_id::text
   AND document->>'participantId'=NEW.participant_id::text AND document->>'actorSubjectId'=NEW.actor_principal_id::text
   AND jsonb_typeof(document->'participantEpoch')='number' AND document->>'participantEpoch' ~ '^[1-9][0-9]{0,19}$'
   AND (document->>'participantEpoch')::numeric<=18446744073709551615
   AND document->>'purpose'='CONTRACT_CREATION_ENDOWMENT' AND document->'oneUse'='true'::jsonb AND document->'used'='false'::jsonb
   AND document->>'amountMode' IN ('EXACT','MAXIMUM') AND jsonb_typeof(document->'maxAmountWei')='string'
   AND document->>'maxAmountWei' ~ '^[1-9][0-9]{0,77}$'
   AND jsonb_typeof(document->'chainId')='string' AND document->>'chainId' ~ '^[1-9][0-9]{0,19}$'
   AND (document->>'chainId')::numeric<=18446744073709551615
   AND document->>'chainEnvironmentId' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
   AND document->>'genesisHash' ~ '^[0-9a-f]{64}$'
   AND document->>'policyDecisionDigest'=substring(NEW.creation_authority_digest,8)
   AND document->>'semanticDigest'=substring(NEW.semantic_digest,8)
   AND (document->>'validUntil')::timestamptz=NEW.valid_until) IS NOT TRUE THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-ISSUANCE';
 END IF;
 NEW.created_at:=date_trunc('milliseconds',clock_timestamp());
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS native_value_authorization_guard ON control.native_value_authorization;
CREATE TRIGGER native_value_authorization_guard BEFORE INSERT OR UPDATE OR DELETE ON control.native_value_authorization
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_native_value_authorization();

CREATE OR REPLACE FUNCTION openpc.require_native_value_issuance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE document jsonb:=convert_from(NEW.document_bytes,'UTF8')::jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  JOIN control.wallet_binding wallet ON wallet.participant_id=NEW.participant_id AND wallet.privacy_domain_id=NEW.privacy_domain_id
   AND wallet.wallet_binding_id=NEW.wallet_binding_id AND wallet.binding_epoch=NEW.wallet_binding_epoch
   AND wallet.subject_id=NEW.actor_principal_id AND wallet.state='ACTIVE' AND wallet.chain_id::text=document->>'chainId'
  JOIN control.participant participant ON participant.participant_id=NEW.participant_id
   AND participant.authority_epoch=(document->>'participantEpoch')::numeric
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.creation_operation_id AND evidence.aggregate_type='native-value-authorization'
   AND evidence.aggregate_id=NEW.native_value_authorization_id AND evidence.catalog_operation_id='CFG-OP-CREATE-NATIVE-VALUE-AUTHORIZATION'
   AND evidence.action_intent_id='ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1'
   AND NEW.creation_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.native_value_authorization_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND ((NEW.execution_workload_id IS NULL AND candidate.maker_principal_id=NEW.actor_principal_id)
    OR (NEW.execution_workload_id IS NOT NULL AND EXISTS(
     SELECT 1 FROM control.principal principal JOIN control.credential credential USING(participant_id,principal_id)
     WHERE principal.participant_id=NEW.participant_id AND principal.principal_id=NEW.actor_principal_id
      AND principal.kind='WORKLOAD' AND principal.state='ACTIVE' AND credential.kind='WORKLOAD_MTLS'
      AND credential.audience=NEW.execution_workload_id AND credential.state='ACTIVE'
      AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp())
     AND NOT EXISTS(SELECT 1 FROM control.principal other JOIN control.credential credential USING(participant_id,principal_id)
      WHERE other.participant_id=NEW.participant_id AND other.principal_id<>NEW.actor_principal_id
       AND other.kind='WORKLOAD' AND other.state='ACTIVE' AND credential.kind='WORKLOAD_MTLS'
       AND credential.audience=NEW.execution_workload_id AND credential.state='ACTIVE'
       AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp())))
   AND candidate.candidate_document->>'walletBindingId'='urn:openpc:resource:'||NEW.wallet_binding_id::text
   AND (candidate.candidate_document->>'executionWorkloadId') IS NOT DISTINCT FROM NEW.execution_workload_id
   AND candidate.candidate_document->>'chainId'=document->>'chainId'
   AND concat(candidate.candidate_document->>'chainId',':',candidate.candidate_document->>'networkId',':',candidate.candidate_document->>'genesisDigest')=document->>'chainEnvironmentId'
   AND candidate.candidate_document->>'genesisDigest'='sha256:'||(document->>'genesisHash')
   AND candidate.candidate_document->>'amountMode'=document->>'amountMode'
   AND candidate.candidate_document->>'maxAmountWei'=document->>'maxAmountWei'
   AND candidate.candidate_document->>'validUntil'=document->>'validUntil'
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.native_value_authorization_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.native_value_authorization_id
    AND event.aggregate_type='native-value-authorization' AND event.event_type='openpc.native-value.authorization.issued.v1')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS native_value_issuance ON control.native_value_authorization;
CREATE CONSTRAINT TRIGGER native_value_issuance AFTER INSERT ON control.native_value_authorization
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_native_value_issuance();

-- The reservation's global unique key is the one-use owner. Neither possession
-- of grant bytes nor a caller's used=false can replace this current-state fence.
-- The worker may read these scoped owners, but cannot UPDATE authority rows.
-- Keep provenance reads under its RLS; elevate only the row-lock operation.
DROP POLICY IF EXISTS native_value_locker_scope ON control.wallet_binding;
CREATE POLICY native_value_locker_scope ON control.wallet_binding FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND pg_trigger_depth()>0)
 WITH CHECK(false);
DROP POLICY IF EXISTS native_value_locker_scope ON control.principal;
CREATE POLICY native_value_locker_scope ON control.principal FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)
  AND openpc.current_action_intent_id()='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND pg_trigger_depth()>0)
 WITH CHECK(false);
DROP POLICY IF EXISTS native_value_locker_scope ON control.credential;
CREATE POLICY native_value_locker_scope ON control.credential FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)
  AND openpc.current_action_intent_id()='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND pg_trigger_depth()>0)
 WITH CHECK(false);
CREATE OR REPLACE FUNCTION openpc.lock_native_value_authority(wallet_id uuid,actor_id uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1' OR pg_trigger_depth()=0 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY';
 END IF;
 PERFORM 1 FROM control.wallet_binding wallet
 JOIN control.participant participant USING(participant_id)
 JOIN control.principal principal ON principal.participant_id=wallet.participant_id AND principal.principal_id=actor_id
 WHERE wallet.wallet_binding_id=wallet_id AND wallet.subject_id=actor_id
  AND openpc.matches_participant(wallet.participant_id) AND openpc.matches_privacy(wallet.privacy_domain_id)
 FOR SHARE OF wallet,participant,principal;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY'; END IF;
 PERFORM 1 FROM control.credential credential WHERE openpc.matches_participant(credential.participant_id)
  AND credential.principal_id=actor_id AND credential.kind='WORKLOAD_MTLS' FOR SHARE;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_native_value_authority(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_native_value_authority(uuid,uuid) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.fence_native_value_reservation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE admitted boolean:=false; wallet_id uuid; actor_id uuid;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY';
 END IF;
 IF NEW.native_value_authorization_id IS NULL AND NEW.native_value_authorization_digest IS NULL THEN RETURN NEW; END IF;
 IF TG_OP='UPDATE' AND NEW.state='EXPIRED' THEN RETURN NEW; END IF;
 SELECT wallet_binding_id,actor_principal_id INTO STRICT wallet_id,actor_id FROM control.native_value_authorization
 WHERE native_value_authorization_id=NEW.native_value_authorization_id;
 PERFORM openpc.lock_native_value_authority(wallet_id,actor_id);
 SELECT true INTO admitted FROM control.native_value_authorization issued_grant
 JOIN control.deployment_intent preparation ON preparation.participant_id=issued_grant.participant_id
  AND preparation.privacy_domain_id=issued_grant.privacy_domain_id AND preparation.preparation_digest=NEW.prepared_record_digest
  AND preparation.intent_digest=NEW.intent_digest AND preparation.wallet_binding_id=issued_grant.wallet_binding_id
  AND coalesce(preparation.execution_principal_id,preparation.actor_principal_id)=issued_grant.actor_principal_id
  AND preparation.execution_workload_id IS NOT DISTINCT FROM issued_grant.execution_workload_id
 JOIN control.mutation_candidate submission ON submission.participant_id=issued_grant.participant_id
  AND submission.privacy_domain_id=issued_grant.privacy_domain_id AND submission.resource_id=NEW.attempt_id
  AND submission.consumed_operation_id=NEW.command_id AND submission.maker_principal_id=preparation.actor_principal_id
  AND submission.state='CONSUMED' AND submission.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
  AND submission.action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND submission.candidate_document->>'deploymentIntentId'='urn:openpc:resource:'||preparation.deployment_intent_id::text
 JOIN control.idempotency_record receipt ON receipt.participant_id=submission.participant_id
  AND receipt.privacy_domain_id=submission.privacy_domain_id AND receipt.operation_id=submission.consumed_operation_id
  AND receipt.catalog_operation_id=submission.catalog_operation_id AND receipt.input_digest=submission.candidate_digest
  AND receipt.principal_id=submission.maker_principal_id AND receipt.terminal_state='COMMITTED'
 JOIN control.mutation_evidence evidence ON evidence.participant_id=submission.participant_id
  AND evidence.privacy_domain_id=submission.privacy_domain_id AND evidence.operation_id=submission.consumed_operation_id
  AND evidence.catalog_operation_id=submission.catalog_operation_id AND evidence.candidate_digest=submission.candidate_digest
  AND evidence.aggregate_id=submission.resource_id AND evidence.aggregate_type='deployment-submission'
 CROSS JOIN LATERAL (SELECT convert_from(preparation.preparation_bytes,'UTF8')::jsonb AS prepared,
  convert_from(issued_grant.document_bytes,'UTF8')::jsonb AS document) exact
 JOIN control.wallet_binding wallet ON wallet.participant_id=issued_grant.participant_id
  AND wallet.privacy_domain_id=issued_grant.privacy_domain_id AND wallet.wallet_binding_id=issued_grant.wallet_binding_id
  AND wallet.binding_epoch=issued_grant.wallet_binding_epoch AND wallet.subject_id=issued_grant.actor_principal_id
  AND wallet.state='ACTIVE' AND wallet.chain_id::text=NEW.chain_id AND wallet.wallet_address=NEW.sender_address
 JOIN control.participant participant ON participant.participant_id=issued_grant.participant_id
  AND participant.state='ACTIVE' AND participant.authority_epoch=(exact.document->>'participantEpoch')::numeric
 JOIN control.principal principal ON principal.participant_id=issued_grant.participant_id
  AND principal.principal_id=issued_grant.actor_principal_id AND principal.state='ACTIVE'
 WHERE issued_grant.native_value_authorization_id=NEW.native_value_authorization_id
  AND issued_grant.participant_id=NEW.participant_id AND issued_grant.privacy_domain_id=NEW.privacy_domain_id
  AND issued_grant.semantic_digest=NEW.native_value_authorization_digest
  AND issued_grant.valid_until>clock_timestamp() AND issued_grant.valid_until>=NEW.expires_at
  AND 'urn:openpc:resource:'||preparation.runtime_target_id::text=NEW.target_runtime_id AND preparation.expires_at>=NEW.expires_at
  AND exact.prepared->'context'->>'nativeValueAuthorizationBytes'='0x'||encode(issued_grant.document_bytes,'hex')
  AND exact.prepared->'context'->>'participantEpoch'=exact.document->>'participantEpoch'
  AND exact.prepared->'context'->>'walletBindingEpoch'=issued_grant.wallet_binding_epoch::text
  AND exact.prepared->'context'->>'chainEnvironmentId'=exact.document->>'chainEnvironmentId'
  AND exact.prepared->'intent'->>'nativeValueAuthorizationDigest'=substring(issued_grant.semantic_digest,8)
  AND exact.prepared->'intent'->>'chainId'=NEW.chain_id AND exact.document->>'chainId'=NEW.chain_id
  AND exact.document->>'genesisHash'=substring(NEW.genesis_digest,8)
  AND exact.prepared->'intent'->>'valueWei' ~ '^[1-9][0-9]{0,77}$'
  AND (exact.prepared->'intent'->>'valueWei')::numeric<2::numeric^256
  AND ((exact.document->>'amountMode'='EXACT' AND exact.document->>'maxAmountWei'=exact.prepared->'intent'->>'valueWei')
   OR (exact.document->>'amountMode'='MAXIMUM' AND (exact.prepared->'intent'->>'valueWei')::numeric<=(exact.document->>'maxAmountWei')::numeric))
  AND (issued_grant.execution_workload_id IS NULL OR EXISTS(SELECT 1 FROM control.credential credential
   WHERE credential.participant_id=principal.participant_id AND credential.principal_id=principal.principal_id
    AND principal.kind='WORKLOAD' AND credential.kind='WORKLOAD_MTLS' AND credential.audience=issued_grant.execution_workload_id
    AND credential.state='ACTIVE' AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp()));
 IF admitted IS DISTINCT FROM true THEN RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.fence_native_value_reservation() FROM PUBLIC;
DROP TRIGGER IF EXISTS native_value_reservation_fence ON control.deployment_address_reservation;
CREATE TRIGGER native_value_reservation_fence BEFORE INSERT OR UPDATE OF state ON control.deployment_address_reservation
 FOR EACH ROW EXECUTE FUNCTION openpc.fence_native_value_reservation();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1','cigl-settings','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_SETTINGS_PUBLICATION'),
 ('ACT-CIGL_SETTINGS_READ_RESOURCE-V1','cigl-settings','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_SETTINGS_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1','cigl-settings','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_SETTINGS_PUBLICATION'),
  ('ACT-CIGL_SETTINGS_READ_RESOURCE-V1','cigl-settings','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_SETTINGS_READ')))<>2 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-SETTINGS-ACTION';
 END IF;
END $$;
ALTER TABLE control.cigl_settings FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_settings()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1'
  OR NEW.definition_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.definition),'UTF8')),'hex') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-SETTINGS';
 END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_settings_guard ON control.cigl_settings;
CREATE TRIGGER cigl_settings_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_settings
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_settings();

CREATE OR REPLACE FUNCTION openpc.require_cigl_settings_publication()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.publication_operation_id AND evidence.aggregate_type='cigl-settings'
   AND evidence.aggregate_id=NEW.cigl_settings_id AND evidence.catalog_operation_id='CFG-OP-CREATE-CIGL-SETTINGS'
   AND evidence.action_intent_id='ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1'
   AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.cigl_settings_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND candidate.candidate_document->'definition'=NEW.definition
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.cigl_settings_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.cigl_settings_id
    AND event.aggregate_type='cigl-settings' AND event.event_type='openpc.cigl.settings.staged.v1')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-SETTINGS-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_settings_publication ON control.cigl_settings;
CREATE CONSTRAINT TRIGGER cigl_settings_publication AFTER INSERT ON control.cigl_settings
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_settings_publication();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-CIGL_GRANTS_CREATE_RESOURCE-V1','cigl-grant','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_GRANT_CREATE'),
 ('ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1','cigl-grant','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_GRANT_STATUS'),
 ('ACT-CIGL_GRANTS_READ_RESOURCE-V1','cigl-grant','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_GRANT_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-CIGL_GRANTS_CREATE_RESOURCE-V1','cigl-grant','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_GRANT_CREATE'),
  ('ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1','cigl-grant','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_GRANT_STATUS'),
  ('ACT-CIGL_GRANTS_READ_RESOURCE-V1','cigl-grant','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_GRANT_READ')))<>3 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT-ACTION';
 END IF;
END $$;
ALTER TABLE control.cigl_method_access_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE control.cigl_grant_history FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION openpc.cigl_subject_current(p_participant uuid,p_subject jsonb)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE kind text:=p_subject->>'kind'; id text:=p_subject->>'id';
BEGIN
 IF jsonb_typeof(p_subject) IS DISTINCT FROM 'object' OR (p_subject-ARRAY['kind','id']) IS DISTINCT FROM '{}'::jsonb
  OR jsonb_typeof(p_subject->'kind') IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 IF kind='ANY_AUTHENTICATED' THEN RETURN p_subject='{"kind":"ANY_AUTHENTICATED"}'::jsonb; END IF;
 IF jsonb_typeof(p_subject->'id') IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 IF kind IN ('ROLE','WORKLOAD') THEN
  IF (id ~ ('^urn:openpc:'||lower(kind)||':[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')) IS DISTINCT FROM true THEN RETURN false; END IF;
 ELSIF (id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') IS DISTINCT FROM true THEN RETURN false; END IF;
 CASE kind
 WHEN 'ANY_AUTHENTICATED' THEN RETURN p_subject='{"kind":"ANY_AUTHENTICATED"}'::jsonb;
 WHEN 'ROLE' THEN RETURN EXISTS(SELECT 1 FROM control.authority_role WHERE participant_id=p_participant AND role_id=id AND state='ACTIVE');
 WHEN 'WORKLOAD' THEN RETURN EXISTS(SELECT 1 FROM control.credential credential
  JOIN control.principal principal ON principal.participant_id=credential.participant_id AND principal.principal_id=credential.principal_id
  WHERE credential.participant_id=p_participant AND credential.audience=id AND credential.kind IN ('WORKLOAD_MTLS','WORKLOAD_OIDC')
   AND credential.state='ACTIVE' AND credential.valid_from<=clock_timestamp()
   AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp()) AND principal.kind='WORKLOAD' AND principal.state='ACTIVE');
 WHEN 'USER' THEN RETURN EXISTS(SELECT 1 FROM control.principal principal WHERE principal.participant_id=p_participant AND principal.principal_id=id::uuid AND principal.kind='USER' AND principal.state='ACTIVE');
 WHEN 'GROUP' THEN RETURN EXISTS(SELECT 1 FROM control.authority_group WHERE participant_id=p_participant AND authority_group_id=id::uuid AND state='ACTIVE');
 WHEN 'PARTICIPANT' THEN RETURN id=p_participant::text AND EXISTS(SELECT 1 FROM control.participant WHERE participant_id=p_participant AND state='ACTIVE' AND archived_at IS NULL);
 ELSE RETURN false;
 END CASE;
END $$;
REVOKE ALL ON FUNCTION openpc.cigl_subject_current(uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.cigl_subject_current(uuid,jsonb) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

-- Serialize a complete snapshot with all grant mutations, including inserts.
-- This scope-specific fence needs no grant-table write privilege at Fleet.
CREATE OR REPLACE FUNCTION openpc.lock_cigl_grant_sources()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 PERFORM pg_advisory_xact_lock(hashtextextended('openpc:cigl-grants:'||
  current_setting('openpc.participant_id')||':'||current_setting('openpc.privacy_domain_id'),0));
END $$;
REVOKE ALL ON FUNCTION openpc.lock_cigl_grant_sources() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_cigl_grant_sources() TO openpc_control_runtime,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_grant()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE canonical jsonb; bytes bytea;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT';
 END IF;
 PERFORM openpc.lock_cigl_grant_sources();
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR NOT (
   (NEW.origin='SHARED' AND current_setting('openpc.action_intent_id')='ACT-CIGL_GRANTS_CREATE_RESOURCE-V1' AND NEW.status='DISABLED')
   OR (NEW.origin='GENERATED' AND current_setting('openpc.action_intent_id')='ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1' AND NEW.status='ACTIVE'
     AND NEW.definition->>'effect'='ALLOW' AND EXISTS(SELECT 1 FROM control.cigl_method_access_grants source WHERE source.grant_id=NEW.generated_by_grant_id
      AND source.participant_id=NEW.participant_id AND source.privacy_domain_id=NEW.privacy_domain_id AND source.origin='SHARED'
      AND source.status='ACTIVE' AND source.publication_operation_id=NEW.publication_operation_id))) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT-CREATE'; END IF;
  NEW.created_at:=clock_timestamp();
 ELSE
  IF current_setting('openpc.action_intent_id')<>'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1'
   OR NEW.revision<>OLD.revision+1 OR (NEW.status=OLD.status AND NEW.status<>'ACTIVE')
   OR (OLD.origin='GENERATED' AND (OLD.status<>'ACTIVE' OR NEW.status<>'DISABLED'
     OR EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims WHERE required_grant_id=OLD.grant_id AND state='ACTIVE')
     OR NOT EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims WHERE required_grant_id=OLD.grant_id AND released_operation_id=NEW.publication_operation_id)))
   OR ROW(NEW.grant_id,NEW.participant_id,NEW.privacy_domain_id,NEW.runtime_binding_id,NEW.selector,NEW.definition,
      NEW.binding_revision,NEW.method_revision,NEW.created_at,NEW.origin,NEW.generated_by_grant_id)
    IS DISTINCT FROM ROW(OLD.grant_id,OLD.participant_id,OLD.privacy_domain_id,OLD.runtime_binding_id,OLD.selector,OLD.definition,
      OLD.binding_revision,OLD.method_revision,OLD.created_at,OLD.origin,OLD.generated_by_grant_id) THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-IMMUTABLE'; END IF;
 END IF;
 IF NEW.definition->>'runtimeBindingId' IS DISTINCT FROM 'urn:openpc:resource:'||NEW.runtime_binding_id::text
  OR NEW.definition->>'selector' IS DISTINCT FROM NEW.selector OR (NEW.definition->>'effect' IN ('ALLOW','DENY')) IS DISTINCT FROM true
  OR (NEW.definition->>'surface' IN ('ETH_CALL','ETH_ESTIMATE_GAS','PREPARE_WRITE','RAW_SUBMISSION','DEPLOYMENT_CONSTRUCTOR','RUNTIME_WRITE_TRACE')) IS DISTINCT FROM true
  OR (NEW.definition-ARRAY['runtimeBindingId','selector','subject','surface','effect']) IS DISTINCT FROM '{}'::jsonb
  OR NOT (NEW.definition ?& ARRAY['runtimeBindingId','selector','subject','surface','effect']) THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-DEFINITION'; END IF;
 IF TG_OP='INSERT' OR NEW.status='ACTIVE' THEN
  IF openpc.cigl_subject_current(NEW.participant_id,NEW.definition->'subject') IS DISTINCT FROM true
   OR NOT EXISTS(SELECT 1 FROM control.contract_runtime_binding binding JOIN control.contract_method_policy method
    ON method.participant_id=binding.participant_id AND method.privacy_domain_id=binding.privacy_domain_id AND method.runtime_binding_id=binding.runtime_binding_id
    WHERE binding.participant_id=NEW.participant_id AND binding.privacy_domain_id=NEW.privacy_domain_id
     AND binding.runtime_binding_id=NEW.runtime_binding_id AND binding.state='BOUND' AND binding.revision=NEW.binding_revision
     AND method.selector=NEW.selector AND method.revision=NEW.method_revision AND method.state IN ('PREPARED','ACTIVE')) THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-GRANT-REFERENCE'; END IF;
 END IF;
 bytes:=decode(substr(NEW.selector,3),'hex');
 canonical:=jsonb_build_object('grantId',NEW.grant_id::text,'runtimeBindingId',NEW.runtime_binding_id::text,
  'selector',jsonb_build_array(get_byte(bytes,0),get_byte(bytes,1),get_byte(bytes,2),get_byte(bytes,3)),
  'subject',NEW.definition->'subject','surface',NEW.definition->>'surface','effect',NEW.definition->>'effect','status',NEW.status);
 IF NEW.grant_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(canonical),'UTF8')),'hex') THEN
  RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-DIGEST'; END IF;
 NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_grant_guard ON control.cigl_method_access_grants;
CREATE TRIGGER cigl_grant_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_method_access_grants
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_grant();

CREATE OR REPLACE FUNCTION openpc.record_cigl_grant_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 INSERT INTO control.cigl_grant_history(grant_id,participant_id,privacy_domain_id,revision,status,grant_digest,
  publication_operation_id,publication_authority_digest) VALUES(NEW.grant_id,NEW.participant_id,NEW.privacy_domain_id,NEW.revision,NEW.status,
  NEW.grant_digest,NEW.publication_operation_id,NEW.publication_authority_digest);
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_grant_history_record ON control.cigl_method_access_grants;
CREATE TRIGGER cigl_grant_history_record AFTER INSERT OR UPDATE ON control.cigl_method_access_grants
 FOR EACH ROW EXECUTE FUNCTION openpc.record_cigl_grant_history();
CREATE OR REPLACE FUNCTION openpc.guard_cigl_grant_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-GRANT-HISTORY'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants grant_row WHERE
  ROW(grant_row.grant_id,grant_row.participant_id,grant_row.privacy_domain_id,grant_row.revision,grant_row.status,grant_row.grant_digest,
   grant_row.publication_operation_id,grant_row.publication_authority_digest)
  =ROW(NEW.grant_id,NEW.participant_id,NEW.privacy_domain_id,NEW.revision,NEW.status,NEW.grant_digest,
   NEW.publication_operation_id,NEW.publication_authority_digest)) THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT-HISTORY'; END IF;
 NEW.occurred_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_grant_history_guard ON control.cigl_grant_history;
CREATE TRIGGER cigl_grant_history_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_grant_history
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_grant_history();

CREATE OR REPLACE FUNCTION openpc.require_cigl_grant_publication()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE operation text:=CASE WHEN NEW.revision=1 THEN 'CFG-OP-CREATE-CIGL-GRANT' ELSE 'CFG-OP-UPDATE-CIGL-GRANT' END;
BEGIN
 IF NEW.origin='GENERATED' THEN RETURN NULL; END IF; -- Exact derived ownership is checked by require_generated_cigl_grant.
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id AND receipt.privacy_domain_id=evidence.privacy_domain_id
   AND receipt.operation_id=evidence.operation_id AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id AND candidate.privacy_domain_id=evidence.privacy_domain_id
   AND candidate.consumed_operation_id=evidence.operation_id AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id AND evidence.operation_id=NEW.publication_operation_id
   AND evidence.aggregate_type='cigl-grant' AND evidence.aggregate_id=NEW.grant_id AND evidence.catalog_operation_id=operation
   AND evidence.aggregate_version=NEW.revision
   AND evidence.action_intent_id=CASE WHEN NEW.revision=1 THEN 'ACT-CIGL_GRANTS_CREATE_RESOURCE-V1' ELSE 'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1' END
   AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.grant_id AND candidate.state='CONSUMED' AND candidate.expected_revision=NEW.revision-1
   AND candidate.action_intent_id=evidence.action_intent_id AND receipt.action_intent_id=evidence.action_intent_id
   AND receipt.expected_aggregate_version=candidate.expected_revision
   AND ((NEW.revision=1 AND candidate.candidate_document->'definition'=NEW.definition
     AND candidate.candidate_document->>'expectedRuntimeBindingRevision'=NEW.binding_revision::text
     AND candidate.candidate_document->>'expectedMethodRevision'=NEW.method_revision::text)
    OR (NEW.revision>1 AND candidate.candidate_document->>'status'=NEW.status
      AND candidate.candidate_document->>'targetRef'='urn:openpc:resource:'||NEW.grant_id::text))
   AND receipt.terminal_state='COMMITTED' AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.grant_id::text
   AND receipt.result_payload->>'revision'=NEW.revision::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id AND event.privacy_domain_id=NEW.privacy_domain_id
     AND event.aggregate_id=NEW.grant_id AND event.aggregate_type='cigl-grant' AND event.aggregate_sequence=NEW.revision
     AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'=NEW.publication_authority_digest
     AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(candidate.candidate_digest,'hex')
     AND event.event_type=CASE WHEN NEW.revision=1 THEN 'openpc.cigl.grant.created.v1' ELSE 'openpc.cigl.grant.status.v1' END)) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GRANT-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_grant_publication ON control.cigl_method_access_grants;
CREATE CONSTRAINT TRIGGER cigl_grant_publication AFTER INSERT OR UPDATE ON control.cigl_method_access_grants
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_grant_publication();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1','cigl-analysis','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_CREATE'),
 ('ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1','cigl-analysis','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_OBSERVE'),
 ('ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1','cigl-analysis','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_REVIEW'),
 ('ACT-CIGL_ANALYSES_READ_RESOURCE-V1','cigl-analysis','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_ANALYSIS_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1','cigl-analysis','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_CREATE'),
  ('ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1','cigl-analysis','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_OBSERVE'),
  ('ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1','cigl-analysis','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_ANALYSIS_REVIEW'),
  ('ACT-CIGL_ANALYSES_READ_RESOURCE-V1','cigl-analysis','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_ANALYSIS_READ')))<>4 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ANALYSIS-ACTION'; END IF;
END $$;
ALTER TABLE control.cigl_analysis FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_analysis()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE capsule text; policy text;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ANALYSIS'; END IF;
 IF TG_OP='INSERT' THEN
  IF current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1'
   OR NEW.creation_operation_id<>NEW.publication_operation_id OR NEW.state<>'OPEN' OR NEW.revision<>1 THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ANALYSIS-CREATE'; END IF;
  IF jsonb_typeof(NEW.definition) IS DISTINCT FROM 'object'
   OR EXISTS(SELECT 1 FROM jsonb_each(NEW.definition) field WHERE field.key<>'expiresInSeconds' AND jsonb_typeof(field.value)<>'string')
   OR (NEW.definition-ARRAY['targetRuntimeId','expectedGenerationDigest','runtimeBindingId','contractMethodPolicyId',
     'expectedRuntimeBindingRevision','expectedMethodRevision','workloadId','transactionHash','expiresInSeconds']) IS DISTINCT FROM '{}'::jsonb
   OR NOT NEW.definition ?& ARRAY['targetRuntimeId','expectedGenerationDigest','runtimeBindingId','contractMethodPolicyId',
     'expectedRuntimeBindingRevision','expectedMethodRevision','workloadId','transactionHash','expiresInSeconds']
   OR NEW.definition->>'targetRuntimeId' IS DISTINCT FROM 'urn:openpc:resource:'||NEW.runtime_target_id::text
   OR NEW.definition->>'runtimeBindingId' IS DISTINCT FROM 'urn:openpc:resource:'||NEW.runtime_binding_id::text
   OR NEW.definition->>'contractMethodPolicyId' IS DISTINCT FROM 'urn:openpc:resource:'||NEW.contract_method_policy_id::text
   OR (NEW.definition->>'transactionHash' ~ '^0x[0-9a-f]{64}$') IS DISTINCT FROM true
   OR (NEW.definition->>'expectedGenerationDigest' ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true
   OR (NEW.definition->>'expectedRuntimeBindingRevision' ~ '^[1-9][0-9]{0,19}$') IS DISTINCT FROM true
   OR (NEW.definition->>'expectedMethodRevision' ~ '^[1-9][0-9]{0,19}$') IS DISTINCT FROM true
   OR jsonb_typeof(NEW.definition->'expiresInSeconds') IS DISTINCT FROM 'number'
   OR (NEW.definition->>'expiresInSeconds' ~ '^[0-9]+$') IS DISTINCT FROM true
   OR (NEW.definition->>'expiresInSeconds')::numeric NOT BETWEEN 30 AND 900 THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-DEFINITION'; END IF;
  NEW.created_at:=date_trunc('milliseconds',clock_timestamp());
  NEW.expires_at:=NEW.created_at+make_interval(secs=>(NEW.definition->>'expiresInSeconds')::integer);
 ELSE
  IF clock_timestamp()>=OLD.expires_at
   OR ROW(NEW.analysis_id,NEW.participant_id,NEW.privacy_domain_id,NEW.runtime_target_id,NEW.runtime_binding_id,
     NEW.contract_method_policy_id,NEW.definition,NEW.capsule_digest,NEW.policy_generation_digest,NEW.creation_operation_id,NEW.created_at,NEW.expires_at)
   IS DISTINCT FROM ROW(OLD.analysis_id,OLD.participant_id,OLD.privacy_domain_id,OLD.runtime_target_id,OLD.runtime_binding_id,
     OLD.contract_method_policy_id,OLD.definition,OLD.capsule_digest,OLD.policy_generation_digest,OLD.creation_operation_id,OLD.created_at,OLD.expires_at)
   OR NEW.receipt_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.signed_receipt),'hex') THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-IMMUTABLE'; END IF;
  IF OLD.state='OPEN' AND OLD.revision=1 THEN
   IF current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1' OR NEW.state<>'OBSERVED' OR NEW.revision<>2 THEN
    RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-IMMUTABLE'; END IF;
  ELSIF OLD.state='OBSERVED' AND OLD.revision=2 THEN
   IF current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1' OR NEW.state<>'REVIEWED' OR NEW.revision<>3
    OR ROW(NEW.signed_receipt,NEW.receipt_digest,NEW.analysis_digest) IS DISTINCT FROM ROW(OLD.signed_receipt,OLD.receipt_digest,OLD.analysis_digest)
    OR NEW.review_definition->>'analysisDigest' IS DISTINCT FROM NEW.analysis_digest
    OR NEW.review_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.review_definition),'UTF8')),'hex') THEN
    RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-IMMUTABLE'; END IF;
  ELSE RAISE EXCEPTION 'PC-DATA-6004-CIGL-ANALYSIS-IMMUTABLE'; END IF;
 END IF;
 -- Share-lock the actual source owners through the mutation. A supplied digest
 -- cannot manufacture a current activation, method or workload credential.
 SELECT observation.capsule_digest,target.policy_generation_digest INTO STRICT capsule,policy
 FROM control.runtime_target target JOIN control.runtime_activation_observation observation
  ON observation.participant_id=target.participant_id AND observation.privacy_domain_id=target.privacy_domain_id
   AND observation.runtime_target_id=target.runtime_target_id AND observation.capsule_digest=target.active_generation_digest
 JOIN control.contract_runtime_binding binding ON binding.participant_id=target.participant_id
  AND binding.privacy_domain_id=target.privacy_domain_id AND binding.runtime_binding_id=NEW.runtime_binding_id
 JOIN control.contract_method_policy method ON method.participant_id=binding.participant_id AND method.privacy_domain_id=binding.privacy_domain_id
  AND method.runtime_binding_id=binding.runtime_binding_id AND method.contract_method_policy_id=NEW.contract_method_policy_id
 WHERE target.runtime_target_id=NEW.runtime_target_id AND target.participant_id=NEW.participant_id AND target.privacy_domain_id=NEW.privacy_domain_id
  AND target.state='ACTIVE_MATCHED' AND target.active_generation_digest=target.desired_generation_digest
  AND target.active_generation_digest=NEW.definition->>'expectedGenerationDigest'
  AND binding.state='BOUND' AND binding.revision::text=NEW.definition->>'expectedRuntimeBindingRevision'
  AND method.state IN ('PREPARED','ACTIVE') AND method.revision::text=NEW.definition->>'expectedMethodRevision'
  AND openpc.cigl_subject_current(NEW.participant_id,jsonb_build_object('kind','WORKLOAD','id',NEW.definition->>'workloadId'))
 FOR SHARE OF target,binding,method;
 IF TG_OP='INSERT' THEN NEW.capsule_digest:=capsule; NEW.policy_generation_digest:=policy;
 ELSIF NEW.capsule_digest<>capsule OR NEW.policy_generation_digest<>policy THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-ANALYSIS-REFERENCE'; END IF;
 RETURN NEW;
 EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-ANALYSIS-REFERENCE';
END $$;
DROP TRIGGER IF EXISTS cigl_analysis_guard ON control.cigl_analysis;
CREATE TRIGGER cigl_analysis_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_analysis
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_analysis();

CREATE OR REPLACE FUNCTION openpc.require_cigl_analysis_publication()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE operation text:=CASE NEW.revision WHEN 1 THEN 'CFG-OP-CREATE-CIGL-ANALYSIS' WHEN 2 THEN 'CFG-OP-UPDATE-CIGL-ANALYSIS' ELSE 'CFG-OP-REVIEW-CIGL-ANALYSIS' END;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id AND receipt.privacy_domain_id=evidence.privacy_domain_id
   AND receipt.operation_id=evidence.operation_id AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id AND candidate.privacy_domain_id=evidence.privacy_domain_id
   AND candidate.consumed_operation_id=evidence.operation_id AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id AND evidence.operation_id=NEW.publication_operation_id
   AND evidence.aggregate_type='cigl-analysis' AND evidence.aggregate_id=NEW.analysis_id AND evidence.catalog_operation_id=operation
   AND evidence.action_intent_id=CASE NEW.revision WHEN 1 THEN 'ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1' WHEN 2 THEN 'ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1' ELSE 'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1' END
   AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.analysis_id AND candidate.state='CONSUMED' AND candidate.expected_revision=NEW.revision-1
   AND ((NEW.revision=1 AND candidate.candidate_document->'definition'=NEW.definition)
    OR (NEW.revision=2 AND candidate.candidate_document->>'targetRef'='urn:openpc:resource:'||NEW.analysis_id::text
      AND candidate.candidate_document->>'expectedRevision'='1'
      AND candidate.candidate_document->>'signedReceipt'='0x'||encode(NEW.signed_receipt,'hex'))
    OR (NEW.revision=3 AND candidate.candidate_document->>'targetRef'='urn:openpc:resource:'||NEW.analysis_id::text
      AND candidate.candidate_document->>'expectedRevision'='2' AND candidate.candidate_document->'review'=NEW.review_definition))
   AND receipt.terminal_state='COMMITTED' AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.analysis_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id AND event.privacy_domain_id=NEW.privacy_domain_id
    AND event.aggregate_id=NEW.analysis_id AND event.aggregate_type='cigl-analysis' AND event.aggregate_sequence=NEW.revision
    AND event.event_type=CASE NEW.revision WHEN 1 THEN 'openpc.cigl.analysis.created.v1' WHEN 2 THEN 'openpc.cigl.analysis.observed.v1' ELSE 'openpc.cigl.analysis.reviewed.v1' END)) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ANALYSIS-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_analysis_publication ON control.cigl_analysis;
CREATE CONSTRAINT TRIGGER cigl_analysis_publication AFTER INSERT OR UPDATE ON control.cigl_analysis
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_analysis_publication();


-- Fleet needs an authority-root read fence, not Participant mutation rights.
-- Lock it before the scoped grant fence to preserve the shared authority order.
-- The definer remains subject to FORCE RLS. Permit its scoped read/lock only;
-- WITH CHECK(false) continues to prohibit Participant writes through this owner.
DROP POLICY IF EXISTS cigl_publication_participant_fence ON control.participant;
CREATE POLICY cigl_publication_participant_fence ON control.participant FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id() IN
  ('ACT-CIGL_ANALYSES_READ_RESOURCE-V1','ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1','ACT-RUNTIME_READ_RPC-V1'))
 WITH CHECK(false);
CREATE OR REPLACE FUNCTION openpc.lock_cigl_publication_participant()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF openpc.current_action_intent_id() NOT IN ('ACT-CIGL_ANALYSES_READ_RESOURCE-V1','ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1','ACT-RUNTIME_READ_RPC-V1')
  THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-PUBLICATION-PARTICIPANT'; END IF;
 PERFORM 1 FROM control.participant
  WHERE participant_id=current_setting('openpc.participant_id')::uuid
   AND state='ACTIVE' AND archived_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-PUBLICATION-PARTICIPANT'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_cigl_publication_participant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_cigl_publication_participant() TO openpc_control_runtime,openpc_control_worker;

-- Invalidation must also fence an archived/inactive authority root. It never
-- confers publication rights and is limited to the existing scoped read action.
CREATE OR REPLACE FUNCTION openpc.lock_cigl_invalidation_participant()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF openpc.current_action_intent_id()<>'ACT-CIGL_ANALYSES_READ_RESOURCE-V1'
  THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-INVALIDATION-PARTICIPANT'; END IF;
 PERFORM 1 FROM control.participant
  WHERE participant_id=current_setting('openpc.participant_id')::uuid FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-CIGL-INVALIDATION-PARTICIPANT'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_cigl_invalidation_participant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_cigl_invalidation_participant() TO openpc_control_worker;

ALTER TABLE control.cigl_method_profile FORCE ROW LEVEL SECURITY;
ALTER TABLE control.cigl_profile_version FORCE ROW LEVEL SECURITY;
ALTER TABLE control.cigl_profile_grant_source FORCE ROW LEVEL SECURITY;
ALTER TABLE control.cigl_profile_method_source FORCE ROW LEVEL SECURITY;
ALTER TABLE control.cigl_profile_dependency_path FORCE ROW LEVEL SECURITY;
GRANT EXECUTE ON FUNCTION openpc.signing_canonical_json(jsonb) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_profile_owner()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1'
  OR NOT EXISTS(SELECT 1 FROM control.cigl_analysis analysis WHERE analysis.participant_id=NEW.participant_id
    AND analysis.privacy_domain_id=NEW.privacy_domain_id AND analysis.contract_method_policy_id=NEW.root_contract_method_policy_id
    AND analysis.state='REVIEWED' AND analysis.revision=3 AND analysis.publication_operation_id=current_setting('openpc.operation_id')::uuid) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-OWNER'; END IF;
 NEW.created_at:=date_trunc('milliseconds',clock_timestamp()); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_owner_guard ON control.cigl_method_profile;
CREATE TRIGGER cigl_profile_owner_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_method_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_owner();

CREATE OR REPLACE FUNCTION openpc.guard_cigl_profile_version()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE claims jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-SCOPE'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PENDING' OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1'
   OR NOT EXISTS(SELECT 1 FROM control.cigl_analysis analysis JOIN control.cigl_method_profile profile
     ON profile.participant_id=analysis.participant_id AND profile.privacy_domain_id=analysis.privacy_domain_id
      AND profile.root_contract_method_policy_id=analysis.contract_method_policy_id
     JOIN control.configuration_work work ON work.configuration_work_id=NEW.configuration_work_id
      AND work.participant_id=analysis.participant_id AND work.privacy_domain_id=analysis.privacy_domain_id
      AND work.resource_id=analysis.analysis_id AND work.operation_id=analysis.publication_operation_id
      AND work.work_kind='CIGL_PROFILE_COMPILATION' AND work.state='PENDING'
     WHERE analysis.analysis_id=NEW.analysis_id AND analysis.participant_id=NEW.participant_id
      AND analysis.privacy_domain_id=NEW.privacy_domain_id AND profile.profile_id=NEW.profile_id
      AND analysis.state='REVIEWED' AND analysis.revision=3 AND analysis.review_digest=NEW.review_digest
      AND analysis.publication_operation_id=current_setting('openpc.operation_id')::uuid)
   OR NEW.revision<>(SELECT coalesce(max(revision),0)+1 FROM control.cigl_profile_version WHERE profile_id=NEW.profile_id) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-REVIEW'; END IF;
  NEW.created_at:=date_trunc('milliseconds',clock_timestamp());
 ELSE
  IF NOT pg_has_role(current_user,'openpc_control_worker','MEMBER') OR OLD.state<>'PENDING' OR NEW.state<>'COMPILED'
   OR (to_jsonb(NEW)-ARRAY['state','profile_cbor','profile_digest','artifact_digest','compilation_receipt','compilation_signer_id','compiled_at','dependency_paths_digest'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','profile_cbor','profile_digest','artifact_digest','compilation_receipt','compilation_signer_id','compiled_at','dependency_paths_digest'])
   OR NEW.artifact_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.profile_cbor),'hex') THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-IMMUTABLE'; END IF;
  claims:=convert_from(NEW.compilation_receipt,'UTF8')::jsonb;
  IF claims->>'purpose' IS DISTINCT FROM 'openpc:cigl-profile-compilation:v1' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-RECEIPT'; END IF;
  claims:=claims->'claims';
  IF claims->>'schemaVersion' IS DISTINCT FROM '1.0' OR claims->>'profileId' IS DISTINCT FROM NEW.profile_id::text
   OR claims->>'profileRevision' IS DISTINCT FROM NEW.revision::text OR claims->>'analysisId' IS DISTINCT FROM NEW.analysis_id::text
   OR claims->>'configurationWorkId' IS DISTINCT FROM NEW.configuration_work_id::text
   OR claims->>'participantId' IS DISTINCT FROM NEW.participant_id::text OR claims->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
   OR claims->>'reviewDigest' IS DISTINCT FROM substr(NEW.review_digest,8) OR claims->>'artifactDigest' IS DISTINCT FROM substr(NEW.artifact_digest,8)
   OR claims->>'profileDigest' IS DISTINCT FROM substr(NEW.profile_digest,8) OR claims->>'signerId' IS DISTINCT FROM NEW.compilation_signer_id
   OR NEW.dependency_paths_digest IS NULL
   OR claims->>'dependencyPathsDigest' IS DISTINCT FROM substr(NEW.dependency_paths_digest,8)
   OR NEW.dependency_paths_digest IS DISTINCT FROM (SELECT 'sha256:'||encode(sha256(convert_to(
     openpc.signing_canonical_json(coalesce(jsonb_agg(path.document ORDER BY path.ordinal),'[]'::jsonb)),'UTF8')),'hex')
     FROM control.cigl_profile_dependency_path path WHERE path.profile_id=NEW.profile_id AND path.profile_revision=NEW.revision)
   OR claims->>'compiledAtMs' IS DISTINCT FROM floor(extract(epoch from NEW.compiled_at)*1000)::text
   OR NEW.compiled_at<NEW.created_at OR NEW.compiled_at>clock_timestamp()
   OR NOT EXISTS(SELECT 1 FROM control.configuration_work work JOIN control.cigl_analysis analysis ON analysis.analysis_id=NEW.analysis_id
      AND analysis.participant_id=work.participant_id AND analysis.privacy_domain_id=work.privacy_domain_id
     WHERE work.configuration_work_id=NEW.configuration_work_id AND work.state='LEASED' AND work.lease_owner=NEW.compilation_signer_id
      AND work.lease_until>clock_timestamp() AND analysis.expires_at>clock_timestamp()
      AND claims->>'operationId'=work.operation_id::text AND claims->>'targetRuntimeId'=analysis.runtime_target_id::text
      AND claims->>'capsuleDigest'=substr(analysis.capsule_digest,8) AND claims->>'analysisDigest'=substr(analysis.analysis_digest,8)
      AND claims->>'policyGenerationDigest'=substr(analysis.policy_generation_digest,8)) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-RECEIPT'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_version_guard ON control.cigl_profile_version;
CREATE TRIGGER cigl_profile_version_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_profile_version
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_version();

CREATE OR REPLACE FUNCTION openpc.guard_cigl_profile_source()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','MEMBER')
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NOT EXISTS(SELECT 1 FROM control.cigl_profile_version version JOIN control.configuration_work work
    ON work.configuration_work_id=version.configuration_work_id AND work.participant_id=version.participant_id AND work.privacy_domain_id=version.privacy_domain_id
    WHERE version.profile_id=NEW.profile_id AND version.revision=NEW.profile_revision AND version.participant_id=NEW.participant_id
     AND version.privacy_domain_id=NEW.privacy_domain_id AND version.state='PENDING' AND work.state='LEASED' AND work.lease_until>clock_timestamp()) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-SOURCE'; END IF;
 IF TG_TABLE_NAME='cigl_profile_grant_source' THEN
  IF NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants grant_row WHERE grant_row.grant_id=NEW.grant_id
   AND grant_row.participant_id=NEW.participant_id AND grant_row.privacy_domain_id=NEW.privacy_domain_id
   AND grant_row.revision=NEW.grant_revision AND grant_row.grant_digest=NEW.grant_digest) THEN RAISE EXCEPTION 'PC-DATA-6007-CIGL-PROFILE-GRANT'; END IF;
 ELSIF TG_TABLE_NAME='cigl_profile_method_source' THEN
  IF NOT EXISTS(SELECT 1 FROM control.contract_method_policy method JOIN control.contract_runtime_binding binding
   ON binding.runtime_binding_id=method.runtime_binding_id AND binding.participant_id=method.participant_id AND binding.privacy_domain_id=method.privacy_domain_id
   WHERE method.contract_method_policy_id=NEW.contract_method_policy_id AND method.participant_id=NEW.participant_id
    AND method.privacy_domain_id=NEW.privacy_domain_id AND binding.runtime_binding_id=NEW.runtime_binding_id
    AND method.revision=NEW.method_revision AND binding.revision=NEW.binding_revision) THEN RAISE EXCEPTION 'PC-DATA-6007-CIGL-PROFILE-METHOD'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM control.cigl_profile_method_source method WHERE method.profile_id=NEW.profile_id
    AND method.profile_revision=NEW.profile_revision AND method.contract_method_policy_id::text=NEW.document->>'contractMethodPolicyId'
    AND method.runtime_binding_id::text=NEW.document->>'runtimeBindingId') THEN RAISE EXCEPTION 'PC-DATA-6007-CIGL-PROFILE-PATH'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_grant_source_guard ON control.cigl_profile_grant_source;
CREATE TRIGGER cigl_profile_grant_source_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_profile_grant_source
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_source();
DROP TRIGGER IF EXISTS cigl_profile_method_source_guard ON control.cigl_profile_method_source;
CREATE TRIGGER cigl_profile_method_source_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_profile_method_source
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_source();
DROP TRIGGER IF EXISTS cigl_profile_path_guard ON control.cigl_profile_dependency_path;
CREATE TRIGGER cigl_profile_path_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_profile_dependency_path
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_source();

CREATE OR REPLACE FUNCTION openpc.guard_cigl_profile_work()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.work_kind='CIGL_PROFILE_COMPILATION' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-HISTORY'; END IF;
  RETURN OLD;
 END IF;
 IF NEW.work_kind<>'CIGL_PROFILE_COMPILATION' THEN
  IF TG_OP='UPDATE' AND OLD.work_kind='CIGL_PROFILE_COMPILATION' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-WORK'; END IF;
  RETURN NEW;
 END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.execution_started_at IS NOT NULL OR NEW.execution_attempt_id IS NOT NULL OR NEW.state='RECONCILING' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-WORK'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PENDING' OR NEW.attempt_count<>0 OR NEW.operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1' THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-WORK'; END IF;
 ELSE
  IF NOT pg_has_role(current_user,'openpc_control_worker','MEMBER') OR OLD.state IN ('COMPLETED','FAILED')
   OR ROW(NEW.configuration_work_id,NEW.participant_id,NEW.privacy_domain_id,NEW.operation_id,NEW.work_kind,NEW.resource_id,
     NEW.input_digest,NEW.configuration_digest,NEW.runtime_configuration_generation_id,NEW.runtime_target_id,NEW.generation_digest,NEW.predecessor_digest,
     NEW.policy_generation_digest,NEW.xds_version_digest,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.configuration_work_id,OLD.participant_id,OLD.privacy_domain_id,OLD.operation_id,OLD.work_kind,OLD.resource_id,
     OLD.input_digest,OLD.configuration_digest,OLD.runtime_configuration_generation_id,OLD.runtime_target_id,OLD.generation_digest,OLD.predecessor_digest,
     OLD.policy_generation_digest,OLD.xds_version_digest,OLD.created_at)
   OR (NEW.state='LEASED' AND NOT ((OLD.state='PENDING' OR (OLD.state='LEASED' AND OLD.lease_until<=clock_timestamp())) AND NEW.attempt_count=OLD.attempt_count+1))
   OR (NEW.state<>'LEASED' AND (OLD.state<>'LEASED' OR OLD.lease_until<=clock_timestamp() OR NEW.attempt_count<>OLD.attempt_count))
   OR (NEW.state IN ('COMPLETED','FAILED') AND NEW.result_receipt_digest IS DISTINCT FROM
     'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.result_receipt),'UTF8')),'hex')) THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-PROFILE-WORK'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_work_guard ON control.configuration_work;
CREATE TRIGGER cigl_profile_work_guard BEFORE INSERT OR UPDATE OR DELETE ON control.configuration_work
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_profile_work();

CREATE OR REPLACE FUNCTION openpc.require_cigl_profile_work()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.work_kind<>'CIGL_PROFILE_COMPILATION' THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.cigl_analysis analysis JOIN control.cigl_profile_version version
   ON version.analysis_id=analysis.analysis_id AND version.participant_id=analysis.participant_id AND version.privacy_domain_id=analysis.privacy_domain_id
   JOIN control.mutation_evidence evidence ON evidence.operation_id=analysis.publication_operation_id
    AND evidence.participant_id=analysis.participant_id AND evidence.privacy_domain_id=analysis.privacy_domain_id
   JOIN control.mutation_candidate candidate ON candidate.consumed_operation_id=evidence.operation_id
    AND candidate.participant_id=evidence.participant_id AND candidate.privacy_domain_id=evidence.privacy_domain_id
    AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
   WHERE analysis.analysis_id=NEW.resource_id AND analysis.participant_id=NEW.participant_id AND analysis.privacy_domain_id=NEW.privacy_domain_id
    AND analysis.state='REVIEWED' AND analysis.revision=3 AND analysis.publication_operation_id=NEW.operation_id
    AND evidence.catalog_operation_id='CFG-OP-REVIEW-CIGL-ANALYSIS' AND candidate.resource_id=analysis.analysis_id
    AND candidate.state='CONSUMED' AND candidate.expected_revision=2 AND candidate.candidate_document->'review'=analysis.review_definition
    AND NEW.input_digest='sha256:'||encode(candidate.candidate_digest,'hex') AND version.configuration_work_id=NEW.configuration_work_id
    AND version.review_digest=analysis.review_digest AND NEW.runtime_target_id=analysis.runtime_target_id
    AND NEW.generation_digest=analysis.definition->>'expectedGenerationDigest' AND NEW.policy_generation_digest=analysis.policy_generation_digest
    AND EXISTS(SELECT 1 FROM control.runtime_activation_observation observation JOIN control.configuration_work prior
      ON prior.configuration_work_id=observation.configuration_work_id WHERE observation.participant_id=analysis.participant_id
      AND observation.privacy_domain_id=analysis.privacy_domain_id AND observation.runtime_target_id=analysis.runtime_target_id
      AND observation.capsule_digest=analysis.capsule_digest AND observation.capsule_digest=NEW.generation_digest
      AND prior.participant_id=observation.participant_id AND prior.privacy_domain_id=observation.privacy_domain_id
      AND prior.work_kind='RUNTIME_ACTIVATION' AND prior.runtime_target_id=observation.runtime_target_id
      AND prior.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
      AND prior.generation_digest=observation.generation_digest
      AND prior.configuration_digest=NEW.configuration_digest)) THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-PROVENANCE'; END IF;
 IF NEW.state='COMPLETED' AND NOT EXISTS(SELECT 1 FROM control.cigl_analysis analysis JOIN control.runtime_target target
   ON target.runtime_target_id=analysis.runtime_target_id AND target.participant_id=analysis.participant_id AND target.privacy_domain_id=analysis.privacy_domain_id
   WHERE analysis.analysis_id=NEW.resource_id AND analysis.expires_at>clock_timestamp()
    AND target.state='ACTIVE_MATCHED' AND target.active_generation_digest=NEW.generation_digest
    AND target.desired_generation_digest=NEW.generation_digest) THEN
  RAISE EXCEPTION 'PC-DATA-6007-CIGL-PROFILE-CURRENTNESS'; END IF;
 IF NEW.state IN ('COMPLETED','FAILED') AND NOT EXISTS(SELECT 1 FROM control.outbox_event event
    JOIN control.cigl_profile_version version ON version.configuration_work_id=NEW.configuration_work_id
    WHERE event.event_id=NEW.result_event_id AND event.participant_id=NEW.participant_id AND event.privacy_domain_id=NEW.privacy_domain_id
     AND event.aggregate_type='cigl-analysis' AND event.aggregate_id=NEW.resource_id
     AND ((NEW.state='COMPLETED' AND version.state='COMPILED' AND event.event_type='openpc.cigl.profile.compiled.v1')
       OR (NEW.state='FAILED' AND version.state='PENDING' AND event.event_type='openpc.cigl.profile.compilation-failed.v1'))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-EFFECT'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_work_provenance ON control.configuration_work;
CREATE CONSTRAINT TRIGGER cigl_profile_work_provenance AFTER INSERT OR UPDATE ON control.configuration_work
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_work();

CREATE OR REPLACE FUNCTION openpc.require_cigl_profile_owner()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.cigl_profile_version version WHERE version.profile_id=NEW.profile_id
  AND version.participant_id=NEW.participant_id AND version.privacy_domain_id=NEW.privacy_domain_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-OWNER-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_owner_provenance ON control.cigl_method_profile;
CREATE CONSTRAINT TRIGGER cigl_profile_owner_provenance AFTER INSERT ON control.cigl_method_profile
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_owner();

CREATE OR REPLACE FUNCTION openpc.require_cigl_profile_result()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE version_number bigint;
BEGIN
 IF TG_TABLE_NAME='cigl_profile_version' THEN version_number:=NEW.revision;
 ELSE version_number:=NEW.profile_revision; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.cigl_profile_version version JOIN control.configuration_work work
   ON work.configuration_work_id=version.configuration_work_id AND work.participant_id=version.participant_id AND work.privacy_domain_id=version.privacy_domain_id
   WHERE version.profile_id=NEW.profile_id AND version.revision=version_number AND version.participant_id=NEW.participant_id
    AND version.privacy_domain_id=NEW.privacy_domain_id AND version.state='COMPILED' AND work.state='COMPLETED') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-PROFILE-ATOMIC-RESULT'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_profile_result_atomic ON control.cigl_profile_version;
CREATE CONSTRAINT TRIGGER cigl_profile_result_atomic AFTER UPDATE ON control.cigl_profile_version
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_result();
DROP TRIGGER IF EXISTS cigl_profile_grant_atomic ON control.cigl_profile_grant_source;
CREATE CONSTRAINT TRIGGER cigl_profile_grant_atomic AFTER INSERT ON control.cigl_profile_grant_source
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_result();
DROP TRIGGER IF EXISTS cigl_profile_method_atomic ON control.cigl_profile_method_source;
CREATE CONSTRAINT TRIGGER cigl_profile_method_atomic AFTER INSERT ON control.cigl_profile_method_source
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_result();
DROP TRIGGER IF EXISTS cigl_profile_path_atomic ON control.cigl_profile_dependency_path;
CREATE CONSTRAINT TRIGGER cigl_profile_path_atomic AFTER INSERT ON control.cigl_profile_dependency_path
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_profile_result();


ALTER TABLE control.cigl_method_grant_dependency_claims FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_dependency_claim()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-DEPENDENCY-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 PERFORM openpc.lock_cigl_grant_sources();
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1' THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY'; END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state NOT IN ('RELEASED','INVALIDATED')
   OR NEW.released_operation_id IS DISTINCT FROM current_setting('openpc.operation_id')::uuid
   OR (to_jsonb(NEW)-ARRAY['state','released_at','released_operation_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','released_at','released_operation_id'])
   OR NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants changed
    WHERE changed.participant_id=NEW.participant_id AND changed.privacy_domain_id=NEW.privacy_domain_id
     AND changed.publication_operation_id=NEW.released_operation_id
     AND ((NEW.state='RELEASED' AND changed.grant_id=NEW.source_grant_id AND changed.revision>NEW.source_grant_revision)
       OR (NEW.state='INVALIDATED' AND changed.grant_id=NEW.required_grant_id AND changed.revision>NEW.required_grant_revision))) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-OWNER'; END IF;
  NEW.released_at:=clock_timestamp(); RETURN NEW;
 END IF;
 -- Retain the same physical/method and policy source fence for direct SQL as
 -- for the repository. The grant advisory lock alone does not lock a binding.
 PERFORM 1 FROM control.cigl_profile_method_source retained
  JOIN control.contract_method_policy method ON method.contract_method_policy_id=retained.contract_method_policy_id AND method.participant_id=retained.participant_id AND method.privacy_domain_id=retained.privacy_domain_id
  JOIN control.contract_runtime_binding binding ON binding.runtime_binding_id=retained.runtime_binding_id AND binding.participant_id=retained.participant_id AND binding.privacy_domain_id=retained.privacy_domain_id
  WHERE retained.profile_id=NEW.profile_id AND retained.profile_revision=NEW.profile_revision ORDER BY method.contract_method_policy_id FOR SHARE OF method,binding;
 PERFORM 1 FROM control.cigl_profile_version version JOIN control.cigl_analysis analysis ON analysis.analysis_id=version.analysis_id
  JOIN control.runtime_target target ON target.runtime_target_id=analysis.runtime_target_id
  JOIN control.runtime_activation_observation observation ON observation.runtime_target_id=target.runtime_target_id
   AND observation.participant_id=target.participant_id AND observation.privacy_domain_id=target.privacy_domain_id
   AND observation.capsule_digest=target.active_generation_digest
  JOIN control.runtime_configuration_generation generation ON generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
   AND generation.runtime_target_id=target.runtime_target_id
   AND generation.participant_id=target.participant_id AND generation.privacy_domain_id=target.privacy_domain_id
   AND generation.generation_digest=observation.generation_digest AND generation.state='ACTIVE'
  WHERE version.profile_id=NEW.profile_id AND version.revision=NEW.profile_revision FOR SHARE OF target,generation;
 IF NEW.state<>'ACTIVE' OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid
  OR NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants source
   JOIN control.cigl_method_access_grants required ON required.participant_id=source.participant_id AND required.privacy_domain_id=source.privacy_domain_id
   JOIN control.cigl_profile_version version ON version.profile_id=NEW.profile_id AND version.revision=NEW.profile_revision
    AND version.participant_id=source.participant_id AND version.privacy_domain_id=source.privacy_domain_id
   JOIN control.cigl_profile_dependency_path path ON path.profile_id=version.profile_id AND path.profile_revision=version.revision AND path.ordinal=NEW.ordinal
   JOIN control.cigl_analysis analysis ON analysis.analysis_id=version.analysis_id AND analysis.participant_id=source.participant_id AND analysis.privacy_domain_id=source.privacy_domain_id
   JOIN control.contract_method_policy root ON root.contract_method_policy_id=analysis.contract_method_policy_id AND root.participant_id=source.participant_id AND root.privacy_domain_id=source.privacy_domain_id
   JOIN control.runtime_target target ON target.runtime_target_id=analysis.runtime_target_id AND target.participant_id=source.participant_id AND target.privacy_domain_id=source.privacy_domain_id
   JOIN control.participant participant ON participant.participant_id=source.participant_id
   WHERE source.grant_id=NEW.source_grant_id AND source.participant_id=NEW.participant_id AND source.privacy_domain_id=NEW.privacy_domain_id
    AND source.origin='SHARED' AND source.status='ACTIVE' AND source.definition->>'effect'='ALLOW' AND source.revision=NEW.source_grant_revision
    AND source.publication_operation_id=NEW.publication_operation_id AND openpc.cigl_subject_current(source.participant_id,source.definition->'subject')
    AND required.grant_id=NEW.required_grant_id AND required.revision=NEW.required_grant_revision AND required.status='ACTIVE' AND required.definition->>'effect'='ALLOW'
    AND required.definition->'subject'=source.definition->'subject' AND required.definition->>'surface'=source.definition->>'surface'
    AND required.runtime_binding_id::text=path.document->>'runtimeBindingId'
    AND required.selector='0x'||(SELECT string_agg(lpad(to_hex(value::text::integer),2,'0'),'' ORDER BY n) FROM jsonb_array_elements(path.document->'selector') WITH ORDINALITY s(value,n))
    AND root.runtime_binding_id=source.runtime_binding_id AND root.selector=source.selector AND root.revision=source.method_revision AND root.state='ACTIVE'
    AND EXISTS(SELECT 1 FROM control.cigl_profile_method_source retained WHERE retained.profile_id=NEW.profile_id AND retained.profile_revision=NEW.profile_revision
      AND retained.contract_method_policy_id=root.contract_method_policy_id AND retained.binding_revision=source.binding_revision AND retained.method_revision=source.method_revision)
    AND EXISTS(SELECT 1 FROM control.cigl_profile_method_source retained WHERE retained.profile_id=NEW.profile_id AND retained.profile_revision=NEW.profile_revision
      AND retained.contract_method_policy_id::text=path.document->>'contractMethodPolicyId' AND retained.binding_revision=required.binding_revision AND retained.method_revision=required.method_revision)
    AND ((NEW.capability='SIMULATE_CALL' AND root.effect='READ' AND source.definition->>'surface'='ETH_CALL')
      OR (NEW.capability='EXECUTE_TRANSACTION' AND root.effect='WRITE' AND source.definition->>'surface' IN ('PREPARE_WRITE','RAW_SUBMISSION','RUNTIME_WRITE_TRACE')))
    AND version.state='COMPILED' AND version.dependency_paths_digest IS NOT NULL AND analysis.analysis_digest=NEW.graph_digest
    AND analysis.policy_generation_digest=NEW.policy_generation_digest AND target.policy_generation_digest=NEW.policy_generation_digest
    AND target.state='ACTIVE_MATCHED' AND target.active_generation_digest=target.desired_generation_digest
    AND target.active_generation_digest=analysis.definition->>'expectedGenerationDigest'
    AND participant.state='ACTIVE' AND participant.archived_at IS NULL AND participant.authority_epoch=NEW.participant_epoch
    AND EXISTS(SELECT 1 FROM control.runtime_activation_observation observation
      JOIN control.runtime_configuration_generation generation ON generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
      AND generation.participant_id=observation.participant_id AND generation.privacy_domain_id=observation.privacy_domain_id
      AND generation.runtime_target_id=observation.runtime_target_id AND generation.generation_digest=observation.generation_digest
      WHERE observation.participant_id=NEW.participant_id AND observation.privacy_domain_id=NEW.privacy_domain_id
      AND observation.capsule_digest=target.active_generation_digest
      AND generation.runtime_target_id=target.runtime_target_id AND generation.state='ACTIVE'
      AND generation.policy_generation_digest=NEW.policy_generation_digest)
    AND NOT EXISTS(SELECT 1 FROM control.cigl_profile_method_source retained
      LEFT JOIN control.contract_method_policy live ON live.contract_method_policy_id=retained.contract_method_policy_id AND live.participant_id=retained.participant_id AND live.privacy_domain_id=retained.privacy_domain_id
      LEFT JOIN control.contract_runtime_binding binding ON binding.runtime_binding_id=retained.runtime_binding_id AND binding.participant_id=retained.participant_id AND binding.privacy_domain_id=retained.privacy_domain_id
      WHERE retained.profile_id=version.profile_id AND retained.profile_revision=version.revision
       AND (live.contract_method_policy_id IS NULL OR live.state<>'ACTIVE' OR live.revision<>retained.method_revision
        OR binding.runtime_binding_id IS NULL OR binding.state<>'BOUND' OR binding.revision<>retained.binding_revision))
    AND NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants denial WHERE denial.participant_id=source.participant_id AND denial.privacy_domain_id=source.privacy_domain_id
      AND denial.runtime_binding_id=required.runtime_binding_id AND denial.selector=required.selector AND denial.status='ACTIVE'
      AND denial.definition->>'effect'='DENY' AND denial.definition->>'surface'=source.definition->>'surface'
      AND (denial.definition->'subject'=source.definition->'subject' OR denial.definition->'subject'='{"kind":"ANY_AUTHENTICATED"}'::jsonb))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-SOURCE'; END IF;
 NEW.created_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_dependency_claim_guard ON control.cigl_method_grant_dependency_claims;
CREATE TRIGGER cigl_dependency_claim_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_method_grant_dependency_claims
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_dependency_claim();

CREATE OR REPLACE FUNCTION openpc.release_cigl_dependency_claims()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  UPDATE control.cigl_method_grant_dependency_claims SET state='RELEASED',released_operation_id=NEW.publication_operation_id,released_at=clock_timestamp()
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND source_grant_id=NEW.grant_id AND state='ACTIVE' AND source_grant_revision<NEW.revision;
  UPDATE control.cigl_method_grant_dependency_claims SET state='INVALIDATED',released_operation_id=NEW.publication_operation_id,released_at=clock_timestamp()
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND required_grant_id=NEW.grant_id AND state='ACTIVE' AND required_grant_revision<NEW.revision;
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_dependency_claim_release ON control.cigl_method_access_grants;
CREATE TRIGGER cigl_dependency_claim_release AFTER UPDATE ON control.cigl_method_access_grants
 FOR EACH ROW EXECUTE FUNCTION openpc.release_cigl_dependency_claims();

-- Deferred provenance also enforces completeness: an approved bundle cannot
-- commit a subset, add a dependency, or substitute a generated/shared grant.
CREATE OR REPLACE FUNCTION openpc.require_cigl_dependency_bundle()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE document jsonb; bundle jsonb; item jsonb; selected control.cigl_method_grant_dependency_claims;
BEGIN
 IF NEW.origin<>'SHARED' OR NEW.revision=1 THEN RETURN NULL; END IF;
 SELECT candidate.candidate_document INTO STRICT document FROM control.mutation_candidate candidate
  WHERE candidate.participant_id=NEW.participant_id AND candidate.privacy_domain_id=NEW.privacy_domain_id
   AND candidate.resource_id=NEW.grant_id AND candidate.consumed_operation_id=NEW.publication_operation_id
   AND candidate.catalog_operation_id='CFG-OP-UPDATE-CIGL-GRANT' AND candidate.state='CONSUMED';
 bundle:=document->'dependencyBundle';
 IF bundle IS NULL THEN
  IF EXISTS(SELECT 1 FROM control.cigl_grant_history WHERE grant_id=NEW.grant_id AND revision=NEW.revision-1 AND status=NEW.status) THEN
   RAISE EXCEPTION 'PC-DATA-6007-CIGL-GRANT-NO-CHANGE'; END IF;
  IF EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims WHERE source_grant_id=NEW.grant_id AND publication_operation_id=NEW.publication_operation_id) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-UNREVIEWED'; END IF;
  RETURN NULL;
 END IF;
 IF NEW.status<>'ACTIVE' OR jsonb_typeof(bundle->'dependencies') IS DISTINCT FROM 'array'
  OR (SELECT count(DISTINCT value->>'actionDigest') FROM jsonb_array_elements(bundle->'dependencies'))<>jsonb_array_length(bundle->'dependencies')
  OR (SELECT count(*) FROM control.cigl_method_grant_dependency_claims WHERE source_grant_id=NEW.grant_id AND source_grant_revision=NEW.revision AND publication_operation_id=NEW.publication_operation_id)
    <>jsonb_array_length(bundle->'dependencies')
  OR jsonb_array_length(bundle->'dependencies')<>(SELECT count(*) FROM control.cigl_profile_dependency_path path
    JOIN control.cigl_profile_version version ON version.profile_id=path.profile_id AND version.revision=path.profile_revision
    WHERE version.profile_id::text=substring(bundle->>'profileId' from 21) AND version.revision::text=bundle->>'profileRevision'
     AND version.participant_id=NEW.participant_id AND version.privacy_domain_id=NEW.privacy_domain_id AND version.profile_digest=bundle->>'profileDigest') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-COMPLETENESS'; END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(bundle->'dependencies') LOOP
  SELECT claim.* INTO selected FROM control.cigl_method_grant_dependency_claims claim
   JOIN control.cigl_profile_dependency_path path_row ON path_row.profile_id=claim.profile_id AND path_row.profile_revision=claim.profile_revision AND path_row.ordinal=claim.ordinal
   WHERE claim.source_grant_id=NEW.grant_id AND claim.source_grant_revision=NEW.revision AND claim.publication_operation_id=NEW.publication_operation_id
    AND 'sha256:'||(path_row.document->>'actionDigest')=item->>'actionDigest';
  IF NOT FOUND OR selected.state<>'ACTIVE' OR selected.capability IS DISTINCT FROM bundle->>'capability'
   OR selected.graph_digest IS DISTINCT FROM bundle->>'graphDigest' OR selected.policy_generation_digest IS DISTINCT FROM bundle->>'policyGenerationDigest'
   OR selected.participant_epoch::text IS DISTINCT FROM bundle->>'participantEpoch'
   OR selected.profile_id::text IS DISTINCT FROM substring(bundle->>'profileId' from 21) OR selected.profile_revision::text IS DISTINCT FROM bundle->>'profileRevision'
   OR NOT EXISTS(SELECT 1 FROM control.cigl_method_access_grants required WHERE required.grant_id=selected.required_grant_id
    AND ((item->'grant'->>'kind'='SHARED' AND 'urn:openpc:resource:'||required.grant_id::text=item->'grant'->>'grantId'
      AND selected.required_grant_revision::text=item->'grant'->>'expectedRevision')
     OR (item->'grant'='{"kind":"GENERATE"}'::jsonb AND required.origin='GENERATED' AND required.generated_by_grant_id=NEW.grant_id
      AND required.publication_operation_id=NEW.publication_operation_id AND required.revision=1))) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-EXACT-BUNDLE'; END IF;
 END LOOP;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_dependency_bundle_provenance ON control.cigl_method_access_grants;
CREATE CONSTRAINT TRIGGER cigl_dependency_bundle_provenance AFTER UPDATE ON control.cigl_method_access_grants
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_dependency_bundle();

CREATE OR REPLACE FUNCTION openpc.require_generated_cigl_grant()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.origin<>'GENERATED' THEN RETURN NULL; END IF;
 IF NEW.status='ACTIVE' THEN
  IF NOT EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims claim
    JOIN control.cigl_profile_dependency_path path ON path.profile_id=claim.profile_id AND path.profile_revision=claim.profile_revision AND path.ordinal=claim.ordinal
    JOIN control.mutation_candidate candidate ON candidate.participant_id=claim.participant_id AND candidate.privacy_domain_id=claim.privacy_domain_id
     AND candidate.resource_id=claim.source_grant_id AND candidate.consumed_operation_id=claim.publication_operation_id AND candidate.state='CONSUMED'
     AND candidate.catalog_operation_id='CFG-OP-UPDATE-CIGL-GRANT'
    WHERE claim.required_grant_id=NEW.grant_id AND claim.state='ACTIVE'
     AND claim.publication_operation_id=NEW.publication_operation_id AND claim.source_grant_id=NEW.generated_by_grant_id
     AND EXISTS(SELECT 1 FROM jsonb_array_elements(candidate.candidate_document->'dependencyBundle'->'dependencies') item
       WHERE item->'grant'='{"kind":"GENERATE"}'::jsonb AND item->>'actionDigest'='sha256:'||(path.document->>'actionDigest'))) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GENERATED-UNOWNED'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims WHERE required_grant_id=NEW.grant_id AND state='ACTIVE')
   OR NOT EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims WHERE required_grant_id=NEW.grant_id AND released_operation_id=NEW.publication_operation_id)
   OR NOT EXISTS(SELECT 1 FROM control.mutation_evidence WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
     AND operation_id=NEW.publication_operation_id AND catalog_operation_id='CFG-OP-UPDATE-CIGL-GRANT') THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GENERATED-RELEASE'; END IF;
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_generated_grant_provenance ON control.cigl_method_access_grants;
CREATE CONSTRAINT TRIGGER cigl_generated_grant_provenance AFTER INSERT OR UPDATE ON control.cigl_method_access_grants
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_generated_cigl_grant();

CREATE OR REPLACE FUNCTION openpc.require_cigl_dependency_claim()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='INSERT' AND NOT EXISTS(SELECT 1 FROM control.mutation_candidate candidate
  JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id AND evidence.privacy_domain_id=candidate.privacy_domain_id
   AND evidence.operation_id=candidate.consumed_operation_id AND evidence.candidate_digest=candidate.candidate_digest
   AND evidence.catalog_operation_id=candidate.catalog_operation_id AND evidence.aggregate_id=candidate.resource_id
  JOIN control.cigl_profile_dependency_path path ON path.profile_id=NEW.profile_id AND path.profile_revision=NEW.profile_revision AND path.ordinal=NEW.ordinal
  JOIN control.cigl_profile_version version ON version.profile_id=path.profile_id AND version.revision=path.profile_revision
  WHERE candidate.participant_id=NEW.participant_id AND candidate.privacy_domain_id=NEW.privacy_domain_id
   AND candidate.resource_id=NEW.source_grant_id AND candidate.state='CONSUMED' AND candidate.catalog_operation_id='CFG-OP-UPDATE-CIGL-GRANT'
   AND candidate.consumed_operation_id=NEW.publication_operation_id AND evidence.aggregate_version=NEW.source_grant_revision
   AND candidate.candidate_document->'dependencyBundle'->>'profileId'='urn:openpc:resource:'||NEW.profile_id::text
   AND candidate.candidate_document->'dependencyBundle'->>'profileRevision'=NEW.profile_revision::text
   AND candidate.candidate_document->'dependencyBundle'->>'profileDigest'=version.profile_digest
   AND candidate.candidate_document->'dependencyBundle'->>'capability'=NEW.capability
   AND candidate.candidate_document->'dependencyBundle'->>'graphDigest'=NEW.graph_digest
   AND candidate.candidate_document->'dependencyBundle'->>'policyGenerationDigest'=NEW.policy_generation_digest
   AND candidate.candidate_document->'dependencyBundle'->>'participantEpoch'=NEW.participant_epoch::text
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(candidate.candidate_document->'dependencyBundle'->'dependencies') item
     WHERE item->>'actionDigest'='sha256:'||(path.document->>'actionDigest')
      AND ((item->'grant'->>'kind'='SHARED' AND item->'grant'->>'grantId'='urn:openpc:resource:'||NEW.required_grant_id::text AND item->'grant'->>'expectedRevision'=NEW.required_grant_revision::text)
       OR (item->'grant'='{"kind":"GENERATE"}'::jsonb AND EXISTS(SELECT 1 FROM control.cigl_method_access_grants required
        WHERE required.grant_id=NEW.required_grant_id AND required.origin='GENERATED' AND required.generated_by_grant_id=NEW.source_grant_id AND required.publication_operation_id=NEW.publication_operation_id))))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-DEPENDENCY-PROVENANCE'; END IF;
 IF TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM control.cigl_method_access_grants required WHERE required.grant_id=NEW.required_grant_id
   AND required.origin='GENERATED' AND required.status='ACTIVE'
   AND NOT EXISTS(SELECT 1 FROM control.cigl_method_grant_dependency_claims claim WHERE claim.required_grant_id=required.grant_id AND claim.state='ACTIVE')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-GENERATED-ORPHAN'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_dependency_claim_provenance ON control.cigl_method_grant_dependency_claims;
CREATE CONSTRAINT TRIGGER cigl_dependency_claim_provenance AFTER INSERT OR UPDATE ON control.cigl_method_grant_dependency_claims
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_dependency_claim();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES('ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1','runtime-targets','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_PROFILE_ACTIVATION')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.action_intent WHERE action_intent_id='ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1'
  AND resource_type='runtime-targets' AND operation_class='UPDATE' AND risk_class='HIGH'
  AND maker_checker_required AND step_up_required AND idempotency_required
  AND existence_disclosure='AUTHORIZED_ONLY' AND payload_disclosure='REDACTED' AND evidence_class='CIGL_PROFILE_ACTIVATION')
 THEN RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ACTIVATION-ACTION'; END IF;
END $$;

-- Compilation permanently names its original analysis capsule. A subsequent
-- publication may use the actual approved/observed installation of that exact
-- compiled profile without rewriting the analysis or its signed receipt.
CREATE OR REPLACE FUNCTION openpc.cigl_profile_has_installed_lineage(
 p_profile uuid,p_revision bigint,p_target uuid,p_capsule text,p_policy text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT EXISTS(
  SELECT 1 FROM control.cigl_profile_version version
  JOIN control.cigl_analysis analysis ON analysis.analysis_id=version.analysis_id
   AND analysis.participant_id=version.participant_id AND analysis.privacy_domain_id=version.privacy_domain_id
  JOIN control.runtime_target target ON target.runtime_target_id=analysis.runtime_target_id
   AND target.participant_id=analysis.participant_id AND target.privacy_domain_id=analysis.privacy_domain_id
  WHERE version.profile_id=p_profile AND version.revision=p_revision AND version.state='COMPILED'
   AND version.participant_id=openpc.current_participant_id() AND version.privacy_domain_id=openpc.current_privacy_domain_id()
   AND analysis.state='REVIEWED' AND analysis.revision=3 AND analysis.runtime_target_id=p_target
   AND target.active_generation_digest=p_capsule
   AND ((analysis.capsule_digest=p_capsule AND analysis.policy_generation_digest=p_policy) OR EXISTS(
    SELECT 1 FROM control.runtime_activation_observation observation
    JOIN control.runtime_configuration_generation generation
     ON generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
      AND generation.participant_id=observation.participant_id AND generation.privacy_domain_id=observation.privacy_domain_id
    JOIN control.configuration_work work ON work.configuration_work_id=observation.configuration_work_id
     AND work.participant_id=observation.participant_id AND work.privacy_domain_id=observation.privacy_domain_id
     AND work.operation_id=observation.operation_id AND work.execution_attempt_id=observation.execution_attempt_id
     AND work.runtime_configuration_generation_id=generation.runtime_configuration_generation_id
     AND work.runtime_target_id=observation.runtime_target_id AND work.xds_version_digest=observation.xds_version_digest
     AND work.generation_digest=generation.generation_digest
    WHERE observation.participant_id=version.participant_id AND observation.privacy_domain_id=version.privacy_domain_id
     AND observation.runtime_target_id=p_target AND observation.capsule_digest=p_capsule
     AND generation.runtime_target_id=p_target AND generation.policy_generation_digest=p_policy AND generation.state='ACTIVE'
     AND work.work_kind='RUNTIME_ACTIVATION' AND work.state='COMPLETED' AND work.execution_started_at IS NOT NULL
     AND work.result_receipt_digest=observation.activation_receipt_digest
     AND generation.cigl_profile_selection->'profiles' @> jsonb_build_array(jsonb_build_object(
      'profileId','urn:openpc:resource:'||version.profile_id::text,'profileRevision',version.revision::text,
      'profileDigest',version.profile_digest,'compilationArtifactDigest',version.artifact_digest)))))
$$;
REVOKE ALL ON FUNCTION openpc.cigl_profile_has_installed_lineage(uuid,bigint,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.cigl_profile_has_installed_lineage(uuid,bigint,uuid,text,text)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_activation_selection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE item jsonb; last_id text:=''; selected control.cigl_profile_version; root_id uuid; roots uuid[]:='{}';
BEGIN
 IF TG_OP='UPDATE' THEN
  IF NEW.cigl_profile_selection IS DISTINCT FROM OLD.cigl_profile_selection THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-ACTIVATION-IMMUTABLE'; END IF;
  IF OLD.cigl_profile_selection IS NOT NULL AND
   ROW(NEW.runtime_configuration_generation_id,NEW.participant_id,NEW.privacy_domain_id,NEW.runtime_target_id,
     NEW.provider_profile_id,NEW.projection_plan_id,NEW.predecessor_digest,NEW.generation_digest,NEW.policy_generation_digest,NEW.created_at)
   IS DISTINCT FROM ROW(OLD.runtime_configuration_generation_id,OLD.participant_id,OLD.privacy_domain_id,OLD.runtime_target_id,
     OLD.provider_profile_id,OLD.projection_plan_id,OLD.predecessor_digest,OLD.generation_digest,OLD.policy_generation_digest,OLD.created_at) THEN
   RAISE EXCEPTION 'PC-DATA-6004-CIGL-ACTIVATION-IMMUTABLE'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.cigl_profile_selection IS NULL THEN
  IF EXISTS(SELECT 1 FROM control.runtime_target target
   JOIN control.runtime_activation_observation observation ON observation.runtime_target_id=target.runtime_target_id
    AND observation.participant_id=target.participant_id AND observation.privacy_domain_id=target.privacy_domain_id
    AND observation.capsule_digest=target.active_generation_digest
   JOIN control.runtime_configuration_generation previous ON previous.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
   WHERE target.runtime_target_id=NEW.runtime_target_id AND previous.cigl_profile_selection IS NOT NULL) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ACTIVATION-REQUIRED'; END IF;
  RETURN NEW;
 END IF;
 PERFORM openpc.assert_request_context(true);
 PERFORM openpc.lock_cigl_grant_sources();
 IF openpc.current_action_intent_id()<>'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1'
  OR NEW.participant_id<>openpc.current_participant_id() OR NEW.privacy_domain_id<>openpc.current_privacy_domain_id()
  OR NEW.state<>'ACTIVATING' OR NEW.revision<>1 OR NEW.predecessor_digest IS NULL
  OR NOT EXISTS(SELECT 1 FROM control.participant WHERE participant_id=NEW.participant_id AND state='ACTIVE'
    AND archived_at IS NULL AND authority_epoch::text=NEW.cigl_profile_selection->>'participantEpoch')
  OR NOT EXISTS(SELECT 1 FROM control.runtime_target WHERE runtime_target_id=NEW.runtime_target_id
    AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND state='ACTIVE_MATCHED'
    AND active_generation_digest=NEW.predecessor_digest AND desired_generation_digest=NEW.predecessor_digest) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ACTIVATION-SOURCE'; END IF;
 IF NEW.cigl_profile_selection ? 'policyRenewal' THEN
  IF NOT EXISTS(SELECT 1 FROM control.policy_activation_occurrence occurrence
   JOIN control.policy_activation activation ON activation.policy_activation_id=occurrence.activation_occurrence_id
    AND activation.participant_id=occurrence.participant_id AND activation.privacy_domain_id=occurrence.privacy_domain_id
    AND activation.policy_generation_id=occurrence.policy_generation_id AND activation.state='PREPARED'
   JOIN control.policy_generation policy ON policy.policy_generation_id=occurrence.policy_generation_id
    AND policy.participant_id=occurrence.participant_id AND policy.privacy_domain_id=occurrence.privacy_domain_id
    AND policy.state='PREPARED' AND NOT policy.active
   JOIN control.policy_activation_occurrence_target cohort ON cohort.activation_occurrence_id=occurrence.activation_occurrence_id
    AND cohort.participant_id=occurrence.participant_id AND cohort.privacy_domain_id=occurrence.privacy_domain_id
   WHERE occurrence.participant_id=NEW.participant_id AND occurrence.privacy_domain_id=NEW.privacy_domain_id
    AND 'urn:openpc:resource:'||occurrence.activation_occurrence_id::text=NEW.cigl_profile_selection->'policyRenewal'->>'activationOccurrenceRef'
    AND occurrence.revision::text=NEW.cigl_profile_selection->'policyRenewal'->>'expectedRevision'
    AND occurrence.state='REQUESTED' AND occurrence.total_target_count=1
    AND 'sha256:'||encode(policy.generation_digest,'hex')=NEW.policy_generation_digest
    AND NEW.policy_generation_digest=NEW.cigl_profile_selection->'policyRenewal'->>'policyGenerationDigest'
    AND cohort.runtime_target_id=NEW.runtime_target_id AND cohort.phase='FORWARD' AND cohort.state='REQUESTED'
    AND cohort.expected_predecessor_digest=NEW.predecessor_digest AND cohort.configuration_work_id IS NULL) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-RENEWAL-AUTHORITY'; END IF;
  -- Renewal carries every installed graph; changing or removing a graph requires
  -- its own analysis/review, not a policy freshness renewal.
  IF NOT EXISTS(SELECT 1 FROM control.runtime_activation_observation observation
   JOIN control.runtime_configuration_generation previous ON previous.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
    AND previous.participant_id=observation.participant_id AND previous.privacy_domain_id=observation.privacy_domain_id
   WHERE observation.runtime_target_id=NEW.runtime_target_id AND observation.participant_id=NEW.participant_id
    AND observation.privacy_domain_id=NEW.privacy_domain_id AND observation.capsule_digest=NEW.predecessor_digest
    AND previous.state='ACTIVE' AND previous.cigl_profile_selection IS NOT NULL
    AND (SELECT jsonb_agg(value-'grantSourcesDigest' ORDER BY value->>'profileId') FROM jsonb_array_elements(previous.cigl_profile_selection->'profiles'))
      = (SELECT jsonb_agg(value-'grantSourcesDigest' ORDER BY value->>'profileId') FROM jsonb_array_elements(NEW.cigl_profile_selection->'profiles'))) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-RENEWAL-LINEAGE'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM control.runtime_target WHERE runtime_target_id=NEW.runtime_target_id
   AND policy_generation_digest=NEW.policy_generation_digest) THEN
   RAISE EXCEPTION 'PC-AUTH-0002-CIGL-RENEWAL-REQUIRED'; END IF;
 END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(NEW.cigl_profile_selection->'profiles') LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR NOT item ?& ARRAY['profileId','profileRevision','profileDigest','compilationArtifactDigest','grantSourcesDigest']
   OR item-ARRAY['profileId','profileRevision','profileDigest','compilationArtifactDigest','grantSourcesDigest']<>'{}'::jsonb
   OR EXISTS(SELECT 1 FROM jsonb_each(item) field WHERE jsonb_typeof(field.value)<>'string')
   OR (item->>'profileId' ~ '^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') IS DISTINCT FROM true
   OR (item->>'profileRevision' ~ '^[1-9][0-9]{0,19}$') IS DISTINCT FROM true
   OR (item->>'grantSourcesDigest' ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true
   OR item->>'profileId'<=last_id THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-ACTIVATION-SELECTION'; END IF;
  last_id:=item->>'profileId';
  SELECT version.* INTO selected FROM control.cigl_profile_version version
   JOIN control.cigl_analysis analysis ON analysis.analysis_id=version.analysis_id
    AND analysis.participant_id=version.participant_id AND analysis.privacy_domain_id=version.privacy_domain_id
   WHERE version.profile_id=substring(item->>'profileId' from 21)::uuid AND version.revision::text=item->>'profileRevision'
    AND version.participant_id=NEW.participant_id AND version.privacy_domain_id=NEW.privacy_domain_id
    AND version.state='COMPILED' AND version.profile_digest=item->>'profileDigest' AND version.artifact_digest=item->>'compilationArtifactDigest'
    AND version.dependency_paths_digest IS NOT NULL AND analysis.runtime_target_id=NEW.runtime_target_id
    AND openpc.cigl_profile_has_installed_lineage(version.profile_id,version.revision,
      NEW.runtime_target_id,NEW.predecessor_digest,
      (SELECT policy_generation_digest FROM control.runtime_target WHERE runtime_target_id=NEW.runtime_target_id));
  IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007-CIGL-ACTIVATION-SELECTION'; END IF;
  SELECT root_contract_method_policy_id INTO root_id FROM control.cigl_method_profile WHERE profile_id=selected.profile_id;
  IF root_id=ANY(roots) THEN RAISE EXCEPTION 'PC-DATA-6004-CIGL-ACTIVATION-ROOT'; END IF;
  roots:=array_append(roots,root_id);
 END LOOP;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_activation_selection_guard ON control.runtime_configuration_generation;
CREATE TRIGGER cigl_activation_selection_guard BEFORE INSERT OR UPDATE ON control.runtime_configuration_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_activation_selection();

CREATE OR REPLACE FUNCTION openpc.guard_cigl_activation_work()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM control.runtime_configuration_generation generation
   WHERE generation.runtime_configuration_generation_id=OLD.runtime_configuration_generation_id
    AND generation.cigl_profile_selection IS NOT NULL) AND
  ROW(NEW.configuration_work_id,NEW.participant_id,NEW.privacy_domain_id,NEW.operation_id,NEW.work_kind,NEW.resource_id,
    NEW.input_digest,NEW.configuration_digest,NEW.runtime_configuration_generation_id,NEW.runtime_target_id,
    NEW.generation_digest,NEW.predecessor_digest,NEW.policy_generation_digest,NEW.xds_version_digest,NEW.created_at)
  IS DISTINCT FROM ROW(OLD.configuration_work_id,OLD.participant_id,OLD.privacy_domain_id,OLD.operation_id,OLD.work_kind,OLD.resource_id,
    OLD.input_digest,OLD.configuration_digest,OLD.runtime_configuration_generation_id,OLD.runtime_target_id,
    OLD.generation_digest,OLD.predecessor_digest,OLD.policy_generation_digest,OLD.xds_version_digest,OLD.created_at) THEN
  RAISE EXCEPTION 'PC-DATA-6004-CIGL-ACTIVATION-WORK-IMMUTABLE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_activation_work_guard ON control.configuration_work;
CREATE TRIGGER cigl_activation_work_guard BEFORE UPDATE ON control.configuration_work
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_activation_work();

CREATE OR REPLACE FUNCTION openpc.require_cigl_activation_selection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.cigl_profile_selection IS NULL THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.configuration_work work
  JOIN control.mutation_evidence evidence ON evidence.operation_id=work.operation_id
   AND evidence.participant_id=work.participant_id AND evidence.privacy_domain_id=work.privacy_domain_id
  JOIN control.mutation_candidate candidate ON candidate.consumed_operation_id=evidence.operation_id
   AND candidate.participant_id=evidence.participant_id AND candidate.privacy_domain_id=evidence.privacy_domain_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  JOIN control.runtime_target target ON target.runtime_target_id=NEW.runtime_target_id
   AND target.participant_id=NEW.participant_id AND target.privacy_domain_id=NEW.privacy_domain_id
  WHERE work.runtime_configuration_generation_id=NEW.runtime_configuration_generation_id
   AND work.participant_id=NEW.participant_id AND work.privacy_domain_id=NEW.privacy_domain_id
   AND work.work_kind='RUNTIME_ACTIVATION' AND work.runtime_target_id=NEW.runtime_target_id AND work.resource_id=NEW.runtime_target_id
   AND work.generation_digest=NEW.generation_digest AND work.predecessor_digest=NEW.predecessor_digest
   AND work.policy_generation_digest=NEW.policy_generation_digest AND work.input_digest='sha256:'||encode(candidate.candidate_digest,'hex')
   AND evidence.catalog_operation_id='CFG-OP-ACTIVATE-CIGL-PROFILES' AND evidence.action_intent_id='ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1'
   AND evidence.aggregate_type='runtime-targets' AND evidence.aggregate_id=NEW.runtime_target_id
   AND evidence.aggregate_version=candidate.expected_revision+1 AND candidate.resource_id=NEW.runtime_target_id AND candidate.state='CONSUMED'
   AND candidate.candidate_document->>'targetRef'='urn:openpc:resource:'||NEW.runtime_target_id::text
   AND candidate.candidate_document->>'expectedGenerationDigest'=NEW.predecessor_digest
   AND (jsonb_build_object('participantEpoch',candidate.candidate_document->'participantEpoch','profiles',candidate.candidate_document->'profiles') || CASE WHEN candidate.candidate_document ? 'policyRenewal' THEN jsonb_build_object('policyRenewal',candidate.candidate_document->'policyRenewal') ELSE '{}'::jsonb END)=NEW.cigl_profile_selection
   AND NEW.generation_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
      'purpose','openpc.runtime.cigl-profile-selection.v1','baseCapsuleDigest',candidate.candidate_document->>'expectedGenerationDigest',
      'selection',NEW.cigl_profile_selection)),'UTF8')),'hex')
   AND (TG_OP<>'INSERT' OR (target.state='STAGING' AND target.revision=candidate.expected_revision+1 AND target.desired_generation_digest=NEW.generation_digest))
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id AND event.privacy_domain_id=NEW.privacy_domain_id
    AND event.aggregate_id=NEW.runtime_target_id AND event.aggregate_type='runtime-targets'
    AND event.event_type='openpc.cigl.profile.activation-requested.v1'
    AND event.payload_digest=sha256(event.payload_cbor)
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(candidate.candidate_digest,'hex')
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'revision'=evidence.aggregate_version::text
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'='sha256:'||encode(evidence.evidence_digest,'hex'))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ACTIVATION-PROVENANCE'; END IF;
 IF NEW.cigl_profile_selection ? 'policyRenewal' AND NOT EXISTS(
  SELECT 1 FROM control.policy_activation_occurrence occurrence
  JOIN control.policy_activation_occurrence_target cohort ON cohort.activation_occurrence_id=occurrence.activation_occurrence_id
   AND cohort.participant_id=occurrence.participant_id AND cohort.privacy_domain_id=occurrence.privacy_domain_id
  JOIN control.configuration_work work ON work.configuration_work_id=cohort.configuration_work_id
   AND work.participant_id=cohort.participant_id AND work.privacy_domain_id=cohort.privacy_domain_id
  WHERE occurrence.participant_id=NEW.participant_id AND occurrence.privacy_domain_id=NEW.privacy_domain_id
   AND 'urn:openpc:resource:'||occurrence.activation_occurrence_id::text=NEW.cigl_profile_selection->'policyRenewal'->>'activationOccurrenceRef'
   AND cohort.runtime_target_id=NEW.runtime_target_id AND cohort.phase='FORWARD'
   AND cohort.runtime_configuration_generation_id=NEW.runtime_configuration_generation_id
   AND work.runtime_configuration_generation_id=NEW.runtime_configuration_generation_id
   AND work.policy_generation_digest=NEW.policy_generation_digest
   AND occurrence.target_generation_digest=decode(substring(NEW.policy_generation_digest from 8),'hex')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-RENEWAL-PROVENANCE'; END IF;
 IF NEW.state='ACTIVE' AND NOT EXISTS(SELECT 1 FROM control.runtime_activation_observation observation
  JOIN control.configuration_work work ON work.configuration_work_id=observation.configuration_work_id
  JOIN control.runtime_target target ON target.runtime_target_id=NEW.runtime_target_id
  WHERE observation.runtime_configuration_generation_id=NEW.runtime_configuration_generation_id
   AND observation.generation_digest=NEW.generation_digest AND observation.capsule_digest=target.active_generation_digest
   AND target.active_generation_digest=target.desired_generation_digest AND target.state='ACTIVE_MATCHED' AND work.state='COMPLETED') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-ACTIVATION-EFFECT'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_activation_selection_provenance ON control.runtime_configuration_generation;
CREATE CONSTRAINT TRIGGER cigl_activation_selection_provenance AFTER INSERT OR UPDATE ON control.runtime_configuration_generation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_activation_selection();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES('ACT-DEPLOYMENT_SUBMISSIONS_READ_RESOURCE-V1','deployment-submission','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_RESULT_READ') ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.action_intent WHERE action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_READ_RESOURCE-V1'
  AND resource_type='deployment-submission' AND operation_class='READ' AND risk_class='STANDARD'
  AND NOT maker_checker_required AND NOT step_up_required AND NOT idempotency_required
  AND existence_disclosure='AUTHORIZED_ONLY' AND payload_disclosure='REDACTED' AND evidence_class='DEPLOYMENT_RESULT_READ')
 THEN RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-READ-ACTION'; END IF;
END $$;
-- The migration owner is deliberately subject to Participant FORCE RLS.
-- This permits its association trigger to read/lock only the selected
-- Participant during result ingestion. It grants no runtime role access and
-- permits no Participant mutation, including through this definer.
DROP POLICY IF EXISTS deployment_association_owner_scope ON control.participant;
CREATE POLICY deployment_association_owner_scope ON control.participant FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)
  AND openpc.current_action_intent_id()='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND pg_trigger_depth()>0)
 WITH CHECK(false);
CREATE OR REPLACE FUNCTION openpc.deployment_flat_document(value jsonb)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT convert_to('{'||string_agg(to_jsonb(key)::text||':'||item::text,',' ORDER BY key COLLATE "C")||'}','UTF8')
 FROM jsonb_each(value) entry(key,item)
$$;
REVOKE ALL ON FUNCTION openpc.deployment_flat_document(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.deployment_flat_document(jsonb) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_deployment_result()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE reservation control.deployment_address_reservation%ROWTYPE; envelope jsonb; claims jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 envelope:=convert_from(NEW.signed_bytes,'UTF8')::jsonb; claims:=envelope->'claims';
 IF envelope->>'purpose'='openpc:deployment-reservation-rejection:v1' THEN
  PERFORM openpc.validate_deployment_rejection(NEW);
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT reservation FROM control.deployment_address_reservation
  WHERE command_id=NEW.command_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id FOR UPDATE;
 IF reservation.state<>'HANDOFF' OR envelope->>'purpose' IS DISTINCT FROM 'openpc:deployment-journal-projection:v1'
  OR claims->>'schema' IS DISTINCT FROM 'PC-DEPLOYMENT-JOURNAL-PROJECTION-1'
  OR claims->'owner'->>'participant_id' IS DISTINCT FROM NEW.participant_id::text
  OR claims->'owner'->>'privacy_domain_id' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR 'urn:openpc:resource:'||(claims->>'targetRuntimeId') IS DISTINCT FROM reservation.target_runtime_id
  OR claims->>'sequence' IS DISTINCT FROM NEW.sequence::text
  OR claims->>'intentDigest' IS DISTINCT FROM substring(reservation.intent_digest from 8)
  OR claims->>'preparationDigest' IS DISTINCT FROM substring(reservation.prepared_record_digest from 8)
  OR claims->>'chainId' IS DISTINCT FROM reservation.chain_id
  OR claims->>'genesisDigest' IS DISTINCT FROM substring(reservation.genesis_digest from 8)
  OR claims->'status'->>'operationId' IS DISTINCT FROM 'urn:openpc:operation:'||NEW.command_id::text
  OR claims->'status'->>'attemptId' IS DISTINCT FROM reservation.attempt_id::text
  OR claims->'status'->>'signedTransactionHash' IS DISTINCT FROM reservation.transaction_hash
  OR (claims->>'observedAt')::timestamptz>clock_timestamp()+interval '5 seconds'
  OR EXISTS(SELECT 1 FROM control.deployment_result result WHERE result.command_id=NEW.command_id AND result.sequence>=NEW.sequence)
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS deployment_result_guard ON control.deployment_result;
CREATE TRIGGER deployment_result_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deployment_result
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_result();

CREATE OR REPLACE FUNCTION openpc.project_deployment_association()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE claims jsonb; occurrence jsonb; invalidation jsonb; preparation jsonb;
 reservation control.deployment_address_reservation%ROWTYPE; participant control.participant%ROWTYPE;
 association control.contract_governance_association%ROWTYPE; document jsonb; encoded bytea; digest text;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id) THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 -- A Control rejection has no target occurrence and can never create or
 -- suspend an association. The result guard owns its separate proof above.
 IF convert_from(NEW.signed_bytes,'UTF8')::jsonb->>'purpose'='openpc:deployment-reservation-rejection:v1' THEN RETURN NEW; END IF;
 claims:=convert_from(NEW.signed_bytes,'UTF8')::jsonb->'claims';
 occurrence:=claims->'outcome'->'occurrence'; invalidation:=claims->'outcome'->'invalidation';
 SELECT * INTO STRICT reservation FROM control.deployment_address_reservation WHERE command_id=NEW.command_id;
 SELECT * INTO STRICT participant FROM control.participant WHERE participant_id=NEW.participant_id FOR SHARE;
 SELECT convert_from(intent.preparation_bytes,'UTF8')::jsonb INTO STRICT preparation FROM control.deployment_intent intent
  WHERE intent.participant_id=NEW.participant_id AND intent.privacy_domain_id=NEW.privacy_domain_id
   AND intent.preparation_digest=reservation.prepared_record_digest AND intent.intent_digest=reservation.intent_digest;
 SELECT * INTO association FROM control.contract_governance_association WHERE command_id=NEW.command_id FOR UPDATE;
 IF FOUND THEN
  document:=convert_from(association.document_bytes,'UTF8')::jsonb;
  IF association.state<>'ACTIVE' OR invalidation IS NULL OR invalidation='null'::jsonb
   OR invalidation->>'occurrenceId' IS DISTINCT FROM document->>'occurrenceId'
   OR invalidation->>'occurrenceDigest' IS DISTINCT FROM document->>'occurrenceDigest'
   OR invalidation->>'reason' NOT IN ('REORG','CODE_IDENTITY_MISMATCH')
   OR occurrence IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  document:=(document-'semanticDigest')||jsonb_build_object('state','SUSPENDED_REORG');
  digest:=encode(sha256(openpc.deployment_flat_document(document)),'hex');
  encoded:=openpc.deployment_flat_document(document||jsonb_build_object('semanticDigest',digest));
  UPDATE control.contract_governance_association SET state='SUSPENDED_REORG',current_sequence=NEW.sequence,
   document_bytes=encoded,semantic_digest='sha256:'||digest,updated_at=clock_timestamp() WHERE association_id=association.association_id;
 ELSIF occurrence IS NOT NULL AND occurrence<>'null'::jsonb THEN
  IF claims->'status'->>'state' IS DISTINCT FROM 'CONFIRMED' OR claims->'status'->>'truthState' IS DISTINCT FROM 'SUCCESS'
   OR occurrence->>'finality' IS DISTINCT FROM 'FINALIZED' OR occurrence->>'reorgStatus' IS DISTINCT FROM 'CANONICAL'
   OR occurrence->>'receiptStatus' IS DISTINCT FROM '1' OR occurrence->>'creationGraphComplete' IS DISTINCT FROM 'true'
   OR occurrence->>'runtimeCodePresent' IS DISTINCT FROM 'true' OR occurrence->>'internalNativeTransfers' IS DISTINCT FROM '0'
   OR invalidation IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  -- A retired/restored Participant cannot acquire new control from an older
  -- epoch's deployment. The effect remains truthful; association stays absent.
  IF participant.state<>'ACTIVE' OR participant.archived_at IS NOT NULL
   OR participant.authority_epoch::text IS DISTINCT FROM preparation->'context'->>'participantEpoch' THEN RETURN NEW; END IF;
  document:=jsonb_build_object('associationId',reservation.attempt_id::text,'occurrenceId',occurrence->>'occurrenceId',
   'occurrenceDigest',occurrence->>'semanticDigest','contractAddress',occurrence->>'derivedContractAddress',
   'chainEnvironmentId',claims->>'chainEnvironmentId','chainId',claims->>'chainId','genesisHash',claims->>'genesisDigest',
   'controllerParticipantId',NEW.participant_id::text,'controllerParticipantEpoch',participant.authority_epoch,
   'controllerGeneration',1,'state','ACTIVE','activatedAt',to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  digest:=encode(sha256(openpc.deployment_flat_document(document)),'hex');
  encoded:=openpc.deployment_flat_document(document||jsonb_build_object('semanticDigest',digest));
  INSERT INTO control.contract_governance_association(association_id,participant_id,privacy_domain_id,command_id,
   activation_sequence,current_sequence,participant_epoch,document_bytes,semantic_digest,state)
  VALUES(reservation.attempt_id,NEW.participant_id,NEW.privacy_domain_id,NEW.command_id,NEW.sequence,NEW.sequence,
   participant.authority_epoch,encoded,'sha256:'||digest,'ACTIVE');
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.project_deployment_association() FROM PUBLIC;
DROP TRIGGER IF EXISTS deployment_result_association ON control.deployment_result;
CREATE TRIGGER deployment_result_association AFTER INSERT ON control.deployment_result
 FOR EACH ROW EXECUTE FUNCTION openpc.project_deployment_association();


CREATE OR REPLACE FUNCTION openpc.runtime_configuration_bindings_current(
  p_participant uuid,p_privacy uuid,p_bindings jsonb
) RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control,openpc AS $$
 SELECT openpc.matches_participant(p_participant) AND openpc.matches_privacy(p_privacy)
   AND jsonb_typeof(p_bindings)='array' AND jsonb_array_length(p_bindings)>0
   AND NOT EXISTS (
     SELECT 1 FROM jsonb_array_elements(p_bindings) binding
     WHERE CASE binding->>'kind'
       WHEN 'ProviderProfile' THEN NOT EXISTS (
         SELECT 1 FROM control.provider_profile p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.provider_profile_id::text=binding->>'id'
           AND p.behavior_fingerprint=binding->>'digest' AND p.chain_id=binding->>'chainId' AND p.state<>'RETIRED')
       WHEN 'ClientIndexerProfile' THEN NOT EXISTS (
         SELECT 1 FROM control.indexer_profile p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.indexer_profile_id::text=binding->>'id'
           AND p.method_profile_digest=binding->>'digest' AND p.engine_version=binding->>'engineVersion' AND p.state<>'RETIRED')
       WHEN 'ProjectionPlan' THEN NOT EXISTS (
         SELECT 1 FROM control.projection_plan p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.projection_plan_id::text=binding->>'id'
           AND p.plan_digest=binding->>'digest' AND p.state<>'RETIRED')
       WHEN 'CiglSettings' THEN NOT EXISTS (
         SELECT 1 FROM control.cigl_settings p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.cigl_settings_id::text=binding->>'id')
       ELSE true END
   )
$$;
REVOKE ALL ON FUNCTION openpc.runtime_configuration_bindings_current(uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_configuration_bindings_current(uuid,uuid,jsonb)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_configuration_input()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control,openpc AS $$
BEGIN
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND
   (to_jsonb(NEW)-'selected') IS DISTINCT FROM (to_jsonb(OLD)-'selected')) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6004';
 END IF;
 IF NEW.selected AND (
   NOT openpc.runtime_configuration_bindings_current(NEW.participant_id,NEW.privacy_domain_id,NEW.resource_bindings)
   OR NOT EXISTS (
     SELECT 1 FROM control.module_configuration_generation c
       JOIN control.module_installation i ON i.module_installation_id=c.module_installation_id
       JOIN control.module_version v ON v.module_version_id=i.module_version_id
      WHERE c.generation_id=NEW.module_configuration_generation_id
        AND c.module_installation_id=NEW.module_installation_id
        AND c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
        AND i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id
        AND c.active AND i.state='ENABLED' AND i.lifecycle_operation_id IS NOT NULL
        AND v.module_id='pc.config.assets'
   )) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6007';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS runtime_configuration_input_guard ON control.runtime_configuration_input;
CREATE TRIGGER runtime_configuration_input_guard BEFORE INSERT OR UPDATE OR DELETE
 ON control.runtime_configuration_input FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_configuration_input();

-- A selected source is data only. Every consumer still needs its own approved
-- qualification/activation and this exact enabled module generation.
CREATE OR REPLACE VIEW control.runtime_configuration_input_current
 WITH (security_invoker=true) AS
 SELECT input.*,true AS active
 FROM control.runtime_configuration_input input
 JOIN control.module_configuration_generation c
   ON c.generation_id=input.module_configuration_generation_id
  AND c.module_installation_id=input.module_installation_id
  AND c.participant_id=input.participant_id AND c.privacy_domain_id=input.privacy_domain_id
 JOIN control.module_installation i ON i.module_installation_id=c.module_installation_id
  AND i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id
 JOIN control.module_version v ON v.module_version_id=i.module_version_id
 WHERE input.selected AND c.active AND i.state='ENABLED'
   AND i.lifecycle_operation_id IS NOT NULL AND v.module_id='pc.config.assets'
   AND openpc.runtime_configuration_bindings_current(input.participant_id,input.privacy_domain_id,input.resource_bindings);
REVOKE ALL ON control.runtime_configuration_input_current FROM PUBLIC;
GRANT SELECT ON control.runtime_configuration_input_current
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;


DROP POLICY IF EXISTS indexer_source_read_fence ON control.runtime_target;
CREATE POLICY indexer_source_read_fence ON control.runtime_target FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'));
DROP POLICY IF EXISTS indexer_source_read_fence ON control.runtime_configuration_generation;
CREATE POLICY indexer_source_read_fence ON control.runtime_configuration_generation FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'));
DROP POLICY IF EXISTS indexer_source_read_fence ON control.configuration_work;
CREATE POLICY indexer_source_read_fence ON control.configuration_work FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'));
DROP POLICY IF EXISTS indexer_source_read_fence ON control.projection_plan;
CREATE POLICY indexer_source_read_fence ON control.projection_plan FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'));
DROP POLICY IF EXISTS indexer_source_read_fence ON control.indexer_profile;
CREATE POLICY indexer_source_read_fence ON control.indexer_profile FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'));
DROP POLICY IF EXISTS indexer_source_read_fence ON control.provider_profile;
CREATE POLICY indexer_source_read_fence ON control.provider_profile FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'));
DROP POLICY IF EXISTS indexer_source_read_fence ON control.provider_probe_observation;
CREATE POLICY indexer_source_read_fence ON control.provider_probe_observation FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'));
DROP POLICY IF EXISTS indexer_source_read_fence ON control.runtime_configuration_input;
CREATE POLICY indexer_source_read_fence ON control.runtime_configuration_input FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'));
DROP POLICY IF EXISTS indexer_source_read_fence ON control.runtime_activation_observation;
CREATE POLICY indexer_source_read_fence ON control.runtime_activation_observation FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'));
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.runtime_target;
CREATE POLICY indexer_source_lock_fence ON control.runtime_target FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')) WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.runtime_configuration_generation;
CREATE POLICY indexer_source_lock_fence ON control.runtime_configuration_generation FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')) WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.configuration_work;
CREATE POLICY indexer_source_lock_fence ON control.configuration_work FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')) WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.projection_plan;
CREATE POLICY indexer_source_lock_fence ON control.projection_plan FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')) WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.indexer_profile;
CREATE POLICY indexer_source_lock_fence ON control.indexer_profile FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')) WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.provider_profile;
CREATE POLICY indexer_source_lock_fence ON control.provider_profile FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')) WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.provider_probe_observation;
CREATE POLICY indexer_source_lock_fence ON control.provider_probe_observation FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')) WITH CHECK(false);
DROP POLICY IF EXISTS indexer_source_lock_fence ON control.runtime_configuration_input;
CREATE POLICY indexer_source_lock_fence ON control.runtime_configuration_input FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')) WITH CHECK(false);
CREATE OR REPLACE FUNCTION openpc.lock_indexer_dispatch_source(p_target_id uuid, p_capsule_digest text)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
DECLARE v_source_id uuid; v_plan_id uuid; v_provider_id uuid; v_configuration_digest text;
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_READ_RPC-V1'
   OR p_capsule_digest !~ '^sha256:[0-9a-f]{64}$' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-INDEXER-SOURCE';
 END IF;
 PERFORM openpc.lock_cigl_publication_participant();
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||
   openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0));
 SELECT generation.projection_plan_id,generation.provider_profile_id,work.configuration_digest
  INTO STRICT v_plan_id,v_provider_id,v_configuration_digest
 FROM control.runtime_target target
 JOIN control.runtime_activation_observation observation
  ON observation.runtime_target_id=target.runtime_target_id
   AND observation.participant_id=target.participant_id AND observation.privacy_domain_id=target.privacy_domain_id
   AND observation.capsule_digest=target.active_generation_digest
 JOIN control.runtime_configuration_generation generation
  ON generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
   AND generation.participant_id=target.participant_id AND generation.privacy_domain_id=target.privacy_domain_id
   AND generation.runtime_target_id=target.runtime_target_id AND generation.generation_digest=observation.generation_digest
 JOIN control.configuration_work work ON work.configuration_work_id=observation.configuration_work_id
  AND work.participant_id=target.participant_id AND work.privacy_domain_id=target.privacy_domain_id
  AND work.runtime_target_id=target.runtime_target_id
  AND work.runtime_configuration_generation_id=generation.runtime_configuration_generation_id
  AND work.generation_digest=generation.generation_digest
  AND work.policy_generation_digest=generation.policy_generation_digest
  AND work.predecessor_digest IS NOT DISTINCT FROM generation.predecessor_digest
  AND work.xds_version_digest=observation.xds_version_digest
  AND work.operation_id=observation.operation_id AND work.execution_attempt_id=observation.execution_attempt_id
  AND work.result_receipt_digest=observation.activation_receipt_digest
 WHERE target.runtime_target_id=p_target_id
  AND openpc.matches_participant(target.participant_id) AND openpc.matches_privacy(target.privacy_domain_id)
  AND target.state='ACTIVE_MATCHED' AND target.active_generation_digest=p_capsule_digest
  AND target.desired_generation_digest=p_capsule_digest AND target.xds_version_digest=observation.xds_version_digest
  AND target.policy_generation_digest=generation.policy_generation_digest
  AND generation.state='ACTIVE' AND work.state='COMPLETED' AND work.work_kind='RUNTIME_ACTIVATION'
  AND work.execution_started_at IS NOT NULL
 FOR SHARE OF target,generation,work;
 SELECT projection.indexer_profile_id INTO STRICT v_source_id FROM control.projection_plan projection
 WHERE projection.projection_plan_id=v_plan_id
  AND openpc.matches_participant(projection.participant_id) AND openpc.matches_privacy(projection.privacy_domain_id)
 FOR SHARE;
 PERFORM 1 FROM control.indexer_profile source WHERE source.indexer_profile_id=v_source_id
  AND openpc.matches_participant(source.participant_id) AND openpc.matches_privacy(source.privacy_domain_id)
 FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-INDEXER-SOURCE'; END IF;
 PERFORM 1 FROM control.provider_profile provider
 JOIN control.provider_probe_observation observation ON observation.observation_id=provider.qualification_observation_id
  AND observation.provider_profile_id=provider.provider_profile_id
  AND observation.participant_id=provider.participant_id AND observation.privacy_domain_id=provider.privacy_domain_id
 WHERE provider.provider_profile_id=v_provider_id
  AND openpc.matches_participant(provider.participant_id) AND openpc.matches_privacy(provider.privacy_domain_id)
 FOR SHARE OF provider,observation;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-INDEXER-SOURCE'; END IF;
 PERFORM 1 FROM control.runtime_configuration_input input
 WHERE openpc.matches_participant(input.participant_id) AND openpc.matches_privacy(input.privacy_domain_id)
  AND input.configuration_digest=decode(substr(v_configuration_digest,8),'hex') AND input.selected
 FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-INDEXER-SOURCE'; END IF;
 RETURN v_plan_id;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_indexer_dispatch_source(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_indexer_dispatch_source(uuid,text) TO openpc_control_reader;

-- One qualification owner for publication and each provider used by dispatch.
-- Holding all three rows prevents replacement of the live observation or its
-- completed qualification while the caller consumes it. Expiry is still a
-- time bound and must be enforced before I/O and again before response release.
CREATE OR REPLACE FUNCTION openpc.lock_indexer_qualified_provider(p_provider_id uuid,p_artifact_digest text)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
DECLARE expiry_ns bigint;
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF openpc.current_action_intent_id() NOT IN ('ACT-RUNTIME_READ_RPC-V1','ACT-CANDIDATE_WRITE-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')
  OR p_artifact_digest !~ '^sha256:[0-9a-f]{64}$' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-INDEXER-PROVIDER';
 END IF;
 SELECT (extract(epoch from observation.valid_until)*1000000000)::bigint INTO STRICT expiry_ns
 FROM control.provider_profile provider
 JOIN control.provider_probe_observation observation ON observation.observation_id=provider.qualification_observation_id
  AND observation.provider_profile_id=provider.provider_profile_id
  AND observation.participant_id=provider.participant_id AND observation.privacy_domain_id=provider.privacy_domain_id
 JOIN control.configuration_work qualification ON qualification.resource_id=provider.provider_profile_id
  AND qualification.participant_id=provider.participant_id AND qualification.privacy_domain_id=provider.privacy_domain_id
  AND qualification.work_kind='PROVIDER_QUALIFICATION' AND qualification.state='COMPLETED'
 WHERE provider.provider_profile_id=p_provider_id AND provider.behavior_fingerprint=p_artifact_digest
  AND openpc.matches_participant(provider.participant_id) AND openpc.matches_privacy(provider.privacy_domain_id)
  AND provider.state IN ('QUALIFIED','ACTIVE') AND provider.revision=observation.observed_revision+2
  AND observation.state='OBSERVED' AND observation.input_digest=provider.behavior_fingerprint
  AND observation.observation_id::text=qualification.result_receipt->>'liveObservationId'
  AND observation.observation_digest=qualification.result_receipt->>'liveObservationDigest'
  AND observation.observation=qualification.result_receipt->'liveObservation'
  AND qualification.result_receipt->>'artifactDigest'=provider.behavior_fingerprint
  AND observation.valid_until>clock_timestamp()
 FOR SHARE OF provider,observation,qualification;
 RETURN expiry_ns;
EXCEPTION WHEN NO_DATA_FOUND THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_indexer_qualified_provider(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_indexer_qualified_provider(uuid,text) TO openpc_control_reader,openpc_control_worker;

-- FactBridge holds the current source owners through the separate fact-store
-- commit. Candidate publication is asynchronous and cannot establish this fence.
DROP POLICY IF EXISTS fact_source_participant_read ON control.participant;
CREATE POLICY fact_source_participant_read ON control.participant FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1');
DROP POLICY IF EXISTS fact_source_participant_lock ON control.participant;
CREATE POLICY fact_source_participant_lock ON control.participant FOR UPDATE TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1') WITH CHECK(false);
-- Custody only, not authorization. The FactBridge owner authenticates before
-- taking this root lock, then rechecks exact signed permission dependencies.
CREATE OR REPLACE FUNCTION openpc.lock_fact_workload_context()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-FACT-SOURCE';
 END IF;
 PERFORM 1 FROM control.participant
  WHERE participant_id=openpc.current_participant_id() AND state='ACTIVE' AND archived_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-FACT-SOURCE'; END IF;
 PERFORM 1 FROM control.privacy_domain WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-FACT-SOURCE'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_fact_workload_context() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_fact_workload_context() TO openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.lock_fact_candidate_source(p_plan_id uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
DECLARE v_source_id uuid;
BEGIN
 PERFORM openpc.lock_fact_workload_context();
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||
   openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0));
 SELECT projection.indexer_profile_id INTO STRICT v_source_id FROM control.projection_plan projection
  WHERE projection.projection_plan_id=p_plan_id
   AND openpc.matches_participant(projection.participant_id) AND openpc.matches_privacy(projection.privacy_domain_id)
   AND projection.state='VALIDATED' AND projection.readiness='READY'
  FOR SHARE;
 PERFORM 1 FROM control.indexer_profile source WHERE source.indexer_profile_id=v_source_id
  AND openpc.matches_participant(source.participant_id) AND openpc.matches_privacy(source.privacy_domain_id)
  AND source.state IN ('QUALIFIED','ACTIVE') FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-FACT-SOURCE'; END IF;
 PERFORM 1 FROM control.runtime_configuration_input input
  WHERE openpc.matches_participant(input.participant_id) AND openpc.matches_privacy(input.privacy_domain_id)
   AND input.selected FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-FACT-SOURCE'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_fact_candidate_source(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_fact_candidate_source(uuid) TO openpc_control_reader;

DROP POLICY IF EXISTS fact_contract_read_fence ON control.contract_runtime_binding;
CREATE POLICY fact_contract_read_fence ON control.contract_runtime_binding FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1');
DROP POLICY IF EXISTS fact_contract_lock_fence ON control.contract_runtime_binding;
CREATE POLICY fact_contract_lock_fence ON control.contract_runtime_binding FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1') WITH CHECK(false);
DROP POLICY IF EXISTS fact_contract_read_fence ON control.abi_artifact;
CREATE POLICY fact_contract_read_fence ON control.abi_artifact FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1');
DROP POLICY IF EXISTS fact_contract_lock_fence ON control.abi_artifact;
CREATE POLICY fact_contract_lock_fence ON control.abi_artifact FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1') WITH CHECK(false);
DROP POLICY IF EXISTS fact_contract_read_fence ON control.logical_contract_asset;
CREATE POLICY fact_contract_read_fence ON control.logical_contract_asset FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1');
DROP POLICY IF EXISTS fact_contract_lock_fence ON control.logical_contract_asset;
CREATE POLICY fact_contract_lock_fence ON control.logical_contract_asset FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1') WITH CHECK(false);
DROP POLICY IF EXISTS fact_contract_read_fence ON control.privacy_domain;
CREATE POLICY fact_contract_read_fence ON control.privacy_domain FOR SELECT TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1');
DROP POLICY IF EXISTS fact_contract_lock_fence ON control.privacy_domain;
CREATE POLICY fact_contract_lock_fence ON control.privacy_domain FOR UPDATE TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id()='ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1') WITH CHECK(false);
CREATE OR REPLACE FUNCTION openpc.lock_fact_contract_binding(p_binding_id uuid)
RETURNS TABLE(binding_revision bigint,chain_id text,network_id text,genesis_digest text,
 contract_address text,code_digest text,proxy_address text,implementation_address text,
 implementation_code_digest text,abi_artifact_id uuid,abi_version text,abi_digest text,canonical_abi_bytes bytea)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF openpc.current_action_intent_id()<>'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-FACT-CONTRACT';
 END IF;
 RETURN QUERY SELECT binding.revision,binding.chain_id,binding.network_id,binding.genesis_digest,
  binding.contract_address,binding.code_digest,binding.proxy_address,binding.implementation_address,
  binding.implementation_code_digest,binding.abi_artifact_id,binding.abi_version,abi.abi_digest,abi.canonical_abi_bytes
 FROM control.contract_runtime_binding binding
 JOIN control.abi_artifact abi ON abi.abi_artifact_id=binding.abi_artifact_id
  AND abi.participant_id=binding.participant_id AND abi.privacy_domain_id=binding.privacy_domain_id
 JOIN control.logical_contract_asset asset ON asset.logical_contract_id=binding.logical_contract_id
  AND asset.participant_id=binding.participant_id AND asset.privacy_domain_id=binding.privacy_domain_id
 WHERE binding.runtime_binding_id=p_binding_id AND binding.state='BOUND'
  AND binding.quarantined_at IS NULL AND octet_length(abi.canonical_abi_bytes) BETWEEN 2 AND 131072
  AND openpc.matches_participant(binding.participant_id) AND openpc.matches_privacy(binding.privacy_domain_id)
 FOR SHARE OF binding,abi,asset;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-FACT-CONTRACT'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_fact_contract_binding(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_fact_contract_binding(uuid) TO openpc_control_reader;

REVOKE ALL ON "control"."privacy_explorer_profile", "control"."privacy_explorer_execution", "control"."privacy_explorer_continuation", "control"."privacy_explorer_route_audit", "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."runtime_target_connection", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_configuration_input", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."cigl_analysis", "control"."cigl_method_profile", "control"."cigl_profile_version", "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source", "control"."cigl_profile_dependency_path", "control"."cigl_method_grant_dependency_claims", "control"."deployment_result", "control"."contract_governance_association" FROM PUBLIC;
REVOKE ALL ON "control"."privacy_explorer_profile", "control"."privacy_explorer_execution", "control"."privacy_explorer_continuation", "control"."privacy_explorer_route_audit", "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."runtime_target_connection", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_configuration_input", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."cigl_analysis", "control"."cigl_method_profile", "control"."cigl_profile_version", "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source", "control"."cigl_profile_dependency_path", "control"."cigl_method_grant_dependency_claims", "control"."deployment_result", "control"."contract_governance_association" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON "control"."privacy_explorer_profile", "control"."privacy_explorer_execution", "control"."privacy_explorer_continuation", "control"."privacy_explorer_route_audit", "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."deployment_policy", "control"."deployment_intent" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_activation_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_target_connection" TO "openpc_control_runtime";
GRANT SELECT ON "control"."provider_probe_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_route_publication" TO "openpc_control_runtime";
GRANT SELECT ON "control"."deployment_address_reservation" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."native_value_authorization" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_settings" TO "openpc_control_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_method_access_grants" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_grant_history" TO "openpc_control_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_analysis" TO "openpc_control_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_method_profile" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_profile_version" TO "openpc_control_runtime";
GRANT SELECT ON "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source" TO "openpc_control_runtime";
GRANT UPDATE ON "control"."cigl_profile_version" TO "openpc_control_worker";
GRANT INSERT ON "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source" TO "openpc_control_worker";
GRANT SELECT ON "control"."cigl_profile_dependency_path" TO "openpc_control_runtime";
GRANT INSERT ON "control"."cigl_profile_dependency_path" TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_method_grant_dependency_claims" TO "openpc_control_runtime";
GRANT SELECT ON "control"."deployment_result", "control"."contract_governance_association" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_configuration_input" TO "openpc_control_runtime";
GRANT INSERT ON "control"."runtime_configuration_input" TO "openpc_control_worker";
GRANT UPDATE (selected) ON "control"."runtime_configuration_input" TO "openpc_control_worker";
GRANT SELECT ON "control"."privacy_explorer_profile", "control"."privacy_explorer_execution", "control"."privacy_explorer_continuation", "control"."privacy_explorer_route_audit", "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."runtime_target_connection", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_configuration_input", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."cigl_analysis", "control"."cigl_method_profile", "control"."cigl_profile_version", "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source", "control"."cigl_profile_dependency_path", "control"."cigl_method_grant_dependency_claims", "control"."deployment_result", "control"."contract_governance_association" TO "openpc_control_worker";
GRANT UPDATE ON "control"."privacy_explorer_profile", "control"."privacy_explorer_execution", "control"."privacy_explorer_continuation", "control"."privacy_explorer_route_audit", "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."deployment_policy", "control"."deployment_intent" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."runtime_target_connection" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_route_publication" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."provider_probe_observation" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."deployment_address_reservation" TO "openpc_control_worker";
GRANT INSERT ON "control"."deployment_result" TO "openpc_control_worker";
GRANT SELECT ON "control"."privacy_explorer_profile", "control"."privacy_explorer_execution", "control"."privacy_explorer_continuation", "control"."privacy_explorer_route_audit", "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_administration_transfer", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."runtime_target_connection", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_configuration_input", "control"."runtime_activation_observation", "control"."runtime_route_publication", "control"."deployment_address_reservation", "control"."deployment_address_claim", "control"."deployment_policy", "control"."deployment_intent", "control"."native_value_authorization", "control"."cigl_settings", "control"."cigl_method_access_grants", "control"."cigl_grant_history", "control"."cigl_analysis", "control"."cigl_method_profile", "control"."cigl_profile_version", "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source", "control"."cigl_profile_dependency_path", "control"."cigl_method_grant_dependency_claims", "control"."deployment_result", "control"."contract_governance_association" TO "openpc_control_reader";
CREATE OR REPLACE FUNCTION openpc.reject_runtime_activation_observation_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
DROP TRIGGER IF EXISTS runtime_activation_observation_immutable ON "control"."runtime_activation_observation";
CREATE TRIGGER runtime_activation_observation_immutable BEFORE UPDATE OR DELETE ON "control"."runtime_activation_observation"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_runtime_activation_observation_mutation();
DROP TRIGGER IF EXISTS runtime_route_publication_immutable ON "control"."runtime_route_publication";
CREATE TRIGGER runtime_route_publication_immutable BEFORE UPDATE OR DELETE ON "control"."runtime_route_publication"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_runtime_activation_observation_mutation();
CREATE OR REPLACE FUNCTION openpc.guard_provider_probe_observation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP='DELETE' OR OLD.state<>'RUNNING' OR
    ROW(NEW.observation_id,NEW.participant_id,NEW.privacy_domain_id,NEW.provider_profile_id,
        NEW.source_revision,NEW.input_digest,NEW.configuration_digest,NEW.created_at)
    IS DISTINCT FROM
    ROW(OLD.observation_id,OLD.participant_id,OLD.privacy_domain_id,OLD.provider_profile_id,
        OLD.source_revision,OLD.input_digest,OLD.configuration_digest,OLD.created_at) THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='DATA-6020-IMMUTABLE-ROW';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS provider_probe_observation_guard ON "control"."provider_probe_observation";
CREATE TRIGGER provider_probe_observation_guard BEFORE UPDATE OR DELETE ON "control"."provider_probe_observation"
FOR EACH ROW EXECUTE FUNCTION openpc.guard_provider_probe_observation();

INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1','evidence-records','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_RECORDS'),
 ('ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1','evidence-records','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_RECORDS')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE action_intent_id IN
 ('ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1','ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1')
 AND (resource_type,operation_class,risk_class,maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
 = ('evidence-records','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_RECORDS'))<>2 THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-ACTION'; END IF;
END $$;
ALTER TABLE control.evidence_stream FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_segment FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_catalogue FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_checkpoint FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_stream,control.evidence_segment,control.evidence_catalogue,control.evidence_checkpoint FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.evidence_stream,control.evidence_catalogue,control.evidence_checkpoint TO openpc_control_runtime,openpc_control_reader;
GRANT SELECT,INSERT ON control.evidence_stream,control.evidence_segment,control.evidence_catalogue,control.evidence_checkpoint TO openpc_control_worker;
GRANT UPDATE ON control.evidence_stream TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_custody()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE head control.evidence_stream%ROWTYPE; segment control.evidence_segment%ROWTYPE;
 prior control.evidence_checkpoint%ROWTYPE; expected jsonb; payload_size integer;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND TG_TABLE_NAME<>'evidence_stream') THEN
  RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW';
 END IF;
 IF TG_TABLE_NAME='evidence_stream' AND TG_OP='UPDATE'
  AND current_setting('openpc.action_intent_id') IN ('ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1','ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1') THEN
  PERFORM openpc.assert_evidence_deletion_accounting(OLD,NEW);
  RETURN NEW;
 END IF;
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN
  RAISE EXCEPTION 'PC-AUTH-0005';
 END IF;
 IF TG_TABLE_NAME='evidence_stream' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
  IF TG_OP='INSERT' THEN
   IF NEW.last_sequence<>0 OR NEW.last_segment_digest IS NOT NULL OR NEW.used_bytes<>0 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSE
   IF (to_jsonb(NEW)-ARRAY['last_sequence','last_segment_digest','used_bytes']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['last_sequence','last_segment_digest','used_bytes']) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   SELECT * INTO segment FROM control.evidence_segment WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND first_sequence=OLD.last_sequence+1;
   IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   SELECT octet_length(p.encrypted_segment) INTO payload_size FROM control.evidence_segment_payload p
    WHERE p.participant_id=segment.participant_id AND p.privacy_domain_id=segment.privacy_domain_id
     AND p.stream_id=segment.stream_id AND p.segment_id=segment.segment_id;
   IF NOT FOUND OR NEW.last_sequence<>segment.through_sequence OR NEW.last_segment_digest<>segment.object_digest
    OR NEW.used_bytes<>OLD.used_bytes+payload_size THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO head FROM control.evidence_stream WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_TABLE_NAME='evidence_segment' THEN
  IF NEW.first_sequence<>head.last_sequence+1 OR NEW.previous_segment_digest IS DISTINCT FROM head.last_segment_digest
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.admitted_at:=clock_timestamp();
 ELSIF TG_TABLE_NAME='evidence_catalogue' THEN
  SELECT * INTO segment FROM control.evidence_segment WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND segment_id=NEW.segment_id;
  IF NOT FOUND OR NEW.sequence NOT BETWEEN segment.first_sequence AND segment.through_sequence THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSE
  SELECT * INTO segment FROM control.evidence_segment WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND segment_id=NEW.segment_id;
  IF NOT FOUND OR NEW.through_sequence<>segment.through_sequence OR NEW.object_digest<>segment.object_digest THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO prior FROM control.evidence_checkpoint WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND sink_id=NEW.sink_id ORDER BY through_sequence DESC LIMIT 1;
  IF segment.first_sequence<>coalesce(prior.through_sequence,0)+1 OR NEW.previous_checkpoint_digest IS DISTINCT FROM prior.checkpoint_digest THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  expected:=jsonb_build_object('object',jsonb_build_object('participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,
   'streamId',NEW.stream_id,'sinkId',NEW.sink_id,'segmentId',NEW.segment_id::text,'objectDigest',NEW.object_digest,
   'firstSequence',segment.first_sequence::text,'throughSequence',segment.through_sequence::text,'previousSegmentDigest',segment.previous_segment_digest,
   'keyId',segment.key_id,'retentionUntil',to_char(segment.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
   'versionId',NEW.object_digest,'assurance','LOCAL_FSYNC_READBACK');
  IF NEW.receipt-'receiptDigest' IS DISTINCT FROM expected OR NEW.receipt->>'receiptDigest' IS DISTINCT FROM NEW.receipt_digest
   OR NEW.receipt_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  expected:=jsonb_build_object('participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,
   'streamId',NEW.stream_id,'sinkId',NEW.sink_id,'segmentId',NEW.segment_id::text,'throughSequence',NEW.through_sequence::text,
   'objectDigest',NEW.object_digest,'previousCheckpointDigest',NEW.previous_checkpoint_digest,'receiptDigest',NEW.receipt_digest);
  IF NEW.checkpoint_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.acknowledged_at:=clock_timestamp();
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_stream_guard ON control.evidence_stream;
CREATE TRIGGER evidence_stream_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_stream FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_custody();
DROP TRIGGER IF EXISTS evidence_segment_guard ON control.evidence_segment;
CREATE TRIGGER evidence_segment_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_segment FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_custody();
DROP TRIGGER IF EXISTS evidence_catalogue_guard ON control.evidence_catalogue;
CREATE TRIGGER evidence_catalogue_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_catalogue FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_custody();
DROP TRIGGER IF EXISTS evidence_checkpoint_guard ON control.evidence_checkpoint;
CREATE TRIGGER evidence_checkpoint_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_checkpoint FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_custody();

INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1','evidence-exports','CREATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_UPDATE_RESOURCE-V1','evidence-exports','UPDATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_READ_COLLECTION-V1','evidence-exports','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_READ_RESOURCE-V1','evidence-exports','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORT_RECORDS-V1','evidence-export','EXPORT','HIGH',true,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','EXPORT_EVIDENCE_EXPORT')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
 (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
 ('ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1','evidence-exports','CREATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_UPDATE_RESOURCE-V1','evidence-exports','UPDATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_READ_COLLECTION-V1','evidence-exports','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_READ_RESOURCE-V1','evidence-exports','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORT_RECORDS-V1','evidence-export','EXPORT','HIGH',true,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','EXPORT_EVIDENCE_EXPORT')))<>5
 THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-EXPORT-ACTION'; END IF;
END $$;
ALTER TABLE control.evidence_export_selection FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_export_request FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_export_output FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_export_selection,control.evidence_export_request,control.evidence_export_output
 FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.evidence_export_selection,control.evidence_export_request,control.evidence_export_output
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.evidence_export_selection,control.evidence_export_request TO openpc_control_runtime;
GRANT UPDATE ON control.evidence_export_request TO openpc_control_runtime,openpc_control_worker;
GRANT INSERT ON control.evidence_export_output TO openpc_control_worker;
GRANT SELECT(participant_id,privacy_domain_id,stream_id,segment_id,object_digest)
 ON control.evidence_segment TO openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_export_selection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE actual jsonb; v_first_sequence numeric; v_last_sequence numeric;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 v_first_sequence:=(NEW.selection->'range'->>'fromSequence')::numeric;
 v_last_sequence:=(NEW.selection->'range'->>'throughSequence')::numeric;
 IF v_first_sequence IS NULL OR v_last_sequence IS NULL OR v_first_sequence<1 OR v_last_sequence<v_first_sequence
  OR v_last_sequence>18446744073709551615 OR v_last_sequence-v_first_sequence>=128
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 SELECT jsonb_agg(jsonb_build_object('evidenceId','urn:openpc:resource:'||c.evidence_id::text,
  'sourceRecordId',c.record_id,'segmentId',c.segment_id::text,'objectDigest',s.object_digest,
  'sequence',c.sequence::text,'evidenceClass',c.evidence_class,'recordDigest',c.receipt_digest,
  'occurredAt',to_char(c.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY c.sequence)
 INTO actual FROM control.evidence_catalogue c JOIN control.evidence_segment s USING(participant_id,privacy_domain_id,stream_id,segment_id)
 WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.stream_id=NEW.stream_id
  AND c.sequence BETWEEN v_first_sequence AND v_last_sequence;
 IF actual IS NULL OR jsonb_array_length(actual)<>v_last_sequence-v_first_sequence+1 OR
  NEW.selection IS DISTINCT FROM jsonb_build_object('version','OPENPC_EVIDENCE_EXPORT_SELECTION_V1',
   'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,
   'range',jsonb_build_object('streamId',NEW.stream_id,'fromSequence',v_first_sequence::text,
    'throughSequence',v_last_sequence::text,'redactionProfileId','pc.evidence.minimized-audit.v1'),'records',actual)
  OR NEW.request_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.selection),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_export_selection_guard ON control.evidence_export_selection;
CREATE TRIGGER evidence_export_selection_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_export_selection
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_export_selection();

CREATE OR REPLACE FUNCTION openpc.guard_evidence_export_request()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE action text; operation uuid; v_through_sequence numeric;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 action:=current_setting('openpc.action_intent_id'); operation:=current_setting('openpc.operation_id')::uuid;
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='INSERT' THEN
  IF action<>'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1' OR NEW.creation_operation_id<>operation
   OR NEW.last_operation_id<>operation OR NEW.state<>'REQUESTED' OR NEW.start_operation_id IS NOT NULL
   OR NEW.revision<>1 OR NEW.checkpoint<>0 OR NEW.output_digest IS NOT NULL OR NEW.last_error_code IS NOT NULL
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.created_at:=clock_timestamp(); NEW.updated_at:=NEW.created_at;
 ELSE
  IF NEW.revision<>OLD.revision+1 OR NEW.participant_id<>OLD.participant_id OR NEW.privacy_domain_id<>OLD.privacy_domain_id
   OR NEW.evidence_export_id<>OLD.evidence_export_id OR NEW.created_at<>OLD.created_at OR NEW.creation_operation_id<>OLD.creation_operation_id
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  IF action='ACT-EVIDENCE_EXPORTS_UPDATE_RESOURCE-V1' THEN
   IF OLD.state<>'REQUESTED' OR NEW.state<>'REQUESTED' OR NEW.request_digest=OLD.request_digest
    OR NEW.last_operation_id<>operation OR NEW.last_error_code IS NOT NULL
    OR (to_jsonb(NEW)-ARRAY['request_digest','stream_id','revision','updated_at','last_operation_id']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['request_digest','stream_id','revision','updated_at','last_operation_id'])
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSIF action='ACT-EVIDENCE_EXPORT_RECORDS-V1' AND OLD.state='REQUESTED' THEN
   IF NEW.state<>'RUNNING' OR NEW.last_operation_id<>operation OR NEW.start_operation_id<>operation
    OR (to_jsonb(NEW)-ARRAY['state','revision','updated_at','last_operation_id','start_operation_id']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['state','revision','updated_at','last_operation_id','start_operation_id'])
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSIF action='ACT-EVIDENCE_EXPORT_RECORDS-V1' AND pg_has_role(current_user,'openpc_control_worker','USAGE') THEN
   IF OLD.state NOT IN ('RUNNING','BACKLOGGED') OR NEW.state NOT IN ('SUCCEEDED','FAILED','BACKLOGGED')
    OR operation<>OLD.start_operation_id OR
    (to_jsonb(NEW)-ARRAY['state','revision','updated_at','checkpoint','output_digest','last_error_code']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['state','revision','updated_at','checkpoint','output_digest','last_error_code'])
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   IF NEW.state='SUCCEEDED' THEN
    SELECT (selection->'range'->>'throughSequence')::numeric INTO v_through_sequence FROM control.evidence_export_selection
     WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND request_digest=NEW.request_digest;
    IF NEW.checkpoint IS DISTINCT FROM v_through_sequence OR NEW.last_error_code IS NOT NULL OR NOT EXISTS
     (SELECT 1 FROM control.evidence_export_output WHERE evidence_export_id=NEW.evidence_export_id
       AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND output_digest=NEW.output_digest)
    THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   ELSIF NEW.last_error_code IS DISTINCT FROM 'PC-OPS-9002' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSE RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  NEW.updated_at:=clock_timestamp();
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_export_request_guard ON control.evidence_export_request;
CREATE TRIGGER evidence_export_request_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_export_request
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_export_request();

CREATE OR REPLACE FUNCTION openpc.require_evidence_export_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE action text; catalog text; expected numeric;
BEGIN
 IF TG_OP='UPDATE' AND OLD.state<>'REQUESTED' THEN RETURN NULL; END IF;
 IF TG_OP='INSERT' THEN action:='ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1';catalog:='CFG-OP-CREATE-EVIDENCE-EXPORT';expected:=0;
 ELSIF NEW.state='REQUESTED' THEN action:='ACT-EVIDENCE_EXPORTS_UPDATE_RESOURCE-V1';catalog:='CFG-OP-UPDATE-EVIDENCE-EXPORT';expected:=OLD.revision;
 ELSE action:='ACT-EVIDENCE_EXPORT_RECORDS-V1';catalog:='CFG-OP-START-EVIDENCE-EXPORT';expected:=OLD.revision; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence e JOIN control.idempotency_record i
  ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id AND i.operation_id=e.operation_id
   AND i.catalog_operation_id=e.catalog_operation_id AND i.input_digest=e.candidate_digest
  WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id
   AND e.operation_id=NEW.last_operation_id AND e.aggregate_type='evidence-export' AND e.aggregate_id=NEW.evidence_export_id
   AND e.catalog_operation_id=catalog AND e.action_intent_id=action AND i.terminal_state='COMMITTED'
   AND i.expected_aggregate_version=expected AND i.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.evidence_export_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=e.participant_id
    AND event.privacy_domain_id=e.privacy_domain_id AND event.aggregate_type=e.aggregate_type AND event.aggregate_id=e.aggregate_id
    AND event.event_type=CASE catalog WHEN 'CFG-OP-CREATE-EVIDENCE-EXPORT' THEN 'openpc.evidence.export.requested.v1'
      WHEN 'CFG-OP-UPDATE-EVIDENCE-EXPORT' THEN 'openpc.evidence.export.updated.v1' ELSE 'openpc.evidence.export.started.v1' END
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(e.candidate_digest,'hex')
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'revision'=NEW.revision::text
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'='sha256:'||encode(e.evidence_digest,'hex')
    AND event.payload_digest=sha256(event.payload_cbor))
   AND (NEW.state<>'RUNNING' OR EXISTS(SELECT 1 FROM control.mutation_candidate c
    WHERE c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
     AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
     AND c.action_intent_id=action AND c.catalog_operation_id=catalog AND c.operation_class='EXPORT'
     AND c.state='CONSUMED' AND c.candidate_document->>'inputDigest'=NEW.request_digest)))
 THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-EXPORT-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS evidence_export_command_required ON control.evidence_export_request;
CREATE CONSTRAINT TRIGGER evidence_export_command_required AFTER INSERT OR UPDATE ON control.evidence_export_request
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_export_command();

CREATE OR REPLACE FUNCTION openpc.guard_evidence_export_output()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE request control.evidence_export_request%ROWTYPE; v_selection jsonb; records jsonb; artifact jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','USAGE')
  OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT request FROM control.evidence_export_request WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND evidence_export_id=NEW.evidence_export_id FOR UPDATE;
 IF request.state NOT IN ('RUNNING','BACKLOGGED') OR request.start_operation_id<>current_setting('openpc.operation_id')::uuid
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT s.selection INTO STRICT v_selection FROM control.evidence_export_selection s WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND request_digest=request.request_digest;
 SELECT jsonb_agg(jsonb_build_object('evidenceId',r->>'evidenceId','sequence',r->>'sequence',
   'evidenceClass',r->>'evidenceClass','recordDigest',r->>'recordDigest','occurredAt',r->>'occurredAt',
   'segmentDigest',r->>'objectDigest','checkpointDigest',c.checkpoint_digest) ORDER BY (r->>'sequence')::numeric)
 INTO records FROM jsonb_array_elements(v_selection->'records') r JOIN control.evidence_checkpoint c
   ON c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.stream_id=NEW.stream_id
    AND c.segment_id=(r->>'segmentId')::uuid AND c.object_digest=r->>'objectDigest' AND c.sink_id=NEW.sink_id
    AND c.receipt->>'assurance'='LOCAL_FSYNC_READBACK';
 IF records IS NULL OR jsonb_array_length(records)<>jsonb_array_length(v_selection->'records')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 artifact:=jsonb_build_object('version','OPENPC_EVIDENCE_REDACTED_EXPORT_V1',
  'evidenceExportId','urn:openpc:resource:'||NEW.evidence_export_id::text,
  'participantId','urn:openpc:participant:'||NEW.participant_id::text,
  'privacyDomainId','urn:openpc:privacy-domain:'||NEW.privacy_domain_id::text,
  'requestDigest',request.request_digest,'range',v_selection->'range','sinkId',NEW.sink_id,
  'assurance','LOCAL_FSYNC_READBACK','records',records);
 IF NEW.artifact<>convert_to(openpc.signing_canonical_json(artifact),'UTF8')
  OR NEW.output_digest<>'sha256:'||encode(sha256(NEW.artifact),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_export_output_guard ON control.evidence_export_output;
CREATE TRIGGER evidence_export_output_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_export_output
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_export_output();

CREATE OR REPLACE FUNCTION openpc.require_evidence_export_completion()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.evidence_export_request r WHERE r.participant_id=NEW.participant_id
  AND r.privacy_domain_id=NEW.privacy_domain_id AND r.stream_id=NEW.stream_id AND r.evidence_export_id=NEW.evidence_export_id
  AND r.state='SUCCEEDED' AND r.output_digest=NEW.output_digest)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS evidence_export_completion_required ON control.evidence_export_output;
CREATE CONSTRAINT TRIGGER evidence_export_completion_required AFTER INSERT ON control.evidence_export_output
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_export_completion();



DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='control'
  AND table_name='evidence_segment' AND column_name='encrypted_segment') THEN
  ALTER TABLE control.evidence_segment NO FORCE ROW LEVEL SECURITY;
  EXECUTE 'INSERT INTO control.evidence_segment_payload(participant_id,privacy_domain_id,stream_id,segment_id,encrypted_segment)
   SELECT participant_id,privacy_domain_id,stream_id,segment_id,encrypted_segment FROM control.evidence_segment
   ON CONFLICT DO NOTHING';
  IF EXISTS(SELECT 1 FROM control.evidence_segment s LEFT JOIN control.evidence_segment_payload p
   USING(participant_id,privacy_domain_id,stream_id,segment_id)
   WHERE p.segment_id IS NULL OR s.encrypted_segment IS DISTINCT FROM p.encrypted_segment OR s.object_digest<>'sha256:'||encode(sha256(p.encrypted_segment),'hex')) THEN
   RAISE EXCEPTION 'PC-DATA-6004-PAYLOAD-MIGRATION';
  END IF;
  ALTER TABLE control.evidence_segment FORCE ROW LEVEL SECURITY;
 END IF;
END $$;
ALTER TABLE control.evidence_segment_payload FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_segment_payload FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT,INSERT ON control.evidence_segment_payload TO openpc_control_worker;
CREATE OR REPLACE FUNCTION openpc.guard_evidence_payload()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE segment control.evidence_segment%ROWTYPE; envelope jsonb; expected jsonb; head numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' THEN
  PERFORM openpc.record_evidence_payload_deletion(OLD);
  RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT segment FROM control.evidence_segment s WHERE s.participant_id=NEW.participant_id
  AND s.privacy_domain_id=NEW.privacy_domain_id AND s.stream_id=NEW.stream_id AND s.segment_id=NEW.segment_id;
 SELECT last_sequence INTO STRICT head FROM control.evidence_stream WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id FOR UPDATE;
 IF segment.first_sequence<=head THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF segment.object_digest<>'sha256:'||encode(sha256(NEW.encrypted_segment),'hex') THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 envelope:=convert_from(NEW.encrypted_segment,'UTF8')::jsonb;
 expected:=jsonb_build_object('version','OPENPC_EVIDENCE_SEGMENT_V1','participantId',segment.participant_id::text,
  'privacyDomainId',segment.privacy_domain_id::text,'streamId',segment.stream_id,'segmentId',segment.segment_id::text,
  'firstSequence',segment.first_sequence::text,'throughSequence',segment.through_sequence::text,'previousSegmentDigest',segment.previous_segment_digest,
  'keyId',segment.key_id,'retentionUntil',to_char(segment.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 IF envelope->'header' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_payload_guard ON control.evidence_segment_payload;
CREATE TRIGGER evidence_payload_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_segment_payload
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_payload();

DROP TRIGGER IF EXISTS evidence_payload_mirror ON control.evidence_segment;
DROP FUNCTION IF EXISTS openpc.mirror_legacy_evidence_payload();
CREATE OR REPLACE FUNCTION openpc.require_evidence_payload()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.evidence_segment_payload p WHERE p.participant_id=NEW.participant_id
  AND p.privacy_domain_id=NEW.privacy_domain_id AND p.stream_id=NEW.stream_id AND p.segment_id=NEW.segment_id
  AND NEW.object_digest='sha256:'||encode(sha256(p.encrypted_segment),'hex')) THEN
  RAISE EXCEPTION 'PC-DATA-6004-EVIDENCE-PAYLOAD';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS evidence_payload_required ON control.evidence_segment;
CREATE CONSTRAINT TRIGGER evidence_payload_required AFTER INSERT ON control.evidence_segment
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_payload();


ALTER TABLE control.evidence_deployment_lineage FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_deployment_lineage FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_deployment_lineage TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.evidence_deployment_lineage TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.evidence_deployment_lineage_projection(source control.evidence_catalogue)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE r record; claims jsonb; occurrence jsonb; invalidation jsonb; historical jsonb;
BEGIN
 IF (source).evidence_class<>'EFFECT' OR (source).source_format<>'PC-DEPLOYMENT-JOURNAL-PROJECTION-1'
  OR (source).record_id!~'^deployment:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:[1-9][0-9]{0,19}$' THEN RETURN NULL; END IF;
 SELECT d.signed_bytes,d.result_digest,d.sequence,a.* INTO r
  FROM control.deployment_result d JOIN control.deployment_address_reservation a
   ON a.participant_id=d.participant_id AND a.privacy_domain_id=d.privacy_domain_id AND a.command_id=d.command_id
  WHERE d.participant_id=(source).participant_id AND d.privacy_domain_id=(source).privacy_domain_id
   AND d.command_id=split_part((source).record_id,':',2)::uuid AND d.sequence=split_part((source).record_id,':',3)::numeric
   AND d.result_digest=(source).receipt_digest AND d.result_digest='sha256:'||encode(sha256(d.signed_bytes),'hex')
   AND a.state='HANDOFF';
 IF NOT FOUND THEN RETURN NULL; END IF;
 claims:=convert_from(r.signed_bytes,'UTF8')::jsonb;
 IF claims->>'purpose' IS DISTINCT FROM 'openpc:deployment-journal-projection:v1' THEN RETURN NULL; END IF;
 claims:=claims->'claims';
 IF claims->>'schema' IS DISTINCT FROM (source).source_format
  OR claims->>'sequence' IS DISTINCT FROM r.sequence::text
  OR (regexp_replace(claims->>'observedAt','([.][0-9]{6})[0-9]+',chr(92)||'1'))::timestamptz IS DISTINCT FROM (source).occurred_at
  OR claims->'owner'->>'participant_id' IS DISTINCT FROM (source).participant_id::text
  OR claims->'owner'->>'privacy_domain_id' IS DISTINCT FROM (source).privacy_domain_id::text
  OR claims->'status'->>'operationId' IS DISTINCT FROM 'urn:openpc:operation:'||r.command_id::text
  OR claims->'status'->>'attemptId' IS DISTINCT FROM r.attempt_id::text
  OR claims->>'targetRuntimeId' IS DISTINCT FROM replace(r.target_runtime_id,'urn:openpc:resource:','')
  OR claims->>'intentDigest' IS DISTINCT FROM substring(r.intent_digest from 8)
  OR claims->>'preparationDigest' IS DISTINCT FROM substring(r.prepared_record_digest from 8)
  OR claims->>'chainId' IS DISTINCT FROM r.chain_id
  OR claims->>'genesisDigest' IS DISTINCT FROM substring(r.genesis_digest from 8)
  OR claims->'status'->>'signedTransactionHash' IS DISTINCT FROM r.transaction_hash THEN RETURN NULL; END IF;
 occurrence:=claims->'outcome'->'occurrence'; invalidation:=claims->'outcome'->'invalidation';
 historical:=jsonb_build_object('sourceVersion',r.sequence::text,'receiptDigest',r.result_digest,
  'observedAt',claims->>'observedAt','state',claims->'status'->>'state','truthState',claims->'status'->>'truthState',
  'journalEvidenceDigest',claims->'status'->>'evidenceDigest',
  'finality',CASE WHEN invalidation<>'null'::jsonb THEN CASE WHEN invalidation->>'reason'='REORG' THEN 'REORG' ELSE 'INVALIDATED' END
    WHEN occurrence<>'null'::jsonb THEN 'FINALIZED' ELSE 'NOT_ESTABLISHED' END,
  'occurrence',CASE WHEN occurrence='null'::jsonb THEN 'null'::jsonb ELSE jsonb_build_object(
   'occurrenceId',occurrence->>'occurrenceId','occurrenceDigest','sha256:'||(occurrence->>'semanticDigest'),
   'blockHash','sha256:'||(occurrence->>'blockHash'),'blockNumber',occurrence->>'blockNumber','reorgStatus',occurrence->>'reorgStatus') END,
  'invalidation',CASE WHEN invalidation='null'::jsonb THEN 'null'::jsonb ELSE jsonb_build_object(
   'occurrenceId',invalidation->>'occurrenceId','occurrenceDigest','sha256:'||(invalidation->>'occurrenceDigest'),
   'observationDigest','sha256:'||(invalidation->>'observationDigest'),'reason',invalidation->>'reason') END);
 RETURN jsonb_build_object('chainId',r.chain_id,'genesisDigest',r.genesis_digest,'historical',historical);
EXCEPTION WHEN insufficient_privilege OR invalid_text_representation OR datetime_field_overflow THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_deployment_lineage_projection(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deployment_lineage_projection(control.evidence_catalogue) TO openpc_control_worker,openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_deployment_lineage()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT openpc.evidence_deployment_lineage_projection(c) INTO expected FROM control.evidence_catalogue c
  WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.stream_id=NEW.stream_id AND c.record_id=NEW.record_id;
 IF expected IS NULL OR NEW.projection IS DISTINCT FROM expected
  OR NEW.projection_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_deployment_lineage_guard ON control.evidence_deployment_lineage;
CREATE TRIGGER evidence_deployment_lineage_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_deployment_lineage
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_deployment_lineage();


CREATE OR REPLACE FUNCTION openpc.evidence_hold_selector_encoding(selector jsonb,participant uuid,privacy uuid)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE kind text:=selector->>'type'; expected jsonb:=jsonb_build_object('type',kind);
 encoded jsonb:=jsonb_build_object('0','pc.evidence.hold-selector.v1','1',openpc.business_uuid(participant),
 '2',openpc.business_uuid(privacy),'3',kind); first_value numeric; last_value numeric; generation jsonb;
 resource_pattern text:='^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
 profile_pattern text:=replace(resource_pattern,':resource:',':fact-profile:');
BEGIN
 IF participant IS NULL OR privacy IS NULL OR jsonb_typeof(selector) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF kind='SEQUENCE_RANGE' THEN
  IF coalesce(selector->>'streamId','')!~'^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$'
   OR coalesce(selector->>'fromSequence','')!~'^[1-9][0-9]{0,19}$' OR NOT(selector ? 'throughSequence') THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  first_value:=(selector->>'fromSequence')::numeric;
  encoded:=encoded||jsonb_build_object('4',selector->>'streamId','5',first_value,'6',CASE WHEN selector->'throughSequence'='null'::jsonb THEN 0 ELSE 1 END);
  IF selector->'throughSequence'<>'null'::jsonb THEN
   IF coalesce(selector->>'throughSequence','')!~'^[1-9][0-9]{0,19}$' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
   last_value:=(selector->>'throughSequence')::numeric; encoded:=encoded||jsonb_build_object('7',last_value);
  END IF;
  expected:=expected||jsonb_build_object('streamId',selector->>'streamId','fromSequence',first_value::text,'throughSequence',last_value::text);
 ELSIF kind='DIGEST' THEN
  IF coalesce(selector->>'recordDigest','')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  expected:=expected||jsonb_build_object('recordDigest',selector->>'recordDigest');
  encoded:=encoded||jsonb_build_object('4',openpc.business_bytes(decode(substring(selector->>'recordDigest' from 8),'hex')));
 ELSIF kind='PROJECTION' THEN
  IF coalesce(selector->>'projectionId','')!~resource_pattern THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  expected:=expected||jsonb_build_object('projectionId',selector->>'projectionId');
  encoded:=encoded||jsonb_build_object('4',openpc.business_uuid(right(selector->>'projectionId',36)::uuid));
 ELSIF kind='FACT_TYPE_KEY' THEN
  IF coalesce(selector->>'factType','') NOT IN ('CONTRACT_STATE_CALL','RELATIONSHIP','EXTERNAL_DECISION')
   OR coalesce(selector->>'factProfileId','')!~profile_pattern OR NOT(selector ? 'factKeyDigest')
   OR (selector->'factKeyDigest'<>'null'::jsonb AND coalesce(selector->>'factKeyDigest','')!~'^sha256:[0-9a-f]{64}$') THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  expected:=expected||jsonb_build_object('factType',selector->>'factType','factProfileId',selector->>'factProfileId','factKeyDigest',selector->'factKeyDigest');
  encoded:=encoded||jsonb_build_object('4',selector->>'factType','5',selector->>'factProfileId','6',CASE WHEN selector->'factKeyDigest'='null'::jsonb THEN 0 ELSE 1 END);
  IF selector->'factKeyDigest'<>'null'::jsonb THEN encoded:=encoded||jsonb_build_object('7',openpc.business_bytes(decode(substring(selector->>'factKeyDigest' from 8),'hex'))); END IF;
 ELSIF kind='BLOCK_RANGE' THEN
  IF coalesce(selector->>'chainId','')!~'^(0|[1-9][0-9]{0,77})$' OR (selector->>'chainId')::numeric>=power(2::numeric,256)
   OR coalesce(selector->>'genesisDigest','')!~'^sha256:[0-9a-f]{64}$'
   OR coalesce(selector->>'fromBlock','')!~'^(0|[1-9][0-9]{0,19})$' OR NOT(selector ? 'throughBlock') THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  first_value:=(selector->>'fromBlock')::numeric;
  encoded:=encoded||jsonb_build_object('4',selector->>'chainId','5',openpc.business_bytes(decode(substring(selector->>'genesisDigest' from 8),'hex')),
   '6',first_value,'7',CASE WHEN selector->'throughBlock'='null'::jsonb THEN 0 ELSE 1 END);
  IF selector->'throughBlock'<>'null'::jsonb THEN
   IF coalesce(selector->>'throughBlock','')!~'^(0|[1-9][0-9]{0,19})$' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
   last_value:=(selector->>'throughBlock')::numeric; encoded:=encoded||jsonb_build_object('8',last_value);
  END IF;
  expected:=expected||jsonb_build_object('chainId',selector->>'chainId','genesisDigest',selector->>'genesisDigest','fromBlock',first_value::text,'throughBlock',last_value::text);
 ELSIF kind='GENERATION' THEN
  generation:=selector->'generation';
  IF generation->>'kind'='RUNTIME_CONFIGURATION' THEN
   IF coalesce(generation->>'generationId','')!~resource_pattern OR generation IS DISTINCT FROM jsonb_build_object('kind','RUNTIME_CONFIGURATION','generationId',generation->>'generationId') THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
   encoded:=encoded||jsonb_build_object('4','RUNTIME_CONFIGURATION','5',openpc.business_uuid(right(generation->>'generationId',36)::uuid));
  ELSIF generation->>'kind'='CANONICAL_FACT' THEN
   IF coalesce(generation->>'factProfileId','')!~profile_pattern OR coalesce(generation->>'canonicalGeneration','')!~'^[1-9][0-9]{0,19}$'
    OR (generation->>'canonicalGeneration')::numeric>18446744073709551615
    OR generation IS DISTINCT FROM jsonb_build_object('kind','CANONICAL_FACT','factProfileId',generation->>'factProfileId','canonicalGeneration',generation->>'canonicalGeneration') THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
   encoded:=encoded||jsonb_build_object('4','CANONICAL_FACT','5',generation->>'factProfileId','6',(generation->>'canonicalGeneration')::numeric);
  ELSE RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  expected:=expected||jsonb_build_object('generation',generation);
 ELSIF kind NOT IN ('PARTICIPANT','PRIVACY_DOMAIN') OR kind IS NULL THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF first_value>18446744073709551615 OR last_value>18446744073709551615 OR last_value<first_value
  OR selector IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 RETURN encoded;
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_selector_encoding(jsonb,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_selector_encoding(jsonb,uuid,uuid) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

-- The descriptor is assembled by the owning source adapter, never accepted from
-- the public hold/deletion request. Missing knowledge remains NULL per dimension.
CREATE OR REPLACE FUNCTION openpc.evidence_hold_source_match(selector jsonb,metadata jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE entries jsonb; dimension text; entry jsonb; check_selector jsonb; matched boolean;
BEGIN
 IF metadata ? 'unresolvedReferences' AND jsonb_typeof(metadata->'unresolvedReferences') IS DISTINCT FROM 'boolean' THEN RETURN NULL; END IF;
 dimension:=CASE selector->>'type' WHEN 'PROJECTION' THEN 'projections' WHEN 'FACT_TYPE_KEY' THEN 'facts'
  WHEN 'BLOCK_RANGE' THEN 'blocks' WHEN 'GENERATION' THEN 'generations' END;
 -- Generation namespaces have independent completeness. A known runtime UUID
 -- never proves that a record references no canonical Fact generation.
 entries:=CASE WHEN dimension='generations' THEN metadata->dimension->(selector->'generation'->>'kind') ELSE metadata->dimension END;
 IF dimension IS NULL OR jsonb_typeof(entries) IS DISTINCT FROM 'array' THEN RETURN NULL; END IF;
 -- Validate every source item before proving absence. A malformed sibling must
 -- not silently become a non-match, even when another item is well formed.
 FOR entry IN SELECT value FROM jsonb_array_elements(entries) LOOP
  IF dimension='projections' THEN
   check_selector:=jsonb_build_object('type','PROJECTION','projectionId',entry);
  ELSIF dimension='facts' THEN
   IF jsonb_typeof(entry) IS DISTINCT FROM 'object' OR entry->'factKeyDigest' IS NOT DISTINCT FROM 'null'::jsonb THEN RETURN NULL; END IF;
   check_selector:=entry||jsonb_build_object('type','FACT_TYPE_KEY');
  ELSIF dimension='blocks' THEN
   IF jsonb_typeof(entry) IS DISTINCT FROM 'object' OR entry-ARRAY['chainId','genesisDigest','blockNumber']<>'{}'::jsonb THEN RETURN NULL; END IF;
   check_selector:=jsonb_build_object('type','BLOCK_RANGE','chainId',entry->'chainId','genesisDigest',entry->'genesisDigest',
    'fromBlock',entry->'blockNumber','throughBlock',entry->'blockNumber');
  ELSE
   IF entry->>'kind' IS DISTINCT FROM selector->'generation'->>'kind' THEN RETURN NULL; END IF;
   check_selector:=jsonb_build_object('type','GENERATION','generation',entry);
  END IF;
  BEGIN
   PERFORM openpc.evidence_hold_selector_encoding(check_selector,'00000000-0000-0000-0000-000000000000'::uuid,'00000000-0000-0000-0000-000000000000'::uuid);
  EXCEPTION WHEN raise_exception OR invalid_text_representation OR numeric_value_out_of_range THEN RETURN NULL;
  END;
 END LOOP;
 SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(entries) e WHERE
  (dimension='projections' AND e=selector->'projectionId')
  OR (dimension='facts' AND e->>'factType'=selector->>'factType' AND e->>'factProfileId'=selector->>'factProfileId'
   AND (selector->'factKeyDigest'='null'::jsonb OR e->>'factKeyDigest'=selector->>'factKeyDigest'))
  OR (dimension='blocks' AND e->>'chainId'=selector->>'chainId' AND e->>'genesisDigest'=selector->>'genesisDigest'
   AND (e->>'blockNumber')::numeric>=(selector->>'fromBlock')::numeric
   AND (selector->'throughBlock'='null'::jsonb OR (e->>'blockNumber')::numeric<=(selector->>'throughBlock')::numeric))
  OR (dimension='generations' AND e=selector->'generation')) INTO matched;
 -- A verified positive remains a preservation duty. Missing reference closure
 -- prevents a negative result from being used as permission to delete.
 IF NOT matched AND metadata->'unresolvedReferences'='true'::jsonb THEN RETURN NULL; END IF;
 RETURN matched;
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_source_match(jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_source_match(jsonb,jsonb) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;


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
 ELSIF (source).source_format='OPENPC_CANONICAL_FACT_V1' THEN
  RETURN openpc.evidence_fact_hold_metadata(source);
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
   AND c.stream_id=stream AND c.segment_id=segment) matches
$$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_match_state(jsonb,uuid,uuid,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_match_state(jsonb,uuid,uuid,text,uuid) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1','evidence-holds','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_CREATION'),
 ('ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1','evidence-holds','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_RELEASE'),
 ('ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1','evidence-holds','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_CREATION'),
 ('ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1','evidence-holds','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_RELEASE'),
 ('ACT-EVIDENCE_HOLDS_READ_RESOURCE-V1','evidence-holds','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_HOLD_READ'),
 ('ACT-EVIDENCE_HOLDS_READ_COLLECTION-V1','evidence-holds','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_HOLD_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
 (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
 idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
 ('ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1','evidence-holds','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_CREATION'),
 ('ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1','evidence-holds','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_RELEASE'),
 ('ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1','evidence-holds','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_CREATION'),
 ('ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1','evidence-holds','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_RELEASE'),
 ('ACT-EVIDENCE_HOLDS_READ_RESOURCE-V1','evidence-holds','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_HOLD_READ'),
 ('ACT-EVIDENCE_HOLDS_READ_COLLECTION-V1','evidence-holds','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_HOLD_READ')))<>6
 THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-HOLD-ACTION'; END IF;
END $$;
ALTER TABLE control.retention_hold FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_hold_coverage FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.retention_hold,control.evidence_hold_coverage
 FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.retention_hold,control.evidence_hold_coverage
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT,UPDATE ON control.retention_hold TO openpc_control_runtime;
GRANT INSERT ON control.evidence_hold_coverage TO openpc_control_worker;
GRANT SELECT(admitted_at) ON control.evidence_segment TO openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.evidence_hold_state_projection(rule control.retention_hold)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',(rule).hold_kind,
  '1',openpc.business_bytes(decode(substring((rule).selector_digest from 8),'hex')),'2',(rule).state,
  '3',openpc.business_uuid((rule).approval_request_id),'4',openpc.business_uuid((rule).creation_operation_id),
  '5',CASE WHEN (rule).release_approval_request_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((rule).release_approval_request_id) END,
  '6',CASE WHEN (rule).release_operation_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((rule).release_operation_id) END,
  '7',floor(extract(epoch from (rule).effective_at)*1000000)*1000,
  '8',floor(extract(epoch from (rule).updated_at)*1000000)*1000)
$$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_state_projection(control.retention_hold) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_state_projection(control.retention_hold)
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.assert_evidence_hold_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=receipt.participant_id
  AND h.privacy_domain_id=receipt.privacy_domain_id AND h.retention_hold_id=receipt.aggregate_id
  AND h.revision=receipt.after_revision AND receipt.after_existence=1
  AND coalesce(h.release_operation_id,h.creation_operation_id)=receipt.operation_id
  AND receipt.catalog_operation_id=CASE WHEN h.selector_type='PARTICIPANT' THEN CASE WHEN h.state='ACTIVE' THEN 'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD' ELSE 'CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD' END ELSE CASE WHEN h.state='ACTIVE' THEN 'CFG-OP-CREATE-EVIDENCE-HOLD' ELSE 'CFG-OP-RELEASE-EVIDENCE-HOLD' END END
  AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.evidence_hold_state_projection(h))
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-HOLD-STATE'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_evidence_hold_receipt(control.audit_occurrence) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_evidence_hold_receipt(control.audit_occurrence) TO openpc_control_runtime;

-- Matching any record preserves its complete immutable encrypted object version.
CREATE OR REPLACE FUNCTION openpc.evidence_hold_matches(selector jsonb,participant uuid,privacy uuid,stream text,segment uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT openpc.evidence_hold_match_state(selector,participant,privacy,stream,segment)<>'NON_MATCH'
$$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_matches(jsonb,uuid,uuid,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_matches(jsonb,uuid,uuid,text,uuid)
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;

-- The lifecycle fence orders admission against release. A terminal release keeps
-- historical acknowledgements, but creates no preservation duty for later objects.
CREATE OR REPLACE FUNCTION openpc.evidence_hold_requires_coverage(rule control.retention_hold,stream text,segment uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.evidence_segment s WHERE s.participant_id=(rule).participant_id
  AND ((rule).selector_type='PARTICIPANT' OR s.privacy_domain_id=(rule).privacy_domain_id)
  AND s.stream_id=stream AND s.segment_id=segment
  AND openpc.evidence_hold_matches((rule).selector,s.participant_id,s.privacy_domain_id,stream,segment)
  AND ((rule).state='ACTIVE' OR s.admitted_at<=(rule).updated_at))
$$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_requires_coverage(control.retention_hold,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_requires_coverage(control.retention_hold,text,uuid)
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_hold()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE encoded jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 encoded:=openpc.evidence_hold_selector_encoding(NEW.selector,NEW.participant_id,NEW.privacy_domain_id);
 IF NEW.selector_type IS DISTINCT FROM NEW.selector->>'type'
  OR openpc.business_cbor(NEW.selector_cbor) IS DISTINCT FROM encoded THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF NEW.selector_type='PARTICIPANT' AND NOT EXISTS(SELECT 1 FROM control.participant p
  WHERE p.participant_id=NEW.participant_id AND p.root_privacy_domain_id=NEW.privacy_domain_id)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'ACTIVE' OR NEW.revision<>1 OR NEW.creation_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>(CASE WHEN NEW.selector_type='PARTICIPANT' THEN 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1' ELSE 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1' END)
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  NEW.created_at:=clock_timestamp(); NEW.effective_at:=NEW.created_at;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['state','revision','release_operation_id','release_approval_request_id','updated_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['state','revision','release_operation_id','release_approval_request_id','updated_at'])
   OR OLD.state<>'ACTIVE' OR NEW.state<>'RELEASED' OR NEW.revision<>2
   OR NEW.release_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>(CASE WHEN NEW.selector_type='PARTICIPANT' THEN 'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1' ELSE 'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1' END)
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 END IF;
 NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_hold_guard ON control.retention_hold;
CREATE TRIGGER evidence_hold_guard BEFORE INSERT OR UPDATE OR DELETE ON control.retention_hold
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_hold();

CREATE OR REPLACE FUNCTION openpc.require_evidence_hold_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE operation uuid; approval uuid; catalog text; action text; expected numeric;
BEGIN
 IF TG_OP='INSERT' THEN
  operation:=NEW.creation_operation_id;approval:=NEW.approval_request_id;catalog:='CFG-OP-CREATE-EVIDENCE-HOLD';
  action:='ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1';expected:=0;
 ELSE
  operation:=NEW.release_operation_id;approval:=NEW.release_approval_request_id;catalog:='CFG-OP-RELEASE-EVIDENCE-HOLD';
  action:='ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1';expected:=1;
 END IF;
 IF NEW.selector_type='PARTICIPANT' THEN
  catalog:=CASE WHEN TG_OP='INSERT' THEN 'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD' ELSE 'CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD' END;
  action:=CASE WHEN TG_OP='INSERT' THEN 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1' ELSE 'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1' END;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence e JOIN control.idempotency_record i
  ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id AND i.operation_id=e.operation_id
   AND i.catalog_operation_id=e.catalog_operation_id AND i.input_digest=e.candidate_digest
  JOIN control.mutation_candidate c ON c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
   AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
  JOIN control.approval_request a ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
   AND a.subject_id=c.mutation_candidate_id AND a.approval_request_id=approval
  WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id
   AND e.operation_id=operation AND e.aggregate_type='evidence-hold' AND e.aggregate_id=NEW.retention_hold_id
   AND e.catalog_operation_id=catalog AND e.action_intent_id=action AND i.terminal_state='COMMITTED'
   AND i.expected_aggregate_version=expected AND i.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.retention_hold_id::text
   AND c.catalog_operation_id=catalog AND c.action_intent_id=action AND c.resource_id=NEW.retention_hold_id
   AND c.state='CONSUMED' AND c.expected_revision=expected
   AND (TG_OP<>'INSERT' OR (c.candidate_document->'selector'=NEW.selector AND c.candidate_document->>'holdKind'=NEW.hold_kind))
   AND EXISTS(SELECT 1 FROM control.outbox_event event JOIN control.audit_occurrence receipt
    ON receipt.participant_id=event.participant_id AND receipt.privacy_domain_id=event.privacy_domain_id
    AND receipt.receipt_id=event.receipt_id WHERE event.participant_id=e.participant_id
    AND event.privacy_domain_id=e.privacy_domain_id AND event.aggregate_id=e.aggregate_id AND event.aggregate_type=e.aggregate_type
    AND event.event_type='io.openpc.control.command.committed.v1' AND event.proof_kind='BUSINESS_RECEIPT_REFERENCE'
    AND event.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1' AND receipt.operation_id=operation
    AND event.payload_digest=sha256(event.payload_cbor))) THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-HOLD-PROVENANCE'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.audit_occurrence receipt WHERE receipt.participant_id=NEW.participant_id
  AND receipt.privacy_domain_id=NEW.privacy_domain_id AND receipt.operation_id=operation
  AND receipt.aggregate_type='evidence-hold' AND receipt.aggregate_id=NEW.retention_hold_id
  AND receipt.catalog_operation_id=catalog AND receipt.action_intent_id=action
  AND receipt.before_existence=CASE WHEN TG_OP='INSERT' THEN 0 ELSE 1 END
  AND receipt.before_revision=expected AND receipt.after_existence=1 AND receipt.after_revision=NEW.revision
  AND openpc.business_cbor(receipt.before_state_preimage)->8=CASE WHEN TG_OP='INSERT' THEN '{}'::jsonb ELSE openpc.evidence_hold_state_projection(OLD) END
  AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.evidence_hold_state_projection(NEW))
 THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-HOLD-SIGNED-TRANSITION'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS evidence_hold_command_required ON control.retention_hold;
CREATE CONSTRAINT TRIGGER evidence_hold_command_required AFTER INSERT OR UPDATE ON control.retention_hold
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_hold_command();

CREATE OR REPLACE FUNCTION openpc.guard_evidence_hold_coverage()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE hold control.retention_hold%ROWTYPE; segment control.evidence_segment%ROWTYPE; expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','USAGE')
  OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 SELECT * INTO STRICT hold FROM control.retention_hold WHERE participant_id=NEW.participant_id
  AND (selector_type='PARTICIPANT' OR privacy_domain_id=NEW.privacy_domain_id) AND retention_hold_id=NEW.retention_hold_id;
 SELECT * INTO STRICT segment FROM control.evidence_segment WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND segment_id=NEW.segment_id;
 IF hold.revision<>NEW.hold_revision OR segment.object_digest<>NEW.object_digest
  OR NOT openpc.evidence_hold_requires_coverage(hold,NEW.stream_id,NEW.segment_id)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 expected:=jsonb_build_object('version','OPENPC_EVIDENCE_HOLD_ACK_V1','object',jsonb_build_object(
  'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'streamId',NEW.stream_id,
  'sinkId',NEW.sink_id,'segmentId',NEW.segment_id::text,'objectDigest',NEW.object_digest,
  'firstSequence',segment.first_sequence::text,'throughSequence',segment.through_sequence::text,
  'previousSegmentDigest',segment.previous_segment_digest,'keyId',segment.key_id,
  'retentionUntil',to_char(segment.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
  'holdId',hold.retention_hold_id::text,'selectorDigest',hold.selector_digest,'revision',hold.revision::text,
  'state',hold.state,'operationId',coalesce(hold.release_operation_id,hold.creation_operation_id)::text,
  'assurance','LOCAL_FSYNC_READBACK');
 IF NEW.receipt-'receiptDigest' IS DISTINCT FROM expected OR NEW.receipt->>'receiptDigest' IS DISTINCT FROM NEW.receipt_digest
  OR NEW.receipt_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.acknowledged_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_hold_coverage_guard ON control.evidence_hold_coverage;
CREATE TRIGGER evidence_hold_coverage_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_hold_coverage
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_hold_coverage();

CREATE OR REPLACE FUNCTION openpc.require_evidence_checkpoint_hold_coverage()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 IF EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=NEW.participant_id
  AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=NEW.privacy_domain_id)
  AND openpc.evidence_hold_requires_coverage(h,NEW.stream_id,NEW.segment_id)
  AND NOT EXISTS(SELECT 1 FROM control.evidence_hold_coverage c WHERE c.participant_id=h.participant_id
   AND c.privacy_domain_id=NEW.privacy_domain_id AND c.retention_hold_id=h.retention_hold_id AND c.hold_revision=h.revision
   AND c.segment_id=NEW.segment_id AND c.sink_id=NEW.sink_id AND c.object_digest=NEW.object_digest))
 THEN RAISE EXCEPTION 'PC-DATA-6007-EVIDENCE-HOLD-COVERAGE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_checkpoint_hold_coverage ON control.evidence_checkpoint;
CREATE TRIGGER evidence_checkpoint_hold_coverage BEFORE INSERT ON control.evidence_checkpoint
 FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_checkpoint_hold_coverage();


ALTER TABLE control.evidence_fact_provenance FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_fact_provenance FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_fact_provenance TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT INSERT ON control.evidence_fact_provenance TO openpc_control_worker;
CREATE OR REPLACE FUNCTION openpc.guard_evidence_fact_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb:=NEW.projection; l jsonb:=p->'lineage'; field text;
 resource_pattern text:='^urn:openpc:fact:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR jsonb_typeof(l) IS DISTINCT FROM 'object'
  OR p-ARRAY['candidateId','sourceSequence','receiptDigest','admittedAt','lineage','integrity','authority','currentReadiness','sourceProfileId','verificationKeyId','verificationKeyDigest']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(p))<>11
  OR l-ARRAY['factId','factDigest','factType','factProfileId','factKeyDigest','canonicalGeneration','projectionId','chainId','genesisDigest','blockNumber','blockHash','predecessorDigest','relationshipPredecessorDigest','reorgReplacementOf']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(l))<>14
  OR EXISTS(SELECT 1 FROM jsonb_each(p) e WHERE e.key<>'lineage' AND jsonb_typeof(e.value)<>'string')
  OR EXISTS(SELECT 1 FROM jsonb_each(l) e WHERE jsonb_typeof(e.value)<>'string'
   AND NOT(e.key IN ('predecessorDigest','relationshipPredecessorDigest','reorgReplacementOf') AND e.value='null'::jsonb))
  OR p->>'integrity' IS DISTINCT FROM 'FACT_COSE_VERIFIED_AT_CUSTODY'
  OR p->>'authority' IS DISTINCT FROM 'NONE' OR p->>'currentReadiness' IS DISTINCT FROM 'NOT_ESTABLISHED'
  OR coalesce(l->>'factId','')!~resource_pattern
  OR coalesce('urn:openpc:fact:'||(p->>'candidateId'),'')!~resource_pattern
  OR coalesce('urn:openpc:fact:'||(p->>'sourceProfileId'),'')!~resource_pattern
  OR coalesce(p->>'sourceSequence','')!~'^[1-9][0-9]{0,18}$'
  OR (p->>'sourceSequence')::numeric>9223372036854775807
  OR NEW.projection_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex')
  OR NEW.record_id<>'fact:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_array(NEW.participant_id::text,NEW.privacy_domain_id::text,p->>'sourceProfileId')),'UTF8')),'hex')||':'||(p->>'sourceSequence')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 FOREACH field IN ARRAY ARRAY['verificationKeyId','verificationKeyDigest','receiptDigest'] LOOP
  IF coalesce(p->>field,'')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['factDigest','blockHash'] LOOP
  IF coalesce(l->>field,'')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['predecessorDigest','relationshipPredecessorDigest'] LOOP
  IF l->field<>'null'::jsonb AND coalesce(l->>field,'')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 IF l->'reorgReplacementOf'<>'null'::jsonb AND coalesce(l->>'reorgReplacementOf','')!~resource_pattern THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM openpc.evidence_hold_selector_encoding(jsonb_build_object('type','FACT_TYPE_KEY','factType',l->>'factType','factProfileId',l->>'factProfileId','factKeyDigest',l->>'factKeyDigest'),NEW.participant_id,NEW.privacy_domain_id);
 PERFORM openpc.evidence_hold_selector_encoding(jsonb_build_object('type','PROJECTION','projectionId',l->>'projectionId'),NEW.participant_id,NEW.privacy_domain_id);
 PERFORM openpc.evidence_hold_selector_encoding(jsonb_build_object('type','GENERATION','generation',jsonb_build_object('kind','CANONICAL_FACT','factProfileId',l->>'factProfileId','canonicalGeneration',l->>'canonicalGeneration')),NEW.participant_id,NEW.privacy_domain_id);
 PERFORM openpc.evidence_hold_selector_encoding(jsonb_build_object('type','BLOCK_RANGE','chainId',l->>'chainId','genesisDigest',l->>'genesisDigest','fromBlock',l->>'blockNumber','throughBlock',l->>'blockNumber'),NEW.participant_id,NEW.privacy_domain_id);
 IF NOT EXISTS(SELECT 1 FROM control.evidence_catalogue c WHERE c.participant_id=NEW.participant_id
  AND c.privacy_domain_id=NEW.privacy_domain_id AND c.stream_id=NEW.stream_id AND c.record_id=NEW.record_id
  AND c.source_format='OPENPC_CANONICAL_FACT_V1' AND c.evidence_class='EFFECT'
  AND c.receipt_digest=p->>'receiptDigest' AND c.sequence::text=p->>'sourceSequence'
  AND c.occurred_at=(p->>'admittedAt')::timestamptz) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_fact_provenance_guard ON control.evidence_fact_provenance;
CREATE TRIGGER evidence_fact_provenance_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_fact_provenance
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_fact_provenance();

CREATE OR REPLACE FUNCTION openpc.evidence_fact_hold_metadata(source control.evidence_catalogue)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE original jsonb; queue jsonb; item jsonb; lineage jsonb; reference jsonb; candidates jsonb;
 seen text[]:=ARRAY[]::text[]; unresolved boolean:=false; steps integer:=0;
 projections jsonb:='[]'; facts jsonb:='[]'; blocks jsonb:='[]'; generations jsonb:='[]';
BEGIN
 SELECT p.projection->'lineage' INTO original FROM control.evidence_fact_provenance p
  WHERE p.participant_id=(source).participant_id AND p.privacy_domain_id=(source).privacy_domain_id
   AND p.stream_id=(source).stream_id AND p.record_id=(source).record_id
   AND (source).source_format='OPENPC_CANONICAL_FACT_V1' AND (source).evidence_class='EFFECT'
   AND p.projection->>'receiptDigest'=(source).receipt_digest AND p.projection->>'sourceSequence'=(source).sequence::text
   AND (p.projection->>'admittedAt')::timestamptz=(source).occurred_at
   AND p.projection_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p.projection),'UTF8')),'hex');
 IF NOT FOUND THEN RETURN NULL; END IF;
 queue:=jsonb_build_array(jsonb_build_object('lineage',original,'path','[]'::jsonb));
 WHILE jsonb_array_length(queue)>0 AND steps<64 LOOP
  item:=queue->0; queue:=queue-0; lineage:=item->'lineage'; steps:=steps+1;
  IF item->'path' ? (lineage->>'factDigest') THEN unresolved:=true; CONTINUE; END IF;
  IF lineage->>'factDigest'=ANY(seen) THEN CONTINUE; END IF;
  seen:=array_append(seen,lineage->>'factDigest');
  projections:=projections||jsonb_build_array(lineage->>'projectionId');
  facts:=facts||jsonb_build_array(jsonb_build_object('factType',lineage->>'factType','factProfileId',lineage->>'factProfileId','factKeyDigest',lineage->>'factKeyDigest'));
  blocks:=blocks||jsonb_build_array(jsonb_build_object('chainId',lineage->>'chainId','genesisDigest',lineage->>'genesisDigest','blockNumber',lineage->>'blockNumber'));
  generations:=generations||jsonb_build_array(jsonb_build_object('kind','CANONICAL_FACT','factProfileId',lineage->>'factProfileId','canonicalGeneration',lineage->>'canonicalGeneration'));
  FOR reference IN SELECT value FROM jsonb_array_elements(jsonb_build_array(lineage->'predecessorDigest',lineage->'relationshipPredecessorDigest',lineage->'reorgReplacementOf')) WHERE value<>'null'::jsonb LOOP
   SELECT jsonb_agg(DISTINCT p.projection->'lineage') INTO candidates
    FROM control.evidence_fact_provenance p JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
    WHERE p.participant_id=(source).participant_id AND p.privacy_domain_id=(source).privacy_domain_id
     AND (p.projection->'lineage'->'factDigest'=reference OR p.projection->'lineage'->'factId'=reference)
     AND p.projection->>'receiptDigest'=c.receipt_digest AND c.source_format='OPENPC_CANONICAL_FACT_V1'
     AND c.evidence_class='EFFECT' AND p.projection->>'sourceSequence'=c.sequence::text
     AND (p.projection->>'admittedAt')::timestamptz=c.occurred_at
     AND p.projection_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p.projection),'UTF8')),'hex');
   IF candidates IS NULL OR jsonb_array_length(candidates)<>1 THEN unresolved:=true;
   -- Visit descendants before queued siblings. Breadth-first de-duplication can
   -- mark both ends of a shared-reference cycle seen before either back edge
   -- reaches its ancestor path, incorrectly reporting complete closure.
   ELSE queue:=jsonb_build_array(jsonb_build_object('lineage',candidates->0,'path',(item->'path')||jsonb_build_array(lineage->>'factDigest')))||queue; END IF;
  END LOOP;
 END LOOP;
 RETURN jsonb_build_object('projections',projections,'facts',facts,'blocks',blocks,
  'generations',jsonb_build_object('CANONICAL_FACT',generations),'unresolvedReferences',unresolved OR jsonb_array_length(queue)>0);
EXCEPTION WHEN insufficient_privilege THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_fact_hold_metadata(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_fact_hold_metadata(control.evidence_catalogue) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1','retention-policies','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RETENTION_POLICY_ACTIVATION'),
('ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1','retention-policies','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RETENTION_POLICY_RETIREMENT'),
('ACT-RETENTION_POLICIES_READ_RESOURCE-V1','retention-policies','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RETENTION_POLICY_READ'),
('ACT-RETENTION_POLICIES_READ_COLLECTION-V1','retention-policies','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RETENTION_POLICY_READ') ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (('ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1','retention-policies','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RETENTION_POLICY_ACTIVATION'),
('ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1','retention-policies','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RETENTION_POLICY_RETIREMENT'),
('ACT-RETENTION_POLICIES_READ_RESOURCE-V1','retention-policies','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RETENTION_POLICY_READ'),
('ACT-RETENTION_POLICIES_READ_COLLECTION-V1','retention-policies','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RETENTION_POLICY_READ')))<>4
 THEN RAISE EXCEPTION 'PC-AUTH-0002-RETENTION-ACTION'; END IF;
END $$;
ALTER TABLE control.retention_policy FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.retention_policy FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.retention_policy TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT INSERT,UPDATE ON control.retention_policy TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.retention_policy_definition(rule control.retention_policy)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('dataClass',(rule).data_class,'policyVersion',(rule).policy_version,
  'retentionPeriodMs',(rule).retention_period_ms::text,'localGraceMs',(rule).local_grace_ms::text,
  'sinkQuorum',(rule).sink_quorum,'deletionMode',(rule).deletion_mode,'makerCheckerRequired',(rule).maker_checker_required)
$$;
CREATE OR REPLACE FUNCTION openpc.retention_policy_state_projection(rule control.retention_policy)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',openpc.business_bytes(decode(substring((rule).policy_digest from 8),'hex')),
  '1',CASE WHEN (rule).predecessor_policy_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((rule).predecessor_policy_id) END,
  '2',openpc.business_uuid((rule).approval_request_id),'3',openpc.business_uuid((rule).activation_operation_id),
  '4',CASE WHEN (rule).retirement_approval_request_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((rule).retirement_approval_request_id) END,
  '5',CASE WHEN (rule).retirement_operation_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((rule).retirement_operation_id) END,
  '6',floor(extract(epoch from (rule).active_from)*1000000)*1000,
  '7',CASE WHEN (rule).active_until IS NULL THEN openpc.business_bytes(''::bytea) ELSE to_jsonb(floor(extract(epoch from (rule).active_until)*1000000)*1000) END)
$$;
REVOKE ALL ON FUNCTION openpc.retention_policy_definition(control.retention_policy),openpc.retention_policy_state_projection(control.retention_policy) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.retention_policy_definition(control.retention_policy),openpc.retention_policy_state_projection(control.retention_policy)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_retention_policy()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE predecessor control.retention_policy%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 IF openpc.business_cbor(NEW.policy_cbor) IS DISTINCT FROM jsonb_build_object(
  '0','pc.evidence.retention-policy.v1','1',openpc.business_uuid(NEW.participant_id),'2',openpc.business_uuid(NEW.privacy_domain_id),
  '3',NEW.data_class,'4',NEW.policy_version,'5',NEW.retention_period_ms,'6',NEW.local_grace_ms,
  '7',NEW.sink_quorum,'8',NEW.deletion_mode,'9',CASE WHEN NEW.maker_checker_required THEN 1 ELSE 0 END) THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR NEW.active_until IS NOT NULL OR NEW.retirement_operation_id IS NOT NULL
   OR NEW.retirement_approval_request_id IS NOT NULL OR NEW.activation_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1'
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  SELECT * INTO predecessor FROM control.retention_policy p WHERE p.participant_id=NEW.participant_id
   AND p.privacy_domain_id=NEW.privacy_domain_id AND p.data_class=NEW.data_class
   ORDER BY p.active_from DESC,p.retention_policy_id DESC LIMIT 1 FOR UPDATE;
  IF NEW.predecessor_policy_id IS DISTINCT FROM predecessor.retention_policy_id
   OR (predecessor.retention_policy_id IS NOT NULL AND predecessor.active_until IS NULL)
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.active_from:=clock_timestamp();NEW.created_at:=NEW.active_from;
  IF predecessor.active_until IS NOT NULL AND predecessor.active_until>NEW.active_from THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['revision','active_until','retirement_operation_id','retirement_approval_request_id','updated_at']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['revision','active_until','retirement_operation_id','retirement_approval_request_id','updated_at'])
   OR OLD.revision<>1 OR NEW.revision<>2 OR OLD.active_until IS NOT NULL
   OR NEW.retirement_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>'ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1'
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  NEW.active_until:=clock_timestamp();
 END IF;
 NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS retention_policy_guard ON control.retention_policy;
CREATE TRIGGER retention_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON control.retention_policy
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_retention_policy();

CREATE OR REPLACE FUNCTION openpc.assert_retention_policy_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.retention_policy p WHERE p.participant_id=receipt.participant_id
  AND p.privacy_domain_id=receipt.privacy_domain_id AND p.retention_policy_id=receipt.aggregate_id
  AND p.revision=receipt.after_revision AND receipt.after_existence=1
  AND coalesce(p.retirement_operation_id,p.activation_operation_id)=receipt.operation_id
  AND receipt.catalog_operation_id=CASE WHEN p.active_until IS NULL THEN 'CFG-OP-ACTIVATE-RETENTION-POLICY' ELSE 'CFG-OP-RETIRE-RETENTION-POLICY' END
  AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.retention_policy_state_projection(p))
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-RETENTION-STATE'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_retention_policy_receipt(control.audit_occurrence) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_retention_policy_receipt(control.audit_occurrence) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.require_retention_policy_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE operation uuid; approval uuid; catalog text; action text; expected numeric;
BEGIN
 IF TG_OP='INSERT' THEN
  operation:=NEW.activation_operation_id;approval:=NEW.approval_request_id;catalog:='CFG-OP-ACTIVATE-RETENTION-POLICY';
  action:='ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1';expected:=0;
 ELSE
  operation:=NEW.retirement_operation_id;approval:=NEW.retirement_approval_request_id;catalog:='CFG-OP-RETIRE-RETENTION-POLICY';
  action:='ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1';expected:=1;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence e JOIN control.mutation_candidate c
  ON c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
   AND c.resource_id=e.aggregate_id AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
  JOIN control.audit_occurrence receipt ON receipt.participant_id=e.participant_id AND receipt.privacy_domain_id=e.privacy_domain_id
   AND receipt.operation_id=e.operation_id AND receipt.aggregate_id=e.aggregate_id AND receipt.aggregate_type='retention-policy'
  WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=operation
   AND e.approval_request_id=approval AND e.aggregate_type='retention-policy' AND e.aggregate_id=NEW.retention_policy_id
   AND e.catalog_operation_id=catalog AND e.action_intent_id=action
   AND c.catalog_operation_id=catalog AND c.action_intent_id=action AND c.state='CONSUMED' AND c.expected_revision=expected
   AND (TG_OP<>'INSERT' OR (c.candidate_document->'policy'=openpc.retention_policy_definition(NEW)
    AND c.candidate_document->'predecessorPolicyId'=coalesce(to_jsonb('urn:openpc:resource:'||NEW.predecessor_policy_id::text),'null'::jsonb)))
   AND receipt.catalog_operation_id=catalog AND receipt.action_intent_id=action
   AND receipt.before_existence=CASE WHEN TG_OP='INSERT' THEN 0 ELSE 1 END
   AND receipt.before_revision=expected AND receipt.after_existence=1 AND receipt.after_revision=NEW.revision
   AND openpc.business_cbor(receipt.before_state_preimage)->8=CASE WHEN TG_OP='INSERT' THEN '{}'::jsonb ELSE openpc.retention_policy_state_projection(OLD) END
   AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.retention_policy_state_projection(NEW)
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=receipt.participant_id
    AND event.privacy_domain_id=receipt.privacy_domain_id AND event.receipt_id=receipt.receipt_id
    AND event.aggregate_type=receipt.aggregate_type AND event.aggregate_id=receipt.aggregate_id
    AND event.event_type='io.openpc.control.command.committed.v1' AND event.proof_kind='BUSINESS_RECEIPT_REFERENCE'
    AND event.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1' AND event.payload_digest=sha256(event.payload_cbor)))
 THEN RAISE EXCEPTION 'PC-AUTH-0002-RETENTION-SIGNED-TRANSITION'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS retention_policy_command_required ON control.retention_policy;
CREATE CONSTRAINT TRIGGER retention_policy_command_required AFTER INSERT OR UPDATE ON control.retention_policy
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_retention_policy_command();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RAW_PROOF_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_LOCAL_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_LOCAL_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1','evidence-deletions','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_DELETION_READ'),
 ('ACT-EVIDENCE_DELETIONS_READ_COLLECTION-V1','evidence-deletions','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_DELETION_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN ( ('ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RAW_PROOF_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_LOCAL_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_LOCAL_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1','evidence-deletions','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_DELETION_READ'),
 ('ACT-EVIDENCE_DELETIONS_READ_COLLECTION-V1','evidence-deletions','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_DELETION_READ')))<>5
 THEN RAISE EXCEPTION 'PC-AUTH-0002-DELETION-ACTION'; END IF;
END $$;
ALTER TABLE control.deletion_job FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_deletion_item FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.deletion_job,control.evidence_deletion_item FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.deletion_job,control.evidence_deletion_item TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT,UPDATE ON control.deletion_job TO openpc_control_runtime;
GRANT INSERT ON control.evidence_deletion_item TO openpc_control_runtime;
GRANT SELECT(participant_id,privacy_domain_id,stream_id,segment_id,ciphertext_bytes) ON control.evidence_segment_payload TO openpc_control_runtime,openpc_control_reader;
GRANT SELECT(first_sequence,through_sequence,retention_until) ON control.evidence_segment TO openpc_control_runtime,openpc_control_reader;
GRANT DELETE ON control.evidence_segment_payload TO openpc_control_runtime;
GRANT UPDATE(used_bytes) ON control.evidence_stream TO openpc_control_runtime;

GRANT EXECUTE ON FUNCTION openpc.lock_deployment_command(uuid) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.evidence_deletion_rejections(stream text,segment uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item record; source record; claims jsonb; command uuid; proofs jsonb:='[]'::jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 -- Lock order: evidence lifecycle, then unique command UUIDs in lexical order.
 -- Reservation, handoff and terminal rejection already use this command fence.
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||current_setting('openpc.participant_id'),0));
 IF EXISTS(SELECT 1 FROM control.evidence_catalogue c
  WHERE c.participant_id=current_setting('openpc.participant_id')::uuid
   AND c.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
   AND c.stream_id=stream AND c.segment_id=segment
   AND c.evidence_class NOT IN ('AUTHENTICATION','BUSINESS_TRANSITION','EFFECT'))
 THEN RETURN NULL; END IF;
 FOR item IN SELECT c.* FROM control.evidence_catalogue c
  WHERE c.participant_id=current_setting('openpc.participant_id')::uuid
   AND c.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
   AND c.stream_id=stream AND c.segment_id=segment AND c.evidence_class='EFFECT'
  ORDER BY c.record_id,c.evidence_id
 LOOP
  IF item.source_format<>'PC-DEPLOYMENT-RESERVATION-REJECTION-1'
   OR item.record_id!~'^deployment:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:1$'
  THEN RETURN NULL; END IF;
  command:=split_part(item.record_id,':',2)::uuid;
  PERFORM openpc.lock_deployment_command(command);
  SELECT *,count(*) OVER() source_count INTO source
   FROM openpc.deployment_rejection_source(command,item.participant_id,item.privacy_domain_id);
  IF NOT FOUND OR source.source_count<>1 OR source.result_digest<>item.receipt_digest
   OR source.result_digest<>'sha256:'||encode(sha256(source.signed_bytes),'hex') THEN RETURN NULL; END IF;
  claims:=convert_from(source.signed_bytes,'UTF8')::jsonb;
  IF claims->>'purpose' IS DISTINCT FROM 'openpc:deployment-reservation-rejection:v1'
   OR claims->'claims'->>'schema' IS DISTINCT FROM item.source_format
   OR claims->'claims'->'binding'->>'commandId' IS DISTINCT FROM command::text
   OR claims->'claims'->'binding'->>'attemptId' IS DISTINCT FROM source.attempt_id
   OR claims->'claims'->'binding'->'owner'->>'participant_id' IS DISTINCT FROM item.participant_id::text
   OR claims->'claims'->'binding'->'owner'->>'privacy_domain_id' IS DISTINCT FROM item.privacy_domain_id::text
   OR claims->'claims'->>'candidateDigest' IS DISTINCT FROM source.candidate_digest
   OR claims->'claims'->>'authorizationEvidenceDigest' IS DISTINCT FROM source.evidence_digest
   OR NOT coalesce(claims->'claims'->>'reason' IN ('CUSTODY_CONFLICT','PREPARATION_EXPIRED','MODULE_GENERATION_UNAVAILABLE'),false)
  THEN RETURN NULL; END IF;
  proofs:=proofs||jsonb_build_array(jsonb_build_object(
   'evidenceId','urn:openpc:resource:'||item.evidence_id::text,'commandId',command::text,
   'attemptId',source.attempt_id,'receiptDigest',source.result_digest,
   'candidateDigest','sha256:'||source.candidate_digest,'authorizationEvidenceDigest','sha256:'||source.evidence_digest,
   'externalAttemptState','NOT_STARTED','sourceFormat',item.source_format));
 END LOOP;
 RETURN proofs;
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_rejections(text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_rejections(text,uuid) TO openpc_control_runtime;


CREATE OR REPLACE FUNCTION openpc.local_evidence_deletion_plan(record uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s record; rule control.retention_policy%ROWTYPE;
 payload_bytes integer; record_count integer; first_seq numeric; last_seq numeric;
 local_sources boolean; source_micros numeric; quorum_micros numeric; eligible_micros numeric; rejections jsonb;
 sink_receipts jsonb; selection jsonb; before_digest text; blockers text[]:=ARRAY[]::text[];
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT segment.participant_id,segment.privacy_domain_id,segment.stream_id,segment.segment_id,
  segment.first_sequence,segment.through_sequence,segment.object_digest,segment.retention_until,segment.admitted_at
  INTO s FROM control.evidence_catalogue c JOIN control.evidence_segment segment
  USING(participant_id,privacy_domain_id,stream_id,segment_id)
  WHERE c.participant_id=current_setting('openpc.participant_id')::uuid
   AND c.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid AND c.evidence_id=record;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT ciphertext_bytes INTO payload_bytes FROM control.evidence_segment_payload p
  WHERE p.participant_id=s.participant_id AND p.privacy_domain_id=s.privacy_domain_id
   AND p.stream_id=s.stream_id AND p.segment_id=s.segment_id;
 IF NOT FOUND THEN
  IF NOT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.evidence_deletion_item i
   USING(participant_id,privacy_domain_id,deletion_job_id) WHERE j.participant_id=s.participant_id
    AND j.privacy_domain_id=s.privacy_domain_id AND j.segment_id=s.segment_id AND i.segment_id=s.segment_id
    AND j.state='SUCCEEDED') THEN RAISE EXCEPTION 'PC-DATA-6004-EVIDENCE-PAYLOAD'; END IF;
  RETURN jsonb_build_object('evidenceId','urn:openpc:resource:'||record::text,'localPayload','DELETED',
   'eligible',false,'blockers',jsonb_build_array('ALREADY_DELETED'),'selection',null,'beforeDigest',null);
 END IF;
 SELECT count(*)::integer,min(sequence),max(sequence),floor(extract(epoch from max(occurred_at))*1000000),
  bool_and(evidence_class IN ('AUTHENTICATION','BUSINESS_TRANSITION'))
  INTO record_count,first_seq,last_seq,source_micros,local_sources FROM control.evidence_catalogue c
  WHERE c.participant_id=s.participant_id AND c.privacy_domain_id=s.privacy_domain_id
   AND c.stream_id=s.stream_id AND c.segment_id=s.segment_id;
 IF record_count NOT BETWEEN 1 AND 128 OR record_count<>s.through_sequence-s.first_sequence+1 OR first_seq<>s.first_sequence OR last_seq<>s.through_sequence
  OR NOT EXISTS(SELECT 1 FROM control.evidence_stream h WHERE h.participant_id=s.participant_id
   AND h.privacy_domain_id=s.privacy_domain_id AND h.stream_id=s.stream_id AND h.last_sequence>=s.through_sequence)
  OR NOT EXISTS(SELECT 1 FROM control.evidence_checkpoint p WHERE p.participant_id=s.participant_id
   AND p.privacy_domain_id=s.privacy_domain_id AND p.stream_id=s.stream_id AND p.segment_id=s.segment_id
   AND p.object_digest=s.object_digest AND p.through_sequence=s.through_sequence) THEN
  blockers:=array_append(blockers,'INCOMPLETE_CHECKPOINT');
 END IF;
 -- Only signed terminal pre-handoff rejection has authoritative NOT_STARTED
 -- custody. Submitted/ambiguous/confirmation/reorg observations remain blocked.
 IF NOT coalesce(local_sources,false) THEN
  -- Catalogue-only readers do not gain raw prepared-command privileges.
  IF pg_has_role(current_user,'openpc_control_runtime','USAGE') THEN
   rejections:=openpc.evidence_deletion_rejections(s.stream_id,s.segment_id);
  END IF;
  IF rejections IS NULL OR jsonb_array_length(rejections)=0 THEN
   blockers:=array_append(blockers,'UNSUPPORTED_SOURCE');
  END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=s.participant_id
  AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=s.privacy_domain_id) AND h.state='ACTIVE'
  AND openpc.evidence_hold_matches(h.selector,s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id)) THEN
  blockers:=array_append(blockers,'ACTIVE_HOLD');
 END IF;
 -- This target table deliberately has no incoming references. A future owner
 -- adding one must supply a real clearing/alias protocol before deletion resumes.
 IF EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f' AND confrelid='control.evidence_segment_payload'::regclass) THEN
  blockers:=array_append(blockers,'REFERENCES');
 END IF;
 SELECT * INTO rule FROM control.retention_policy p WHERE p.participant_id=s.participant_id
  AND p.privacy_domain_id=s.privacy_domain_id AND p.data_class='AUDIT_EVIDENCE' AND p.active_until IS NULL;
 IF NOT FOUND THEN blockers:=array_append(blockers,'NO_ACTIVE_POLICY');
 ELSE
  IF rule.deletion_mode<>'ROW_DELETE' THEN blockers:=array_append(blockers,'UNSUPPORTED_MODE'); END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('sinkId',chosen.sink_id,'checkpointDigest',chosen.checkpoint_digest,
   'receiptDigest',chosen.receipt_digest,'acknowledgedAtMicros',chosen.ack_micros::text)
    ORDER BY chosen.ack_micros,chosen.sink_id),'[]'::jsonb),max(chosen.ack_micros)
   INTO sink_receipts,quorum_micros FROM (
    SELECT p.sink_id,p.checkpoint_digest,p.receipt_digest,floor(extract(epoch from p.acknowledged_at)*1000000) ack_micros
    FROM control.evidence_checkpoint p WHERE p.participant_id=s.participant_id AND p.privacy_domain_id=s.privacy_domain_id
     AND p.stream_id=s.stream_id AND p.segment_id=s.segment_id AND p.object_digest=s.object_digest
     AND p.through_sequence=s.through_sequence AND p.receipt->>'receiptDigest'=p.receipt_digest
     AND p.receipt->'object'->>'objectDigest'=s.object_digest
    ORDER BY p.acknowledged_at,p.sink_id LIMIT rule.sink_quorum
   ) chosen;
  IF jsonb_array_length(sink_receipts)<>rule.sink_quorum THEN blockers:=array_append(blockers,'SINK_QUORUM'); END IF;
  eligible_micros:=greatest(source_micros+rule.retention_period_ms*1000,
   coalesce(quorum_micros,floor(extract(epoch from s.admitted_at)*1000000))+rule.local_grace_ms*1000,
   floor(extract(epoch from s.retention_until)*1000000));
  IF eligible_micros>floor(extract(epoch from clock_timestamp())*1000000) THEN
   blockers:=array_append(blockers,'RETENTION_NOT_ELAPSED');
  END IF;
  IF record_count BETWEEN 1 AND 128 THEN
   selection:=jsonb_build_object('version','OPENPC_LOCAL_EVIDENCE_DELETION_V1',
    'evidenceId','urn:openpc:resource:'||record::text,'participantId','urn:openpc:participant:'||s.participant_id::text,
    'privacyDomainId',s.privacy_domain_id::text,'retentionPolicyId','urn:openpc:resource:'||rule.retention_policy_id::text,
    'policyDigest',rule.policy_digest,'targetDatabase','openpc_control','dataClass','AUDIT_EVIDENCE','deletionMode','ROW_DELETE',
    'streamId',s.stream_id,'segmentId',s.segment_id::text,'firstSequence',s.first_sequence::text,
    'throughSequence',s.through_sequence::text,'objectDigest',s.object_digest,'ciphertextBytes',payload_bytes,
    'recordCount',record_count,'eligibleAfterMicros',eligible_micros::text,'sinkReceipts',sink_receipts,'priorCursor',null);
   IF rejections IS NOT NULL AND jsonb_array_length(rejections)>0 THEN
    selection:=selection||jsonb_build_object('sourceRejections',rejections);
   END IF;
   before_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
    'domain','pc.evidence.local-payload-before.v1','participantId',s.participant_id::text,'privacyDomainId',s.privacy_domain_id::text,
    'streamId',s.stream_id,'segmentId',s.segment_id::text,'objectDigest',s.object_digest,
    'ciphertextBytes',payload_bytes,'recordCount',record_count)),'UTF8')),'hex');
  END IF;
 END IF;
 RETURN jsonb_build_object('evidenceId','urn:openpc:resource:'||record::text,'localPayload','RETAINED',
  'eligible',cardinality(blockers)=0,'blockers',to_jsonb(blockers),'selection',selection,'beforeDigest',before_digest);
END $$;
REVOKE ALL ON FUNCTION openpc.local_evidence_deletion_plan(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.local_evidence_deletion_plan(uuid) TO openpc_control_runtime,openpc_control_reader;


CREATE OR REPLACE FUNCTION openpc.evidence_deletion_target(plan jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('evidenceId',plan->'selection'->'evidenceId',
  'segmentId',plan->'selection'->'segmentId','firstSequence',plan->'selection'->'firstSequence',
  'throughSequence',plan->'selection'->'throughSequence','objectDigest',plan->'selection'->'objectDigest',
  'ciphertextBytes',plan->'selection'->'ciphertextBytes','recordCount',plan->'selection'->'recordCount',
  'beforeDigest',plan->'beforeDigest')
$$;
CREATE OR REPLACE FUNCTION openpc.local_evidence_deletion_batch_plan(record uuid,previous uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE plan jsonb; selected jsonb; targets jsonb:='[]'::jsonb; target jsonb; candidate record;
 prior control.deletion_job%ROWTYPE; receipt_digest text; next_job uuid; position integer:=0;
 cursor jsonb:='null'::jsonb; anchor jsonb; prior_policy jsonb; blockers jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF (record IS NULL)=(previous IS NULL) THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF previous IS NOT NULL THEN
  SELECT * INTO prior FROM control.deletion_job j
   WHERE j.participant_id=current_setting('openpc.participant_id')::uuid
    AND j.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid AND j.deletion_job_id=previous;
  IF NOT FOUND OR prior.state<>'SUCCEEDED'
   OR prior.selection->>'version'<>'OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1' THEN RETURN NULL; END IF;
  SELECT 'sha256:'||encode(a.receipt_digest,'hex') INTO receipt_digest FROM control.audit_occurrence a
   WHERE a.participant_id=prior.participant_id AND a.privacy_domain_id=prior.privacy_domain_id
    AND a.aggregate_type='evidence-deletion' AND a.aggregate_id=prior.deletion_job_id
    AND a.operation_id=prior.operation_id AND a.profile_id='pc.control.evidence-deletion.batch'
    AND a.catalog_operation_id='CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH';
  IF receipt_digest IS NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  targets:=prior.selection->'targets'; position:=(prior.selection->>'batchIndex')::integer+1;
  cursor:=jsonb_build_object('deletionJobId','urn:openpc:resource:'||previous::text,'receiptDigest',receipt_digest);
  SELECT deletion_job_id INTO next_job FROM control.deletion_job j
   WHERE j.participant_id=prior.participant_id AND j.privacy_domain_id=prior.privacy_domain_id
    AND j.previous_deletion_job_id=previous AND j.state='SUCCEEDED';
  IF next_job IS NOT NULL OR position=jsonb_array_length(targets) THEN
   RETURN jsonb_build_object('evidenceId',prior.selection->'evidenceId','localPayload','DELETED',
    'eligible',false,'blockers','[]'::jsonb,'selection',null,'beforeDigest',null,
    'continuationState',CASE WHEN next_job IS NULL THEN 'COMPLETE' ELSE 'ADVANCED' END,
    'nextDeletionJobId',CASE WHEN next_job IS NULL THEN NULL ELSE 'urn:openpc:resource:'||next_job::text END);
  END IF;
  target:=targets->position;
  prior_policy:=jsonb_build_array(prior.selection->'retentionPolicyId',prior.selection->'policyDigest');
  plan:=openpc.local_evidence_deletion_plan(right(target->>'evidenceId',36)::uuid);
 ELSE
  anchor:=openpc.local_evidence_deletion_plan(record);
  IF anchor IS NULL THEN RETURN NULL; END IF;
  IF anchor->'selection'='null'::jsonb THEN
   RETURN anchor||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null);
  END IF;
  FOR candidate IN
   SELECT first_record.evidence_id FROM control.evidence_segment s
    JOIN control.evidence_segment_payload p USING(participant_id,privacy_domain_id,stream_id,segment_id)
    CROSS JOIN LATERAL (SELECT c.evidence_id FROM control.evidence_catalogue c
     WHERE c.participant_id=s.participant_id AND c.privacy_domain_id=s.privacy_domain_id
      AND c.stream_id=s.stream_id AND c.segment_id=s.segment_id ORDER BY c.sequence LIMIT 1) first_record
    WHERE s.participant_id=current_setting('openpc.participant_id')::uuid
     AND s.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
     AND s.stream_id=anchor->'selection'->>'streamId'
     AND s.segment_id>=(anchor->'selection'->>'segmentId')::uuid
    ORDER BY s.segment_id LIMIT 16
  LOOP
   selected:=openpc.local_evidence_deletion_plan(candidate.evidence_id);
   IF selected->'selection'='null'::jsonb THEN
    RETURN selected||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null);
   END IF;
   targets:=targets||jsonb_build_array(openpc.evidence_deletion_target(selected));
   IF plan IS NULL THEN plan:=selected; END IF;
  END LOOP;
  target:=targets->0;
 END IF;
 IF plan IS NULL OR target IS NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 blockers:=plan->'blockers';
 IF plan->'selection'='null'::jsonb THEN
  RETURN plan||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null);
 END IF;
 IF openpc.evidence_deletion_target(plan) IS DISTINCT FROM target OR
  (prior_policy IS NOT NULL AND prior_policy IS DISTINCT FROM
   jsonb_build_array(plan->'selection'->'retentionPolicyId',plan->'selection'->'policyDigest')) THEN
  blockers:=blockers||jsonb_build_array('STALE_SELECTION');
 END IF;
 selected:=(plan->'selection')||jsonb_build_object('version','OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1',
  'targets',targets,'batchIndex',position,'priorCursor',cursor);
 RETURN plan||jsonb_build_object('eligible',jsonb_array_length(blockers)=0,'blockers',blockers,
  'selection',CASE WHEN blockers ? 'STALE_SELECTION' THEN NULL ELSE selected END,
  'continuationState',CASE WHEN jsonb_array_length(blockers)=0 THEN 'READY' ELSE 'BLOCKED' END,
  'nextDeletionJobId',null);
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_target(jsonb),openpc.local_evidence_deletion_batch_plan(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_target(jsonb),openpc.local_evidence_deletion_batch_plan(uuid,uuid)
 TO openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.evidence_deletion_selection_plan(selection jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF selection->>'version'='OPENPC_RAW_PROOF_DELETION_BATCH_V1' THEN
  IF selection->'priorCursor'='null'::jsonb THEN
   RETURN openpc.raw_proof_deletion_batch_plan(right(selection->>'objectRef',36)::uuid,NULL);
  END IF;
  RETURN openpc.raw_proof_deletion_batch_plan(NULL,right(selection->'priorCursor'->>'deletionJobId',36)::uuid);
 ELSIF selection->>'version'='OPENPC_LOCAL_EVIDENCE_DELETION_V1' THEN
  RETURN openpc.local_evidence_deletion_plan(right(selection->>'evidenceId',36)::uuid);
 ELSIF selection->>'version'='OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1' THEN
  IF selection->'priorCursor'='null'::jsonb THEN
   RETURN openpc.local_evidence_deletion_batch_plan(right(selection->>'evidenceId',36)::uuid,NULL);
  END IF;
  RETURN openpc.local_evidence_deletion_batch_plan(NULL,right(selection->'priorCursor'->>'deletionJobId',36)::uuid);
 END IF;
 RAISE EXCEPTION 'PC-DATA-6004';
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_selection_plan(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_selection_plan(jsonb) TO openpc_control_runtime;


CREATE OR REPLACE FUNCTION openpc.evidence_deletion_operation(selection jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE selection->>'version' WHEN 'OPENPC_LOCAL_EVIDENCE_DELETION_V1' THEN 'CFG-OP-DELETE-LOCAL-EVIDENCE'
 WHEN 'OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1' THEN 'CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH'
 WHEN 'OPENPC_RAW_PROOF_DELETION_BATCH_V1' THEN 'CFG-OP-DELETE-RAW-PROOF-BATCH' END
$$;
CREATE OR REPLACE FUNCTION openpc.evidence_deletion_action(selection jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE selection->>'version' WHEN 'OPENPC_LOCAL_EVIDENCE_DELETION_V1' THEN 'ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1'
 WHEN 'OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1' THEN 'ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1'
 WHEN 'OPENPC_RAW_PROOF_DELETION_BATCH_V1' THEN 'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1' END
$$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_operation(jsonb),openpc.evidence_deletion_action(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_operation(jsonb),openpc.evidence_deletion_action(jsonb) TO openpc_control_runtime;


CREATE OR REPLACE FUNCTION openpc.evidence_deletion_selector_digest(selection jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','pc.evidence.local-payload-selector.v1','participantId',selection->'participantId',
  'privacyDomainId',selection->'privacyDomainId','streamId',selection->'streamId','segmentId',selection->'segmentId',
  'firstSequence',selection->'firstSequence','throughSequence',selection->'throughSequence')),'UTF8')),'hex')
$$;
CREATE OR REPLACE FUNCTION openpc.evidence_deletion_after_digest(selector_digest text)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','pc.evidence.local-payload-after.v1','selectorDigest',selector_digest,'payloads','[]'::jsonb)),'UTF8')),'hex')
$$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_selector_digest(jsonb),openpc.evidence_deletion_after_digest(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_selector_digest(jsonb),openpc.evidence_deletion_after_digest(text) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_deletion_job()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE plan jsonb; item control.evidence_deletion_item%ROWTYPE; current_bytes bigint;
BEGIN
 IF TG_OP<>'DELETE' AND NEW.selection->>'version'='OPENPC_RAW_PROOF_DELETION_BATCH_V1' THEN
  RETURN openpc.guard_raw_proof_deletion_job(TG_OP,OLD,NEW);
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id') IS DISTINCT FROM openpc.evidence_deletion_action(NEW.selection)
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.operation_id<>current_setting('openpc.operation_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 SELECT used_bytes INTO STRICT current_bytes FROM control.evidence_stream
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id FOR UPDATE;
 IF TG_OP='INSERT' THEN
  NEW.previous_deletion_job_id:=right(NEW.selection->'priorCursor'->>'deletionJobId',36)::uuid;
  IF NEW.previous_deletion_job_id IS NOT NULL THEN
   PERFORM 1 FROM control.deletion_job WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
    AND deletion_job_id=NEW.previous_deletion_job_id FOR UPDATE;
  END IF;
  plan:=openpc.evidence_deletion_selection_plan(NEW.selection);
  IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM NEW.selection
   OR plan->>'beforeDigest' IS DISTINCT FROM NEW.before_digest OR NEW.state<>'EXECUTING' OR NEW.revision<>0
   OR NEW.retention_policy_id<>right(NEW.selection->>'retentionPolicyId',36)::uuid
   OR NEW.stream_id<>NEW.selection->>'streamId' OR NEW.segment_id<>(NEW.selection->>'segmentId')::uuid
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.target_selector_digest:=openpc.evidence_deletion_selector_digest(NEW.selection);
  NEW.eligibility_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.selection),'UTF8')),'hex');
  NEW.before_used_bytes:=current_bytes;NEW.after_used_bytes:=NULL;
  NEW.started_at:=clock_timestamp();NEW.created_at:=NEW.started_at;
 ELSE
  IF OLD.state<>'EXECUTING' OR NEW.state<>'SUCCEEDED' OR OLD.revision<>0 OR NEW.revision<>1
   OR (to_jsonb(NEW)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at'])
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO STRICT item FROM control.evidence_deletion_item WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND deletion_job_id=NEW.deletion_job_id;
  IF item.segment_id<>NEW.segment_id OR item.object_digest<>NEW.selection->>'objectDigest'
   OR current_bytes<>NEW.before_used_bytes-item.ciphertext_bytes
   OR EXISTS(SELECT 1 FROM control.evidence_segment_payload WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND segment_id=NEW.segment_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.deleted_count:=1;NEW.deleted_bytes:=item.ciphertext_bytes;NEW.after_used_bytes:=current_bytes;
  NEW.after_digest:=openpc.evidence_deletion_after_digest(NEW.target_selector_digest);
  NEW.completed_at:=clock_timestamp();
 END IF;
 NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_deletion_job_guard ON control.deletion_job;
CREATE TRIGGER evidence_deletion_job_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deletion_job
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_deletion_job();

CREATE OR REPLACE FUNCTION openpc.record_evidence_payload_deletion(payload control.evidence_segment_payload)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE job control.deletion_job%ROWTYPE; plan jsonb;
BEGIN
 -- Only the actual payload BEFORE DELETE trigger can attest this local effect.
 IF pg_trigger_depth()<>1 OR current_setting('openpc.action_intent_id') NOT IN ('ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1','ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1')
  OR payload.participant_id<>current_setting('openpc.participant_id')::uuid
  OR payload.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||payload.participant_id::text,0));
 SELECT * INTO STRICT job FROM control.deletion_job WHERE participant_id=payload.participant_id
  AND privacy_domain_id=payload.privacy_domain_id AND operation_id=current_setting('openpc.operation_id')::uuid
  AND state='EXECUTING' AND revision=0 AND segment_id=payload.segment_id AND stream_id=payload.stream_id FOR UPDATE;
 plan:=openpc.evidence_deletion_selection_plan(job.selection);
 IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM job.selection
  OR plan->>'beforeDigest' IS DISTINCT FROM job.before_digest
  OR payload.ciphertext_bytes<>(job.selection->>'ciphertextBytes')::integer
  OR 'sha256:'||encode(sha256(payload.encrypted_segment),'hex')<>job.selection->>'objectDigest'
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 INSERT INTO control.evidence_deletion_item(participant_id,privacy_domain_id,deletion_job_id,segment_id,object_digest,ciphertext_bytes)
 VALUES(payload.participant_id,payload.privacy_domain_id,job.deletion_job_id,payload.segment_id,job.selection->>'objectDigest',payload.ciphertext_bytes);
END $$;
REVOKE ALL ON FUNCTION openpc.record_evidence_payload_deletion(control.evidence_segment_payload) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.record_evidence_payload_deletion(control.evidence_segment_payload) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_deletion_item()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' AND pg_trigger_depth()=2 AND NEW.protected_object_id IS NOT NULL
  AND openpc.raw_proof_deletion_item_matches(NEW) THEN RETURN NEW; END IF;
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<>2
  OR NOT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.evidence_segment_payload p
   ON p.participant_id=j.participant_id AND p.privacy_domain_id=j.privacy_domain_id AND p.segment_id=j.segment_id
   WHERE j.participant_id=NEW.participant_id AND j.privacy_domain_id=NEW.privacy_domain_id
    AND j.deletion_job_id=NEW.deletion_job_id AND j.operation_id=current_setting('openpc.operation_id')::uuid
    AND j.state='EXECUTING' AND j.segment_id=NEW.segment_id AND j.selection->>'objectDigest'=NEW.object_digest
    AND p.ciphertext_bytes=NEW.ciphertext_bytes)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_deletion_item_guard ON control.evidence_deletion_item;
CREATE TRIGGER evidence_deletion_item_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_deletion_item
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_deletion_item();

CREATE OR REPLACE FUNCTION openpc.assert_evidence_deletion_accounting(old_stream control.evidence_stream,new_stream control.evidence_stream)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF old_stream.participant_id<>current_setting('openpc.participant_id')::uuid
  OR old_stream.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR (to_jsonb(old_stream)-'used_bytes') IS DISTINCT FROM (to_jsonb(new_stream)-'used_bytes')
  OR NOT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.evidence_deletion_item i
   USING(participant_id,privacy_domain_id,deletion_job_id)
   WHERE j.participant_id=old_stream.participant_id AND j.privacy_domain_id=old_stream.privacy_domain_id
    AND j.stream_id=old_stream.stream_id AND j.operation_id=current_setting('openpc.operation_id')::uuid
    AND j.state='EXECUTING' AND old_stream.used_bytes=j.before_used_bytes
    AND new_stream.used_bytes=old_stream.used_bytes-i.ciphertext_bytes
    AND NOT EXISTS(SELECT 1 FROM control.evidence_segment_payload p WHERE p.participant_id=j.participant_id
     AND p.privacy_domain_id=j.privacy_domain_id AND p.segment_id=j.segment_id)) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_evidence_deletion_accounting(control.evidence_stream,control.evidence_stream) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_evidence_deletion_accounting(control.evidence_stream,control.evidence_stream) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.evidence_deletion_state_projection(job control.deletion_job)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',openpc.business_uuid((job).retention_policy_id),
  '1',openpc.business_bytes(decode(substring((job).target_selector_digest from 8),'hex')),
  '2',openpc.business_bytes(decode(substring((job).eligibility_digest from 8),'hex')),
  '3',openpc.business_bytes(decode(substring((job).before_digest from 8),'hex')),
  '4',openpc.business_bytes(decode(substring((job).after_digest from 8),'hex')),
  '5',openpc.business_uuid((job).attempt_id),'6',openpc.business_uuid((job).operation_id),
  '7',openpc.business_uuid((job).approval_request_id),'8',(job).deleted_count,'9',(job).deleted_bytes,
  '10',(job).retained_alias_count,'11',floor(extract(epoch from (job).started_at)*1000000)*1000,
  '12',floor(extract(epoch from (job).completed_at)*1000000)*1000,'13',(job).before_used_bytes,'14',(job).after_used_bytes)
$$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_state_projection(control.deletion_job) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_state_projection(control.deletion_job) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.assert_evidence_deletion_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.deletion_job j WHERE j.participant_id=receipt.participant_id
  AND j.privacy_domain_id=receipt.privacy_domain_id AND j.deletion_job_id=receipt.aggregate_id
  AND j.operation_id=receipt.operation_id AND j.state='SUCCEEDED' AND j.revision=1
  AND receipt.catalog_operation_id=openpc.evidence_deletion_operation(j.selection) AND receipt.before_existence=0 AND receipt.before_revision=0
  AND receipt.after_existence=1 AND receipt.after_revision=1
  AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.evidence_deletion_state_projection(j))
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-DELETION-STATE'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_evidence_deletion_receipt(control.audit_occurrence) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_evidence_deletion_receipt(control.audit_occurrence) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.require_evidence_deletion_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.evidence_deletion_item item
  USING(participant_id,privacy_domain_id,deletion_job_id)
  JOIN control.mutation_evidence e ON e.participant_id=j.participant_id AND e.privacy_domain_id=j.privacy_domain_id
   AND e.aggregate_id=j.deletion_job_id AND e.operation_id=j.operation_id AND e.aggregate_type='evidence-deletion'
  JOIN control.mutation_candidate c ON c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
   AND c.resource_id=e.aggregate_id AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
  JOIN control.audit_occurrence receipt ON receipt.participant_id=e.participant_id AND receipt.privacy_domain_id=e.privacy_domain_id
   AND receipt.operation_id=e.operation_id AND receipt.aggregate_id=e.aggregate_id AND receipt.aggregate_type='evidence-deletion'
  WHERE j.participant_id=NEW.participant_id AND j.privacy_domain_id=NEW.privacy_domain_id AND j.deletion_job_id=NEW.deletion_job_id
   AND j.state='SUCCEEDED' AND j.revision=1 AND j.deleted_count=1 AND j.deleted_bytes=item.ciphertext_bytes
   AND j.after_digest=openpc.evidence_deletion_after_digest(j.target_selector_digest)
   AND CASE WHEN j.target_data_class='RAW_SOURCE_BODY' THEN openpc.raw_proof_deletion_effect_matches(j,item)
    ELSE j.target_data_class='AUDIT_EVIDENCE' AND j.segment_id=item.segment_id AND j.selection->>'objectDigest'=item.object_digest
     AND NOT EXISTS(SELECT 1 FROM control.evidence_segment_payload p WHERE p.participant_id=j.participant_id
      AND p.privacy_domain_id=j.privacy_domain_id AND p.segment_id=j.segment_id)
     AND EXISTS(SELECT 1 FROM control.evidence_stream s WHERE s.participant_id=j.participant_id
      AND s.privacy_domain_id=j.privacy_domain_id AND s.stream_id=j.stream_id AND s.used_bytes=j.after_used_bytes) END
   AND e.approval_request_id=j.approval_request_id AND e.catalog_operation_id=openpc.evidence_deletion_operation(j.selection)
   AND e.action_intent_id=openpc.evidence_deletion_action(j.selection) AND c.catalog_operation_id=e.catalog_operation_id
   AND c.action_intent_id=e.action_intent_id AND c.state='CONSUMED' AND c.expected_revision=0
   AND c.candidate_document->'selection'=j.selection AND c.candidate_document->>'beforeDigest'=j.before_digest
   AND receipt.catalog_operation_id=e.catalog_operation_id AND receipt.action_intent_id=e.action_intent_id
   AND receipt.before_existence=0 AND receipt.before_revision=0 AND receipt.after_existence=1 AND receipt.after_revision=1
   AND openpc.business_cbor(receipt.before_state_preimage)->8='{}'::jsonb
   AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.evidence_deletion_state_projection(j)
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=receipt.participant_id
    AND event.privacy_domain_id=receipt.privacy_domain_id AND event.receipt_id=receipt.receipt_id
    AND event.aggregate_type=receipt.aggregate_type AND event.aggregate_id=receipt.aggregate_id
    AND event.event_type='io.openpc.control.command.committed.v1' AND event.proof_kind='BUSINESS_RECEIPT_REFERENCE'
    AND event.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1' AND event.payload_digest=sha256(event.payload_cbor)))
 THEN RAISE EXCEPTION 'PC-AUTH-0002-DELETION-SIGNED-EFFECT'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS evidence_deletion_command_required ON control.deletion_job;
CREATE CONSTRAINT TRIGGER evidence_deletion_command_required AFTER INSERT OR UPDATE ON control.deletion_job
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_deletion_command();


INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1','protected-proofs','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_RETENTION'),
('ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1','protected-proof-access','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_ACCESS_REQUEST'),
('ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1','protected-proof-access','EXPORT','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_CONSUMPTION'),
('ACT-PROTECTED_PROOFS_READ_SOURCE-V1','evidence-records','READ','HIGH',false,false,false,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_SOURCE_READ'),
('ACT-PROTECTED_PROOFS_READ_RESOURCE-V1','protected-proofs','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_METADATA_READ'),
('ACT-PROTECTED_PROOFS_READ_COLLECTION-V1','protected-proofs','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_METADATA_READ'),
('ACT-PROTECTED_PROOF_ACCESS_READ_RESOURCE-V1','protected-proof-access','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_ACCESS_READ'),
('ACT-PROTECTED_PROOF_ACCESS_READ_COLLECTION-V1','protected-proof-access','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_ACCESS_READ') ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE (action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
 IN (('ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1','protected-proofs','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_RETENTION'),
('ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1','protected-proof-access','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_ACCESS_REQUEST'),
('ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1','protected-proof-access','EXPORT','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_CONSUMPTION'),
('ACT-PROTECTED_PROOFS_READ_SOURCE-V1','evidence-records','READ','HIGH',false,false,false,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_SOURCE_READ'),
('ACT-PROTECTED_PROOFS_READ_RESOURCE-V1','protected-proofs','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_METADATA_READ'),
('ACT-PROTECTED_PROOFS_READ_COLLECTION-V1','protected-proofs','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_METADATA_READ'),
('ACT-PROTECTED_PROOF_ACCESS_READ_RESOURCE-V1','protected-proof-access','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_ACCESS_READ'),
('ACT-PROTECTED_PROOF_ACCESS_READ_COLLECTION-V1','protected-proof-access','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','PROTECTED_PROOF_ACCESS_READ')))<>8 THEN RAISE EXCEPTION 'PC-AUTH-0002-PROTECTED-PROOF-ACTION'; END IF;
END $$;
ALTER TABLE control.protected_proof_object FORCE ROW LEVEL SECURITY;
ALTER TABLE control.protected_proof_payload FORCE ROW LEVEL SECURITY;
ALTER TABLE control.protected_proof_access FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.protected_proof_object,control.protected_proof_payload,control.protected_proof_access
 FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT,INSERT ON control.protected_proof_object,control.protected_proof_payload,control.protected_proof_access TO openpc_control_runtime;
GRANT UPDATE ON control.protected_proof_access TO openpc_control_runtime;
GRANT SELECT ON control.protected_proof_object,control.protected_proof_access TO openpc_control_reader;
GRANT SELECT ON control.authentication_occurrence TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.protected_proof_binding(o control.protected_proof_object)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('objectRef','urn:openpc:resource:'||(o).object_id::text,
  'objectVersion',(o).object_version::text,'objectDigest',(o).object_digest,'source',(o).source)
$$;

CREATE OR REPLACE FUNCTION openpc.guard_protected_proof_object()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a record; e record; expected jsonb; payload jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.creation_operation_id<>current_setting('openpc.operation_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT occurrence.* INTO a FROM control.evidence_catalogue c JOIN control.authentication_occurrence occurrence
  ON occurrence.participant_id=c.participant_id AND occurrence.privacy_domain_id=c.privacy_domain_id
   AND occurrence.occurrence_id::text=c.record_id AND c.evidence_class='AUTHENTICATION'
   AND c.receipt_digest='sha256:'||encode(occurrence.receipt_digest,'hex')
  WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
   AND 'urn:openpc:resource:'||c.evidence_id::text=NEW.source->>'evidenceId' AND occurrence.method='WEBAUTHN_ASSERTION';
 SELECT proof.* INTO e FROM control.mutation_evidence proof JOIN control.idempotency_record i
  ON i.participant_id=proof.participant_id AND i.privacy_domain_id=proof.privacy_domain_id
   AND i.operation_id=proof.operation_id AND i.terminal_state='COMMITTED' AND i.input_digest=proof.candidate_digest
  WHERE proof.participant_id=NEW.participant_id AND proof.privacy_domain_id=NEW.privacy_domain_id
   AND proof.operation_id=a.operation_id AND proof.principal_id=a.principal_id AND proof.aggregate_id=a.session_id
   AND proof.mfa_challenge_id=a.source_id AND proof.signer_credential_id=a.credential_id
   AND proof.webauthn_assertion_binding_digest=a.proof_digest AND proof.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY';
 IF a.occurrence_id IS NULL OR e.operation_id IS NULL OR e.evidence_digest<>sha256(e.evidence_cbor)
  OR coalesce(NEW.source->>'signerKeyDigest','')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 expected:=jsonb_build_object('evidenceId',NEW.source->>'evidenceId','occurrenceId',a.occurrence_id::text,
  'operationId',a.operation_id::text,'sourceReceiptDigest','sha256:'||encode(a.receipt_digest,'hex'),
  'proofDigest','sha256:'||encode(a.proof_digest,'hex'),'assertionDigest','sha256:'||encode(e.evidence_digest,'hex'),
  'signatureDigest','sha256:'||encode(sha256(e.cose_sign1),'hex'),'signerKeyDigest',NEW.source->>'signerKeyDigest',
  'occurredAt',to_char(a.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'materialType','IDENTITY_SIGNED_AUTHORIZATION_ASSERTION','evidenceClass','AUTHENTICATION',
  'sourceFormat','IDENTITY_RUNTIME_ASSERTION_3002_2_13','occurrenceIntegrity','CONTROL_DATABASE_IMMUTABLE',
  'proofIntegrity','IDENTITY_COSE_ED25519','finality','NOT_APPLICABLE','authorityEffect','NONE');
 payload:=jsonb_build_object('version','OPENPC_PROTECTED_IDENTITY_PROOF_V1','participantId',NEW.participant_id::text,
  'privacyDomainId',NEW.privacy_domain_id::text,'source',expected,
  'assertionBase64',replace(encode(e.evidence_cbor,'base64'),chr(10),''),'coseSign1Base64',replace(encode(e.cose_sign1,'base64'),chr(10),''));
 IF NEW.source IS DISTINCT FROM expected OR NEW.object_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(payload),'UTF8')),'hex')
  OR NEW.object_version<>1 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.created_at:=clock_timestamp(); NEW.updated_at:=NEW.created_at;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_protected_proof_payload()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE used bigint;
BEGIN
 IF TG_OP='DELETE' THEN
  PERFORM openpc.record_raw_proof_payload_deletion(OLD);
  RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT EXISTS(SELECT 1 FROM control.protected_proof_object o WHERE o.object_id=NEW.object_id
  AND o.participant_id=NEW.participant_id AND o.privacy_domain_id=NEW.privacy_domain_id
  AND o.creation_operation_id=current_setting('openpc.operation_id')::uuid)
  OR current_setting('openpc.action_intent_id')<>'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1' THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('protected-proof-capacity:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0));
 SELECT coalesce(sum(octet_length(ciphertext)),0) INTO used FROM control.protected_proof_payload
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id;
 IF used+octet_length(NEW.ciphertext)>16777216 THEN RAISE EXCEPTION 'PC-OPS-9002'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_protected_proof_access()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o control.protected_proof_object; expected jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO o FROM control.protected_proof_object WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND object_id=NEW.object_id;
 IF o.object_id IS NULL OR o.retain_until<=clock_timestamp() OR NEW.expires_at>o.retain_until
  OR NEW.object_binding IS DISTINCT FROM openpc.protected_proof_binding(o)
  OR NEW.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_OP='INSERT' THEN
  IF current_setting('openpc.action_intent_id')<>'ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1'
   OR NEW.creation_operation_id<>current_setting('openpc.operation_id')::uuid OR NEW.revision<>1
   OR NEW.consumed_at IS NOT NULL OR NEW.consumption_operation_id IS NOT NULL OR NEW.consumption_request IS NOT NULL
   THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  NEW.created_at:=clock_timestamp(); NEW.updated_at:=NEW.created_at;
 ELSE
  IF current_setting('openpc.action_intent_id')<>'ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1'
   OR OLD.revision<>1 OR NEW.revision<>2 OR NEW.consumption_operation_id<>current_setting('openpc.operation_id')::uuid
   OR (to_jsonb(NEW)-ARRAY['revision','consumption_operation_id','consumed_at','updated_at','consumption_request']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['revision','consumption_operation_id','consumed_at','updated_at','consumption_request'])
   THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  expected:=jsonb_build_object('targetRef','urn:openpc:resource:'||NEW.access_id::text,'expectedRevision','1',
   'object',NEW.object_binding,'purpose',NEW.purpose,'caseReference',NEW.case_reference,
   'recipientPrincipalId',NEW.recipient_principal_id::text,'expiresAt',to_char(NEW.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  IF NEW.consumption_request-ARRAY['reason','actionIntentId','actionIntentDigest'] IS DISTINCT FROM expected
   OR NEW.consumption_request->>'actionIntentId'<>'ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1'
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.consumed_at:=clock_timestamp(); NEW.updated_at:=NEW.consumed_at;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.require_protected_proof_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE op uuid; rid uuid; action text; catalog text; aggregate text; document jsonb; expected numeric;
 e control.mutation_evidence; c control.mutation_candidate; original control.mutation_evidence;
BEGIN
 IF TG_TABLE_NAME='protected_proof_object' THEN
  op:=NEW.creation_operation_id;rid:=NEW.object_id;action:='ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1';
  catalog:='CFG-OP-RETAIN-PROTECTED-PROOF';aggregate:='protected-proof';expected:=0;
  document:=jsonb_build_object('source',NEW.source,'purpose',NEW.purpose,'caseReference',NEW.case_reference,
   'retainUntil',to_char(NEW.retain_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  IF NOT EXISTS(SELECT 1 FROM control.protected_proof_payload WHERE object_id=rid AND participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSIF TG_OP='INSERT' THEN
  op:=NEW.creation_operation_id;rid:=NEW.access_id;action:='ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1';
  catalog:='CFG-OP-REQUEST-PROTECTED-ACCESS';aggregate:='protected-proof-access';expected:=0;
  document:=jsonb_build_object('object',NEW.object_binding,'purpose',NEW.purpose,'caseReference',NEW.case_reference,
   'recipientPrincipalId',NEW.recipient_principal_id::text,'expiresAt',to_char(NEW.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 ELSE
  op:=NEW.consumption_operation_id;rid:=NEW.access_id;action:='ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1';
  catalog:='CFG-OP-CONSUME-PROTECTED-ACCESS';aggregate:='protected-proof-access';expected:=1;document:=NEW.consumption_request;
 END IF;
 SELECT proof.* INTO e FROM control.mutation_evidence proof JOIN control.idempotency_record i
  ON i.participant_id=proof.participant_id AND i.privacy_domain_id=proof.privacy_domain_id AND i.operation_id=proof.operation_id
   AND i.principal_id=proof.principal_id AND i.action_intent_id=proof.action_intent_id AND i.catalog_operation_id=proof.catalog_operation_id
   AND i.input_digest=proof.candidate_digest AND i.terminal_state='COMMITTED' AND i.expected_aggregate_version=expected
   AND i.result_payload->>'resourceRef'='urn:openpc:resource:'||rid::text
  WHERE proof.participant_id=NEW.participant_id AND proof.privacy_domain_id=NEW.privacy_domain_id
   AND proof.operation_id=op AND proof.action_intent_id=action AND proof.catalog_operation_id=catalog
   AND proof.aggregate_type=aggregate AND proof.aggregate_id=rid;
 IF e.operation_id IS NULL OR NOT EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=e.participant_id
  AND event.privacy_domain_id=e.privacy_domain_id AND event.aggregate_type=aggregate AND event.aggregate_id=rid
  AND event.event_type=CASE catalog WHEN 'CFG-OP-RETAIN-PROTECTED-PROOF' THEN 'openpc.evidence.protected.retained.v1'
   WHEN 'CFG-OP-REQUEST-PROTECTED-ACCESS' THEN 'openpc.evidence.protected.access-requested.v1' ELSE 'openpc.evidence.protected.consumed.v1' END
  AND event.payload_digest=sha256(event.payload_cbor)
  AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(e.candidate_digest,'hex')
  AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'='sha256:'||encode(e.evidence_digest,'hex'))
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF expected=0 THEN
  SELECT candidate.* INTO c FROM control.mutation_candidate candidate JOIN control.approval_request a
   ON a.participant_id=candidate.participant_id AND a.privacy_domain_id=candidate.privacy_domain_id
    AND a.subject_id=candidate.mutation_candidate_id AND a.approval_request_id=e.approval_request_id
   WHERE candidate.participant_id=e.participant_id AND candidate.privacy_domain_id=e.privacy_domain_id
    AND candidate.consumed_operation_id=op AND candidate.state='CONSUMED' AND candidate.candidate_digest=e.candidate_digest
    AND candidate.action_intent_id=action AND candidate.catalog_operation_id=catalog AND candidate.resource_id=rid
    AND candidate.maker_principal_id=e.principal_id AND candidate.expected_revision=0;
  IF c.mutation_candidate_id IS NULL OR e.checker_principal_id IS NULL OR e.checker_principal_id=e.principal_id
   OR NEW.approval_request_id IS DISTINCT FROM e.approval_request_id
   OR c.candidate_document-ARRAY['participantId','actionIntentId','actionIntentDigest','reason'] IS DISTINCT FROM document
   OR NOT EXISTS(SELECT 1 FROM control.mfa_challenge m WHERE m.participant_id=e.participant_id AND m.mfa_challenge_id=e.mfa_challenge_id
    AND m.principal_id=e.principal_id AND m.used_operation_id=op AND m.action_intent_id=action AND m.resource_digest=e.candidate_digest
    AND m.consumed_at>clock_timestamp()-interval '5 minutes') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 ELSE
  IF e.candidate_digest<>sha256(convert_to(openpc.signing_canonical_json(document),'UTF8')) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO original FROM control.mutation_evidence WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.creation_operation_id;
  IF original.operation_id IS NULL OR (original.principal_id,original.bound_participant_epoch,original.bound_principal_epoch,
    original.bound_authority_envelope_id,original.bound_envelope_epoch,original.bound_assignment_id) IS DISTINCT FROM
   (e.principal_id,e.bound_participant_epoch,e.bound_principal_epoch,e.bound_authority_envelope_id,e.bound_envelope_epoch,e.bound_assignment_id)
   THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 END IF;
 IF TG_TABLE_NAME='protected_proof_access' THEN
  IF NEW.recipient_principal_id<>e.principal_id OR NOT EXISTS(SELECT 1 FROM control.session s
   WHERE s.participant_id=NEW.participant_id AND s.session_id=NEW.sender_session_id AND s.principal_id=e.principal_id
    AND s.privacy_domain_id=NEW.privacy_domain_id AND s.state='ACTIVE' AND s.absolute_expires_at>clock_timestamp()
    AND s.idle_expires_at>clock_timestamp()) THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  IF expected=0 AND NOT EXISTS(SELECT 1 FROM control.mfa_challenge m WHERE m.participant_id=e.participant_id
   AND m.mfa_challenge_id=e.mfa_challenge_id AND m.session_id=NEW.sender_session_id) THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 END IF;
 RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS protected_proof_object_guard ON control.protected_proof_object;
CREATE TRIGGER protected_proof_object_guard BEFORE INSERT OR UPDATE OR DELETE ON control.protected_proof_object
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_protected_proof_object();

DROP TRIGGER IF EXISTS protected_proof_payload_guard ON control.protected_proof_payload;
CREATE TRIGGER protected_proof_payload_guard BEFORE INSERT OR UPDATE OR DELETE ON control.protected_proof_payload
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_protected_proof_payload();

DROP TRIGGER IF EXISTS protected_proof_access_guard ON control.protected_proof_access;
CREATE TRIGGER protected_proof_access_guard BEFORE INSERT OR UPDATE OR DELETE ON control.protected_proof_access
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_protected_proof_access();

DROP TRIGGER IF EXISTS protected_proof_object_command ON control.protected_proof_object;
CREATE CONSTRAINT TRIGGER protected_proof_object_command AFTER INSERT OR UPDATE ON control.protected_proof_object
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_protected_proof_command();

DROP TRIGGER IF EXISTS protected_proof_access_command ON control.protected_proof_access;
CREATE CONSTRAINT TRIGGER protected_proof_access_command AFTER INSERT OR UPDATE ON control.protected_proof_access
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_protected_proof_command();
REVOKE ALL ON FUNCTION openpc.protected_proof_binding(control.protected_proof_object),openpc.guard_protected_proof_object(),
 openpc.guard_protected_proof_payload(),openpc.guard_protected_proof_access(),openpc.require_protected_proof_command() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.protected_proof_binding(control.protected_proof_object),openpc.guard_protected_proof_object(),
 openpc.guard_protected_proof_payload(),openpc.guard_protected_proof_access(),openpc.require_protected_proof_command() TO openpc_control_runtime;


ALTER TABLE control.protected_proof_checkpoint FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.protected_proof_checkpoint FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.protected_proof_checkpoint TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.protected_proof_checkpoint TO openpc_control_worker;
GRANT SELECT ON control.protected_proof_object,control.protected_proof_payload TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.protected_proof_payload_digest(payload control.protected_proof_payload)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'keyId',(payload).key_id,'nonceBase64',replace(encode((payload).nonce,'base64'),chr(10),''),
  'ciphertextBase64',replace(encode((payload).ciphertext,'base64'),chr(10),''))),'UTF8')),'hex')
$$;
REVOKE ALL ON FUNCTION openpc.protected_proof_payload_digest(control.protected_proof_payload) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.protected_proof_payload_digest(control.protected_proof_payload) TO openpc_control_runtime,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_protected_proof_checkpoint()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE object control.protected_proof_object; payload control.protected_proof_payload; expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 SELECT * INTO STRICT object FROM control.protected_proof_object
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND object_id=NEW.object_id;
 SELECT * INTO STRICT payload FROM control.protected_proof_payload
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND object_id=NEW.object_id;
 IF NEW.payload_digest IS DISTINCT FROM openpc.protected_proof_payload_digest(payload)
  OR NEW.ciphertext_bytes<>octet_length(payload.ciphertext) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 expected:=jsonb_build_object('object',openpc.protected_proof_binding(object)||jsonb_build_object(
  'dataClass','RAW_SOURCE_BODY','participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,
  'sinkId',NEW.sink_id,'payloadDigest',NEW.payload_digest,'ciphertextBytes',NEW.ciphertext_bytes,
  'retainUntil',to_char(object.retain_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
  'versionId',NEW.payload_digest,'assurance','LOCAL_FSYNC_READBACK');
 IF NEW.receipt-'receiptDigest' IS DISTINCT FROM expected OR NEW.receipt->>'receiptDigest' IS DISTINCT FROM NEW.receipt_digest
  OR NEW.receipt_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 expected:=jsonb_build_object('domain','pc.evidence.protected-checkpoint.v1','participantId',NEW.participant_id::text,
  'privacyDomainId',NEW.privacy_domain_id::text,'objectRef','urn:openpc:resource:'||NEW.object_id::text,
  'objectVersion',object.object_version::text,'sinkId',NEW.sink_id,'payloadDigest',NEW.payload_digest,'receiptDigest',NEW.receipt_digest);
 IF NEW.checkpoint_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.acknowledged_at:=clock_timestamp();
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_protected_proof_checkpoint() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.guard_protected_proof_checkpoint() TO openpc_control_worker;
DROP TRIGGER IF EXISTS protected_proof_checkpoint_guard ON control.protected_proof_checkpoint;
CREATE TRIGGER protected_proof_checkpoint_guard BEFORE INSERT OR UPDATE OR DELETE ON control.protected_proof_checkpoint
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_protected_proof_checkpoint();
GRANT EXECUTE ON FUNCTION openpc.protected_proof_binding(control.protected_proof_object) TO openpc_control_worker;



CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_object_plan(object_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE object control.protected_proof_object; payload control.protected_proof_payload;
 source control.evidence_catalogue; rule control.retention_policy; receipts jsonb; selection jsonb;
 blockers text[]:=ARRAY[]::text[]; expected_payload_digest text; before_digest text; eligible_micros numeric;
 quorum_micros numeric; source_micros numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO object FROM control.protected_proof_object o
  WHERE o.participant_id=current_setting('openpc.participant_id')::uuid
   AND o.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid AND o.object_id=raw_proof_deletion_object_plan.object_id;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO payload FROM control.protected_proof_payload p WHERE p.participant_id=object.participant_id
  AND p.privacy_domain_id=object.privacy_domain_id AND p.object_id=object.object_id;
 IF NOT FOUND THEN
  IF NOT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.evidence_deletion_item i
   USING(participant_id,privacy_domain_id,deletion_job_id) WHERE j.participant_id=object.participant_id
    AND j.privacy_domain_id=object.privacy_domain_id AND j.protected_object_id=object.object_id
    AND i.protected_object_id=object.object_id AND j.target_data_class='RAW_SOURCE_BODY' AND j.state='SUCCEEDED')
   THEN RAISE EXCEPTION 'PC-DATA-6004-RAW-PAYLOAD'; END IF;
  RETURN jsonb_build_object('objectRef','urn:openpc:resource:'||object.object_id::text,
   'localPayload','DELETED','eligible',false,'blockers',jsonb_build_array('ALREADY_DELETED'),'selection',null,'beforeDigest',null);
 END IF;
 expected_payload_digest:=openpc.protected_proof_payload_digest(payload);
 SELECT c.* INTO source FROM control.evidence_catalogue c JOIN control.authentication_occurrence a
  ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
   AND a.occurrence_id::text=c.record_id AND c.receipt_digest='sha256:'||encode(a.receipt_digest,'hex')
   AND a.receipt_digest=sha256(a.receipt) AND a.occurred_at=c.occurred_at AND a.method='WEBAUTHN_ASSERTION'
  WHERE c.participant_id=object.participant_id AND c.privacy_domain_id=object.privacy_domain_id
   AND 'urn:openpc:resource:'||c.evidence_id::text=object.source->>'evidenceId'
   AND c.record_id=object.source->>'occurrenceId' AND c.receipt_digest=object.source->>'sourceReceiptDigest'
   AND c.evidence_class='AUTHENTICATION' AND c.source_format='OPENPC_AUTHENTICATION_OCCURRENCE_V1'
   AND object.source->>'materialType'='IDENTITY_SIGNED_AUTHORIZATION_ASSERTION'
   AND object.source->>'finality'='NOT_APPLICABLE' AND object.source->>'authorityEffect'='NONE';
 IF NOT FOUND THEN blockers:=array_append(blockers,'UNSUPPORTED_SOURCE'); END IF;
 -- These immutable local authentication sources have no chain finality/reorg
 -- dimension. Missing source lineage is a blocker, never a no-gap assertion.
 IF source.evidence_id IS NULL OR NOT EXISTS(SELECT 1 FROM control.protected_proof_checkpoint c
  WHERE c.participant_id=object.participant_id AND c.privacy_domain_id=object.privacy_domain_id
   AND c.object_id=object.object_id AND c.payload_digest=expected_payload_digest
   AND c.ciphertext_bytes=octet_length(payload.ciphertext)
   AND c.receipt->'object'->>'objectDigest'=object.object_digest
   AND c.receipt->'object'->>'objectVersion'=object.object_version::text
   AND c.receipt->'object'->'source'=object.source
   AND c.receipt->>'versionId'=expected_payload_digest AND c.receipt->>'receiptDigest'=c.receipt_digest) THEN
  blockers:=array_append(blockers,'INCOMPLETE_CHECKPOINT');
 END IF;
 IF EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=object.participant_id
  AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=object.privacy_domain_id) AND h.state='ACTIVE'
  AND (CASE h.selector_type
   WHEN 'PARTICIPANT' THEN true WHEN 'PRIVACY_DOMAIN' THEN true
   WHEN 'DIGEST' THEN (h.selector->>'recordDigest' IN (object.object_digest,expected_payload_digest,source.receipt_digest))
   WHEN 'SEQUENCE_RANGE' THEN h.selector->>'streamId'=source.stream_id
    AND source.sequence>=(h.selector->>'fromSequence')::numeric
    AND (h.selector->'throughSequence'='null'::jsonb OR source.sequence<=(h.selector->>'throughSequence')::numeric)
   ELSE openpc.evidence_hold_source_match(h.selector,openpc.evidence_hold_record_metadata(source))
  END) IS DISTINCT FROM false) THEN blockers:=array_append(blockers,'ACTIVE_HOLD'); END IF;
 -- References to immutable object metadata remain valid; a live disclosure
 -- depends on the payload and must finish/expire. Unknown future physical FKs
 -- require their owning clearance protocol before this adapter can resume.
 IF EXISTS(SELECT 1 FROM control.protected_proof_access a WHERE a.participant_id=object.participant_id
  AND a.privacy_domain_id=object.privacy_domain_id AND a.object_id=object.object_id
  AND a.consumed_at IS NULL AND a.expires_at>clock_timestamp())
  OR EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f' AND confrelid='control.protected_proof_payload'::regclass)
 THEN blockers:=array_append(blockers,'REFERENCES'); END IF;
 SELECT * INTO rule FROM control.retention_policy p WHERE p.participant_id=object.participant_id
  AND p.privacy_domain_id=object.privacy_domain_id AND p.data_class='RAW_SOURCE_BODY' AND p.active_until IS NULL;
 IF NOT FOUND THEN blockers:=array_append(blockers,'NO_ACTIVE_POLICY');
 ELSE
  IF rule.deletion_mode<>'ROW_DELETE' THEN blockers:=array_append(blockers,'UNSUPPORTED_MODE'); END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('sinkId',chosen.sink_id,'checkpointDigest',chosen.checkpoint_digest,
   'receiptDigest',chosen.receipt_digest,'acknowledgedAtMicros',chosen.ack_micros::text)
   ORDER BY chosen.ack_micros,chosen.sink_id),'[]'::jsonb),max(chosen.ack_micros)
   INTO receipts,quorum_micros FROM (
    SELECT c.sink_id,c.checkpoint_digest,c.receipt_digest,floor(extract(epoch from c.acknowledged_at)*1000000) ack_micros
    FROM control.protected_proof_checkpoint c WHERE c.participant_id=object.participant_id
     AND c.privacy_domain_id=object.privacy_domain_id AND c.object_id=object.object_id
     AND c.payload_digest=expected_payload_digest AND c.ciphertext_bytes=octet_length(payload.ciphertext)
     AND c.receipt->'object'->>'objectDigest'=object.object_digest AND c.receipt->'object'->'source'=object.source
     AND c.receipt->>'versionId'=expected_payload_digest AND c.receipt->>'receiptDigest'=c.receipt_digest
    ORDER BY c.acknowledged_at,c.sink_id LIMIT rule.sink_quorum) chosen;
  IF jsonb_array_length(receipts)<>rule.sink_quorum THEN blockers:=array_append(blockers,'SINK_QUORUM'); END IF;
  source_micros:=floor(extract(epoch from source.occurred_at)*1000000);
  eligible_micros:=greatest(source_micros+rule.retention_period_ms*1000,
   coalesce(quorum_micros,floor(extract(epoch from object.created_at)*1000000))+rule.local_grace_ms*1000,
   floor(extract(epoch from object.retain_until)*1000000));
  IF eligible_micros>floor(extract(epoch from clock_timestamp())*1000000) THEN blockers:=array_append(blockers,'RETENTION_NOT_ELAPSED'); END IF;
  selection:=jsonb_build_object('version','OPENPC_RAW_PROOF_DELETION_BATCH_V1',
   'participantId','urn:openpc:participant:'||object.participant_id::text,'privacyDomainId',object.privacy_domain_id::text,
   'retentionPolicyId','urn:openpc:resource:'||rule.retention_policy_id::text,'policyDigest',rule.policy_digest,
   'targetDatabase','openpc_control','dataClass','RAW_SOURCE_BODY','deletionMode','ROW_DELETE',
   'objectRef','urn:openpc:resource:'||object.object_id::text,'objectVersion',object.object_version::text,
   'objectDigest',object.object_digest,'payloadDigest',expected_payload_digest,'ciphertextBytes',octet_length(payload.ciphertext),
   'source',object.source,'eligibleAfterMicros',eligible_micros::text,'sinkReceipts',receipts);
  before_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
   'domain','pc.evidence.raw-proof-before.v1','participantId',object.participant_id::text,'privacyDomainId',object.privacy_domain_id::text,
   'objectRef',selection->'objectRef','objectVersion',selection->'objectVersion','objectDigest',object.object_digest,
   'payloadDigest',expected_payload_digest,'ciphertextBytes',octet_length(payload.ciphertext))),'UTF8')),'hex');
 END IF;
 RETURN jsonb_build_object('objectRef','urn:openpc:resource:'||object.object_id::text,'localPayload','RETAINED',
  'eligible',cardinality(blockers)=0,'blockers',to_jsonb(blockers),'selection',selection,'beforeDigest',before_digest);
END $$;
REVOKE ALL ON FUNCTION openpc.raw_proof_deletion_object_plan(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.raw_proof_deletion_object_plan(uuid) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_target(plan jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('objectRef',plan->'selection'->'objectRef','objectVersion',plan->'selection'->'objectVersion',
  'objectDigest',plan->'selection'->'objectDigest','payloadDigest',plan->'selection'->'payloadDigest',
  'ciphertextBytes',plan->'selection'->'ciphertextBytes','beforeDigest',plan->'beforeDigest')
$$;

CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_batch_plan(anchor uuid,previous uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE plan jsonb; selected jsonb; targets jsonb:='[]'::jsonb; target jsonb; candidate record;
 prior control.deletion_job; receipt_digest text; next_job uuid; position integer:=0;
 cursor jsonb:='null'::jsonb; prior_policy jsonb; blockers jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF (anchor IS NULL)=(previous IS NULL) THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF previous IS NOT NULL THEN
  SELECT * INTO prior FROM control.deletion_job j WHERE j.participant_id=current_setting('openpc.participant_id')::uuid
   AND j.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid AND j.deletion_job_id=previous;
  IF NOT FOUND OR prior.state<>'SUCCEEDED' OR prior.selection->>'version'<>'OPENPC_RAW_PROOF_DELETION_BATCH_V1' THEN RETURN NULL; END IF;
  SELECT 'sha256:'||encode(a.receipt_digest,'hex') INTO receipt_digest FROM control.audit_occurrence a
   WHERE a.participant_id=prior.participant_id AND a.privacy_domain_id=prior.privacy_domain_id
    AND a.aggregate_type='evidence-deletion' AND a.aggregate_id=prior.deletion_job_id AND a.operation_id=prior.operation_id
    AND a.profile_id='pc.control.evidence-deletion.raw-proof' AND a.catalog_operation_id='CFG-OP-DELETE-RAW-PROOF-BATCH';
  IF receipt_digest IS NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  targets:=prior.selection->'targets';position:=(prior.selection->>'batchIndex')::integer+1;
  cursor:=jsonb_build_object('deletionJobId','urn:openpc:resource:'||previous::text,'receiptDigest',receipt_digest);
  SELECT deletion_job_id INTO next_job FROM control.deletion_job j WHERE j.participant_id=prior.participant_id
   AND j.privacy_domain_id=prior.privacy_domain_id AND j.previous_deletion_job_id=previous AND j.state='SUCCEEDED';
  IF next_job IS NOT NULL OR position=jsonb_array_length(targets) THEN
   RETURN jsonb_build_object('objectRef',prior.selection->'objectRef','localPayload','DELETED','eligible',false,
    'blockers','[]'::jsonb,'selection',null,'beforeDigest',null,
    'continuationState',CASE WHEN next_job IS NULL THEN 'COMPLETE' ELSE 'ADVANCED' END,
    'nextDeletionJobId',CASE WHEN next_job IS NULL THEN NULL ELSE 'urn:openpc:resource:'||next_job::text END);
  END IF;
  target:=targets->position;
  prior_policy:=jsonb_build_array(prior.selection->'retentionPolicyId',prior.selection->'policyDigest');
  plan:=openpc.raw_proof_deletion_object_plan(right(target->>'objectRef',36)::uuid);
 ELSE
  plan:=openpc.raw_proof_deletion_object_plan(anchor);
  IF plan IS NULL THEN RETURN NULL; END IF;
  IF plan->'selection'='null'::jsonb THEN RETURN plan||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null); END IF;
  FOR candidate IN SELECT o.object_id FROM control.protected_proof_object o
   JOIN control.protected_proof_payload p USING(participant_id,privacy_domain_id,object_id)
   WHERE o.participant_id=current_setting('openpc.participant_id')::uuid AND o.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
    AND o.object_id>=anchor ORDER BY o.object_id LIMIT 16 LOOP
   selected:=openpc.raw_proof_deletion_object_plan(candidate.object_id);
   IF selected->'selection'='null'::jsonb THEN RETURN selected||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null); END IF;
   targets:=targets||jsonb_build_array(openpc.raw_proof_deletion_target(selected));
  END LOOP;
  target:=targets->0;
 END IF;
 IF plan IS NULL OR target IS NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 blockers:=plan->'blockers';
 IF plan->'selection'='null'::jsonb THEN RETURN plan||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null); END IF;
 IF openpc.raw_proof_deletion_target(plan) IS DISTINCT FROM target OR
  (prior_policy IS NOT NULL AND prior_policy IS DISTINCT FROM jsonb_build_array(plan->'selection'->'retentionPolicyId',plan->'selection'->'policyDigest'))
 THEN blockers:=blockers||jsonb_build_array('STALE_SELECTION'); END IF;
 selected:=(plan->'selection')||jsonb_build_object('targets',targets,'batchIndex',position,'priorCursor',cursor);
 RETURN plan||jsonb_build_object('eligible',jsonb_array_length(blockers)=0,'blockers',blockers,
  'selection',CASE WHEN blockers ? 'STALE_SELECTION' THEN NULL ELSE selected END,
  'continuationState',CASE WHEN jsonb_array_length(blockers)=0 THEN 'READY' ELSE 'BLOCKED' END,'nextDeletionJobId',null);
END $$;
REVOKE ALL ON FUNCTION openpc.raw_proof_deletion_target(jsonb),openpc.raw_proof_deletion_batch_plan(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.raw_proof_deletion_target(jsonb),openpc.raw_proof_deletion_batch_plan(uuid,uuid) TO openpc_control_runtime;

GRANT DELETE ON control.protected_proof_payload TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_selector_digest(selection jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','pc.evidence.raw-proof-selector.v1','participantId',selection->'participantId',
  'privacyDomainId',selection->'privacyDomainId','objectRef',selection->'objectRef','objectVersion',selection->'objectVersion')),'UTF8')),'hex')
$$;

CREATE OR REPLACE FUNCTION openpc.guard_raw_proof_deletion_job(operation text,old_job control.deletion_job,new_job control.deletion_job)
RETURNS control.deletion_job LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE plan jsonb; item control.evidence_deletion_item; current_bytes integer;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF operation NOT IN ('INSERT','UPDATE') OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1'
  OR new_job.participant_id<>current_setting('openpc.participant_id')::uuid
  OR new_job.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR new_job.operation_id<>current_setting('openpc.operation_id')::uuid
  OR new_job.target_data_class<>'RAW_SOURCE_BODY' OR new_job.target_database<>'openpc_control'
  OR new_job.selection->>'version'<>'OPENPC_RAW_PROOF_DELETION_BATCH_V1'
  OR new_job.stream_id IS NOT NULL OR new_job.segment_id IS NOT NULL
  OR new_job.protected_object_id IS DISTINCT FROM right(new_job.selection->>'objectRef',36)::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||new_job.participant_id::text,0));
 SELECT coalesce(sum(octet_length(ciphertext)),0)::integer INTO current_bytes FROM control.protected_proof_payload
  WHERE participant_id=new_job.participant_id AND privacy_domain_id=new_job.privacy_domain_id;
 IF operation='INSERT' THEN
  new_job.previous_deletion_job_id:=right(new_job.selection->'priorCursor'->>'deletionJobId',36)::uuid;
  IF new_job.previous_deletion_job_id IS NOT NULL THEN
   PERFORM 1 FROM control.deletion_job WHERE participant_id=new_job.participant_id AND privacy_domain_id=new_job.privacy_domain_id
    AND deletion_job_id=new_job.previous_deletion_job_id FOR UPDATE;
  END IF;
  plan:=openpc.evidence_deletion_selection_plan(new_job.selection);
  IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM new_job.selection
   OR plan->>'beforeDigest' IS DISTINCT FROM new_job.before_digest OR new_job.state<>'EXECUTING' OR new_job.revision<>0
   OR new_job.retention_policy_id IS DISTINCT FROM right(new_job.selection->>'retentionPolicyId',36)::uuid
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  new_job.target_selector_digest:=openpc.raw_proof_deletion_selector_digest(new_job.selection);
  new_job.eligibility_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(new_job.selection),'UTF8')),'hex');
  new_job.before_used_bytes:=current_bytes;new_job.after_used_bytes:=NULL;
  new_job.started_at:=clock_timestamp();new_job.created_at:=new_job.started_at;
 ELSE
  IF old_job.target_data_class<>'RAW_SOURCE_BODY' OR old_job.state<>'EXECUTING' OR new_job.state<>'SUCCEEDED'
   OR old_job.revision<>0 OR new_job.revision<>1
   OR (to_jsonb(new_job)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at']) IS DISTINCT FROM
      (to_jsonb(old_job)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at'])
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO STRICT item FROM control.evidence_deletion_item WHERE participant_id=new_job.participant_id
   AND privacy_domain_id=new_job.privacy_domain_id AND deletion_job_id=new_job.deletion_job_id;
  IF item.protected_object_id IS DISTINCT FROM new_job.protected_object_id OR item.object_digest<>new_job.selection->>'payloadDigest'
   OR current_bytes<>new_job.before_used_bytes-item.ciphertext_bytes
   OR EXISTS(SELECT 1 FROM control.protected_proof_payload WHERE participant_id=new_job.participant_id
    AND privacy_domain_id=new_job.privacy_domain_id AND object_id=new_job.protected_object_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  new_job.deleted_count:=1;new_job.deleted_bytes:=item.ciphertext_bytes;new_job.after_used_bytes:=current_bytes;
  new_job.after_digest:=openpc.evidence_deletion_after_digest(new_job.target_selector_digest);
  new_job.completed_at:=clock_timestamp();
 END IF;
 new_job.updated_at:=clock_timestamp();RETURN new_job;
END $$;

CREATE OR REPLACE FUNCTION openpc.record_raw_proof_payload_deletion(payload control.protected_proof_payload)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE job control.deletion_job; plan jsonb;
BEGIN
 IF pg_trigger_depth()<>1 OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1'
  OR payload.participant_id<>current_setting('openpc.participant_id')::uuid
  OR payload.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||payload.participant_id::text,0));
 SELECT * INTO STRICT job FROM control.deletion_job WHERE participant_id=payload.participant_id
  AND privacy_domain_id=payload.privacy_domain_id AND operation_id=current_setting('openpc.operation_id')::uuid
  AND target_data_class='RAW_SOURCE_BODY' AND state='EXECUTING' AND revision=0 AND protected_object_id=payload.object_id FOR UPDATE;
 plan:=openpc.evidence_deletion_selection_plan(job.selection);
 IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM job.selection
  OR plan->>'beforeDigest' IS DISTINCT FROM job.before_digest
  OR octet_length(payload.ciphertext)<>(job.selection->>'ciphertextBytes')::integer
  OR openpc.protected_proof_payload_digest(payload)<>job.selection->>'payloadDigest' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 INSERT INTO control.evidence_deletion_item(participant_id,privacy_domain_id,deletion_job_id,protected_object_id,object_digest,ciphertext_bytes)
 VALUES(payload.participant_id,payload.privacy_domain_id,job.deletion_job_id,payload.object_id,job.selection->>'payloadDigest',octet_length(payload.ciphertext));
END $$;

CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_item_matches(item control.evidence_deletion_item)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.protected_proof_payload p
  ON p.participant_id=j.participant_id AND p.privacy_domain_id=j.privacy_domain_id AND p.object_id=j.protected_object_id
  WHERE j.participant_id=(item).participant_id AND j.privacy_domain_id=(item).privacy_domain_id AND j.deletion_job_id=(item).deletion_job_id
   AND j.operation_id=current_setting('openpc.operation_id')::uuid AND j.state='EXECUTING' AND j.target_data_class='RAW_SOURCE_BODY'
   AND j.protected_object_id=(item).protected_object_id AND (item).segment_id IS NULL
   AND j.selection->>'payloadDigest'=(item).object_digest AND openpc.protected_proof_payload_digest(p)=(item).object_digest
   AND octet_length(p.ciphertext)=(item).ciphertext_bytes)
$$;

CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_effect_matches(job control.deletion_job,item control.evidence_deletion_item)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT (job).target_data_class='RAW_SOURCE_BODY' AND (job).protected_object_id=(item).protected_object_id
  AND (job).selection->>'payloadDigest'=(item).object_digest AND (job).segment_id IS NULL AND (item).segment_id IS NULL
  AND NOT EXISTS(SELECT 1 FROM control.protected_proof_payload p WHERE p.participant_id=(job).participant_id
   AND p.privacy_domain_id=(job).privacy_domain_id AND p.object_id=(job).protected_object_id)
  AND (SELECT coalesce(sum(octet_length(p.ciphertext)),0) FROM control.protected_proof_payload p
   WHERE p.participant_id=(job).participant_id AND p.privacy_domain_id=(job).privacy_domain_id)=(job).after_used_bytes
$$;
REVOKE ALL ON FUNCTION openpc.raw_proof_deletion_selector_digest(jsonb),
 openpc.guard_raw_proof_deletion_job(text,control.deletion_job,control.deletion_job),
 openpc.record_raw_proof_payload_deletion(control.protected_proof_payload),
 openpc.raw_proof_deletion_item_matches(control.evidence_deletion_item),
 openpc.raw_proof_deletion_effect_matches(control.deletion_job,control.evidence_deletion_item) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.raw_proof_deletion_selector_digest(jsonb),
 openpc.guard_raw_proof_deletion_job(text,control.deletion_job,control.deletion_job),
 openpc.record_raw_proof_payload_deletion(control.protected_proof_payload),
 openpc.raw_proof_deletion_item_matches(control.evidence_deletion_item),
 openpc.raw_proof_deletion_effect_matches(control.deletion_job,control.evidence_deletion_item) TO openpc_control_runtime;


ALTER TABLE control.evidence_rpc_provenance FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_rpc_provenance FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_rpc_provenance TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.evidence_rpc_provenance TO openpc_control_worker;
CREATE OR REPLACE FUNCTION openpc.guard_rpc_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb:=NEW.projection; a jsonb:=p->'activation'; t jsonb:=p->'transition';
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF p-ARRAY['integrity','activationIntegrity','authority','currentAuthority','providerEffect','chainFinality',
  'decisionId','targetRuntimeId','spoolId','sourceSequence','sourceDigest','capsuleDigest','reservedAtNs','occurredAtNs','transition','activation']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(p))<>16
  OR a-ARRAY['operationId','attemptId','configurationWorkId','generationId','generationDigest','receiptDigest','signerId','verificationKeyDigest']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(a))<>8
  OR t-ARRAY['phase','traceId','requestDigest','decisionDigest','responseDigest','authorityBindingDigest','sourceScopeDigest','operationId',
   'pcCode','decisionEffect','boundary','sourceSegmentId','sourceRecordDigest','admittedAtNs']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(t))<>14
  OR p->>'integrity' IS DISTINCT FROM 'AEAD_CHAIN_VERIFIED_AT_CUSTODY'
  OR p->>'activationIntegrity' IS DISTINCT FROM 'ACTIVATION_COSE_VERIFIED_AT_CUSTODY'
  OR p->>'authority' IS DISTINCT FROM 'NONE' OR p->>'currentAuthority' IS DISTINCT FROM 'NOT_ESTABLISHED'
  OR p->>'providerEffect' IS DISTINCT FROM 'NOT_ESTABLISHED' OR p->>'chainFinality' IS DISTINCT FROM 'NOT_ESTABLISHED'
  OR NEW.projection_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex')
  OR NEW.record_id<>'rpc:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_array(p->>'targetRuntimeId',p->>'spoolId')),'UTF8')),'hex')||':'||(p->>'sourceSequence')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.evidence_catalogue c WHERE c.participant_id=NEW.participant_id
  AND c.privacy_domain_id=NEW.privacy_domain_id AND c.stream_id=NEW.stream_id AND c.record_id=NEW.record_id
  AND c.evidence_class='EFFECT' AND c.source_format='OPENPC_RPC_DECISION_TRANSITION_V1'
  AND c.receipt_digest=p->>'sourceDigest' AND c.sequence::text=p->>'sourceSequence'
  AND extract(epoch FROM c.occurred_at)*1000000=floor((p->>'occurredAtNs')::numeric/1000)) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.runtime_activation_observation o JOIN control.configuration_work w
  ON w.participant_id=o.participant_id AND w.privacy_domain_id=o.privacy_domain_id AND w.configuration_work_id=o.configuration_work_id
   AND w.runtime_target_id=o.runtime_target_id AND w.runtime_configuration_generation_id=o.runtime_configuration_generation_id
   AND w.operation_id=o.operation_id AND w.execution_attempt_id=o.execution_attempt_id AND w.generation_digest=o.generation_digest AND w.state='COMPLETED'
  WHERE o.participant_id=NEW.participant_id AND o.privacy_domain_id=NEW.privacy_domain_id
   AND o.runtime_target_id::text=p->>'targetRuntimeId' AND o.capsule_digest=p->>'capsuleDigest'
   AND o.operation_id::text=a->>'operationId' AND o.execution_attempt_id::text=a->>'attemptId'
   AND o.configuration_work_id::text=a->>'configurationWorkId' AND o.runtime_configuration_generation_id::text=a->>'generationId'
   AND o.generation_digest=a->>'generationDigest'
   AND 'sha256:'||encode(sha256(decode(o.activation_receipt->>'activationReceiptCoseHex','hex')),'hex')=a->>'receiptDigest') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_rpc_provenance_guard ON control.evidence_rpc_provenance;
CREATE TRIGGER evidence_rpc_provenance_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_rpc_provenance
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_rpc_provenance();
