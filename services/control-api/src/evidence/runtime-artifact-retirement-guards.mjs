/** Feature metadata only. Canonical owns action/profile admission, grants,
 * generated registration, source DELETE admission and both native assertions.
 * There is deliberately no permissive stub for an unavailable physical owner. */
export const runtimeArtifactRetirementProfile = Object.freeze({
  profileId: 'pc.control.evidence-deletion.runtime-artifact',
  profileVersion: 1,
  profileDigest: 'sha256:d1f1c8ccfbd049063197e8511e1b0604888963b29cc40fec7ca8e72f539d85c5',
  actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1',
  catalogOperationId: 'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH',
});
// These assertions consume original database composite rows, never a supplied
// eligible/retired flag or capability. Canonical must implement and grant them.
// Eligibility rechecks exact selection, live authority, custody, holds and every
// reference under the shared producer fence. Effect checks the original physical
// deletion and immutable job/result chain; historical readback never reruns
// today's eligibility or turns retained history into serving authority.
export const runtimeArtifactRetirementRequiredOwners = Object.freeze({
  eligibility:
    'openpc.assert_runtime_artifact_retirement_eligible(control.deletion_job,control.runtime_configuration_input)',
  effect:
    'openpc.assert_runtime_artifact_retirement_effect(control.deletion_job,control.runtime_artifact_retirement)',
});
const identity = (r) => `jsonb_build_object('participantId',(${r}).participant_id::text,
 'privacyDomainId',(${r}).privacy_domain_id::text,'runtimeConfigurationInputId',(${r}).runtime_configuration_input_id::text,
 'moduleInstallationId',(${r}).module_installation_id::text,'moduleConfigurationGenerationId',(${r}).module_configuration_generation_id::text,
 'configurationDigest',(${r}).configuration_digest,'configurationBytes',(${r}).configuration_bytes,
 'resourceBindingsDigest',(${r}).resource_bindings_digest,
 'createdAt',to_char((${r}).source_created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))`;

export const runtimeArtifactRetirementGuardsSql = `
ALTER TABLE control.runtime_artifact_retirement FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.runtime_artifact_retirement FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
-- Canonical adds the minimum SELECT/INSERT/function grants with the native
-- owner. This declaration never grants DELETE, UPDATE, TRUNCATE or source use.
CREATE OR REPLACE FUNCTION openpc.runtime_artifact_retirement_source(r control.runtime_artifact_retirement)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT ${identity('r')}
$$;
CREATE OR REPLACE FUNCTION openpc.runtime_artifact_retirement_digest(r control.runtime_artifact_retirement)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','pc.evidence.runtime-artifact-retirement.v1','deletionJobId',(r).deletion_job_id::text,'source',${identity('r')})),'UTF8')),'hex')
$$;
CREATE OR REPLACE FUNCTION openpc.runtime_artifact_retirement_after_digest(r control.runtime_artifact_retirement)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','pc.evidence.runtime-artifact-after.v1','retirementDigest',openpc.runtime_artifact_retirement_digest(r))),'UTF8')),'hex')
$$;
CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_retirement_context()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE k text:='evidence-lifecycle:'||openpc.current_participant_id()::text;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
  OR current_setting('session_replication_role')<>'origin'
  OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
  OR NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.mode='ExclusiveLock'
   AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=((hashtextextended(k,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(k,0)&4294967295)::oid AND l.objsubid=1)
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-CONTEXT'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_retirement_owner(owner_kind text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE owner_signature text;
BEGIN
 owner_signature:=case owner_kind when 'eligibility' then '${runtimeArtifactRetirementRequiredOwners.eligibility}'
  when 'effect' then '${runtimeArtifactRetirementRequiredOwners.effect}' else null end;
 IF owner_signature IS NULL OR NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
   JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
   WHERE p.oid=to_regprocedure(owner_signature) AND r.rolname='openpc_control_owner' AND n.nspname='openpc'
    AND l.lanname='plpgsql' AND p.prokind='f' AND p.provolatile='v' AND NOT p.prosecdef AND NOT p.proisstrict
    AND NOT p.proretset AND NOT p.proleakproof AND p.proparallel='u' AND p.prosupport=0
    AND p.prorettype='pg_catalog.void'::regtype AND p.pronargs=2 AND p.pronargdefaults=0 AND p.provariadic=0
    AND p.proargmodes IS NULL AND p.proconfig=ARRAY['search_path=pg_catalog']::text[])
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-OWNER-UNAVAILABLE'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_retirement()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE source record; job control.deletion_job;
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<>2 THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_runtime_artifact_retirement_context();
 IF openpc.current_action_intent_id()<>'${runtimeArtifactRetirementProfile.actionIntentId}'
  OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id() THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT module_installation_id,module_configuration_generation_id,configuration_digest,created_at,resource_bindings,selected,
  openpc.runtime_artifact_input_information(runtime_configuration_input_id) info INTO STRICT source
  FROM control.runtime_configuration_input WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND runtime_configuration_input_id=NEW.runtime_configuration_input_id;
 SELECT * INTO STRICT job FROM control.deletion_job WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
  AND deletion_job_id=NEW.deletion_job_id AND operation_id=openpc.current_operation_id()
  AND state='EXECUTING' AND revision=0 AND target_database='openpc_control' AND target_data_class='RUNTIME_ARTIFACT'
  AND external_attempt_state='NOT_STARTED';
 IF source.selected OR source.info->'bytesMatch' IS DISTINCT FROM 'true'::jsonb
  OR NEW.module_installation_id IS DISTINCT FROM source.module_installation_id
  OR NEW.module_configuration_generation_id IS DISTINCT FROM source.module_configuration_generation_id
  OR NEW.configuration_digest IS DISTINCT FROM 'sha256:'||encode(source.configuration_digest,'hex')
  OR NEW.configuration_bytes IS DISTINCT FROM (source.info->>'byteLength')::integer
  OR NEW.source_created_at IS DISTINCT FROM source.created_at
  OR NEW.resource_bindings_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(source.resource_bindings),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-SOURCE'; END IF;
 NEW.retirement_digest:=openpc.runtime_artifact_retirement_digest(NEW);
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.capture_runtime_artifact_retirement()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE job control.deletion_job;
BEGIN
 IF TG_TABLE_SCHEMA<>'control' OR TG_TABLE_NAME<>'runtime_configuration_input' OR TG_OP<>'DELETE'
  OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR pg_trigger_depth()<>1 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM openpc.assert_runtime_artifact_retirement_context();
 IF OLD.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR OLD.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR openpc.current_action_intent_id()<>'${runtimeArtifactRetirementProfile.actionIntentId}' THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT job FROM control.deletion_job WHERE participant_id=OLD.participant_id AND privacy_domain_id=OLD.privacy_domain_id
  AND operation_id=openpc.current_operation_id() AND target_database='openpc_control' AND target_data_class='RUNTIME_ARTIFACT'
  AND state='EXECUTING' AND revision=0 AND external_attempt_state='NOT_STARTED';
 IF OLD.selected OR OLD.configuration_digest IS DISTINCT FROM sha256(OLD.configuration_cbor)
  OR octet_length(OLD.configuration_cbor) NOT BETWEEN 1 AND 4194304
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-SOURCE'; END IF;
 PERFORM openpc.assert_runtime_artifact_retirement_owner('eligibility');
 PERFORM openpc.assert_runtime_artifact_retirement_eligible(job,OLD);
 INSERT INTO control.runtime_artifact_retirement(deletion_job_id,participant_id,privacy_domain_id,runtime_configuration_input_id,
  module_installation_id,module_configuration_generation_id,configuration_digest,configuration_bytes,resource_bindings_digest,source_created_at,retirement_digest)
 VALUES(job.deletion_job_id,OLD.participant_id,OLD.privacy_domain_id,OLD.runtime_configuration_input_id,OLD.module_installation_id,
  OLD.module_configuration_generation_id,'sha256:'||encode(OLD.configuration_digest,'hex'),octet_length(OLD.configuration_cbor),
  'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(OLD.resource_bindings),'UTF8')),'hex'),OLD.created_at,'');
 RETURN OLD;
END $$;
-- Do not attach capture to the input here: canonical owns native DELETE
-- admission, current-view/direct-SQL denial, eligibility and source fences.
CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_retirement_statement()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_runtime_artifact_retirement_context();
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS runtime_artifact_retirement_statement_guard ON control.runtime_artifact_retirement;
CREATE TRIGGER runtime_artifact_retirement_statement_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
 ON control.runtime_artifact_retirement FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_runtime_artifact_retirement_statement();
DROP TRIGGER IF EXISTS runtime_artifact_retirement_guard ON control.runtime_artifact_retirement;
CREATE TRIGGER runtime_artifact_retirement_guard BEFORE INSERT OR UPDATE OR DELETE ON control.runtime_artifact_retirement
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_artifact_retirement();

CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_retirement_committed(r control.runtime_artifact_retirement)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE job control.deletion_job; receipt control.audit_occurrence;
BEGIN
 PERFORM openpc.assert_runtime_artifact_retirement_context();
 IF (r).participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR (r).privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR (r).retirement_digest IS DISTINCT FROM openpc.runtime_artifact_retirement_digest(r)
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-SOURCE'; END IF;
 SELECT * INTO STRICT job FROM control.deletion_job WHERE participant_id=(r).participant_id AND privacy_domain_id=(r).privacy_domain_id
  AND deletion_job_id=(r).deletion_job_id AND state='SUCCEEDED' AND revision=1 AND target_database='openpc_control'
  AND target_data_class='RUNTIME_ARTIFACT' AND external_attempt_state='NOT_STARTED' AND deleted_count=1
  AND deleted_bytes=(r).configuration_bytes AND before_used_bytes=(r).configuration_bytes AND after_used_bytes=0
  AND retained_alias_count=0 AND after_digest=openpc.runtime_artifact_retirement_after_digest(r);
 IF EXISTS(SELECT 1 FROM control.runtime_configuration_input WHERE participant_id=(r).participant_id AND privacy_domain_id=(r).privacy_domain_id
  AND runtime_configuration_input_id=(r).runtime_configuration_input_id)
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-EFFECT'; END IF;
 PERFORM openpc.assert_runtime_artifact_retirement_owner('effect');
 PERFORM openpc.assert_runtime_artifact_retirement_effect(job,r);
 SELECT * INTO STRICT receipt FROM control.audit_occurrence a WHERE a.participant_id=job.participant_id AND a.privacy_domain_id=job.privacy_domain_id
  AND a.operation_id=job.operation_id AND a.aggregate_id=job.deletion_job_id AND a.aggregate_type='evidence-deletion'
  AND a.profile_id='${runtimeArtifactRetirementProfile.profileId}' AND a.profile_version=1
  AND a.profile_digest=decode('${runtimeArtifactRetirementProfile.profileDigest.slice(7)}','hex')
  AND a.action_intent_id='${runtimeArtifactRetirementProfile.actionIntentId}' AND a.catalog_operation_id='${runtimeArtifactRetirementProfile.catalogOperationId}'
  AND a.before_existence=0 AND a.before_revision=0 AND a.after_existence=1 AND a.after_revision=1
  AND a.receipt_digest=sha256(a.receipt_cbor);
 PERFORM openpc.assert_evidence_deletion_receipt(receipt);
 IF NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=receipt.participant_id AND i.privacy_domain_id=receipt.privacy_domain_id
  AND i.idempotency_record_id=receipt.idempotency_record_id AND i.operation_id=receipt.operation_id AND i.terminal_state='COMMITTED'
  AND i.input_digest=receipt.candidate_digest AND i.action_intent_id=receipt.action_intent_id AND i.catalog_operation_id=receipt.catalog_operation_id)
  OR (SELECT count(*) FROM control.outbox_event e WHERE e.participant_id=receipt.participant_id AND e.privacy_domain_id=receipt.privacy_domain_id
   AND e.receipt_id=receipt.receipt_id AND e.aggregate_id=receipt.aggregate_id AND e.aggregate_type=receipt.aggregate_type
   AND e.event_type='io.openpc.control.command.committed.v1' AND e.proof_kind='BUSINESS_RECEIPT_REFERENCE'
   AND e.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1' AND e.payload_digest=sha256(e.payload_cbor))<>1
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-RECEIPT'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.require_runtime_artifact_retirement_commit()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_runtime_artifact_retirement_committed(NEW);
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS runtime_artifact_retirement_commit_required ON control.runtime_artifact_retirement;
CREATE CONSTRAINT TRIGGER runtime_artifact_retirement_commit_required AFTER INSERT ON control.runtime_artifact_retirement
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_runtime_artifact_retirement_commit();

-- Denial observation only. False is not eligibility or serving permission.
-- Deliberately independent of input/module identities: a new generation cannot
-- bypass retired bytes. Canonical calls this under the same producer fence.
CREATE OR REPLACE FUNCTION openpc.runtime_artifact_digest_retired(p_digest text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_runtime_artifact_retirement_context();
 IF (p_digest ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN EXISTS(SELECT 1 FROM control.runtime_artifact_retirement r WHERE r.participant_id=openpc.current_participant_id()
  AND r.privacy_domain_id=openpc.current_privacy_domain_id() AND r.configuration_digest=p_digest);
END $$;
REVOKE ALL ON FUNCTION openpc.runtime_artifact_retirement_source(control.runtime_artifact_retirement),
 openpc.runtime_artifact_retirement_digest(control.runtime_artifact_retirement),
 openpc.runtime_artifact_retirement_after_digest(control.runtime_artifact_retirement),openpc.assert_runtime_artifact_retirement_context(),
 openpc.assert_runtime_artifact_retirement_owner(text),openpc.guard_runtime_artifact_retirement(),openpc.capture_runtime_artifact_retirement(),
 openpc.guard_runtime_artifact_retirement_statement(),openpc.assert_runtime_artifact_retirement_committed(control.runtime_artifact_retirement),
 openpc.require_runtime_artifact_retirement_commit(),openpc.runtime_artifact_digest_retired(text) FROM PUBLIC;
`;
