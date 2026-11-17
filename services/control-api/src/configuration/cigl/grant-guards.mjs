export const ciglGrantGuardsSql = `
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
CREATE OR REPLACE FUNCTION openpc.lock_cigl_grant_sources(p_fail_fast boolean)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE scope_key bigint;
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF p_fail_fast IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PC-DATA-6004'; END IF;
 IF p_fail_fast THEN PERFORM openpc.assert_request_context(true); END IF;
 scope_key:=hashtextextended('openpc:cigl-grants:'||
  current_setting('openpc.participant_id')||':'||current_setting('openpc.privacy_domain_id'),0);
 IF NOT p_fail_fast THEN PERFORM pg_advisory_xact_lock(scope_key);
 ELSIF NOT pg_try_advisory_xact_lock(scope_key)
 THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PC-DATA-6007'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_cigl_grant_sources(boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_cigl_grant_sources(boolean) TO openpc_control_runtime,openpc_control_worker;

-- Preserve the existing blocking interface and its source/authority lock order.
CREATE OR REPLACE FUNCTION openpc.lock_cigl_grant_sources()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.lock_cigl_grant_sources(false);
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
`;
