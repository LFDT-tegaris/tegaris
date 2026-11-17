/** Lifecycle effects require the shared signed business commit. */
// These are the actual M2 observation producers, including empty statements and
// future inserts. The declaration and reader share this single catalogue.
export const moduleReferenceWriteTables = Object.freeze([
  'module_installation',
  'module_configuration_generation',
  'module_version',
  'module_dependency',
  'module_capability',
  'policy_generation',
  'policy_version',
  'policy_artifact',
  'runtime_configuration_input',
  'configuration_work',
  'runtime_configuration_generation',
  'runtime_target',
  'policy_activation_occurrence',
  'policy_activation_occurrence_target',
  'provider_profile',
  'indexer_profile',
  'projection_plan',
]);
const moduleReferenceWriteFunctionSql = `
CREATE OR REPLACE FUNCTION openpc.guard_module_reference_write_fence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'DATA-6020-MODULE-REFERENCE-HISTORY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF TG_TABLE_NAME IN ('module_version','module_dependency','module_capability') AND
  NOT pg_try_advisory_xact_lock(hashtextextended('module-release-catalog',0)) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6007';
 END IF;
 IF openpc.current_participant_id() IS NULL OR openpc.current_privacy_domain_id() IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6001';
 END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||
  openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0)) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6007';
 END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_module_reference_write_fence() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.guard_module_reference_write_fence() TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker;
`;
export const moduleControlReferenceTables = Object.freeze([
  'runtime_configuration_input',
  'configuration_work',
  'runtime_configuration_generation',
  'runtime_target',
  'provider_profile',
  'indexer_profile',
  'projection_plan',
]);
const referenceTriggers = (tables) =>
  tables
    .map(
      (table) => `
DROP TRIGGER IF EXISTS a_module_reference_fence_${table} ON control.${table};
CREATE TRIGGER a_module_reference_fence_${table} BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON control.${table}
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_module_reference_write_fence();`,
    )
    .join('\n');
// Policy migrations precede Control API tables on a clean install. Each owning
// generated tail installs its own triggers; the full catalogue is still checked.
export const moduleReferenceWriteFenceSql =
  moduleReferenceWriteFunctionSql + referenceTriggers(moduleReferenceWriteTables);
export const moduleControlReferenceWriteFenceSql = referenceTriggers(
  moduleReferenceWriteTables.filter((table) => moduleControlReferenceTables.includes(table)),
);
const modulePolicyReferenceWriteFenceSql =
  moduleReferenceWriteFunctionSql +
  referenceTriggers(
    moduleReferenceWriteTables.filter((table) => !moduleControlReferenceTables.includes(table)),
  );
export const moduleLifecycleGuardSql = `
${modulePolicyReferenceWriteFenceSql}
CREATE OR REPLACE FUNCTION openpc.deployment_module_generation(participant uuid,privacy uuid)
RETURNS bytea LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 WITH RECURSIVE nodes AS (
  SELECT m.*,v.module_id,v.semantic_version,v.manifest_digest,c.configuration_digest,c.generation,c.active
  FROM control.module_installation m JOIN control.module_version v USING(module_version_id)
  JOIN control.module_configuration_generation c USING(module_installation_id)
  WHERE m.participant_id=participant AND m.privacy_domain_id=privacy
   AND c.participant_id=participant AND c.privacy_domain_id=privacy AND v.release_payload_cbor IS NOT NULL
 ), closure(id) AS (
  SELECT module_installation_id FROM nodes WHERE module_id IN ('pc.transaction.delivery','pc.deployment.governance')
  UNION
  SELECT provider.module_installation_id FROM closure
   JOIN nodes consumer ON consumer.module_installation_id=closure.id
   JOIN control.module_dependency d ON d.consumer_module_version_id=consumer.module_version_id
   JOIN nodes provider ON provider.module_id=d.provider_module_id AND provider.semantic_version=d.semantic_version
    AND provider.manifest_digest=d.provider_manifest_digest
 ), selected AS (SELECT nodes.* FROM nodes JOIN closure ON closure.id=nodes.module_installation_id)
 SELECT CASE WHEN
  (SELECT count(*) FROM nodes WHERE module_id IN ('pc.transaction.delivery','pc.deployment.governance'))=2
  AND (SELECT count(DISTINCT module_id) FROM nodes WHERE module_id IN ('pc.transaction.delivery','pc.deployment.governance'))=2
  AND NOT EXISTS(SELECT 1 FROM selected WHERE state<>'ENABLED' OR NOT active OR generation<>1
   OR active_manifest_digest IS DISTINCT FROM manifest_digest OR lifecycle_evaluation_digest IS NULL
   OR NOT EXISTS(SELECT 1 FROM control.audit_occurrence a JOIN control.evidence_record e USING(participant_id,privacy_domain_id,receipt_id)
    WHERE a.participant_id=participant AND a.privacy_domain_id=privacy AND a.aggregate_id=selected.module_installation_id
     AND a.operation_id=selected.lifecycle_operation_id AND a.catalog_operation_id='MOD-OP-ENABLE'
     AND a.after_revision=selected.aggregate_version AND a.after_existence=1 AND a.receipt_digest=sha256(a.receipt_cbor)
     AND e.receipt_digest=a.receipt_digest))
  AND NOT EXISTS(SELECT 1 FROM selected consumer JOIN control.module_dependency d ON d.consumer_module_version_id=consumer.module_version_id
   WHERE NOT EXISTS(SELECT 1 FROM selected provider JOIN control.module_capability capability ON capability.module_version_id=provider.module_version_id
    WHERE provider.module_id=d.provider_module_id AND provider.semantic_version=d.semantic_version
     AND provider.manifest_digest=d.provider_manifest_digest AND capability.capability_id=d.capability_id))
  THEN sha256(convert_to(openpc.signing_canonical_json((SELECT jsonb_agg(jsonb_build_array(module_id,semantic_version,
    encode(manifest_digest,'hex'),encode(configuration_digest,'hex'),generation,aggregate_version,
    encode(lifecycle_evaluation_digest,'hex'),lifecycle_operation_id) ORDER BY module_id) FROM selected)),'UTF8'))
  ELSE NULL END
$$;
REVOKE ALL ON FUNCTION openpc.deployment_module_generation(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.deployment_module_generation(uuid,uuid) TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.check_module_lifecycle_state(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE installation control.module_installation%ROWTYPE; version control.module_version%ROWTYPE;
 configuration control.module_configuration_generation%ROWTYPE; evaluation control.module_lifecycle_evaluation%ROWTYPE;
 prior control.audit_occurrence%ROWTYPE; candidate control.mutation_candidate%ROWTYPE; projection jsonb;
 enabled boolean:=receipt.catalog_operation_id='MOD-OP-ENABLE';
 disabled boolean:=receipt.catalog_operation_id='MOD-OP-DISABLE';
 binding bytea; value text; bytes bytea;
BEGIN
 IF receipt.catalog_operation_id NOT IN ('MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE') OR receipt.before_existence<>1
  OR receipt.after_existence<>1 OR receipt.after_revision<>receipt.before_revision+1
 THEN RAISE EXCEPTION 'DATA-6021-MODULE-LIFECYCLE'; END IF;
 SELECT * INTO STRICT installation FROM control.module_installation m WHERE m.participant_id=receipt.participant_id
  AND m.privacy_domain_id=receipt.privacy_domain_id AND m.module_installation_id=receipt.aggregate_id
  AND m.aggregate_version=receipt.after_revision AND m.lifecycle_operation_id=receipt.operation_id;
 SELECT * INTO STRICT version FROM control.module_version WHERE module_version_id=installation.module_version_id;
 SELECT * INTO STRICT configuration FROM control.module_configuration_generation c
  WHERE c.participant_id=receipt.participant_id AND c.privacy_domain_id=receipt.privacy_domain_id
   AND c.module_installation_id=receipt.aggregate_id AND c.generation=1;
 SELECT * INTO STRICT evaluation FROM control.module_lifecycle_evaluation e
  WHERE e.participant_id=receipt.participant_id AND e.privacy_domain_id=receipt.privacy_domain_id
   AND e.operation_id=receipt.operation_id AND e.module_installation_id=receipt.aggregate_id
   AND e.revision=receipt.after_revision AND e.result_digest=installation.lifecycle_evaluation_digest
   AND e.result_digest=sha256(e.result_cbor);
 SELECT * INTO STRICT prior FROM control.audit_occurrence a WHERE a.participant_id=receipt.participant_id
  AND a.privacy_domain_id=receipt.privacy_domain_id AND a.aggregate_type=receipt.aggregate_type
  AND a.aggregate_id=receipt.aggregate_id AND a.after_revision=receipt.before_revision
  AND ((disabled AND a.catalog_operation_id='MOD-OP-ENABLE')
    OR (enabled AND a.catalog_operation_id IN ('MOD-OP-INSTALL','MOD-OP-DISABLE'))
    OR (NOT enabled AND NOT disabled AND a.catalog_operation_id='MOD-OP-REGISTER'));
 SELECT * INTO STRICT candidate FROM control.mutation_candidate c WHERE c.participant_id=receipt.participant_id
  AND c.privacy_domain_id=receipt.privacy_domain_id AND c.consumed_operation_id=receipt.operation_id
  AND c.catalog_operation_id=receipt.catalog_operation_id AND c.state='CONSUMED'
  AND c.resource_id=receipt.aggregate_id AND c.expected_revision=receipt.before_revision;
 IF disabled THEN
  -- Same framed transport descriptor as moduleDisableReplacementDigest; SQL
  -- verifies the admitted candidate against authoritative unchanged state.
  binding:=convert_to('pc.control.module-disable.v1','UTF8')||decode('00','hex');
  FOREACH value IN ARRAY ARRAY['MOD-OP-DISABLE','urn:openpc:resource:'||receipt.aggregate_id::text,
    receipt.before_revision::text,'sha256:'||encode(version.manifest_digest,'hex')] LOOP
   bytes:=convert_to(value,'UTF8'); binding:=binding||int4send(octet_length(bytes))||bytes;
  END LOOP;
  IF candidate.candidate_document->>'replacementDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(binding),'hex')
    OR candidate.candidate_document->>'expectedRevision' IS DISTINCT FROM receipt.before_revision::text
    OR candidate.candidate_document->>'actionIntentId' IS DISTINCT FROM 'ACT-MODULES_UPDATE_RESOURCE-V1'
    OR candidate.candidate_document-ARRAY['actionIntentId','actionIntentDigest','expectedRevision','replacementDigest','reason']<>'{}'::jsonb
  THEN RAISE EXCEPTION 'DATA-6021-MODULE-DISABLE-BINDING'; END IF;
 END IF;
 IF installation.state::text<>(CASE WHEN enabled THEN 'ENABLED' ELSE 'INSTALLED_DISABLED' END)
  OR configuration.active<>enabled OR installation.desired_manifest_digest<>version.manifest_digest
  OR installation.active_manifest_digest IS DISTINCT FROM (CASE WHEN enabled THEN version.manifest_digest ELSE NULL END)
  OR openpc.business_cbor(prior.after_state_preimage)->8 IS DISTINCT FROM openpc.business_cbor(receipt.before_state_preimage)->8
  OR installation.authority_epoch::text IS DISTINCT FROM (convert_from(receipt.authority_snapshot,'UTF8')::jsonb->'authorities'->0->>'authorityEpoch')
  OR installation.delegation_epoch::text IS DISTINCT FROM (convert_from(receipt.authority_snapshot,'UTF8')::jsonb->'authorities'->0->>'delegationEpoch')
  OR (NOT disabled AND (candidate.candidate_document->>'targetRef' IS DISTINCT FROM 'urn:openpc:resource:'||receipt.aggregate_id::text
  OR candidate.candidate_document->>'inputDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
   'targetRef','urn:openpc:resource:'||receipt.aggregate_id::text,'expectedRevision',receipt.before_revision::text,
   'manifestDigest','sha256:'||encode(version.manifest_digest,'hex'))),'UTF8')),'hex')))
 THEN RAISE EXCEPTION 'DATA-6021-MODULE-LIFECYCLE-BINDING'; END IF;
 projection:=jsonb_build_object('0',version.module_id,'1',version.semantic_version,'2',openpc.business_bytes(version.manifest_digest),
  '3',openpc.business_bytes(installation.admission_dependency_digest),'4',openpc.business_bytes(configuration.configuration_digest),
  '5',installation.state::text,'6',CASE WHEN enabled THEN 1 ELSE 0 END,'7',1,'8',CASE WHEN enabled THEN 1 ELSE 0 END,
  '9',openpc.business_bytes(evaluation.result_digest));
 IF enabled THEN projection:=projection||jsonb_build_object('10',openpc.business_bytes(version.manifest_digest)); END IF;
 IF projection IS DISTINCT FROM openpc.business_cbor(receipt.after_state_preimage)->8
  OR (projection-'5'-'6'-'8'-'9'-'10') IS DISTINCT FROM
     ((openpc.business_cbor(prior.after_state_preimage)->8)-'5'-'6'-'8'-'9'-'10')
 THEN RAISE EXCEPTION 'DATA-6021-MODULE-LIFECYCLE-PROJECTION'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_module_initial_transition()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='module_installation' THEN
  IF to_jsonb(NEW)-ARRAY['state','aggregate_version','active_manifest_digest','lifecycle_evaluation_digest','lifecycle_operation_id','authority_epoch','delegation_epoch','updated_at']
    IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','aggregate_version','active_manifest_digest','lifecycle_evaluation_digest','lifecycle_operation_id','authority_epoch','delegation_epoch','updated_at']
   OR NEW.aggregate_version<>OLD.aggregate_version+1 OR NEW.lifecycle_operation_id IS NULL
   OR NEW.lifecycle_evaluation_digest IS NULL
   OR NOT ((OLD.state='ADMITTED' AND NEW.state='INSTALLED_DISABLED' AND OLD.active_manifest_digest IS NULL AND NEW.active_manifest_digest IS NULL)
    OR (OLD.state='INSTALLED_DISABLED' AND NEW.state='ENABLED' AND OLD.active_manifest_digest IS NULL AND NEW.active_manifest_digest IS NOT DISTINCT FROM NEW.desired_manifest_digest)
    OR (OLD.state='ENABLED' AND NEW.state='INSTALLED_DISABLED' AND OLD.active_manifest_digest IS NOT DISTINCT FROM OLD.desired_manifest_digest AND NEW.active_manifest_digest IS NULL))
  THEN RAISE EXCEPTION 'DATA-6021-MODULE-UNSUPPORTED-TRANSITION'; END IF;
 ELSE
  IF to_jsonb(NEW)-'active' IS DISTINCT FROM to_jsonb(OLD)-'active' OR OLD.active=NEW.active
  THEN RAISE EXCEPTION 'DATA-6021-MODULE-GENERATION-IMMUTABLE'; END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.check_module_initial_commit()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE operation uuid; receipt control.audit_occurrence%ROWTYPE;
BEGIN
 SELECT lifecycle_operation_id INTO STRICT operation FROM control.module_installation
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
    AND module_installation_id=NEW.module_installation_id;
 SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=operation AND aggregate_id=NEW.module_installation_id
  AND aggregate_type='module-registration' AND catalog_operation_id IN ('MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE');
 PERFORM openpc.check_module_lifecycle_state(receipt);
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS module_initial_transition ON control.module_installation;
CREATE TRIGGER module_initial_transition BEFORE UPDATE ON control.module_installation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_module_initial_transition();
DROP TRIGGER IF EXISTS module_generation_transition ON control.module_configuration_generation;
CREATE TRIGGER module_generation_transition BEFORE UPDATE ON control.module_configuration_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_module_initial_transition();
DROP TRIGGER IF EXISTS module_initial_commit ON control.module_installation;
CREATE CONSTRAINT TRIGGER module_initial_commit AFTER UPDATE ON control.module_installation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_module_initial_commit();
DROP TRIGGER IF EXISTS module_generation_commit ON control.module_configuration_generation;
CREATE CONSTRAINT TRIGGER module_generation_commit AFTER UPDATE ON control.module_configuration_generation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_module_initial_commit();
DROP TRIGGER IF EXISTS module_evaluation_commit ON control.module_lifecycle_evaluation;
CREATE CONSTRAINT TRIGGER module_evaluation_commit AFTER INSERT ON control.module_lifecycle_evaluation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_module_initial_commit();
REVOKE ALL ON FUNCTION openpc.check_module_lifecycle_state(control.audit_occurrence),openpc.guard_module_initial_transition(),openpc.check_module_initial_commit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.check_module_lifecycle_state(control.audit_occurrence),openpc.guard_module_initial_transition(),openpc.check_module_initial_commit() TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT UPDATE (state,aggregate_version,active_manifest_digest,lifecycle_evaluation_digest,lifecycle_operation_id,authority_epoch,delegation_epoch,updated_at)
 ON control.module_installation TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT UPDATE (active) ON control.module_configuration_generation TO openpc_control_runtime,openpc_control_platform_runtime;
`;
