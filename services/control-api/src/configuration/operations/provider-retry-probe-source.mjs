// Registered by the canonical security-tail/migration owner. These declarations
// only read existing native evidence; they cannot issue an operations receipt.
const action = "openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'";
const scoped = `openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id) AND ${action}`;
const locked = [
  'privacy_domain',
  'provider_profile',
  'provider_probe_observation',
  'configuration_work',
  'runtime_configuration_input',
  'module_installation',
  'module_configuration_generation',
];
// The existing current-input view also reads every resource binding and the
// retirement catalogue. Invisible bindings/retirements must never look absent.
const read = [
  ...locked,
  'outbox_event',
  'mutation_evidence',
  'indexer_profile',
  'projection_plan',
  'cigl_settings',
  'runtime_artifact_retirement',
];
const referenceIds = [
  'providerProfileId',
  'observationId',
  'qualificationWorkId',
  'operationId',
  'resultEventId',
];
const referenceDigests = [
  'artifactDigest',
  'configurationDigest',
  'observationDigest',
  'resultReceiptDigest',
  'authorizationEvidenceDigest',
];
const context = `
 PERFORM openpc.assert_request_context(true);
 IF current_setting('role') NOT IN ('openpc_control_owner','openpc_operations_qualification_owner')
  OR current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
  OR current_setting('session_replication_role')<>'origin'
  OR current_setting('openpc.context_mode',true) IS DISTINCT FROM 'PARTICIPANT'
  OR NOT (${action})
  OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_CONTEXT'; END IF;
 IF jsonb_typeof(p_reference) IS DISTINCT FROM 'object' OR octet_length(p_reference::text)>4096
  OR (SELECT count(*) FROM jsonb_object_keys(p_reference))<>10
  OR NOT p_reference ?& ARRAY[${[...referenceIds, ...referenceDigests].map((k) => `'${k}'`).join(',')}]
  OR EXISTS(SELECT 1 FROM jsonb_each(p_reference) item WHERE jsonb_typeof(item.value)<>'string')
  OR ${referenceIds.map((k) => `coalesce(p_reference->>'${k}','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`).join('\n  OR ')}
  OR ${referenceDigests.map((k) => `coalesce(p_reference->>'${k}','') !~ '^sha256:[0-9a-f]{64}$'`).join('\n  OR ')}
 THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_REFERENCE'; END IF;
`;

export const providerRetryProbeSourceSql = `
${read
  .map(
    (table) => `
GRANT SELECT ON control.${table} TO openpc_control_owner;
DROP POLICY IF EXISTS operations_probe_source_read ON control.${table};
CREATE POLICY operations_probe_source_read ON control.${table} FOR SELECT TO openpc_control_owner USING(${scoped});`,
  )
  .join('\n')}
${locked
  .map(
    (table) => `
GRANT UPDATE ON control.${table} TO openpc_control_owner;
DROP POLICY IF EXISTS operations_probe_source_lock ON control.${table};
CREATE POLICY operations_probe_source_lock ON control.${table} FOR UPDATE TO openpc_control_owner USING(${scoped}) WITH CHECK(false);`,
  )
  .join('\n')}
GRANT SELECT,UPDATE ON control.participant TO openpc_control_owner;
DROP POLICY IF EXISTS operations_probe_participant_read ON control.participant;
CREATE POLICY operations_probe_participant_read ON control.participant FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND ${action});
DROP POLICY IF EXISTS operations_probe_participant_lock ON control.participant;
CREATE POLICY operations_probe_participant_lock ON control.participant FOR UPDATE TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND ${action}) WITH CHECK(false);
-- UPDATE privilege is necessary for row locks. Existing permissive policies
-- compose with OR, so their write checks cannot override this read-action fence.
${[...locked, 'participant']
  .map(
    (table) => `
DROP POLICY IF EXISTS operations_probe_read_action_no_update ON control.${table};
CREATE POLICY operations_probe_read_action_no_update ON control.${table} AS RESTRICTIVE FOR UPDATE TO openpc_control_owner
 USING(true) WITH CHECK(openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1');`,
  )
  .join('\n')}
GRANT SELECT ON control.runtime_configuration_input_current_metadata,control.module_version TO openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.read_provider_retry_probe_source(p_reference jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE p control.provider_profile; o control.provider_probe_observation; w control.configuration_work;
 e control.outbox_event; a control.mutation_evidence;
BEGIN
 ${context.trim()}
 SELECT * INTO STRICT p FROM control.provider_profile
  WHERE provider_profile_id=(p_reference->>'providerProfileId')::uuid
   AND openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id);
 SELECT * INTO STRICT o FROM control.provider_probe_observation
  WHERE observation_id=(p_reference->>'observationId')::uuid AND provider_profile_id=p.provider_profile_id
   AND participant_id=p.participant_id AND privacy_domain_id=p.privacy_domain_id;
 SELECT * INTO STRICT w FROM control.configuration_work
  WHERE configuration_work_id=(p_reference->>'qualificationWorkId')::uuid AND resource_id=p.provider_profile_id
   AND participant_id=p.participant_id AND privacy_domain_id=p.privacy_domain_id;
 IF o.state IS DISTINCT FROM 'OBSERVED' OR o.observed_revision IS DISTINCT FROM o.source_revision+1
  OR o.input_digest IS DISTINCT FROM p_reference->>'artifactDigest'
  OR o.configuration_digest IS DISTINCT FROM p_reference->>'configurationDigest'
  OR o.observation_digest IS DISTINCT FROM p_reference->>'observationDigest'
  OR o.completed_at IS NULL OR o.valid_until IS NULL OR o.valid_until<=o.completed_at
  OR w.work_kind IS DISTINCT FROM 'PROVIDER_QUALIFICATION' OR w.state NOT IN ('COMPLETED','FAILED')
  OR w.operation_id IS DISTINCT FROM (p_reference->>'operationId')::uuid
  OR w.input_digest IS DISTINCT FROM o.input_digest OR w.configuration_digest IS DISTINCT FROM o.configuration_digest
  OR w.result_receipt_digest IS DISTINCT FROM p_reference->>'resultReceiptDigest'
  OR w.result_event_id IS DISTINCT FROM (p_reference->>'resultEventId')::uuid
  OR w.completed_at IS NULL OR w.result_receipt IS NULL OR w.completed_at<o.completed_at
 THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 SELECT * INTO STRICT e FROM control.outbox_event WHERE event_id=w.result_event_id
  AND participant_id=w.participant_id AND privacy_domain_id=w.privacy_domain_id;
 SELECT * INTO STRICT a FROM control.mutation_evidence WHERE operation_id=w.operation_id
  AND participant_id=w.participant_id AND privacy_domain_id=w.privacy_domain_id;
 IF e.aggregate_type IS DISTINCT FROM 'provider-profile' OR e.aggregate_id IS DISTINCT FROM p.provider_profile_id
  OR e.event_type IS DISTINCT FROM (CASE w.state WHEN 'COMPLETED' THEN 'provider-profile.qualified.v1' ELSE 'provider-profile.qualification-failed.v1' END)
  OR e.payload_cbor IS DISTINCT FROM convert_to(openpc.signing_canonical_json(w.result_receipt),'UTF8')
  OR e.payload_digest IS DISTINCT FROM sha256(e.payload_cbor)
  OR 'sha256:'||encode(e.payload_digest,'hex') IS DISTINCT FROM w.result_receipt_digest
  OR a.action_intent_id IS DISTINCT FROM 'ACT-PROVIDER_APPROVE_QUALIFICATION-V1'
  OR a.catalog_operation_id IS DISTINCT FROM 'CFG-OP-QUALIFY-PROVIDER-PROFILE'
  OR a.aggregate_type IS DISTINCT FROM 'provider-profile'
  OR a.aggregate_id IS DISTINCT FROM p.provider_profile_id OR a.aggregate_version IS DISTINCT FROM o.observed_revision+1
  OR a.evidence_digest IS DISTINCT FROM sha256(a.evidence_cbor)
  OR 'sha256:'||encode(a.evidence_digest,'hex') IS DISTINCT FROM p_reference->>'authorizationEvidenceDigest'
  OR octet_length(a.cose_sign1) NOT BETWEEN 1 AND 4194304 OR e.cose_sign1 IS DISTINCT FROM a.cose_sign1
  OR octet_length(a.evidence_cbor) NOT BETWEEN 1 AND 4194304
  OR octet_length(e.payload_cbor) NOT BETWEEN 1 AND 4194304
 THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 IF w.state='COMPLETED' AND (
  w.result_receipt->>'liveObservationId' IS DISTINCT FROM o.observation_id::text
  OR w.result_receipt->>'liveObservationDigest' IS DISTINCT FROM o.observation_digest
  OR w.result_receipt->'liveObservation' IS DISTINCT FROM o.observation
  OR w.result_receipt->>'artifactDigest' IS DISTINCT FROM o.input_digest
  OR w.result_receipt->>'resourceId' IS DISTINCT FROM p.provider_profile_id::text
  OR w.result_receipt->>'workKind' IS DISTINCT FROM 'PROVIDER_QUALIFICATION'
  OR w.result_receipt->>'consumer' IS DISTINCT FROM 'LS-MULTI-RPC'
  OR jsonb_typeof(w.result_receipt->'artifactCbor') IS DISTINCT FROM 'array')
 THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 IF w.state='FAILED' AND (w.result_receipt->>'resourceId' IS DISTINCT FROM p.provider_profile_id::text
  OR w.result_receipt->>'workKind' IS DISTINCT FROM 'PROVIDER_QUALIFICATION'
  OR w.result_receipt->'terminal' IS DISTINCT FROM 'true'::jsonb
  OR w.result_receipt->>'errorCode' IS DISTINCT FROM w.last_error_code)
 THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 -- The retained COSE authorizes the original mutation. It is NOT a signature
 -- over this result payload or an operations qualification receipt.
 RETURN jsonb_build_object('reference',p_reference,'participantId',p.participant_id,'privacyDomainId',p.privacy_domain_id,
  'workState',w.state,'sourceRevision',o.source_revision::text,'observedRevision',o.observed_revision::text,
  'validUntilMs',floor(extract(epoch from o.valid_until)*1000)::text,
  'completedAtMs',floor(extract(epoch from w.completed_at)*1000)::text,
  'observation',o.observation,'resultReceipt',w.result_receipt,
  'resultPayloadHex',encode(e.payload_cbor,'hex'),'authorizationEvidenceHex',encode(a.evidence_cbor,'hex'),
  'authorizationCoseHex',encode(a.cose_sign1,'hex'));
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE';
END $$;

CREATE OR REPLACE FUNCTION openpc.lock_provider_retry_probe_source(p_reference jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE pid uuid; privacy uuid; p control.provider_profile; o control.provider_probe_observation;
 w control.configuration_work; input_id uuid; installation_id uuid; current_generation_id uuid; history jsonb;
BEGIN
 ${context.trim()}
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 -- Parent roots precede native source rows. NOWAIT/try-lock fail closed when an
 -- outer generation/qualification consumer already owns a different fence.
 PERFORM 1 FROM control.participant WHERE participant_id=pid AND state='ACTIVE' AND archived_at IS NULL FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 PERFORM 1 FROM control.privacy_domain WHERE participant_id=pid AND privacy_domain_id=privacy AND state='ACTIVE' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||pid::text||':'||privacy::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT p FROM control.provider_profile WHERE provider_profile_id=(p_reference->>'providerProfileId')::uuid
  AND participant_id=pid AND privacy_domain_id=privacy FOR SHARE NOWAIT;
 SELECT * INTO STRICT o FROM control.provider_probe_observation WHERE observation_id=(p_reference->>'observationId')::uuid
  AND participant_id=pid AND privacy_domain_id=privacy FOR SHARE NOWAIT;
 SELECT * INTO STRICT w FROM control.configuration_work WHERE configuration_work_id=(p_reference->>'qualificationWorkId')::uuid
  AND participant_id=pid AND privacy_domain_id=privacy FOR SHARE NOWAIT;
 IF p.state NOT IN ('QUALIFIED','ACTIVE') OR p.qualification_observation_id IS DISTINCT FROM o.observation_id
  OR p.behavior_fingerprint IS DISTINCT FROM o.input_digest OR p.revision IS DISTINCT FROM o.observed_revision+2
  OR w.state IS DISTINCT FROM 'COMPLETED' OR o.valid_until<=clock_timestamp()
  OR (SELECT count(*) FROM control.configuration_work q WHERE q.participant_id=pid AND q.privacy_domain_id=privacy
      AND q.resource_id=p.provider_profile_id AND q.work_kind='PROVIDER_QUALIFICATION' AND q.state='COMPLETED'
      AND q.result_receipt->>'liveObservationId'=o.observation_id::text
      AND q.result_receipt->>'liveObservationDigest'=o.observation_digest)<>1
 THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 SELECT c.runtime_configuration_input_id,c.module_installation_id,c.module_configuration_generation_id
  INTO STRICT input_id,installation_id,current_generation_id FROM control.runtime_configuration_input_current_metadata c
  WHERE c.participant_id=pid AND c.privacy_domain_id=privacy AND c.active
   AND 'sha256:'||encode(c.configuration_digest,'hex')=w.configuration_digest;
 PERFORM 1 FROM control.module_installation WHERE module_installation_id=installation_id
  AND participant_id=pid AND privacy_domain_id=privacy AND state='ENABLED' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 PERFORM 1 FROM control.module_configuration_generation WHERE generation_id=current_generation_id
  AND module_installation_id=installation_id AND participant_id=pid AND privacy_domain_id=privacy AND active FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 PERFORM 1 FROM control.runtime_configuration_input WHERE runtime_configuration_input_id=input_id
  AND participant_id=pid AND privacy_domain_id=privacy AND selected FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 -- Re-read the existing current view after all physical fences are held.
 PERFORM 1 FROM control.runtime_configuration_input_current_metadata WHERE runtime_configuration_input_id=input_id
  AND participant_id=pid AND privacy_domain_id=privacy AND module_installation_id=installation_id
  AND module_configuration_generation_id=current_generation_id AND 'sha256:'||encode(configuration_digest,'hex')=w.configuration_digest;
 IF NOT FOUND OR o.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 history:=openpc.read_provider_retry_probe_source(p_reference);
 IF o.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE'; END IF;
 RETURN jsonb_build_object('history',history,'configurationInputId',input_id,
  'moduleInstallationId',installation_id,'moduleConfigurationGenerationId',current_generation_id);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN RAISE EXCEPTION 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE';
 WHEN lock_not_available THEN RAISE EXCEPTION 'PC-DATA-6007';
END $$;
ALTER FUNCTION openpc.read_provider_retry_probe_source(jsonb) OWNER TO openpc_control_owner;
ALTER FUNCTION openpc.lock_provider_retry_probe_source(jsonb) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.read_provider_retry_probe_source(jsonb),openpc.lock_provider_retry_probe_source(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_provider_retry_probe_source(jsonb),openpc.lock_provider_retry_probe_source(jsonb)
 TO openpc_control_owner,openpc_operations_qualification_owner;
`;
