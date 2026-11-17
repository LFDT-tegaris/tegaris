/** One current physical input and its immutable primary-key successor. The
 * earlier disposition remains a separate admission; neither its historical
 * selection nor a caller-supplied cursor establishes current eligibility. */
export const runtimeArtifactRetirementSelectionSql = `
CREATE OR REPLACE FUNCTION openpc.runtime_artifact_retirement_before(source jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','pc.evidence.runtime-artifact-before.v1','source',source)),'UTF8')),'hex')
$$;
CREATE OR REPLACE FUNCTION openpc.runtime_artifact_retirement_input_identity(input_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE source record; info jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT participant_id,privacy_domain_id,runtime_configuration_input_id,module_installation_id,
  module_configuration_generation_id,configuration_digest,resource_bindings,created_at INTO STRICT source
  FROM control.runtime_configuration_input WHERE participant_id=openpc.current_participant_id()
   AND privacy_domain_id=openpc.current_privacy_domain_id() AND runtime_configuration_input_id=input_id;
 info:=openpc.runtime_artifact_input_information(input_id);
 IF info->'bytesMatch' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-ARCHIVE_UNPROVEN'; END IF;
 RETURN jsonb_build_object('participantId',source.participant_id::text,'privacyDomainId',source.privacy_domain_id::text,
  'runtimeConfigurationInputId',input_id::text,'moduleInstallationId',source.module_installation_id::text,
  'moduleConfigurationGenerationId',source.module_configuration_generation_id::text,
  'configurationDigest','sha256:'||encode(source.configuration_digest,'hex'),'configurationBytes',(info->>'byteLength')::integer,
  'resourceBindingsDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(source.resource_bindings),'UTF8')),'hex'),
  'createdAt',to_char(source.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $$;

CREATE OR REPLACE FUNCTION openpc.runtime_artifact_retirement_selection(policy_id uuid,previous_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p uuid:=openpc.current_participant_id(); d uuid:=openpc.current_privacy_domain_id();
 prior control.deletion_job; retired control.runtime_artifact_retirement; admission control.runtime_artifact_source_disposition;
 denied control.runtime_artifact_source_denial; receipt control.audit_occurrence;
 input_id uuid; next_id uuid; selected jsonb; source jsonb; next_source jsonb; successor jsonb:='null'::jsonb;
 cursor jsonb:='null'::jsonb; expected jsonb; root_digest text;
BEGIN
 PERFORM openpc.lock_runtime_artifact_disposition();
 IF openpc.current_action_intent_id() NOT IN ('ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1','ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1')
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF previous_id IS NOT NULL THEN
  SELECT * INTO STRICT prior FROM control.deletion_job WHERE participant_id=p AND privacy_domain_id=d
   AND deletion_job_id=previous_id AND target_data_class='RUNTIME_ARTIFACT' AND state='SUCCEEDED' AND revision=1;
  SELECT * INTO STRICT retired FROM control.runtime_artifact_retirement WHERE participant_id=p AND privacy_domain_id=d AND deletion_job_id=previous_id;
  PERFORM openpc.assert_runtime_artifact_retirement_committed(retired);
  IF EXISTS(SELECT 1 FROM control.deletion_job WHERE participant_id=p AND privacy_domain_id=d AND previous_deletion_job_id=previous_id
    AND operation_id IS DISTINCT FROM openpc.current_operation_id())
   OR prior.selection->'nextInput'='null'::jsonb THEN RAISE EXCEPTION 'RUNTIME-RETIREMENT-STALE_SELECTION'; END IF;
  expected:=prior.selection->'nextInput'; input_id:=(expected->>'runtimeConfigurationInputId')::uuid;
  SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=p AND privacy_domain_id=d
   AND operation_id=prior.operation_id AND aggregate_id=previous_id AND aggregate_type='evidence-deletion';
  cursor:=jsonb_build_object('deletionJobId','urn:openpc:resource:'||previous_id::text,
   'receiptDigest','sha256:'||encode(receipt.receipt_digest,'hex'));
 ELSE
  -- A committed predecessor with a promised successor cannot be bypassed by
  -- opening another chain or changing only the request key.
  IF EXISTS(SELECT 1 FROM control.deletion_job j WHERE j.participant_id=p AND j.privacy_domain_id=d
    AND j.target_data_class='RUNTIME_ARTIFACT' AND j.state='SUCCEEDED' AND j.selection->'nextInput'<>'null'::jsonb
    AND NOT EXISTS(SELECT 1 FROM control.deletion_job n WHERE n.participant_id=p AND n.privacy_domain_id=d AND n.previous_deletion_job_id=j.deletion_job_id))
   THEN RAISE EXCEPTION 'RUNTIME-RETIREMENT-STALE_SELECTION'; END IF;
  SELECT runtime_configuration_input_id INTO input_id FROM control.runtime_configuration_input
   WHERE participant_id=p AND privacy_domain_id=d ORDER BY runtime_configuration_input_id LIMIT 1;
 END IF;
 IF input_id IS NULL THEN RAISE EXCEPTION 'RUNTIME-RETIREMENT-ALREADY_DELETED'; END IF;
 IF input_id IS DISTINCT FROM (SELECT runtime_configuration_input_id FROM control.runtime_configuration_input
  WHERE participant_id=p AND privacy_domain_id=d ORDER BY runtime_configuration_input_id LIMIT 1)
 THEN RAISE EXCEPTION 'RUNTIME-RETIREMENT-STALE_SELECTION'; END IF;
 source:=openpc.runtime_artifact_retirement_input_identity(input_id);
 IF expected IS NOT NULL AND expected IS DISTINCT FROM jsonb_build_object('runtimeConfigurationInputId',input_id::text,
  'configurationDigest',source->>'configurationDigest','beforeDigest',openpc.runtime_artifact_retirement_before(source))
 THEN RAISE EXCEPTION 'RUNTIME-RETIREMENT-STALE_SELECTION'; END IF;
 SELECT * INTO admission FROM control.runtime_artifact_source_disposition WHERE participant_id=p AND privacy_domain_id=d
  AND runtime_configuration_input_id=input_id AND configuration_digest=decode(substring(source->>'configurationDigest' from 8),'hex');
 IF NOT FOUND THEN RAISE EXCEPTION 'RUNTIME-RETIREMENT-GOVERNED_DISPOSITION_REQUIRED'; END IF;
 PERFORM openpc.assert_runtime_artifact_source_disposition_committed(admission);
 SELECT * INTO denied FROM control.runtime_artifact_source_denial WHERE participant_id=p AND privacy_domain_id=d
  AND disposition_id=admission.disposition_id AND source_owner_id=admission.source_owner_id;
 IF NOT FOUND OR denied.denial_digest IS DISTINCT FROM sha256(denied.signed_denial)
 THEN RAISE EXCEPTION 'RUNTIME-RETIREMENT-RUNTIME_CUSTODY_UNPROVEN'; END IF;
 selected:=openpc.runtime_artifact_source_observation(input_id,policy_id);
 root_digest:=selected->>'sourceRootDigest';
 IF selected->>'sourceOwnerId' IS DISTINCT FROM admission.source_owner_id::text
  OR root_digest IS DISTINCT FROM admission.selection->>'sourceRootDigest'
  OR selected->'observation'->'source' IS DISTINCT FROM source
  OR selected->>'archivePendingDigest' IS DISTINCT FROM admission.selection->>'archivePendingDigest'
 THEN RAISE EXCEPTION 'RUNTIME-RETIREMENT-RUNTIME_CUSTODY_UNPROVEN'; END IF;
 SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=p AND privacy_domain_id=d
  AND operation_id=admission.operation_id AND aggregate_id=admission.disposition_id AND aggregate_type='runtime-artifact-disposition';
 SELECT runtime_configuration_input_id INTO next_id FROM control.runtime_configuration_input
  WHERE participant_id=p AND privacy_domain_id=d AND runtime_configuration_input_id>input_id ORDER BY runtime_configuration_input_id LIMIT 1;
 IF next_id IS NOT NULL THEN
  next_source:=openpc.runtime_artifact_retirement_input_identity(next_id);
  successor:=jsonb_build_object('runtimeConfigurationInputId',next_id::text,'configurationDigest',next_source->>'configurationDigest',
   'beforeDigest',openpc.runtime_artifact_retirement_before(next_source));
 END IF;
 RETURN selected->'observation'||jsonb_build_object('priorCursor',cursor,'nextInput',successor,'disposition',jsonb_build_object(
  'dispositionId',admission.disposition_id::text,'operationId',admission.operation_id::text,
  'receiptDigest','sha256:'||encode(receipt.receipt_digest,'hex'),'nativeDenialDigest','sha256:'||encode(denied.denial_digest,'hex'),
  'sourceOwnerId',admission.source_owner_id::text,'sourceRootDigest',root_digest));
END $$;

CREATE OR REPLACE FUNCTION openpc.runtime_artifact_retirement_plan(policy_id uuid,previous_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE selection jsonb; blocker text; next_job uuid; prior control.deletion_job; retired control.runtime_artifact_retirement;
BEGIN
 PERFORM openpc.lock_runtime_artifact_disposition();
 IF previous_id IS NOT NULL THEN
  SELECT * INTO STRICT prior FROM control.deletion_job WHERE participant_id=openpc.current_participant_id()
   AND privacy_domain_id=openpc.current_privacy_domain_id() AND deletion_job_id=previous_id AND target_data_class='RUNTIME_ARTIFACT';
  SELECT * INTO STRICT retired FROM control.runtime_artifact_retirement WHERE participant_id=prior.participant_id
   AND privacy_domain_id=prior.privacy_domain_id AND deletion_job_id=prior.deletion_job_id;
  PERFORM openpc.assert_runtime_artifact_retirement_committed(retired);
  SELECT deletion_job_id INTO next_job FROM control.deletion_job WHERE participant_id=prior.participant_id
   AND privacy_domain_id=prior.privacy_domain_id AND previous_deletion_job_id=previous_id;
  IF next_job IS NOT NULL OR prior.selection->'nextInput'='null'::jsonb THEN
   RETURN jsonb_build_object('selection',null,'beforeDigest',null,'eligible',false,'blockers','[]'::jsonb,
    'continuationState',CASE WHEN next_job IS NULL THEN 'COMPLETE' ELSE 'ADVANCED' END,
    'nextDeletionJobId',CASE WHEN next_job IS NULL THEN NULL ELSE 'urn:openpc:resource:'||next_job::text END,'authority','NONE');
  END IF;
 END IF;
 BEGIN
  selection:=openpc.runtime_artifact_retirement_selection(policy_id,previous_id);
 EXCEPTION WHEN no_data_found THEN blocker:='STALE_SELECTION';
 WHEN raise_exception THEN
  blocker:=regexp_replace(SQLERRM,'^RUNTIME-(DISPOSITION|RETIREMENT)-','');
  blocker:=CASE blocker WHEN 'INCOMPLETE_REFERENCES' THEN 'INCOMPLETE_REFERENCE_COVERAGE'
    WHEN 'SOURCE_UNPROVEN' THEN 'SOURCE_REDELIVERY_UNPROVEN' WHEN 'ARCHIVE_UNPROVEN' THEN 'RUNTIME_CUSTODY_UNPROVEN' ELSE blocker END;
  IF blocker NOT IN ('STALE_SELECTION','SELECTED_INPUT','REFERENCES','ACTIVE_HOLD','SINK_QUORUM','RETENTION_NOT_ELAPSED',
   'INCOMPLETE_REFERENCE_COVERAGE','SOURCE_REDELIVERY_UNPROVEN','RUNTIME_CUSTODY_UNPROVEN','GOVERNED_DISPOSITION_REQUIRED','ALREADY_DELETED') THEN RAISE; END IF;
 END;
 RETURN jsonb_build_object('selection',selection,'beforeDigest',CASE WHEN selection IS NULL THEN NULL
  ELSE openpc.runtime_artifact_retirement_before(selection->'source') END,'eligible',selection IS NOT NULL,
  'blockers',CASE WHEN blocker IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(blocker) END,
  'continuationState',CASE WHEN selection IS NULL THEN 'BLOCKED' ELSE 'READY' END,'nextDeletionJobId',null,'authority','NONE');
END $$;
REVOKE ALL ON FUNCTION openpc.runtime_artifact_retirement_before(jsonb),openpc.runtime_artifact_retirement_input_identity(uuid),
 openpc.runtime_artifact_retirement_selection(uuid,uuid),openpc.runtime_artifact_retirement_plan(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_artifact_retirement_before(jsonb),openpc.runtime_artifact_retirement_input_identity(uuid),
 openpc.runtime_artifact_retirement_selection(uuid,uuid),openpc.runtime_artifact_retirement_plan(uuid,uuid) TO openpc_control_runtime;
`;
