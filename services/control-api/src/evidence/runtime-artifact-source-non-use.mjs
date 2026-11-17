/** Validate the native V2 result as one exact installed-source observation.
 * The transaction MAC authenticates its producer; this shape alone is never
 * authority, a governed admission, reference clearance or a deletion result. */
export const runtimeArtifactSourceNonUseSql = `
CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_source_non_use(
 a control.runtime_artifact_source_disposition,proof jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE s control.runtime_artifact_source; input control.runtime_configuration_input; h text;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO STRICT s FROM control.runtime_artifact_source WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND source_owner_id=a.source_owner_id;
 SELECT * INTO STRICT input FROM control.runtime_configuration_input WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND runtime_configuration_input_id=a.runtime_configuration_input_id;
 IF a.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR a.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR s.database_role IS DISTINCT FROM session_user OR s.custody_root IS NULL
  OR s.custody_root->>'consumer_profile' IS DISTINCT FROM 'openpc:local-runtime-source-consumers:v2'
  OR input.configuration_digest IS DISTINCT FROM a.configuration_digest
  OR input.configuration_digest IS DISTINCT FROM sha256(input.configuration_cbor)
  OR proof IS DISTINCT FROM jsonb_build_object('profile','openpc:runtime-artifact-source-non-use:v1',
   'binding',s.custody_root,'input',jsonb_build_object('input_id',input.runtime_configuration_input_id::text,
    'module_installation_id',input.module_installation_id::text,
    'module_configuration_generation_id',input.module_configuration_generation_id::text,
    'configuration_digest',encode(input.configuration_digest,'hex')),
   'pending_digest',proof->'pending_digest','committed_digest',proof->'committed_digest',
   'history_sequence',proof->'history_sequence','history_head_digest',proof->'history_head_digest',
   'retained_head_digest',proof->'retained_head_digest','consumers',jsonb_build_array(
    'RuntimeTargetEffect','TargetDispositionIssuance','DispositionBootstrapRestore','CiglReconciliation',
    'SettledTransport','PriorBootstrapBinding','CiglInvalidation','NoEffectSuspension','TargetHandoff'))
  OR jsonb_typeof(proof->'history_sequence') IS DISTINCT FROM 'number'
  OR coalesce(proof->>'history_sequence','') !~ '^[0-9]{1,4}$'
  OR (proof->>'history_sequence')::integer NOT BETWEEN 2 AND 4096
  OR proof->>'pending_digest'=proof->>'committed_digest'
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-NON-USE-UNPROVEN'; END IF;
 FOREACH h IN ARRAY ARRAY['pending_digest','committed_digest','history_head_digest','retained_head_digest'] LOOP
  IF jsonb_typeof(proof->h) IS DISTINCT FROM 'string' OR coalesce(proof->>h,'') !~ '^[0-9a-f]{64}$'
  THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-NON-USE-UNPROVEN'; END IF;
 END LOOP;
END $$;
ALTER FUNCTION openpc.assert_runtime_artifact_source_non_use(control.runtime_artifact_source_disposition,jsonb) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.assert_runtime_artifact_source_non_use(control.runtime_artifact_source_disposition,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_runtime_artifact_source_non_use(control.runtime_artifact_source_disposition,jsonb) TO openpc_control_worker;
`;
