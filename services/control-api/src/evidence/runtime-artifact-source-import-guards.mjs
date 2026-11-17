// The native source journals the exact pending identity before authorizing its
// SQL INSERT. This transaction MAC is distinct from disposition/denial custody.
export const runtimeArtifactSourceImportGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_source_import(input control.runtime_configuration_input)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE s control.runtime_artifact_source; secret bytea; wire bytea; nonce bytea; mac bytea;
 expected bytea; different integer:=0; document jsonb; pending jsonb; root jsonb; installation jsonb;
 wire_text text:=current_setting('openpc.runtime_source_import_wire',true);
 nonce_text text:=current_setting('openpc.runtime_source_import_nonce',true);
 mac_text text:=current_setting('openpc.runtime_source_import_mac',true);
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF input.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR input.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.runtime_artifact_source WHERE participant_id=input.participant_id
  AND privacy_domain_id=input.privacy_domain_id AND custody_root IS NOT NULL) THEN RETURN; END IF;
 SELECT * INTO STRICT s FROM control.runtime_artifact_source WHERE participant_id=input.participant_id
  AND privacy_domain_id=input.privacy_domain_id;
 IF s.database_role<>session_user OR NOT pg_has_role(session_user,'openpc_control_worker','USAGE')
  OR openpc.current_action_intent_id()<>'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1'
  OR current_setting('transaction_isolation')<>'read committed'
  OR current_setting('session_replication_role')<>'origin'
  OR coalesce(length(wire_text),0) NOT BETWEEN 2 AND 16384
  OR coalesce(nonce_text,'') !~ '^[0-9a-f]{64}$' OR coalesce(mac_text,'') !~ '^[0-9a-f]{64}$'
  OR wire_text !~ '^[0-9a-f]+$' OR length(wire_text)%2<>0
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 wire:=decode(wire_text,'hex'); nonce:=decode(nonce_text,'hex'); mac:=decode(mac_text,'hex');
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_artifact_source_verifier_key
  WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND source_owner_id=s.source_owner_id;
 expected:=public.hmac(convert_to('OPENPC_RUNTIME_ARTIFACT_SOURCE_IMPORT_V1'||pg_current_xact_id()::text
  ||encode(sha256(wire),'hex'),'UTF8')||nonce,secret,'sha256');
 FOR n IN 0..31 LOOP different:=different | (get_byte(expected,n) # get_byte(mac,n)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 document:=convert_from(wire,'UTF8')::jsonb;
 pending:=document->'pending'->'claims'; root:=document->'root'->'claims';
 installation:=jsonb_build_object('participant_id',s.participant_id::text,'privacy_domain_id',s.privacy_domain_id::text,
  'source_owner_id',s.source_owner_id::text,'source_file_binding',encode(s.source_file_binding,'hex'));
 IF document IS DISTINCT FROM jsonb_build_object('pending',document->'pending','root',document->'root')
  OR document->'pending'->>'purpose' IS DISTINCT FROM 'openpc:runtime-artifact-source-history:v1'
  OR document->'root'->>'purpose' IS DISTINCT FROM 'openpc:runtime-artifact-source-root:v1'
  OR pending->'installation' IS DISTINCT FROM installation OR root->'installation' IS DISTINCT FROM installation
  OR pending->'version' IS DISTINCT FROM '1'::jsonb OR root->'version' IS DISTINCT FROM '1'::jsonb
  OR root->'binding' IS DISTINCT FROM s.custody_root
  OR pending->'observation' IS DISTINCT FROM jsonb_build_object('ImportPending',jsonb_build_object(
   'input_id',input.runtime_configuration_input_id::text,'module_installation_id',input.module_installation_id::text,
   'module_configuration_generation_id',input.module_configuration_generation_id::text,
   'configuration_digest',encode(input.configuration_digest,'hex')))
  OR input.configuration_digest IS DISTINCT FROM sha256(input.configuration_cbor)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
END $$;
ALTER FUNCTION openpc.assert_runtime_artifact_source_import(control.runtime_configuration_input) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.assert_runtime_artifact_source_import(control.runtime_configuration_input) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_runtime_artifact_source_import(control.runtime_configuration_input) TO openpc_control_worker;
`;
