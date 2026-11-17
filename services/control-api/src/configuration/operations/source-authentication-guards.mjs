import {
  operationsSourceAnchor as anchor,
  operationsSourceProfiles as profiles,
  publicOperationsSourceAnchor as publicAnchor,
  publicOperationsSourceProfiles as publicProfiles,
} from '../../../../../scripts/operations/installation-source-authentication.mjs';

// Canonical registration calls this before operations_generation_missing is
// replaced. This adds no table, writer, receipt family or generic binding grant.
// Installation custody is the closed PRIVATE installation.sourceAuthentication
// object returned by authenticateOperationsSources, stored before first staging.
export const operationsSourceAuthenticationGuardsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.operations_source_authentication_valid(p_installation jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE custody jsonb; selected jsonb; profile_name text; manifest jsonb; entry jsonb;
 schema_bytes bytea; profile_bytes bytea; manifest_bytes bytea;
 profiles CONSTANT jsonb := '${JSON.stringify(profiles).replaceAll("'", "''")}'::jsonb;
 public_profiles CONSTANT jsonb := '${JSON.stringify(publicProfiles).replaceAll("'", "''")}'::jsonb;
BEGIN
 IF jsonb_typeof(p_installation) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 -- Materialize the same JSONB object once for this call's repeated field reads.
 p_installation := p_installation #> '{}'::text[];
 custody:=p_installation->'sourceAuthentication';
 profile_name:=p_installation->'pins'->>'profile'; selected:=profiles->profile_name;
 IF selected IS NULL OR jsonb_typeof(custody) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 IF custody->'version'='2'::jsonb THEN
  selected:=public_profiles->profile_name;
  IF selected IS NULL OR (SELECT count(*) FROM jsonb_object_keys(custody))<>5
   OR NOT custody ?& ARRAY['version','sourceProfile','inventoryHex','schemaHex','profileHex']
   OR custody->>'sourceProfile' IS DISTINCT FROM '${publicAnchor.sourceProfile}'
   OR jsonb_typeof(custody->'inventoryHex') IS DISTINCT FROM 'string'
   OR jsonb_typeof(custody->'schemaHex') IS DISTINCT FROM 'string'
   OR jsonb_typeof(custody->'profileHex') IS DISTINCT FROM 'string'
  THEN RETURN false; END IF;
  IF length(custody->>'inventoryHex')<>${publicAnchor.inventoryBytes * 2}
   OR length(custody->>'schemaHex')<>${publicAnchor.schemaBytes * 2}
   OR length(custody->>'profileHex')<>(selected->>'bytes')::integer*2
   OR custody->>'inventoryHex' !~ '^[0-9a-f]+$'
   OR custody->>'schemaHex' !~ '^[0-9a-f]+$'
   OR custody->>'profileHex' !~ '^[0-9a-f]+$'
  THEN RETURN false; END IF;
  manifest_bytes:=decode(custody->>'inventoryHex','hex');
  schema_bytes:=decode(custody->>'schemaHex','hex');
  profile_bytes:=decode(custody->>'profileHex','hex');
  IF 'sha256:'||encode(sha256(manifest_bytes),'hex') IS DISTINCT FROM '${publicAnchor.inventoryDigest}'
   OR 'sha256:'||encode(sha256(schema_bytes),'hex') IS DISTINCT FROM '${publicAnchor.schemaDigest}'
   OR 'sha256:'||encode(sha256(profile_bytes),'hex') IS DISTINCT FROM selected->>'digest'
  THEN RETURN false; END IF;
  manifest:=convert_from(manifest_bytes,'UTF8')::jsonb;
  IF manifest->>'schema' IS DISTINCT FROM 'pc.operations.public-source-inventory'
   OR manifest->'schemaVersion' IS DISTINCT FROM '1'::jsonb
   OR manifest->>'sourceProfile' IS DISTINCT FROM '${publicAnchor.sourceProfile}'
   OR jsonb_typeof(manifest->'files') IS DISTINCT FROM 'array'
   OR jsonb_array_length(manifest->'files')<>6
  THEN RETURN false; END IF;
  IF (SELECT count(*) FROM jsonb_array_elements(manifest->'files') f
   WHERE f->>'path'='${publicAnchor.schemaPath}' AND f->>'digest'='${publicAnchor.schemaDigest}'
    AND f->'bytes'='${publicAnchor.schemaBytes}'::jsonb)<>1
  THEN RETURN false; END IF;
  FOR entry IN SELECT value FROM jsonb_each(public_profiles) LOOP
   IF (SELECT count(*) FROM jsonb_array_elements(manifest->'files') f
    WHERE f->>'path'=entry->>'path' AND f->>'digest'=entry->>'digest'
     AND f->'bytes'=entry->'bytes')<>1
   THEN RETURN false; END IF;
  END LOOP;
 ELSE
 IF (SELECT count(*) FROM jsonb_object_keys(custody))<>6
  OR NOT custody ?& ARRAY['version','receiptId','archiveDigest','manifestHex','schemaHex','profileHex']
  OR custody->'version' IS DISTINCT FROM '1'::jsonb
  OR custody->>'receiptId' IS DISTINCT FROM '${anchor.receiptId}'
  OR custody->>'archiveDigest' IS DISTINCT FROM '${anchor.archiveDigest}'
  OR jsonb_typeof(custody->'manifestHex') IS DISTINCT FROM 'string'
  OR jsonb_typeof(custody->'schemaHex') IS DISTINCT FROM 'string'
  OR jsonb_typeof(custody->'profileHex') IS DISTINCT FROM 'string'
 THEN RETURN false; END IF;
 -- Bound before decoding. The independently pinned archive manifest, not a
 -- self-consistent caller digest pair, supplies exact original membership.
 IF length(custody->>'manifestHex')<>${anchor.manifestBytes * 2}
  OR length(custody->>'schemaHex')<>${anchor.schemaBytes * 2}
  OR length(custody->>'profileHex')<>(selected->>'bytes')::integer*2
  OR custody->>'manifestHex' !~ '^[0-9a-f]+$'
  OR custody->>'schemaHex' !~ '^[0-9a-f]+$'
  OR custody->>'profileHex' !~ '^[0-9a-f]+$'
 THEN RETURN false; END IF;
 manifest_bytes:=decode(custody->>'manifestHex','hex');
 schema_bytes:=decode(custody->>'schemaHex','hex');
 profile_bytes:=decode(custody->>'profileHex','hex');
 IF 'sha256:'||encode(sha256(manifest_bytes),'hex') IS DISTINCT FROM '${anchor.manifestDigest}'
  OR 'sha256:'||encode(sha256(schema_bytes),'hex') IS DISTINCT FROM '${anchor.schemaDigest}'
  OR 'sha256:'||encode(sha256(profile_bytes),'hex') IS DISTINCT FROM selected->>'digest'
 THEN RETURN false; END IF;
 manifest:=convert_from(manifest_bytes,'UTF8')::jsonb;
 IF manifest->>'packageId' IS DISTINCT FROM '${anchor.packageId}' THEN RETURN false; END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(manifest->'files') f
  WHERE f->>'path'='${anchor.schemaPath}' AND f->>'class'='NORMATIVE_MACHINE_CONTRACT'
   AND f->>'sha256'='${anchor.schemaDigest.slice(7)}' AND f->'bytes'='${anchor.schemaBytes}'::jsonb)<>1
 THEN RETURN false; END IF;
 FOR entry IN SELECT value FROM jsonb_each(profiles) LOOP
  IF (SELECT count(*) FROM jsonb_array_elements(manifest->'files') f
   WHERE f->>'path'=entry->>'path' AND f->>'class'='NORMATIVE_MACHINE_CONTRACT'
    AND f->>'sha256'=substring(entry->>'digest' from 8) AND f->'bytes'=entry->'bytes')<>1
  THEN RETURN false; END IF;
 END LOOP;
 END IF;
 -- Pins alone do not authenticate a changed parsed installation. JSON schema
 -- is parsed from the authenticated bytes; YAML uses its independently derived
 -- canonical parsed identity, from the same accepted all-five source mapping.
 IF p_installation->'pins'->>'configurationSchemaDigest' IS DISTINCT FROM '${anchor.schemaDigest}'
  OR p_installation->'pins'->>'namedProfileDigest' IS DISTINCT FROM selected->>'digest'
  OR p_installation->'schema' IS DISTINCT FROM convert_from(schema_bytes,'UTF8')::jsonb
  OR p_installation->'namedProfile'->>'profile' IS DISTINCT FROM profile_name
  OR 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p_installation->'namedProfile'),'UTF8')),'hex')
     IS DISTINCT FROM selected->>'canonicalDigest'
 THEN RETURN false; END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION openpc.operations_source_authentication_valid(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.operations_source_authentication_valid(jsonb) TO openpc_control_owner;

-- This is the ONLY generation-facing source predicate. The JSON verifier above
-- verifies data, not installation authority. Read actual RLS-scoped immutable
-- rows, under the same existing generation transaction/lock owner.
CREATE OR REPLACE FUNCTION openpc.operations_generation_source_authenticated(p_environment text,p_generation uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE installed control.operations_installation%ROWTYPE; candidate control.operations_generation%ROWTYPE;
BEGIN
 PERFORM openpc.assert_request_context(true);
 -- Source truth is also consumed by existing SECURITY DEFINER read owners
 -- (for example current_notification_delivery_limit). Do not require their
 -- current role/action to equal an installation mutation's role/action. EXECUTE
 -- grants, request scope and actual rows remain enforced; commit admission is
 -- still a separate guarded operation on its own same transaction client.
 IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR current_setting('row_security') IS DISTINCT FROM 'on'
  OR current_setting('openpc.context_mode',true) IS DISTINCT FROM 'PARTICIPANT'
 THEN RETURN false; END IF;
 SELECT * INTO installed FROM control.operations_installation WHERE environment_id=p_environment;
 SELECT * INTO candidate FROM control.operations_generation WHERE environment_id=p_environment AND generation_id=p_generation;
 IF installed.environment_id IS NULL OR candidate.generation_id IS NULL
  OR installed.state<>'ACTIVE' OR candidate.state<>'STAGED'
  OR installed.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR installed.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR candidate.participant_id IS DISTINCT FROM installed.participant_id
  OR candidate.privacy_domain_id IS DISTINCT FROM installed.privacy_domain_id
  OR installed.installation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(installed.installation_bytes),'hex')
  OR installed.installation IS DISTINCT FROM convert_from(installed.installation_bytes,'UTF8')::jsonb
  OR installed.installation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(installed.installation),'UTF8')
  OR installed.installation->'pins'->>'environmentId' IS DISTINCT FROM p_environment
  OR candidate.candidate_digest IS DISTINCT FROM 'sha256:'||encode(sha256(candidate.candidate_bytes),'hex')
  OR candidate.candidate IS DISTINCT FROM convert_from(candidate.candidate_bytes,'UTF8')::jsonb
  OR candidate.candidate_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(candidate.candidate),'UTF8')
  OR candidate.candidate->'configuration'->>'environmentId' IS DISTINCT FROM p_environment
  OR candidate.candidate->'configuration'->>'profile' IS DISTINCT FROM installed.installation->'pins'->>'profile'
  OR candidate.candidate->'configuration'->'generation'->>'generationId' IS DISTINCT FROM 'urn:openpc:generation:'||p_generation::text
  OR candidate.candidate->'configuration'->'generation'->>'baseGenerationId' IS DISTINCT FROM 'urn:openpc:generation:'||candidate.base_generation_id::text
 THEN RETURN false; END IF;
 RETURN openpc.operations_source_authentication_valid(installed.installation);
END $$;
REVOKE ALL ON FUNCTION openpc.operations_generation_source_authenticated(text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.operations_generation_source_authenticated(text,uuid) TO openpc_control_owner;
`;
