-- Generated from configuration/operations/source-authentication-guards.mjs.
CREATE OR REPLACE FUNCTION openpc.operations_source_authentication_valid(p_installation jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE custody jsonb; selected jsonb; profile_name text; manifest jsonb; entry jsonb;
 schema_bytes bytea; profile_bytes bytea; manifest_bytes bytea;
 profiles CONSTANT jsonb := '{"local":{"path":"SPECIFICATIONS/OPERATIONS/profiles/local.yaml","digest":"sha256:aad2b9f62d1659cec987be45b5e2e7c8d504a706f8583819675118bef14eaa0c","bytes":3014,"canonicalDigest":"sha256:deaa78277144b603295fb75bc2aaf21e8400504aa67680e83981c01822ca2d9a"},"development":{"path":"SPECIFICATIONS/OPERATIONS/profiles/development.yaml","digest":"sha256:e20a644061a759c38d2c09d29a74adb43c8cc683da852a33ade726b4ae5f989f","bytes":3122,"canonicalDigest":"sha256:50bdcd6777e07c9a6cc688c54bf5d14962fbec68f7ccb2fe94854d7b978e94f5"},"test":{"path":"SPECIFICATIONS/OPERATIONS/profiles/test.yaml","digest":"sha256:fc48ee6b68c13821f0fd5b88222629851ad30a21027c69c9cd4a968a301f3c37","bytes":3121,"canonicalDigest":"sha256:e7bf9922e9141cd358f28d79b0cbc70e553e0998c296f610e09a3e846a613997"},"staging":{"path":"SPECIFICATIONS/OPERATIONS/profiles/staging.yaml","digest":"sha256:386955e70c3eb1af05f926fb6385ef523cb96a2b1ac4624f3b8cbbb8a09d252b","bytes":3026,"canonicalDigest":"sha256:8c8c997bd3a2292713973595fbdefedfef01c9a38292da366be7caa48d859d95"},"production":{"path":"SPECIFICATIONS/OPERATIONS/profiles/production.yaml","digest":"sha256:53bd65338e2e8d1334d4ecb3519769ce32a8e706e683f731a0d27263a9d2902a","bytes":3134,"canonicalDigest":"sha256:493d8802e490ce0d088f5c4c119f434a7267c15075dc777e48937c4503649f71"}}'::jsonb;
 public_profiles CONSTANT jsonb := '{"local":{"path":"config/profiles/local.yaml","digest":"sha256:aad2b9f62d1659cec987be45b5e2e7c8d504a706f8583819675118bef14eaa0c","bytes":3014,"canonicalDigest":"sha256:deaa78277144b603295fb75bc2aaf21e8400504aa67680e83981c01822ca2d9a"},"development":{"path":"config/profiles/development.yaml","digest":"sha256:e20a644061a759c38d2c09d29a74adb43c8cc683da852a33ade726b4ae5f989f","bytes":3122,"canonicalDigest":"sha256:50bdcd6777e07c9a6cc688c54bf5d14962fbec68f7ccb2fe94854d7b978e94f5"},"test":{"path":"config/profiles/test.yaml","digest":"sha256:fc48ee6b68c13821f0fd5b88222629851ad30a21027c69c9cd4a968a301f3c37","bytes":3121,"canonicalDigest":"sha256:e7bf9922e9141cd358f28d79b0cbc70e553e0998c296f610e09a3e846a613997"},"staging":{"path":"config/profiles/staging.yaml","digest":"sha256:386955e70c3eb1af05f926fb6385ef523cb96a2b1ac4624f3b8cbbb8a09d252b","bytes":3026,"canonicalDigest":"sha256:8c8c997bd3a2292713973595fbdefedfef01c9a38292da366be7caa48d859d95"},"production":{"path":"config/profiles/production.yaml","digest":"sha256:53bd65338e2e8d1334d4ecb3519769ce32a8e706e683f731a0d27263a9d2902a","bytes":3134,"canonicalDigest":"sha256:493d8802e490ce0d088f5c4c119f434a7267c15075dc777e48937c4503649f71"}}'::jsonb;
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
   OR custody->>'sourceProfile' IS DISTINCT FROM 'PUBLIC_OPERATIONS_SOURCE_V1'
   OR jsonb_typeof(custody->'inventoryHex') IS DISTINCT FROM 'string'
   OR jsonb_typeof(custody->'schemaHex') IS DISTINCT FROM 'string'
   OR jsonb_typeof(custody->'profileHex') IS DISTINCT FROM 'string'
  THEN RETURN false; END IF;
  IF length(custody->>'inventoryHex')<>2378
   OR length(custody->>'schemaHex')<>93796
   OR length(custody->>'profileHex')<>(selected->>'bytes')::integer*2
   OR custody->>'inventoryHex' !~ '^[0-9a-f]+$'
   OR custody->>'schemaHex' !~ '^[0-9a-f]+$'
   OR custody->>'profileHex' !~ '^[0-9a-f]+$'
  THEN RETURN false; END IF;
  manifest_bytes:=decode(custody->>'inventoryHex','hex');
  schema_bytes:=decode(custody->>'schemaHex','hex');
  profile_bytes:=decode(custody->>'profileHex','hex');
  IF 'sha256:'||encode(sha256(manifest_bytes),'hex') IS DISTINCT FROM 'sha256:e467be325380375f53f5ae7a91cb56c24c2dbe02c383156aed97ffa8350547e6'
   OR 'sha256:'||encode(sha256(schema_bytes),'hex') IS DISTINCT FROM 'sha256:350280220fae0d2fb0c360cb1c5a9011e8c46218e7b10b9a269fba78078496cd'
   OR 'sha256:'||encode(sha256(profile_bytes),'hex') IS DISTINCT FROM selected->>'digest'
  THEN RETURN false; END IF;
  manifest:=convert_from(manifest_bytes,'UTF8')::jsonb;
  IF manifest->>'schema' IS DISTINCT FROM 'pc.operations.public-source-inventory'
   OR manifest->'schemaVersion' IS DISTINCT FROM '1'::jsonb
   OR manifest->>'sourceProfile' IS DISTINCT FROM 'PUBLIC_OPERATIONS_SOURCE_V1'
   OR jsonb_typeof(manifest->'files') IS DISTINCT FROM 'array'
   OR jsonb_array_length(manifest->'files')<>6
  THEN RETURN false; END IF;
  IF (SELECT count(*) FROM jsonb_array_elements(manifest->'files') f
   WHERE f->>'path'='config/schema/effective-configuration.schema.json' AND f->>'digest'='sha256:350280220fae0d2fb0c360cb1c5a9011e8c46218e7b10b9a269fba78078496cd'
    AND f->'bytes'='46898'::jsonb)<>1
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
  OR custody->>'receiptId' IS DISTINCT FROM 'OPENPC-C17-FINAL-DELIVERY-20260827-01'
  OR custody->>'archiveDigest' IS DISTINCT FROM 'sha256:36242402f8ace4b1cff124385b0be45e8e2a2c1fed9ceb980be2644052309ed5'
  OR jsonb_typeof(custody->'manifestHex') IS DISTINCT FROM 'string'
  OR jsonb_typeof(custody->'schemaHex') IS DISTINCT FROM 'string'
  OR jsonb_typeof(custody->'profileHex') IS DISTINCT FROM 'string'
 THEN RETURN false; END IF;
 -- Bound before decoding. The independently pinned archive manifest, not a
 -- self-consistent caller digest pair, supplies exact original membership.
 IF length(custody->>'manifestHex')<>296548
  OR length(custody->>'schemaHex')<>93796
  OR length(custody->>'profileHex')<>(selected->>'bytes')::integer*2
  OR custody->>'manifestHex' !~ '^[0-9a-f]+$'
  OR custody->>'schemaHex' !~ '^[0-9a-f]+$'
  OR custody->>'profileHex' !~ '^[0-9a-f]+$'
 THEN RETURN false; END IF;
 manifest_bytes:=decode(custody->>'manifestHex','hex');
 schema_bytes:=decode(custody->>'schemaHex','hex');
 profile_bytes:=decode(custody->>'profileHex','hex');
 IF 'sha256:'||encode(sha256(manifest_bytes),'hex') IS DISTINCT FROM 'sha256:39800a6f39f3b989f9230844404099d44908c3bfa31d442964c9d947f7885609'
  OR 'sha256:'||encode(sha256(schema_bytes),'hex') IS DISTINCT FROM 'sha256:350280220fae0d2fb0c360cb1c5a9011e8c46218e7b10b9a269fba78078496cd'
  OR 'sha256:'||encode(sha256(profile_bytes),'hex') IS DISTINCT FROM selected->>'digest'
 THEN RETURN false; END IF;
 manifest:=convert_from(manifest_bytes,'UTF8')::jsonb;
 IF manifest->>'packageId' IS DISTINCT FROM 'OPENPC-C17-RECEIVING-AUTHORITY-COHERENCE-20260827-01' THEN RETURN false; END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(manifest->'files') f
  WHERE f->>'path'='SPECIFICATIONS/OPERATIONS/configuration.schema.json' AND f->>'class'='NORMATIVE_MACHINE_CONTRACT'
   AND f->>'sha256'='350280220fae0d2fb0c360cb1c5a9011e8c46218e7b10b9a269fba78078496cd' AND f->'bytes'='46898'::jsonb)<>1
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
 IF p_installation->'pins'->>'configurationSchemaDigest' IS DISTINCT FROM 'sha256:350280220fae0d2fb0c360cb1c5a9011e8c46218e7b10b9a269fba78078496cd'
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
