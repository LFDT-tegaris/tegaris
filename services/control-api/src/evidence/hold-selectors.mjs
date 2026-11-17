/** Canonical selector validation and matching belong to the preservation owner.
 * A NULL match is missing source knowledge, never permission to delete. */
export const evidenceHoldSelectorsSql = `
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
`;
