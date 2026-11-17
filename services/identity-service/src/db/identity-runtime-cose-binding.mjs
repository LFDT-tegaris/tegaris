// Structural cross-binding for already cryptographically verified identity
// evidence. Signature verification remains with the pinned identity verifier.
export const identityRuntimeCoseBindingSql = `
CREATE OR REPLACE FUNCTION openpc.identity_runtime_cose_key_id(evidence bytea,cose bytea)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE outer_item jsonb; fields jsonb; header jsonb; envelope jsonb; key_id text;
BEGIN
 IF octet_length(cose)=0 OR get_byte(cose,0)<>210 THEN RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-TAG'; END IF;
 outer_item:=openpc.business_cbor_item(cose,1,0);
 IF (outer_item->>'next')::integer<>octet_length(cose) THEN RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-TRAILING'; END IF;
 fields:=outer_item->'value';
 IF jsonb_typeof(fields) IS DISTINCT FROM 'array' OR jsonb_array_length(fields)<>4 OR
    fields->1 IS DISTINCT FROM '{}'::jsonb OR length(fields->3->>'bytes') IS DISTINCT FROM 128 THEN
  RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-BINDING'; END IF;
 envelope:=openpc.business_cbor(decode(fields->2->>'bytes','hex'));
 IF envelope IS DISTINCT FROM jsonb_build_object('0',1,'1',3002,'2',2,'3',openpc.business_cbor(evidence)) THEN
  RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-COSE-BINDING'; END IF;
 header:=openpc.business_cbor(decode(fields->0->>'bytes','hex'));
 IF header IS DISTINCT FROM jsonb_build_object('1',-8,'2',jsonb_build_array(100,101,102,103),'3','application/pc+cbor',
    '4',header->'4','100',3002,'101',2,'102','pc.cose.identity-runtime.v2','103',2) OR
    length(header->'4'->>'bytes') IS DISTINCT FROM 142 THEN
  RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-TYPED-PURPOSE-BINDING'; END IF;
 key_id:=convert_from(decode(header->'4'->>'bytes','hex'),'UTF8');
 IF key_id !~ '^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-KEY-ID'; END IF;
 RETURN key_id;
END $$;
`;
