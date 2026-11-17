/** Database-side structural decoding for typed receipt/trust bindings. Never verifies authority. */
export const businessCborSql = `
CREATE OR REPLACE FUNCTION openpc.business_cbor_item(data bytea, byte_offset integer, depth integer DEFAULT 0)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE
  initial integer; major integer; additional integer; width integer; cursor integer;
  argument numeric := 0; value jsonb; child jsonb; key_item jsonb; key_number numeric;
  previous_key numeric := -1; i integer; bytes bytea; decoded text;
BEGIN
  IF octet_length(data)>66560 OR byte_offset<0 OR byte_offset>=octet_length(data) OR depth>8 THEN
    RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR';
  END IF;
  initial:=get_byte(data,byte_offset); major:=initial/32; additional:=initial%32; cursor:=byte_offset+1;
  IF additional<24 THEN argument:=additional;
  ELSE
    width:=CASE additional WHEN 24 THEN 1 WHEN 25 THEN 2 WHEN 26 THEN 4 WHEN 27 THEN 8 ELSE 0 END;
    IF width=0 OR cursor+width>octet_length(data) THEN RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR'; END IF;
    FOR i IN 0..width-1 LOOP argument:=argument*256+get_byte(data,cursor+i); END LOOP;
    cursor:=cursor+width;
    IF (width=1 AND argument<24) OR (width=2 AND argument<=255) OR
       (width=4 AND argument<=65535) OR (width=8 AND argument<=4294967295) THEN
      RAISE EXCEPTION 'DATA-6021-NONCANONICAL-BUSINESS-CBOR';
    END IF;
  END IF;
  CASE major
    WHEN 0 THEN value:=to_jsonb(argument);
    WHEN 1 THEN value:=to_jsonb(-1-argument);
    WHEN 2,3 THEN
      IF argument>65536 OR cursor+argument>octet_length(data) THEN RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR'; END IF;
      bytes:=substring(data FROM cursor+1 FOR argument::integer); cursor:=cursor+argument::integer;
      IF major=2 THEN value:=jsonb_build_object('bytes',encode(bytes,'hex'));
      ELSE
        decoded:=convert_from(bytes,'UTF8');
        IF normalize(decoded,NFC)<>decoded OR convert_to(decoded,'UTF8')<>bytes THEN
          RAISE EXCEPTION 'DATA-6021-NONCANONICAL-BUSINESS-CBOR';
        END IF;
        value:=to_jsonb(decoded);
      END IF;
    WHEN 4 THEN
      IF argument>256 THEN RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR'; END IF;
      value:='[]'::jsonb;
      FOR i IN 1..argument::integer LOOP
        child:=openpc.business_cbor_item(data,cursor,depth+1);
        value:=value||jsonb_build_array(child->'value'); cursor:=(child->>'next')::integer;
      END LOOP;
    WHEN 5 THEN
      IF argument>256 THEN RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR'; END IF;
      value:='{}'::jsonb;
      FOR i IN 1..argument::integer LOOP
        IF cursor>=octet_length(data) OR get_byte(data,cursor)/32<>0 THEN
          RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR-MAP-KEY';
        END IF;
        key_item:=openpc.business_cbor_item(data,cursor,depth+1); key_number:=(key_item->>'value')::numeric;
        IF key_number<=previous_key OR key_number>4294967295 THEN RAISE EXCEPTION 'DATA-6021-NONCANONICAL-BUSINESS-CBOR-MAP'; END IF;
        previous_key:=key_number; cursor:=(key_item->>'next')::integer;
        child:=openpc.business_cbor_item(data,cursor,depth+1);
        value:=value||jsonb_build_object(key_number::text,child->'value'); cursor:=(child->>'next')::integer;
      END LOOP;
    ELSE RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR-TYPE';
  END CASE;
  RETURN jsonb_build_object('value',value,'next',cursor);
END $$;
CREATE OR REPLACE FUNCTION openpc.business_cbor(data bytea)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE decoded jsonb;
BEGIN
  IF octet_length(data)>65536 THEN RAISE EXCEPTION 'DATA-6021-INVALID-BUSINESS-CBOR'; END IF;
  decoded:=openpc.business_cbor_item(data,0,0);
  IF (decoded->>'next')::integer<>octet_length(data) THEN RAISE EXCEPTION 'DATA-6021-TRAILING-BUSINESS-CBOR'; END IF;
  RETURN decoded->'value';
END $$;
CREATE OR REPLACE FUNCTION openpc.business_bytes(data bytea)
RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('bytes',encode(data,'hex'))
$$;
CREATE OR REPLACE FUNCTION openpc.business_uuid(id uuid)
RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
 SELECT openpc.business_bytes(uuid_send(id))
$$;

CREATE OR REPLACE FUNCTION openpc.business_request_digest(binding text[])
RETURNS bytea LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE preimage bytea:=convert_to('pc.control.configuration-request.v1','UTF8')||decode('00','hex'); value text; bytes bytea;
BEGIN
 IF cardinality(binding)<>10 THEN RAISE EXCEPTION 'DATA-6021-REQUEST-BINDING'; END IF;
 FOREACH value IN ARRAY binding LOOP
  IF value IS NULL OR octet_length(value) NOT BETWEEN 1 AND 256 OR normalize(value,NFC)<>value THEN
    RAISE EXCEPTION 'DATA-6021-REQUEST-BINDING'; END IF;
  bytes:=convert_to(value,'UTF8');preimage:=preimage||int4send(octet_length(bytes))||bytes;
 END LOOP;
 RETURN sha256(preimage);
END $$;
`;
