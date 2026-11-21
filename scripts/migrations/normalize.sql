-- Session-local canonicalization of ACL array order only. SQL definitions,
-- role identities, privilege bits and grant options remain significant.
CREATE OR REPLACE FUNCTION pg_temp.tegaris_catalog_canonical(value jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $canonical$
DECLARE result jsonb; source text; entry text; grantee text; privileges text;
 grantor text; normalized text; entries text[]:=ARRAY[]::text[];
BEGIN
 CASE jsonb_typeof(value)
 WHEN 'array' THEN
  SELECT coalesce(jsonb_agg(pg_temp.tegaris_catalog_canonical(v) ORDER BY ord),'[]'::jsonb)
   INTO result FROM jsonb_array_elements(value) WITH ORDINALITY a(v,ord);
  RETURN result;
 WHEN 'object' THEN
  SELECT coalesce(jsonb_object_agg(k,pg_temp.tegaris_catalog_canonical(v)),'{}'::jsonb)
   INTO result FROM jsonb_each(value) a(k,v);
  RETURN result;
 WHEN 'string' THEN
  source:=value#>>'{}';
  IF left(source,1)='{' AND right(source,1)='}' AND strpos(source,'=')>0 AND strpos(source,'/')>0 THEN
   FOREACH entry IN ARRAY string_to_array(substr(source,2,length(source)-2),',') LOOP
    grantee:=split_part(entry,'=',1); privileges:=split_part(split_part(entry,'=',2),'/',1);
    grantor:=split_part(split_part(entry,'=',2),'/',2);
    SELECT coalesce(string_agg(m[1],'' ORDER BY m[1] COLLATE "C"),'') INTO normalized
     FROM regexp_matches(privileges,'[A-Za-z]\*?','g') m;
    entries:=array_append(entries,grantee||'='||normalized||'/'||grantor);
   END LOOP;
   SELECT '{'||string_agg(v,',' ORDER BY v COLLATE "C")||'}' INTO source FROM unnest(entries) a(v);
   RETURN to_jsonb(source);
  END IF;
  RETURN value;
 ELSE RETURN value;
 END CASE;
END $canonical$;
