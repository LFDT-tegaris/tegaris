/** Closed native attestation shape only. Actual original signatures, Control
 * qualification and the held Fact fence belong to the native issuer. Neither
 * these fields nor this function provide a Fact lease or serving authority. */
export const targetDispositionFactProofSql = `
CREATE OR REPLACE FUNCTION openpc.check_runtime_target_fact_proof(proof jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE custody jsonb;
BEGIN
 IF proof->>'sourceMode'='FACT_FREE' THEN
  IF proof ? 'factCustody' THEN RAISE EXCEPTION 'TARGET-DISPOSITION-FACT-PROOF'; END IF;
  RETURN;
 END IF;
 custody:=proof->'factCustody';
 IF proof->>'sourceMode' IS DISTINCT FROM 'FACT_BOUND'
  OR jsonb_typeof(custody) IS DISTINCT FROM 'object'
  OR custody IS DISTINCT FROM jsonb_build_object('version',1,'capsuleDigest',custody->'capsuleDigest',
   'factStateDigest',custody->'factStateDigest','dependencyDigest',custody->'dependencyDigest',
   'originalRecordsDigest',custody->'originalRecordsDigest','validUntilNs',custody->'validUntilNs')
  OR custody->'capsuleDigest' IS DISTINCT FROM proof->'capsuleDigest'
  OR EXISTS(SELECT 1 FROM (VALUES('capsuleDigest'),('factStateDigest'),('dependencyDigest'),('originalRecordsDigest')) f(name)
   WHERE jsonb_typeof(custody->f.name) IS DISTINCT FROM 'string' OR coalesce(custody->>f.name,'') !~ '^[0-9a-f]{64}$')
  OR jsonb_typeof(custody->'validUntilNs') IS DISTINCT FROM 'string'
  OR coalesce(custody->>'validUntilNs','') !~ '^[1-9][0-9]{0,19}$'
  OR jsonb_typeof(proof->'capsuleValidUntilNs') IS DISTINCT FROM 'string'
  OR coalesce(proof->>'capsuleValidUntilNs','') !~ '^[1-9][0-9]{0,19}$'
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-FACT-PROOF'; END IF;
 IF (custody->>'validUntilNs')::numeric>18446744073709551615
  OR (proof->>'capsuleValidUntilNs')::numeric>18446744073709551615
  OR (custody->>'validUntilNs')::numeric<=extract(epoch from clock_timestamp())*1000000000
  OR (custody->>'validUntilNs')::numeric>(proof->>'capsuleValidUntilNs')::numeric
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-FACT-EXPIRY'; END IF;
END $$;
ALTER FUNCTION openpc.check_runtime_target_fact_proof(jsonb) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.check_runtime_target_fact_proof(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.check_runtime_target_fact_proof(jsonb) TO openpc_control_worker;
`;
