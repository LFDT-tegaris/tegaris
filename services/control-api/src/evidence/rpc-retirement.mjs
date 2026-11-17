/** Completion of a local read is not chain finality. V1 RELEASED is produced
 * only by the protected read-response path (Broker rejects writes); source
 * reads have their separate release owner. Operation-status observations do
 * not settle the referenced operation, and WRITE_AMBIGUITY is never terminal.
 * The witness retains only the minimum needed to retire earlier transitions,
 * not a replacement normalized projection or serving/replay authority. */
export const rpcRetirementSql = `
CREATE OR REPLACE FUNCTION openpc.rpc_retirement_identity(p jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_array(
  p->'decisionId',p->'targetRuntimeId',p->'spoolId',p->'capsuleDigest',p->'reservedAtNs',
  p->'transition'->'requestDigest',p->'activation')),'UTF8')),'hex')
$$;
CREATE OR REPLACE FUNCTION openpc.rpc_retirement_terminal(p jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT coalesce(p->'transition'->>'phase' IN ('INTERRUPTED','RELEASED','SOURCE_READ_RELEASED')
  OR (p->'transition'->>'phase'='COMMITTED' AND p->'transition'->>'decisionEffect'
   IN ('DENY_TERMINAL','AUTHORIZED_EMPTY','WITHHOLD_STALE')),false)
$$;
CREATE OR REPLACE FUNCTION openpc.rpc_retirement_witness(c control.evidence_catalogue,p jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('identityDigest',openpc.rpc_retirement_identity(p),
  'terminalEvidenceId','urn:openpc:resource:'||(c).evidence_id::text,'terminalRecordId',(c).record_id,
  'terminalSequence',(c).sequence::text,'terminalSourceDigest',(c).receipt_digest,
  'terminalProjectionDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex'),
  'terminalOccurredAtNs',p->'occurredAtNs','terminalPhase',p->'transition'->'phase',
  'terminalEffect',p->'transition'->'decisionEffect','terminalDecisionDigest',p->'transition'->'decisionDigest',
  'sourceScopeDigest',p->'transition'->'sourceScopeDigest','authorityBindingDigest',p->'transition'->'authorityBindingDigest')
$$;
CREATE OR REPLACE FUNCTION openpc.rpc_projection_closed_by(p jsonb,w jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT coalesce(w->>'identityDigest'=openpc.rpc_retirement_identity(p)
  AND (w->>'terminalSequence')::numeric>=(p->>'sourceSequence')::numeric
  AND (w->>'terminalOccurredAtNs')::numeric>=(p->>'occurredAtNs')::numeric
  AND CASE p->'transition'->>'phase'
   WHEN 'RESERVED' THEN w->>'terminalPhase' IN ('INTERRUPTED','RELEASED')
    OR (w->>'terminalPhase'='COMMITTED' AND w->>'terminalEffect' IN ('DENY_TERMINAL','AUTHORIZED_EMPTY','WITHHOLD_STALE'))
   WHEN 'SOURCE_READ_STARTED' THEN w->>'terminalPhase'='SOURCE_READ_RELEASED'
    AND w->'sourceScopeDigest'=p->'transition'->'sourceScopeDigest'
    AND w->'authorityBindingDigest'=p->'transition'->'authorityBindingDigest'
   WHEN 'COMMITTED' THEN CASE WHEN p->'transition'->>'decisionEffect'='ALLOW_FORWARD'
    THEN w->>'terminalPhase'='RELEASED' AND w->'terminalDecisionDigest'=p->'transition'->'decisionDigest'
    ELSE openpc.rpc_retirement_terminal(p) AND w->>'terminalSourceDigest'=p->>'sourceDigest'
     AND w->>'terminalPhase'=p->'transition'->>'phase' AND w->'terminalEffect'=p->'transition'->'decisionEffect'
     AND w->>'terminalSequence'=p->>'sourceSequence'
     AND w->>'terminalProjectionDigest'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex') END
   ELSE openpc.rpc_retirement_terminal(p) AND w->>'terminalSourceDigest'=p->>'sourceDigest'
    AND w->>'terminalPhase'=p->'transition'->>'phase' AND w->>'terminalSequence'=p->>'sourceSequence'
    AND w->>'terminalProjectionDigest'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex') END,false)
$$;
CREATE OR REPLACE FUNCTION openpc.rpc_projection_retirement_witness(c control.evidence_catalogue,p jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE witnesses jsonb;
BEGIN
 -- Custody authenticates the contiguous original journal. Both live witnesses
 -- and intentionally retired witnesses retain the original catalogue anchor.
 -- A missing/corrupt projection cannot masquerade as a successful retirement.
 SELECT jsonb_agg(DISTINCT witness) INTO witnesses FROM (
  SELECT openpc.rpc_retirement_witness(s,r.projection) witness
   FROM control.evidence_rpc_provenance r JOIN control.evidence_catalogue s USING(participant_id,privacy_domain_id,stream_id,record_id)
   WHERE r.participant_id=(c).participant_id AND r.privacy_domain_id=(c).privacy_domain_id AND r.stream_id=(c).stream_id
    AND r.projection->>'decisionId'=p->>'decisionId' AND openpc.rpc_retirement_terminal(r.projection)
    AND r.projection->>'sourceSequence'=s.sequence::text AND r.projection->>'sourceDigest'=s.receipt_digest
    AND s.source_format='OPENPC_RPC_DECISION_TRANSITION_V1'
    AND r.projection_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(r.projection),'UTF8')),'hex')
  UNION ALL
  SELECT (j.selection->'rpcClosure')-'archive' FROM control.evidence_projection_retirement r
   JOIN control.deletion_job j USING(participant_id,privacy_domain_id,deletion_job_id)
   JOIN control.evidence_catalogue s ON s.participant_id=r.participant_id AND s.privacy_domain_id=r.privacy_domain_id
    AND s.stream_id=r.stream_id AND s.record_id=r.record_id
   WHERE r.participant_id=(c).participant_id AND r.privacy_domain_id=(c).privacy_domain_id AND r.stream_id=(c).stream_id
    AND r.data_class='NORMALIZED_JSON_PROJECTION' AND j.state='SUCCEEDED'
    AND j.selection->>'sourceKind'='RPC_CLOSED_TRANSITION'
    AND j.selection->'rpcClosure'->>'terminalRecordId'=r.record_id
    AND j.selection->'rpcClosure'->>'terminalSourceDigest'=r.source_receipt_digest AND s.receipt_digest=r.source_receipt_digest
    AND j.selection->'rpcClosure'->>'terminalProjectionDigest'=r.projection_digest
    AND r.retirement_digest=openpc.projection_retirement_digest(r)
 ) candidates WHERE openpc.rpc_projection_closed_by(p,witness);
 IF jsonb_array_length(witnesses)<>1 THEN RETURN NULL; END IF;
 RETURN witnesses->0;
END $$;
REVOKE ALL ON FUNCTION openpc.rpc_retirement_identity(jsonb),openpc.rpc_retirement_terminal(jsonb),
 openpc.rpc_retirement_witness(control.evidence_catalogue,jsonb),openpc.rpc_projection_closed_by(jsonb,jsonb),
 openpc.rpc_projection_retirement_witness(control.evidence_catalogue,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.rpc_retirement_identity(jsonb),openpc.rpc_retirement_terminal(jsonb),
 openpc.rpc_retirement_witness(control.evidence_catalogue,jsonb),openpc.rpc_projection_closed_by(jsonb,jsonb),
 openpc.rpc_projection_retirement_witness(control.evidence_catalogue,jsonb) TO openpc_control_runtime,openpc_control_reader;
`;
