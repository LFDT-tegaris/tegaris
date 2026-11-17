/** Cross-database cryptography and identity binding execute in the existing
 * Fact reader before custody. This guard enforces the independent Control
 * catalogue/scope/shape binding; it cannot confer current Fact readiness. */
export const factProvenanceGuardsSql = `
ALTER TABLE control.evidence_fact_provenance FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_fact_provenance FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_fact_provenance TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT INSERT ON control.evidence_fact_provenance TO openpc_control_worker;
CREATE OR REPLACE FUNCTION openpc.guard_evidence_fact_provenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb:=NEW.projection; l jsonb:=p->'lineage'; field text; deleted_source control.evidence_catalogue;
 resource_pattern text:='^urn:openpc:fact:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT deleted_source FROM control.evidence_catalogue WHERE participant_id=OLD.participant_id AND privacy_domain_id=OLD.privacy_domain_id
   AND stream_id=OLD.stream_id AND record_id=OLD.record_id;
  PERFORM openpc.record_projection_deletion(deleted_source,'NORMALIZED_JSON_PROJECTION',OLD.projection);RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 IF EXISTS(SELECT 1 FROM control.evidence_projection_retirement r WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
  AND r.data_class='NORMALIZED_JSON_PROJECTION' AND r.stream_id=NEW.stream_id AND r.record_id=NEW.record_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR jsonb_typeof(l) IS DISTINCT FROM 'object'
  OR p-ARRAY['candidateId','sourceSequence','receiptDigest','admittedAt','lineage','integrity','authority','currentReadiness','sourceProfileId','verificationKeyId','verificationKeyDigest']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(p))<>11
  OR l-ARRAY['factId','factDigest','factType','factProfileId','factKeyDigest','canonicalGeneration','projectionId','chainId','genesisDigest','blockNumber','blockHash','predecessorDigest','relationshipPredecessorDigest','reorgReplacementOf']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(l))<>14
  OR EXISTS(SELECT 1 FROM jsonb_each(p) e WHERE e.key<>'lineage' AND jsonb_typeof(e.value)<>'string')
  OR EXISTS(SELECT 1 FROM jsonb_each(l) e WHERE jsonb_typeof(e.value)<>'string'
   AND NOT(e.key IN ('predecessorDigest','relationshipPredecessorDigest','reorgReplacementOf') AND e.value='null'::jsonb))
  OR p->>'integrity' IS DISTINCT FROM 'FACT_COSE_VERIFIED_AT_CUSTODY'
  OR p->>'authority' IS DISTINCT FROM 'NONE' OR p->>'currentReadiness' IS DISTINCT FROM 'NOT_ESTABLISHED'
  OR coalesce(l->>'factId','')!~resource_pattern
  OR coalesce('urn:openpc:fact:'||(p->>'candidateId'),'')!~resource_pattern
  OR coalesce('urn:openpc:fact:'||(p->>'sourceProfileId'),'')!~resource_pattern
  OR coalesce(p->>'sourceSequence','')!~'^[1-9][0-9]{0,18}$'
  OR (p->>'sourceSequence')::numeric>9223372036854775807
  OR NEW.projection_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex')
  OR NEW.record_id<>'fact:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_array(NEW.participant_id::text,NEW.privacy_domain_id::text,p->>'sourceProfileId')),'UTF8')),'hex')||':'||(p->>'sourceSequence')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 FOREACH field IN ARRAY ARRAY['verificationKeyId','verificationKeyDigest','receiptDigest'] LOOP
  IF coalesce(p->>field,'')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['factDigest','blockHash'] LOOP
  IF coalesce(l->>field,'')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['predecessorDigest','relationshipPredecessorDigest'] LOOP
  IF l->field<>'null'::jsonb AND coalesce(l->>field,'')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 IF l->'reorgReplacementOf'<>'null'::jsonb AND coalesce(l->>'reorgReplacementOf','')!~resource_pattern THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM openpc.evidence_hold_selector_encoding(jsonb_build_object('type','FACT_TYPE_KEY','factType',l->>'factType','factProfileId',l->>'factProfileId','factKeyDigest',l->>'factKeyDigest'),NEW.participant_id,NEW.privacy_domain_id);
 PERFORM openpc.evidence_hold_selector_encoding(jsonb_build_object('type','PROJECTION','projectionId',l->>'projectionId'),NEW.participant_id,NEW.privacy_domain_id);
 PERFORM openpc.evidence_hold_selector_encoding(jsonb_build_object('type','GENERATION','generation',jsonb_build_object('kind','CANONICAL_FACT','factProfileId',l->>'factProfileId','canonicalGeneration',l->>'canonicalGeneration')),NEW.participant_id,NEW.privacy_domain_id);
 PERFORM openpc.evidence_hold_selector_encoding(jsonb_build_object('type','BLOCK_RANGE','chainId',l->>'chainId','genesisDigest',l->>'genesisDigest','fromBlock',l->>'blockNumber','throughBlock',l->>'blockNumber'),NEW.participant_id,NEW.privacy_domain_id);
 IF NOT EXISTS(SELECT 1 FROM control.evidence_catalogue c WHERE c.participant_id=NEW.participant_id
  AND c.privacy_domain_id=NEW.privacy_domain_id AND c.stream_id=NEW.stream_id AND c.record_id=NEW.record_id
  AND c.source_format='OPENPC_CANONICAL_FACT_V1' AND c.evidence_class='EFFECT'
  AND c.receipt_digest=p->>'receiptDigest' AND c.sequence::text=p->>'sourceSequence'
  AND c.occurred_at=(p->>'admittedAt')::timestamptz) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_fact_provenance_guard ON control.evidence_fact_provenance;
CREATE TRIGGER evidence_fact_provenance_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_fact_provenance
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_fact_provenance();

-- The direct immutable lineage is the preservation minimum. Reference closure
-- is resolved afresh across retained projections and signed retirements, so a
-- later hold can still cover an ancestor without retaining the whole projection.
CREATE OR REPLACE FUNCTION openpc.evidence_fact_lineages(participant uuid,privacy uuid)
RETURNS TABLE(stream_id text,record_id text,lineage jsonb)
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT p.stream_id,p.record_id,p.projection->'lineage'
 FROM control.evidence_fact_provenance p JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
 WHERE p.participant_id=participant AND p.privacy_domain_id=privacy
  AND c.source_format='OPENPC_CANONICAL_FACT_V1' AND c.evidence_class='EFFECT'
  AND p.projection->>'receiptDigest'=c.receipt_digest AND p.projection->>'sourceSequence'=c.sequence::text
  AND (p.projection->>'admittedAt')::timestamptz=c.occurred_at
  AND p.projection_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p.projection),'UTF8')),'hex')
 UNION ALL
 SELECT r.stream_id,r.record_id,r.preservation_metadata->'factLineage'
 FROM control.evidence_projection_retirement r JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
 JOIN control.deletion_job j USING(participant_id,privacy_domain_id,deletion_job_id)
 WHERE r.participant_id=participant AND r.privacy_domain_id=privacy AND r.data_class='NORMALIZED_JSON_PROJECTION'
  AND c.source_format='OPENPC_CANONICAL_FACT_V1' AND c.evidence_class='EFFECT'
  AND r.evidence_id=c.evidence_id AND r.source_receipt_digest=c.receipt_digest AND r.sequence=c.sequence AND r.segment_id=c.segment_id
  AND j.state='SUCCEEDED' AND j.selection->>'sourceKind'='FACT_PROVENANCE'
  AND j.selection->>'projectionDigest'=r.projection_digest AND j.selection->>'sourceReceiptDigest'=r.source_receipt_digest
  AND r.retirement_digest=openpc.projection_retirement_digest(r)
  AND jsonb_typeof(r.preservation_metadata->'factLineage')='object'
$$;
REVOKE ALL ON FUNCTION openpc.evidence_fact_lineages(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_fact_lineages(uuid,uuid) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.evidence_fact_hold_metadata(source control.evidence_catalogue)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE original jsonb; queue jsonb; item jsonb; lineage jsonb; reference jsonb; candidates jsonb;
 seen text[]:=ARRAY[]::text[]; unresolved boolean:=false; steps integer:=0;
 projections jsonb:='[]'; facts jsonb:='[]'; blocks jsonb:='[]'; generations jsonb:='[]';
BEGIN
 -- The closure resolver reloads authoritative ancestors. First bind the caller's
 -- starting record itself, so a modified class/digest/sequence cannot borrow the
 -- lineage of an otherwise valid catalogue identity.
 IF (source).source_format IS DISTINCT FROM 'OPENPC_CANONICAL_FACT_V1'
  OR (source).evidence_class IS DISTINCT FROM 'EFFECT'
  OR NOT EXISTS(SELECT 1 FROM control.evidence_catalogue c
   WHERE c.participant_id=(source).participant_id AND c.privacy_domain_id=(source).privacy_domain_id
    AND c.stream_id=(source).stream_id AND c.record_id=(source).record_id
    AND c IS NOT DISTINCT FROM source) THEN RETURN NULL; END IF;
 SELECT jsonb_agg(DISTINCT p.lineage) INTO candidates FROM openpc.evidence_fact_lineages((source).participant_id,(source).privacy_domain_id) p
  WHERE p.stream_id=(source).stream_id AND p.record_id=(source).record_id;
 IF candidates IS NULL OR jsonb_array_length(candidates)<>1 THEN RETURN NULL; END IF;
 original:=candidates->0;
 queue:=jsonb_build_array(jsonb_build_object('lineage',original,'path','[]'::jsonb));
 WHILE jsonb_array_length(queue)>0 AND steps<64 LOOP
  item:=queue->0; queue:=queue-0; lineage:=item->'lineage'; steps:=steps+1;
  IF item->'path' ? (lineage->>'factDigest') THEN unresolved:=true; CONTINUE; END IF;
  IF lineage->>'factDigest'=ANY(seen) THEN CONTINUE; END IF;
  seen:=array_append(seen,lineage->>'factDigest');
  projections:=projections||jsonb_build_array(lineage->>'projectionId');
  facts:=facts||jsonb_build_array(jsonb_build_object('factType',lineage->>'factType','factProfileId',lineage->>'factProfileId','factKeyDigest',lineage->>'factKeyDigest'));
  blocks:=blocks||jsonb_build_array(jsonb_build_object('chainId',lineage->>'chainId','genesisDigest',lineage->>'genesisDigest','blockNumber',lineage->>'blockNumber'));
  generations:=generations||jsonb_build_array(jsonb_build_object('kind','CANONICAL_FACT','factProfileId',lineage->>'factProfileId','canonicalGeneration',lineage->>'canonicalGeneration'));
  FOR reference IN SELECT value FROM jsonb_array_elements(jsonb_build_array(lineage->'predecessorDigest',lineage->'relationshipPredecessorDigest',lineage->'reorgReplacementOf')) WHERE value<>'null'::jsonb LOOP
   SELECT jsonb_agg(DISTINCT p.lineage) INTO candidates
    FROM openpc.evidence_fact_lineages((source).participant_id,(source).privacy_domain_id) p
    WHERE p.lineage->'factDigest'=reference OR p.lineage->'factId'=reference;
   IF candidates IS NULL OR jsonb_array_length(candidates)<>1 THEN unresolved:=true;
   -- Visit descendants before queued siblings. Breadth-first de-duplication can
   -- mark both ends of a shared-reference cycle seen before either back edge
   -- reaches its ancestor path, incorrectly reporting complete closure.
   ELSE queue:=jsonb_build_array(jsonb_build_object('lineage',candidates->0,'path',(item->'path')||jsonb_build_array(lineage->>'factDigest')))||queue; END IF;
  END LOOP;
 END LOOP;
 RETURN jsonb_build_object('projections',projections,'facts',facts,'blocks',blocks,
  'generations',jsonb_build_object('CANONICAL_FACT',generations),'unresolvedReferences',unresolved OR jsonb_array_length(queue)>0);
EXCEPTION WHEN insufficient_privilege THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_fact_hold_metadata(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_fact_hold_metadata(control.evidence_catalogue) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
`;
