/** Current database predicates for source withdrawal. Native original-history
 * custody is checked separately after committed governance, never inferred here. */
export const runtimeArtifactDispositionSelectionSql = `
-- API admission and installed-worker reconciliation have distinct role/action
-- gates. They serialize through the same producer locks, in the same order.
CREATE OR REPLACE FUNCTION openpc.lock_runtime_artifact_disposition()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
  OR current_setting('session_replication_role')<>'origin'
  OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND NOT rolsuper AND NOT rolbypassrls)
  OR NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
  OR NOT pg_has_role(session_user,'openpc_control_runtime','USAGE')
  OR openpc.current_action_intent_id() NOT IN
   ('ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1','ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1',
    'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1','ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1')
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-release-catalog',0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('module-admission:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))
 THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='RUNTIME-DISPOSITION-PRODUCER-CONTENTION'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_runtime_artifact_disposition() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_runtime_artifact_disposition() TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_unused_references(observed jsonb,input_id uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE related jsonb; node jsonb; reference jsonb; parent_configuration text; parent_installation text;
BEGIN
 IF observed->'runtimeProducerFencesObserved' IS DISTINCT FROM 'true'::jsonb
  OR observed->'dependencyProducerFencesObserved' IS DISTINCT FROM 'true'::jsonb
  OR observed->'root'->>'id' IS DISTINCT FROM input_id::text
  OR observed->'root'->>'kind' IS DISTINCT FROM 'INPUT'
  OR EXISTS(SELECT 1 FROM jsonb_each(observed->'owners') branch WHERE branch.value->'overflow' IS DISTINCT FROM 'false'::jsonb)
 THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-INCOMPLETE_REFERENCES'; END IF;
 SELECT min(r->>'id') FILTER(WHERE r->>'kind'='MODULE_CONFIGURATION'),
   min(r->>'id') FILTER(WHERE r->>'kind'='MODULE_INSTALLATION')
 INTO parent_configuration,parent_installation FROM jsonb_array_elements(observed->'root'->'references') r;
 IF parent_configuration IS NULL OR parent_installation IS NULL
  OR (SELECT count(*) FROM jsonb_array_elements(observed->'root'->'references') r WHERE r->>'kind'='MODULE_CONFIGURATION')<>1
  OR (SELECT count(*) FROM jsonb_array_elements(observed->'root'->'references') r WHERE r->>'kind'='MODULE_INSTALLATION')<>1
 THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-INCOMPLETE_REFERENCES'; END IF;
 -- Consume the existing owner's typed graph, including downstream original
 -- references. Shared parents alone do not connect unrelated inputs.
 WITH RECURSIVE nodes AS (
  SELECT entry.value body,entry.value->>'kind'||':'||(entry.value->>'id') id
   FROM jsonb_each(observed->'owners') branch CROSS JOIN LATERAL jsonb_array_elements(branch.value->'rows') entry
 ), refs AS (
  SELECT n.id src,r.value->>'kind'||':'||(r.value->>'id') dst,r.value->>'kind' target_kind
   FROM nodes n CROSS JOIN LATERAL jsonb_array_elements(n.body->'references') r
 ), tokens AS (
  SELECT n.id,t.value->>'kind'||':'||(t.value->>'digest') token FROM nodes n
   CROSS JOIN LATERAL jsonb_array_elements(n.body->'tokens') t
 ), token_heads AS (SELECT token,min(id) head FROM tokens GROUP BY token),
 edges AS (
  SELECT src,dst FROM refs UNION SELECT dst,src FROM refs WHERE target_kind IN
   ('WORK','RUNTIME_GENERATION','TARGET','PROBE','POLICY_OCCURRENCE','POLICY_AUTHORIZATION','TARGET_DISPOSITION_ADMISSION','TARGET_DISPOSITION_DELIVERY')
  UNION SELECT t.id,h.head FROM tokens t JOIN token_heads h USING(token)
  UNION SELECT h.head,t.id FROM tokens t JOIN token_heads h USING(token)
 ), reached(id) AS (
  SELECT 'INPUT:'||input_id::text UNION SELECT e.dst FROM reached r JOIN edges e ON e.src=r.id
 ) SELECT coalesce(jsonb_agg(n.body ORDER BY n.id),'[]'::jsonb) INTO related FROM reached r JOIN nodes n USING(id);
 IF jsonb_array_length(related)=0 THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-INCOMPLETE_REFERENCES'; END IF;
 FOR node IN SELECT value FROM jsonb_array_elements(related) LOOP
  IF node->>'kind' NOT IN ('INPUT','MODULE_CONFIGURATION','MODULE_INSTALLATION','PROVIDER','INDEXER','PROJECTION','CIGL_SETTINGS')
   OR EXISTS(SELECT 1 FROM jsonb_each(node->'checks') c WHERE c.value='false'::jsonb)
   OR (node->>'kind'='INPUT' AND (node->>'id'<>input_id::text OR node->>'state'<>'RETAINED'
    OR node->'checks'->'bytesMatch' IS DISTINCT FROM 'true'::jsonb OR node->'checks'->'bindingsKnown' IS DISTINCT FROM 'true'::jsonb))
   -- Module parents record where import occurred. They do not themselves use
   -- every historical input imported under that generation. Keep their exact
   -- identities in the observation, and reject an actual retained copy of the
   -- same bytes. Incoming consumers/rollback history remain forbidden above.
   OR (node->>'kind'='MODULE_CONFIGURATION' AND (
    node->>'id' IS DISTINCT FROM parent_configuration
    OR coalesce(node->>'state','') NOT IN ('ACTIVE','INACTIVE')
    OR coalesce(node->'digests'->>'configuration','') !~ '^sha256:[0-9a-f]{64}$'
    OR node->'digests'->>'configuration'=observed->'root'->'digests'->>'configuration'
    OR node->'references' IS DISTINCT FROM jsonb_build_array(jsonb_build_object('kind','MODULE_INSTALLATION','id',parent_installation,'required',true))))
   OR (node->>'kind'='MODULE_INSTALLATION' AND (
    node->>'id' IS DISTINCT FROM parent_installation
    OR coalesce(node->>'state','') NOT IN ('ENABLED','INSTALLED_DISABLED')
    OR coalesce(node->'digests'->>'lifecycle','') !~ '^sha256:[0-9a-f]{64}$'
    OR coalesce(node->'details'->>'lifecycleOperationId','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'))
  THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-REFERENCES'; END IF;
  FOR reference IN SELECT value FROM jsonb_array_elements(node->'references') LOOP
   IF reference->'required'='true'::jsonb AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(related) target
    WHERE target->>'kind'=reference->>'kind' AND target->>'id'=reference->>'id')
   THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-INCOMPLETE_REFERENCES'; END IF;
  END LOOP;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(related) c JOIN jsonb_array_elements(related) i
   ON i->>'kind'='MODULE_INSTALLATION' AND i->>'id'=parent_installation
   WHERE c->>'kind'='MODULE_CONFIGURATION' AND c->>'id'=parent_configuration
    AND ((c->>'state'='ACTIVE' AND i->>'state'='ENABLED' AND i->'digests'->>'manifest' ~ '^sha256:[0-9a-f]{64}$')
      OR (c->>'state'='INACTIVE' AND i->>'state'='INSTALLED_DISABLED' AND i->'digests'->'manifest'='null'::jsonb)))
 THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-INCOMPLETE_REFERENCES'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_runtime_artifact_unused_references(jsonb,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_runtime_artifact_unused_references(jsonb,uuid) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.runtime_artifact_source_observation(input_id uuid,policy_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.runtime_artifact_source; a control.evidence_runtime_artifact_archive; rule control.retention_policy;
 input record; part record; observed jsonb; segments jsonb:='[]'::jsonb; sinks jsonb; ack_micros numeric;
 eligible numeric; p uuid:=openpc.current_participant_id(); d uuid:=openpc.current_privacy_domain_id();
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
  OR current_setting('session_replication_role')<>'origin' OR NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM openpc.lock_runtime_artifact_disposition();
 s:=openpc.runtime_artifact_materialization_source();
 IF s.custody_root->>'consumer_profile' IS DISTINCT FROM 'openpc:local-runtime-source-consumers:v2' OR s.archive_custody IS NULL
  THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-SOURCE_UNPROVEN'; END IF;
 PERFORM openpc.assert_runtime_artifact_materialization_boundary();
 SELECT runtime_configuration_input_id,module_installation_id,module_configuration_generation_id,configuration_digest,resource_bindings,selected,created_at,
  openpc.runtime_artifact_input_information(runtime_configuration_input_id) info INTO STRICT input
  FROM control.runtime_configuration_input WHERE participant_id=p AND privacy_domain_id=d AND runtime_configuration_input_id=input_id;
 IF input.selected OR input.info->'bytesMatch' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-SELECTED_INPUT'; END IF;
 observed:=openpc.observe_runtime_artifact_references(input_id,'sha256:'||encode(input.configuration_digest,'hex'));
 PERFORM openpc.assert_runtime_artifact_unused_references(observed,input_id);
 SELECT * INTO STRICT a FROM control.evidence_runtime_artifact_archive WHERE participant_id=p AND privacy_domain_id=d
  AND runtime_configuration_input_id=input_id AND stream_id=s.archive_custody->>'stream_id';
 IF a.source_pending_original IS NULL OR a.manifest_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(a.manifest),'UTF8')),'hex')
  OR a.manifest->'identity' IS DISTINCT FROM jsonb_build_object('participantId',p::text,'privacyDomainId',d::text,
   'runtimeConfigurationInputId',input_id::text,'moduleInstallationId',input.module_installation_id::text,
   'moduleConfigurationGenerationId',input.module_configuration_generation_id::text,'configurationDigest','sha256:'||encode(input.configuration_digest,'hex'),
   'configurationBytes',(input.info->>'byteLength')::integer,'resourceBindingsDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(input.resource_bindings),'UTF8')),'hex'),
   'createdAt',to_char(input.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
  OR (SELECT count(*) FROM control.evidence_runtime_artifact_archive_part entry
   JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
   JOIN control.evidence_segment seg USING(participant_id,privacy_domain_id,stream_id,segment_id)
   WHERE entry.participant_id=p AND entry.privacy_domain_id=d AND entry.stream_id=a.stream_id AND entry.manifest_record_id=a.record_id
    AND entry.ordinal BETWEEN 0 AND jsonb_array_length(a.manifest->'chunks')
    AND entry.record_id=CASE WHEN entry.ordinal=jsonb_array_length(a.manifest->'chunks') THEN a.record_id
     ELSE a.manifest->'chunks'->entry.ordinal->>'recordId' END
    AND c.receipt_digest=CASE WHEN entry.ordinal=jsonb_array_length(a.manifest->'chunks') THEN a.manifest_digest
     ELSE a.manifest->'chunks'->entry.ordinal->>'digest' END
    AND c.evidence_class='EFFECT' AND c.source_format=CASE WHEN entry.ordinal=jsonb_array_length(a.manifest->'chunks')
     THEN 'OPENPC_RUNTIME_ARTIFACT_MANIFEST_V1' ELSE 'OPENPC_RUNTIME_ARTIFACT_CHUNK_V1' END
    AND c.occurred_at=input.created_at AND c.sequence BETWEEN seg.first_sequence AND seg.through_sequence) IS DISTINCT FROM jsonb_array_length(a.manifest->'chunks')+1
  OR openpc.runtime_artifact_archive_payloads_match(input_id) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-ARCHIVE_UNPROVEN'; END IF;
 SELECT * INTO STRICT rule FROM control.retention_policy WHERE participant_id=p AND privacy_domain_id=d AND retention_policy_id=policy_id
  AND data_class='RUNTIME_ARTIFACT' AND deletion_mode='ROW_DELETE' AND active_until IS NULL;
 eligible:=floor(extract(epoch from input.created_at)*1000000)+rule.retention_period_ms*1000;
 FOR part IN SELECT DISTINCT seg.segment_id,seg.object_digest,seg.first_sequence,seg.through_sequence,seg.admitted_at
  FROM control.evidence_runtime_artifact_archive_part entry JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
  JOIN control.evidence_segment seg USING(participant_id,privacy_domain_id,stream_id,segment_id)
  WHERE entry.participant_id=p AND entry.privacy_domain_id=d AND entry.stream_id=a.stream_id AND entry.manifest_record_id=a.record_id
  ORDER BY seg.first_sequence LOOP
  IF EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=p AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=d)
   AND h.state='ACTIVE' AND openpc.evidence_hold_matches(h.selector,p,d,a.stream_id,part.segment_id))
   THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-ACTIVE_HOLD'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('sinkId',ack.sink_id,'checkpointDigest',ack.checkpoint_digest,
    'receiptDigest',ack.receipt_digest,'acknowledgedAtMicros',ack.micros::text) ORDER BY ack.micros,ack.sink_id),'[]'::jsonb),max(ack.micros)
   INTO sinks,ack_micros FROM (SELECT c.sink_id,c.checkpoint_digest,c.receipt_digest,floor(extract(epoch from c.acknowledged_at)*1000000) micros
    FROM control.evidence_checkpoint c WHERE c.participant_id=p AND c.privacy_domain_id=d AND c.stream_id=a.stream_id
     AND c.segment_id=part.segment_id AND c.object_digest=part.object_digest AND c.through_sequence=part.through_sequence
     AND c.receipt->>'receiptDigest'=c.receipt_digest
     AND ((NOT c.receipt ? 'kind' AND c.receipt->>'assurance'='LOCAL_FSYNC_READBACK'
       AND c.receipt->'object'->>'objectDigest'=part.object_digest
       AND c.receipt_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(c.receipt-'receiptDigest'),'UTF8')),'hex'))
      OR (c.receipt->>'kind'='SIGNED_REMOTE_ARCHIVE_V1'
       AND openpc.remote_archive_covers(p,d,a.stream_id,part.segment_id,c.sink_id)))
    ORDER BY c.acknowledged_at,c.sink_id LIMIT greatest(1,rule.sink_quorum)) ack;
  IF jsonb_array_length(sinks)<>greatest(1,rule.sink_quorum) THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-SINK_QUORUM'; END IF;
  eligible:=greatest(eligible,ack_micros+rule.local_grace_ms*1000);
  segments:=segments||jsonb_build_array(jsonb_build_object('segmentId',part.segment_id::text,'objectDigest',part.object_digest,
   'firstSequence',part.first_sequence::text,'throughSequence',part.through_sequence::text,'sinkReceipts',sinks));
 END LOOP;
 IF jsonb_array_length(segments) NOT BETWEEN 1 AND 65 THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-ARCHIVE_UNPROVEN'; END IF;
 IF eligible>floor(extract(epoch from clock_timestamp())*1000000) THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-RETENTION_NOT_ELAPSED'; END IF;
 RETURN jsonb_build_object('version','OPENPC_RUNTIME_ARTIFACT_SOURCE_DISPOSITION_V1','sourceOwnerId',s.source_owner_id::text,
  'sourceRootDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(s.custody_root),'UTF8')),'hex'),
  'archivePendingDigest','sha256:'||encode(sha256(a.source_pending_original),'hex'),
  'observation',jsonb_build_object('version','OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1','participantId','urn:openpc:participant:'||p::text,
   'privacyDomainId',d::text,'retentionPolicyId','urn:openpc:resource:'||policy_id::text,'policyDigest',rule.policy_digest,
   'targetDatabase','openpc_control','dataClass','RUNTIME_ARTIFACT','deletionMode','ROW_DELETE','source',a.manifest->'identity',
   'streamId',a.stream_id,'manifestRecordId',a.record_id,'manifestDigest',a.manifest_digest,'archiveSegments',segments,
   'referenceObservationDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(observed),'UTF8')),'hex'),
   'eligibleAfterMicros',eligible::text,'priorCursor',null));
END $$;
REVOKE ALL ON FUNCTION openpc.runtime_artifact_source_observation(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_artifact_source_observation(uuid,uuid) TO openpc_control_runtime;

-- Withdrawal admits only new disposition. Physical retirement instead consumes
-- this observation with a committed native denial and its own live governance.
CREATE OR REPLACE FUNCTION openpc.runtime_artifact_disposition_selection(input_id uuid,policy_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE configuration bytea;
BEGIN
 PERFORM openpc.lock_runtime_artifact_disposition();
 IF openpc.current_action_intent_id() NOT IN
  ('ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1','ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1')
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT configuration_digest INTO STRICT configuration FROM control.runtime_configuration_input
  WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id()
   AND runtime_configuration_input_id=input_id;
 IF NOT openpc.runtime_artifact_new_use_allowed(openpc.current_participant_id(),openpc.current_privacy_domain_id(),configuration)
 THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-ALREADY_DISPOSED'; END IF;
 RETURN openpc.runtime_artifact_source_observation(input_id,policy_id);
END $$;
REVOKE ALL ON FUNCTION openpc.runtime_artifact_disposition_selection(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_artifact_disposition_selection(uuid,uuid) TO openpc_control_runtime;
`;
