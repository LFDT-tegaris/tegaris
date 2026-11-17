/** Feature declaration only. The integrator registers this with Drizzle's
 * existing security migration owner and connects the hold source dispatcher.
 * Native CBOR/source verification precedes custody; SQL independently binds
 * every metadata/record/segment/checkpoint identity. No deletion is authorized. */
export const candidateArchiveGuardsSql = `
ALTER TABLE control.evidence_candidate_archive FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_candidate_archive_part FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_candidate_archive,control.evidence_candidate_archive_part
 FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.evidence_candidate_archive,control.evidence_candidate_archive_part
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.evidence_candidate_archive,control.evidence_candidate_archive_part TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_candidate_archive()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE m jsonb:=NEW.manifest; i jsonb:=m->'identity'; b jsonb:=i->'block'; entry jsonb;
 prefix text; expected_id text; expected_digest text; expected_format text; index integer:=0;
 total integer; part_count integer; previous_sequence numeric:=0; original control.evidence_catalogue;
 field text; block_field text;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR NOT pg_has_role(current_user,'openpc_control_worker','USAGE') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 IF m IS DISTINCT FROM jsonb_build_object('version','OPENPC_CANDIDATE_PROJECTION_MANIFEST_V1',
  'class','CANDIDATE_PROJECTION','store','openpc_candidate_index','authority','NONE',
  'currentReadiness','NOT_ESTABLISHED','identity',i,'identityDigest',m->'identityDigest','chunks',m->'chunks')
  OR jsonb_typeof(i) IS DISTINCT FROM 'object' OR jsonb_typeof(b) IS DISTINCT FROM 'object'
  OR i-ARRAY['participantId','privacyDomainId','sourceProfileId','generationId','partitionId','candidateId',
   'publicationDigest','sourceProfileDigest','partitionDigest','projectionId','mappingDigest','nativeRecordId',
   'recordKind','recordSequence','candidateFeedSequence','observedEventId','observedEventDigest','payloadDigest',
   'payloadBytes','schemaDigest','evidenceDigest','checkpointDigest','occurredAt','chainId','genesisDigest','block']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(i))<>26
  OR b-ARRAY['number','hash','parentHash','finalityKind','finalityEvidenceDigest','headNumber','headHash']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(b))<>7
  OR jsonb_typeof(m->'chunks') IS DISTINCT FROM 'array'
  OR jsonb_array_length(m->'chunks') NOT BETWEEN 1 AND 16
  OR i->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR i->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR i->>'candidateId' IS DISTINCT FROM NEW.candidate_id::text
  OR NEW.manifest_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(m),'UTF8')),'hex')
  OR m->>'identityDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(i),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 FOR field IN SELECT jsonb_object_keys(i) LOOP
  IF field NOT IN ('payloadBytes','block') AND jsonb_typeof(i->field) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 FOR field IN SELECT jsonb_object_keys(b) LOOP
  IF jsonb_typeof(b->field) IS DISTINCT FROM 'string'
   AND NOT(field IN ('headNumber','headHash') AND b->field='null'::jsonb)
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['participantId','privacyDomainId','sourceProfileId','generationId','partitionId','candidateId','projectionId','observedEventId'] LOOP
  IF coalesce(i->>field,'')!~'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['publicationDigest','sourceProfileDigest','partitionDigest','mappingDigest','observedEventDigest',
  'payloadDigest','schemaDigest','evidenceDigest','checkpointDigest','genesisDigest'] LOOP
  IF coalesce(i->>field,'')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 FOREACH block_field IN ARRAY ARRAY['hash','parentHash','finalityEvidenceDigest'] LOOP
  IF coalesce(b->>block_field,'')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END LOOP;
 IF coalesce(i->>'recordKind','') NOT IN ('EVENT_LOG','STATE_CALL','TRANSACTION_RECEIPT','BLOCK_HEADER','FULL_BLOCK_TRANSACTIONS','EXTERNAL_OBSERVATION')
  OR length(i->>'nativeRecordId') NOT BETWEEN 1 AND 256
  OR coalesce(i->>'recordSequence','')!~'^(0|[1-9][0-9]{0,19})$' OR (i->>'recordSequence')::numeric>18446744073709551615
  OR coalesce(i->>'candidateFeedSequence','')!~'^[1-9][0-9]{0,18}$' OR (i->>'candidateFeedSequence')::numeric>9223372036854775807
  OR coalesce(i->>'chainId','')!~'^(0|[1-9][0-9]{0,77})$' OR (i->>'chainId')::numeric>=power(2::numeric,256)
  OR coalesce(b->>'number','')!~'^(0|[1-9][0-9]{0,19})$' OR (b->>'number')::numeric>18446744073709551615
  OR coalesce(b->>'finalityKind','') NOT IN ('SAFE_TAG','FINALIZED_TAG','CONFIRMATIONS')
  OR ((b->>'finalityKind'='CONFIRMATIONS') IS DISTINCT FROM (b->'headNumber'<>'null'::jsonb AND b->'headHash'<>'null'::jsonb))
  OR ((b->'headNumber'='null'::jsonb) IS DISTINCT FROM (b->'headHash'='null'::jsonb))
  OR (b->'headNumber'<>'null'::jsonb AND (coalesce(b->>'headNumber','')!~'^(0|[1-9][0-9]{0,19})$'
    OR (b->>'headNumber')::numeric>18446744073709551615 OR coalesce(b->>'headHash','')!~'^sha256:[0-9a-f]{64}$'))
  OR jsonb_typeof(i->'payloadBytes') IS DISTINCT FROM 'number'
  OR coalesce(i->>'payloadBytes','')!~'^[1-9][0-9]{0,6}$' OR (i->>'payloadBytes')::integer NOT BETWEEN 1 AND 1048576
  OR coalesce(i->>'occurredAt','')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}Z$'
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 total:=(i->>'payloadBytes')::integer; part_count:=jsonb_array_length(m->'chunks');
 prefix:='candidate:'||substring(m->>'identityDigest' from 8);
 IF part_count<>(total+65535)/65536 OR NEW.record_id<>prefix||':manifest' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(m->'chunks') LOOP
  IF entry IS DISTINCT FROM jsonb_build_object('index',index,'offset',index*65536,
    'bytes',least(65536,total-index*65536),'recordId',prefix||':chunk:'||index::text,'digest',entry->'digest')
    OR coalesce(entry->>'digest','')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  index:=index+1;
 END LOOP;
 -- Every chunk precedes the final manifest. Native feed sequence is independent
 -- of the catalogue's contiguous archive sequence and is never used as its cursor.
 FOR index IN 0..part_count LOOP
  expected_id:=CASE WHEN index=part_count THEN NEW.record_id ELSE m->'chunks'->index->>'recordId' END;
  expected_digest:=CASE WHEN index=part_count THEN NEW.manifest_digest ELSE m->'chunks'->index->>'digest' END;
  expected_format:=CASE WHEN index=part_count THEN 'OPENPC_CANDIDATE_PROJECTION_MANIFEST_V1' ELSE 'OPENPC_CANDIDATE_PROJECTION_CHUNK_V1' END;
  SELECT c.* INTO STRICT original FROM control.evidence_catalogue c
   JOIN control.evidence_segment s USING(participant_id,privacy_domain_id,stream_id,segment_id)
   JOIN control.evidence_segment_payload body USING(participant_id,privacy_domain_id,stream_id,segment_id)
   WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
    AND c.stream_id=NEW.stream_id AND c.record_id=expected_id
    AND c.evidence_class='EFFECT' AND c.source_format=expected_format AND c.receipt_digest=expected_digest
    AND c.occurred_at=(i->>'occurredAt')::timestamptz AND c.sequence BETWEEN s.first_sequence AND s.through_sequence
    AND s.object_digest='sha256:'||encode(sha256(body.encrypted_segment),'hex');
  IF original.sequence<=previous_sequence THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  previous_sequence:=original.sequence;
 END LOOP;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS candidate_archive_guard ON control.evidence_candidate_archive;
CREATE TRIGGER candidate_archive_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_candidate_archive
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_candidate_archive();
REVOKE ALL ON FUNCTION openpc.guard_candidate_archive() FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.index_candidate_archive_parts()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item jsonb; index integer:=0;
BEGIN
 FOR item IN SELECT value FROM jsonb_array_elements(NEW.manifest->'chunks') LOOP
  INSERT INTO control.evidence_candidate_archive_part(participant_id,privacy_domain_id,stream_id,manifest_record_id,ordinal,record_id)
   VALUES(NEW.participant_id,NEW.privacy_domain_id,NEW.stream_id,NEW.record_id,index,item->>'recordId');
  index:=index+1;
 END LOOP;
 INSERT INTO control.evidence_candidate_archive_part(participant_id,privacy_domain_id,stream_id,manifest_record_id,ordinal,record_id)
  VALUES(NEW.participant_id,NEW.privacy_domain_id,NEW.stream_id,NEW.record_id,index,NEW.record_id);
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.index_candidate_archive_parts() FROM PUBLIC;
DROP TRIGGER IF EXISTS candidate_archive_parts ON control.evidence_candidate_archive;
CREATE TRIGGER candidate_archive_parts AFTER INSERT ON control.evidence_candidate_archive
 FOR EACH ROW EXECUTE FUNCTION openpc.index_candidate_archive_parts();
CREATE OR REPLACE FUNCTION openpc.guard_candidate_archive_part()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE parent control.evidence_candidate_archive; expected text; count_parts integer;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1' THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT parent FROM control.evidence_candidate_archive WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND record_id=NEW.manifest_record_id;
 count_parts:=jsonb_array_length(parent.manifest->'chunks');
 expected:=CASE WHEN NEW.ordinal=count_parts THEN parent.record_id ELSE parent.manifest->'chunks'->NEW.ordinal->>'recordId' END;
 IF expected IS NULL OR NEW.record_id IS DISTINCT FROM expected OR NEW.ordinal<0 OR NEW.ordinal>count_parts THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_candidate_archive_part() FROM PUBLIC;
DROP TRIGGER IF EXISTS candidate_archive_part_guard ON control.evidence_candidate_archive_part;
CREATE TRIGGER candidate_archive_part_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_candidate_archive_part
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_candidate_archive_part();

CREATE OR REPLACE FUNCTION openpc.candidate_archive_hold_metadata(source control.evidence_catalogue)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE identity jsonb;
BEGIN
 SELECT a.manifest->'identity' INTO STRICT identity FROM control.evidence_candidate_archive a
  JOIN control.evidence_candidate_archive_part part ON part.participant_id=a.participant_id AND part.privacy_domain_id=a.privacy_domain_id
   AND part.stream_id=a.stream_id AND part.manifest_record_id=a.record_id
  JOIN control.evidence_catalogue c ON c.participant_id=part.participant_id AND c.privacy_domain_id=part.privacy_domain_id
   AND c.stream_id=part.stream_id AND c.record_id=part.record_id
  WHERE c IS NOT DISTINCT FROM source AND a.manifest_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(a.manifest),'UTF8')),'hex');
 -- This owner proves only its direct projection/block. Missing cross-store
 -- ancestry stays UNKNOWN; candidate generation is not canonical Fact generation.
 RETURN jsonb_build_object('projections',jsonb_build_array('urn:openpc:resource:'||(identity->>'projectionId')),
  'blocks',jsonb_build_array(jsonb_build_object('chainId',identity->>'chainId','genesisDigest',identity->>'genesisDigest',
   'blockNumber',identity->'block'->>'number')),'unresolvedReferences',true);
EXCEPTION WHEN no_data_found OR too_many_rows OR insufficient_privilege THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.candidate_archive_hold_metadata(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.candidate_archive_hold_metadata(control.evidence_catalogue)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.candidate_archive_coverage(pid uuid,privacy uuid,stream text,record_ref text,sinks text[])
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.evidence_candidate_archive; object record; checkpoint control.evidence_checkpoint;
 sink text; receipts jsonb; objects jsonb:='[]'; original_count integer; pending jsonb;
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF pid IS DISTINCT FROM openpc.current_participant_id() OR privacy IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR sinks IS NULL OR cardinality(sinks) NOT BETWEEN 1 AND 8 OR array_position(sinks,NULL) IS NOT NULL
  OR cardinality(sinks)<>(SELECT count(DISTINCT value) FROM unnest(sinks) value)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT a FROM control.evidence_candidate_archive WHERE participant_id=pid
  AND privacy_domain_id=privacy AND stream_id=stream AND record_id=record_ref;
 pending:=jsonb_build_object('state','PENDING','authority','NONE','manifestDigest',a.manifest_digest);
 SELECT count(*) INTO original_count FROM control.evidence_candidate_archive_part part
  JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
  WHERE part.participant_id=pid AND part.privacy_domain_id=privacy AND part.stream_id=stream AND part.manifest_record_id=record_ref;
 IF original_count<>jsonb_array_length(a.manifest->'chunks')+1 THEN RETURN pending; END IF;
 FOR object IN SELECT DISTINCT s.segment_id,s.object_digest,s.first_sequence,s.through_sequence
  FROM control.evidence_candidate_archive_part part JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
  JOIN control.evidence_segment s USING(participant_id,privacy_domain_id,stream_id,segment_id)
  WHERE part.participant_id=pid AND part.privacy_domain_id=privacy AND part.stream_id=stream AND part.manifest_record_id=record_ref
  ORDER BY s.first_sequence LOOP
  receipts:='[]';
  FOREACH sink IN ARRAY sinks LOOP
   SELECT * INTO checkpoint FROM control.evidence_checkpoint c WHERE c.participant_id=pid AND c.privacy_domain_id=privacy
    AND c.stream_id=stream AND c.segment_id=object.segment_id AND c.object_digest=object.object_digest
    AND c.through_sequence=object.through_sequence AND c.sink_id=sink;
   IF NOT FOUND THEN RETURN pending; END IF;
   IF checkpoint.receipt->>'kind'='SIGNED_REMOTE_ARCHIVE_V1' THEN
    IF NOT openpc.remote_archive_covers(pid,privacy,stream,object.segment_id,sink) THEN RETURN pending; END IF;
   ELSIF EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=pid
     AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=privacy)
     AND openpc.evidence_hold_requires_coverage(h,stream,object.segment_id)
     AND NOT EXISTS(SELECT 1 FROM control.evidence_hold_coverage c WHERE c.participant_id=pid AND c.privacy_domain_id=privacy
       AND c.retention_hold_id=h.retention_hold_id AND c.hold_revision=h.revision AND c.stream_id=stream
       AND c.segment_id=object.segment_id AND c.object_digest=object.object_digest AND c.sink_id=sink))
   THEN RETURN pending; END IF;
   receipts:=receipts||jsonb_build_array(jsonb_build_object('sinkId',sink,'checkpointDigest',checkpoint.checkpoint_digest,'receiptDigest',checkpoint.receipt_digest));
  END LOOP;
  objects:=objects||jsonb_build_array(jsonb_build_object('segmentId',object.segment_id::text,'objectDigest',object.object_digest,
   'firstSequence',object.first_sequence::text,'throughSequence',object.through_sequence::text,'sinkReceipts',receipts));
 END LOOP;
 IF jsonb_array_length(objects)=0 THEN RETURN pending; END IF;
 RETURN jsonb_build_object('state','COMPLETE','authority','NONE','manifestDigest',a.manifest_digest,'segments',objects);
END $$;
REVOKE ALL ON FUNCTION openpc.candidate_archive_coverage(uuid,uuid,text,text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.candidate_archive_coverage(uuid,uuid,text,text,text[])
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
`;
