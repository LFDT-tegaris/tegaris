const dispositionSession = `EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user
 AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication
 AND NOT pg_has_role(oid,'openpc_control_owner','MEMBER')
 AND NOT pg_has_role(oid,'openpc_control_key_governor','MEMBER'))
 AND pg_has_role(session_user,'openpc_control_runtime','USAGE')
 AND openpc.current_action_intent_id() IN
 ('ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1','ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1',
  'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1','ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1')`;

/** Feature declaration only. The integrator registers this with Drizzle's
 * existing security migration owner and connects the hold source dispatcher.
 * The native immutable row and its exact chunks bind custody; SQL independently binds
 * every metadata/record/segment/checkpoint identity. No deletion is authorized. */
export const runtimeArtifactArchiveGuardsSql = `
ALTER TABLE control.evidence_runtime_artifact_archive FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_runtime_artifact_archive_part FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_runtime_artifact_archive,control.evidence_runtime_artifact_archive_part
 FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.evidence_runtime_artifact_archive,control.evidence_runtime_artifact_archive_part
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.evidence_runtime_artifact_archive,control.evidence_runtime_artifact_archive_part TO openpc_control_worker;

-- The raw-input comparison must run as its owner after plaintext column
-- privileges are closed. FORCE RLS still applies to encrypted custody: allow
-- this trigger's exact authenticated export scope, never a bypass-RLS role.
${['evidence_catalogue', 'evidence_segment', 'evidence_segment_payload']
  .map(
    (table) => `
DROP POLICY IF EXISTS runtime_archive_owner_read ON control.${table};
CREATE POLICY runtime_archive_owner_read ON control.${table} FOR SELECT TO openpc_control_owner
 USING(pg_trigger_depth()>0 AND openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-EVIDENCE_EXPORT_RECORDS-V1'
  AND pg_has_role(session_user,'openpc_control_worker','USAGE'));`,
  )
  .join('\n')}

-- API selection may test exact installed archive integrity, but cannot read
-- ciphertext. This separate owner policy does not widen the export trigger's
-- existing worker/action/depth admission.
${[
  'evidence_runtime_artifact_archive',
  'evidence_runtime_artifact_archive_part',
  'evidence_catalogue',
  'evidence_segment',
  'evidence_segment_payload',
]
  .map(
    (table) => `
DROP POLICY IF EXISTS runtime_archive_disposition_owner_read ON control.${table};
CREATE POLICY runtime_archive_disposition_owner_read ON control.${table} FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND (${dispositionSession}));`,
  )
  .join('\n')}

CREATE OR REPLACE FUNCTION openpc.runtime_artifact_archive_payloads_match(input_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE s control.runtime_artifact_source; a control.evidence_runtime_artifact_archive; input record;
 p uuid:=openpc.current_participant_id(); d uuid:=openpc.current_privacy_domain_id();
 lock_key text; expected_mode text; part_count integer;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF (${dispositionSession}) IS DISTINCT FROM true
  OR current_setting('transaction_isolation')<>'read committed' OR current_setting('session_replication_role')<>'origin'
  OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND NOT rolsuper AND NOT rolbypassrls)
  OR (current_setting('role')<>'none' AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_setting('role')
   AND NOT rolsuper AND NOT rolbypassrls AND pg_has_role(oid,'openpc_control_runtime','USAGE')))
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 -- SECURITY DEFINER changes current_user. Inspect the actual session and the
 -- existing producer fences; never call the invoker role-checking lock owner.
 FOREACH lock_key IN ARRAY ARRAY['evidence-lifecycle:'||p::text,'module-release-catalog',
  'module-admission:'||p::text||':'||d::text,'openpc-policy-generations:'||p::text||':'||d::text] LOOP
  expected_mode:=CASE WHEN lock_key LIKE 'module-admission:%' OR lock_key LIKE 'evidence-lifecycle:%' THEN 'ExclusiveLock' ELSE 'ShareLock' END;
  IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.mode=expected_mode
   AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=((hashtextextended(lock_key,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(lock_key,0)&4294967295)::oid AND l.objsubid=1)
  THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-OBSERVATION-FENCE'; END IF;
 END LOOP;
 IF input_id IS NULL THEN RETURN false; END IF;
 s:=openpc.runtime_artifact_materialization_source();
 IF s.custody_root->>'consumer_profile' IS DISTINCT FROM 'openpc:local-runtime-source-consumers:v2' OR s.archive_custody IS NULL
 THEN RETURN false; END IF;
 SELECT runtime_configuration_input_id,module_installation_id,module_configuration_generation_id,configuration_digest,resource_bindings,created_at,
  openpc.runtime_artifact_input_information(runtime_configuration_input_id) info INTO STRICT input
  FROM control.runtime_configuration_input WHERE participant_id=p AND privacy_domain_id=d AND runtime_configuration_input_id=input_id;
 SELECT * INTO STRICT a FROM control.evidence_runtime_artifact_archive WHERE participant_id=p AND privacy_domain_id=d
  AND runtime_configuration_input_id=input_id AND stream_id=s.archive_custody->>'stream_id';
 IF a.source_pending_original IS NULL OR input.info->'bytesMatch' IS DISTINCT FROM 'true'::jsonb
  OR jsonb_typeof(a.manifest->'chunks') IS DISTINCT FROM 'array'
  OR a.manifest->>'version' IS DISTINCT FROM 'OPENPC_RUNTIME_ARTIFACT_MANIFEST_V1'
  OR a.manifest_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(a.manifest),'UTF8')),'hex')
  OR a.manifest->'identity' IS DISTINCT FROM jsonb_build_object('participantId',p::text,'privacyDomainId',d::text,
   'runtimeConfigurationInputId',input_id::text,'moduleInstallationId',input.module_installation_id::text,
   'moduleConfigurationGenerationId',input.module_configuration_generation_id::text,'configurationDigest','sha256:'||encode(input.configuration_digest,'hex'),
   'configurationBytes',(input.info->>'byteLength')::integer,'resourceBindingsDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(input.resource_bindings),'UTF8')),'hex'),
   'createdAt',to_char(input.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
 THEN RETURN false; END IF;
 part_count:=jsonb_array_length(a.manifest->'chunks');
 IF part_count NOT BETWEEN 1 AND 64 OR
  (SELECT count(*) FROM control.evidence_runtime_artifact_archive_part entry WHERE entry.participant_id=p AND entry.privacy_domain_id=d
   AND entry.stream_id=a.stream_id AND entry.manifest_record_id=a.record_id)<>part_count+1
 THEN RETURN false; END IF;
 -- Only stored hashes and complete stored membership are compared. There is no
 -- caller-selected segment or expected digest, and no payload leaves this owner.
 RETURN (SELECT count(*) FROM control.evidence_runtime_artifact_archive_part entry
  JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
  JOIN control.evidence_segment seg USING(participant_id,privacy_domain_id,stream_id,segment_id)
  JOIN control.evidence_segment_payload payload USING(participant_id,privacy_domain_id,stream_id,segment_id)
  WHERE entry.participant_id=p AND entry.privacy_domain_id=d AND entry.stream_id=a.stream_id AND entry.manifest_record_id=a.record_id
   AND entry.ordinal BETWEEN 0 AND part_count
   AND entry.record_id=CASE WHEN entry.ordinal=part_count THEN a.record_id ELSE a.manifest->'chunks'->entry.ordinal->>'recordId' END
   AND c.receipt_digest=CASE WHEN entry.ordinal=part_count THEN a.manifest_digest ELSE a.manifest->'chunks'->entry.ordinal->>'digest' END
   AND c.evidence_class='EFFECT' AND c.source_format=CASE WHEN entry.ordinal=part_count
    THEN 'OPENPC_RUNTIME_ARTIFACT_MANIFEST_V1' ELSE 'OPENPC_RUNTIME_ARTIFACT_CHUNK_V1' END
   AND c.occurred_at=input.created_at AND c.sequence BETWEEN seg.first_sequence AND seg.through_sequence
   AND seg.object_digest='sha256:'||encode(sha256(payload.encrypted_segment),'hex'))=part_count+1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RETURN false;
END $$;
ALTER FUNCTION openpc.runtime_artifact_archive_payloads_match(uuid) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.runtime_artifact_archive_payloads_match(uuid) FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.runtime_artifact_archive_payloads_match(uuid) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_archive()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE m jsonb:=NEW.manifest; i jsonb:=m->'identity'; entry jsonb;
 prefix text; expected_id text; expected_digest text; expected_format text; index integer:=0;
 total integer; part_count integer; previous_sequence numeric:=0; original control.evidence_catalogue;
 native control.runtime_configuration_input; source control.runtime_artifact_source; pending jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR NOT pg_has_role(session_user,'openpc_control_worker','USAGE') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 -- Direct SQL may arrive after other row locks; never reverse-wait. The
 -- ordinary custody owner already acquired this same lock before stream rows.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT native FROM control.runtime_configuration_input WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND runtime_configuration_input_id=NEW.runtime_configuration_input_id FOR SHARE;
 IF i IS DISTINCT FROM jsonb_build_object('participantId',native.participant_id::text,
  'privacyDomainId',native.privacy_domain_id::text,'runtimeConfigurationInputId',native.runtime_configuration_input_id::text,
  'moduleInstallationId',native.module_installation_id::text,'moduleConfigurationGenerationId',native.module_configuration_generation_id::text,
  'configurationDigest','sha256:'||encode(native.configuration_digest,'hex'),'configurationBytes',octet_length(native.configuration_cbor),
  'resourceBindingsDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(native.resource_bindings),'UTF8')),'hex'),
  'createdAt',to_char(native.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
  OR sha256(native.configuration_cbor) IS DISTINCT FROM native.configuration_digest
  OR octet_length(native.configuration_cbor) NOT BETWEEN 1 AND 4194304
  OR m IS DISTINCT FROM jsonb_build_object('version','OPENPC_RUNTIME_ARTIFACT_MANIFEST_V1',
   'class','RUNTIME_ARTIFACT','store','openpc_control','authority','NONE','currentReadiness','NOT_ESTABLISHED',
   'identity',i,'identityDigest',m->'identityDigest','chunks',m->'chunks')
  OR jsonb_typeof(m->'chunks') IS DISTINCT FROM 'array'
  OR jsonb_array_length(m->'chunks') NOT BETWEEN 1 AND 64
  OR NEW.manifest_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(m),'UTF8')),'hex')
  OR m->>'identityDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
   jsonb_build_object('domain','pc.runtime-artifact.archive-identity.v1','identity',i)),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO source FROM control.runtime_artifact_source WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id;
 IF source.custody_root->>'consumer_profile'='openpc:local-runtime-source-consumers:v2' THEN
  pending:=openpc.runtime_artifact_archive_permit(NEW.runtime_configuration_input_id,NEW.stream_id);
  IF NEW.source_pending_original IS DISTINCT FROM decode(pending->>'original','hex')
   THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-ORIGINAL-UNAVAILABLE'; END IF;
 ELSIF NEW.source_pending_original IS NOT NULL THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-ORIGINAL-UNAVAILABLE'; END IF;
 total:=octet_length(native.configuration_cbor); part_count:=jsonb_array_length(m->'chunks');
 prefix:='runtime-artifact:'||substring(m->>'identityDigest' from 8);
 IF part_count<>(total+65535)/65536 OR NEW.record_id<>prefix||':manifest' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(m->'chunks') LOOP
  IF entry IS DISTINCT FROM jsonb_build_object('index',index,'offset',index*65536,
    'bytes',least(65536,total-index*65536),'recordId',prefix||':chunk:'||index::text,'digest',entry->'digest')
    OR entry->>'digest' IS DISTINCT FROM 'sha256:'||encode(sha256(substring(native.configuration_cbor from index*65536+1 for least(65536,total-index*65536))),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  index:=index+1;
 END LOOP;
 -- Every chunk precedes the final manifest. The native input identity never
 -- substitutes for the catalogue's contiguous archive sequence.
 FOR index IN 0..part_count LOOP
  expected_id:=CASE WHEN index=part_count THEN NEW.record_id ELSE m->'chunks'->index->>'recordId' END;
  expected_digest:=CASE WHEN index=part_count THEN NEW.manifest_digest ELSE m->'chunks'->index->>'digest' END;
  expected_format:=CASE WHEN index=part_count THEN 'OPENPC_RUNTIME_ARTIFACT_MANIFEST_V1' ELSE 'OPENPC_RUNTIME_ARTIFACT_CHUNK_V1' END;
  SELECT c.* INTO STRICT original FROM control.evidence_catalogue c
   JOIN control.evidence_segment s USING(participant_id,privacy_domain_id,stream_id,segment_id)
   JOIN control.evidence_segment_payload body USING(participant_id,privacy_domain_id,stream_id,segment_id)
   WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
    AND c.stream_id=NEW.stream_id AND c.record_id=expected_id
    AND c.evidence_class='EFFECT' AND c.source_format=expected_format AND c.receipt_digest=expected_digest
    AND c.occurred_at=native.created_at AND c.sequence BETWEEN s.first_sequence AND s.through_sequence
    AND s.object_digest='sha256:'||encode(sha256(body.encrypted_segment),'hex')
    AND (NEW.source_pending_original IS NULL OR (c.xmin=pg_current_xact_id()::xid AND s.xmin=pg_current_xact_id()::xid AND body.xmin=pg_current_xact_id()::xid));
  IF original.sequence<=previous_sequence THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  previous_sequence:=original.sequence;
 END LOOP;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS runtime_artifact_archive_guard ON control.evidence_runtime_artifact_archive;
CREATE TRIGGER runtime_artifact_archive_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_runtime_artifact_archive
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_artifact_archive();
REVOKE ALL ON FUNCTION openpc.guard_runtime_artifact_archive() FROM PUBLIC;
ALTER FUNCTION openpc.guard_runtime_artifact_archive() OWNER TO openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.index_runtime_artifact_archive_parts()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item jsonb; index integer:=0;
BEGIN
 FOR item IN SELECT value FROM jsonb_array_elements(NEW.manifest->'chunks') LOOP
  INSERT INTO control.evidence_runtime_artifact_archive_part(participant_id,privacy_domain_id,stream_id,manifest_record_id,ordinal,record_id)
   VALUES(NEW.participant_id,NEW.privacy_domain_id,NEW.stream_id,NEW.record_id,index,item->>'recordId');
  index:=index+1;
 END LOOP;
 INSERT INTO control.evidence_runtime_artifact_archive_part(participant_id,privacy_domain_id,stream_id,manifest_record_id,ordinal,record_id)
  VALUES(NEW.participant_id,NEW.privacy_domain_id,NEW.stream_id,NEW.record_id,index,NEW.record_id);
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.index_runtime_artifact_archive_parts() FROM PUBLIC;
DROP TRIGGER IF EXISTS runtime_artifact_archive_parts ON control.evidence_runtime_artifact_archive;
CREATE TRIGGER runtime_artifact_archive_parts AFTER INSERT ON control.evidence_runtime_artifact_archive
 FOR EACH ROW EXECUTE FUNCTION openpc.index_runtime_artifact_archive_parts();
CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_archive_part()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE parent control.evidence_runtime_artifact_archive; expected text; count_parts integer;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1' THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT parent FROM control.evidence_runtime_artifact_archive WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND record_id=NEW.manifest_record_id;
 count_parts:=jsonb_array_length(parent.manifest->'chunks');
 expected:=CASE WHEN NEW.ordinal=count_parts THEN parent.record_id ELSE parent.manifest->'chunks'->NEW.ordinal->>'recordId' END;
 IF expected IS NULL OR NEW.record_id IS DISTINCT FROM expected OR NEW.ordinal<0 OR NEW.ordinal>count_parts THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_runtime_artifact_archive_part() FROM PUBLIC;
DROP TRIGGER IF EXISTS runtime_artifact_archive_part_guard ON control.evidence_runtime_artifact_archive_part;
CREATE TRIGGER runtime_artifact_archive_part_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_runtime_artifact_archive_part
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_artifact_archive_part();

CREATE OR REPLACE FUNCTION openpc.runtime_artifact_archive_hold_metadata(source control.evidence_catalogue)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE identity jsonb;
BEGIN
 SELECT a.manifest->'identity' INTO STRICT identity FROM control.evidence_runtime_artifact_archive a
  JOIN control.evidence_runtime_artifact_archive_part part ON part.participant_id=a.participant_id AND part.privacy_domain_id=a.privacy_domain_id
   AND part.stream_id=a.stream_id AND part.manifest_record_id=a.record_id
  JOIN control.evidence_catalogue c ON c.participant_id=part.participant_id AND c.privacy_domain_id=part.privacy_domain_id
   AND c.stream_id=part.stream_id AND c.record_id=part.record_id
  WHERE c IS NOT DISTINCT FROM source AND a.manifest_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(a.manifest),'UTF8')),'hex');
 -- Module configuration is not a runtime generation. Preserve unknown
 -- cross-owner lineage; metadata cannot declare those references absent.
 RETURN jsonb_build_object('unresolvedReferences',true);
EXCEPTION WHEN no_data_found OR too_many_rows OR insufficient_privilege THEN RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.runtime_artifact_archive_hold_metadata(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_artifact_archive_hold_metadata(control.evidence_catalogue)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.runtime_artifact_archive_coverage(pid uuid,privacy uuid,stream text,record_ref text,sinks text[])
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.evidence_runtime_artifact_archive; object record; checkpoint control.evidence_checkpoint;
 sink text; receipts jsonb; objects jsonb:='[]'; original_count integer; pending jsonb;
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF pid IS DISTINCT FROM openpc.current_participant_id() OR privacy IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR sinks IS NULL OR cardinality(sinks) NOT BETWEEN 1 AND 8 OR array_position(sinks,NULL) IS NOT NULL
  OR cardinality(sinks)<>(SELECT count(DISTINCT value) FROM unnest(sinks) value)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT a FROM control.evidence_runtime_artifact_archive WHERE participant_id=pid
  AND privacy_domain_id=privacy AND stream_id=stream AND record_id=record_ref;
 pending:=jsonb_build_object('state','PENDING','authority','NONE','manifestDigest',a.manifest_digest);
 SELECT count(*) INTO original_count FROM control.evidence_runtime_artifact_archive_part part
  JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
  WHERE part.participant_id=pid AND part.privacy_domain_id=privacy AND part.stream_id=stream AND part.manifest_record_id=record_ref;
 IF original_count<>jsonb_array_length(a.manifest->'chunks')+1 THEN RETURN pending; END IF;
 FOR object IN SELECT DISTINCT s.segment_id,s.object_digest,s.first_sequence,s.through_sequence
  FROM control.evidence_runtime_artifact_archive_part part JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
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
REVOKE ALL ON FUNCTION openpc.runtime_artifact_archive_coverage(uuid,uuid,text,text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_artifact_archive_coverage(uuid,uuid,text,text,text[])
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
`;
