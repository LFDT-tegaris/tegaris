/** Transport attempt journal. No remote observation grants local deletion,
 * signed custody, checkpoint advancement, or external WORM qualification. */
export const remoteArchiveGuardsSql = `
ALTER TABLE control.evidence_remote_archive_intent FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_remote_archive_attempt FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_remote_archive_intent,control.evidence_remote_archive_attempt FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_remote_archive_intent,control.evidence_remote_archive_attempt TO openpc_control_worker,openpc_control_runtime,openpc_control_reader;
GRANT INSERT ON control.evidence_remote_archive_intent TO openpc_control_worker;
GRANT INSERT,UPDATE ON control.evidence_remote_archive_attempt TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.remote_archive_rules(pid uuid,privacy uuid,stream text,segment uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT coalesce(jsonb_agg(jsonb_build_object('holdId',h.retention_hold_id::text,
  'selectorDigest',h.selector_digest,'creationOperationId',h.creation_operation_id::text,
  'releaseOperationId',h.release_operation_id::text,'state',h.state,'revision',h.revision::text)
  ORDER BY h.retention_hold_id),'[]'::jsonb)
 FROM control.retention_hold h WHERE h.participant_id=pid
  AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=privacy)
  AND openpc.evidence_hold_requires_coverage(h,stream,segment)
$$;
REVOKE ALL ON FUNCTION openpc.remote_archive_rules(uuid,uuid,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.remote_archive_rules(uuid,uuid,text,uuid) TO openpc_control_worker,openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.remote_archive_rules(s control.evidence_segment)
RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT openpc.remote_archive_rules((s).participant_id,(s).privacy_domain_id,(s).stream_id,(s).segment_id)
$$;
REVOKE ALL ON FUNCTION openpc.remote_archive_rules(control.evidence_segment) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.remote_archive_rules(control.evidence_segment) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_remote_archive_intent()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.evidence_segment; payload bytea; object jsonb; expected jsonb; rules jsonb; p jsonb; admitted record; facts jsonb; payload_digest text; payload_size integer;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','USAGE')
  OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 p:=NEW.profile;
 admitted:=openpc.require_archive_profile(current_setting('openpc.archive_profile_digest',true),NEW.stream_id);
 IF admitted.transport_digest IS DISTINCT FROM NEW.profile_digest OR admitted.transport IS DISTINCT FROM p
  OR admitted.sink_id IS DISTINCT FROM NEW.sink_id
  OR coalesce(admitted.claims->>'sourceKind','SEGMENT') IS DISTINCT FROM NEW.source_kind THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 expected:=jsonb_build_object('profileId',p->>'profileId','sinkId',NEW.sink_id,
  'endpoint',p->>'endpoint','transport',p->>'transport','region',p->>'region',
  'bucket',p->>'bucket','expectedBucketOwner',p->>'expectedBucketOwner','prefix',p->>'prefix',
  'lockMode','COMPLIANCE','requestTimeoutMs',p->'requestTimeoutMs','maxVersionPages',p->'maxVersionPages');
 IF p IS DISTINCT FROM expected
  OR NEW.profile_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex')
  OR coalesce(p->>'profileId','')!~'^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$'
  OR NEW.sink_id!~'^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$'
  OR coalesce(p->>'region','')!~'^[a-z0-9-]{1,63}$'
  OR coalesce(p->>'bucket','')!~'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'
  OR coalesce(p->>'prefix','')!~'^[a-zA-Z0-9_-]{1,64}$'
  OR coalesce(p->>'expectedBucketOwner','')!~'^[0-9]{12}$'
  OR jsonb_typeof(p->'requestTimeoutMs') IS DISTINCT FROM 'number'
  OR jsonb_typeof(p->'maxVersionPages') IS DISTINCT FROM 'number'
  OR coalesce(p->>'requestTimeoutMs','')!~'^[0-9]+$'
  OR coalesce(p->>'maxVersionPages','')!~'^[0-9]+$'
  OR (p->>'requestTimeoutMs')::numeric NOT BETWEEN 100 AND 30000
  OR (p->>'maxVersionPages')::numeric NOT BETWEEN 1 AND 32
  OR NOT coalesce((p->>'transport'='HTTPS' AND p->>'endpoint'~'^https://[^/@?#[:space:]]+/?$')
   OR (p->>'transport'='LOOPBACK_TEST' AND p->>'endpoint'~'^http://127[.]0[.]0[.]1(:[0-9]{1,5})?/?$'),false)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 IF NEW.source_kind='SEGMENT' THEN
 SELECT * INTO STRICT s FROM control.evidence_segment WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND segment_id=NEW.segment_id;
 SELECT encrypted_segment INTO STRICT payload FROM control.evidence_segment_payload
  WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id
   AND stream_id=s.stream_id AND segment_id=s.segment_id;
 rules:=openpc.remote_archive_rules(s);
 IF jsonb_array_length(rules)>1024 OR s.object_digest<>'sha256:'||encode(sha256(payload),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 object:=jsonb_build_object('sinkId',NEW.sink_id,'participantId',s.participant_id::text,
  'privacyDomainId',s.privacy_domain_id::text,'streamId',s.stream_id,'segmentId',s.segment_id::text,
  'firstSequence',s.first_sequence::text,'throughSequence',s.through_sequence::text,
  'previousSegmentDigest',s.previous_segment_digest,'objectDigest',s.object_digest,'keyId',s.key_id,
  'retentionUntil',to_char(s.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  payload_digest:=s.object_digest; payload_size:=octet_length(payload);
 ELSIF NEW.source_kind='PROTECTED_PROOF' THEN
  facts:=openpc.protected_remote_archive_source(NEW.participant_id,NEW.privacy_domain_id,NEW.protected_object_id,NEW.sink_id);
  IF facts->>'state' IS DISTINCT FROM 'BOUND' OR facts->'packet'='null'::jsonb
   OR facts->'lineage'->>'streamId' IS DISTINCT FROM NEW.stream_id
   OR (facts->'object'->>'retainUntil')::timestamptz<=clock_timestamp()
   OR (facts->'object'->>'objectVersion')::numeric IS DISTINCT FROM NEW.protected_object_version
   OR facts->'object'->>'objectDigest' IS DISTINCT FROM NEW.protected_object_digest
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  object:=facts->'object'; rules:=facts->'rules';
  payload_digest:=object->>'payloadDigest'; payload_size:=(facts->>'payloadBytes')::integer;
 ELSE RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 expected:=jsonb_build_object('intentId',NEW.intent_id::text,'profileDigest',NEW.profile_digest,
  'source',jsonb_build_object('kind',NEW.source_kind,'object',object),'payloadDigest',payload_digest,
  'payloadBytes',payload_size,'initialProtection',jsonb_build_object('revision','1','rules',rules));
 IF NEW.intent IS DISTINCT FROM expected
  OR NEW.intent_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.created_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_remote_archive_intent_guard ON control.evidence_remote_archive_intent;
CREATE TRIGGER evidence_remote_archive_intent_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_remote_archive_intent
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_remote_archive_intent();

CREATE OR REPLACE FUNCTION openpc.guard_remote_archive_attempt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE i control.evidence_remote_archive_intent; s control.evidence_segment;
 expected jsonb; prior jsonb; rules jsonb; protection jsonb; locator jsonb; observation jsonb;
 object_key text; legal_hold text; deadline text; version_id text; admitted record; facts jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','USAGE')
  OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 SELECT * INTO STRICT i FROM control.evidence_remote_archive_intent WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND intent_id=NEW.intent_id;
 admitted:=openpc.require_archive_profile(current_setting('openpc.archive_profile_digest',true),i.stream_id);
 IF admitted.transport_digest IS DISTINCT FROM i.profile_digest OR admitted.transport IS DISTINCT FROM i.profile
  OR admitted.sink_id IS DISTINCT FROM i.sink_id
  OR coalesce(admitted.claims->>'sourceKind','SEGMENT') IS DISTINCT FROM i.source_kind THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'STARTED' OR NEW.observation IS NOT NULL OR NEW.observation_digest IS NOT NULL
   OR EXISTS(SELECT 1 FROM control.evidence_remote_archive_attempt a WHERE a.participant_id=i.participant_id
    AND a.privacy_domain_id=i.privacy_domain_id AND a.intent_id=i.intent_id AND a.state IN ('STARTED','AMBIGUOUS'))
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  IF i.source_kind='SEGMENT' THEN
  SELECT * INTO STRICT s FROM control.evidence_segment WHERE participant_id=i.participant_id
   AND privacy_domain_id=i.privacy_domain_id AND stream_id=i.stream_id AND segment_id=i.segment_id;
  rules:=openpc.remote_archive_rules(s);
  ELSE
   facts:=openpc.protected_remote_archive_source(i.participant_id,i.privacy_domain_id,i.protected_object_id,i.sink_id,i.intent_id);
   IF facts->>'state' IS DISTINCT FROM 'BOUND' OR facts->'object' IS DISTINCT FROM i.intent->'source'->'object'
    OR facts->'lineage'->>'streamId' IS DISTINCT FROM i.stream_id
    OR (NEW.action='PUT' AND (facts->'packet'='null'::jsonb OR (facts->'object'->>'retainUntil')::timestamptz<=clock_timestamp()))
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   rules:=facts->'rules';
  END IF;
  IF jsonb_array_length(rules)>1024 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT a.binding->'protection' INTO prior FROM control.evidence_remote_archive_attempt a
   WHERE a.participant_id=i.participant_id AND a.privacy_domain_id=i.privacy_domain_id AND a.intent_id=i.intent_id
   ORDER BY (a.binding->'protection'->>'revision')::numeric DESC,a.attempt_id DESC LIMIT 1;
  prior:=coalesce(prior,i.intent->'initialProtection');
  protection:=jsonb_build_object('revision',CASE WHEN rules=prior->'rules' THEN prior->>'revision'
   ELSE ((prior->>'revision')::numeric+1)::text END,'rules',rules);
  IF (protection->>'revision')::numeric NOT BETWEEN 1 AND 18446744073709551615
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  IF NEW.action='PUT' THEN
   locator:='null'::jsonb;
   IF protection IS DISTINCT FROM i.intent->'initialProtection'
    OR EXISTS(SELECT 1 FROM control.evidence_remote_archive_attempt a WHERE a.participant_id=i.participant_id
     AND a.privacy_domain_id=i.privacy_domain_id AND a.intent_id=i.intent_id)
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSIF NEW.action='PROTECTION' THEN
   SELECT a.observation->'locator' INTO locator FROM control.evidence_remote_archive_attempt a
    WHERE a.participant_id=i.participant_id AND a.privacy_domain_id=i.privacy_domain_id
     AND a.intent_id=i.intent_id AND a.action='PUT' AND a.state='OBSERVED';
   IF locator IS NULL OR locator='null'::jsonb THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSE RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  expected:=jsonb_build_object('attemptId',NEW.attempt_id::text,'intent',i.intent,'intentDigest',i.intent_digest,
   'action',NEW.action,'locator',locator,'protection',protection,
   'protectionDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(protection),'UTF8')),'hex'));
  IF NEW.binding IS DISTINCT FROM expected OR NEW.protection_digest IS DISTINCT FROM expected->>'protectionDigest'
   OR NEW.binding_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex')
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.started_at:=clock_timestamp();
 ELSE
  IF OLD.state='OBSERVED' OR OLD.state NOT IN ('STARTED','AMBIGUOUS')
   OR NEW.state NOT IN ('AMBIGUOUS','OBSERVED')
   OR (to_jsonb(NEW)-ARRAY['state','observation','observation_digest','updated_at'])
      IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','observation','observation_digest','updated_at'])
  THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 END IF;
 IF NEW.state='OBSERVED' THEN
  observation:=NEW.observation;
  version_id:=observation->'locator'->>'versionId';
  deadline:=observation->'observedRetention'->>'retainUntil';
  IF coalesce(length(version_id),0) NOT BETWEEN 1 AND 1024 OR version_id='null'
   OR version_id~'[[:cntrl:][:space:]]'
   OR coalesce(deadline,'')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  IF i.source_kind='SEGMENT' THEN
  IF deadline::timestamptz < (i.intent->'source'->'object'->>'retentionUntil')::timestamptz
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  object_key:=(i.profile->>'prefix')||'/segment/'||encode(sha256(convert_to(openpc.signing_canonical_json(
   jsonb_build_object('sinkId',i.sink_id,'participantId',i.participant_id::text,
    'privacyDomainId',i.privacy_domain_id::text,'streamId',i.stream_id,'segmentId',i.segment_id::text)),'UTF8')),'hex');
  ELSE
   IF deadline::timestamptz IS DISTINCT FROM (i.intent->'source'->'object'->>'retainUntil')::timestamptz
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   object_key:=(i.profile->>'prefix')||'/proof/'||encode(sha256(convert_to(openpc.signing_canonical_json(
    jsonb_build_object('sinkId',i.sink_id,'participantId',i.participant_id::text,
     'privacyDomainId',i.privacy_domain_id::text,'objectRef','urn:openpc:resource:'||i.protected_object_id::text,
     'objectVersion',i.protected_object_version::text)),'UTF8')),'hex');
  END IF;
  locator:=jsonb_build_object('sinkId',i.sink_id,'profileDigest',i.profile_digest,
   'bucket',i.profile->>'bucket','key',object_key,'versionId',version_id);
  SELECT CASE WHEN EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.binding->'protection'->'rules') rule
   WHERE rule->>'state'='ACTIVE') THEN 'ON' ELSE 'OFF' END INTO legal_hold;
  expected:=jsonb_build_object('version','OPENPC_REMOTE_ARCHIVE_RECEIPT_V1',
   'intent',i.intent,'intentDigest',i.intent_digest,'locator',locator,
   'assurance','REMOTE_INTERFACE_VERIFIED','providerQualification','NOT_ESTABLISHED',
   'observedRetention',jsonb_build_object('mode','COMPLIANCE','retainUntil',deadline),
   'protection',NEW.binding->'protection','protectionDigest',NEW.protection_digest,
   'observedLegalHold',legal_hold);
  expected:=expected||jsonb_build_object('receiptDigest',
   'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex'));
  IF observation IS DISTINCT FROM expected
   OR NEW.observation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(observation),'UTF8')),'hex')
   OR (NEW.binding->'locator'<>'null'::jsonb AND observation->'locator' IS DISTINCT FROM NEW.binding->'locator')
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END IF;
 NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_remote_archive_attempt_guard ON control.evidence_remote_archive_attempt;
CREATE TRIGGER evidence_remote_archive_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_remote_archive_attempt
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_remote_archive_attempt();
`;
