const admission = (profileBound) => {
  const name = profileBound ? 'commit_fleet_fact_admission_v2' : 'commit_fleet_fact_admission';
  const parameters = profileBound
    ? 'material bytea,nonce bytea,mac bytea,wanted_profile text'
    : 'material bytea,nonce bytea,mac bytea';
  const signature = profileBound ? 'bytea,bytea,bytea,text' : 'bytea,bytea,bytea';
  return `
CREATE OR REPLACE FUNCTION openpc.${name}(${parameters})
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE m jsonb; e jsonb; p uuid; d uuid; c uuid; g uuid; event uuid; kind text; n numeric;
 secret bytea; expected bytea; different integer:=0; prior bytea; head numeric;
${profileBound ? ' installed control.fact_consumer_profile; pending control.fleet_fact_delivery; expected_pending jsonb; lease uuid;' : ''}
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF material IS NULL OR nonce IS NULL OR mac IS NULL
  OR current_setting('openpc.action_intent_id')<>'ACT-OPERATIONS_READ_OPERATION-V1'
  OR octet_length(material) NOT BETWEEN 1 AND 16384 OR octet_length(nonce)<>32 OR octet_length(mac)<>32
${profileBound ? "  OR coalesce(wanted_profile,'')!~'^sha256:[0-9a-f]{64}$'" : ''}
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.fleet_fact_admission_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to('OPENPC_FLEET_FACT_ADMISSION_V${profileBound ? 2 : 1}','UTF8')||${profileBound ? "decode(substring(wanted_profile from 8),'hex')||" : ''}sha256(material)||nonce,secret,'sha256');
 FOR i IN 0..31 LOOP different:=different | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 m:=convert_from(material,'UTF8')::jsonb;
 p:=(m->>'participantId')::uuid; d:=(m->>'privacyDomainId')::uuid;
 c:=(m->>'candidateId')::uuid; g:=(m->>'generationId')::uuid;
 e:=m->'envelope'; event:=(e->>'id')::uuid; kind:=m->>'factType'; n:=(m->>'sequence')::numeric;
 IF p IS DISTINCT FROM openpc.current_participant_id() OR d IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR m IS DISTINCT FROM jsonb_build_object('participantId',p::text,'privacyDomainId',d::text,
    'candidateId',c::text,'generationId',g::text,'factType',kind,'sequence',n::text,'envelope',e,
    'factDigest',m->>'factDigest','signedFactDigest',m->>'signedFactDigest','consumerId','LS-FLEET-CONTROL')
  OR convert_from(material,'UTF8') IS DISTINCT FROM openpc.signing_canonical_json(m)
  OR e->>'subject' IS DISTINCT FROM 'urn:openpc:resource:'||c::text
  OR e->>'participantid' IS DISTINCT FROM 'urn:openpc:participant:'||p::text
  OR e->>'privacydomainid' IS DISTINCT FROM 'urn:openpc:privacy-domain:'||d::text
  OR e->>'source' IS DISTINCT FROM 'urn:openpc:service:LS-FACT-BRIDGE'
  OR e->>'type' IS DISTINCT FROM 'io.openpc.fact.candidate.admitted.v1'
  OR e->>'sequence' IS DISTINCT FROM n::text
 THEN RAISE EXCEPTION 'DATA-6021-FLEET-FACT-BINDING'; END IF;
${profileBound ? " PERFORM pg_advisory_xact_lock_shared(hashtextextended('fact-consumer-profile:'||p::text||':'||d::text||':LS-FLEET-CONTROL',0));" : ''}
 INSERT INTO control.fleet_fact_admission_cursor(participant_id,privacy_domain_id,fact_type)
  VALUES(p,d,kind) ON CONFLICT DO NOTHING;
 SELECT sequence INTO STRICT head FROM control.fleet_fact_admission_cursor
  WHERE participant_id=p AND privacy_domain_id=d AND fact_type=kind FOR UPDATE;
 SELECT i.material INTO prior FROM control.fleet_fact_admission_inbox i
  WHERE i.participant_id=p AND i.privacy_domain_id=d AND i.event_id=event;
 IF FOUND THEN
  IF prior<>material THEN RAISE EXCEPTION 'DATA-6021-FLEET-FACT-CONFLICT'; END IF;
  RETURN false;
 END IF;
 ${
   profileBound
     ? `installed:=openpc.require_fact_consumer_profile('LS-FLEET-CONTROL');
 IF installed.profile_digest IS DISTINCT FROM wanted_profile THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 lease:=encode(substring(nonce from 1 for 16),'hex')::uuid;
 SELECT * INTO STRICT pending FROM control.fleet_fact_delivery WHERE participant_id=p AND privacy_domain_id=d AND event_id=event FOR UPDATE;
 expected_pending:=jsonb_build_object('participantId',p::text,'privacyDomainId',d::text,'eventId',event::text,
  'candidateId',c::text,'generationId',g::text,'factType',kind,'sequence',n::text,'consumerId','LS-FLEET-CONTROL',
  'envelope',e,'envelopeDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(e),'UTF8')),'hex'),
  'dataDigest',e->>'datadigest');
 IF pending.state<>'LEASED' OR pending.lease_id IS DISTINCT FROM lease
  OR convert_from(pending.material,'UTF8')::jsonb IS DISTINCT FROM expected_pending
  OR NOT EXISTS(SELECT 1 FROM control.fleet_fact_delivery_attempt a WHERE a.participant_id=p AND a.privacy_domain_id=d
   AND a.event_id=event AND a.lease_id=lease AND a.profile_digest=wanted_profile AND a.outcome='ACTIVE')
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM openpc.close_fleet_delivery_lease(event,lease,'COMMITTED',NULL);`
     : "RAISE EXCEPTION 'PC-AUTH-0005'; -- V1 remains exact historical replay only."
 }
 IF n<>head+1 THEN RAISE EXCEPTION 'DATA-6021-FLEET-FACT-GAP'; END IF;
 INSERT INTO control.fleet_fact_admission_inbox(participant_id,privacy_domain_id,event_id,candidate_id,generation_id,
  fact_type,sequence,fact_digest,signed_fact_digest,material,material_digest,commit_nonce,consumer_profile_digest)
 VALUES(p,d,event,c,g,kind,n,m->>'factDigest',m->>'signedFactDigest',material,sha256(material),nonce,${profileBound ? 'wanted_profile' : 'NULL'});
 UPDATE control.fleet_fact_admission_cursor SET sequence=n WHERE participant_id=p AND privacy_domain_id=d AND fact_type=kind;
 RETURN true;
END $$;
ALTER FUNCTION openpc.${name}(${signature}) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.${name}(${signature}) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.${name}(${signature}) TO openpc_control_worker;
`;
};

export const fleetFactGuardsSql = `
ALTER TABLE control.fleet_fact_admission_inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE control.fleet_fact_admission_cursor FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.fleet_fact_admission_key,control.fleet_fact_admission_inbox,control.fleet_fact_admission_cursor
 FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.fleet_fact_admission_inbox,control.fleet_fact_admission_cursor TO openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.fleet_fact_admission_key TO openpc_control_owner;
GRANT SELECT,INSERT ON control.fleet_fact_admission_inbox TO openpc_control_owner;
GRANT SELECT,INSERT,UPDATE ON control.fleet_fact_admission_cursor TO openpc_control_owner;
DROP POLICY IF EXISTS fleet_fact_native_owner ON control.fleet_fact_admission_inbox;
CREATE POLICY fleet_fact_native_owner ON control.fleet_fact_admission_inbox TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
DROP POLICY IF EXISTS fleet_fact_native_owner ON control.fleet_fact_admission_cursor;
CREATE POLICY fleet_fact_native_owner ON control.fleet_fact_admission_cursor TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));

${admission(false)}
${admission(true)}
`;
