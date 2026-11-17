/** Native owner capabilities bind original transport bytes independently from
 * source verification. No lease/failure/quarantine state grants Fact use. */
export const fleetDeliveryGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.verify_fleet_delivery_capability(material bytea,nonce bytea,mac bytea,profile_digest text,purpose text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE secret bytea; expected bytea; difference integer:=0; value jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF material IS NULL OR nonce IS NULL OR mac IS NULL OR octet_length(material) NOT BETWEEN 1 AND 65536
  OR octet_length(nonce)<>32 OR octet_length(mac)<>32 OR coalesce(profile_digest,'')!~'^sha256:[0-9a-f]{64}$'
  OR openpc.current_action_intent_id()<>'ACT-OPERATIONS_READ_OPERATION-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.fleet_fact_admission_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to(purpose,'UTF8')||decode(substring(profile_digest from 8),'hex')||sha256(material)||nonce,secret,'sha256');
 FOR i IN 0..31 LOOP difference:=difference | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
 IF difference<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 value:=convert_from(material,'UTF8')::jsonb;
 IF convert_from(material,'UTF8') IS DISTINCT FROM openpc.signing_canonical_json(value)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN value;
END $$;
ALTER FUNCTION openpc.verify_fleet_delivery_capability(bytea,bytea,bytea,text,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.verify_fleet_delivery_capability(bytea,bytea,bytea,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.fleet_delivery_retry_delay(failures integer,initial_ms integer,maximum_ms integer)
RETURNS bigint LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT least(maximum_ms::bigint,initial_ms::bigint*(1::bigint<<least(greatest(failures-1,0),32)))
$$;

CREATE OR REPLACE FUNCTION openpc.close_fleet_delivery_lease(wanted_event uuid,wanted_lease uuid,result text,problem text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d control.fleet_fact_delivery; a control.fleet_fact_delivery_attempt; now_ms numeric; failures integer; next_state text;
BEGIN
 SELECT * INTO STRICT d FROM control.fleet_fact_delivery WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=wanted_event FOR UPDATE;
 SELECT * INTO STRICT a FROM control.fleet_fact_delivery_attempt WHERE participant_id=d.participant_id
  AND privacy_domain_id=d.privacy_domain_id AND event_id=d.event_id AND lease_id=wanted_lease;
 IF a.outcome<>'ACTIVE' THEN
  IF a.outcome IS DISTINCT FROM result OR a.problem IS DISTINCT FROM problem THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  RETURN d.state;
 END IF;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF d.state<>'LEASED' OR d.lease_id IS DISTINCT FROM wanted_lease
  OR result NOT IN ('FAILED','LEASE_EXPIRED','CAPACITY_RELEASE','UNAVAILABLE_RELEASE','COMMITTED')
  OR (result='LEASE_EXPIRED' AND d.lease_until_ms>now_ms)
  OR (result<>'LEASE_EXPIRED' AND d.lease_until_ms<=now_ms)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 failures:=d.failed_attempts+CASE WHEN result IN ('FAILED','LEASE_EXPIRED') THEN 1 ELSE 0 END;
 next_state:=CASE WHEN result='COMMITTED' THEN 'COMMITTED' WHEN failures>=d.maximum_attempts THEN 'EXHAUSTED' ELSE 'WAITING' END;
 UPDATE control.fleet_fact_delivery_attempt SET outcome=result,ended_at_ms=now_ms,problem=close_fleet_delivery_lease.problem
  WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=d.event_id AND lease_id=wanted_lease;
 UPDATE control.fleet_fact_delivery SET failed_attempts=failures,state=next_state,lease_id=NULL,lease_until_ms=NULL,
  next_attempt_ms=now_ms+openpc.fleet_delivery_retry_delay(failures,d.initial_backoff_ms,d.maximum_backoff_ms),last_problem=problem
  WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=d.event_id;
 RETURN next_state;
END $$;
ALTER FUNCTION openpc.close_fleet_delivery_lease(uuid,uuid,text,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.close_fleet_delivery_lease(uuid,uuid,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.begin_fleet_fact_delivery(material bytea,nonce bytea,mac bytea,wanted_profile text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE request jsonb; e jsonb; p uuid; v uuid; event uuid; candidate uuid; generation uuid; lease uuid; kind text;
 n numeric; head numeric; now_ms numeric; until_ms numeric; original bytea;
 profile control.fact_consumer_profile; d control.fleet_fact_delivery;
BEGIN
 request:=openpc.verify_fleet_delivery_capability(material,nonce,mac,wanted_profile,'OPENPC_FLEET_FACT_DELIVERY_BEGIN_V1');
 e:=request->'event'; lease:=(request->>'leaseId')::uuid;
 p:=(e->>'participantId')::uuid; v:=(e->>'privacyDomainId')::uuid; event:=(e->>'eventId')::uuid;
 candidate:=(e->>'candidateId')::uuid; generation:=(e->>'generationId')::uuid;
 kind:=e->>'factType'; n:=(e->>'sequence')::numeric;
 IF request IS DISTINCT FROM jsonb_build_object('event',e,'leaseId',lease::text)
  OR p IS DISTINCT FROM openpc.current_participant_id() OR v IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR e IS DISTINCT FROM jsonb_build_object('participantId',p::text,'privacyDomainId',v::text,'eventId',event::text,
    'candidateId',candidate::text,'generationId',generation::text,'factType',kind,'sequence',n::text,
    'consumerId','LS-FLEET-CONTROL','envelope',e->'envelope','envelopeDigest',e->>'envelopeDigest','dataDigest',e->>'dataDigest')
  OR lease IS NULL OR substring(lease::text from 15 for 1)<>'7'
  OR kind NOT IN ('CONTRACT_STATE_CALL','RELATIONSHIP','EXTERNAL_DECISION') OR n<1 OR n>9223372036854775807
  OR e->>'envelopeDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(e->'envelope'),'UTF8')),'hex')
  OR coalesce(e->>'dataDigest','')!~'^sha256:[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 profile:=openpc.require_fact_consumer_profile('LS-FLEET-CONTROL');
 IF profile.profile_digest IS DISTINCT FROM wanted_profile THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 INSERT INTO control.fleet_fact_admission_cursor(participant_id,privacy_domain_id,fact_type) VALUES(p,v,kind) ON CONFLICT DO NOTHING;
 SELECT sequence INTO STRICT head FROM control.fleet_fact_admission_cursor WHERE participant_id=p AND privacy_domain_id=v AND fact_type=kind FOR UPDATE;
 IF n<=head THEN
  IF EXISTS(SELECT 1 FROM control.fleet_fact_admission_inbox i WHERE i.participant_id=p AND i.privacy_domain_id=v
    AND i.event_id=event AND i.candidate_id=candidate AND i.generation_id=generation AND i.fact_type=kind AND i.sequence=n
    AND convert_from(i.material,'UTF8')::jsonb->'envelope'=e->'envelope')
  THEN RETURN jsonb_build_object('state','COMMITTED'); END IF;
  RAISE EXCEPTION 'PC-DATA-6007';
 END IF;
 IF n<>head+1 THEN RAISE EXCEPTION 'DATA-6021-FLEET-FACT-GAP'; END IF;
 original:=convert_to(openpc.signing_canonical_json(e),'UTF8');
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 INSERT INTO control.fleet_fact_delivery(participant_id,privacy_domain_id,event_id,candidate_id,generation_id,fact_type,sequence,
  material,material_digest,initial_profile_digest,maximum_attempts,initial_backoff_ms,maximum_backoff_ms,next_attempt_ms)
 VALUES(p,v,event,candidate,generation,kind,n,original,sha256(original),wanted_profile,
  (profile.claims->>'maximumAttempts')::integer,(profile.claims->>'initialBackoffMs')::integer,
  (profile.claims->>'maximumBackoffMs')::integer,now_ms) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT d FROM control.fleet_fact_delivery WHERE participant_id=p AND privacy_domain_id=v AND event_id=event FOR UPDATE;
 IF d.material IS DISTINCT FROM original THEN RAISE EXCEPTION 'DATA-6021-FLEET-FACT-CONFLICT'; END IF;
 IF d.state='LEASED' THEN
  IF d.lease_until_ms<=now_ms THEN
   PERFORM openpc.close_fleet_delivery_lease(event,d.lease_id,'LEASE_EXPIRED','PC-DATA-6005');
   SELECT * INTO STRICT d FROM control.fleet_fact_delivery WHERE participant_id=p AND privacy_domain_id=v AND event_id=event;
  ELSIF d.lease_id=lease THEN
   RETURN jsonb_build_object('state','LEASED','leaseId',lease::text,'leaseUntilMs',d.lease_until_ms::text);
  ELSE RETURN jsonb_build_object('state','BUSY'); END IF;
 END IF;
 IF d.state='WAITING' AND (profile.claims->>'maximumAttempts')::integer<d.maximum_attempts THEN
  UPDATE control.fleet_fact_delivery SET maximum_attempts=greatest(d.failed_attempts,(profile.claims->>'maximumAttempts')::integer),
   state=CASE WHEN d.failed_attempts>=(profile.claims->>'maximumAttempts')::integer THEN 'EXHAUSTED' ELSE 'WAITING' END
   WHERE participant_id=p AND privacy_domain_id=v AND event_id=event;
  SELECT * INTO STRICT d FROM control.fleet_fact_delivery WHERE participant_id=p AND privacy_domain_id=v AND event_id=event;
 END IF;
 IF d.state IN ('EXHAUSTED','QUARANTINED','COMMITTED') THEN RETURN jsonb_build_object('state',d.state); END IF;
 IF d.next_attempt_ms>now_ms THEN RETURN jsonb_build_object('state','WAITING','nextAttemptMs',d.next_attempt_ms::text); END IF;
 until_ms:=least(now_ms+30000,(profile.claims->>'validUntilMs')::numeric);
 INSERT INTO control.fleet_fact_delivery_attempt(participant_id,privacy_domain_id,event_id,lease_generation,lease_id,profile_digest,started_at_ms,lease_until_ms)
 VALUES(p,v,event,d.lease_generation+1,lease,wanted_profile,now_ms,until_ms);
 UPDATE control.fleet_fact_delivery SET state='LEASED',lease_id=lease,lease_until_ms=until_ms,lease_generation=d.lease_generation+1
 WHERE participant_id=p AND privacy_domain_id=v AND event_id=event;
 RETURN jsonb_build_object('state','LEASED','leaseId',lease::text,'leaseUntilMs',until_ms::text);
END $$;
ALTER FUNCTION openpc.begin_fleet_fact_delivery(bytea,bytea,bytea,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.begin_fleet_fact_delivery(bytea,bytea,bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.begin_fleet_fact_delivery(bytea,bytea,bytea,text) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.fail_fleet_fact_delivery(material bytea,nonce bytea,mac bytea,wanted_profile text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE request jsonb; p uuid; v uuid; event uuid; lease uuid; result text; problem text; profile control.fact_consumer_profile;
BEGIN
 request:=openpc.verify_fleet_delivery_capability(material,nonce,mac,wanted_profile,'OPENPC_FLEET_FACT_DELIVERY_FAIL_V1');
 p:=(request->>'participantId')::uuid; v:=(request->>'privacyDomainId')::uuid;
 event:=(request->>'eventId')::uuid; lease:=(request->>'leaseId')::uuid;
 result:=request->>'outcome'; problem:=request->>'problem';
 IF request IS DISTINCT FROM jsonb_build_object('participantId',p::text,'privacyDomainId',v::text,'eventId',event::text,'leaseId',lease::text,'outcome',result,'problem',problem)
  OR p IS DISTINCT FROM openpc.current_participant_id() OR v IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR result IS NULL OR problem IS NULL OR result NOT IN ('FAILED','CAPACITY_RELEASE','UNAVAILABLE_RELEASE') OR problem<>'PC-DATA-6005'
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 profile:=openpc.require_fact_consumer_profile('LS-FLEET-CONTROL');
 IF profile.profile_digest IS DISTINCT FROM wanted_profile THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM 1 FROM control.fleet_fact_delivery_attempt WHERE participant_id=p AND privacy_domain_id=v AND event_id=event
  AND lease_id=lease AND profile_digest=wanted_profile;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 RETURN openpc.close_fleet_delivery_lease(event,lease,result,problem);
END $$;
ALTER FUNCTION openpc.fail_fleet_fact_delivery(bytea,bytea,bytea,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.fail_fleet_fact_delivery(bytea,bytea,bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.fail_fleet_fact_delivery(bytea,bytea,bytea,text) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_fleet_delivery_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_OP='UPDATE' THEN
  IF TG_TABLE_NAME='fleet_fact_delivery_attempt' THEN
   IF OLD.outcome<>'ACTIVE' OR NEW.outcome='ACTIVE'
    OR to_jsonb(NEW)-ARRAY['outcome','ended_at_ms','problem'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['outcome','ended_at_ms','problem']
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSE
   IF to_jsonb(NEW)-ARRAY['failed_attempts','lease_generation','state','lease_id','lease_until_ms','next_attempt_ms','last_problem','maximum_attempts']
    IS DISTINCT FROM to_jsonb(OLD)-ARRAY['failed_attempts','lease_generation','state','lease_id','lease_until_ms','next_attempt_ms','last_problem','maximum_attempts']
    OR NEW.maximum_attempts>OLD.maximum_attempts
    OR NEW.failed_attempts NOT BETWEEN OLD.failed_attempts AND OLD.failed_attempts+1
    OR NEW.lease_generation NOT BETWEEN OLD.lease_generation AND OLD.lease_generation+1
    OR OLD.state IN ('QUARANTINED','COMMITTED')
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;

${['fleet_fact_delivery', 'fleet_fact_delivery_attempt']
  .map(
    (table) => `
ALTER TABLE control.${table} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${table} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.${table} TO openpc_control_worker,openpc_control_reader;
GRANT SELECT,INSERT,UPDATE ON control.${table} TO openpc_control_owner;
DROP POLICY IF EXISTS fleet_delivery_owner ON control.${table};
CREATE POLICY fleet_delivery_owner ON control.${table} TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
DROP TRIGGER IF EXISTS fleet_delivery_history ON control.${table};
CREATE TRIGGER fleet_delivery_history BEFORE UPDATE OR DELETE ON control.${table}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_fleet_delivery_history();
`,
  )
  .join('\n')}
`;
