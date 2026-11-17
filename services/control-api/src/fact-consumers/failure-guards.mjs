import { factConsumerFailureContext as definition } from '../../../../packages/security-kernel/src/fact-consumer/failure-generated.ts';
import { factConsumerDatabaseRoleSql } from './database-role-sql.mjs';

/** Source-owned effect admission; no human mutation/session branch is relaxed. */
export const factConsumerFailureGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_fact_failure_signer()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT (current_user='openpc_control_owner' OR pg_has_role(current_user,'openpc_control_key_governor','USAGE'))
  OR TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED'
   OR to_jsonb(NEW)-'state' IS DISTINCT FROM to_jsonb(OLD)-'state'
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSE
  IF NEW.state<>'ACTIVE' OR NOT ${factConsumerDatabaseRoleSql('NEW.database_role', 'NEW.participant_id', 'NEW.privacy_domain_id')}
   OR NEW.environment_id!~'^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$'
   OR substring(NEW.workload_credential_id::text from 15 for 1)<>'7'
   OR encode(NEW.public_key_spki,'hex')!~'^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=NEW.database_role AND r.rolcanlogin
     AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole
     AND pg_has_role(r.rolname,'openpc_control_worker','USAGE')
     AND NOT pg_has_role(r.rolname,'openpc_control_owner','MEMBER')
     AND NOT pg_has_role(r.rolname,'openpc_control_key_governor','MEMBER'))
   OR NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal w USING(participant_id,principal_id)
     WHERE c.participant_id=NEW.participant_id AND c.credential_id=NEW.workload_credential_id
      AND c.credential_epoch=NEW.workload_credential_epoch AND c.kind IN ('WORKLOAD_MTLS','WORKLOAD_OIDC')
      AND c.state='ACTIVE' AND w.state='ACTIVE' AND w.kind='WORKLOAD'
      AND c.valid_from<=clock_timestamp() AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
      AND c.public_key_digest IS DISTINCT FROM sha256(NEW.public_key_spki))
   OR EXISTS(SELECT 1 FROM control.fact_consumer_profile p WHERE p.participant_id=NEW.participant_id
     AND p.privacy_domain_id=NEW.privacy_domain_id AND p.issuer_spki=NEW.public_key_spki)
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 END IF;
 RETURN NEW;
END $$;
ALTER TABLE control.fact_consumer_failure_signer FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.fact_consumer_failure_signer FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT,INSERT,UPDATE ON control.fact_consumer_failure_signer TO openpc_control_owner,openpc_control_key_governor;
GRANT SELECT ON control.fact_consumer_failure_signer TO openpc_control_worker;
DROP POLICY IF EXISTS fact_failure_signer_installation ON control.fact_consumer_failure_signer;
CREATE POLICY fact_failure_signer_installation ON control.fact_consumer_failure_signer TO openpc_control_owner,openpc_control_key_governor USING(true) WITH CHECK(true);
DROP TRIGGER IF EXISTS fact_failure_signer_installation ON control.fact_consumer_failure_signer;
CREATE TRIGGER fact_failure_signer_installation BEFORE INSERT OR UPDATE OR DELETE ON control.fact_consumer_failure_signer
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_fact_failure_signer();

CREATE OR REPLACE FUNCTION openpc.require_fact_failure_signer(p control.fact_consumer_profile,wanted_signer text)
RETURNS control.fact_consumer_failure_signer LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s control.fact_consumer_failure_signer; now_ms numeric;
BEGIN
 SELECT * INTO s FROM control.fact_consumer_failure_signer WHERE participant_id=p.participant_id
  AND privacy_domain_id=p.privacy_domain_id AND consumer_id=p.consumer_id AND state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF s.signer_key_id IS DISTINCT FROM wanted_signer OR s.environment_id IS DISTINCT FROM p.claims->>'environmentId'
  OR s.database_role IS DISTINCT FROM session_user OR s.database_role IS DISTINCT FROM p.database_role
  OR s.workload_credential_id IS DISTINCT FROM p.workload_credential_id OR s.workload_credential_epoch IS DISTINCT FROM p.workload_credential_epoch
  OR s.signer_role<>'FACT_CONSUMER_FAILURE' OR s.purpose_code<>${definition.purposeCode}
  OR now_ms<s.valid_from_ms OR now_ms>=s.valid_until_ms OR s.public_key_spki=p.issuer_spki
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 RETURN s;
END $$;
ALTER FUNCTION openpc.require_fact_failure_signer(control.fact_consumer_profile,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.require_fact_failure_signer(control.fact_consumer_profile,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.prepare_fleet_fact_quarantine(material bytea,nonce bytea,mac bytea,wanted_profile text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE request jsonb; d control.fleet_fact_delivery; q control.fleet_fact_quarantine;
 profile control.fact_consumer_profile; signer control.fact_consumer_failure_signer;
 actor uuid; now_ms numeric; claims jsonb; original jsonb;
BEGIN
 request:=openpc.verify_fleet_delivery_capability(material,nonce,mac,wanted_profile,'OPENPC_FLEET_FACT_FAILURE_PREPARE_V1');
 IF request IS DISTINCT FROM jsonb_build_object('participantId',openpc.current_participant_id()::text,
  'privacyDomainId',openpc.current_privacy_domain_id()::text,'eventId',(request->>'eventId')::uuid::text,'signerKeyId',request->>'signerKeyId')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 profile:=openpc.require_fact_consumer_profile('LS-FLEET-CONTROL');
 IF profile.profile_digest IS DISTINCT FROM wanted_profile THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO d FROM control.fleet_fact_delivery WHERE participant_id=profile.participant_id
  AND privacy_domain_id=profile.privacy_domain_id AND event_id=(request->>'eventId')::uuid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO q FROM control.fleet_fact_quarantine WHERE participant_id=d.participant_id
  AND privacy_domain_id=d.privacy_domain_id AND event_id=d.event_id FOR UPDATE;
 IF q.state='COMMITTED' THEN
  IF d.state<>'QUARANTINED' OR q.material_digest<>d.material_digest THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  RETURN jsonb_build_object('state','COMMITTED','receiptId',q.receipt_id,'workItemId',q.work_item_id,
    'payload',encode(q.payload,'hex'),'cose',encode(q.cose,'hex'),'receiptDigest',q.receipt_digest);
 END IF;
 IF q.event_id IS NOT NULL OR d.state<>'EXHAUSTED' OR d.failed_attempts<>d.maximum_attempts
  OR d.last_problem IS DISTINCT FROM 'PC-DATA-6005' OR d.lease_id IS NOT NULL
  OR EXISTS(SELECT 1 FROM control.fleet_fact_delivery_attempt a WHERE a.participant_id=d.participant_id
    AND a.privacy_domain_id=d.privacy_domain_id AND a.event_id=d.event_id AND a.outcome='ACTIVE')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 signer:=openpc.require_fact_failure_signer(profile,request->>'signerKeyId');
 SELECT principal_id INTO STRICT actor FROM control.credential WHERE participant_id=d.participant_id AND credential_id=profile.workload_credential_id;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000); original:=convert_from(d.material,'UTF8')::jsonb;
 claims:=jsonb_build_object('environmentId',profile.claims->'environmentId','participantId',d.participant_id::text,
  'privacyDomainId',d.privacy_domain_id::text,'consumerId','LS-FLEET-CONTROL',
  'subscriptionId','SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1','eventId',d.event_id::text,
  'candidateId',d.candidate_id::text,'generationId',d.generation_id::text,'factType',d.fact_type,'sequence',d.sequence::text,
  'envelopeDigest',original->'envelopeDigest','dataDigest',original->'dataDigest',
  'materialDigest','sha256:'||encode(d.material_digest,'hex'),'initialProfileDigest',d.initial_profile_digest,
  'currentProfileDigest',wanted_profile,'failedAttempts',d.failed_attempts,'maximumAttempts',d.maximum_attempts,
  'leaseGeneration',d.lease_generation::text,'workloadCredentialId',profile.workload_credential_id::text,
  'workloadCredentialEpoch',profile.workload_credential_epoch::text,'workloadPrincipalId',actor::text,
  'workItemId',uuidv7()::text,'problem','PC-DATA-6005','recordedAtMs',now_ms,'signerKeyId',signer.signer_key_id,'receiptId',uuidv7()::text);
 INSERT INTO control.fleet_fact_quarantine(participant_id,privacy_domain_id,event_id,receipt_id,work_item_id,material_digest,claims)
 VALUES(d.participant_id,d.privacy_domain_id,d.event_id,(claims->>'receiptId')::uuid,(claims->>'workItemId')::uuid,d.material_digest,claims);
 RETURN jsonb_build_object('state','PREPARED','claims',claims,'signerSpki',encode(signer.public_key_spki,'hex'));
END $$;
ALTER FUNCTION openpc.prepare_fleet_fact_quarantine(bytea,bytea,bytea,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.prepare_fleet_fact_quarantine(bytea,bytea,bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.prepare_fleet_fact_quarantine(bytea,bytea,bytea,text) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.commit_fleet_fact_quarantine(material bytea,nonce bytea,mac bytea,wanted_profile text)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE request jsonb; q control.fleet_fact_quarantine; d control.fleet_fact_delivery;
 profile control.fact_consumer_profile; signer control.fact_consumer_failure_signer;
 c jsonb; expected jsonb; signed_payload bytea; signed_cose bytea; now_ms numeric;
BEGIN
 request:=openpc.verify_fleet_delivery_capability(material,nonce,mac,wanted_profile,'OPENPC_FLEET_FACT_FAILURE_COMMIT_V1');
 IF request IS DISTINCT FROM jsonb_build_object('participantId',openpc.current_participant_id()::text,
  'privacyDomainId',openpc.current_privacy_domain_id()::text,'eventId',(request->>'eventId')::uuid::text,
  'payload',request->>'payload','cose',request->>'cose')
  OR coalesce(request->>'payload','')!~'^[0-9a-f]+$' OR coalesce(request->>'cose','')!~'^[0-9a-f]+$'
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 signed_payload:=decode(request->>'payload','hex'); signed_cose:=decode(request->>'cose','hex');
 SELECT * INTO d FROM control.fleet_fact_delivery WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=(request->>'eventId')::uuid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO q FROM control.fleet_fact_quarantine WHERE participant_id=d.participant_id
  AND privacy_domain_id=d.privacy_domain_id AND event_id=d.event_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF q.state='COMMITTED' THEN
  IF d.state<>'QUARANTINED' OR q.payload IS DISTINCT FROM signed_payload OR q.cose IS DISTINCT FROM signed_cose
   OR q.claims->>'currentProfileDigest' IS DISTINCT FROM wanted_profile
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  RETURN q.work_item_id;
 END IF;
 profile:=openpc.require_fact_consumer_profile('LS-FLEET-CONTROL');
 c:=q.claims; signer:=openpc.require_fact_failure_signer(profile,c->>'signerKeyId');
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF q.state<>'PREPARED' OR d.state<>'EXHAUSTED' OR q.material_digest<>d.material_digest
  OR profile.profile_digest IS DISTINCT FROM wanted_profile OR c->>'currentProfileDigest' IS DISTINCT FROM wanted_profile
  OR c->>'workloadCredentialId' IS DISTINCT FROM profile.workload_credential_id::text
  OR c->>'workloadCredentialEpoch' IS DISTINCT FROM profile.workload_credential_epoch::text
  OR c->>'failedAttempts' IS DISTINCT FROM d.failed_attempts::text OR c->>'maximumAttempts' IS DISTINCT FROM d.maximum_attempts::text
  OR c->>'leaseGeneration' IS DISTINCT FROM d.lease_generation::text OR d.lease_id IS NOT NULL
  OR d.failed_attempts<>d.maximum_attempts OR d.last_problem IS DISTINCT FROM 'PC-DATA-6005'
  OR (c->>'recordedAtMs')::numeric>now_ms OR now_ms-(c->>'recordedAtMs')::numeric>30000
  OR (c->>'recordedAtMs')::numeric<signer.valid_from_ms
  OR EXISTS(SELECT 1 FROM control.fleet_fact_delivery_attempt a WHERE a.participant_id=d.participant_id
   AND a.privacy_domain_id=d.privacy_domain_id AND a.event_id=d.event_id AND a.outcome='ACTIVE')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 expected:=jsonb_build_object(
  '0',openpc.business_bytes(decode('${definition.definitionDigest.slice(7)}','hex')),
  '1',c->'environmentId',
  '2',openpc.business_uuid(q.participant_id),
  '3',openpc.business_uuid(q.privacy_domain_id),
  '4',c->'consumerId',
  '5',c->'subscriptionId',
  '6',openpc.business_uuid((c->>'eventId')::uuid),
  '7',openpc.business_uuid((c->>'candidateId')::uuid),
  '8',openpc.business_uuid((c->>'generationId')::uuid),
  '9',c->'factType',
  '10',(c->>'sequence')::numeric,
  '11',openpc.business_bytes(decode(substring(c->>'envelopeDigest' from 8),'hex')),
  '12',openpc.business_bytes(decode(substring(c->>'dataDigest' from 8),'hex')),
  '13',openpc.business_bytes(decode(substring(c->>'materialDigest' from 8),'hex')),
  '14',openpc.business_bytes(decode(substring(c->>'initialProfileDigest' from 8),'hex')),
  '15',openpc.business_bytes(decode(substring(c->>'currentProfileDigest' from 8),'hex')),
  '16',(c->>'failedAttempts')::numeric,
  '17',(c->>'maximumAttempts')::numeric,
  '18',(c->>'leaseGeneration')::numeric,
  '19',openpc.business_uuid((c->>'workloadCredentialId')::uuid),
  '20',(c->>'workloadCredentialEpoch')::numeric,
  '21',openpc.business_uuid((c->>'workloadPrincipalId')::uuid),
  '22',openpc.business_uuid(q.work_item_id),
  '23','PC-DATA-6005',
  '24',(c->>'recordedAtMs')::numeric,
  '25',openpc.business_bytes(sha256(signer.public_key_spki)),
  '26',openpc.business_uuid(q.receipt_id));
 IF openpc.business_cbor(signed_payload) IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM openpc.archive_cose_binding(signed_payload,signed_cose,signer.signer_key_id,${definition.schemaId},${definition.purposeCode});
 INSERT INTO control.work_item(work_item_id,participant_id,privacy_domain_id,kind,state,resource_ref,payload_digest,reason,created_by_principal_id,row_version)
 VALUES(q.work_item_id,q.participant_id,q.privacy_domain_id,'FLEET_FAILURE','OPEN','urn:openpc:resource:'||d.candidate_id::text,
   d.material_digest,'Fact delivery quarantined (PC-DATA-6005).',(c->>'workloadPrincipalId')::uuid,1);
 UPDATE control.fleet_fact_quarantine SET state='COMMITTED',payload=signed_payload,
  cose=signed_cose,receipt_digest='sha256:'||encode(sha256(signed_cose),'hex'),
  signer_key_id=signer.signer_key_id,committed_at_ms=now_ms
 WHERE participant_id=q.participant_id AND privacy_domain_id=q.privacy_domain_id AND event_id=q.event_id;
 INSERT INTO control.fleet_fact_failure_outbox(participant_id,privacy_domain_id,receipt_id,receipt_digest)
 VALUES(q.participant_id,q.privacy_domain_id,q.receipt_id,'sha256:'||encode(sha256(signed_cose),'hex'));
 UPDATE control.fleet_fact_delivery SET state='QUARANTINED' WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=d.event_id;
 -- Time can expire while signing; the same current workload/profile and signer
 -- are checked after effects and before this atomic transaction can succeed.
 profile:=openpc.require_fact_consumer_profile('LS-FLEET-CONTROL');
 PERFORM openpc.require_fact_failure_signer(profile,signer.signer_key_id);
 RETURN q.work_item_id;
END $$;
ALTER FUNCTION openpc.commit_fleet_fact_quarantine(bytea,bytea,bytea,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.commit_fleet_fact_quarantine(bytea,bytea,bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.commit_fleet_fact_quarantine(bytea,bytea,bytea,text) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_fleet_quarantine_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' OR TG_TABLE_NAME='fleet_fact_failure_outbox' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF OLD.state<>'PREPARED' OR NEW.state<>'COMMITTED'
  OR to_jsonb(NEW)-ARRAY['state','payload','cose','receipt_digest','signer_key_id','committed_at_ms']
    IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','payload','cose','receipt_digest','signer_key_id','committed_at_ms']
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.assert_fleet_quarantine_atomic()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.fleet_fact_quarantine q
   JOIN control.fleet_fact_delivery d USING(participant_id,privacy_domain_id,event_id)
   JOIN control.fleet_fact_failure_outbox o USING(participant_id,privacy_domain_id,receipt_id)
   JOIN control.work_item w ON w.participant_id=q.participant_id AND w.privacy_domain_id=q.privacy_domain_id AND w.work_item_id=q.work_item_id
   WHERE q.participant_id=NEW.participant_id AND q.privacy_domain_id=NEW.privacy_domain_id AND q.event_id=NEW.event_id
    AND q.state='COMMITTED' AND d.state='QUARANTINED' AND q.material_digest=d.material_digest
    AND o.receipt_digest=q.receipt_digest AND w.kind='FLEET_FAILURE' AND w.state='OPEN' AND w.row_version=1
    AND w.resource_ref='urn:openpc:resource:'||d.candidate_id::text AND w.payload_digest=d.material_digest
    AND w.reason='Fact delivery quarantined (PC-DATA-6005).' AND w.created_by_principal_id=(q.claims->>'workloadPrincipalId')::uuid
    AND w.assignee_principal_id IS NULL AND w.claimed_by_principal_id IS NULL AND w.completed_by_principal_id IS NULL)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NULL;
END $$;
${['fleet_fact_quarantine', 'fleet_fact_failure_outbox']
  .map(
    (table) => `
ALTER TABLE control.${table} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${table} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.${table} TO openpc_control_worker,openpc_control_reader;
GRANT SELECT,INSERT,UPDATE ON control.${table} TO openpc_control_owner;
DROP POLICY IF EXISTS fleet_failure_owner ON control.${table};
CREATE POLICY fleet_failure_owner ON control.${table} TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)) WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
DROP TRIGGER IF EXISTS fleet_failure_history ON control.${table};
CREATE TRIGGER fleet_failure_history BEFORE UPDATE OR DELETE ON control.${table} FOR EACH ROW EXECUTE FUNCTION openpc.guard_fleet_quarantine_history();
`,
  )
  .join('\n')}
ALTER FUNCTION openpc.assert_fleet_quarantine_atomic() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.assert_fleet_quarantine_atomic() FROM PUBLIC;
GRANT SELECT,INSERT ON control.work_item TO openpc_control_owner;
DROP POLICY IF EXISTS fleet_failure_work_item ON control.work_item;
CREATE POLICY fleet_failure_work_item ON control.work_item TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id) AND openpc.current_action_intent_id()='ACT-OPERATIONS_READ_OPERATION-V1')
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id) AND openpc.current_action_intent_id()='ACT-OPERATIONS_READ_OPERATION-V1' AND kind='FLEET_FAILURE');
DROP TRIGGER IF EXISTS fleet_quarantine_atomic ON control.fleet_fact_quarantine;
CREATE CONSTRAINT TRIGGER fleet_quarantine_atomic AFTER INSERT OR UPDATE ON control.fleet_fact_quarantine
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.assert_fleet_quarantine_atomic();
`;
