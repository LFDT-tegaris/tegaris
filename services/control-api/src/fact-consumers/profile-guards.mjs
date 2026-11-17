import { factConsumerProfileContext as p } from '../../../../packages/security-kernel/src/fact-consumer/generated.ts';
import { factConsumerDatabaseRoleSql } from './database-role-sql.mjs';

/** This SQL binds canonical bytes and current workload state. Runtime signature
 * verification against installed trust remains mandatory, independently. */
export const factConsumerProfileGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_fact_consumer_profile()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE c jsonb; expected jsonb; previous control.fact_consumer_profile; issuer text;
BEGIN
 IF TG_OP<>'INSERT' OR NOT (current_user='openpc_control_owner' OR pg_has_role(current_user,'openpc_control_key_governor','USAGE'))
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('fact-consumer-profile:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text||':'||NEW.consumer_id,0));
 SELECT * INTO previous FROM control.fact_consumer_profile WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND consumer_id=NEW.consumer_id ORDER BY revision DESC LIMIT 1;
 IF NEW.revision<>coalesce(previous.revision,0)+1 OR (previous.revision IS NOT NULL AND
   (NEW.profile_id IS DISTINCT FROM previous.profile_id OR NEW.claims->>'environmentId' IS DISTINCT FROM previous.claims->>'environmentId'))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 c:=NEW.claims; issuer:='sha256:'||encode(sha256(NEW.issuer_spki),'hex');
 expected:=jsonb_build_object('environmentId',c->'environmentId','participantId',NEW.participant_id::text,
  'privacyDomainId',NEW.privacy_domain_id::text,'profileId',NEW.profile_id,'revision',NEW.revision::text,
  'consumerId',NEW.consumer_id,'subscriptionId',CASE NEW.consumer_id WHEN 'LS-CONTROL-WORK' THEN 'SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1' WHEN 'LS-FLEET-CONTROL' THEN 'SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1' END,
  'validFromMs',c->'validFromMs','validUntilMs',c->'validUntilMs','issuerKeyId',issuer,
  'workloadCredentialId',NEW.workload_credential_id::text,'workloadCredentialEpoch',NEW.workload_credential_epoch::text,
  'databaseRole',NEW.database_role,'maximumAttempts',c->'maximumAttempts','initialBackoffMs',c->'initialBackoffMs','maximumBackoffMs',c->'maximumBackoffMs');
 IF c IS DISTINCT FROM expected OR jsonb_typeof(c->'environmentId') IS DISTINCT FROM 'string'
  OR coalesce(c->>'environmentId','')!~'^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$'
  OR NEW.profile_id!~'^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$'
  OR NOT ${factConsumerDatabaseRoleSql('NEW.database_role', 'NEW.participant_id', 'NEW.privacy_domain_id')}
  OR encode(NEW.issuer_spki,'hex')!~'^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$'
  OR substring(NEW.workload_credential_id::text from 15 for 1)<>'7'
  OR EXISTS(SELECT 1 FROM jsonb_each(c) e WHERE e.key IN ('validFromMs','validUntilMs','maximumAttempts','initialBackoffMs','maximumBackoffMs')
    AND (jsonb_typeof(e.value)<>'number' OR (e.value#>>'{}')!~'^(0|[1-9][0-9]*)$'))
  OR (c->>'validFromMs')::numeric<0 OR (c->>'validUntilMs')::numeric>9007199254740991
  OR (c->>'validUntilMs')::numeric<=(c->>'validFromMs')::numeric
  OR (c->>'maximumAttempts')::numeric NOT BETWEEN 1 AND 1000
  OR (c->>'initialBackoffMs')::numeric NOT BETWEEN 1 AND 3600000
  OR (c->>'maximumBackoffMs')::numeric NOT BETWEEN (c->>'initialBackoffMs')::numeric AND 3600000
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 expected:=jsonb_build_object('0',openpc.business_bytes(decode('${p.definitionDigest.slice(7)}','hex')),
  '1',c->'environmentId','2',openpc.business_uuid(NEW.participant_id),'3',openpc.business_uuid(NEW.privacy_domain_id),
  '4',NEW.profile_id,'5',NEW.revision,'6',NEW.consumer_id,'7',c->'subscriptionId',
  '8',(c->>'validFromMs')::numeric,'9',(c->>'validUntilMs')::numeric,'10',openpc.business_bytes(sha256(NEW.issuer_spki)),
  '11',openpc.business_uuid(NEW.workload_credential_id),'12',NEW.workload_credential_epoch,
  '13',NEW.database_role,'14',(c->>'maximumAttempts')::numeric,'15',(c->>'initialBackoffMs')::numeric,'16',(c->>'maximumBackoffMs')::numeric);
 IF openpc.business_cbor(NEW.payload) IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM openpc.archive_cose_binding(NEW.payload,NEW.cose,issuer,${p.schemaId},${p.purposeCode});
 PERFORM 1 FROM pg_catalog.pg_roles WHERE rolname=NEW.database_role AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
  AND pg_has_role(rolname,'openpc_control_worker','USAGE');
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 NEW.admitted_at:=clock_timestamp(); RETURN NEW;
END $$;
ALTER TABLE control.fact_consumer_profile FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.fact_consumer_profile FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT,INSERT ON control.fact_consumer_profile TO openpc_control_owner,openpc_control_key_governor;
GRANT SELECT ON control.fact_consumer_profile TO openpc_control_worker;
DROP POLICY IF EXISTS fact_consumer_installation ON control.fact_consumer_profile;
CREATE POLICY fact_consumer_installation ON control.fact_consumer_profile TO openpc_control_owner,openpc_control_key_governor USING(true) WITH CHECK(true);
DROP TRIGGER IF EXISTS fact_consumer_installation ON control.fact_consumer_profile;
CREATE TRIGGER fact_consumer_installation BEFORE INSERT OR UPDATE OR DELETE ON control.fact_consumer_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_fact_consumer_profile();

CREATE OR REPLACE FUNCTION openpc.require_fact_consumer_profile(wanted_consumer text)
RETURNS control.fact_consumer_profile LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE p control.fact_consumer_profile; now_ms numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(session_user,'openpc_control_worker','USAGE')
  OR openpc.current_action_intent_id()<>'ACT-OPERATIONS_READ_OPERATION-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('fact-consumer-profile:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text||':'||wanted_consumer,0));
 SELECT * INTO STRICT p FROM control.fact_consumer_profile WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND consumer_id=wanted_consumer ORDER BY revision DESC LIMIT 1;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000);
 IF session_user<>p.database_role OR now_ms<(p.claims->>'validFromMs')::numeric OR now_ms>=(p.claims->>'validUntilMs')::numeric
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM 1 FROM control.participant v WHERE v.participant_id=p.participant_id AND v.state='ACTIVE' AND v.archived_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM 1 FROM control.privacy_domain v WHERE v.participant_id=p.participant_id AND v.privacy_domain_id=p.privacy_domain_id AND v.state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM 1 FROM control.credential c JOIN control.principal w USING(participant_id,principal_id)
  WHERE c.participant_id=p.participant_id AND c.credential_id=p.workload_credential_id AND c.credential_epoch=p.workload_credential_epoch
   AND c.kind IN ('WORKLOAD_MTLS','WORKLOAD_OIDC') AND c.state='ACTIVE' AND w.kind='WORKLOAD' AND w.state='ACTIVE'
   AND c.valid_from<=clock_timestamp() AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
   AND c.public_key_digest IS DISTINCT FROM sha256(p.issuer_spki) FOR SHARE OF c,w;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 RETURN p;
END $$;
ALTER FUNCTION openpc.require_fact_consumer_profile(text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.require_fact_consumer_profile(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.require_fact_consumer_profile(text) TO openpc_control_worker;
${['participant', 'privacy_domain', 'principal', 'credential']
  .map(
    (table) => `
DROP POLICY IF EXISTS fact_consumer_workload_fence ON control.${table};
CREATE POLICY fact_consumer_workload_fence ON control.${table} FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-OPERATIONS_READ_OPERATION-V1') WITH CHECK(false);`,
  )
  .join('\n')}
`;
