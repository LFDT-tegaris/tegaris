import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const verificationReceipt = notificationCoseProfiles.NotificationVerificationReceiptV1;
/** Security tail consumed by canonical Drizzle generation. No migration number,
 * registry edit or broad runtime grant is allocated by this feature contribution. */
export const notificationEndpointAdmissionGuardsSql = String.raw`
ALTER TABLE control.installed_notification_channel FORCE ROW LEVEL SECURITY;
ALTER TABLE control.notification_endpoint_candidate FORCE ROW LEVEL SECURITY;
ALTER TABLE control.notification_verification_attempt FORCE ROW LEVEL SECURITY;
ALTER TABLE control.notification_endpoint FORCE ROW LEVEL SECURITY;
ALTER TABLE control.notification_endpoint_verification FORCE ROW LEVEL SECURITY;
ALTER TABLE control.notification_verification_attempt ALTER CONSTRAINT notification_verification_attachment_operation_fk DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE control.notification_endpoint_verification ALTER CONSTRAINT notification_verification_operation_fk DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION openpc.guard_notification_channel_installation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND (OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED'
    OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'))
 THEN RAISE EXCEPTION 'DATA-6020-NOTIFICATION-INSTALLATION-IMMUTABLE'; END IF;
 -- A direct UPDATE may already own its row lock. Never wait in this reversed
 -- order: deny and roll back before effects if an admitted reader holds the fence.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('notification-installation:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_channel_installation_guard ON control.installed_notification_channel;
CREATE TRIGGER notification_channel_installation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.installed_notification_channel
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_channel_installation();

CREATE OR REPLACE FUNCTION openpc.guard_notification_candidate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-NOTIFICATION-CANDIDATE-IMMUTABLE'; END IF;
 IF NEW.participant_id<>openpc.current_participant_id() OR NEW.privacy_domain_id<>openpc.current_privacy_domain_id()
   OR current_setting('openpc.action_intent_id')<>'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1'
   OR NEW.predecessor->>'endpointId'<>NEW.endpoint_id::text
   OR NEW.predecessor->>'participantId'<>NEW.participant_id::text
   OR NEW.predecessor->>'privacyDomainId'<>NEW.privacy_domain_id::text
   OR NEW.construction->'binding'->>'endpointId'<>NEW.endpoint_id::text
   OR (NEW.construction->'binding'->>'revision')::numeric<>(NEW.predecessor->>'revision')::numeric+1
   OR NEW.replacement_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
      jsonb_build_object('domain','pc.notification-endpoint.replacement.v1','predecessor',NEW.predecessor,
        'replacement',NEW.construction->'binding','credential',jsonb_build_object(
          'reference',NEW.construction->'credential'->>'reference','version',NEW.construction->'credential'->>'version',
          'fingerprint',NEW.construction->'credential'->>'fingerprint','epoch',NEW.construction->'credential'->>'epoch'))),'UTF8')),'hex')
   OR NEW.expires_at_ms<=floor(extract(epoch from clock_timestamp())*1000)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_candidate_guard ON control.notification_endpoint_candidate;
CREATE TRIGGER notification_candidate_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_endpoint_candidate
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_candidate();

CREATE OR REPLACE FUNCTION openpc.guard_notification_verification_attempt() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE c jsonb; signed jsonb; payload bytea; cose bytea; claims jsonb; outer_item jsonb; fields jsonb; header jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-NOTIFICATION-ATTEMPT-IMMUTABLE'; END IF;
 IF NEW.participant_id<>openpc.current_participant_id() OR NEW.privacy_domain_id<>openpc.current_privacy_domain_id()
  OR current_setting('openpc.action_intent_id')<>'ACT-NOTIFICATION_UPDATE_VERIFY-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 c:=convert_from(NEW.challenge_bytes,'UTF8')::jsonb->'challenge';
 IF NEW.challenge_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(jsonb_build_object('challenge',c)),'UTF8')
  OR c IS NULL OR c->>'challengeId'<>NEW.attempt_id::text OR c->>'principalId'<>NEW.principal_id::text
   OR c->'predecessor'->>'participantId'<>NEW.participant_id::text
   OR c->'predecessor'->>'privacyDomainId'<>NEW.privacy_domain_id::text
   OR c->'predecessor'->>'endpointId'<>NEW.endpoint_id::text
   OR (c->'predecessor'->>'revision')::numeric<>NEW.predecessor_revision
   OR c->>'businessIdempotencyDigest'<>NEW.business_idempotency_digest
 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ATTEMPT-BINDING'; END IF;
 IF TG_OP='INSERT' THEN
   IF NEW.state<>'PREPARED' OR (c->>'expiresAtMs')::numeric<=floor(extract(epoch from clock_timestamp())*1000)
   THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ATTEMPT-PREPARE'; END IF;
 ELSE
   IF (to_jsonb(OLD)-ARRAY['state','response_bytes','verified_at_ms','receipt_digest','attached_operation_id']) IS DISTINCT FROM
      (to_jsonb(NEW)-ARRAY['state','response_bytes','verified_at_ms','receipt_digest','attached_operation_id'])
   THEN RAISE EXCEPTION 'DATA-6020-NOTIFICATION-ATTEMPT-IMMUTABLE'; END IF;
   IF NOT ((OLD.state='PREPARED' AND NEW.state='DISPATCHED')
     OR (OLD.state='DISPATCHED' AND NEW.state IN ('UNKNOWN','PROVED','REJECTED'))
     OR (OLD.state='PROVED' AND NEW.state='ATTACHED'
       AND ROW(OLD.response_bytes,OLD.verified_at_ms,OLD.receipt_digest) IS NOT DISTINCT FROM ROW(NEW.response_bytes,NEW.verified_at_ms,NEW.receipt_digest)
       AND NEW.attached_operation_id::text=current_setting('openpc.operation_id')
       AND (c->>'expiresAtMs')::numeric>floor(extract(epoch from clock_timestamp())*1000)))
   THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ATTEMPT-TRANSITION'; END IF;
 END IF;
 IF NEW.response_bytes IS NOT NULL THEN
  signed:=convert_from(NEW.response_bytes,'UTF8')::jsonb;
  IF NEW.response_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(signed),'UTF8')
   OR (SELECT count(*) FROM jsonb_object_keys(signed))<>2
  THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-OBSERVATION-WIRE'; END IF;
  payload:=decode(signed->>'payloadHex','hex'); cose:=decode(signed->>'coseHex','hex');
  claims:=openpc.business_cbor(payload);
  IF get_byte(cose,0) IS DISTINCT FROM 210 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-OBSERVATION-COSE'; END IF;
  outer_item:=openpc.business_cbor_item(cose,1,0); fields:=outer_item->'value';
  IF (outer_item->>'next')::integer IS DISTINCT FROM octet_length(cose)
   OR jsonb_typeof(fields) IS DISTINCT FROM 'array' OR jsonb_array_length(fields)<>4
   OR fields->1 IS DISTINCT FROM '{}'::jsonb OR fields->2 IS DISTINCT FROM openpc.business_bytes(payload)
   OR length(fields->3->>'bytes') IS DISTINCT FROM 128
  THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-OBSERVATION-COSE'; END IF;
  header:=openpc.business_cbor(decode(fields->0->>'bytes','hex'));
  IF (SELECT count(*) FROM jsonb_object_keys(claims))<>11 OR NEW.verified_at_ms>floor(extract(epoch from clock_timestamp())*1000)
   OR header IS DISTINCT FROM jsonb_build_object('1',-7,'2',jsonb_build_array(100,101,102,103),'3','${verificationReceipt.contentType}',
     '4',openpc.business_bytes(convert_to('sha256:'||(claims->'10'->>'bytes'),'UTF8')),
     '100',${verificationReceipt.schemaId},'101',${verificationReceipt.schemaVersion},'102',${verificationReceipt.purposeCode},'103',${verificationReceipt.signatureProfileVersion})
   OR claims->'0' IS DISTINCT FROM openpc.business_bytes(decode('${verificationReceipt.definitionDigest.slice(7)}','hex'))
   OR claims->>'1' IS DISTINCT FROM c->>'environmentId'
   OR claims->'2' IS DISTINCT FROM openpc.business_bytes(uuid_send(NEW.participant_id))
   OR claims->'3' IS DISTINCT FROM openpc.business_bytes(uuid_send(NEW.privacy_domain_id))
   OR claims->'5' IS DISTINCT FROM openpc.business_bytes(decode(substr(c->>'signedVerificationProfileDigest',8),'hex'))
   OR claims->'6' IS DISTINCT FROM openpc.business_bytes(sha256(convert_to(openpc.signing_canonical_json(c),'UTF8')))
   OR (claims->>'7')::integer IS DISTINCT FROM (CASE WHEN NEW.state='REJECTED' THEN 2 ELSE 1 END)
   OR (claims->>'8')::numeric<(c->>'issuedAtMs')::numeric OR (claims->>'8')::numeric>NEW.verified_at_ms
   OR (claims->>'9')::numeric<=NEW.verified_at_ms OR (claims->>'9')::numeric>(c->>'expiresAtMs')::numeric
   OR NEW.receipt_digest IS DISTINCT FROM 'sha256:'||encode(sha256(cose),'hex')
  THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-OBSERVATION-BINDING'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_verification_attempt_guard ON control.notification_verification_attempt;
CREATE TRIGGER notification_verification_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_verification_attempt
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_verification_attempt();

CREATE OR REPLACE FUNCTION openpc.guard_notification_verification_row() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.notification_verification_attempt%ROWTYPE; c jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-NOTIFICATION-VERIFICATION-IMMUTABLE'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
   OR NEW.operation_id::text IS DISTINCT FROM current_setting('openpc.operation_id')
   OR current_setting('openpc.action_intent_id')<>'ACT-NOTIFICATION_UPDATE_VERIFY-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT a FROM control.notification_verification_attempt WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.verification_id AND state='ATTACHED'
   AND attached_operation_id=NEW.operation_id AND endpoint_id=NEW.endpoint_id;
 c:=convert_from(a.challenge_bytes,'UTF8')::jsonb->'challenge';
 IF NEW.endpoint_revision IS DISTINCT FROM (c->>'resultRevision')::numeric
   OR NEW.channel IS DISTINCT FROM c->'predecessor'->>'channel'
   OR NEW.destination_ref IS DISTINCT FROM c->'predecessor'->>'destinationRef'
   OR NEW.channel_profile_digest IS DISTINCT FROM c->'predecessor'->>'channelProfileDigest'
   OR NEW.credential_ref IS DISTINCT FROM c->'predecessor'->>'credentialRef'
 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-VERIFICATION-BINDING'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_verification_row_guard ON control.notification_endpoint_verification;
CREATE TRIGGER notification_verification_row_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_endpoint_verification
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_verification_row();

CREATE OR REPLACE FUNCTION openpc.notification_endpoint_business_projection(item control.notification_endpoint)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',(item).channel,'1',(item).state,'2',(item).destination_ref,
   '3',openpc.business_bytes(decode(substr((item).channel_profile_digest,8),'hex')),'4',(item).credential_ref,
   '5',0,'6',openpc.business_bytes(decode(substr((item).candidate_digest,8),'hex')),
   '7',CASE WHEN (item).verification_id IS NULL THEN 0 ELSE 1 END)
   || CASE WHEN (item).verification_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('8',(item).verification_id::text) END
$$;
CREATE OR REPLACE FUNCTION openpc.assert_notification_endpoint_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.notification_endpoint%ROWTYPE; before_projection jsonb; after_projection jsonb; registration control.installed_notification_channel%ROWTYPE;
BEGIN
 IF receipt.profile_version<>1 OR receipt.aggregate_type<>'notification-endpoint' OR receipt.catalog_operation_id NOT IN
  ('CFG-OP-CREATE-NOTIFICATION-ENDPOINT','CFG-OP-UPDATE-NOTIFICATION-ENDPOINT','CFG-OP-VERIFY-NOTIFICATION-ENDPOINT')
 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-PROFILE'; END IF;
 SELECT * INTO STRICT item FROM control.notification_endpoint WHERE participant_id=receipt.participant_id
  AND privacy_domain_id=receipt.privacy_domain_id AND endpoint_id=receipt.aggregate_id;
 -- The repository retains this scope fence before its SERIALIZABLE snapshot.
 -- Reacquire nonblocking through COMMIT; do not request runtime UPDATE privilege.
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('notification-installation:'||item.participant_id::text||':'||item.privacy_domain_id::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT registration FROM control.installed_notification_channel n
   WHERE n.participant_id=item.participant_id AND n.privacy_domain_id=item.privacy_domain_id
    AND n.credential_ref=item.credential_ref AND n.channel=item.channel AND n.destination_ref=item.destination_ref
    AND n.channel_profile_digest=item.channel_profile_digest AND n.state='ACTIVE';
 IF (openpc.business_cbor(decode(registration.channel_signed->>'payloadHex','hex'))->>'6')::numeric>floor(extract(epoch from clock_timestamp())*1000)
   OR (openpc.business_cbor(decode(registration.channel_signed->>'payloadHex','hex'))->>'7')::numeric<=floor(extract(epoch from clock_timestamp())*1000)
   OR registration.credential->>'state' IS DISTINCT FROM 'ACTIVE'
   OR (registration.credential->>'validFromMs')::numeric>floor(extract(epoch from clock_timestamp())*1000)
   OR (registration.credential->>'validUntilMs')::numeric<=floor(extract(epoch from clock_timestamp())*1000)
   OR NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
     WHERE c.participant_id=item.participant_id AND c.credential_id=registration.workload_credential_id
       AND c.principal_id=registration.principal_id AND c.credential_epoch=registration.workload_epoch
       AND c.state='ACTIVE' AND c.kind='WORKLOAD_MTLS' AND c.audience=registration.workload_id
       AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp() AND p.state='ACTIVE' AND p.kind='WORKLOAD')
 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-CURRENT-REGISTRATION'; END IF;
 before_projection:=openpc.business_cbor(receipt.before_state_preimage)->8;
 after_projection:=openpc.business_cbor(receipt.after_state_preimage)->8;
 IF receipt.after_existence<>1 OR receipt.after_revision<>item.revision OR item.arbitrary_egress
  OR after_projection IS DISTINCT FROM openpc.notification_endpoint_business_projection(item)
 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-ACTUAL-STATE'; END IF;
 IF receipt.catalog_operation_id='CFG-OP-CREATE-NOTIFICATION-ENDPOINT' THEN
  IF receipt.before_existence<>0 OR receipt.before_revision<>0 OR receipt.after_revision<>1
    OR item.state<>'DISABLED' OR item.verification_id IS NOT NULL
    OR item.candidate_digest IS DISTINCT FROM 'sha256:'||encode(receipt.candidate_digest,'hex')
  THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-CREATE'; END IF;
 ELSE
  IF receipt.before_existence<>1 OR receipt.after_revision<>receipt.before_revision+1 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-REVISION'; END IF;
  IF receipt.catalog_operation_id='CFG-OP-UPDATE-NOTIFICATION-ENDPOINT' THEN
   IF before_projection->>'1'='RETIRED' OR item.verification_id IS NOT NULL
     OR item.state IS DISTINCT FROM (CASE WHEN before_projection->>'1'='QUARANTINED' THEN 'QUARANTINED' ELSE 'DISABLED' END)
   THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-REPLACEMENT'; END IF;
   IF NOT EXISTS(SELECT 1 FROM control.notification_endpoint_candidate c
     JOIN control.idempotency_record i ON i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id AND i.principal_id=c.principal_id
     WHERE c.participant_id=item.participant_id AND c.privacy_domain_id=item.privacy_domain_id AND c.endpoint_id=item.endpoint_id
       AND c.replacement_digest=item.candidate_digest AND i.operation_id=receipt.operation_id
       AND c.expires_at_ms>floor(extract(epoch from clock_timestamp())*1000)
       AND (c.predecessor->>'revision')::numeric=receipt.before_revision
       AND c.predecessor->>'channel'=before_projection->>'0'
       AND c.predecessor->>'destinationRef'=before_projection->>'2'
       AND openpc.business_bytes(decode(substr(c.predecessor->>'channelProfileDigest',8),'hex'))=before_projection->'3'
       AND c.predecessor->>'credentialRef'=before_projection->>'4'
       AND c.construction->'credential'=registration.credential
       AND c.construction->'binding'=jsonb_build_object('participantId',item.participant_id,'privacyDomainId',item.privacy_domain_id,
         'endpointId',item.endpoint_id,'revision',item.revision::text,'channel',item.channel,'destinationRef',item.destination_ref,
         'channelProfileDigest',item.channel_profile_digest,'credentialRef',item.credential_ref))
   THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-REPLACEMENT-ADMISSION'; END IF;
  ELSE
   IF before_projection->>'1' NOT IN ('ACTIVE','DISABLED') OR item.state<>'ACTIVE'
     OR before_projection-ARRAY['1','7','8'] IS DISTINCT FROM after_projection-ARRAY['1','7','8']
     OR NOT EXISTS (SELECT 1 FROM control.notification_verification_attempt a
       JOIN control.notification_endpoint_verification v ON v.participant_id=a.participant_id AND v.privacy_domain_id=a.privacy_domain_id AND v.verification_id=a.attempt_id
       WHERE a.participant_id=receipt.participant_id AND a.privacy_domain_id=receipt.privacy_domain_id AND a.endpoint_id=item.endpoint_id
        AND a.attempt_id=item.verification_id AND a.state='ATTACHED' AND a.attached_operation_id=receipt.operation_id
        AND v.operation_id=receipt.operation_id AND v.endpoint_revision=item.revision)
   THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-VERIFY'; END IF;
  END IF;
 END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_endpoint_mutation() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE action text:=current_setting('openpc.action_intent_id');
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-NOTIFICATION-ENDPOINT-IMMUTABLE'; END IF;
 IF NEW.participant_id<>openpc.current_participant_id() OR NEW.privacy_domain_id<>openpc.current_privacy_domain_id() OR NEW.arbitrary_egress
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='INSERT' THEN
  IF action<>'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1' OR NEW.revision<>1 OR NEW.state<>'DISABLED' OR NEW.verification_id IS NOT NULL
  THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-CREATE'; END IF;
 ELSE
  IF NEW.revision<>OLD.revision+1 OR ROW(NEW.participant_id,NEW.privacy_domain_id,NEW.endpoint_id,NEW.created_at) IS DISTINCT FROM ROW(OLD.participant_id,OLD.privacy_domain_id,OLD.endpoint_id,OLD.created_at)
  THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-REVISION'; END IF;
  IF action='ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1' THEN
   IF OLD.state='RETIRED' OR NEW.verification_id IS NOT NULL OR NEW.state IS DISTINCT FROM (CASE WHEN OLD.state='QUARANTINED' THEN 'QUARANTINED' ELSE 'DISABLED' END)
   THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-REPLACEMENT'; END IF;
  ELSIF action='ACT-NOTIFICATION_UPDATE_VERIFY-V1' THEN
   IF OLD.state NOT IN ('DISABLED','ACTIVE') OR NEW.state<>'ACTIVE' OR NEW.verification_id IS NULL
    OR ROW(NEW.channel,NEW.destination_ref,NEW.channel_profile_digest,NEW.credential_ref,NEW.candidate_digest) IS DISTINCT FROM ROW(OLD.channel,OLD.destination_ref,OLD.channel_profile_digest,OLD.credential_ref,OLD.candidate_digest)
   THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-VERIFY'; END IF;
  ELSE RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_endpoint_mutation_guard ON control.notification_endpoint;
CREATE TRIGGER notification_endpoint_mutation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_endpoint
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_endpoint_mutation();
CREATE OR REPLACE FUNCTION openpc.check_notification_endpoint_effect_receipt() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.audit_occurrence%ROWTYPE; prior jsonb;
BEGIN
 SELECT * INTO STRICT receipt FROM control.audit_occurrence r WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
  AND r.aggregate_type='notification-endpoint' AND r.aggregate_id=NEW.endpoint_id AND r.after_revision=NEW.revision;
 IF TG_OP='INSERT' THEN prior:='{}'::jsonb; ELSE prior:=openpc.notification_endpoint_business_projection(OLD); END IF;
 IF openpc.business_cbor(receipt.before_state_preimage)->8 IS DISTINCT FROM prior
  OR openpc.business_cbor(receipt.after_state_preimage)->8 IS DISTINCT FROM openpc.notification_endpoint_business_projection(NEW)
  OR receipt.before_revision IS DISTINCT FROM (CASE WHEN TG_OP='INSERT' THEN 0 ELSE OLD.revision END)
 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ENDPOINT-EFFECT-RECEIPT'; END IF;
 PERFORM openpc.assert_notification_endpoint_receipt(receipt);
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_endpoint_effect_receipt ON control.notification_endpoint;
CREATE CONSTRAINT TRIGGER notification_endpoint_effect_receipt AFTER INSERT OR UPDATE ON control.notification_endpoint
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_notification_endpoint_effect_receipt();

CREATE OR REPLACE FUNCTION openpc.check_notification_verification_attachment() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.audit_occurrence%ROWTYPE;
BEGIN
 IF NEW.state<>'ATTACHED' THEN RETURN NEW; END IF;
 SELECT * INTO STRICT receipt FROM control.audit_occurrence r WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
   AND r.operation_id=NEW.attached_operation_id AND r.aggregate_id=NEW.endpoint_id AND r.catalog_operation_id='CFG-OP-VERIFY-NOTIFICATION-ENDPOINT';
 IF NOT EXISTS(SELECT 1 FROM control.notification_endpoint e WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id
   AND e.endpoint_id=NEW.endpoint_id AND e.verification_id=NEW.attempt_id AND e.state='ACTIVE' AND e.revision=NEW.predecessor_revision+1)
 THEN RAISE EXCEPTION 'DATA-6021-NOTIFICATION-ATTACHMENT-EFFECT'; END IF;
 PERFORM openpc.assert_notification_endpoint_receipt(receipt);
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_verification_attachment ON control.notification_verification_attempt;
CREATE CONSTRAINT TRIGGER notification_verification_attachment AFTER UPDATE ON control.notification_verification_attempt
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_notification_verification_attachment();
`;

export const notificationEndpointAdmissionGrantsSql = String.raw`
DROP POLICY IF EXISTS notification_channel_installer ON control.installed_notification_channel;
CREATE POLICY notification_channel_installer ON control.installed_notification_channel TO openpc_control_owner USING(true) WITH CHECK(true);
REVOKE ALL ON control.installed_notification_channel,control.notification_endpoint_candidate,control.notification_verification_attempt,
 control.notification_endpoint,control.notification_endpoint_verification FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.installed_notification_channel TO openpc_control_runtime;
GRANT SELECT,INSERT ON control.notification_endpoint_candidate TO openpc_control_runtime;
GRANT SELECT,INSERT,UPDATE ON control.notification_verification_attempt,control.notification_endpoint TO openpc_control_runtime;
GRANT SELECT,INSERT ON control.notification_endpoint_verification TO openpc_control_runtime;
GRANT SELECT ON control.notification_endpoint TO openpc_control_reader;
REVOKE ALL ON FUNCTION openpc.guard_notification_channel_installation(),openpc.guard_notification_candidate(),
 openpc.guard_notification_verification_attempt(),openpc.guard_notification_verification_row(),openpc.notification_endpoint_business_projection(control.notification_endpoint),
 openpc.assert_notification_endpoint_receipt(control.audit_occurrence),openpc.guard_notification_endpoint_mutation(),
 openpc.check_notification_endpoint_effect_receipt(),openpc.check_notification_verification_attachment() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.notification_endpoint_business_projection(control.notification_endpoint),
 openpc.assert_notification_endpoint_receipt(control.audit_occurrence) TO openpc_control_runtime;
`;

/** Called inside the same scoped mutation before signer discovery. This checks
 * the selected operation's exact admitted profile and executable SQL owners;
 * runtime signer authority is still discovered/fenced by AtomicConfigurationMutation. */
export const notificationEndpointPersistenceAdmissionSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.assert_notification_endpoint_persistence(p_operation text,p_profile bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE required record; admitted control.business_transition_profile%ROWTYPE;
BEGIN
 IF p_operation NOT IN ('CFG-OP-CREATE-NOTIFICATION-ENDPOINT','CFG-OP-UPDATE-NOTIFICATION-ENDPOINT','CFG-OP-VERIFY-NOTIFICATION-ENDPOINT')
  OR NOT pg_has_role(current_user,'openpc_control_runtime','MEMBER')
  OR has_table_privilege(current_user,'control.installed_notification_channel','INSERT,UPDATE,DELETE')
 THEN RAISE EXCEPTION 'PC-INTEGRATION-5001'; END IF;
 SELECT * INTO STRICT admitted FROM control.business_transition_profile WHERE catalog_operation_id=p_operation AND profile_version=1
  AND profile_digest=p_profile AND aggregate_type='notification-endpoint' AND action_intent_id=current_setting('openpc.action_intent_id');
 IF admitted.profile_digest<>sha256(admitted.definition_canonical_json) THEN RAISE EXCEPTION 'PC-INTEGRATION-5001'; END IF;
 FOR required IN SELECT * FROM (VALUES
  ('control.notification_endpoint','notification_endpoint_mutation_guard','openpc.guard_notification_endpoint_mutation()',false),
  ('control.notification_endpoint','notification_endpoint_effect_receipt','openpc.check_notification_endpoint_effect_receipt()',true),
  ('control.installed_notification_channel','notification_channel_installation_guard','openpc.guard_notification_channel_installation()',false),
  ('control.audit_occurrence','business_receipt_typed','openpc.guard_business_receipt()',false),
  ('control.audit_occurrence','business_receipt_complete','openpc.check_business_receipt_completion()',true),
  ('control.outbox_event','business_outbox_payload','openpc.guard_business_outbox()',false)
 ) v(table_name,trigger_name,function_name,deferred)
 LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_proc f ON f.oid=t.tgfoid
   WHERE c.oid=to_regclass(required.table_name) AND t.tgname=required.trigger_name AND t.tgenabled IN ('O','A')
    AND f.oid=to_regprocedure(required.function_name) AND t.tgdeferrable=required.deferred AND t.tginitdeferred=required.deferred
    AND c.relrowsecurity AND c.relforcerowsecurity AND NOT f.prosecdef)
  THEN RAISE EXCEPTION 'PC-INTEGRATION-5001'; END IF;
 END LOOP;
 IF p_operation='CFG-OP-UPDATE-NOTIFICATION-ENDPOINT' AND NOT EXISTS (
  SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_endpoint_candidate'::regclass
    AND tgname='notification_candidate_guard' AND tgfoid='openpc.guard_notification_candidate()'::regprocedure AND tgenabled IN ('O','A'))
 THEN RAISE EXCEPTION 'PC-INTEGRATION-5001'; END IF;
 IF p_operation='CFG-OP-VERIFY-NOTIFICATION-ENDPOINT' THEN
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_verification_attempt'::regclass
      AND tgname='notification_verification_attempt_guard' AND tgfoid='openpc.guard_notification_verification_attempt()'::regprocedure AND tgenabled IN ('O','A'))
    OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_verification_attempt'::regclass
      AND tgname='notification_verification_attachment' AND tgfoid='openpc.check_notification_verification_attachment()'::regprocedure AND tgenabled IN ('O','A') AND tgdeferrable AND tginitdeferred)
    OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_endpoint_verification'::regclass
      AND tgname='notification_verification_row_guard' AND tgfoid='openpc.guard_notification_verification_row()'::regprocedure AND tgenabled IN ('O','A'))
    OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='control.notification_verification_attempt'::regclass
      AND conname='notification_verification_attachment_operation_fk' AND condeferrable AND condeferred AND convalidated)
  THEN RAISE EXCEPTION 'PC-INTEGRATION-5001'; END IF;
 END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_notification_endpoint_persistence(text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_notification_endpoint_persistence(text,bytea) TO openpc_control_runtime;
`;
