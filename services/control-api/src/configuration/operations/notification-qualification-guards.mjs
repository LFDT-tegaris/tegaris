import {
  qualificationInstallationSchema,
  qualificationOriginRequestSchema,
  qualificationOriginProofSchema,
  qualificationRunRequestSchema,
  qualificationRecordSchema,
} from './notification-qualification-contract.ts';
const documentKeys = {
  notification_qualification_installation: Object.keys(qualificationInstallationSchema.shape),
  notification_qualification_origin: Object.keys(qualificationOriginRequestSchema.shape),
  notification_qualification_origin_proof: Object.keys(qualificationOriginProofSchema.shape),
  notification_qualification_run: Object.keys(qualificationRunRequestSchema.shape),
  notification_qualification_record: Object.keys(qualificationRecordSchema.shape),
};
/** Canonical registers these guards only with the five owning schemas and exact
 * qualification-owner/Identity grants. No normal runtime role gains access.
 * Native TLS/build-service ES256 validation remains mandatory in the TS owner;
 * SQL independently enforces scope, immutable bytes and causal record ordering. */
export const notificationQualificationGuardsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.guard_notification_qualification() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE pins control.notification_qualification_installation%ROWTYPE;
 run control.notification_qualification_run%ROWTYPE;
 original control.notification_qualification_origin%ROWTYPE; event control.outbox_event%ROWTYPE; v jsonb; at_ms numeric;
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_IMMUTABLE'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
 OR current_setting('session_replication_role')<>'origin'
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
 OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_CONTEXT'; END IF;
 ${Object.entries(documentKeys)
   .map(
     ([table, keys]) =>
       `IF TG_TABLE_NAME='${table}' AND (jsonb_typeof(NEW.body) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(NEW.body))<>${keys.length} OR NOT NEW.body ?& ARRAY[${keys.map((k) => `'${k}'`).join(',')}] OR EXISTS(SELECT 1 FROM jsonb_each(NEW.body) f WHERE f.value='null'::jsonb)) THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_SHAPE'; END IF;`,
   )
   .join('\n')}
 IF NEW.body->'schemaVersion' IS DISTINCT FROM '1'::jsonb
 OR NEW.body_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(NEW.body),'UTF8')
 OR NEW.body_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.body_bytes),'hex')
 THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_BYTES'; END IF;
 at_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF TG_TABLE_NAME='notification_qualification_installation' THEN
  IF current_user<>'openpc_operations_qualification_bootstrap' THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_INSTALLER'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('notification-qualification-installation:'||NEW.installation_id::text,0));
  IF TG_OP='UPDATE' THEN
   IF NEW.state IS DISTINCT FROM 'REVOKED' OR (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state')
   THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_IMMUTABLE'; END IF;
  ELSE
   IF NEW.state IS DISTINCT FROM 'ACTIVE' OR NEW.body->>'installationId' IS DISTINCT FROM NEW.installation_id::text
   OR NEW.body->>'participantId' IS DISTINCT FROM NEW.participant_id::text OR NEW.body->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
   OR NEW.body->>'environmentId' IS DISTINCT FROM NEW.environment_id OR jsonb_typeof(NEW.body->'input') IS DISTINCT FROM 'object' OR (NEW.body->'input'->>'profile' IN ('local','development','test','staging')) IS NOT TRUE
   OR jsonb_typeof(NEW.body->'maximumRunMs') IS DISTINCT FROM 'number' OR (NEW.body->>'maximumRunMs')::numeric NOT BETWEEN 1 AND 3600000
   OR jsonb_typeof(NEW.body->'maximumSamples') IS DISTINCT FROM 'number' OR (NEW.body->>'maximumSamples')::numeric NOT BETWEEN 1 AND 4096
   OR jsonb_typeof(NEW.body->'maximumEvidenceBytes') IS DISTINCT FROM 'number' OR (NEW.body->>'maximumEvidenceBytes')::numeric NOT BETWEEN 1 AND 16777216
   OR jsonb_typeof(NEW.body->'maximumSources') IS DISTINCT FROM 'number' OR (NEW.body->>'maximumSources')::numeric NOT BETWEEN 1 AND 10000
   OR NOT EXISTS(SELECT 1 FROM control.operations_installation i WHERE i.environment_id=NEW.environment_id AND i.participant_id=NEW.participant_id AND i.privacy_domain_id=NEW.privacy_domain_id AND i.state='ACTIVE' AND i.installation_digest=NEW.body->>'operationsInstallationDigest')
   THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_INSTALLATION'; END IF;
   IF EXISTS(SELECT 1 FROM unnest(ARRAY['executor','reviewer','signer']) a WHERE NEW.body->a->>'principalId' IS NULL
    OR NEW.body->a->>'principalId' IN (NEW.body->'subjectAuthor'->>'principalId',NEW.body->'harnessAuthor'->>'principalId',NEW.body->>'rootPrincipalId'))
    OR (SELECT count(DISTINCT NEW.body->a->>'principalId') FROM unnest(ARRAY['executor','reviewer','signer']) a)<>3
   THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_INDEPENDENCE'; END IF;
  END IF;
  RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' OR current_user<>'openpc_operations_qualification_owner' THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_NATIVE_OWNER'; END IF;
 IF TG_TABLE_NAME='notification_qualification_origin' THEN
  SELECT * INTO STRICT pins FROM control.notification_qualification_installation WHERE installation_id=NEW.installation_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id FOR SHARE;
  IF pins.state<>'ACTIVE' OR NEW.body->>'mode' IS DISTINCT FROM 'NEW_AUTHENTICATED_ORIGIN'
   OR NEW.body->>'originId' IS DISTINCT FROM NEW.origin_id::text OR NEW.body->>'installationId' IS DISTINCT FROM NEW.installation_id::text
   OR NEW.body->>'installationDigest' IS DISTINCT FROM pins.body_digest
   OR NEW.body->>'operationId' IS DISTINCT FROM openpc.current_operation_id()::text
   OR NEW.body->>'sourceDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.source_bytes),'hex')
   OR NEW.body->>'buildDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.build_bytes),'hex')
   OR ((NEW.body->>'kind'='SUBJECT' AND NEW.body->'author'=pins.body->'subjectAuthor' AND NEW.origin_id::text=pins.body->>'subjectOriginId')
     OR (NEW.body->>'kind'='HARNESS' AND NEW.body->'author'=pins.body->'harnessAuthor' AND NEW.origin_id::text=pins.body->>'harnessOriginId')) IS NOT TRUE
   OR jsonb_typeof(NEW.body->'issuedAtMs') IS DISTINCT FROM 'number' OR jsonb_typeof(NEW.body->'deadlineAtMs') IS DISTINCT FROM 'number'
   OR (NEW.body->>'issuedAtMs')::numeric>at_ms OR (NEW.body->>'deadlineAtMs')::numeric<=at_ms
   OR (NEW.body->>'deadlineAtMs')::numeric-(NEW.body->>'issuedAtMs')::numeric NOT BETWEEN 1 AND 30000
   THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_ORIGIN'; END IF;
 ELSIF TG_TABLE_NAME='notification_qualification_origin_proof' THEN
  SELECT * INTO STRICT original FROM control.notification_qualification_origin WHERE origin_id=NEW.origin_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id;
  IF NEW.body->>'originId' IS DISTINCT FROM NEW.origin_id::text OR NEW.body->>'requestDigest' IS DISTINCT FROM original.body_digest
   OR NEW.body->>'signatureHex' IS NULL OR NEW.body->>'signatureHex' !~ '^[0-9a-f]{128}$'
   OR jsonb_typeof(NEW.body->'retainedAtMs') IS DISTINCT FROM 'number' OR (NEW.body->>'retainedAtMs')::numeric>at_ms
   OR (NEW.body->>'state' IN ('ORIGINAL_VERIFIED_WITHIN_WINDOW','HISTORICAL_ONLY')) IS NOT TRUE
   OR (NEW.body->>'state'='ORIGINAL_VERIFIED_WITHIN_WINDOW' AND (NEW.body->>'retainedAtMs')::numeric>=(original.body->>'deadlineAtMs')::numeric)
   THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_ORIGIN_PROOF'; END IF;
 ELSIF TG_TABLE_NAME='notification_qualification_run' THEN
  SELECT * INTO STRICT pins FROM control.notification_qualification_installation WHERE installation_id=NEW.installation_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id FOR SHARE;
  IF pins.state<>'ACTIVE' OR NEW.reservation_transaction IS DISTINCT FROM pg_current_xact_id()::text
   OR NEW.body->>'purpose' IS DISTINCT FROM 'QUALIFICATION_RUN' OR NEW.body->>'runId' IS DISTINCT FROM NEW.run_id::text
   OR NEW.body->>'installationDigest' IS DISTINCT FROM pins.body_digest OR NEW.body->'executor' IS DISTINCT FROM pins.body->'executor'
   OR NEW.body->>'operationId' IS DISTINCT FROM openpc.current_operation_id()::text
   OR NEW.body->>'inputPayloadDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(decode(NEW.body->>'inputPayloadHex','hex')),'hex')
   OR jsonb_typeof(NEW.body->'reservedAtMs') IS DISTINCT FROM 'number' OR jsonb_typeof(NEW.body->'deadlineAtMs') IS DISTINCT FROM 'number'
   OR (NEW.body->>'reservedAtMs')::numeric>at_ms OR (NEW.body->>'deadlineAtMs')::numeric<=at_ms
   OR (NEW.body->>'deadlineAtMs')::numeric-(NEW.body->>'reservedAtMs')::numeric>(pins.body->>'maximumRunMs')::numeric
   OR NOT EXISTS(SELECT 1 FROM control.notification_qualification_origin_proof p WHERE p.origin_id=(pins.body->>'subjectOriginId')::uuid AND p.participant_id=NEW.participant_id AND p.privacy_domain_id=NEW.privacy_domain_id AND p.body_digest=NEW.body->>'subjectOriginDigest' AND p.body->>'state'='ORIGINAL_VERIFIED_WITHIN_WINDOW')
   OR NOT EXISTS(SELECT 1 FROM control.notification_qualification_origin_proof p WHERE p.origin_id=(pins.body->>'harnessOriginId')::uuid AND p.participant_id=NEW.participant_id AND p.privacy_domain_id=NEW.privacy_domain_id AND p.body_digest=NEW.body->>'harnessOriginDigest' AND p.body->>'state'='ORIGINAL_VERIFIED_WITHIN_WINDOW')
   THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_RUN'; END IF;
 ELSE
  SELECT * INTO STRICT run FROM control.notification_qualification_run WHERE run_id=NEW.run_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id;
  SELECT * INTO STRICT pins FROM control.notification_qualification_installation WHERE installation_id=run.installation_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id;
  PERFORM pg_advisory_xact_lock(hashtextextended('notification-qualification-run:'||NEW.run_id::text,0));
  IF NEW.body->>'runId' IS DISTINCT FROM NEW.run_id::text OR NEW.body->>'kind' IS DISTINCT FROM NEW.kind OR NEW.body->>'key' IS DISTINCT FROM NEW.record_key
   OR NEW.body->>'operationId' IS DISTINCT FROM openpc.current_operation_id()::text OR jsonb_typeof(NEW.body->'recordedAtMs') IS DISTINCT FROM 'number'
   OR (NEW.body->>'recordedAtMs')::numeric>at_ms OR NOT NEW.body ? 'value'
   THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_RECORD'; END IF;
  IF coalesce((SELECT sum(octet_length(body_bytes)) FROM control.notification_qualification_record WHERE run_id=NEW.run_id),0)+octet_length(NEW.body_bytes)>(pins.body->>'maximumEvidenceBytes')::numeric THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_EVIDENCE_BOUND'; END IF;
  v:=NEW.body->'value';
  IF NEW.kind NOT IN ('SOURCE','SAMPLE','CASE') AND NEW.record_key<>'original' THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_CARDINALITY'; END IF;
  IF NEW.kind='INPUT' THEN
   IF v->>'payloadHex' IS DISTINCT FROM run.body->>'inputPayloadHex' OR v->>'coseHex' IS NULL OR octet_length(decode(v->>'coseHex','hex')) NOT BETWEEN 65 AND 66560
   THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_INPUT'; END IF;
  ELSIF NEW.kind='DISPATCH' THEN
   IF run.reservation_transaction=pg_current_xact_id()::text OR pins.state<>'ACTIVE' OR at_ms>=(run.body->>'deadlineAtMs')::numeric
   OR v->'executor' IS DISTINCT FROM pins.body->'executor'
   OR NOT EXISTS(SELECT 1 FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='INPUT')
   THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_DISPATCH'; END IF;
  ELSE
   IF NOT EXISTS(SELECT 1 FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='DISPATCH') THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_NOT_DISPATCHED'; END IF;
   IF NEW.kind IN ('SOURCE','SAMPLE','CASE') AND EXISTS(SELECT 1 FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='RESULT')
   THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_SEALED'; END IF;
   IF NEW.kind='SOURCE' THEN
    SELECT * INTO STRICT event FROM control.outbox_event WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.record_key::uuid;
    PERFORM openpc.check_notification_delivery_requested_event(event);
    IF v->'original' IS DISTINCT FROM to_jsonb(event) OR event.aggregate_type<>'notification-occurrence' THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_SOURCE_BYTES'; END IF;
    IF v->>'eventId' IS DISTINCT FROM NEW.record_key
     OR (SELECT count(*) FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='SOURCE')>=(pins.body->>'maximumSources')::numeric
     OR EXISTS(SELECT 1 FROM control.notification_qualification_record WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND kind='SOURCE' AND record_key=NEW.record_key)
     THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_SOURCE'; END IF;
   ELSIF NEW.kind='SAMPLE' THEN
    IF (SELECT count(*) FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='SAMPLE')>=(pins.body->>'maximumSamples')::numeric
     OR jsonb_typeof(v->'atMs') IS DISTINCT FROM 'number' OR (v->>'atMs')::numeric>at_ms
     THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_SAMPLE'; END IF;
   ELSIF NEW.kind='CASE' THEN
    IF v->>'caseId' IS DISTINCT FROM NEW.record_key OR NEW.record_key NOT IN ('POSITIVE','DUPLICATE_REPLAY','CRASH_LEASE','POISON_QUARANTINE','SATURATION_CANCEL')
     OR (v->>'status' IN ('PASS','FAIL','BLOCKED','UNKNOWN')) IS NOT TRUE
     THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_CASE'; END IF;
   ELSIF NEW.kind='RESULT' THEN
    IF (SELECT count(*) FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='CASE')<>5
     OR NOT EXISTS(SELECT 1 FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='RAW' AND body_digest=v->>'rawEvidenceDigest')
     OR NOT EXISTS(SELECT 1 FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='OUTCOMES' AND body_digest=v->>'originalSignedOutcomesDigest')
     THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_RESULT'; END IF;
   ELSIF NEW.kind='NORMALIZED' THEN
    IF NOT EXISTS(SELECT 1 FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='RESULT') THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_RESULT'; END IF;
   ELSIF NEW.kind='REVIEW' THEN
    IF pins.state<>'ACTIVE' OR v->'reviewer' IS DISTINCT FROM pins.body->'reviewer'
     OR NOT EXISTS(SELECT 1 FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='NORMALIZED' AND body_digest=v->>'normalizedResultsDigest')
     OR (v->>'decision' IN ('ACCEPTED','REJECTED')) IS NOT TRUE
     THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_REVIEW'; END IF;
   ELSIF NEW.kind='CAPACITY' THEN
    IF pins.state<>'ACTIVE' OR NOT EXISTS(SELECT 1 FROM control.notification_qualification_record WHERE run_id=NEW.run_id AND kind='REVIEW' AND body->'value'->>'decision'='ACCEPTED')
     THEN RAISE EXCEPTION 'NOTIFICATION_QUALIFICATION_CAPACITY'; END IF;
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_notification_qualification() FROM PUBLIC;
${['installation', 'origin', 'origin_proof', 'run', 'record']
  .map((suffix) => {
    const table = `notification_qualification_${suffix}`;
    return `ALTER TABLE control.${table} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${table} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.${table} TO openpc_operations_qualification_owner,openpc_operations_qualification_bootstrap;
GRANT UPDATE ON control.${table} TO openpc_operations_qualification_owner;
GRANT INSERT${suffix === 'installation' ? ',UPDATE' : ''} ON control.${table} TO ${suffix === 'installation' ? 'openpc_operations_qualification_bootstrap' : 'openpc_operations_qualification_owner'};
CREATE POLICY notification_qualification_read ON control.${table} FOR SELECT TO openpc_operations_qualification_owner,openpc_operations_qualification_bootstrap USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
CREATE POLICY notification_qualification_write ON control.${table} FOR ALL TO ${suffix === 'installation' ? 'openpc_operations_qualification_bootstrap' : 'openpc_operations_qualification_owner'} USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)) WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
CREATE POLICY notification_qualification_lock ON control.${table} FOR UPDATE TO openpc_operations_qualification_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)) WITH CHECK(false);
CREATE TRIGGER notification_qualification_guard BEFORE INSERT OR UPDATE OR DELETE ON control.${table} FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_qualification();
CREATE TRIGGER notification_qualification_truncate_guard BEFORE TRUNCATE ON control.${table} FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_notification_qualification();`;
  })
  .join('\n')}
`;
