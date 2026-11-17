import { businessTransitionProfiles } from '../../../../packages/security-kernel/src/business-transition/profiles.generated.ts';
import { businessTransitionCoseContext } from '../../../../packages/security-kernel/src/business-transition/generated.ts';
const ordinaryProfiles = businessTransitionProfiles
  .filter(
    (profile) =>
      profile.schemaDefinitionDigest === businessTransitionCoseContext.definitionDigest &&
      [
        'indexer-profile',
        'module-registration',
        'evidence-hold',
        'retention-policy',
        'evidence-deletion',
        'store-retirement',
        'runtime-artifact-disposition',
        'work-item',
        'notification',
        'notification-endpoint',
        'workload-renewal-policy',
      ].includes(profile.aggregateType),
  )
  .map((profile) => `decode('${profile.profileDigest.slice(7)}','hex')`)
  .join(',');

/** An ordinary reservation and occurrence commit together; durable lifecycle reservations have their own owner. */
export const receiptSigningAttemptGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_receipt_signing_attempt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE payload jsonb; profile control.business_transition_profile%ROWTYPE;
BEGIN
 payload:=openpc.business_cbor(NEW.payload_cbor);
 SELECT * INTO STRICT profile FROM control.business_transition_profile WHERE profile_digest=NEW.profile_digest;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR
    NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id() OR
    NEW.operation_id IS DISTINCT FROM openpc.current_operation_id() OR
    profile.action_intent_id IS DISTINCT FROM openpc.current_action_intent_id() OR
    payload->'0' IS DISTINCT FROM openpc.business_uuid(NEW.attempt_id) OR
    payload->'1' IS DISTINCT FROM openpc.business_bytes(profile.schema_definition_digest) OR
    payload->>'2' IS DISTINCT FROM profile.profile_id OR payload->'3' IS DISTINCT FROM to_jsonb(profile.profile_version) OR
    payload->'4' IS DISTINCT FROM openpc.business_bytes(NEW.profile_digest) OR
    payload->'6' IS DISTINCT FROM openpc.business_uuid(NEW.participant_id) OR
    payload->'7' IS DISTINCT FROM openpc.business_uuid(NEW.privacy_domain_id) OR
    payload->'8' IS DISTINCT FROM openpc.business_uuid(NEW.operation_id) OR
    payload->>'9' IS DISTINCT FROM profile.action_intent_id OR payload->>'10' IS DISTINCT FROM profile.catalog_operation_id OR
    payload->>'11' IS DISTINCT FROM profile.aggregate_type OR
    payload->>'24' IS DISTINCT FROM NEW.signer_id OR
    payload->'25' IS DISTINCT FROM openpc.business_bytes(NEW.signer_trust_digest) OR
    jsonb_typeof(payload->'23') IS DISTINCT FROM 'number' OR (payload->>'23')::numeric>NEW.reserved_at_ns OR
    NEW.reserved_at_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000 OR
    NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=NEW.participant_id
     AND i.privacy_domain_id=NEW.privacy_domain_id AND i.operation_id=NEW.operation_id AND i.terminal_state IS NULL
     AND payload->'17'=openpc.business_uuid(i.idempotency_record_id) AND payload->'16'=openpc.business_bytes(i.input_digest)
     AND i.action_intent_id=profile.action_intent_id AND i.catalog_operation_id=profile.catalog_operation_id)
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-PAYLOAD'; END IF;
 IF (NEW.reservation_kind='ORDINARY_ATOMIC' AND
     (NEW.schema_version<>1 OR profile.profile_digest NOT IN (${ordinaryProfiles}))) OR
    (NEW.reservation_kind='LIFECYCLE_DURABLE' AND (NEW.schema_version<>2 OR profile.aggregate_type<>'signing-key-rotation')) THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-OWNER'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.business_signing_selection s
  JOIN control.business_signing_key k USING(participant_id,privacy_domain_id,signer_id)
  JOIN control.business_signing_key_state ks USING(participant_id,privacy_domain_id,signer_id)
  WHERE s.participant_id=NEW.participant_id AND s.privacy_domain_id=NEW.privacy_domain_id
   AND s.environment_id=payload->>'5' AND s.profile_digest=NEW.profile_digest AND s.signer_id=NEW.signer_id
   AND s.row_version=NEW.selection_version AND s.admission_version=NEW.admission_version AND s.fence_generation=NEW.fence_generation
   AND s.fenced_operation_id IS NULL
   AND k.trust_digest=NEW.signer_trust_digest AND k.key_epoch=NEW.key_epoch AND ks.state='ACTIVE'
   AND k.valid_from_ns<=(payload->>'23')::numeric AND k.valid_until_ns>NEW.reserved_at_ns
   FOR SHARE OF s,ks) THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ATTEMPT-FENCE'; END IF;
 IF NOT openpc.signing_admission_open(NEW.participant_id,NEW.privacy_domain_id,NEW.signer_id,NEW.operation_id)
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-UNRESOLVED-ADMISSION'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER receipt_signing_attempt_typed BEFORE INSERT ON control.receipt_signing_attempt
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_receipt_signing_attempt();
CREATE OR REPLACE FUNCTION openpc.check_receipt_signing_attempt_completion()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.reservation_kind='ORDINARY_ATOMIC' THEN
  IF NOT EXISTS(SELECT 1 FROM control.audit_occurrence r WHERE r.participant_id=NEW.participant_id
   AND r.privacy_domain_id=NEW.privacy_domain_id AND r.operation_id=NEW.operation_id
   AND r.receipt_id=NEW.attempt_id AND r.receipt_cbor=NEW.payload_cbor AND r.receipt_digest=NEW.payload_digest)
  THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-ATOMIC-SIGNING-ATTEMPT'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM control.signing_rotation_attestation a JOIN control.signing_provider_attempt p USING(attempt_id)
   WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id
    AND a.operation_id=NEW.operation_id AND a.attempt_id=NEW.attempt_id AND a.receipt_cbor=NEW.payload_cbor
    AND a.signer_id=NEW.signer_id AND a.signer_trust_digest=NEW.signer_trust_digest
    AND a.selection_version=NEW.selection_version AND p.request->>'method'='SIGN_RECEIPT'
    AND p.request->>'payloadHex'=encode(NEW.payload_cbor,'hex') AND p.request->>'attemptId'=NEW.attempt_id::text)
  THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-LIFECYCLE-SIGNING-ATTEMPT'; END IF;
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER receipt_signing_attempt_complete AFTER INSERT ON control.receipt_signing_attempt
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_receipt_signing_attempt_completion();
CREATE OR REPLACE FUNCTION openpc.guard_receipt_attempt_reference()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.receipt_signing_attempt a WHERE a.participant_id=NEW.participant_id
  AND a.privacy_domain_id=NEW.privacy_domain_id AND a.operation_id=NEW.operation_id AND a.attempt_id=NEW.receipt_id
  AND a.payload_cbor=NEW.receipt_cbor AND a.payload_digest=NEW.receipt_digest AND a.signer_id=NEW.signer_id
  AND a.signer_trust_digest=NEW.signer_trust_snapshot_digest AND a.profile_digest=NEW.profile_digest)
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-SIGNING-ATTEMPT-REQUIRED'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER receipt_attempt_reference BEFORE INSERT ON control.audit_occurrence
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_receipt_attempt_reference();
`;
