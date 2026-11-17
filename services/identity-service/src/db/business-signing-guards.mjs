import { businessTransitionCoseContext } from '../../../../packages/security-kernel/src/business-transition/generated.ts';
import { businessTransitionCoseContextV2 } from '../../../../packages/security-kernel/src/business-transition/generated-v2.ts';
import { workloadRenewalSigningTrustBranchSql } from './workload-renewal-signing-guards.mjs';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
} from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';

/** Projected by the owning Drizzle security-tail generator, never patched into migration SQL. */
export const businessSigningGuardsSql = `
DO $role$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='openpc_control_key_governor') THEN
  CREATE ROLE openpc_control_key_governor NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
 END IF;
END $role$;
CREATE OR REPLACE FUNCTION openpc.check_business_signing_trust()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE key_row control.business_signing_key%ROWTYPE; grants jsonb; renewal_grant jsonb; actual jsonb; expected jsonb; schema_digest text; schema_count integer; receipt_version integer;
BEGIN
 SELECT * INTO STRICT key_row FROM control.business_signing_key
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND signer_id=NEW.signer_id;
 IF NOT pg_has_role(current_user,'openpc_control_key_governor','MEMBER') AND
    NOT pg_has_role(current_user,'openpc_control_owner','MEMBER') AND key_row.admission_kind<>'GOVERNED' THEN
   RAISE EXCEPTION 'DATA-6021-SIGNING-BOOTSTRAP-AUTHORITY';
 END IF;
 IF key_row.signing_purpose_code=371 THEN
  SELECT jsonb_build_array(p.profile_id,p.profile_version,openpc.business_bytes(p.profile_digest),
    'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1','ID-OP-ENVELOPE-ACTIVATE') INTO STRICT grants
   FROM control.identity_envelope_signing_grant g JOIN control.identity_envelope_signing_profile p USING(profile_digest)
   WHERE g.participant_id=key_row.participant_id AND g.privacy_domain_id=key_row.privacy_domain_id
     AND g.signer_id=key_row.signer_id AND g.signing_purpose_code=371
     AND p.profile_digest=decode('${identityEnvelopeSigningProfileDigest.slice(7)}','hex');
  IF EXISTS(SELECT 1 FROM control.business_signing_grant g WHERE g.participant_id=key_row.participant_id
    AND g.privacy_domain_id=key_row.privacy_domain_id AND g.signer_id=key_row.signer_id) THEN
   RAISE EXCEPTION 'DATA-6021-MIXED-SIGNING-PURPOSE-GRANTS';
  END IF;
  actual:=openpc.business_cbor(key_row.trust_preimage);
  expected:=jsonb_build_array('pc.identity.authority-envelope-signing-trust.v1',openpc.business_uuid(key_row.participant_id),
   openpc.business_uuid(key_row.privacy_domain_id),key_row.environment_id,key_row.signer_id,
   openpc.business_bytes(key_row.public_key_spki_der),openpc.business_uuid(key_row.workload_credential_id),
   key_row.workload_credential_epoch,key_row.envelope_workload_participant_epoch,key_row.envelope_workload_principal_epoch,
   key_row.key_epoch,key_row.valid_from_ns,key_row.valid_until_ns,
   key_row.admission_kind,key_row.admission_reference,openpc.business_bytes(key_row.admission_digest),
   key_row.secret_class,key_row.secret_reference,key_row.secret_version,24034,1,371,
   openpc.business_bytes(decode('${identityEnvelopeContext.definitionDigest.slice(7)}','hex')),grants);
 ELSIF key_row.signing_purpose_code=338 THEN
 SELECT jsonb_agg(jsonb_build_array(p.profile_id,p.profile_version,openpc.business_bytes(p.profile_digest),
   p.action_intent_id,p.catalog_operation_id) ORDER BY convert_to(p.profile_id,'UTF8'),p.profile_version)
 INTO grants FROM control.business_signing_grant g JOIN control.business_transition_profile p USING(profile_digest)
 WHERE g.participant_id=key_row.participant_id AND g.privacy_domain_id=key_row.privacy_domain_id AND g.signer_id=key_row.signer_id;
 IF grants IS NULL OR jsonb_array_length(grants) NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-SIGNING-GRANTS'; END IF;
 SELECT count(DISTINCT p.schema_definition_digest),min(encode(p.schema_definition_digest,'hex'))
 INTO schema_count,schema_digest FROM control.business_signing_grant g JOIN control.business_transition_profile p USING(profile_digest)
 WHERE g.participant_id=key_row.participant_id AND g.privacy_domain_id=key_row.privacy_domain_id AND g.signer_id=key_row.signer_id;
 IF schema_count<>1 THEN RAISE EXCEPTION 'DATA-6021-MIXED-SIGNING-SCHEMA-GRANTS'; END IF;
 receipt_version:=CASE schema_digest
  WHEN '${businessTransitionCoseContext.definitionDigest.slice(7)}' THEN 1
  WHEN '${businessTransitionCoseContextV2.definitionDigest.slice(7)}' THEN 2 END;
 IF receipt_version IS NULL THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-SIGNING-SCHEMA'; END IF;
 actual:=openpc.business_cbor(key_row.trust_preimage);
 expected:=jsonb_build_array('pc.control.business-signing-trust.v1',openpc.business_uuid(key_row.participant_id),
   openpc.business_uuid(key_row.privacy_domain_id),key_row.environment_id,key_row.signer_id,
   openpc.business_bytes(key_row.public_key_spki_der),openpc.business_uuid(key_row.workload_credential_id),
   key_row.workload_credential_epoch,key_row.key_epoch,key_row.valid_from_ns,key_row.valid_until_ns,
   key_row.admission_kind,key_row.admission_reference,openpc.business_bytes(key_row.admission_digest),
   key_row.secret_class,key_row.secret_reference,key_row.secret_version,24001,receipt_version,338,grants);
 ${workloadRenewalSigningTrustBranchSql}
 ELSE RAISE EXCEPTION 'DATA-6021-UNADMITTED-SIGNING-PURPOSE'; END IF;
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-SIGNING-TRUST-BINDING'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal p USING(participant_id,principal_id)
  WHERE c.participant_id=key_row.participant_id AND c.credential_id=key_row.workload_credential_id
    AND p.kind='WORKLOAD' AND c.kind IN ('WORKLOAD_OIDC','WORKLOAD_MTLS')
    AND c.credential_epoch=key_row.workload_credential_epoch
    AND c.public_key_digest IS DISTINCT FROM sha256(key_row.public_key_spki_der)) THEN
   RAISE EXCEPTION 'DATA-6021-SIGNING-WORKLOAD-BINDING';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER business_signing_key_complete AFTER INSERT ON control.business_signing_key
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_business_signing_trust();
CREATE CONSTRAINT TRIGGER business_signing_grant_complete AFTER INSERT ON control.business_signing_grant
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_business_signing_trust();
CREATE CONSTRAINT TRIGGER identity_envelope_signing_grant_complete AFTER INSERT ON control.identity_envelope_signing_grant
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_business_signing_trust();
CREATE CONSTRAINT TRIGGER workload_renewal_signing_grant_complete AFTER INSERT ON control.workload_renewal_signing_grant
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_business_signing_trust();
CREATE OR REPLACE FUNCTION openpc.guard_identity_envelope_signing_selection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT pg_has_role(current_user,'openpc_control_key_governor','MEMBER') AND
    NOT pg_has_role(current_user,'openpc_control_owner','MEMBER') THEN
  RAISE EXCEPTION 'DATA-6021-ENVELOPE-SIGNING-INSTALLATION-AUTHORITY';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.business_signing_key k
   JOIN control.business_signing_key_state state USING(participant_id,privacy_domain_id,signer_id)
   JOIN control.credential credential ON credential.participant_id=k.participant_id
     AND credential.credential_id=k.workload_credential_id
   JOIN control.principal principal ON principal.participant_id=credential.participant_id
     AND principal.principal_id=credential.principal_id
   JOIN control.participant participant ON participant.participant_id=k.participant_id
   WHERE k.participant_id=NEW.participant_id AND k.privacy_domain_id=NEW.privacy_domain_id
     AND k.signer_id=NEW.signer_id AND k.environment_id=NEW.environment_id
     AND k.signing_purpose_code=371 AND state.state='ACTIVE'
     AND k.valid_from_ns<=floor(extract(epoch FROM clock_timestamp())*1000000)*1000
     AND k.valid_until_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000
     AND credential.credential_epoch=k.workload_credential_epoch AND credential.state='ACTIVE'
     AND credential.kind IN ('WORKLOAD_OIDC','WORKLOAD_MTLS')
     AND credential.valid_from<=clock_timestamp() AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
     AND principal.kind='WORKLOAD' AND principal.state='ACTIVE' AND participant.state='ACTIVE'
     AND participant.authority_epoch=k.envelope_workload_participant_epoch
     AND principal.authority_epoch=k.envelope_workload_principal_epoch
     FOR SHARE OF state) THEN
  RAISE EXCEPTION 'DATA-6021-ENVELOPE-SIGNING-CURRENT-KEY';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER identity_envelope_signing_selection_guard BEFORE INSERT ON control.identity_envelope_signing_selection
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_envelope_signing_selection();
CREATE OR REPLACE FUNCTION openpc.guard_business_key_lifecycle()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE key_row control.business_signing_key%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='business_signing_selection' AND TG_OP='UPDATE' AND
  (to_jsonb(NEW)->>'admission_version') IS DISTINCT FROM (to_jsonb(OLD)->>'admission_version') THEN
  IF (to_jsonb(NEW)-'admission_version') IS DISTINCT FROM (to_jsonb(OLD)-'admission_version') OR
   (to_jsonb(NEW)->>'admission_version')::numeric<>(to_jsonb(OLD)->>'admission_version')::numeric+1 OR
   NOT EXISTS(SELECT 1 FROM control.signing_rotation_command c JOIN control.signing_key_rotation r
     ON r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.rotation_id=c.rotation_id
     JOIN control.signing_rotation_observation o ON o.participant_id=c.participant_id AND o.privacy_domain_id=c.privacy_domain_id AND o.operation_id=c.operation_id
    WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
     AND c.operation_id=openpc.current_operation_id() AND c.state='WRITE_AMBIGUITY' AND o.kind='UNRESOLVED'
     AND NEW.signer_id IN(r.old_signer_id,r.new_signer_id))
   THEN RAISE EXCEPTION 'DATA-6021-SIGNING-ADMISSION-VERSION'; END IF;
  RETURN NEW;
 END IF;
 IF NOT pg_has_role(current_user,'openpc_control_key_governor','MEMBER') AND
    NOT pg_has_role(current_user,'openpc_control_owner','MEMBER') THEN
  IF openpc.current_action_intent_id()<>'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' OR
   NOT EXISTS(SELECT 1 FROM control.signing_key_rotation r
    JOIN control.signing_rotation_command command ON command.participant_id=r.participant_id AND command.privacy_domain_id=r.privacy_domain_id
     AND command.rotation_id=r.rotation_id AND command.operation_id=openpc.current_operation_id()
     AND command.action_intent_id=openpc.current_action_intent_id() AND command.state IN ('ACCEPTED','WRITE_AMBIGUITY')
    CROSS JOIN LATERAL (SELECT openpc.signing_transition_effects(command.action_intent_id,r.state,command.to_state) value) effects
    WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
    AND NEW.change_reference='urn:openpc:resource:'||r.rotation_id::text AND r.approval_request_id IS NOT NULL
    AND ((TG_TABLE_NAME='business_signing_selection' AND (effects.value->>'cutover')::boolean AND
       (NEW.signer_id=r.new_signer_id OR (NEW.signer_id=r.old_signer_id AND EXISTS(
         SELECT 1 FROM control.signing_rotation_attestation a WHERE a.participant_id=r.participant_id AND a.privacy_domain_id=r.privacy_domain_id
          AND a.rotation_id=r.rotation_id AND a.operation_id=command.operation_id AND a.from_revision=r.revision
          AND a.to_state=command.to_state AND a.history_digest=NEW.change_digest
          AND to_jsonb(NEW)->>'fenced_operation_id'=a.operation_id::text))))
      OR (TG_TABLE_NAME='business_signing_key_state' AND
       (((effects.value->>'admitTrust')::boolean AND TG_OP='INSERT' AND NEW.signer_id=r.new_signer_id AND to_jsonb(NEW)->>'state'='ADMITTED')
        OR ((effects.value->>'cutover')::boolean AND ((NEW.signer_id=r.new_signer_id AND to_jsonb(NEW)->>'state'='ACTIVE')
          OR (NEW.signer_id=r.old_signer_id AND to_jsonb(NEW)->>'state'='RETIRED')))
        OR ((effects.value->>'revoke')::boolean AND NEW.signer_id=r.old_signer_id AND to_jsonb(NEW)->>'state'='REVOKED'))))) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='PC-AUTH-0005-KEY-GOVERNANCE-REQUIRED';
  END IF;
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-KEY-HISTORY'; END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.participant_id<>OLD.participant_id OR NEW.privacy_domain_id<>OLD.privacy_domain_id OR
     NEW.row_version<>OLD.row_version+1 OR NEW.changed_at_ns<OLD.changed_at_ns OR
     NEW.change_digest=OLD.change_digest THEN RAISE EXCEPTION 'DATA-6021-KEY-LIFECYCLE-REVISION'; END IF;
  IF TG_TABLE_NAME='business_signing_key_state' THEN
   IF NEW.signer_id<>OLD.signer_id OR NOT (
     (OLD.state='ADMITTED' AND NEW.state IN ('ACTIVE','REVOKED','COMPROMISED')) OR
     (OLD.state='ACTIVE' AND NEW.state IN ('RETIRED','REVOKED','COMPROMISED')) OR
     (OLD.state='RETIRED' AND NEW.state IN ('REVOKED','COMPROMISED')) OR
     (OLD.state='REVOKED' AND NEW.state='COMPROMISED')) THEN RAISE EXCEPTION 'DATA-6021-KEY-LIFECYCLE-TRANSITION'; END IF;
  ELSE
   IF NEW.environment_id<>OLD.environment_id OR NEW.profile_digest<>OLD.profile_digest OR NOT (
      (NEW.signer_id=OLD.signer_id AND OLD.fenced_operation_id IS NULL AND NEW.fenced_operation_id IS NOT NULL
       AND NEW.fenced_operation_id=openpc.current_operation_id() AND NEW.fence_generation=OLD.fence_generation+1) OR
      (NEW.signer_id<>OLD.signer_id AND OLD.fenced_operation_id IS NOT NULL AND OLD.fenced_operation_id=openpc.current_operation_id()
       AND NEW.fenced_operation_id IS NULL AND NEW.fence_generation=OLD.fence_generation))
   THEN RAISE EXCEPTION 'DATA-6021-KEY-SELECTION-TRANSITION'; END IF;
  END IF;
 ELSE
  IF NEW.row_version<>1 THEN RAISE EXCEPTION 'DATA-6021-KEY-LIFECYCLE-REVISION'; END IF;
  IF TG_TABLE_NAME='business_signing_key_state' THEN
   IF NEW.state<>'ADMITTED' THEN RAISE EXCEPTION 'DATA-6021-KEY-LIFECYCLE-TRANSITION'; END IF;
  END IF;
 END IF;
 IF TG_TABLE_NAME='business_signing_selection' THEN
  IF TG_OP='INSERT' AND (NEW.fence_generation<>1 OR NEW.admission_version<>1 OR NEW.fenced_operation_id IS NOT NULL) THEN RAISE EXCEPTION 'DATA-6021-KEY-SELECTION-FENCE'; END IF;
  SELECT k.* INTO STRICT key_row FROM control.business_signing_key k
   JOIN control.business_signing_key_state s USING(participant_id,privacy_domain_id,signer_id)
   WHERE k.participant_id=NEW.participant_id AND k.privacy_domain_id=NEW.privacy_domain_id
    AND k.signer_id=NEW.signer_id AND k.environment_id=NEW.environment_id AND s.state='ACTIVE'
    AND k.valid_from_ns<=floor(extract(epoch FROM clock_timestamp())*1000000)*1000
    AND k.valid_until_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000 FOR SHARE OF s;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER business_signing_state_guard BEFORE INSERT OR UPDATE OR DELETE ON control.business_signing_key_state
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_key_lifecycle();
CREATE TRIGGER business_signing_selection_guard BEFORE INSERT OR UPDATE OR DELETE ON control.business_signing_selection
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_key_lifecycle();
`;
