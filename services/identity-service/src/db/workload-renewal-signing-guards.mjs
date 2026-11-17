import {
  workloadRenewalSigningProfile,
  workloadRenewalSigningProfileDigest,
} from '../../../../packages/security-kernel/src/workload-renewal/generated-signing.ts';

/** Complete Participant history is an owning projection, never a private-domain
 * filtered coalesce. Invoker role/context/RLS are checked before authoritative0. */
export const workloadRenewalSigningGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.workload_renewal_participant_security_epoch(wanted_participant uuid,wanted_privacy uuid)
RETURNS numeric LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $wr_security$
DECLARE history_oid oid; history_owner text; enabled boolean; forced boolean; policies jsonb; epoch numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=current_user AND NOT r.rolsuper AND NOT r.rolbypassrls)
   OR NOT (pg_has_role(current_user,'openpc_control_runtime','USAGE')
    OR pg_has_role(current_user,'openpc_control_worker','USAGE')
    OR pg_has_role(current_user,'openpc_control_reader','USAGE')
    OR pg_has_role(current_user,'openpc_control_platform_runtime','USAGE'))
   OR pg_has_role(current_user,'openpc_control_owner','MEMBER')
   OR pg_has_role(current_user,'openpc_control_key_governor','MEMBER')
   OR pg_has_role(current_user,'openpc_control_maintenance','MEMBER')
   OR current_setting('row_security')<>'on'
   OR openpc.current_participant_id() IS DISTINCT FROM wanted_participant
   OR openpc.current_privacy_domain_id() IS DISTINCT FROM wanted_privacy THEN
  RAISE EXCEPTION 'DATA-6021-RENEWAL-SECURITY-HISTORY-VISIBILITY';
 END IF;
 SELECT c.oid,owner.rolname,c.relrowsecurity,c.relforcerowsecurity INTO STRICT history_oid,history_owner,enabled,forced
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles owner ON owner.oid=c.relowner
 WHERE n.nspname='control' AND c.relname='participant_lifecycle_transition' AND c.relkind='r';
 SELECT jsonb_agg(jsonb_build_object('name',p.polname,'permissive',p.polpermissive,'command',p.polcmd,
  'roles',(SELECT jsonb_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid=ANY(p.polroles)),
  'using',pg_get_expr(p.polqual,p.polrelid)) ORDER BY p.polname) INTO policies
 FROM pg_policy p WHERE p.polrelid=history_oid;
 IF history_owner<>'openpc_control_owner' OR NOT enabled OR NOT forced OR NOT has_table_privilege(current_user,history_oid,'SELECT')
  OR policies IS DISTINCT FROM '[{"name":"participant_isolation","permissive":true,"command":"*","roles":["openpc_control_platform_runtime","openpc_control_reader","openpc_control_runtime","openpc_control_worker"],"using":"openpc.matches_participant(participant_id)"}]'::jsonb THEN
  RAISE EXCEPTION 'DATA-6021-RENEWAL-SECURITY-HISTORY-VISIBILITY';
 END IF;
 IF EXISTS(SELECT 1 FROM control.participant_lifecycle_transition t WHERE t.participant_id=wanted_participant
   AND t.mutation NOT IN ('ARCHIVE','RESTORE','SHRINK','TRANSFER')) THEN
  RAISE EXCEPTION 'DATA-6021-RENEWAL-SECURITY-HISTORY-UNKNOWN';
 END IF;
 SELECT coalesce((SELECT t.new_epoch FROM control.participant_lifecycle_transition t
   WHERE t.participant_id=p.participant_id AND t.mutation='ARCHIVE' ORDER BY t.new_epoch DESC LIMIT 1),0)
 INTO STRICT epoch FROM control.participant p JOIN control.privacy_domain d ON d.participant_id=p.participant_id
 WHERE p.participant_id=wanted_participant AND p.state='ACTIVE' AND d.privacy_domain_id=wanted_privacy AND d.state='ACTIVE';
 IF epoch NOT BETWEEN 0 AND 18446744073709551615 THEN RAISE EXCEPTION 'DATA-6021-RENEWAL-SECURITY-HISTORY-INVALID'; END IF;
 RETURN epoch;
END $wr_security$;
ALTER FUNCTION openpc.workload_renewal_participant_security_epoch(uuid,uuid) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.workload_renewal_participant_security_epoch(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.workload_renewal_participant_security_epoch(uuid,uuid)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_workload_renewal_signing_selection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $wr_selection$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-RENEWAL-SIGNING-SELECTION'; END IF;
 IF NOT pg_has_role(current_user,'openpc_control_key_governor','MEMBER') AND NOT pg_has_role(current_user,'openpc_control_owner','MEMBER') THEN
  RAISE EXCEPTION 'DATA-6021-RENEWAL-SIGNING-INSTALLATION-AUTHORITY';
 END IF;
 IF NEW.profile_digest<>decode('${workloadRenewalSigningProfileDigest.slice(7)}','hex') OR NEW.admission_version<>1
  OR NOT EXISTS(SELECT 1 FROM control.workload_renewal_signing_grant g
   JOIN control.business_signing_key k USING(participant_id,privacy_domain_id,signer_id,signing_purpose_code)
   JOIN control.business_signing_key_state state USING(participant_id,privacy_domain_id,signer_id)
   JOIN control.workload_credential_family f ON f.participant_id=g.participant_id AND f.privacy_domain_id=g.privacy_domain_id AND f.family_id=g.family_id
   JOIN control.credential c ON c.participant_id=f.participant_id AND c.credential_id=f.current_credential_id
   JOIN control.principal p ON p.participant_id=f.participant_id AND p.principal_id=f.principal_id
   JOIN control.privacy_domain d ON d.participant_id=f.participant_id AND d.privacy_domain_id=f.privacy_domain_id
   WHERE g.participant_id=NEW.participant_id AND g.privacy_domain_id=NEW.privacy_domain_id AND g.signer_id=NEW.signer_id
    AND g.profile_digest=NEW.profile_digest AND k.environment_id=NEW.environment_id AND k.signing_purpose_code=376
    AND state.state='ACTIVE' AND state.row_version=g.key_security_generation
    AND f.state='ACTIVE' AND f.principal_id=g.principal_id AND f.workload_id=g.workload_id AND f.security_epoch=g.family_security_epoch
    AND c.kind='WORKLOAD_MTLS' AND c.state='ACTIVE' AND c.principal_id=f.principal_id AND c.audience=f.workload_id
    AND c.secret_fingerprint=f.current_fingerprint AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
    AND p.kind='WORKLOAD' AND p.state='ACTIVE' AND d.state='ACTIVE'
    AND k.valid_from_ns<=floor(extract(epoch FROM clock_timestamp())*1000000)*1000
    AND k.valid_until_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000
    FOR SHARE OF state) THEN
  RAISE EXCEPTION 'DATA-6021-RENEWAL-SIGNING-CURRENT-KEY';
 END IF;
 RETURN NEW;
END $wr_selection$;
ALTER FUNCTION openpc.guard_workload_renewal_signing_selection() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.guard_workload_renewal_signing_selection() FROM PUBLIC;
DROP TRIGGER IF EXISTS wr_signing_selection_guard ON control.workload_renewal_signing_selection;
CREATE TRIGGER wr_signing_selection_guard BEFORE INSERT OR UPDATE OR DELETE ON control.workload_renewal_signing_selection
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_renewal_signing_selection();
`;

/** Exact order is emitted from the reviewed metadata. Never bind broad
 * authorization epochs or the historical transport leaf into this v2 trust. */
export const workloadRenewalSigningTrustBranchSql = `
 ELSIF key_row.signing_purpose_code=376 THEN
  SELECT to_jsonb(g) INTO STRICT renewal_grant FROM control.workload_renewal_signing_grant g
   JOIN control.workload_renewal_signing_profile p USING(profile_digest)
   WHERE g.participant_id=key_row.participant_id AND g.privacy_domain_id=key_row.privacy_domain_id AND g.signer_id=key_row.signer_id
    AND g.signing_purpose_code=376 AND p.profile_digest=decode('${workloadRenewalSigningProfileDigest.slice(7)}','hex');
  IF EXISTS(SELECT 1 FROM control.business_signing_grant g WHERE g.participant_id=key_row.participant_id
    AND g.privacy_domain_id=key_row.privacy_domain_id AND g.signer_id=key_row.signer_id)
    OR EXISTS(SELECT 1 FROM control.identity_envelope_signing_grant g WHERE g.participant_id=key_row.participant_id
    AND g.privacy_domain_id=key_row.privacy_domain_id AND g.signer_id=key_row.signer_id) THEN
   RAISE EXCEPTION 'DATA-6021-MIXED-SIGNING-PURPOSE-GRANTS';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal p USING(participant_id,principal_id)
   JOIN control.workload_credential_family f ON f.participant_id=c.participant_id AND f.privacy_domain_id=key_row.privacy_domain_id
    AND f.family_id=(renewal_grant->>'family_id')::uuid
   WHERE c.participant_id=key_row.participant_id AND c.credential_id=key_row.workload_credential_id
    AND c.principal_id=(renewal_grant->>'principal_id')::uuid AND c.audience=renewal_grant->>'workload_id'
    AND f.principal_id=c.principal_id AND f.workload_id=c.audience AND p.kind='WORKLOAD') THEN
   RAISE EXCEPTION 'DATA-6021-SIGNING-WORKLOAD-BINDING';
  END IF;
  actual:=openpc.business_cbor(key_row.trust_preimage);
  expected:=jsonb_build_array('${workloadRenewalSigningProfile.trustDomain}',openpc.business_uuid(key_row.participant_id),
   openpc.business_uuid(key_row.privacy_domain_id),key_row.environment_id,openpc.business_uuid((renewal_grant->>'principal_id')::uuid),
   renewal_grant->>'workload_id',openpc.business_uuid((renewal_grant->>'family_id')::uuid),
   (renewal_grant->>'family_security_epoch')::numeric,(renewal_grant->>'participant_security_invalidation_epoch')::numeric,
   (renewal_grant->>'key_security_generation')::numeric,openpc.business_bytes(decode(substring(key_row.signer_id from 8),'hex')),
   openpc.business_bytes(key_row.public_key_spki_der),key_row.key_epoch,key_row.valid_from_ns,key_row.valid_until_ns,
   openpc.business_bytes(decode(substring(renewal_grant->>'provider_qualification_digest' from 3),'hex')),
   key_row.admission_kind,key_row.admission_reference,openpc.business_bytes(key_row.admission_digest),
   key_row.secret_class,key_row.secret_reference,key_row.secret_version,24039,1,376,
   openpc.business_bytes(decode('${workloadRenewalSigningProfile.schemaDefinitionDigest.slice(7)}','hex')),
   '${workloadRenewalSigningProfile.profileId}',2,openpc.business_bytes(decode('${workloadRenewalSigningProfileDigest.slice(7)}','hex')),
   'POLICY_AUTHORIZED','${workloadRenewalSigningProfile.actionIntentId}','${workloadRenewalSigningProfile.catalogOperationId}');
`;
