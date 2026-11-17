/** Immutable installation custody is not a recovery lease. Cryptographic input
 * verification belongs to the host enrollment owner and every live case read. */
export const identityEnvelopeRecoveryGuardsSql = `
-- Fact-only live source validation. The actual fixed actor, signature, issuer,
-- credential, ceremony and effect authority remain mandatory application fences.
CREATE OR REPLACE FUNCTION openpc.identity_envelope_recovery_source_current(p_enrollment uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 RETURN openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
 AND EXISTS(SELECT 1 FROM control.identity_envelope_recovery_enrollment e
  JOIN control.identity_envelope_recovery_custody_trust t ON t.custody_trust_id=e.custody_trust_id
   AND t.participant_id=e.participant_id AND t.privacy_domain_id=e.privacy_domain_id
   AND t.platform_context_id=e.platform_context_id AND t.document_digest=e.custody_trust_digest
   AND t.state='ACTIVE' AND t.row_version=1 AND t.valid_from<=e.valid_from AND t.valid_until>=e.valid_until
  JOIN control.platform_context p ON p.platform_context_id=e.platform_context_id
   AND p.owner_participant_id=e.participant_id AND p.state='ACTIVE'
   AND p.authority_epoch::text=e.document->>'rootEpoch' AND p.row_version::text=e.document->>'rootRevision'
  JOIN control.operations_installation i ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id
   AND i.environment_id=e.document->>'installationEnvironmentId' AND i.installation_digest=e.document->>'installationDigest'
   AND i.state='ACTIVE'
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
   AND e.state='ACTIVE' AND e.row_version=1 AND e.valid_from<=clock_timestamp() AND e.valid_until>clock_timestamp()
   AND e.document_digest=sha256(convert_to(openpc.signing_canonical_json(e.document),'UTF8'))
   AND t.document_digest=sha256(convert_to(openpc.signing_canonical_json(t.document),'UTF8'))
   AND i.installation_bytes=convert_to(openpc.signing_canonical_json(i.installation),'UTF8')
   AND i.installation_digest='sha256:'||encode(sha256(i.installation_bytes),'hex')
   AND openpc.operations_source_authentication_valid(i.installation)
   AND NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.platform_context_id=p.platform_context_id AND r.state='WITHDRAWING'));
END $$;
REVOKE ALL ON FUNCTION openpc.identity_envelope_recovery_source_current(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.identity_envelope_recovery_source_current(uuid) TO openpc_control_runtime,openpc_control_platform_runtime;

CREATE OR REPLACE FUNCTION openpc.lock_identity_envelope_recovery_enrollment(p_enrollment uuid)
RETURNS SETOF control.identity_envelope_recovery_enrollment LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 PERFORM 1 FROM control.participant WHERE participant_id=openpc.current_participant_id() AND state='ACTIVE' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 PERFORM 1 FROM control.platform_context p JOIN control.identity_envelope_recovery_enrollment e
  ON e.platform_context_id=p.platform_context_id AND e.participant_id=p.owner_participant_id
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
   AND p.state='ACTIVE' FOR SHARE OF p;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 PERFORM 1 FROM control.identity_envelope_recovery_custody_trust t
  JOIN control.identity_envelope_recovery_enrollment e ON e.custody_trust_id=t.custody_trust_id
   AND e.participant_id=t.participant_id AND e.privacy_domain_id=t.privacy_domain_id AND e.custody_trust_digest=t.document_digest
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
  FOR SHARE OF t;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 -- Declare the affected issuer write before session/credential children. The
 -- parent Participant write serializes same-Participant recovery/cutover.
 PERFORM 1 FROM control.principal issuer JOIN control.identity_envelope_recovery_enrollment e
  ON e.participant_id=issuer.participant_id AND issuer.principal_id::text=e.document->>'issuerPrincipalId'
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
   AND issuer.state='ACTIVE' AND issuer.kind='WORKLOAD' FOR UPDATE OF issuer;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 RETURN QUERY SELECT e.* FROM control.identity_envelope_recovery_enrollment e
  WHERE e.enrollment_id=p_enrollment AND openpc.matches_participant(e.participant_id) AND openpc.matches_privacy(e.privacy_domain_id)
  FOR SHARE;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_identity_envelope_recovery_enrollment(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_identity_envelope_recovery_enrollment(uuid) TO openpc_control_runtime,openpc_control_platform_runtime;

-- INVOKER and a separate statement retain FORCE RLS without recursively
-- expanding the Root's envelope policy inside identity row-lock policies.
-- This is installation read eligibility, never business or lease authority.
CREATE OR REPLACE FUNCTION openpc.identity_envelope_recovery_installation_source_current(p_enrollment uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 RETURN current_user='openpc_control_owner'
 AND pg_has_role(session_user,'openpc_control_owner','MEMBER')
 AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
 AND openpc.current_action_intent_id() IN ('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')
 AND EXISTS(SELECT 1 FROM control.identity_envelope_recovery_enrollment enrollment
  JOIN control.identity_envelope_recovery_custody_trust trust ON trust.custody_trust_id=enrollment.custody_trust_id
   AND trust.participant_id=enrollment.participant_id AND trust.privacy_domain_id=enrollment.privacy_domain_id
   AND trust.platform_context_id=enrollment.platform_context_id AND trust.document_digest=enrollment.custody_trust_digest
   AND trust.state='ACTIVE' AND trust.row_version=1
   AND trust.valid_from<=enrollment.valid_from AND trust.valid_until>=enrollment.valid_until
  JOIN control.platform_context root ON root.platform_context_id=enrollment.platform_context_id
   AND root.owner_participant_id=enrollment.participant_id AND root.state='ACTIVE'
   AND root.authority_epoch::text=enrollment.document->>'rootEpoch'
   AND root.row_version::text=enrollment.document->>'rootRevision'
  JOIN (
   SELECT platform_context_id,owner_participant_id,installation_privacy_domain_id,
    platform_authority_epoch,environment_id,installation_digest,admission_digest FROM control.platform_envelope_scope
   UNION ALL
   SELECT platform_context_id,owner_participant_id,installation_privacy_domain_id,
    platform_authority_epoch,environment_id,installation_digest,admission_digest FROM control.platform_envelope_scope_successor
   UNION ALL SELECT platform_context_id,owner_participant_id,installation_privacy_domain_id,platform_authority_epoch,environment_id,installation_digest,admission_digest FROM control.root_expiry_recovery_scope
  ) scope ON scope.platform_context_id=root.platform_context_id AND scope.owner_participant_id=enrollment.participant_id
   AND scope.installation_privacy_domain_id=enrollment.privacy_domain_id AND scope.platform_authority_epoch=root.authority_epoch
   AND 'sha256:'||encode(scope.admission_digest,'hex')=enrollment.document->>'rootDigest'
   AND scope.environment_id=enrollment.document->>'installationEnvironmentId'
   AND scope.installation_digest=enrollment.document->>'installationDigest'
  JOIN control.operations_installation installation ON installation.participant_id=enrollment.participant_id
   AND installation.privacy_domain_id=enrollment.privacy_domain_id AND installation.environment_id=scope.environment_id
   AND installation.installation_digest=scope.installation_digest AND installation.state='ACTIVE'
  WHERE enrollment.enrollment_id=p_enrollment AND openpc.matches_participant(enrollment.participant_id)
   AND openpc.matches_privacy(enrollment.privacy_domain_id) AND enrollment.state='ACTIVE' AND enrollment.row_version=1
   AND enrollment.document->>'schema'='pc.identity.identity-envelope-recovery-enrollment'
   AND enrollment.document->>'purpose'='pc.installation.identity-envelope-repair-custody.v1'
   AND trust.document->>'purpose'=enrollment.document->>'purpose'
   AND trust.document->>'installationEnvironmentId'=scope.environment_id
   AND trust.document->>'installationDigest'=scope.installation_digest
   AND trust.document->>'profile'=enrollment.document->>'profile'
   AND enrollment.document_digest=sha256(convert_to(openpc.signing_canonical_json(enrollment.document),'UTF8'))
   AND trust.document_digest=sha256(convert_to(openpc.signing_canonical_json(trust.document),'UTF8'))
   AND installation.installation_bytes=convert_to(openpc.signing_canonical_json(installation.installation),'UTF8')
   AND installation.installation_digest='sha256:'||encode(sha256(installation.installation_bytes),'hex')
   AND openpc.operations_source_authentication_valid(installation.installation)
   AND enrollment.valid_from<=clock_timestamp() AND enrollment.valid_until>clock_timestamp()
   AND NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement replacement
    WHERE replacement.platform_context_id=root.platform_context_id AND replacement.state='WITHDRAWING'));
END $$;
REVOKE ALL ON FUNCTION openpc.identity_envelope_recovery_installation_source_current(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.identity_envelope_recovery_installation_source_current(uuid) TO openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.guard_identity_envelope_recovery_installation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
DECLARE expected_schema text; record_id text;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR NEW.row_version<>OLD.row_version+1
   OR (to_jsonb(NEW)-ARRAY['state','row_version','revoked_at','revocation_reason_digest']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['state','row_version','revoked_at','revocation_reason_digest']) THEN
   RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY'; END IF;
  NEW.revoked_at:=clock_timestamp();
  RETURN NEW;
 END IF;
 IF current_user<>'openpc_control_owner' OR NOT pg_has_role(session_user,'openpc_control_owner','MEMBER')
  OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
  THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY-INSTALLATION'; END IF;
 PERFORM openpc.assert_request_context(true);
 expected_schema:=CASE TG_TABLE_NAME
  WHEN 'identity_envelope_recovery_custody_trust' THEN 'pc.installation.identity-envelope-recovery-receiving-trust'
  WHEN 'identity_envelope_recovery_enrollment' THEN 'pc.identity.identity-envelope-recovery-enrollment'
  ELSE NULL END;
 record_id:=CASE TG_TABLE_NAME
  WHEN 'identity_envelope_recovery_custody_trust' THEN to_jsonb(NEW)->>'custody_trust_id'
  ELSE to_jsonb(NEW)->>'enrollment_id' END;
 IF expected_schema IS NULL OR NEW.document->>'schema' IS DISTINCT FROM expected_schema
  OR NEW.document->>'schemaVersion' IS DISTINCT FROM '1'
  OR NEW.document->>'purpose' IS DISTINCT FROM 'pc.installation.identity-envelope-repair-custody.v1'
  OR NEW.state<>'ACTIVE' OR NEW.row_version<>1
  OR NEW.document_digest<>sha256(convert_to(openpc.signing_canonical_json(NEW.document),'UTF8'))
  OR NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id)
  OR NEW.document->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR NEW.document->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR NEW.document->>'platformContextId' IS DISTINCT FROM NEW.platform_context_id::text
  OR (NEW.document->>'validFrom')::timestamptz IS DISTINCT FROM NEW.valid_from
  OR (NEW.document->>'validUntil')::timestamptz IS DISTINCT FROM NEW.valid_until
  OR NEW.valid_from>clock_timestamp() OR NEW.valid_until<=clock_timestamp()
  OR (CASE WHEN TG_TABLE_NAME='identity_envelope_recovery_custody_trust'
    THEN NEW.document->>'custodyTrustId' ELSE NEW.document->>'enrollmentId' END) IS DISTINCT FROM record_id
  THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY-INSTALLATION'; END IF;
 IF TG_TABLE_NAME='identity_envelope_recovery_enrollment' THEN
  IF NEW.document->>'custodyTrustId' IS DISTINCT FROM NEW.custody_trust_id::text
   OR NEW.document->>'custodyTrustDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.custody_trust_digest,'hex')
   OR NOT EXISTS(SELECT 1 FROM control.identity_envelope_recovery_custody_trust trust
    WHERE trust.custody_trust_id=NEW.custody_trust_id AND trust.participant_id=NEW.participant_id
     AND trust.privacy_domain_id=NEW.privacy_domain_id AND trust.document_digest=NEW.custody_trust_digest
     AND trust.state='ACTIVE' AND trust.row_version=1 AND trust.valid_from<=NEW.valid_from AND trust.valid_until>=NEW.valid_until)
   THEN RAISE EXCEPTION 'PC-AUTH-0005-SIGNER-RECOVERY-CUSTODY'; END IF;
 END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_envelope_recovery_trust_guard ON control.identity_envelope_recovery_custody_trust;
CREATE TRIGGER identity_envelope_recovery_trust_guard BEFORE INSERT OR UPDATE OR DELETE ON control.identity_envelope_recovery_custody_trust
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_envelope_recovery_installation();
DROP TRIGGER IF EXISTS identity_envelope_recovery_enrollment_guard ON control.identity_envelope_recovery_enrollment;
CREATE TRIGGER identity_envelope_recovery_enrollment_guard BEFORE INSERT OR UPDATE OR DELETE ON control.identity_envelope_recovery_enrollment
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_envelope_recovery_installation();

-- Permanently preserve the dedicated recovery-principal separation, including
-- after enrollment revocation. This returns no enrollment or signing material.
CREATE OR REPLACE FUNCTION openpc.is_platform_recovery_executor(p_principal uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.platform_recovery_enrollment e
   WHERE openpc.matches_participant(e.participant_id) AND e.document#>>'{recoveryPrincipal,principalId}'=p_principal::text)
 OR EXISTS(SELECT 1 FROM control.identity_envelope_recovery_enrollment e
   WHERE openpc.matches_participant(e.participant_id) AND e.document#>>'{recoveryPrincipal,principalId}'=p_principal::text)
$$;
REVOKE ALL ON FUNCTION openpc.is_platform_recovery_executor(uuid) FROM PUBLIC;
`;
