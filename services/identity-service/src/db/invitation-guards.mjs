// Emitted by the owning Drizzle generator. Immutable token history is part of replay protection.
export const invitationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_invitation_oidc_custody()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.purpose IS DISTINCT FROM OLD.purpose OR
  (OLD.purpose='INVITATION' AND
   ((to_jsonb(NEW)-'consumed_at') IS DISTINCT FROM (to_jsonb(OLD)-'consumed_at') OR
    OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL OR NEW.consumed_at>=OLD.expires_at)) THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS invitation_oidc_custody ON control.oidc_transaction;
CREATE TRIGGER invitation_oidc_custody BEFORE UPDATE ON control.oidc_transaction
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_invitation_oidc_custody();
DROP TRIGGER IF EXISTS invitation_token_immutable ON control.participant_invitation_token;
CREATE TRIGGER invitation_token_immutable BEFORE UPDATE OR DELETE ON control.participant_invitation_token
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE OR REPLACE FUNCTION openpc.guard_participant_invitation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-INVITATION-TOMBSTONE'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PENDING' OR NEW.row_version<>1 OR NEW.token_version<>1 THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-INVITATION-INITIAL';
  END IF;
 ELSE
  IF OLD.state<>'PENDING' OR NEW.row_version<>OLD.row_version+1 OR
     NEW.last_mutation_operation_id=OLD.last_mutation_operation_id OR
     (to_jsonb(NEW)-'creator_participant_id'-'state'-'token_version'-'expires_at'-'row_version'-'updated_at'-'last_mutation_operation_id') IS DISTINCT FROM
     (to_jsonb(OLD)-'creator_participant_id'-'state'-'token_version'-'expires_at'-'row_version'-'updated_at'-'last_mutation_operation_id') OR
     NOT ((NEW.state='PENDING' AND NEW.token_version=OLD.token_version+1 AND NEW.expires_at>clock_timestamp()) OR
          (NEW.state='REVOKED' AND NEW.token_version=OLD.token_version AND NEW.expires_at=OLD.expires_at) OR
          (NEW.state='ACCEPTED' AND NEW.token_version=OLD.token_version AND NEW.expires_at=OLD.expires_at AND OLD.expires_at>clock_timestamp())) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-INVITATION-TRANSITION';
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS participant_invitation_lifecycle ON control.participant_invitation;
CREATE TRIGGER participant_invitation_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.participant_invitation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_invitation();
CREATE OR REPLACE FUNCTION openpc.guard_invitation_token()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 -- Pre-upgrade expired history can retain missing provenance, but can never be
 -- revived: token history is immutable and renewal inserts a new governed version.
 IF NEW.issuance_authority IS NULL AND NEW.expires_at>clock_timestamp() AND NOT EXISTS (
  SELECT 1 FROM control.participant_bootstrap_custody custody WHERE custody.participant_id=NEW.participant_id
    AND custody.invitation_id=NEW.invitation_id AND custody.state='ACTIVE' AND custody.custody_generation=NEW.token_version
    AND custody.expires_at=NEW.expires_at AND ((NEW.token_version=1 AND custody.created_operation_id=NEW.operation_id
      AND custody.candidate->>'tokenDigest'='sha256:'||encode(NEW.token_digest,'hex')) OR NEW.token_version>1)) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1005-INVITATION-ISSUANCE-AUTHORITY';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM control.participant_invitation invitation
   WHERE invitation.participant_id=NEW.participant_id AND invitation.privacy_domain_id=NEW.privacy_domain_id
     AND invitation.invitation_id=NEW.invitation_id AND invitation.state='PENDING'
     AND invitation.token_version=NEW.token_version AND invitation.expires_at=NEW.expires_at
     AND invitation.last_mutation_operation_id=NEW.operation_id) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-INVITATION-TOKEN';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS invitation_token_binding ON control.participant_invitation_token;
CREATE TRIGGER invitation_token_binding BEFORE INSERT ON control.participant_invitation_token
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_invitation_token();
CREATE OR REPLACE FUNCTION openpc.require_invitation_current_token()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM control.participant_invitation invitation
   JOIN control.participant_invitation_token token
    ON token.participant_id=invitation.participant_id AND token.privacy_domain_id=invitation.privacy_domain_id
     AND token.invitation_id=invitation.invitation_id AND token.token_version=invitation.token_version
     AND token.expires_at=invitation.expires_at
   WHERE invitation.participant_id=NEW.participant_id AND invitation.privacy_domain_id=NEW.privacy_domain_id
    AND invitation.invitation_id=NEW.invitation_id) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-INVITATION-CURRENT-TOKEN';
 END IF;
 IF EXISTS (SELECT 1 FROM control.participant_invitation invitation WHERE invitation.invitation_id=NEW.invitation_id AND invitation.state='ACCEPTED'
   AND NOT EXISTS (SELECT 1 FROM control.participant_invitation_acceptance acceptance
    WHERE acceptance.participant_id=invitation.participant_id AND acceptance.privacy_domain_id=invitation.privacy_domain_id
      AND acceptance.invitation_id=invitation.invitation_id AND acceptance.token_version=invitation.token_version
      AND (acceptance.operation_id=invitation.last_mutation_operation_id OR EXISTS (
        SELECT 1 FROM control.participant_bootstrap_custody custody WHERE custody.participant_id=invitation.participant_id
          AND custody.invitation_id=invitation.invitation_id AND custody.mandate_id=invitation.bootstrap_mandate_id
          AND custody.state='ACCEPTED' AND custody.accepted_membership_id=acceptance.membership_id
          AND custody.accepted_operation_id=invitation.last_mutation_operation_id)))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS invitation_current_token ON control.participant_invitation;
CREATE CONSTRAINT TRIGGER invitation_current_token AFTER INSERT OR UPDATE ON control.participant_invitation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_invitation_current_token();

CREATE OR REPLACE FUNCTION openpc.guard_invitation_proof()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM control.participant_invitation invitation
   JOIN control.participant_invitation_token token ON token.invitation_id=invitation.invitation_id AND token.token_version=invitation.token_version
   JOIN control.oidc_transaction oidc ON oidc.transaction_id=NEW.transaction_id AND oidc.purpose='INVITATION'
     AND oidc.selected_participant_id=invitation.participant_id AND oidc.issuer=invitation.recipient_issuer AND oidc.client_id=invitation.recipient_audience
     AND oidc.consumed_at IS NULL AND oidc.expires_at>clock_timestamp()
   WHERE invitation.participant_id=NEW.participant_id AND invitation.privacy_domain_id=NEW.privacy_domain_id
     AND invitation.invitation_id=NEW.invitation_id AND invitation.state='PENDING' AND invitation.expires_at>clock_timestamp()
     AND token.token_version=NEW.token_version AND token.token_digest=NEW.token_digest AND (token.issuance_authority IS NOT NULL OR EXISTS (
       SELECT 1 FROM control.participant_bootstrap_custody custody WHERE custody.participant_id=invitation.participant_id AND custody.invitation_id=invitation.invitation_id
         AND custody.mandate_id=invitation.bootstrap_mandate_id AND custody.state='ACTIVE' AND custody.expires_at>clock_timestamp()))) THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS invitation_proof_binding ON control.participant_invitation_proof;
CREATE TRIGGER invitation_proof_binding BEFORE INSERT ON control.participant_invitation_proof FOR EACH ROW EXECUTE FUNCTION openpc.guard_invitation_proof();
DROP TRIGGER IF EXISTS invitation_proof_immutable ON control.participant_invitation_proof;
CREATE TRIGGER invitation_proof_immutable BEFORE UPDATE OR DELETE ON control.participant_invitation_proof FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();

CREATE OR REPLACE FUNCTION openpc.guard_invitation_acceptance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM control.participant_invitation invitation
   JOIN control.participant_invitation_proof proof ON proof.invitation_id=invitation.invitation_id AND proof.token_version=invitation.token_version
   JOIN control.oidc_transaction oidc ON oidc.transaction_id=proof.transaction_id AND oidc.purpose='INVITATION' AND oidc.consumed_at IS NOT NULL
   JOIN control.participant_membership membership ON membership.participant_id=invitation.participant_id AND membership.membership_id=NEW.membership_id AND membership.identity_subject_id=NEW.identity_subject_id
   WHERE invitation.participant_id=NEW.participant_id AND invitation.privacy_domain_id=NEW.privacy_domain_id AND invitation.invitation_id=NEW.invitation_id
     AND invitation.token_version=NEW.token_version AND ((invitation.state='ACCEPTED' AND invitation.last_mutation_operation_id=NEW.operation_id) OR
       (invitation.state='PENDING' AND EXISTS (SELECT 1 FROM control.participant_bootstrap_custody custody
         WHERE custody.participant_id=invitation.participant_id AND custody.invitation_id=invitation.invitation_id
           AND custody.mandate_id=invitation.bootstrap_mandate_id AND custody.state='CLAIM_PENDING' AND custody.candidate_membership_id=NEW.membership_id)))
     AND proof.participant_id=NEW.participant_id AND proof.privacy_domain_id=NEW.privacy_domain_id AND proof.transaction_id=NEW.proof_transaction_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS invitation_acceptance_binding ON control.participant_invitation_acceptance;
CREATE TRIGGER invitation_acceptance_binding BEFORE INSERT ON control.participant_invitation_acceptance FOR EACH ROW EXECUTE FUNCTION openpc.guard_invitation_acceptance();
DROP TRIGGER IF EXISTS invitation_acceptance_immutable ON control.participant_invitation_acceptance;
CREATE TRIGGER invitation_acceptance_immutable BEFORE UPDATE OR DELETE ON control.participant_invitation_acceptance FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();

CREATE OR REPLACE FUNCTION openpc.require_invitation_acceptance_evidence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM control.mutation_evidence evidence
   JOIN control.participant_invitation invitation ON invitation.invitation_id=NEW.invitation_id
   JOIN control.outbox_event event ON event.participant_id=evidence.participant_id AND event.privacy_domain_id=evidence.privacy_domain_id
    AND event.aggregate_type='invitation-redemption' AND event.aggregate_id=NEW.invitation_id
    AND event.event_type='openpc.identity.invitation.accepted.v1'
    AND event.payload_cbor=NEW.evidence_cbor AND event.payload_digest=NEW.evidence_digest AND event.cose_sign1=NEW.cose_sign1
   WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
    AND evidence.operation_id=NEW.operation_id AND evidence.principal_id=NEW.membership_id
    AND evidence.action_intent_id='ACT-PARTICIPANT_CREATE_MEMBER-V1' AND evidence.catalog_operation_id='ID-OP-INVITATION-ACCEPT'
    AND evidence.aggregate_type='invitation-redemption' AND evidence.aggregate_id=NEW.invitation_id
    AND evidence.aggregate_version=invitation.row_version-CASE WHEN invitation.bootstrap_mandate_id IS NULL THEN 1 ELSE 0 END
    AND evidence.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(NEW.result),'UTF8'))
    AND evidence.evidence_role='IDENTITY_PROOF_INPUT' AND evidence.evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
    AND evidence.evidence_cbor=NEW.evidence_cbor AND evidence.evidence_digest=NEW.evidence_digest AND evidence.cose_sign1=NEW.cose_sign1) THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS invitation_acceptance_evidence ON control.participant_invitation_acceptance;
CREATE CONSTRAINT TRIGGER invitation_acceptance_evidence AFTER INSERT ON control.participant_invitation_acceptance
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_invitation_acceptance_evidence();
`;
