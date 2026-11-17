// Private global identity reservations. Scoped directory claims never merge subjects.
export const identityOidcBindingUpgradeSql = `
INSERT INTO control.identity_oidc_binding(issuer,subject,audience,identity_subject_id,state)
 SELECT credential.issuer,credential.subject,credential.audience,
   CASE WHEN count(DISTINCT membership.identity_subject_id)=1 AND
     bool_and(membership.identity_subject_id IS NOT NULL AND credential.state='ACTIVE' AND credential.credential_epoch>0
       AND credential.valid_from<=clock_timestamp() AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp()))
     THEN min(membership.identity_subject_id::text)::uuid ELSE NULL END,
   CASE WHEN count(DISTINCT membership.identity_subject_id)=1 AND
     bool_and(membership.identity_subject_id IS NOT NULL AND credential.state='ACTIVE' AND credential.credential_epoch>0
       AND credential.valid_from<=clock_timestamp() AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp()))
     THEN 'UNVERIFIED_LEGACY' ELSE 'AMBIGUOUS_LEGACY' END
 FROM control.credential credential LEFT JOIN control.participant_membership membership
   ON membership.participant_id=credential.participant_id AND membership.membership_id=credential.principal_id
 WHERE credential.kind='OIDC_SUBJECT' AND credential.issuer IS NOT NULL AND credential.subject IS NOT NULL
   AND credential.audience IS NOT NULL AND length(credential.issuer)>0 AND length(credential.subject) BETWEEN 1 AND 255 AND length(credential.audience)>0
 GROUP BY credential.issuer,credential.subject,credential.audience;
`;

export const identityOidcBindingGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_identity_oidc_reservation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' OR current_user<>'openpc_identity_binding_owner' THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-IDENTITY-RESERVATION';
 END IF;
 IF TG_OP='UPDATE' AND (OLD.state<>'UNVERIFIED_LEGACY' OR
   (NEW.issuer,NEW.subject,NEW.audience,NEW.created_at) IS DISTINCT FROM (OLD.issuer,OLD.subject,OLD.audience,OLD.created_at) OR
   NOT ((NEW.state='BOUND' AND NEW.identity_subject_id=OLD.identity_subject_id) OR
        (NEW.state='AMBIGUOUS_LEGACY' AND NEW.identity_subject_id IS NULL))) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-IDENTITY-RESERVATION';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_oidc_reservation_immutable ON control.identity_oidc_binding;
CREATE TRIGGER identity_oidc_reservation_immutable BEFORE UPDATE OR DELETE ON control.identity_oidc_binding
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_oidc_reservation();

CREATE OR REPLACE FUNCTION openpc.observe_oidc_identity_claim()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
DECLARE local_subject uuid; existing control.identity_oidc_binding%ROWTYPE; qualified boolean;
BEGIN
 IF TG_OP='UPDATE' AND OLD.kind='OIDC_SUBJECT' AND
   (OLD.kind,OLD.participant_id,OLD.principal_id,OLD.issuer,OLD.subject,OLD.audience) IS DISTINCT FROM
   (NEW.kind,NEW.participant_id,NEW.principal_id,NEW.issuer,NEW.subject,NEW.audience) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-OIDC-CLAIM-IMMUTABLE';
 END IF;
 -- Invalid legacy accounts remain unusable for proof resolution; ordinary scoped login retains its checks.
 IF NEW.kind<>'OIDC_SUBJECT' OR NEW.issuer IS NULL OR NEW.subject IS NULL OR NEW.audience IS NULL
   OR length(NEW.issuer)=0 OR length(NEW.subject) NOT BETWEEN 1 AND 255 OR length(NEW.audience)=0 THEN RETURN NEW; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(NEW.issuer,NEW.subject,NEW.audience)::text,713));
 SELECT membership.identity_subject_id INTO local_subject FROM control.participant_membership membership
  WHERE membership.participant_id=NEW.participant_id AND membership.membership_id=NEW.principal_id;
 qualified:=local_subject IS NOT NULL AND NEW.state='ACTIVE' AND NEW.credential_epoch>0
   AND NEW.valid_from<=clock_timestamp() AND (NEW.valid_until IS NULL OR NEW.valid_until>clock_timestamp());
 SELECT * INTO existing FROM control.identity_oidc_binding
  WHERE issuer=NEW.issuer AND subject=NEW.subject AND audience=NEW.audience FOR UPDATE;
 IF NOT FOUND THEN
  INSERT INTO control.identity_oidc_binding(issuer,subject,audience,identity_subject_id,state)
   VALUES(NEW.issuer,NEW.subject,NEW.audience,CASE WHEN qualified THEN local_subject ELSE NULL END,
    CASE WHEN qualified THEN 'UNVERIFIED_LEGACY' ELSE 'AMBIGUOUS_LEGACY' END);
 ELSIF existing.state='BOUND' THEN
  -- Local revocation cannot revoke a global identity. A different local subject cannot claim it.
  IF existing.identity_subject_id IS DISTINCT FROM local_subject THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-OIDC-IDENTITY-CONFLICT';
  END IF;
 ELSIF existing.state='UNVERIFIED_LEGACY' AND (NOT qualified OR existing.identity_subject_id IS DISTINCT FROM local_subject) THEN
  UPDATE control.identity_oidc_binding SET state='AMBIGUOUS_LEGACY',identity_subject_id=NULL
   WHERE issuer=NEW.issuer AND subject=NEW.subject AND audience=NEW.audience;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS credential_oidc_identity_reservation ON control.credential;
CREATE TRIGGER credential_oidc_identity_reservation BEFORE INSERT OR UPDATE OF kind,participant_id,principal_id,issuer,subject,audience,state,credential_epoch,valid_from,valid_until ON control.credential
 FOR EACH ROW EXECUTE FUNCTION openpc.observe_oidc_identity_claim();

-- Internal proof consumer only. Possession of these arguments is not proof; the Identity
-- invitation owner verifies signed OIDC, token/version, custody and durable issuance authority first.
CREATE OR REPLACE FUNCTION openpc.resolve_proved_oidc_identity(issuer_value text,subject_value text,audience_value text)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
DECLARE existing control.identity_oidc_binding%ROWTYPE; resolved uuid;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-PARTICIPANT_CREATE_MEMBER-V1' OR issuer_value IS NULL OR subject_value IS NULL OR audience_value IS NULL
   OR length(issuer_value)=0 OR length(subject_value) NOT BETWEEN 1 AND 255 OR length(audience_value)=0 THEN
  RAISE EXCEPTION 'PC-AUTH-0002';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(issuer_value,subject_value,audience_value)::text,713));
 SELECT * INTO existing FROM control.identity_oidc_binding
  WHERE issuer=issuer_value AND subject=subject_value AND audience=audience_value FOR UPDATE;
 IF NOT FOUND THEN
  resolved:=uuidv7();
  INSERT INTO control.identity_subject(identity_subject_id) VALUES(resolved);
  INSERT INTO control.identity_oidc_binding(issuer,subject,audience,identity_subject_id,state)
   VALUES(issuer_value,subject_value,audience_value,resolved,'BOUND');
  RETURN resolved;
 END IF;
 IF existing.state='AMBIGUOUS_LEGACY' THEN RAISE EXCEPTION 'PC-AUTH-0002'; END IF;
 IF existing.state='UNVERIFIED_LEGACY' THEN
  IF EXISTS (SELECT 1 FROM control.credential credential
    LEFT JOIN control.participant_membership membership ON membership.participant_id=credential.participant_id AND membership.membership_id=credential.principal_id
    WHERE credential.kind='OIDC_SUBJECT' AND credential.issuer=issuer_value AND credential.subject=subject_value AND credential.audience=audience_value
      AND (membership.identity_subject_id IS DISTINCT FROM existing.identity_subject_id OR credential.state<>'ACTIVE' OR credential.credential_epoch<=0
        OR credential.valid_from>clock_timestamp() OR credential.valid_until<=clock_timestamp())) THEN
   RAISE EXCEPTION 'PC-AUTH-0002';
  END IF;
  UPDATE control.identity_oidc_binding SET state='BOUND' WHERE issuer=issuer_value AND subject=subject_value AND audience=audience_value;
 END IF;
 RETURN existing.identity_subject_id;
END $$;
`;

export const identityOidcBindingGrantsSql = `
ALTER ROLE openpc_identity_binding_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE openpc_identity_binding_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
GRANT USAGE ON SCHEMA openpc,control TO openpc_identity_binding_owner;
GRANT USAGE ON SCHEMA openpc TO openpc_identity_binding_resolver;
GRANT SELECT ON control.credential,control.participant_membership TO openpc_identity_binding_owner;
GRANT SELECT,INSERT ON control.identity_subject,control.identity_oidc_binding TO openpc_identity_binding_owner;
GRANT UPDATE ON control.identity_oidc_binding TO openpc_identity_binding_owner;
GRANT EXECUTE ON FUNCTION openpc.assert_request_context(boolean),openpc.current_action_intent_id(),openpc.current_participant_id(),openpc.current_privacy_domain_id(),openpc.current_operation_id(),openpc.require_uuid_setting(text) TO openpc_identity_binding_owner;
ALTER FUNCTION openpc.observe_oidc_identity_claim() OWNER TO openpc_identity_binding_owner;
ALTER FUNCTION openpc.resolve_proved_oidc_identity(text,text,text) OWNER TO openpc_identity_binding_owner;
GRANT EXECUTE ON FUNCTION openpc.resolve_proved_oidc_identity(text,text,text) TO openpc_identity_binding_resolver;
`;
