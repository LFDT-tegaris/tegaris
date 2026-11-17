// Emitted by the owning Drizzle migration generator, including populated-store initialization.
export const identitySubjectUpgradeSql = `
INSERT INTO control.identity_subject(identity_subject_id,created_at)
 SELECT principal_id,created_at FROM control.principal WHERE kind IN ('USER','PLATFORM_OPERATOR');
INSERT INTO control.participant_membership(membership_id,participant_id,identity_subject_id,created_at)
 SELECT principal_id,participant_id,principal_id,created_at FROM control.principal
 WHERE kind IN ('USER','PLATFORM_OPERATOR');
`;

export const identitySubjectGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_human_membership()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM control.principal principal
   WHERE principal.participant_id=NEW.participant_id AND principal.principal_id=NEW.membership_id
     AND principal.kind IN ('USER','PLATFORM_OPERATOR')) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-MEMBERSHIP-KIND';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS membership_human_identity ON control.participant_membership;
CREATE TRIGGER membership_human_identity BEFORE INSERT ON control.participant_membership
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_human_membership();
CREATE OR REPLACE FUNCTION openpc.guard_member_principal_kind()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.kind<>OLD.kind AND EXISTS (SELECT 1 FROM control.participant_membership membership
   WHERE membership.participant_id=OLD.participant_id AND membership.membership_id=OLD.principal_id) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-MEMBERSHIP-KIND';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS member_principal_kind ON control.principal;
CREATE TRIGGER member_principal_kind BEFORE UPDATE OF kind ON control.principal
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_member_principal_kind();
CREATE OR REPLACE FUNCTION openpc.guard_removed_membership()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF OLD.state='OFFBOARDED' AND NEW.state<>OLD.state AND EXISTS (
   SELECT 1 FROM control.participant_membership membership
    WHERE membership.participant_id=OLD.participant_id AND membership.membership_id=OLD.principal_id) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-MEMBERSHIP-TERMINAL';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS removed_membership_terminal ON control.principal;
CREATE TRIGGER removed_membership_terminal BEFORE UPDATE OF state ON control.principal
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_removed_membership();
DROP TRIGGER IF EXISTS identity_subject_immutable ON control.identity_subject;
CREATE TRIGGER identity_subject_immutable BEFORE UPDATE OR DELETE ON control.identity_subject
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS membership_binding_immutable ON control.participant_membership;
CREATE TRIGGER membership_binding_immutable BEFORE UPDATE OR DELETE ON control.participant_membership
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
`;
