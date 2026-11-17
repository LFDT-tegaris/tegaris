// Generated with the owning Drizzle migration. Groups constrain explicit grants; they never grant authority.
export const authorityGroupGuardsSql = (directory = false) => `
CREATE OR REPLACE FUNCTION openpc.assignment_group_permits(owner_id uuid, group_ref uuid, principal_ref uuid, grant_validity tstzrange)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT group_ref IS NULL OR EXISTS (
  SELECT 1 FROM control.authority_group g
   JOIN control.authority_group_member m ON m.participant_id=g.participant_id AND m.authority_group_id=g.authority_group_id
   JOIN control.participant_membership binding ON binding.participant_id=m.participant_id AND binding.membership_id=m.principal_id
   JOIN control.principal p ON p.participant_id=m.participant_id AND p.principal_id=m.principal_id
  WHERE g.participant_id=owner_id AND g.authority_group_id=group_ref AND g.state='ACTIVE'
   AND m.principal_id=principal_ref AND m.state='ACTIVE' AND m.valid_during @> clock_timestamp()
   AND grant_validity <@ m.valid_during AND p.state='ACTIVE' AND p.kind IN ('USER','PLATFORM_OPERATOR')
   ${directory ? 'AND openpc.directory_group_permits(owner_id,group_ref)' : ''})
$$;
CREATE OR REPLACE FUNCTION openpc.guard_authority_group()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'group_name'-'state'-'row_version'-'updated_at'-'last_mutation_operation_id') IS DISTINCT FROM
     (to_jsonb(OLD)-'group_name'-'state'-'row_version'-'updated_at'-'last_mutation_operation_id') OR
     OLD.state<>'ACTIVE' OR NEW.state NOT IN ('ACTIVE','RETIRED') OR NEW.row_version<>OLD.row_version+1 THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-TRANSITION';
  END IF;
  IF NEW.state='RETIRED' AND (EXISTS(SELECT FROM control.authority_group_member m WHERE m.participant_id=NEW.participant_id AND m.authority_group_id=NEW.authority_group_id AND m.state IN ('ACTIVE','SUSPENDED'))
    OR EXISTS(SELECT FROM control.assignment a WHERE a.participant_id=NEW.participant_id AND a.authority_group_id=NEW.authority_group_id AND a.state IN ('ACTIVE','SUSPENDED'))) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-DEPENDENTS';
  END IF;
 ELSIF NEW.state<>'ACTIVE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-STATE';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_authority_group_member()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-MEMBER-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'state'-'revoked_at') IS DISTINCT FROM (to_jsonb(OLD)-'state'-'revoked_at') OR
     OLD.state IN ('REVOKED','EXPIRED','RETIRED') OR NEW.state NOT IN ('REVOKED','EXPIRED') OR NEW.revoked_at IS NULL THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-MEMBER-TRANSITION';
  END IF;
 ELSE
  IF NEW.state<>'ACTIVE' OR NEW.revoked_at IS NOT NULL OR isempty(NEW.valid_during) OR lower_inf(NEW.valid_during) OR NOT lower_inc(NEW.valid_during) OR upper_inc(NEW.valid_during)
    OR NOT EXISTS (SELECT FROM control.authority_group g WHERE g.participant_id=NEW.participant_id AND g.authority_group_id=NEW.authority_group_id AND g.state='ACTIVE')
    OR NOT EXISTS (SELECT FROM control.principal p JOIN control.participant_membership m ON m.participant_id=p.participant_id AND m.membership_id=p.principal_id
      WHERE p.participant_id=NEW.participant_id AND p.principal_id=NEW.principal_id AND p.state='ACTIVE' AND p.kind IN ('USER','PLATFORM_OPERATOR')) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-GROUP-MEMBER-SCOPE';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_assignment_group()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.authority_group_id IS NULL OR NEW.state NOT IN ('ACTIVE','SUSPENDED') THEN RETURN NEW; END IF;
 IF NOT EXISTS (SELECT FROM control.authority_group g JOIN control.authority_group_member m
    ON m.participant_id=g.participant_id AND m.authority_group_id=g.authority_group_id
    JOIN control.participant_membership binding ON binding.participant_id=m.participant_id AND binding.membership_id=m.principal_id
    JOIN control.principal p ON p.participant_id=m.participant_id AND p.principal_id=m.principal_id
    WHERE g.participant_id=NEW.participant_id AND g.authority_group_id=NEW.authority_group_id AND g.state='ACTIVE'
      AND m.principal_id=NEW.principal_id AND m.state='ACTIVE' AND NEW.valid_during <@ m.valid_during
      AND p.state='ACTIVE' AND p.kind IN ('USER','PLATFORM_OPERATOR')
      ${directory ? 'AND openpc.directory_group_permits(NEW.participant_id,NEW.authority_group_id)' : ''}) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-ASSIGNMENT-GROUP';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authority_group_lifecycle ON control.authority_group;
CREATE TRIGGER authority_group_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.authority_group FOR EACH ROW EXECUTE FUNCTION openpc.guard_authority_group();
DROP TRIGGER IF EXISTS authority_group_member_lifecycle ON control.authority_group_member;
CREATE TRIGGER authority_group_member_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.authority_group_member FOR EACH ROW EXECUTE FUNCTION openpc.guard_authority_group_member();
DROP TRIGGER IF EXISTS assignment_group_bound ON control.assignment;
CREATE TRIGGER assignment_group_bound BEFORE INSERT OR UPDATE ON control.assignment FOR EACH ROW EXECUTE FUNCTION openpc.guard_assignment_group();
`;
export const authorityGroupUpgradeSql = `
DO $group_upgrade$ BEGIN
 IF EXISTS (SELECT FROM control.assignment a WHERE a.authority_group_id IS NOT NULL AND a.state IN ('ACTIVE','SUSPENDED') AND NOT EXISTS (
   SELECT FROM control.authority_group g JOIN control.authority_group_member m ON m.participant_id=g.participant_id AND m.authority_group_id=g.authority_group_id
    JOIN control.participant_membership binding ON binding.participant_id=m.participant_id AND binding.membership_id=m.principal_id
    JOIN control.principal p ON p.participant_id=m.participant_id AND p.principal_id=m.principal_id
   WHERE g.participant_id=a.participant_id AND g.authority_group_id=a.authority_group_id AND g.state='ACTIVE'
    AND m.principal_id=a.principal_id AND m.state='ACTIVE' AND a.valid_during <@ m.valid_during
    AND p.state='ACTIVE' AND p.kind IN ('USER','PLATFORM_OPERATOR'))) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-UNRESOLVED-GROUP-ASSIGNMENT';
 END IF;
END $group_upgrade$;
`;
export const authorityGroupGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.assignment_group_permits(uuid,uuid,uuid,tstzrange)
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader,openpc_control_worker;
`;
