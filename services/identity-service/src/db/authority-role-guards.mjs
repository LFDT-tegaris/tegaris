// Generated with the owning Drizzle migration; never patch migration SQL directly.
export const authorityRoleUpgradeSql = `
-- OPENPC GENERATED ROLE UPGRADE
INSERT INTO control.authority_role
 (authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
SELECT right(source.role_id,36)::uuid,source.participant_id,source.role_id,'Imported assignment role',
 ARRAY(SELECT DISTINCT capability FROM control.assignment a,
   unnest(a.action_intent_ids) capability
   WHERE a.participant_id=source.participant_id AND a.role_id=source.role_id ORDER BY capability),
 'MIGRATED_ASSIGNMENT',source.created_by_principal_id
FROM (SELECT DISTINCT ON (participant_id,role_id)
 participant_id,role_id,created_by_principal_id FROM control.assignment
 WHERE role_id IS NOT NULL ORDER BY participant_id,role_id,assignment_id) source;
-- END OPENPC GENERATED ROLE UPGRADE
`;

export const authorityRoleGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assignment_role_permits(owner_id uuid, role_ref text, action_id text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT role_ref IS NULL OR EXISTS (
  SELECT 1 FROM control.authority_role role WHERE role.participant_id=owner_id
   AND role.role_id=role_ref AND role.state='ACTIVE' AND action_id=ANY(role.action_intent_ids))
$$;

CREATE OR REPLACE FUNCTION openpc.guard_authority_role()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-ROLE-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'creator_participant_id'-'state'-'row_version'-'updated_at') IS DISTINCT FROM
     (to_jsonb(OLD)-'creator_participant_id'-'state'-'row_version'-'updated_at') OR
     OLD.state<>'ACTIVE' OR NEW.state<>'ARCHIVED' OR NEW.row_version<>OLD.row_version+1 OR
     EXISTS(SELECT 1 FROM control.assignment a WHERE a.participant_id=NEW.participant_id
       AND a.role_id=NEW.role_id AND a.state IN ('ACTIVE','SUSPENDED')) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-ROLE-TRANSITION';
  END IF;
 ELSIF NEW.state<>'ACTIVE' OR EXISTS(
   SELECT 1 FROM unnest(NEW.action_intent_ids) capability
    WHERE NOT EXISTS (SELECT 1 FROM control.action_intent registered WHERE registered.action_intent_id=capability)
 ) THEN RAISE EXCEPTION 'PC-IDENTITY-1002-ROLE-CAPABILITY';
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_assignment_role()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE role_row control.authority_role%ROWTYPE;
BEGIN
 IF NEW.role_id IS NULL OR NEW.state NOT IN ('ACTIVE','SUSPENDED') THEN RETURN NEW; END IF;
 SELECT * INTO role_row FROM control.authority_role role
  WHERE role.participant_id=NEW.participant_id AND role.role_id=NEW.role_id FOR SHARE;
 IF NOT FOUND OR role_row.state<>'ACTIVE' OR NOT NEW.action_intent_ids <@ role_row.action_intent_ids THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-ASSIGNMENT-ROLE';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authority_role_lifecycle ON control.authority_role;
CREATE TRIGGER authority_role_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.authority_role
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_authority_role();
DROP TRIGGER IF EXISTS assignment_role_bound ON control.assignment;
CREATE TRIGGER assignment_role_bound BEFORE INSERT OR UPDATE ON control.assignment
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_assignment_role();
`;

export const authorityRoleGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.assignment_role_permits(uuid,text,text)
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader,openpc_control_worker;
`;
