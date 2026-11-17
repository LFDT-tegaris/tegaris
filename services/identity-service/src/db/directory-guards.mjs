export const directoryGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_directory_connector()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'display_name'-'state'-'mass_change_threshold'-'external_group_freshness_seconds'-'row_version'-'updated_at'-'last_mutation_operation_id') IS DISTINCT FROM
     (to_jsonb(OLD)-'display_name'-'state'-'mass_change_threshold'-'external_group_freshness_seconds'-'row_version'-'updated_at'-'last_mutation_operation_id') OR
     OLD.state='RETIRED' OR NEW.row_version<>OLD.row_version+1 THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-TRANSITION';
  END IF;
 ELSIF NEW.state<>'ACTIVE' OR NEW.row_version<>1 THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-INITIAL-STATE';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_directory_member()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-MEMBER-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'state'-'provider_version'-'provider_modified_at'-'observed_at'-'source_digest'-'row_version'-'updated_at'-'last_mutation_operation_id') IS DISTINCT FROM
     (to_jsonb(OLD)-'state'-'provider_version'-'provider_modified_at'-'observed_at'-'source_digest'-'row_version'-'updated_at'-'last_mutation_operation_id') OR
     OLD.state='OFFBOARDED' OR NEW.row_version<>OLD.row_version+1 OR NEW.provider_modified_at<OLD.provider_modified_at OR NEW.observed_at<OLD.observed_at OR
     (NEW.provider_version=OLD.provider_version AND NEW.source_digest<>OLD.source_digest) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-MEMBER-TRANSITION';
  END IF;
 ELSIF NEW.state<>'LINKED' OR NEW.row_version<>1 THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-MEMBER-INITIAL-STATE';
 END IF;
 IF NOT EXISTS (SELECT FROM control.principal p JOIN control.participant_membership m ON m.participant_id=p.participant_id AND m.membership_id=p.principal_id
    JOIN control.credential c ON c.participant_id=p.participant_id AND c.principal_id=p.principal_id
    WHERE p.participant_id=NEW.participant_id AND p.principal_id=NEW.principal_id AND p.kind='USER' AND c.credential_id=NEW.oidc_credential_id AND c.kind='OIDC_SUBJECT') THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-MEMBER-BINDING';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS directory_connector_lifecycle ON control.directory_connector;
CREATE TRIGGER directory_connector_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.directory_connector FOR EACH ROW EXECUTE FUNCTION openpc.guard_directory_connector();
DROP TRIGGER IF EXISTS directory_member_lifecycle ON control.directory_member;
CREATE TRIGGER directory_member_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.directory_member FOR EACH ROW EXECUTE FUNCTION openpc.guard_directory_member();
`;
