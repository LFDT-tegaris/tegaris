export const directoryGroupGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.directory_group_permits(owner_id uuid, group_ref uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT NOT EXISTS (SELECT FROM control.directory_group_mapping WHERE participant_id=owner_id AND authority_group_id=group_ref)
 OR EXISTS (SELECT FROM control.directory_group_mapping m JOIN control.directory_connector c ON c.participant_id=m.participant_id AND c.connector_id=m.connector_id
 WHERE m.participant_id=owner_id AND m.authority_group_id=group_ref AND c.state='ACTIVE' AND c.profile_digest=m.profile_digest
 AND m.observed_at<=clock_timestamp() AND least(m.fresh_until,m.observed_at+make_interval(secs=>c.external_group_freshness_seconds))>clock_timestamp())
$$;
CREATE OR REPLACE FUNCTION openpc.guard_directory_group_mapping()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-GROUP-TOMBSTONE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-'provider_version'-'provider_modified_at'-'source_digest'-'source_member_ids'-'observed_at'-'fresh_until'-'row_version'-'last_mutation_operation_id'-'updated_at') IS DISTINCT FROM
     (to_jsonb(OLD)-'provider_version'-'provider_modified_at'-'source_digest'-'source_member_ids'-'observed_at'-'fresh_until'-'row_version'-'last_mutation_operation_id'-'updated_at') OR
     NEW.row_version<>OLD.row_version+1 OR NEW.observed_at<OLD.observed_at OR NEW.provider_modified_at<OLD.provider_modified_at OR
     (NEW.provider_version=OLD.provider_version AND NEW.source_digest<>OLD.source_digest) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-GROUP-TRANSITION';
  END IF;
 ELSE
  IF NEW.row_version<>1 OR EXISTS (SELECT FROM control.authority_group_member WHERE participant_id=NEW.participant_id AND authority_group_id=NEW.authority_group_id AND state IN ('ACTIVE','SUSPENDED'))
   OR EXISTS (SELECT FROM control.assignment WHERE participant_id=NEW.participant_id AND authority_group_id=NEW.authority_group_id AND state IN ('ACTIVE','SUSPENDED')) THEN
   RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-GROUP-INITIAL-STATE';
  END IF;
 END IF;
 IF NEW.observed_at>clock_timestamp() OR NEW.provider_modified_at>clock_timestamp() OR
  (SELECT count(DISTINCT value) FROM unnest(NEW.source_member_ids) value)<>cardinality(NEW.source_member_ids) OR
  NOT EXISTS (SELECT FROM control.directory_connector c JOIN control.authority_group g ON g.participant_id=c.participant_id
    WHERE c.participant_id=NEW.participant_id AND c.connector_id=NEW.connector_id AND c.state='ACTIVE' AND c.profile_digest=NEW.profile_digest
      AND g.authority_group_id=NEW.authority_group_id AND g.state='ACTIVE'
      AND NEW.fresh_until=NEW.observed_at+make_interval(secs=>c.external_group_freshness_seconds)
      AND NEW.observed_at>=clock_timestamp()-make_interval(secs=>least(300,c.external_group_freshness_seconds))) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-GROUP-SOURCE';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_directory_group_member()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF EXISTS (SELECT FROM control.directory_group_mapping WHERE participant_id=NEW.participant_id AND authority_group_id=NEW.authority_group_id) AND
  NOT EXISTS (SELECT FROM control.directory_group_mapping g JOIN control.directory_member m ON m.participant_id=g.participant_id AND m.connector_id=g.connector_id
   WHERE g.participant_id=NEW.participant_id AND g.authority_group_id=NEW.authority_group_id AND m.principal_id=NEW.principal_id AND m.state='LINKED'
    AND m.external_id=ANY(g.source_member_ids) AND openpc.directory_group_permits(g.participant_id,g.authority_group_id)) THEN
  RAISE EXCEPTION 'PC-IDENTITY-1002-DIRECTORY-GROUP-MEMBER';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.invalidate_directory_group_context()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF ((OLD.state='ACTIVE' AND NEW.state<>'ACTIVE') OR NEW.external_group_freshness_seconds<OLD.external_group_freshness_seconds)
  AND EXISTS (SELECT FROM control.directory_group_mapping g JOIN control.assignment a ON a.participant_id=g.participant_id AND a.authority_group_id=g.authority_group_id
    WHERE g.participant_id=NEW.participant_id AND g.connector_id=NEW.connector_id AND a.state IN ('ACTIVE','SUSPENDED')) THEN
  UPDATE control.participant SET authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() WHERE participant_id=NEW.participant_id;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS directory_group_lifecycle ON control.directory_group_mapping;
CREATE TRIGGER directory_group_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON control.directory_group_mapping FOR EACH ROW EXECUTE FUNCTION openpc.guard_directory_group_mapping();
DROP TRIGGER IF EXISTS directory_group_member_bound ON control.authority_group_member;
CREATE TRIGGER directory_group_member_bound BEFORE INSERT ON control.authority_group_member FOR EACH ROW EXECUTE FUNCTION openpc.guard_directory_group_member();
DROP TRIGGER IF EXISTS directory_group_context_invalidated ON control.directory_connector;
CREATE TRIGGER directory_group_context_invalidated AFTER UPDATE ON control.directory_connector FOR EACH ROW EXECUTE FUNCTION openpc.invalidate_directory_group_context();
`;
export const directoryGroupGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.directory_group_permits(uuid,uuid)
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader,openpc_control_worker;
`;
