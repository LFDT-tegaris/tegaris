export const secretRecipientGuardsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.guard_installed_secret_recipient() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,openpc,control AS $$
BEGIN
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE') THEN
   RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secret-recipient:'||coalesce(NEW.participant_id,OLD.participant_id)::text||':'||coalesce(NEW.privacy_domain_id,OLD.privacy_domain_id)::text,0));
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND
   (OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR
    (to_jsonb(OLD)-'state') IS DISTINCT FROM (to_jsonb(NEW)-'state'))) THEN
   RAISE EXCEPTION 'OPS-SECRET-INSTALLATION-IMMUTABLE';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS installed_secret_recipient_guard ON control.installed_secret_recipient;
CREATE TRIGGER installed_secret_recipient_guard BEFORE INSERT OR UPDATE OR DELETE ON control.installed_secret_recipient
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_installed_secret_recipient();
`;
export const secretRecipientGrantsSql = String.raw`
DROP POLICY IF EXISTS secret_recipient_installation ON control.installed_secret_recipient;
CREATE POLICY secret_recipient_installation ON control.installed_secret_recipient
 TO openpc_control_owner USING(true) WITH CHECK(true);
REVOKE ALL ON control.installed_secret_recipient FROM PUBLIC,openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance;
GRANT SELECT ON control.installed_secret_recipient TO openpc_control_runtime;
`;
