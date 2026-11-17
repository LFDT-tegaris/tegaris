// Platform rows are installed explicitly by the trust/bootstrap owner. Application
// roles cannot create, mutate, or infer this root. Lock order is all Participant
// fences, then Platform rows; root epoch changes must not acquire child locks.
/** Preserve the Root row policy without expanding envelope RLS into every
 * surrounding authority query. Invoker rights and envelope RLS remain intact. */
export const platformContextReadSql = `
CREATE OR REPLACE FUNCTION openpc.platform_context_scoped_read_current(p_root uuid,p_owner uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 IF current_user='openpc_control_owner' AND openpc.matches_participant(p_owner) THEN RETURN true; END IF;
 RETURN EXISTS(SELECT 1 FROM control.authority_envelope envelope
  WHERE envelope.platform_context_id=p_root AND openpc.matches_participant(envelope.participant_id));
END $$;
REVOKE ALL ON FUNCTION openpc.platform_context_scoped_read_current(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_context_scoped_read_current(uuid,uuid)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime,openpc_control_reader,openpc_control_worker;
`;

export const platformContextGuardsSql = `
-- Root custody is a transaction fence, not permission to update the root.
-- Keep application UPDATE rights absent; the owner retains the lock under RLS.
CREATE OR REPLACE FUNCTION openpc.lock_platform_scope_context(p_root_id uuid)
RETURNS SETOF control.platform_context
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 RETURN QUERY SELECT p.* FROM control.platform_context p
 WHERE p.platform_context_id=p_root_id AND p.state='ACTIVE'
 AND EXISTS(SELECT 1 FROM control.authority_envelope e
   WHERE e.platform_context_id=p.platform_context_id
     AND e.participant_id=openpc.current_participant_id())
 FOR SHARE OF p;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_platform_scope_context(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.guard_platform_context()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-CONTEXT'; END IF;
 IF NEW.platform_context_id<>OLD.platform_context_id OR NEW.owner_participant_id<>OLD.owner_participant_id
   OR NEW.created_at<>OLD.created_at OR OLD.state='RETIRED'
   OR NEW.authority_epoch<>OLD.authority_epoch+1 OR NEW.row_version<>OLD.row_version+1
   OR NEW.updated_at<=OLD.updated_at THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-CONTEXT';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS platform_context_monotonic ON control.platform_context;
CREATE TRIGGER platform_context_monotonic BEFORE UPDATE OR DELETE ON control.platform_context
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_context();

CREATE OR REPLACE FUNCTION openpc.guard_envelope_platform_binding()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
BEGIN
 IF NEW.platform_context_id IS DISTINCT FROM OLD.platform_context_id
   OR NEW.platform_authority_epoch IS DISTINCT FROM OLD.platform_authority_epoch THEN
  RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-CONTEXT';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS authority_envelope_platform_immutable ON control.authority_envelope;
CREATE TRIGGER authority_envelope_platform_immutable BEFORE UPDATE ON control.authority_envelope
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_envelope_platform_binding();

DROP POLICY IF EXISTS envelope_platform_custody_read ON control.authority_envelope;
CREATE POLICY envelope_platform_custody_read ON control.authority_envelope FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id));
DROP POLICY IF EXISTS platform_context_custody_lock ON control.platform_context;
CREATE POLICY platform_context_custody_lock ON control.platform_context FOR UPDATE TO openpc_control_owner
 USING(exists(select 1 from control.authority_envelope envelope
   where envelope.platform_context_id=platform_context.platform_context_id
     and openpc.matches_participant(envelope.participant_id))) WITH CHECK(false);

-- This returns custody, not permission. Callers must first verify and retain
-- their selected current envelope/grant path under the Participant fence.
CREATE OR REPLACE FUNCTION openpc.lock_authority_envelope_platform_context(p_envelope_id uuid)
RETURNS TABLE(platform_context_id uuid,platform_authority_epoch text,delegation_epoch text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control AS $$
BEGIN
 PERFORM openpc.assert_request_context(false);
 RETURN QUERY SELECT platform.platform_context_id,platform.authority_epoch::text,envelope.delegation_epoch::text
 FROM control.authority_envelope envelope JOIN control.platform_context platform
   ON platform.platform_context_id=envelope.platform_context_id
 WHERE envelope.participant_id=openpc.current_participant_id()
   AND envelope.authority_envelope_id=p_envelope_id AND envelope.state='ACTIVE'
   AND envelope.valid_from<=clock_timestamp() AND (envelope.valid_until IS NULL OR envelope.valid_until>clock_timestamp())
   AND platform.state='ACTIVE' AND platform.authority_epoch=envelope.platform_authority_epoch
 FOR SHARE OF platform;
END $$;
`;

export const platformContextGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.lock_platform_scope_context(uuid)
 TO openpc_control_reader,openpc_control_runtime,openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.lock_authority_envelope_platform_context(uuid)
 TO openpc_control_reader,openpc_control_runtime,openpc_control_platform_runtime;
`;
