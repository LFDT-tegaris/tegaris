/** Classify only the exact legacy QA timing when adding policy metadata. All
 * original session bytes, expiries, counters and generations remain untouched. */
export function orderQaSessionDurationUpgrade(base) {
  const column = 'ALTER TABLE "control"."session" ADD COLUMN "duration_profile"';
  if (!base.includes(column)) return base;
  const boundary = 'ALTER TABLE "control"."session" ADD CONSTRAINT "session_duration_profile_ck"';
  if (
    base.split(column).length !== 2 ||
    base.split(boundary).length !== 2 ||
    !base.includes('ADD COLUMN "idle_timeout_ms"') ||
    !base.includes('ADD COLUMN "absolute_timeout_ms"') ||
    base.indexOf('ADD COLUMN "absolute_timeout_ms"') > base.indexOf(boundary)
  )
    throw new Error('Missing generated session duration prerequisite');
  const start = '-- OPENPC GENERATED LEGACY SESSION DURATION CLASSIFICATION';
  const end = '-- END OPENPC GENERATED LEGACY SESSION DURATION CLASSIFICATION';
  const original = base.replace(new RegExp(`${start}[\\s\\S]*?${end}\\n?`, 'u'), '');
  return original.replace(
    boundary,
    `${start}
UPDATE "control"."session"
SET "duration_profile"='LOCAL_QA', "idle_timeout_ms"=86400000, "absolute_timeout_ms"=86400000
WHERE "absolute_expires_at"="issued_at"+interval '24 hours'
  AND "idle_expires_at"=least("last_seen_at"+interval '24 hours',"absolute_expires_at");
${end}
${boundary}`,
  );
}

/** New session issuance pins duration policy. Current deployment settings
 * cannot extend an existing family, including refresh and context readback. */
export const qaSessionDurationGuardsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.guard_session_duration_profile()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN
 IF TG_OP='UPDATE' AND
  (NEW.participant_id,NEW.principal_id,NEW.refresh_family_id,NEW.issued_at,NEW.absolute_expires_at,
   NEW.duration_profile,NEW.idle_timeout_ms,NEW.absolute_timeout_ms) IS DISTINCT FROM
  (OLD.participant_id,OLD.principal_id,OLD.refresh_family_id,OLD.issued_at,OLD.absolute_expires_at,
   OLD.duration_profile,OLD.idle_timeout_ms,OLD.absolute_timeout_ms) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-SESSION-DURATION';
 END IF;
 IF TG_OP='INSERT' AND NEW.duration_profile<>'C17' AND
  (current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1' OR
   (NEW.duration_profile='LOCAL_QA_10X' AND
    current_setting('openpc.local_qa_duration_profile',true) IS DISTINCT FROM 'LOCAL_QA_10X')) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-SESSION-DURATION';
 END IF;
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('openpc-session-duration-family:'||NEW.participant_id::text||':'||NEW.refresh_family_id::text,0));
  IF EXISTS(SELECT 1 FROM control.session s
    WHERE s.participant_id=NEW.participant_id AND s.refresh_family_id=NEW.refresh_family_id
      AND (s.principal_id,s.issued_at,s.absolute_expires_at,s.duration_profile,s.idle_timeout_ms,s.absolute_timeout_ms)
       IS DISTINCT FROM
          (NEW.principal_id,NEW.issued_at,NEW.absolute_expires_at,NEW.duration_profile,NEW.idle_timeout_ms,NEW.absolute_timeout_ms)) THEN
   RAISE EXCEPTION 'PC-AUTH-0005-SESSION-DURATION';
  END IF;
 END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION openpc.guard_session_duration_profile() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.guard_session_duration_profile() FROM PUBLIC;
DROP TRIGGER IF EXISTS session_duration_profile_guard ON control.session;
CREATE TRIGGER session_duration_profile_guard BEFORE INSERT OR UPDATE ON control.session
FOR EACH ROW EXECUTE FUNCTION openpc.guard_session_duration_profile();
`;
