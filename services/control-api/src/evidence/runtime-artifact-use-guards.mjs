/** Native consumers call this inside the transaction that claims/starts/restores
 * serving. The lock lives through that transaction; a detached true value is
 * never authority. Original STARTED/UNKNOWN result lookup does not call this:
 * reconciliation preserves the original identity and may not serve/resubmit.
 */
// Serializable API mutations can have a snapshot older than their lifecycle
// lock. Lock EVERY matching original (including unselected aliases) so PostgreSQL
// rejects a concurrently removed/changed original with 40001. A stale absence
// in the retirement catalogue must never permit qualification or later use.
const originalLockBody = `
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF pid IS DISTINCT FROM openpc.current_participant_id() OR privacy IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR pid IS NULL OR privacy IS NULL OR configuration IS NULL OR octet_length(configuration)<>32
  OR current_setting('transaction_isolation')<>'serializable'
  OR current_setting('session_replication_role')<>'origin'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||pid::text,0))
 THEN RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='PC-DATA-6007'; END IF;
 PERFORM input.runtime_configuration_input_id FROM control.runtime_configuration_input input
  WHERE input.participant_id=pid AND input.privacy_domain_id=privacy AND input.configuration_digest=configuration
  ORDER BY input.runtime_configuration_input_id FOR SHARE NOWAIT;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='PC-DATA-6007';
END `;
export const runtimeArtifactUseGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.lock_runtime_artifact_originals(pid uuid,privacy uuid,configuration bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$${originalLockBody}$$;
ALTER FUNCTION openpc.lock_runtime_artifact_originals(uuid,uuid,bytea) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.lock_runtime_artifact_originals(uuid,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_runtime_artifact_originals(uuid,uuid,bytea)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
CREATE OR REPLACE FUNCTION openpc.runtime_artifact_new_use_allowed(pid uuid,privacy uuid,configuration bytea)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF pid IS NULL OR privacy IS NULL OR pid IS DISTINCT FROM openpc.current_participant_id()
  OR privacy IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR configuration IS NULL OR octet_length(configuration)<>32
  OR current_setting('transaction_isolation') NOT IN ('read committed','serializable')
  OR current_setting('row_security')<>'on' OR current_setting('session_replication_role')<>'origin'
  OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND NOT rolsuper AND NOT rolbypassrls)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 -- A producer may already hold module/policy/row locks. Never reverse-wait.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||pid::text,0))
 THEN
  -- API transactions retry only known serialization failures after rollback.
  -- Native READ COMMITTED consumers retain their existing BUSY signal.
  IF current_setting('transaction_isolation')='serializable' THEN
   RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='PC-DATA-6007';
  END IF;
  RAISE EXCEPTION 'PC-DATA-6007';
 END IF;
 -- The immutable, deferred-receipt-bound owner denies by scoped bytes across
 -- all installation/generation identities. Unknown/missing owners fail closed.
 IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
  WHERE c.oid='control.runtime_artifact_retirement'::regclass AND c.relkind='r'
   AND c.relrowsecurity AND c.relforcerowsecurity AND r.rolname='openpc_control_owner')
 OR EXISTS(SELECT 1 FROM (VALUES
   ('runtime_artifact_retirement_statement_guard','openpc.guard_runtime_artifact_retirement_statement()',62,false),
   ('runtime_artifact_retirement_guard','openpc.guard_runtime_artifact_retirement()',31,false),
   ('runtime_artifact_retirement_commit_required','openpc.require_runtime_artifact_retirement_commit()',5,true)
  ) expected(name,signature,kind,deferred)
  WHERE NOT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_roles r ON r.oid=p.proowner
   WHERE t.tgrelid='control.runtime_artifact_retirement'::regclass AND t.tgname=expected.name
    AND t.tgfoid=to_regprocedure(expected.signature) AND t.tgtype=expected.kind AND t.tgenabled='O'
    AND t.tgdeferrable=expected.deferred AND t.tginitdeferred=expected.deferred AND NOT t.tgisinternal
    AND t.tgnargs=0 AND t.tgqual IS NULL AND r.rolname='openpc_control_owner' AND NOT p.prosecdef))
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-OWNER-UNAVAILABLE'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
  WHERE c.oid='control.runtime_artifact_source_disposition'::regclass AND c.relkind='r'
   AND c.relrowsecurity AND c.relforcerowsecurity AND r.rolname='openpc_control_owner')
  OR NOT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_roles r ON r.oid=p.proowner
   WHERE t.tgrelid='control.runtime_artifact_source_disposition'::regclass
    AND t.tgname='runtime_artifact_source_disposition_guard'
    AND t.tgfoid=to_regprocedure('openpc.guard_runtime_artifact_source_disposition_immutable()')
    AND t.tgtype=62 AND t.tgenabled='O' AND NOT t.tgisinternal AND NOT t.tgdeferrable
    AND NOT t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL AND NOT p.prosecdef
    AND r.rolname='openpc_control_owner')
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-OWNER-UNAVAILABLE'; END IF;
 IF current_setting('transaction_isolation')='serializable' THEN
  IF NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
   WHERE p.oid=to_regprocedure('openpc.lock_runtime_artifact_originals(uuid,uuid,bytea)')
    AND r.rolname='openpc_control_owner' AND p.prosecdef AND p.provolatile='v'
    AND p.proconfig=ARRAY['search_path=pg_catalog','row_security=on']::text[]
    AND p.prosrc='${originalLockBody.replaceAll("'", "''")}')
  THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-OWNER-UNAVAILABLE'; END IF;
  PERFORM openpc.lock_runtime_artifact_originals(pid,privacy,configuration);
 END IF;
 -- Retirement mutations keep their stricter read-committed context owner.
 -- This read uses the lifecycle fence plus, for serializable callers, locked
 -- original rows above. It grants no deletion, source write or serving authority.
 RETURN NOT EXISTS(SELECT 1 FROM control.runtime_artifact_retirement r
  WHERE r.participant_id=pid AND r.privacy_domain_id=privacy
   AND r.configuration_digest='sha256:'||encode(configuration,'hex'))
  AND NOT EXISTS(SELECT 1 FROM control.runtime_artifact_source_disposition d
   WHERE d.participant_id=pid AND d.privacy_domain_id=privacy AND d.configuration_digest=configuration);
END $$;
REVOKE ALL ON FUNCTION openpc.runtime_artifact_new_use_allowed(uuid,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_artifact_new_use_allowed(uuid,uuid,bytea)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
`;
