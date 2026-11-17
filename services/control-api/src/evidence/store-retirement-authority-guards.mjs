import { authoritySnapshotColumns } from '../../../identity-service/src/db/authority-snapshot-columns.ts';

const tables = Object.keys(authoritySnapshotColumns);
const rank = {
  participant: 0,
  privacy_domain: 1,
  principal: 2,
  authority_envelope: 2,
  authority_role: 2,
  assignment: 2,
  session: 3,
  delegation: 3,
  credential: 3,
};
const lockRows = tables
  .map(
    (
      table,
    ) => `SELECT '${table}'::text AS owner, '${authoritySnapshotColumns[table][0]}'::text AS identity,
 ${rank[table]} AS rank,(row->>'${authoritySnapshotColumns[table][0]}')::uuid AS id FROM jsonb_array_elements(snapshot->'dependencies'->'${table}') row`,
  )
  .join('\nUNION ALL\n');
const comparisons = tables
  .map((table) => {
    const columns = authoritySnapshotColumns[table];
    const fields = columns.map((column) => `'${column}',v.${column}::text`).join(',');
    const before =
      table === 'session'
        ? `(retained-ARRAY['idle_expires_at','row_version','step_up_verified_at'])`
        : 'retained';
    const after =
      table === 'session'
        ? `(actual-ARRAY['idle_expires_at','row_version','step_up_verified_at'])`
        : 'actual';
    return `
 FOR retained IN SELECT value FROM jsonb_array_elements(snapshot->'dependencies'->'${table}') LOOP
  SELECT jsonb_build_object(${fields}) INTO STRICT actual FROM control.${table} v
   WHERE v.participant_id=a.participant_id AND v.${columns[0]}=(retained->>'${columns[0]}')::uuid;
  IF ${before} IS DISTINCT FROM ${after} OR actual->>'state' IS DISTINCT FROM 'ACTIVE'
   ${
     table === 'session'
       ? `OR (retained->>'idle_expires_at')::timestamptz<=clock_timestamp()
     OR (actual->>'idle_expires_at')::timestamptz<=clock_timestamp() OR (actual->>'absolute_expires_at')::timestamptz<=clock_timestamp()`
       : ''
   }
   ${['assignment', 'delegation'].includes(table) ? `OR NOT ((actual->>'valid_during')::tstzrange @> clock_timestamp())` : ''}
   ${
     ['authority_envelope', 'credential'].includes(table)
       ? `OR (actual->>'valid_from')::timestamptz>clock_timestamp()
     OR (actual->>'valid_until' IS NOT NULL AND (actual->>'valid_until')::timestamptz<=clock_timestamp())`
       : ''
   }
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 END LOOP;`;
  })
  .join('\n');

/** Revalidate the exact sealed authority paths before dispatch. This is neither
 * a new approval nor authority supplied by the caller. No broad Identity grants
 * are added to the worker; the definer can only inspect this committed receipt. */
export const storeRetirementAuthorityGuardsSql = `
${tables
  .map(
    (table) => `
DROP POLICY IF EXISTS retirement_authority_read_fence ON control.${table};
CREATE POLICY retirement_authority_read_fence ON control.${table} FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-EVIDENCE_DELETIONS_RECONCILE_STORE_BATCH-V1')
 WITH CHECK(false);`,
  )
  .join('\n')}
DROP POLICY IF EXISTS retirement_authority_receipt_read ON control.audit_occurrence;
CREATE POLICY retirement_authority_receipt_read ON control.audit_occurrence FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-EVIDENCE_DELETIONS_RECONCILE_STORE_BATCH-V1');
CREATE OR REPLACE FUNCTION openpc.lock_store_retirement_authority(wanted uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE a control.store_retirement_admission; host control.store_retirement_host; snapshot jsonb; dependency record; actual jsonb; retained jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO STRICT a FROM control.store_retirement_admission
  WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id()
   AND attempt_id=wanted AND xmin<>pg_current_xact_id()::xid;
 SELECT * INTO STRICT host FROM control.store_retirement_host WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND host_digest=a.host_digest;
 IF session_user<>host.database_role OR NOT pg_has_role(session_user,'openpc_control_worker','USAGE')
  OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_DELETIONS_RECONCILE_STORE_BATCH-V1' THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT convert_from(authority_snapshot,'UTF8')::jsonb INTO STRICT snapshot FROM control.audit_occurrence
  WHERE participant_id=a.participant_id AND privacy_domain_id=a.privacy_domain_id AND operation_id=a.operation_id
   AND aggregate_id=a.attempt_id AND aggregate_type='store-retirement' AND profile_id='pc.control.store-retirement.admit'
   AND catalog_operation_id='CFG-OP-ADMIT-STORE-RETIREMENT';
 IF snapshot->>'schema' IS DISTINCT FROM 'pc.control.precommit-authority-snapshot.v1'
  OR jsonb_array_length(snapshot->'authorities') IS DISTINCT FROM 3
  OR snapshot->>'participantId' IS DISTINCT FROM a.participant_id::text
  OR snapshot->>'privacyDomainId' IS DISTINCT FROM a.privacy_domain_id::text
  OR snapshot->>'operationId' IS DISTINCT FROM a.operation_id::text
  OR a.dispatch_not_after_ms<=floor(extract(epoch from clock_timestamp())*1000)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 FOR dependency IN SELECT DISTINCT * FROM (${lockRows}
 UNION ALL SELECT 'credential','credential_id',3,host.workload_credential_id
 UNION ALL SELECT 'principal','principal_id',2,c.principal_id FROM control.credential c
  WHERE c.participant_id=a.participant_id AND c.credential_id=host.workload_credential_id
 ) dependencies ORDER BY rank,id,owner LOOP
  EXECUTE format('SELECT to_jsonb(%I) FROM control.%I WHERE participant_id=$1 AND %I=$2 FOR SHARE',dependency.identity,dependency.owner,dependency.identity)
   INTO STRICT actual USING a.participant_id,dependency.id;
 END LOOP;
 PERFORM openpc.lock_store_retirement_workload(a.host_digest);
 ${comparisons}
END $$;
ALTER FUNCTION openpc.lock_store_retirement_authority(uuid) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.lock_store_retirement_authority(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_store_retirement_authority(uuid) TO openpc_control_worker;
`.replace(/[ \t]+$/gmu, '');
