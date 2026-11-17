import { authoritySnapshotColumns } from './authority-snapshot-columns.ts';

const tables = Object.keys(authoritySnapshotColumns).sort();
const ranks = {
  participant: 0,
  privacy_domain: 1,
  principal: 2,
  authority_envelope: 2,
  assignment: 2,
  session: 3,
  delegation: 3,
  credential: 3,
};
const locks = tables
  .map(
    (
      table,
    ) => `SELECT '${table}'::text table_name,'${authoritySnapshotColumns[table][0]}'::text column_name,
 ${ranks[table]} rank,(d->>'${authoritySnapshotColumns[table][0]}')::uuid id
 FROM jsonb_array_elements(snapshot->'dependencies'->'${table}') d`,
  )
  .join('\nUNION ALL\n');
const projections = tables
  .map((table) => {
    const columns = authoritySnapshotColumns[table];
    return `
 SELECT coalesce(jsonb_agg(jsonb_build_object(${columns.map((c) => `'${c}',owner.${c}::text`).join(',')}) ORDER BY owner.${columns[0]}),'[]'::jsonb)
 INTO actual FROM control.${table} owner WHERE owner.participant_id=command.participant_id
 AND owner.${columns[0]} IN(SELECT (d->>'${columns[0]}')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'${table}') d);
${
  columns.includes('runtime_capability_ids')
    ? `
 -- An immutable pre-migration snapshot omitted runtime grants. Preserve its
 -- comparison/digest shape only while the actual owner still grants none.
 SELECT coalesce(jsonb_agg(CASE WHEN current_row->>'runtime_capability_ids'='{}'
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot->'dependencies'->'${table}') retained
     WHERE retained->>'${columns[0]}'=current_row->>'${columns[0]}' AND NOT retained ? 'runtime_capability_ids')
   THEN current_row-'runtime_capability_ids' ELSE current_row END ORDER BY current_row->>'${columns[0]}'),'[]'::jsonb)
 INTO actual FROM jsonb_array_elements(actual) current_row;
`
    : ''
}
 current_rows:=current_rows||jsonb_build_object('${table}',actual);
 IF actual IS DISTINCT FROM snapshot->'dependencies'->'${table}'${
   table === 'session'
     ? ` AND NOT (
  jsonb_array_length(actual)=jsonb_array_length(snapshot->'dependencies'->'session') AND NOT EXISTS(
   SELECT 1 FROM jsonb_array_elements(snapshot->'dependencies'->'session') retained WHERE NOT EXISTS(
    SELECT 1 FROM jsonb_array_elements(actual) current_row WHERE
     (retained-ARRAY['idle_expires_at','row_version'])=(current_row-ARRAY['idle_expires_at','row_version'])
     AND (current_row->>'row_version')::bigint>=(retained->>'row_version')::bigint
     AND (current_row->>'idle_expires_at')::timestamptz>=(retained->>'idle_expires_at')::timestamptz)))`
     : table === 'credential'
       ? ` AND NOT (
  jsonb_array_length(actual)=jsonb_array_length(snapshot->'dependencies'->'credential') AND NOT EXISTS(
   SELECT 1 FROM jsonb_array_elements(snapshot->'dependencies'->'credential') retained WHERE NOT EXISTS(
    SELECT 1 FROM jsonb_array_elements(actual) current_row WHERE (retained-'row_version')=(current_row-'row_version')
     AND (current_row->>'row_version')::bigint>=(retained->>'row_version')::bigint)))`
       : ''
 }
 THEN unchanged:=false; END IF;`;
  })
  .join('\n');

/** Reuses the retained authority dependency set. Changed authority can describe past truth but never authorize dispatch. */
export const signingAttemptAuthoritySql = `
CREATE OR REPLACE FUNCTION openpc.signing_attempt_authority_status(p_attempt uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE command control.signing_rotation_command%ROWTYPE; snapshot jsonb; dependency record;
 actual jsonb; current_rows jsonb:='{}'::jsonb; unchanged boolean:=true; live boolean; approval jsonb; locked_count bigint;
BEGIN
 SELECT c.* INTO STRICT command FROM control.signing_rotation_command c JOIN control.signing_provider_attempt a
  ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id AND a.operation_id=c.operation_id
  WHERE a.attempt_id=p_attempt AND c.participant_id=openpc.current_participant_id()
   AND c.privacy_domain_id=openpc.current_privacy_domain_id()
   AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1';
 snapshot:=convert_from(command.authorization_snapshot,'UTF8')::jsonb;
 IF sha256(command.authorization_snapshot)<>command.authorization_snapshot_digest
  OR snapshot->>'schema'<>'pc.control.precommit-authority-snapshot.v1'
  OR snapshot->>'operationId'<>command.operation_id::text OR snapshot->>'decision'<>'ALLOW'
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-RETAINED-AUTHORITY'; END IF;
 FOR dependency IN SELECT * FROM (${locks}) dependencies ORDER BY rank,id,table_name LOOP
  EXECUTE format('SELECT %I FROM control.%I WHERE participant_id=$1 AND %I=$2 FOR SHARE',
   dependency.column_name,dependency.table_name,dependency.column_name) USING command.participant_id,dependency.id;
  GET DIAGNOSTICS locked_count=ROW_COUNT;
  IF locked_count<>1 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-MISSING-AUTHORITY'; END IF;
 END LOOP;
${projections}
 SELECT NOT EXISTS(
  SELECT 1 FROM control.session s WHERE s.participant_id=command.participant_id
   AND s.session_id IN(SELECT (d->>'session_id')::uuid FROM jsonb_array_elements(current_rows->'session') d)
   AND (s.state<>'ACTIVE' OR s.issued_at>clock_timestamp() OR s.idle_expires_at<=clock_timestamp() OR s.absolute_expires_at<=clock_timestamp())
  UNION ALL SELECT 1 FROM control.authority_envelope e WHERE e.participant_id=command.participant_id
   AND e.authority_envelope_id IN(SELECT (d->>'authority_envelope_id')::uuid FROM jsonb_array_elements(current_rows->'authority_envelope') d)
   AND (e.state<>'ACTIVE' OR e.valid_from>clock_timestamp() OR e.valid_until<=clock_timestamp())
  UNION ALL SELECT 1 FROM control.assignment a WHERE a.participant_id=command.participant_id
   AND a.assignment_id IN(SELECT (d->>'assignment_id')::uuid FROM jsonb_array_elements(current_rows->'assignment') d)
   AND (a.state<>'ACTIVE' OR NOT a.valid_during @> clock_timestamp())
  UNION ALL SELECT 1 FROM control.delegation d WHERE d.participant_id=command.participant_id
   AND d.delegation_id IN(SELECT (r->>'delegation_id')::uuid FROM jsonb_array_elements(current_rows->'delegation') r)
   AND (d.state<>'ACTIVE' OR NOT d.valid_during @> clock_timestamp())
  UNION ALL SELECT 1 FROM control.credential c WHERE c.participant_id=command.participant_id
   AND c.credential_id IN(SELECT (d->>'credential_id')::uuid FROM jsonb_array_elements(current_rows->'credential') d)
   AND (c.state<>'ACTIVE' OR c.valid_from>clock_timestamp() OR c.valid_until<=clock_timestamp())
 ) INTO live;
 SELECT jsonb_build_object('approvalRequestId',a.approval_request_id::text,'state',a.state,
  'expiresAt',a.expires_at::text,'candidateDigest',encode(a.subject_digest,'hex'),
  'live',a.state='APPROVED' AND a.expires_at>clock_timestamp()) INTO STRICT approval
 FROM control.approval_request a
 WHERE a.participant_id=command.participant_id AND a.privacy_domain_id=command.privacy_domain_id
  AND a.approval_request_id=command.approval_request_id AND a.subject_digest=command.approval_candidate_digest
 FOR SHARE OF a;
 RETURN jsonb_build_object('unchangedLive',unchanged AND live AND (approval->>'live')::boolean,
  'dependencies',current_rows,'approval',approval);
END $$;
CREATE OR REPLACE FUNCTION openpc.signing_continuation_authority_digest(p_status jsonb)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT sha256(convert_to(jsonb_set(jsonb_set(p_status,'{dependencies,session}',
  (SELECT coalesce(jsonb_agg(value-ARRAY['idle_expires_at','row_version'] ORDER BY value->>'session_id'),'[]'::jsonb)
   FROM jsonb_array_elements(p_status->'dependencies'->'session') value)),'{dependencies,credential}',
  (SELECT coalesce(jsonb_agg(value-'row_version' ORDER BY value->>'credential_id'),'[]'::jsonb)
   FROM jsonb_array_elements(p_status->'dependencies'->'credential') value))::text,'UTF8'))
$$;
`;

// PostgreSQL row locks require UPDATE privilege. Keep that privilege in a NOLOGIN,
// non-member function role rather than granting authority-row writes to the worker.
const readTables = [
  ...tables,
  'approval_request',
  'signing_rotation_command',
  'signing_provider_attempt',
  'signing_key_rotation',
];
const privacyTables = new Set([
  'privacy_domain',
  'approval_request',
  'signing_rotation_command',
  'signing_provider_attempt',
  'signing_key_rotation',
]);
export const signingAttemptAuthorityGrantsSql = `
GRANT USAGE ON SCHEMA openpc,control TO openpc_signing_authority_locker;
GRANT EXECUTE ON FUNCTION openpc.require_uuid_setting(text),openpc.current_participant_id(),openpc.current_privacy_domain_id(),
 openpc.matches_participant(uuid),openpc.matches_privacy(uuid) TO openpc_signing_authority_locker;
${readTables
  .map(
    (table) => `GRANT SELECT ON control.${table} TO openpc_signing_authority_locker;
DROP POLICY IF EXISTS signing_authority_locker_scope ON control.${table};
CREATE POLICY signing_authority_locker_scope ON control.${table} FOR ALL TO openpc_signing_authority_locker
 USING(openpc.matches_participant(participant_id)${privacyTables.has(table) ? ' AND openpc.matches_privacy(privacy_domain_id)' : ''})
 WITH CHECK(false);`,
  )
  .join('\n')}
${[
  ...tables.map((table) => [table, authoritySnapshotColumns[table][0]]),
  ['approval_request', 'approval_request_id'],
]
  .map(
    ([table, column]) =>
      `GRANT UPDATE(${column}) ON control.${table} TO openpc_signing_authority_locker;`,
  )
  .join('\n')}
ALTER FUNCTION openpc.signing_attempt_authority_status(uuid) OWNER TO openpc_signing_authority_locker;
`;
