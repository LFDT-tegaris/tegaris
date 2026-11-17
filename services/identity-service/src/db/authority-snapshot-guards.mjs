import { governedReceiptOperationIds } from './governed-receipt-inputs.ts';
const governedOperations = governedReceiptOperationIds.map((id) => `'${id}'`).join(',');
import { authoritySnapshotColumns } from './authority-snapshot-columns.ts';

const keys = Object.keys(authoritySnapshotColumns).sort();
const dependencies = keys
  .map((table) => {
    const columns = authoritySnapshotColumns[table];
    const fields = columns.map((column) => `'${column}',owner.${column}::text`).join(',');
    return `
  IF jsonb_typeof(snapshot->'dependencies'->'${table}') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-TYPE'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object(${fields}) ORDER BY owner.${columns[0]}),'[]'::jsonb) INTO expected
   FROM control.${table} owner WHERE owner.participant_id=NEW.participant_id AND owner.${columns[0]} IN
    (SELECT (dependency->>'${columns[0]}')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'${table}') dependency);
  IF snapshot->'dependencies'->'${table}' IS DISTINCT FROM expected ${
    table === 'session'
      ? `AND NOT (
    NEW.aggregate_type='signing-key-rotation'
    AND jsonb_array_length(snapshot->'dependencies'->'session')=jsonb_array_length(expected)
    AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot->'dependencies'->'session') retained
      WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(expected) current_row
       WHERE (retained-'idle_expires_at')=(current_row-'idle_expires_at')
        AND (retained->>'idle_expires_at')::timestamptz<=(current_row->>'idle_expires_at')::timestamptz
        AND (extract(epoch FROM (retained->>'idle_expires_at')::timestamptz)*1000000000)>NEW.recorded_at_ns
        AND (current_row->>'idle_expires_at')::timestamptz>clock_timestamp()))
  )`
      : ''
  } THEN
    RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-ACTUAL-ROW'; END IF;`;
  })
  .join('\n');

export const authoritySnapshotGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_business_authority_snapshot()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE snapshot jsonb; expected jsonb; bound jsonb;
BEGIN
 IF octet_length(NEW.authority_snapshot)>65536 THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-SIZE'; END IF;
 snapshot:=convert_from(NEW.authority_snapshot,'UTF8')::jsonb;
 IF snapshot->>'schema'='pc.control.signing-rotation-continuation-snapshot.v1' THEN
  IF NEW.aggregate_type<>'signing-key-rotation' THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-RECEIPT-PURPOSE'; END IF;
  PERFORM openpc.check_signing_continuation_snapshot(NEW.authority_snapshot,NEW.participant_id,NEW.privacy_domain_id,
   NEW.operation_id,NEW.receipt_id,NEW.recorded_at_ns,true);
  RETURN NEW;
 END IF;
 IF snapshot IS DISTINCT FROM jsonb_build_object('schema','pc.control.precommit-authority-snapshot.v1',
  'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'operationId',NEW.operation_id::text,
  'recordedAtNs',snapshot->'recordedAtNs','decision','ALLOW','authorities',snapshot->'authorities','dependencies',snapshot->'dependencies') OR
  jsonb_typeof(snapshot->'authorities') IS DISTINCT FROM 'array' OR
  jsonb_array_length(snapshot->'authorities')<>(CASE WHEN NEW.aggregate_type='signing-key-rotation' OR NEW.catalog_operation_id IN (${governedOperations}) THEN 3 ELSE 1 END) OR
  NOT ((snapshot->>'recordedAtNs') ~ '^[0-9]{1,20}$') OR (snapshot->>'recordedAtNs')::numeric>NEW.recorded_at_ns THEN
   RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-HEADER'; END IF;
 IF snapshot->'dependencies' IS DISTINCT FROM jsonb_build_object(${keys.map((key) => `'${key}',snapshot->'dependencies'->'${key}'`).join(',')}) THEN
  RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-DEPENDENCIES'; END IF;
${dependencies}
 bound:=snapshot->'authorities'->0;
 IF bound->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text OR
    bound->>'actionIntentId' IS DISTINCT FROM NEW.action_intent_id OR bound->>'resourceId' IS DISTINCT FROM NEW.aggregate_id::text OR
    NOT (snapshot->'dependencies'->'participant' @> jsonb_build_array(jsonb_build_object('participant_id',NEW.participant_id::text,'state','ACTIVE','authority_epoch',bound->>'participantEpoch'))) OR
    NOT (snapshot->'dependencies'->'privacy_domain' @> jsonb_build_array(jsonb_build_object('privacy_domain_id',NEW.privacy_domain_id::text,'state','ACTIVE'))) OR
    NOT (snapshot->'dependencies'->'principal' @> jsonb_build_array(jsonb_build_object('principal_id',bound->>'principalId','state','ACTIVE','authority_epoch',bound->>'principalEpoch'))) OR
    NOT (snapshot->'dependencies'->'session' @> jsonb_build_array(jsonb_build_object('session_id',bound->>'sessionId','principal_id',bound->>'principalId','state','ACTIVE','session_epoch',bound->>'sessionEpoch'))) OR
    NOT (snapshot->'dependencies'->'assignment' @> jsonb_build_array(jsonb_build_object('assignment_id',bound->>'assignmentId','state','ACTIVE','row_version',bound->>'assignmentRowVersion'))) OR
    NOT (snapshot->'dependencies'->'authority_envelope' @> jsonb_build_array(jsonb_build_object('authority_envelope_id',bound->>'authorityEnvelopeId','state','ACTIVE','authority_epoch',bound->>'authorityEpoch'))) THEN
   RAISE EXCEPTION 'DATA-6021-AUTHORITY-SNAPSHOT-BOUND-PATH'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER business_authority_snapshot_typed BEFORE INSERT ON control.audit_occurrence
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_authority_snapshot();
`;
