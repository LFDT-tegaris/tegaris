import { evidenceExportCoseContext as profile } from '../../../../packages/security-kernel/src/evidence-export/generated.ts';

const claimsMap = profile.fields
  .map((field) => {
    const claim = `c->>'${field.name}'`;
    const value =
      field.key === 0
        ? `openpc.business_bytes(decode('${profile.definitionDigest.slice(7)}','hex'))`
        : field.type === 'uuidv7'
          ? `openpc.business_uuid((${claim})::uuid)`
          : field.type === 'H32'
            ? `openpc.business_bytes(decode(substr(${claim},8),'hex'))`
            : field.type === 'u64p'
              ? `(${claim})::numeric`
              : claim;
    return `'${field.key}',${value}`;
  })
  .join(',');

/** Preparation, exact signed observation and publication have distinct admissions.
 * The publication owner adds the deferred original-receipt/outbox pair checks. */
export const evidenceExportCompletionGuardsSql = `
ALTER TABLE control.evidence_export_completion FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_export_completion FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_export_completion TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT INSERT ON control.evidence_export_completion TO openpc_control_runtime;
GRANT UPDATE(state,cose_sign1) ON control.evidence_export_completion TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.archive_cose_binding(bytea,bytea,text,integer,integer) TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.evidence_export_completion_source(uuid) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_export_completion_preparation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE c jsonb; source jsonb; installed control.evidence_export_producer_installation; expected jsonb; now_ns numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='UPDATE' THEN
  IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
   OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
   OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
   OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
   OR NOT ((OLD.state='PREPARED' AND NEW.state='OBSERVED' AND OLD.cose_sign1 IS NULL AND NEW.cose_sign1 IS NOT NULL)
    OR (OLD.state='OBSERVED' AND NEW.state='PUBLISHED' AND OLD.cose_sign1 IS NOT NULL AND NEW.cose_sign1=OLD.cose_sign1))
   OR to_jsonb(NEW)-ARRAY['state','cose_sign1'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','cose_sign1']
  THEN RAISE EXCEPTION 'DATA-6020-EXPORT-COMPLETION-IMMUTABLE'; END IF;
  -- A direct UPDATE already owns a row lock. Never wait in reverse order.
  IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('evidence-export-producer:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0))
   OR NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0))
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  IF NEW.authority_snapshot IS DISTINCT FROM convert_to(openpc.signing_canonical_json(openpc.evidence_export_producer_authority(NEW.trust_digest)),'UTF8')
  THEN RAISE EXCEPTION 'PC-AUTH-0005-EXPORT-COMPLETION-AUTHORITY'; END IF;
  source:=openpc.evidence_export_completion_source(NEW.evidence_export_id);
  IF source->>'streamId' IS DISTINCT FROM NEW.stream_id OR
   source-'streamId' IS DISTINCT FROM NEW.claims-ARRAY['environmentId','eventId','sourceId','sequence','recordedAtNs','dataDigest','authoritySnapshotDigest','signerTrustSnapshotDigest','signerKeyId']
  THEN RAISE EXCEPTION 'DATA-6021-EXPORT-COMPLETION-BINDING'; END IF;
  PERFORM openpc.archive_cose_binding(NEW.receipt_payload,NEW.cose_sign1,NEW.claims->>'signerKeyId',${profile.schemaId},${profile.purposeCode});
  RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-EXPORT-COMPLETION-IMMUTABLE'; END IF;
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 OR NEW.state<>'PREPARED' OR NEW.cose_sign1 IS NOT NULL
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('evidence-export-producer:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 SELECT * INTO STRICT installed FROM control.evidence_export_producer_installation
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND trust_digest=NEW.trust_digest AND state='ACTIVE';
 IF NEW.authority_snapshot IS DISTINCT FROM convert_to(openpc.signing_canonical_json(openpc.evidence_export_producer_authority(NEW.trust_digest)),'UTF8')
 THEN RAISE EXCEPTION 'PC-AUTH-0005-EXPORT-COMPLETION-AUTHORITY'; END IF;
 source:=openpc.evidence_export_completion_source(NEW.evidence_export_id);
 c:=NEW.claims;
 expected:=(source-'streamId')||jsonb_build_object(
  'environmentId',installed.environment_id,'eventId',NEW.event_id::text,'sourceId',installed.source_id::text,
  'sequence','1','recordedAtNs',c->>'recordedAtNs','dataDigest','sha256:'||encode(sha256(NEW.source_data),'hex'),
  'authoritySnapshotDigest','sha256:'||encode(sha256(NEW.authority_snapshot),'hex'),
  'signerTrustSnapshotDigest',installed.trust_digest,'signerKeyId',installed.signer_id);
 IF c IS DISTINCT FROM expected OR source->>'streamId' IS DISTINCT FROM NEW.stream_id
 OR coalesce(c->>'recordedAtNs','')!~'^[1-9][0-9]{0,19}$'
 THEN RAISE EXCEPTION 'DATA-6021-EXPORT-COMPLETION-BINDING'; END IF;
 now_ns:=floor(extract(epoch from clock_timestamp())*1000000)*1000;
 IF (c->>'recordedAtNs')::numeric>now_ns OR (c->>'recordedAtNs')::numeric<now_ns-5000000000
 OR mod((c->>'recordedAtNs')::numeric,1000)<>0
 THEN RAISE EXCEPTION 'DATA-6021-EXPORT-COMPLETION-TIME'; END IF;
 IF openpc.business_cbor(NEW.source_data) IS DISTINCT FROM jsonb_build_object(
  '0','urn:openpc:resource:'||NEW.evidence_export_id::text,'1',(source->>'checkpoint')::numeric,
  '2',openpc.business_bytes(decode(substr(source->>'outputDigest',8),'hex')),'3',(source->>'recordCount')::numeric)
 OR openpc.business_cbor(NEW.receipt_payload) IS DISTINCT FROM jsonb_build_object(${claimsMap})
 THEN RAISE EXCEPTION 'DATA-6021-EXPORT-COMPLETION-PAYLOAD'; END IF;
 expected:=jsonb_build_object('specversion','1.0','id',NEW.event_id::text,'source','urn:openpc:service:'||installed.source_id::text,
  'type','io.openpc.evidence.export.completed.v1','subject','urn:openpc:resource:'||NEW.evidence_export_id::text,
  'time',to_char(to_timestamp(floor((c->>'recordedAtNs')::numeric/1000000000)::double precision) at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS')||'.'||lpad(mod((c->>'recordedAtNs')::numeric/1000,1000000)::bigint::text,6,'0')||'Z',
  'datacontenttype','application/json','dataschema','https://schemas.openpc.local/event-payloads.schema.json#/$defs/EvidenceExportCompleted',
  'participantid','urn:openpc:participant:'||NEW.participant_id::text,'privacydomainid','urn:openpc:privacy-domain:'||NEW.privacy_domain_id::text,
  'correlationid',source->>'startOperationId','causationid',source->>'causationId','sequence','1','datadigest',c->>'dataDigest',
  'data',jsonb_build_object('evidenceExportId','urn:openpc:resource:'||NEW.evidence_export_id::text,'checkpoint',source->>'checkpoint','outputDigest',source->>'outputDigest','recordCount',source->>'recordCount'));
 IF NEW.event_payload IS DISTINCT FROM convert_to(openpc.signing_canonical_json(expected),'UTF8')
 THEN RAISE EXCEPTION 'DATA-6021-EXPORT-COMPLETION-EVENT'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_evidence_export_completion_preparation() FROM PUBLIC;
DROP TRIGGER IF EXISTS evidence_export_completion_preparation ON control.evidence_export_completion;
CREATE TRIGGER evidence_export_completion_preparation BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_export_completion
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_export_completion_preparation();
`;
