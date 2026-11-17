import { evidenceExportCoseContext as profile } from '../../../../packages/security-kernel/src/evidence-export/generated.ts';

/** This source family references its own original receipt by event identity. It
 * never impersonates a command receipt, legacy signed payload or delivery grant. */
export const evidenceExportPublicationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.check_evidence_export_completion_event(event control.outbox_event)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE completion control.evidence_export_completion%ROWTYPE; claims jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
  OR event.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR event.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT completion FROM control.evidence_export_completion
 WHERE participant_id=event.participant_id AND privacy_domain_id=event.privacy_domain_id AND event_id=event.event_id;
 claims:=completion.claims;
 IF completion.state NOT IN ('OBSERVED','PUBLISHED') OR completion.cose_sign1 IS NULL
  OR event.proof_kind<>'EVIDENCE_EXPORT_COMPLETION_REFERENCE'
  OR event.sequence_namespace<>'EVIDENCE_EXPORT_COMPLETION_V1'
  OR event.aggregate_type<>'evidence-export' OR event.aggregate_id<>completion.evidence_export_id
  OR event.aggregate_sequence IS NOT NULL OR event.business_sequence IS DISTINCT FROM 1::numeric
  OR event.receipt_id IS NOT NULL OR event.cose_sign1 IS NOT NULL
  OR event.authority_generation IS NOT NULL OR event.webauthn_assertion_binding_digest IS NOT NULL
  OR event.event_type<>'io.openpc.evidence.export.completed.v1'
  OR event.data_schema_uri IS DISTINCT FROM 'https://schemas.openpc.local/event-payloads.schema.json#/$defs/EvidenceExportCompleted'
  OR event.source IS DISTINCT FROM 'urn:openpc:service:'||(claims->>'sourceId')
  OR event.subject IS DISTINCT FROM 'urn:openpc:resource:'||completion.evidence_export_id::text
  OR event.correlation_id::text IS DISTINCT FROM claims->>'startOperationId'
  OR event.causation_id::text IS DISTINCT FROM claims->>'causationId'
  OR floor(extract(epoch from event.occurred_at)*1000000)*1000 IS DISTINCT FROM (claims->>'recordedAtNs')::numeric
  OR event.payload_cbor IS DISTINCT FROM completion.source_data
  OR event.payload_digest IS DISTINCT FROM sha256(completion.source_data)
 THEN RAISE EXCEPTION 'DATA-6021-EXPORT-COMPLETION-OUTBOX'; END IF;
 PERFORM openpc.archive_cose_binding(completion.receipt_payload,completion.cose_sign1,claims->>'signerKeyId',${profile.schemaId},${profile.purposeCode});
END $$;
REVOKE ALL ON FUNCTION openpc.check_evidence_export_completion_event(control.outbox_event) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.check_evidence_export_completion_event(control.outbox_event) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.check_evidence_export_publication_pair()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE completion control.evidence_export_completion%ROWTYPE; event control.outbox_event%ROWTYPE;
BEGIN
 SELECT * INTO STRICT completion FROM control.evidence_export_completion
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id;
 SELECT * INTO STRICT event FROM control.outbox_event
 WHERE participant_id=completion.participant_id AND privacy_domain_id=completion.privacy_domain_id AND event_id=completion.event_id;
 IF completion.state<>'PUBLISHED' THEN RAISE EXCEPTION 'DATA-6021-EXPORT-PUBLICATION-INCOMPLETE'; END IF;
 PERFORM openpc.check_evidence_export_completion_event(event);
 RETURN NULL;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RAISE EXCEPTION 'DATA-6021-EXPORT-PUBLICATION-INCOMPLETE';
END $$;
REVOKE ALL ON FUNCTION openpc.check_evidence_export_publication_pair() FROM PUBLIC;
DROP TRIGGER IF EXISTS evidence_export_publication_pair ON control.evidence_export_completion;
CREATE CONSTRAINT TRIGGER evidence_export_publication_pair AFTER UPDATE ON control.evidence_export_completion
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.state='PUBLISHED')
 EXECUTE FUNCTION openpc.check_evidence_export_publication_pair();
DROP TRIGGER IF EXISTS evidence_export_outbox_pair ON control.outbox_event;
CREATE CONSTRAINT TRIGGER evidence_export_outbox_pair AFTER INSERT ON control.outbox_event
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.proof_kind='EVIDENCE_EXPORT_COMPLETION_REFERENCE')
 EXECUTE FUNCTION openpc.check_evidence_export_publication_pair();
`;
