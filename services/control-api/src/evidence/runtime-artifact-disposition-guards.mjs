import { runtimeArtifactDispositionSelectionSql } from './runtime-artifact-disposition-selection.mjs';

const operation = 'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE';
const action = 'ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1';
const profile = 'pc.control.runtime-artifact.disposition';
export const runtimeArtifactDispositionGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
 VALUES('${action}','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RUNTIME_ARTIFACT_SOURCE_DISPOSITION'),
 ('ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1','evidence-deletions','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_ARTIFACT_SOURCE_DISPOSITION_READ')
 ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.action_intent WHERE action_intent_id='${action}' AND resource_type='evidence-deletions'
  AND operation_class='CREATE' AND risk_class='HIGH' AND maker_checker_required AND step_up_required AND idempotency_required
  AND existence_disclosure='AUTHORIZED_ONLY' AND payload_disclosure='REDACTED' AND evidence_class='RUNTIME_ARTIFACT_SOURCE_DISPOSITION')
 OR NOT EXISTS(SELECT 1 FROM control.action_intent WHERE action_intent_id='ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1'
  AND resource_type='evidence-deletions' AND operation_class='READ' AND risk_class='STANDARD' AND NOT maker_checker_required
  AND NOT step_up_required AND NOT idempotency_required AND existence_disclosure='AUTHORIZED_ONLY' AND payload_disclosure='AUTHORIZED_FULL')
 THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-ACTION-UNAVAILABLE'; END IF;
END $$;
${runtimeArtifactDispositionSelectionSql}
GRANT INSERT ON control.runtime_artifact_source_disposition TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.runtime_artifact_disposition_state(a control.runtime_artifact_source_disposition)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',openpc.business_uuid((a).source_owner_id),'1',openpc.business_uuid((a).runtime_configuration_input_id),
  '2',openpc.business_bytes((a).configuration_digest),'3',openpc.business_bytes((a).selection_digest),
  '4',openpc.business_uuid((a).approval_request_id),'5',openpc.business_uuid((a).operation_id),
  '6',floor(extract(epoch from (a).admitted_at)*1000000)*1000)
$$;
REVOKE ALL ON FUNCTION openpc.runtime_artifact_disposition_state(control.runtime_artifact_source_disposition) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_artifact_disposition_state(control.runtime_artifact_source_disposition) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_source_disposition_immutable()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' OR openpc.current_action_intent_id() IS DISTINCT FROM '${action}' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 PERFORM openpc.lock_runtime_artifact_disposition();
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_disposition_row()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE actual jsonb;
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<>1 OR openpc.current_action_intent_id() IS DISTINCT FROM '${action}'
  OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR NEW.operation_id IS DISTINCT FROM openpc.current_operation_id() OR NEW.revision<>1
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 actual:=openpc.runtime_artifact_disposition_selection(NEW.runtime_configuration_input_id,right(NEW.selection->'observation'->>'retentionPolicyId',36)::uuid);
 IF actual IS DISTINCT FROM NEW.selection OR NEW.source_owner_id IS DISTINCT FROM (actual->>'sourceOwnerId')::uuid
  OR NEW.configuration_digest IS DISTINCT FROM decode(substring(actual->'observation'->'source'->>'configurationDigest' from 8),'hex')
  OR NEW.selection_digest IS DISTINCT FROM sha256(convert_to(openpc.signing_canonical_json(actual),'UTF8'))
 THEN RAISE EXCEPTION 'RUNTIME-DISPOSITION-STALE_SELECTION'; END IF;
 NEW.admitted_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS runtime_artifact_disposition_row ON control.runtime_artifact_source_disposition;
CREATE TRIGGER runtime_artifact_disposition_row BEFORE INSERT OR UPDATE OR DELETE ON control.runtime_artifact_source_disposition
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_artifact_disposition_row();

CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_disposition_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF receipt.profile_id<>'${profile}' OR receipt.profile_version<>1 OR receipt.catalog_operation_id<>'${operation}'
  OR receipt.action_intent_id<>'${action}' OR receipt.aggregate_type<>'runtime-artifact-disposition'
  OR receipt.before_existence<>0 OR receipt.before_revision<>0 OR receipt.after_existence<>1 OR receipt.after_revision<>1
  OR openpc.business_cbor(receipt.before_state_preimage)->8 IS DISTINCT FROM '{}'::jsonb
  OR NOT EXISTS(SELECT 1 FROM control.runtime_artifact_source_disposition a WHERE a.participant_id=receipt.participant_id
   AND a.privacy_domain_id=receipt.privacy_domain_id AND a.disposition_id=receipt.aggregate_id AND a.operation_id=receipt.operation_id
   AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.runtime_artifact_disposition_state(a))
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-SOURCE-DISPOSITION'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_source_disposition_committed(a control.runtime_artifact_source_disposition)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE matched integer; receipt control.audit_occurrence;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF a.participant_id IS DISTINCT FROM openpc.current_participant_id() OR a.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR a.revision<>1 OR a.selection_digest IS DISTINCT FROM sha256(convert_to(openpc.signing_canonical_json(a.selection),'UTF8'))
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=a.participant_id AND privacy_domain_id=a.privacy_domain_id
  AND aggregate_id=a.disposition_id AND aggregate_type='runtime-artifact-disposition' AND operation_id=a.operation_id;
 PERFORM openpc.assert_runtime_artifact_disposition_receipt(receipt);
 SELECT count(*) INTO matched FROM control.mutation_evidence e JOIN control.mutation_candidate c
  ON c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id AND c.resource_id=e.aggregate_id
   AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
  JOIN control.idempotency_record i ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id
   AND i.operation_id=e.operation_id AND i.catalog_operation_id=e.catalog_operation_id AND i.input_digest=e.candidate_digest
 WHERE e.participant_id=a.participant_id AND e.privacy_domain_id=a.privacy_domain_id AND e.operation_id=a.operation_id
  AND e.approval_request_id=a.approval_request_id AND e.aggregate_type='runtime-artifact-disposition' AND e.aggregate_id=a.disposition_id
  AND e.catalog_operation_id='${operation}' AND e.action_intent_id='${action}'
  AND c.catalog_operation_id=e.catalog_operation_id AND c.action_intent_id=e.action_intent_id AND c.state='CONSUMED' AND c.expected_revision=0
  AND c.candidate_document->'selection'=a.selection AND i.terminal_state='COMMITTED' AND i.expected_aggregate_version=0
  AND receipt.candidate_digest=e.candidate_digest AND receipt.idempotency_record_id=i.idempotency_record_id
  AND receipt.receipt_digest=sha256(receipt.receipt_cbor)
  AND (SELECT count(*) FROM control.outbox_event event WHERE event.participant_id=receipt.participant_id
   AND event.privacy_domain_id=receipt.privacy_domain_id AND event.receipt_id=receipt.receipt_id
   AND event.aggregate_type=receipt.aggregate_type AND event.aggregate_id=receipt.aggregate_id
   AND event.event_type='io.openpc.control.command.committed.v1' AND event.proof_kind='BUSINESS_RECEIPT_REFERENCE'
   AND event.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1' AND event.payload_digest=sha256(event.payload_cbor))=1;
 IF matched<>1 THEN RAISE EXCEPTION 'PC-AUTH-0002-RUNTIME-DISPOSITION-SIGNED-ADMISSION'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.require_runtime_artifact_disposition_commit()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_runtime_artifact_source_disposition_committed(NEW);
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS runtime_artifact_disposition_commit ON control.runtime_artifact_source_disposition;
CREATE CONSTRAINT TRIGGER runtime_artifact_disposition_commit AFTER INSERT ON control.runtime_artifact_source_disposition
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_runtime_artifact_disposition_commit();
REVOKE ALL ON FUNCTION openpc.guard_runtime_artifact_disposition_row(),openpc.assert_runtime_artifact_disposition_receipt(control.audit_occurrence),
 openpc.assert_runtime_artifact_source_disposition_committed(control.runtime_artifact_source_disposition),openpc.require_runtime_artifact_disposition_commit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_runtime_artifact_disposition_receipt(control.audit_occurrence),
 openpc.assert_runtime_artifact_source_disposition_committed(control.runtime_artifact_source_disposition) TO openpc_control_runtime,openpc_control_worker;
`;
