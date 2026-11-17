import { workItemReceiptGuardsSql } from './work-item-receipt-guards.mjs';
import { governedReceiptGuardsSql } from './governed-receipt-guards.mjs';
import { governedReceiptOperationIds } from './governed-receipt-inputs.ts';
import { stepUpOnlyConfigurationOperations } from '../domain/configuration-step-up-admission.ts';
const governedOperations = governedReceiptOperationIds.map((id) => `'${id}'`).join(',');
const stepUpOperations = stepUpOnlyConfigurationOperations.map((id) => `'${id}'`).join(',');
import { identityRuntimeCoseBindingSql } from './identity-runtime-cose-binding.mjs';
import { moduleReceiptGuardSql } from './module-receipt-guards.mjs';
import { businessTransitionProfiles } from '../../../../packages/security-kernel/src/business-transition/profiles.generated.ts';
import { businessTransitionCoseContext } from '../../../../packages/security-kernel/src/business-transition/generated.ts';
import { businessTransitionCoseContextV2 } from '../../../../packages/security-kernel/src/business-transition/generated-v2.ts';

const profiles = businessTransitionProfiles
  .map((p) => `decode('${Buffer.from(p.definitionCanonicalJson).toString('hex')}','hex')`)
  .join(',');

export const businessReceiptGuardsSql = `
${identityRuntimeCoseBindingSql}
${governedReceiptGuardsSql}
${moduleReceiptGuardSql}
${workItemReceiptGuardsSql}
CREATE OR REPLACE FUNCTION openpc.guard_business_profile_admission()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.definition_canonical_json NOT IN (${profiles}) THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-BUSINESS-PROFILE'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER business_profile_admission BEFORE INSERT ON control.business_transition_profile
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_profile_admission();
CREATE OR REPLACE FUNCTION openpc.guard_business_receipt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE actual jsonb; expected jsonb; before_state jsonb; after_state jsonb; proof jsonb; receipt_version integer; continuation control.signing_continuation%ROWTYPE; continuation_used boolean:=false; authorization_time numeric;
 profile control.business_transition_profile%ROWTYPE; authorization_row control.mutation_evidence%ROWTYPE; runtime_payload jsonb; runtime_key_id text; outer_cose jsonb; protected_header jsonb;
BEGIN
 actual:=openpc.business_cbor(NEW.receipt_cbor);
 SELECT * INTO STRICT profile FROM control.business_transition_profile WHERE profile_digest=NEW.profile_digest;
 receipt_version:=CASE encode(profile.schema_definition_digest,'hex')
  WHEN '${businessTransitionCoseContext.definitionDigest.slice(7)}' THEN 1
  WHEN '${businessTransitionCoseContextV2.definitionDigest.slice(7)}' THEN 2 END;
 IF receipt_version IS NULL OR (receipt_version=2 AND profile.catalog_operation_id NOT IN
  ('OPS-OP-ADVANCE-SIGNING-KEY-ROTATION','OPS-OP-RECOVER-SIGNING-KEY-ROTATION'))
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-SCHEMA-VERSION'; END IF;
 IF NEW.schema_definition_digest<>profile.schema_definition_digest OR NEW.action_intent_id<>profile.action_intent_id OR
    NEW.catalog_operation_id<>profile.catalog_operation_id OR NEW.aggregate_type<>profile.aggregate_type OR
    NEW.transition_kind<>profile.transition_kind THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-PROFILE-BINDING'; END IF;
 expected:=jsonb_build_object('0',openpc.business_uuid(NEW.receipt_id),'1',openpc.business_bytes(NEW.schema_definition_digest),
  '2',NEW.profile_id,'3',NEW.profile_version,'4',openpc.business_bytes(NEW.profile_digest),'5',NEW.environment_id,
  '6',openpc.business_uuid(NEW.participant_id),'7',openpc.business_uuid(NEW.privacy_domain_id),
  '8',openpc.business_uuid(NEW.operation_id),'9',NEW.action_intent_id,'10',NEW.catalog_operation_id,
  '11',NEW.aggregate_type,'12',openpc.business_uuid(NEW.aggregate_id),'13',openpc.business_bytes(NEW.actor_key_digest),
  '14',openpc.business_bytes(NEW.pre_commit_authority_digest),'15',openpc.business_bytes(NEW.action_intent_digest),
  '16',openpc.business_bytes(NEW.candidate_digest),'17',openpc.business_uuid(NEW.idempotency_record_id),
  '18',jsonb_build_object('0',NEW.before_existence,'1',NEW.before_revision,'2',openpc.business_bytes(NEW.before_state_digest)),
  '19',jsonb_build_object('0',NEW.after_existence,'1',NEW.after_revision,'2',openpc.business_bytes(NEW.after_state_digest)),
  '20',actual->'20','21',actual->'21','22',NEW.transition_kind,'23',NEW.recorded_at_ns,
  '24',NEW.signer_id,'25',openpc.business_bytes(NEW.signer_trust_snapshot_digest),'26',openpc.business_bytes(NEW.request_digest));
 IF actual IS DISTINCT FROM expected OR octet_length(NEW.actor_key_digest)<>32 OR
    octet_length(NEW.action_intent_digest)<>32 OR octet_length(NEW.candidate_digest)<>32 OR
    octet_length(NEW.request_digest)<>32 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-TYPED-BINDING'; END IF;
 IF get_byte(NEW.cose_sign1,0)<>210 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-COSE-TAG'; END IF;
 outer_cose:=openpc.business_cbor_item(NEW.cose_sign1,1,0);
 IF (outer_cose->>'next')::integer<>octet_length(NEW.cose_sign1) THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-COSE-TRAILING'; END IF;
 outer_cose:=outer_cose->'value';
 IF jsonb_typeof(outer_cose)<>'array' OR jsonb_array_length(outer_cose)<>4 OR outer_cose->1<>'{}'::jsonb OR
    outer_cose->2 IS DISTINCT FROM openpc.business_bytes(NEW.receipt_cbor) OR
    length(outer_cose->3->>'bytes') IS DISTINCT FROM 128 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-COSE-BINDING'; END IF;
 protected_header:=openpc.business_cbor(decode(outer_cose->0->>'bytes','hex'));
 IF protected_header IS DISTINCT FROM jsonb_build_object('1',-7,'2',jsonb_build_array(100,101,102,103),
  '3','application/pc+cbor','4',openpc.business_bytes(convert_to(NEW.signer_id,'UTF8')),
  '100',24001,'101',receipt_version,'102',338,'103',2) THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-COSE-CONTEXT'; END IF;
 before_state:=openpc.business_cbor(NEW.before_state_preimage);
 after_state:=openpc.business_cbor(NEW.after_state_preimage);
 IF before_state IS DISTINCT FROM jsonb_build_array('pc.control.transition-state.v1',openpc.business_bytes(NEW.profile_digest),
  openpc.business_uuid(NEW.participant_id),openpc.business_uuid(NEW.privacy_domain_id),NEW.aggregate_type,
  openpc.business_uuid(NEW.aggregate_id),NEW.before_existence,NEW.before_revision,before_state->8) OR
  after_state IS DISTINCT FROM jsonb_build_array('pc.control.transition-state.v1',openpc.business_bytes(NEW.profile_digest),
  openpc.business_uuid(NEW.participant_id),openpc.business_uuid(NEW.privacy_domain_id),NEW.aggregate_type,
  openpc.business_uuid(NEW.aggregate_id),NEW.after_existence,NEW.after_revision,after_state->8) OR
  (NEW.before_existence=0 AND before_state->8<>'{}'::jsonb) THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-STATE-BINDING'; END IF;
 IF receipt_version=2 AND convert_from(NEW.authority_snapshot,'UTF8')::jsonb->>'schema'='pc.control.signing-rotation-continuation-snapshot.v1' THEN
  SELECT * INTO STRICT continuation FROM control.signing_continuation WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id AND state='CONSUMED'
   AND consumed_receipt_id=NEW.receipt_id;
  continuation_used:=true;
 END IF;
 IF jsonb_typeof(actual->'20') IS DISTINCT FROM 'array' OR jsonb_array_length(actual->'20')<>(CASE WHEN continuation_used OR NEW.catalog_operation_id IN (${governedOperations}) OR NEW.catalog_operation_id IN (${stepUpOperations}) THEN 2 ELSE 1 END) OR
    jsonb_typeof(actual->'21') IS DISTINCT FROM 'array' OR
    (receipt_version=1 AND jsonb_array_length(actual->'21')<>1) OR
    (receipt_version=2 AND jsonb_array_length(actual->'21') NOT BETWEEN 0 AND 1) THEN
  RAISE EXCEPTION 'DATA-6021-RECEIPT-PROFILE-CARDINALITY'; END IF;
 IF NEW.catalog_operation_id IN ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE') THEN
  PERFORM openpc.check_module_admission_receipt(NEW);
 ELSIF NEW.catalog_operation_id IN (${governedOperations}) THEN
  PERFORM openpc.check_governed_configuration_receipt(NEW);
 ELSE
 SELECT * INTO STRICT authorization_row FROM control.mutation_evidence e WHERE e.participant_id=NEW.participant_id
  AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id
  AND e.action_intent_id=NEW.action_intent_id AND e.catalog_operation_id=NEW.catalog_operation_id AND e.aggregate_id=NEW.aggregate_id
  AND e.candidate_digest=NEW.candidate_digest AND e.evidence_digest=sha256(e.evidence_cbor)
  AND e.evidence_role='AUTHORIZATION_INPUT' AND e.evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13';
 proof:=jsonb_build_object('0',2,'1',authorization_row.mutation_evidence_id::text,'2',openpc.business_bytes(authorization_row.evidence_digest));
 IF continuation_used THEN
  SELECT jsonb_agg(p ORDER BY p->>'1') INTO expected FROM jsonb_array_elements(jsonb_build_array(proof,
   jsonb_build_object('0',2,'1',continuation.assertion_id::text,'2',openpc.business_bytes(continuation.assertion_digest)))) p;
  SELECT (convert_from(c.authorization_snapshot,'UTF8')::jsonb->>'recordedAtNs')::numeric INTO STRICT authorization_time
   FROM control.signing_rotation_command c WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
    AND c.operation_id=NEW.operation_id AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1';
 ELSIF NEW.catalog_operation_id IN (${stepUpOperations}) THEN
  expected:=jsonb_build_array(proof,openpc.configuration_step_up_receipt_input(NEW,authorization_row));
  authorization_time:=NEW.recorded_at_ns;
 ELSE expected:=jsonb_build_array(proof); authorization_time:=NEW.recorded_at_ns;
 END IF;
 IF actual->'20' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-AUTHORIZATION-OWNER'; END IF;
 runtime_payload:=openpc.business_cbor(authorization_row.evidence_cbor);
 runtime_key_id:=openpc.identity_runtime_cose_key_id(authorization_row.evidence_cbor,authorization_row.cose_sign1);
 IF runtime_key_id=NEW.signer_id OR
    runtime_payload->'1' IS DISTINCT FROM openpc.business_bytes(NEW.actor_key_digest) OR
    jsonb_typeof(runtime_payload->'8') IS DISTINCT FROM 'number' OR jsonb_typeof(runtime_payload->'9') IS DISTINCT FROM 'number' OR
    (runtime_payload->>'8')::numeric>authorization_time OR (runtime_payload->>'9')::numeric<=authorization_time THEN
   RAISE EXCEPTION 'DATA-6021-AUTHORIZATION-TYPED-PURPOSE-BINDING'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=NEW.participant_id
   AND i.privacy_domain_id=NEW.privacy_domain_id AND i.operation_id=NEW.operation_id
   AND i.idempotency_record_id=NEW.idempotency_record_id AND i.action_intent_id=NEW.action_intent_id
   AND i.catalog_operation_id=NEW.catalog_operation_id AND i.input_digest=NEW.candidate_digest
   AND NEW.request_digest=openpc.business_request_digest(ARRAY[i.participant_id::text,i.privacy_domain_id::text,i.principal_id::text,
     i.action_intent_id,i.catalog_operation_id,NEW.aggregate_type,NEW.aggregate_id::text,i.expected_aggregate_version::text,
     'sha256:'||encode(i.input_digest,'hex'),i.idempotency_key])) THEN
  RAISE EXCEPTION 'DATA-6021-RECEIPT-IDEMPOTENCY-OWNER'; END IF;

 IF NEW.aggregate_type='evidence-hold' THEN
  PERFORM openpc.assert_evidence_hold_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='evidence-deletion' THEN
  PERFORM openpc.assert_evidence_deletion_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='runtime-artifact-disposition' THEN
  PERFORM openpc.assert_runtime_artifact_disposition_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='store-retirement' THEN
  PERFORM openpc.assert_store_retirement_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='retention-policy' THEN
  PERFORM openpc.assert_retention_policy_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='workload-renewal-policy' THEN
  PERFORM openpc.assert_workload_renewal_policy_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='work-item' THEN
  PERFORM openpc.assert_work_item_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='notification' THEN
  PERFORM openpc.assert_notification_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='notification-endpoint' THEN
  PERFORM openpc.assert_notification_endpoint_receipt(NEW);
 END IF;
 IF NEW.aggregate_type='indexer-profile' THEN
  IF profile.profile_version NOT IN (1,2) OR (profile.profile_version=2 AND (
    (NEW.before_existence=1 AND (NOT (before_state->8 ?& ARRAY['0','1','2','3','4']) OR
      before_state->8->'4' NOT IN ('0'::jsonb,'1'::jsonb) OR
      (before_state->8 ? '5') IS DISTINCT FROM (before_state->8->'4'='1'::jsonb) OR
      ((before_state->8)-ARRAY['0','1','2','3','4','5'])<>'{}'::jsonb OR
      (before_state->8->'4'='1'::jsonb AND (before_state->8->'5' IS DISTINCT FROM
        jsonb_build_object('bytes',before_state->8->'5'->>'bytes') OR
        coalesce(before_state->8->'5'->>'bytes','')!~'^[0-9a-f]{64}$')))) OR
    after_state->8->'4' NOT IN ('0'::jsonb,'1'::jsonb)))
  THEN RAISE EXCEPTION 'DATA-6021-INDEXER-PROVENANCE-PROFILE'; END IF;
  IF NOT EXISTS(SELECT 1 FROM control.indexer_profile i WHERE i.participant_id=NEW.participant_id
   AND i.privacy_domain_id=NEW.privacy_domain_id AND i.indexer_profile_id=NEW.aggregate_id
   AND i.revision=NEW.after_revision AND NEW.after_existence=1
   AND (profile.profile_version=2 OR i.policy_generation_digest IS NOT NULL)
   AND after_state->8=(jsonb_build_object('0',i.engine,'1',i.engine_version,
    '2',openpc.business_bytes(decode(substring(i.method_profile_digest from 8),'hex')),'3',i.state) ||
    CASE WHEN profile.profile_version=1 THEN jsonb_build_object('4',openpc.business_bytes(decode(substring(i.policy_generation_digest from 8),'hex')))
    WHEN i.policy_generation_digest IS NULL THEN jsonb_build_object('4',0)
    ELSE jsonb_build_object('4',1,'5',openpc.business_bytes(decode(substring(i.policy_generation_digest from 8),'hex'))) END)) THEN
    RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-INDEXER-STATE'; END IF;
  IF (NEW.catalog_operation_id='CFG-OP-CREATE-INDEXER-PROFILE' AND
      (NEW.before_existence<>0 OR NEW.after_revision<>1 OR after_state->8->>'3'<>'REGISTERED')) OR
     (NEW.catalog_operation_id='CFG-OP-UPDATE-INDEXER-PROFILE' AND
      (NEW.before_existence<>1 OR NEW.after_revision<>NEW.before_revision+1 OR
       before_state->8->'0' IS DISTINCT FROM after_state->8->'0' OR
       before_state->8->'1' IS DISTINCT FROM after_state->8->'1' OR
       before_state->8->'3' IS DISTINCT FROM after_state->8->'3' OR
       (before_state->8->'2'=after_state->8->'2' AND before_state->8->'4'=after_state->8->'4'
        AND before_state->8->'5' IS NOT DISTINCT FROM after_state->8->'5'))) THEN
    RAISE EXCEPTION 'DATA-6021-RECEIPT-INDEXER-TRANSITION'; END IF;
 END IF;
 IF receipt_version=2 THEN
  PERFORM openpc.check_signing_rotation_receipt(NEW);
  RETURN NEW;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.business_signing_selection s
  JOIN control.business_signing_key k USING(participant_id,privacy_domain_id,signer_id)
  JOIN control.business_signing_key_state lifecycle USING(participant_id,privacy_domain_id,signer_id)
  JOIN control.credential c ON c.participant_id=k.participant_id AND c.credential_id=k.workload_credential_id
  JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
  WHERE s.participant_id=NEW.participant_id AND s.privacy_domain_id=NEW.privacy_domain_id
   AND s.environment_id=NEW.environment_id AND s.profile_digest=NEW.profile_digest AND s.signer_id=NEW.signer_id
   AND k.trust_digest=NEW.signer_trust_snapshot_digest AND k.environment_id=NEW.environment_id
   AND lifecycle.state='ACTIVE' AND c.state='ACTIVE' AND p.kind='WORKLOAD' AND p.state='ACTIVE'
   AND c.credential_epoch=k.workload_credential_epoch
   AND c.valid_from<=clock_timestamp() AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
   AND k.valid_from_ns<=NEW.recorded_at_ns AND k.valid_until_ns>NEW.recorded_at_ns
   AND k.valid_until_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000
   FOR SHARE OF s,lifecycle,c,p) THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-LIVE-SIGNING-TRUST'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER business_receipt_typed BEFORE INSERT ON control.audit_occurrence
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_receipt();
CREATE OR REPLACE FUNCTION openpc.guard_business_outbox()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.audit_occurrence%ROWTYPE; payload jsonb;
BEGIN
 IF NEW.proof_kind='LEGACY' THEN RETURN NEW; END IF;
 -- This distinct namespace is fail-closed until the Control export owner installs
 -- its exact receipt/source/outbox checker. It cannot enter command receipt admission.
 IF NEW.proof_kind='EVIDENCE_EXPORT_COMPLETION_REFERENCE' THEN
  PERFORM openpc.check_evidence_export_completion_event(NEW);
  RETURN NEW;
 END IF;
 -- A distinct registered family: the owning checker must exist and validate
 -- actual original receipts, source, occurrence, payload references and cursors.
 -- Any missing owner or denial propagates; there is no command-receipt fallback.
 IF NEW.proof_kind='NOTIFICATION_DELIVERY_REQUEST_REFERENCE' THEN
  PERFORM openpc.check_notification_delivery_requested_event(NEW);
  RETURN NEW;
 END IF;
 -- Terminal native outcomes have a separate source-owned proof. A request
 -- receipt cannot authorize completion; missing final publication stays closed.
 IF NEW.proof_kind='NOTIFICATION_DELIVERY_COMPLETION_REFERENCE' THEN
  PERFORM openpc.check_notification_delivery_completed_event(NEW);
  RETURN NEW;
 END IF;
 IF NEW.proof_kind<>'BUSINESS_RECEIPT_REFERENCE' THEN RAISE EXCEPTION 'DATA-6021-UNADMITTED-OUTBOX-PROOF'; END IF;
 SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND receipt_id=NEW.receipt_id;
 payload:=openpc.business_cbor(NEW.payload_cbor);
 IF receipt.aggregate_type='signing-key-rotation' THEN
  PERFORM openpc.check_signing_rotation_event(NEW,receipt);
  RETURN NEW;
 END IF;
 IF NEW.aggregate_type<>receipt.aggregate_type OR NEW.aggregate_id<>receipt.aggregate_id OR
    NEW.payload_digest<>sha256(NEW.payload_cbor) OR NEW.event_type<>'io.openpc.control.command.committed.v1' OR
    NEW.data_schema_uri<>'https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted' OR
    payload IS DISTINCT FROM jsonb_build_object('0',openpc.business_uuid(receipt.operation_id),
      '1','urn:openpc:'||receipt.aggregate_type||':'||receipt.aggregate_id::text,
      '2',receipt.action_intent_id,'3',openpc.business_bytes(receipt.action_intent_digest)) THEN
   RAISE EXCEPTION 'DATA-6021-OUTBOX-RECEIPT-PAYLOAD'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER business_outbox_payload BEFORE INSERT ON control.outbox_event
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_outbox();
CREATE OR REPLACE FUNCTION openpc.check_business_receipt_completion()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.audit_occurrence%ROWTYPE; event_refs jsonb;
BEGIN
 SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND receipt_id=NEW.receipt_id;
 SELECT jsonb_agg(jsonb_build_object('0',openpc.business_uuid(e.event_id),'1',e.event_type,'2',e.data_schema_uri,
   '3',e.source,'4',e.subject,'5',e.business_sequence,'6',floor(extract(epoch FROM e.occurred_at)*1000000)*1000,
   '7',openpc.business_uuid(e.correlation_id),'9',openpc.business_bytes(e.payload_digest)) ||
   CASE WHEN e.causation_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('8',openpc.business_uuid(e.causation_id)) END ||
   CASE WHEN e.authority_generation IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('10',openpc.business_bytes(e.authority_generation)) END
   ORDER BY e.business_sequence) INTO event_refs FROM control.outbox_event e
  WHERE e.participant_id=receipt.participant_id AND e.privacy_domain_id=receipt.privacy_domain_id
    AND e.receipt_id=receipt.receipt_id AND e.proof_kind='BUSINESS_RECEIPT_REFERENCE';
 IF coalesce(event_refs,'[]'::jsonb) IS DISTINCT FROM (openpc.business_cbor(receipt.receipt_cbor)->'21') OR
    EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=receipt.participant_id
      AND e.privacy_domain_id=receipt.privacy_domain_id AND e.receipt_id=receipt.receipt_id
      AND NOT EXISTS(SELECT 1 FROM control.business_outbox_head h WHERE h.participant_id=e.participant_id
        AND h.privacy_domain_id=e.privacy_domain_id AND h.sequence_namespace=e.sequence_namespace
        AND h.aggregate_type=e.aggregate_type AND h.aggregate_id=e.aggregate_id AND h.last_sequence>=e.business_sequence)) OR
    NOT EXISTS(SELECT 1 FROM control.evidence_record e WHERE e.participant_id=receipt.participant_id
      AND e.privacy_domain_id=receipt.privacy_domain_id AND e.receipt_id=receipt.receipt_id
      AND e.recorded_at_ns=receipt.recorded_at_ns) OR
    NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=receipt.participant_id
      AND i.privacy_domain_id=receipt.privacy_domain_id AND i.operation_id=receipt.operation_id
      AND i.terminal_state='COMMITTED' AND i.result_digest IS NOT NULL AND i.result_payload IS NOT NULL) THEN
   RAISE EXCEPTION 'DATA-6021-INCOMPLETE-BUSINESS-COMMIT'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER business_receipt_complete AFTER INSERT ON control.audit_occurrence
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_business_receipt_completion();
CREATE CONSTRAINT TRIGGER business_event_complete AFTER INSERT ON control.outbox_event
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.proof_kind='BUSINESS_RECEIPT_REFERENCE')
 EXECUTE FUNCTION openpc.check_business_receipt_completion();
CREATE OR REPLACE FUNCTION openpc.guard_business_head()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF (TG_OP='INSERT' AND NEW.last_sequence<>1) OR
   (TG_OP='UPDATE' AND (NEW.participant_id<>OLD.participant_id OR NEW.privacy_domain_id<>OLD.privacy_domain_id OR
     NEW.sequence_namespace<>OLD.sequence_namespace OR NEW.aggregate_type<>OLD.aggregate_type OR NEW.aggregate_id<>OLD.aggregate_id OR
     NEW.last_sequence<>OLD.last_sequence+1)) THEN RAISE EXCEPTION 'DATA-6021-BUSINESS-SEQUENCE-TRANSITION'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER business_head_monotonic BEFORE INSERT OR UPDATE ON control.business_outbox_head
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_head();
CREATE OR REPLACE FUNCTION openpc.check_business_head_completion()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.outbox_event e WHERE e.participant_id=NEW.participant_id
  AND e.privacy_domain_id=NEW.privacy_domain_id AND e.sequence_namespace=NEW.sequence_namespace
  AND e.aggregate_type=NEW.aggregate_type AND e.aggregate_id=NEW.aggregate_id
  AND e.business_sequence=NEW.last_sequence AND e.proof_kind='BUSINESS_RECEIPT_REFERENCE') THEN
  RAISE EXCEPTION 'DATA-6021-ORPHAN-BUSINESS-SEQUENCE'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER business_head_complete AFTER INSERT OR UPDATE ON control.business_outbox_head
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_business_head_completion();
`;
