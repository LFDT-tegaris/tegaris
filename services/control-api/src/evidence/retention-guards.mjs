const actions = [
  [
    'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1',
    'CREATE',
    'HIGH',
    true,
    true,
    true,
    'REDACTED',
    'RETENTION_POLICY_ACTIVATION',
  ],
  [
    'ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1',
    'UPDATE',
    'HIGH',
    true,
    true,
    true,
    'REDACTED',
    'RETENTION_POLICY_RETIREMENT',
  ],
  [
    'ACT-RETENTION_POLICIES_READ_RESOURCE-V1',
    'READ',
    'STANDARD',
    false,
    false,
    false,
    'AUTHORIZED_FULL',
    'RETENTION_POLICY_READ',
  ],
  [
    'ACT-RETENTION_POLICIES_READ_COLLECTION-V1',
    'READ',
    'STANDARD',
    false,
    false,
    false,
    'AUTHORIZED_FULL',
    'RETENTION_POLICY_READ',
  ],
]
  .map(
    ([action, operation, risk, maker, step, idempotent, payload, evidence]) =>
      `('${action}','retention-policies','${operation}','${risk}',${maker},${step},${idempotent},'AUTHORIZED_ONLY','${payload}','${evidence}')`,
  )
  .join(',\n');

export const retentionPolicyGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ${actions} ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (${actions}))<>4
 THEN RAISE EXCEPTION 'PC-AUTH-0002-RETENTION-ACTION'; END IF;
END $$;
ALTER TABLE control.retention_policy FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.retention_policy FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.retention_policy TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT INSERT,UPDATE ON control.retention_policy TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.retention_policy_definition(rule control.retention_policy)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('dataClass',(rule).data_class,'policyVersion',(rule).policy_version,
  'retentionPeriodMs',(rule).retention_period_ms::text,'localGraceMs',(rule).local_grace_ms::text,
  'sinkQuorum',(rule).sink_quorum,'deletionMode',(rule).deletion_mode,'makerCheckerRequired',(rule).maker_checker_required)
$$;
CREATE OR REPLACE FUNCTION openpc.retention_policy_state_projection(rule control.retention_policy)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',openpc.business_bytes(decode(substring((rule).policy_digest from 8),'hex')),
  '1',CASE WHEN (rule).predecessor_policy_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((rule).predecessor_policy_id) END,
  '2',openpc.business_uuid((rule).approval_request_id),'3',openpc.business_uuid((rule).activation_operation_id),
  '4',CASE WHEN (rule).retirement_approval_request_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((rule).retirement_approval_request_id) END,
  '5',CASE WHEN (rule).retirement_operation_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((rule).retirement_operation_id) END,
  '6',floor(extract(epoch from (rule).active_from)*1000000)*1000,
  '7',CASE WHEN (rule).active_until IS NULL THEN openpc.business_bytes(''::bytea) ELSE to_jsonb(floor(extract(epoch from (rule).active_until)*1000000)*1000) END)
$$;
REVOKE ALL ON FUNCTION openpc.retention_policy_definition(control.retention_policy),openpc.retention_policy_state_projection(control.retention_policy) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.retention_policy_definition(control.retention_policy),openpc.retention_policy_state_projection(control.retention_policy)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_retention_policy()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE predecessor control.retention_policy%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 IF openpc.business_cbor(NEW.policy_cbor) IS DISTINCT FROM jsonb_build_object(
  '0','pc.evidence.retention-policy.v1','1',openpc.business_uuid(NEW.participant_id),'2',openpc.business_uuid(NEW.privacy_domain_id),
  '3',NEW.data_class,'4',NEW.policy_version,'5',NEW.retention_period_ms,'6',NEW.local_grace_ms,
  '7',NEW.sink_quorum,'8',NEW.deletion_mode,'9',CASE WHEN NEW.maker_checker_required THEN 1 ELSE 0 END) THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR NEW.active_until IS NOT NULL OR NEW.retirement_operation_id IS NOT NULL
   OR NEW.retirement_approval_request_id IS NOT NULL OR NEW.activation_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1'
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  SELECT * INTO predecessor FROM control.retention_policy p WHERE p.participant_id=NEW.participant_id
   AND p.privacy_domain_id=NEW.privacy_domain_id AND p.data_class=NEW.data_class
   ORDER BY p.active_from DESC,p.retention_policy_id DESC LIMIT 1 FOR UPDATE;
  IF NEW.predecessor_policy_id IS DISTINCT FROM predecessor.retention_policy_id
   OR (predecessor.retention_policy_id IS NOT NULL AND predecessor.active_until IS NULL)
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.active_from:=clock_timestamp();NEW.created_at:=NEW.active_from;
  IF predecessor.active_until IS NOT NULL AND predecessor.active_until>NEW.active_from THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['revision','active_until','retirement_operation_id','retirement_approval_request_id','updated_at']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['revision','active_until','retirement_operation_id','retirement_approval_request_id','updated_at'])
   OR OLD.revision<>1 OR NEW.revision<>2 OR OLD.active_until IS NOT NULL
   OR NEW.retirement_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>'ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1'
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  NEW.active_until:=clock_timestamp();
 END IF;
 NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS retention_policy_guard ON control.retention_policy;
CREATE TRIGGER retention_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON control.retention_policy
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_retention_policy();

CREATE OR REPLACE FUNCTION openpc.assert_retention_policy_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.retention_policy p WHERE p.participant_id=receipt.participant_id
  AND p.privacy_domain_id=receipt.privacy_domain_id AND p.retention_policy_id=receipt.aggregate_id
  AND p.revision=receipt.after_revision AND receipt.after_existence=1
  AND coalesce(p.retirement_operation_id,p.activation_operation_id)=receipt.operation_id
  AND receipt.catalog_operation_id=CASE WHEN p.active_until IS NULL THEN 'CFG-OP-ACTIVATE-RETENTION-POLICY' ELSE 'CFG-OP-RETIRE-RETENTION-POLICY' END
  AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.retention_policy_state_projection(p))
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-RETENTION-STATE'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_retention_policy_receipt(control.audit_occurrence) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_retention_policy_receipt(control.audit_occurrence) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.require_retention_policy_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE operation uuid; approval uuid; catalog text; action text; expected numeric;
BEGIN
 IF TG_OP='INSERT' THEN
  operation:=NEW.activation_operation_id;approval:=NEW.approval_request_id;catalog:='CFG-OP-ACTIVATE-RETENTION-POLICY';
  action:='ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1';expected:=0;
 ELSE
  operation:=NEW.retirement_operation_id;approval:=NEW.retirement_approval_request_id;catalog:='CFG-OP-RETIRE-RETENTION-POLICY';
  action:='ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1';expected:=1;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence e JOIN control.mutation_candidate c
  ON c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
   AND c.resource_id=e.aggregate_id AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
  JOIN control.audit_occurrence receipt ON receipt.participant_id=e.participant_id AND receipt.privacy_domain_id=e.privacy_domain_id
   AND receipt.operation_id=e.operation_id AND receipt.aggregate_id=e.aggregate_id AND receipt.aggregate_type='retention-policy'
  WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=operation
   AND e.approval_request_id=approval AND e.aggregate_type='retention-policy' AND e.aggregate_id=NEW.retention_policy_id
   AND e.catalog_operation_id=catalog AND e.action_intent_id=action
   AND c.catalog_operation_id=catalog AND c.action_intent_id=action AND c.state='CONSUMED' AND c.expected_revision=expected
   AND (TG_OP<>'INSERT' OR (c.candidate_document->'policy'=openpc.retention_policy_definition(NEW)
    AND c.candidate_document->'predecessorPolicyId'=coalesce(to_jsonb('urn:openpc:resource:'||NEW.predecessor_policy_id::text),'null'::jsonb)))
   AND receipt.catalog_operation_id=catalog AND receipt.action_intent_id=action
   AND receipt.before_existence=CASE WHEN TG_OP='INSERT' THEN 0 ELSE 1 END
   AND receipt.before_revision=expected AND receipt.after_existence=1 AND receipt.after_revision=NEW.revision
   AND openpc.business_cbor(receipt.before_state_preimage)->8=CASE WHEN TG_OP='INSERT' THEN '{}'::jsonb ELSE openpc.retention_policy_state_projection(OLD) END
   AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.retention_policy_state_projection(NEW)
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=receipt.participant_id
    AND event.privacy_domain_id=receipt.privacy_domain_id AND event.receipt_id=receipt.receipt_id
    AND event.aggregate_type=receipt.aggregate_type AND event.aggregate_id=receipt.aggregate_id
    AND event.event_type='io.openpc.control.command.committed.v1' AND event.proof_kind='BUSINESS_RECEIPT_REFERENCE'
    AND event.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1' AND event.payload_digest=sha256(event.payload_cbor)))
 THEN RAISE EXCEPTION 'PC-AUTH-0002-RETENTION-SIGNED-TRANSITION'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS retention_policy_command_required ON control.retention_policy;
CREATE CONSTRAINT TRIGGER retention_policy_command_required AFTER INSERT OR UPDATE ON control.retention_policy
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_retention_policy_command();
`;
