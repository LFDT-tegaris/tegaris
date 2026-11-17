const historicalReadPolicies = [
  [
    'mutation_evidence',
    `mutation_evidence.operation_id=w.operation_id
     AND mutation_evidence.aggregate_id=w.runtime_target_id
     AND mutation_evidence.action_intent_id='ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1'
     AND mutation_evidence.catalog_operation_id='CFG-OP-UPDATE-RUNTIME-TARGET'
     AND mutation_evidence.evidence_role='AUTHORIZATION_INPUT'
     AND mutation_evidence.evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13'`,
  ],
  [
    'outbox_event',
    'outbox_event.event_id=w.result_event_id AND outbox_event.aggregate_id=w.runtime_target_id',
  ],
  ['idempotency_record', 'idempotency_record.operation_id=w.operation_id'],
]
  .map(
    ([table, binding]) => `
DROP POLICY IF EXISTS runtime_unsigned_withdrawal_provenance_read ON control.${table};
CREATE POLICY runtime_unsigned_withdrawal_provenance_read ON control.${table}
 FOR SELECT TO openpc_control_owner USING(
 openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
 AND openpc.current_action_intent_id() IN ('ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
  'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1')
 AND EXISTS(SELECT 1 FROM control.configuration_work w
  JOIN control.runtime_target_disposition_admission a
   ON a.participant_id=w.participant_id AND a.privacy_domain_id=w.privacy_domain_id
    AND a.runtime_target_id=w.runtime_target_id
    AND a.binding->'cause'=jsonb_build_object('kind','Activation','work_id',w.configuration_work_id::text,
     'operation_id',w.operation_id::text,'execution_attempt_id',NULL)
  WHERE w.participant_id=${table}.participant_id AND w.privacy_domain_id=${table}.privacy_domain_id
   AND w.work_kind='RUNTIME_ACTIVATION' AND w.state='FAILED'
   AND w.execution_started_at IS NULL AND w.execution_attempt_id IS NULL
   AND a.binding->>'action'='Withdraw' AND a.activation_proof IS NULL AND a.restoration_proof IS NULL
   AND a.binding->'source'->>'original_work_id'<>w.configuration_work_id::text
   AND w.predecessor_digest='sha256:'||(a.binding->'source'->>'capsule_digest')
   AND ${binding}
   AND NOT EXISTS(SELECT 1 FROM control.runtime_target_disposition_delivery d
    WHERE d.participant_id=a.participant_id AND d.privacy_domain_id=a.privacy_domain_id
     AND d.runtime_target_id=a.runtime_target_id AND d.revision=a.revision)));
`,
  )
  .join('\n');

/** Historical predicate only: no permit, signature, deletion or serving grant.
 * Callers independently lock the latest head and admit a fresh denial. */
export const unsignedWithdrawalRecoverySql = `
${historicalReadPolicies}
CREATE OR REPLACE FUNCTION openpc.runtime_unsigned_withdrawal_recoverable(
 target uuid,wanted_revision bigint,wanted_digest text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE pid uuid; privacy uuid; abandoned control.runtime_target_disposition_admission;
 previous control.runtime_target_disposition_admission; delivery control.runtime_target_disposition_delivery;
 failed control.configuration_work; generation control.runtime_configuration_generation; payload bytea;
BEGIN
 PERFORM openpc.assert_request_context(true);
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 IF target IS NULL OR wanted_revision IS NULL OR wanted_revision<2 OR wanted_digest IS NULL
  OR openpc.current_action_intent_id() NOT IN ('ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
   'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1') THEN RETURN false; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||pid::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||pid::text||':'||privacy::text||':'||target::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT a.* INTO abandoned FROM control.runtime_target_disposition_admission a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target
   AND a.revision=wanted_revision AND a.admission_digest=wanted_digest FOR SHARE NOWAIT;
 IF NOT FOUND OR abandoned.binding->>'action' IS DISTINCT FROM 'Withdraw'
  OR abandoned.activation_proof IS NOT NULL OR abandoned.restoration_proof IS NOT NULL
  OR abandoned.binding->'cause'->>'kind' IS DISTINCT FROM 'Activation'
  OR abandoned.binding->'cause'->'execution_attempt_id' IS DISTINCT FROM 'null'::jsonb
  OR EXISTS(SELECT 1 FROM control.runtime_target_disposition_delivery d WHERE d.participant_id=pid
   AND d.privacy_domain_id=privacy AND d.runtime_target_id=target AND d.revision=wanted_revision)
 THEN RETURN false; END IF;
 SELECT a.* INTO previous FROM control.runtime_target_disposition_admission a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target
   AND a.revision=wanted_revision-1 FOR SHARE NOWAIT;
 IF NOT FOUND OR previous.binding->>'action' IS DISTINCT FROM 'ConfirmActivation'
  OR previous.binding->'target' IS DISTINCT FROM abandoned.binding->'target'
  OR previous.binding->'source' IS DISTINCT FROM abandoned.binding->'source'
  OR abandoned.binding->'previous_revision' IS DISTINCT FROM to_jsonb(previous.revision)
 THEN RETURN false; END IF;
 SELECT d.* INTO delivery FROM control.runtime_target_disposition_delivery d
  WHERE d.participant_id=pid AND d.privacy_domain_id=privacy AND d.runtime_target_id=target
   AND d.revision=previous.revision;
 IF NOT FOUND OR abandoned.binding->>'previous_delivery_digest' IS DISTINCT FROM substring(delivery.delivery_digest from 8)
  OR NOT EXISTS(SELECT 1 FROM control.runtime_target_disposition_acknowledgement k
   WHERE k.participant_id=pid AND k.privacy_domain_id=privacy AND k.runtime_target_id=target
    AND k.delivery_digest=delivery.delivery_digest AND k.claims->>'installed_state'='ActivationConfirmed')
 THEN RETURN false; END IF;
 SELECT w.* INTO failed FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
  AND w.runtime_target_id=target AND w.configuration_work_id::text=abandoned.binding->'cause'->>'work_id' FOR SHARE NOWAIT;
 IF NOT FOUND OR abandoned.binding->'cause' IS DISTINCT FROM jsonb_build_object('kind','Activation',
  'work_id',failed.configuration_work_id::text,'operation_id',failed.operation_id::text,'execution_attempt_id',NULL)
  OR failed.state IS DISTINCT FROM 'FAILED' OR failed.work_kind IS DISTINCT FROM 'RUNTIME_ACTIVATION'
  OR failed.execution_started_at IS NOT NULL OR failed.execution_attempt_id IS NOT NULL
  OR failed.predecessor_digest IS DISTINCT FROM 'sha256:'||(abandoned.binding->'source'->>'capsule_digest')
  OR failed.configuration_work_id::text=abandoned.binding->'source'->>'original_work_id'
 THEN RETURN false; END IF;
 SELECT g.* INTO generation FROM control.runtime_configuration_generation g
  WHERE g.participant_id=pid AND g.privacy_domain_id=privacy
   AND g.runtime_configuration_generation_id=failed.runtime_configuration_generation_id FOR SHARE NOWAIT;
 IF NOT FOUND THEN RETURN false; END IF;
 payload:=openpc.runtime_generation_retry_failure_payload(generation,failed);
 IF NOT EXISTS(SELECT 1 FROM control.outbox_event e JOIN control.mutation_evidence a
  ON a.participant_id=e.participant_id AND a.privacy_domain_id=e.privacy_domain_id
   AND a.operation_id=failed.operation_id AND a.aggregate_id=target
   AND a.action_intent_id='ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1'
   AND a.catalog_operation_id='CFG-OP-UPDATE-RUNTIME-TARGET'
   AND a.evidence_role='AUTHORIZATION_INPUT' AND a.evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
  JOIN control.idempotency_record i ON i.participant_id=a.participant_id AND i.privacy_domain_id=a.privacy_domain_id
   AND i.operation_id=a.operation_id AND i.input_digest=a.candidate_digest AND i.terminal_state='COMMITTED'
   AND i.result_payload->>'state'='FAILED' AND i.result_payload->>'truthState'='FAILED'
  WHERE e.participant_id=pid AND e.privacy_domain_id=privacy AND e.event_id=failed.result_event_id
   AND e.aggregate_id=target AND e.aggregate_type='runtime-targets' AND e.event_type='runtime-target.activation-failed.v1'
   AND e.payload_cbor=payload AND e.payload_digest=sha256(payload) AND e.cose_sign1=a.cose_sign1
   AND octet_length(a.cose_sign1)>0 AND a.evidence_digest=sha256(a.evidence_cbor))
  OR EXISTS(SELECT 1 FROM control.runtime_activation_observation o
   WHERE o.configuration_work_id=failed.configuration_work_id OR o.runtime_configuration_generation_id=generation.runtime_configuration_generation_id)
  OR EXISTS(SELECT 1 FROM control.policy_activation_occurrence_target o
   WHERE o.configuration_work_id=failed.configuration_work_id OR o.runtime_configuration_generation_id=generation.runtime_configuration_generation_id)
  OR EXISTS(SELECT 1 FROM control.runtime_target_disposition_admission a
   WHERE a.runtime_target_id=target AND (a.binding->'source'->>'original_work_id'=failed.configuration_work_id::text
    OR a.binding->'source'->>'runtime_configuration_generation_id'=generation.runtime_configuration_generation_id::text))
 THEN RETURN false; END IF;
 RETURN true;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'PC-DATA-6007';
END $$;
ALTER FUNCTION openpc.runtime_unsigned_withdrawal_recoverable(uuid,bigint,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.runtime_unsigned_withdrawal_recoverable(uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_unsigned_withdrawal_recoverable(uuid,bigint,text) TO openpc_control_runtime,openpc_control_worker;
`;
