// Content identity remains stable across attempts. Only a proved terminal
// no-execution failure may release it for a separately governed generation.
export const runtimeGenerationRetryGuardsSql = `
-- This typed assertion checks only the supplied terminal-result shape. It
-- neither reads nor grants current execution/admission authority. The trigger
-- below obtains real rows under locks and separately closes all effect/evidence
-- dependencies; detached caller values can never bypass those owners.
CREATE OR REPLACE FUNCTION openpc.runtime_generation_retry_failure_payload(
 prior control.runtime_configuration_generation, work control.configuration_work)
RETURNS bytea LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE payload bytea;
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF prior.runtime_configuration_generation_id IS NULL OR work.configuration_work_id IS NULL
  OR prior.runtime_target_id IS NULL OR prior.generation_digest IS NULL
  OR prior.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR prior.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR prior.state IS DISTINCT FROM 'FAILED' OR prior.activated_at IS NOT NULL OR prior.cigl_profile_selection IS NOT NULL
  OR work.participant_id IS DISTINCT FROM prior.participant_id
  OR work.privacy_domain_id IS DISTINCT FROM prior.privacy_domain_id
  OR work.runtime_configuration_generation_id IS DISTINCT FROM prior.runtime_configuration_generation_id
  OR work.operation_id IS NULL OR work.last_error_code IS NULL
  OR work.state IS DISTINCT FROM 'FAILED' OR work.work_kind IS DISTINCT FROM 'RUNTIME_ACTIVATION'
  OR work.runtime_target_id IS DISTINCT FROM prior.runtime_target_id OR work.resource_id IS DISTINCT FROM prior.runtime_target_id
  OR work.generation_digest IS DISTINCT FROM prior.generation_digest
  OR work.predecessor_digest IS DISTINCT FROM prior.predecessor_digest
  OR work.execution_started_at IS NOT NULL OR work.execution_attempt_id IS NOT NULL
  OR work.lease_owner IS NOT NULL OR work.lease_until IS NOT NULL OR work.reconcile_after IS NOT NULL
  OR work.completed_at IS NULL OR work.result_event_id IS NULL
  OR work.result_receipt IS DISTINCT FROM jsonb_build_object('errorCode',work.last_error_code,
    'resourceId',work.resource_id::text,'terminal',true,'workKind','RUNTIME_ACTIVATION')
 THEN RAISE EXCEPTION 'PC-DATA-6007-RUNTIME-RETRY'; END IF;
 payload:=convert_to(openpc.signing_canonical_json(work.result_receipt),'UTF8');
 IF work.result_receipt_digest IS DISTINCT FROM 'sha256:'||encode(sha256(payload),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007-RUNTIME-RETRY'; END IF;
 RETURN payload;
END $$;
REVOKE ALL ON FUNCTION openpc.runtime_generation_retry_failure_payload(control.runtime_configuration_generation,control.configuration_work) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_generation_retry_failure_payload(control.runtime_configuration_generation,control.configuration_work) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_generation_retry()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE prior control.runtime_configuration_generation; work control.configuration_work;
 target control.runtime_target; payload bytea;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.runtime_configuration_generation g
  WHERE g.runtime_target_id=NEW.runtime_target_id AND g.generation_digest=NEW.generation_digest
   AND g.predecessor_digest IS NOT DISTINCT FROM NEW.predecessor_digest AND g.state='FAILED')
 THEN RETURN NEW; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR openpc.current_action_intent_id() NOT IN
    ('ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1','ACT-POLICY_ACTIVATE_RELEASE-V1')
  OR current_setting('transaction_isolation')<>'serializable'
  OR NEW.state<>'ACTIVATING' OR NEW.revision<>1 OR NEW.activated_at IS NOT NULL
  OR NEW.cigl_profile_selection IS NOT NULL
 THEN RAISE EXCEPTION 'PC-DATA-6007-RUNTIME-RETRY'; END IF;
 -- Reentrant with the shared BEFORE STATEMENT reference fence. Never reverse-wait.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='PC-DATA-6007'; END IF;
 SELECT * INTO STRICT target FROM control.runtime_target t
  WHERE t.participant_id=NEW.participant_id AND t.privacy_domain_id=NEW.privacy_domain_id
   AND t.runtime_target_id=NEW.runtime_target_id FOR UPDATE NOWAIT;
 -- Public activation still checks current discovery and expected revision;
 -- this guard only proves the old attempt cannot have dispatched an effect.
 IF target.state<>'FAILED' OR openpc.runtime_installed_predecessor(target.runtime_target_id) IS DISTINCT FROM NEW.predecessor_digest
 THEN RAISE EXCEPTION 'PC-DATA-6007-RUNTIME-RETRY'; END IF;
 IF openpc.current_action_intent_id()='ACT-POLICY_ACTIVATE_RELEASE-V1' AND
  (NEW.policy_generation_digest IS NULL OR NOT EXISTS (
    SELECT 1 FROM control.policy_activation_occurrence occurrence
    JOIN control.policy_activation_occurrence_target cohort
      ON cohort.activation_occurrence_id=occurrence.activation_occurrence_id
     AND cohort.participant_id=occurrence.participant_id
     AND cohort.privacy_domain_id=occurrence.privacy_domain_id
    WHERE occurrence.participant_id=NEW.participant_id
      AND occurrence.privacy_domain_id=NEW.privacy_domain_id
      AND occurrence.state='REQUESTED'
      AND cohort.runtime_target_id=NEW.runtime_target_id
      AND cohort.phase='FORWARD' AND cohort.state='REQUESTED'
      AND cohort.configuration_work_id IS NULL
      AND cohort.expected_target_revision=target.revision
      AND cohort.expected_predecessor_digest IS NOT DISTINCT FROM target.active_generation_digest
      AND NEW.policy_generation_digest='sha256:'||encode(occurrence.target_generation_digest,'hex')
  )) THEN RAISE EXCEPTION 'PC-DATA-6007-RUNTIME-RETRY'; END IF;
 FOR prior IN SELECT g.* FROM control.runtime_configuration_generation g
  WHERE g.runtime_target_id=NEW.runtime_target_id AND g.generation_digest=NEW.generation_digest
   AND g.predecessor_digest IS NOT DISTINCT FROM NEW.predecessor_digest
  ORDER BY g.runtime_configuration_generation_id FOR SHARE NOWAIT
 LOOP
  IF prior.participant_id<>NEW.participant_id OR prior.privacy_domain_id<>NEW.privacy_domain_id
   OR prior.state<>'FAILED' OR prior.activated_at IS NOT NULL OR prior.cigl_profile_selection IS NOT NULL
  THEN RAISE EXCEPTION 'PC-DATA-6007-RUNTIME-RETRY'; END IF;
  SELECT * INTO STRICT work FROM control.configuration_work w
   WHERE w.participant_id=prior.participant_id AND w.privacy_domain_id=prior.privacy_domain_id
    AND w.runtime_configuration_generation_id=prior.runtime_configuration_generation_id FOR SHARE NOWAIT;
  payload:=openpc.runtime_generation_retry_failure_payload(prior,work);
  -- This is the existing configuration-result owner's canonical failure payload
  -- bound to its original committed authorization signature, not a new signature
  -- over a fabricated result or a new permission to execute.
  IF (NOT EXISTS(SELECT 1 FROM control.outbox_event e JOIN control.mutation_evidence a
    ON a.participant_id=e.participant_id AND a.privacy_domain_id=e.privacy_domain_id
     AND a.operation_id=work.operation_id AND a.aggregate_id=work.resource_id
     AND a.action_intent_id='ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1'
     AND a.catalog_operation_id='CFG-OP-UPDATE-RUNTIME-TARGET'
    JOIN control.idempotency_record i ON i.participant_id=a.participant_id AND i.privacy_domain_id=a.privacy_domain_id
     AND i.operation_id=a.operation_id AND i.input_digest=a.candidate_digest
     AND i.terminal_state='COMMITTED' AND i.result_payload->>'state'='FAILED'
     AND i.result_payload->>'truthState'='FAILED'
    WHERE e.participant_id=work.participant_id AND e.privacy_domain_id=work.privacy_domain_id
     AND e.event_id=work.result_event_id AND e.aggregate_id=work.resource_id
     AND e.aggregate_type='runtime-targets' AND e.event_type='runtime-target.activation-failed.v1'
     AND e.payload_cbor=payload AND e.payload_digest=sha256(payload)
     AND e.cose_sign1=a.cose_sign1 AND octet_length(a.cose_sign1)>0
     AND a.evidence_digest=sha256(a.evidence_cbor))
   AND NOT EXISTS(SELECT 1 FROM control.outbox_event e
    JOIN control.idempotency_record i
      ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id
     AND i.operation_id=work.operation_id AND i.terminal_state='COMMITTED'
     AND i.result_payload->>'state'='FAILED' AND i.result_payload->>'truthState'='FAILED'
    JOIN control.policy_activation_occurrence_target cohort
      ON cohort.configuration_work_id=work.configuration_work_id
     AND cohort.runtime_configuration_generation_id=prior.runtime_configuration_generation_id
     AND cohort.participant_id=work.participant_id AND cohort.privacy_domain_id=work.privacy_domain_id
     AND cohort.phase='FORWARD' AND cohort.state='FAILED'
    JOIN control.policy_activation_occurrence occurrence
      ON occurrence.activation_occurrence_id=cohort.activation_occurrence_id
     AND occurrence.participant_id=cohort.participant_id
     AND occurrence.privacy_domain_id=cohort.privacy_domain_id
     AND occurrence.state='FAILED'
    JOIN control.policy_activation activation
      ON activation.policy_activation_id=occurrence.activation_occurrence_id
     AND activation.participant_id=occurrence.participant_id
     AND activation.privacy_domain_id=occurrence.privacy_domain_id
     AND activation.state='FAILED_FENCED' AND activation.activated_at IS NULL
     AND activation.webauthn_assertion_binding_digest IS NOT NULL
    WHERE openpc.current_action_intent_id()='ACT-POLICY_ACTIVATE_RELEASE-V1'
      AND e.participant_id=work.participant_id AND e.privacy_domain_id=work.privacy_domain_id
      AND e.event_id=work.result_event_id AND e.aggregate_id=work.resource_id
      AND e.aggregate_type='runtime-targets' AND e.event_type='runtime-target.activation-failed.v1'
      AND e.payload_cbor=payload AND e.payload_digest=sha256(payload)
      AND octet_length(e.cose_sign1)>0))
   OR EXISTS(SELECT 1 FROM control.runtime_activation_observation o
    WHERE o.runtime_configuration_generation_id=prior.runtime_configuration_generation_id
     OR o.configuration_work_id=work.configuration_work_id)
   OR EXISTS(SELECT 1 FROM control.policy_activation_occurrence_target o
    LEFT JOIN control.policy_activation_occurrence occurrence
      ON occurrence.activation_occurrence_id=o.activation_occurrence_id
     AND occurrence.participant_id=o.participant_id
     AND occurrence.privacy_domain_id=o.privacy_domain_id
    WHERE (o.runtime_configuration_generation_id=prior.runtime_configuration_generation_id
       OR o.configuration_work_id=work.configuration_work_id)
      AND (o.phase<>'FORWARD' OR o.state<>'FAILED' OR occurrence.state IS DISTINCT FROM 'FAILED'))
   OR EXISTS(SELECT 1 FROM control.runtime_target_disposition_admission a
    WHERE a.runtime_target_id=prior.runtime_target_id AND (
     a.binding->'source'->>'original_work_id'=work.configuration_work_id::text
     OR a.binding->'source'->>'runtime_configuration_generation_id'=prior.runtime_configuration_generation_id::text
     OR (a.binding->'cause'->>'work_id'=work.configuration_work_id::text AND (
       -- The failed successor did not run. Its acknowledged withdrawal denied
       -- the predecessor, not this content generation. A fresh governed attempt
       -- keeps that denial and must issue/ACK its own handoff and activation.
       a.participant_id=prior.participant_id AND a.privacy_domain_id=prior.privacy_domain_id
       AND a.binding->>'action'='Withdraw' AND a.activation_proof IS NULL AND a.restoration_proof IS NULL
       AND a.binding->'cause'=jsonb_build_object('kind','Activation',
         'work_id',work.configuration_work_id::text,'operation_id',work.operation_id::text,'execution_attempt_id',NULL)
       AND a.binding->'source'->>'capsule_digest'=substring(NEW.predecessor_digest from 8)
       AND a.revision=(SELECT max(head.revision) FROM control.runtime_target_disposition_admission head
         WHERE head.participant_id=a.participant_id AND head.privacy_domain_id=a.privacy_domain_id
          AND head.runtime_target_id=a.runtime_target_id)
       AND EXISTS(SELECT 1 FROM control.runtime_activation_observation original
         WHERE original.participant_id=a.participant_id AND original.privacy_domain_id=a.privacy_domain_id
          AND original.runtime_target_id=a.runtime_target_id AND original.capsule_digest=NEW.predecessor_digest
          AND original.configuration_work_id::text=a.binding->'source'->>'original_work_id'
          AND original.runtime_configuration_generation_id::text=a.binding->'source'->>'runtime_configuration_generation_id'
          AND original.configuration_work_id<>work.configuration_work_id
          AND original.runtime_configuration_generation_id<>prior.runtime_configuration_generation_id)
       AND (openpc.runtime_unsigned_withdrawal_recoverable(a.runtime_target_id,a.revision::bigint,a.admission_digest)
        OR EXISTS(SELECT 1 FROM control.runtime_target_disposition_delivery delivery
         JOIN control.runtime_target_disposition_acknowledgement acknowledgement
          ON acknowledgement.participant_id=delivery.participant_id AND acknowledgement.privacy_domain_id=delivery.privacy_domain_id
           AND acknowledgement.runtime_target_id=delivery.runtime_target_id AND acknowledgement.delivery_digest=delivery.delivery_digest
         WHERE delivery.participant_id=a.participant_id AND delivery.privacy_domain_id=a.privacy_domain_id
          AND delivery.runtime_target_id=a.runtime_target_id AND delivery.revision=a.revision
          AND acknowledgement.claims->>'installed_state'='NewUseDenied'))
     ) IS NOT TRUE)))
  THEN RAISE EXCEPTION 'PC-DATA-6007-RUNTIME-RETRY'; END IF;
 END LOOP;
 RETURN NEW;
EXCEPTION WHEN lock_not_available THEN
 RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='PC-DATA-6007';
END $$;
REVOKE ALL ON FUNCTION openpc.guard_runtime_generation_retry() FROM PUBLIC;
DROP TRIGGER IF EXISTS runtime_generation_retry_guard ON control.runtime_configuration_generation;
CREATE TRIGGER runtime_generation_retry_guard BEFORE INSERT ON control.runtime_configuration_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_generation_retry();
`;
