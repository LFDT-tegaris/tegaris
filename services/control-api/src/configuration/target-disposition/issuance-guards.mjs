/** Revalidate one already committed admission. This owner never INSERTs an
 * admission, mints a permit, changes its proof or supplies signing authority. */
export const targetDispositionIssuanceSql = `
CREATE OR REPLACE FUNCTION openpc.lock_runtime_target_disposition_issuance(
 target uuid,wanted_revision bigint,wanted_digest text,worker text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE pid uuid; privacy uuid; head control.runtime_target_disposition_admission; latest text;
 original control.configuration_work; cause control.configuration_work; current_target control.runtime_target;
 authority record; principal uuid; proof jsonb; action text;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR current_setting('transaction_isolation')<>'read committed' OR target IS NULL
  OR wanted_revision IS NULL OR wanted_revision<1 OR wanted_digest IS NULL
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ISSUANCE-CONTEXT'; END IF;
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 SELECT * INTO STRICT head FROM control.runtime_target_disposition_admission a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target
  ORDER BY a.revision DESC LIMIT 1;
 IF head.revision IS DISTINCT FROM wanted_revision OR head.admission_digest IS DISTINCT FROM wanted_digest
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ISSUANCE-HEAD'; END IF;
 action:=head.binding->>'action';
 IF action IN ('ConfirmActivation','Restore') THEN
  PERFORM 1 FROM control.platform_context root JOIN control.platform_scope_replacement replacement
    ON replacement.platform_context_id=root.platform_context_id
    WHERE replacement.participant_id=pid AND replacement.privacy_domain_id=privacy AND replacement.state='WITHDRAWING'
    FOR SHARE OF root;
  IF FOUND THEN RAISE EXCEPTION 'TARGET-DISPOSITION-PLATFORM-WITHDRAWING'; END IF;
  IF worker IS NOT NULL THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ISSUANCE-CONTEXT'; END IF;
  proof:=CASE action WHEN 'ConfirmActivation' THEN head.activation_proof ELSE head.restoration_proof END;
  PERFORM openpc.lock_runtime_target_current_sources(target,head.binding->'source',proof,
   CASE action WHEN 'ConfirmActivation' THEN 'CONFIRM' ELSE 'RESTORE' END);
 ELSIF action='Withdraw' THEN
  IF coalesce(worker,'')='' THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ISSUANCE-CONTEXT'; END IF;
  IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||pid::text||':'||privacy::text,0))
   OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||pid::text||':'||privacy::text,0))
   OR NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||pid::text,0))
   OR NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||pid::text||':'||privacy::text||':'||target::text,0))
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSE RAISE EXCEPTION 'TARGET-DISPOSITION-ISSUANCE-ACTION'; END IF;
 -- Re-read only after the original Control fences have been reacquired.
 SELECT admission_digest INTO STRICT latest FROM control.runtime_target_disposition_admission a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target
  ORDER BY a.revision DESC LIMIT 1;
 IF latest IS DISTINCT FROM wanted_digest THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ISSUANCE-HEAD'; END IF;
 SELECT * INTO STRICT authority FROM openpc.lock_runtime_discovery_authority(target,
  'sha256:'||(head.binding->'target'->>'certificate_digest'));
 SELECT c.principal_id INTO STRICT principal FROM control.credential c
  WHERE c.participant_id=pid AND c.credential_id=authority.credential_id;
 IF head.binding->'target' IS DISTINCT FROM jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,
  'target_id',target::text,'credential_id',authority.credential_id::text,'principal_id',principal::text,
  'credential_epoch',authority.credential_epoch,'principal_epoch',authority.principal_epoch,
  'certificate_digest',head.binding->'target'->>'certificate_digest')
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-IDENTITY'; END IF;
 SELECT * INTO STRICT original FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
  AND w.runtime_target_id=target AND w.configuration_work_id=(head.binding->'source'->>'original_work_id')::uuid FOR SHARE NOWAIT;
 SELECT * INTO STRICT current_target FROM control.runtime_target t WHERE t.participant_id=pid AND t.privacy_domain_id=privacy
  AND t.runtime_target_id=target FOR SHARE NOWAIT;
 IF action='ConfirmActivation' THEN
  IF NOT coalesce(((original.state='COMPLETED' AND current_target.active_generation_digest='sha256:'||(proof->>'capsuleDigest'))
   OR (original.state IN ('LEASED','RECONCILING') AND openpc.runtime_work_predecessor_matches(original.configuration_work_id)
    AND current_target.desired_generation_digest=original.generation_digest)),false)
   OR head.binding->'cause' IS DISTINCT FROM jsonb_build_object('kind','Activation','work_id',original.configuration_work_id::text,
    'operation_id',original.operation_id::text,'execution_attempt_id',original.execution_attempt_id::text)
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACTIVATION-TARGET'; END IF;
 ELSIF action='Withdraw' AND (openpc.expired_denial_issuance_matches(target,wanted_revision,head.admission_digest,worker)
  OR openpc.expired_handover_issuance_matches(target,wanted_revision,head.admission_digest,worker)
  OR openpc.expired_credential_handover_issuance_matches(target,wanted_revision,head.admission_digest,worker)) THEN
  -- The separate native proof admits this exact negative source only.
  RETURN;
 ELSIF action='Withdraw' AND head.binding->'cause'->>'kind'='Dependency'
   AND head.binding->'cause'->>'owner'='Platform' THEN
  IF original.state<>'COMPLETED' OR original.work_kind<>'RUNTIME_ACTIVATION'
    OR original.operation_id::text IS DISTINCT FROM head.binding->'source'->>'original_operation_id'
    OR original.execution_attempt_id::text IS DISTINCT FROM head.binding->'source'->>'original_execution_attempt_id'
    OR current_target.active_generation_digest IS DISTINCT FROM 'sha256:'||(head.binding->'source'->>'capsule_digest')
    OR NOT EXISTS(SELECT 1 FROM control.platform_scope_target_withdrawal q
      JOIN control.platform_scope_replacement r ON r.replacement_id=q.replacement_id
        AND r.participant_id=q.participant_id AND r.privacy_domain_id=q.privacy_domain_id
      JOIN control.platform_context p ON p.platform_context_id=r.platform_context_id
        AND p.owner_participant_id=r.participant_id AND p.authority_epoch=r.predecessor_epoch
        AND p.row_version=r.expected_root_revision AND p.state='ACTIVE'
      WHERE q.participant_id=pid AND q.privacy_domain_id=privacy AND q.runtime_target_id=target
        AND q.replacement_id::text=head.binding->'cause'->>'resource_id'
        AND r.state='WITHDRAWING' AND r.row_version=1
        AND head.binding->'cause'=jsonb_build_object('kind','Dependency','owner','Platform',
          'resource_id',r.replacement_id::text,'operation_id',r.prepare_operation_id::text,'revision',1)
        AND q.source->>'originalWorkId'=original.configuration_work_id::text
        AND q.source->>'originalAttemptId'=original.execution_attempt_id::text
        AND q.source->>'capsuleDigest'=current_target.active_generation_digest
        AND q.source->>'activationReceiptDigest'=original.result_receipt_digest)
    OR EXISTS(SELECT 1 FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
      AND w.runtime_target_id=target AND w.work_kind='RUNTIME_ACTIVATION' AND w.state IN('PENDING','LEASED','RECONCILING'))
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CAUSE-UNAVAILABLE'; END IF;
 ELSE
  IF head.binding->'cause'->>'kind'='UnsignedWithdrawalRecovery' AND (
   action IS DISTINCT FROM 'Withdraw'
   OR head.revision IS DISTINCT FROM (head.binding->'cause'->>'abandoned_revision')::bigint+1
   OR head.binding->'previous_revision' IS DISTINCT FROM to_jsonb(head.revision-2)
   OR NOT openpc.runtime_unsigned_withdrawal_recoverable(target,(head.revision-1)::bigint,
    'sha256:'||(head.binding->'cause'->>'abandoned_admission_digest')))
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-RECOVERY-BINDING'; END IF;
  SELECT * INTO STRICT cause FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
   AND w.runtime_target_id=target AND w.configuration_work_id=(head.binding->'cause'->>'work_id')::uuid FOR SHARE NOWAIT;
  IF cause.work_kind<>'RUNTIME_ACTIVATION' OR cause.execution_started_at IS NOT NULL OR cause.execution_attempt_id IS NOT NULL
   OR cause.operation_id::text IS DISTINCT FROM head.binding->'cause'->>'operation_id'
   OR (head.binding->'cause'->>'kind' IN ('Activation','UnsignedWithdrawalRecovery')) IS NOT TRUE
   OR (CASE WHEN head.binding->'cause'->>'kind'='UnsignedWithdrawalRecovery'
    THEN head.binding->'cause' ? 'execution_attempt_id'
    ELSE head.binding->'cause'->'execution_attempt_id' IS DISTINCT FROM 'null'::jsonb END)
   OR (original.state<>'COMPLETED' AND NOT coalesce((action='Withdraw' AND cause.denied_predecessor_work_id=original.configuration_work_id
    AND original.state='FAILED' AND original.result_receipt->>'outcome'='EXPIRED_OBSERVED_DENIED'
    AND openpc.runtime_work_predecessor_matches(cause.configuration_work_id)),false)) OR original.work_kind<>'RUNTIME_ACTIVATION'
   OR original.operation_id::text IS DISTINCT FROM head.binding->'source'->>'original_operation_id'
   OR original.execution_attempt_id::text IS DISTINCT FROM head.binding->'source'->>'original_execution_attempt_id'
   OR (current_target.active_generation_digest IS DISTINCT FROM 'sha256:'||(head.binding->'source'->>'capsule_digest') AND NOT coalesce((action='Withdraw' AND cause.denied_predecessor_work_id=original.configuration_work_id
    AND original.state='FAILED' AND original.result_receipt->>'outcome'='EXPIRED_OBSERVED_DENIED'
    AND openpc.runtime_work_predecessor_matches(cause.configuration_work_id)),false))
   OR current_target.desired_generation_digest IS DISTINCT FROM cause.generation_digest
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ISSUANCE-CAUSE'; END IF;
  IF action='Restore' THEN
   IF cause.state<>'FAILED' OR cause.completed_at IS NULL OR current_target.state<>'FAILED'
    OR EXISTS(SELECT 1 FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
     AND w.runtime_target_id=target AND w.work_kind='RUNTIME_ACTIVATION' AND w.state IN ('PENDING','LEASED','RECONCILING'))
   THEN RAISE EXCEPTION 'TARGET-DISPOSITION-RESTORE-CAUSE'; END IF;
  ELSIF cause.state<>'LEASED' OR cause.lease_owner IS DISTINCT FROM worker OR cause.lease_until<=clock_timestamp()
   OR NOT openpc.runtime_work_predecessor_matches(cause.configuration_work_id) OR current_target.state<>'STAGING'
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CAUSE-UNAVAILABLE'; END IF;
 END IF;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'PC-DATA-6007';
END $$;
ALTER FUNCTION openpc.lock_runtime_target_disposition_issuance(uuid,bigint,text,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.lock_runtime_target_disposition_issuance(uuid,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_runtime_target_disposition_issuance(uuid,bigint,text,text) TO openpc_control_worker;
`;
