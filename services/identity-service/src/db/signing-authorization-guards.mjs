import { authoritySnapshotColumns } from './authority-snapshot-columns.ts';
const keys = Object.keys(authoritySnapshotColumns).sort();
const dependencies = keys
  .map((table) => {
    const columns = authoritySnapshotColumns[table];
    return `
 SELECT coalesce(jsonb_agg(jsonb_build_object(${columns.map((c) => `'${c}',owner.${c}::text`).join(',')}) ORDER BY owner.${columns[0]}),'[]'::jsonb)
 INTO expected FROM control.${table} owner WHERE owner.participant_id=NEW.participant_id
  AND owner.${columns[0]} IN(SELECT (d->>'${columns[0]}')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'${table}') d);
 IF snapshot->'dependencies'->'${table}' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-ACTUAL-ROW'; END IF;`;
  })
  .join('\n');
export const signingAuthorizationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_signing_command_authorization()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE snapshot jsonb; bound jsonb; expected jsonb; rotation control.signing_key_rotation%ROWTYPE;
 evidence control.mutation_evidence%ROWTYPE; runtime_payload jsonb; approval control.approval_request%ROWTYPE;
 checker control.approval_decision_record%ROWTYPE; now_ns numeric;
 generation control.signing_authorization_generation%ROWTYPE; effects jsonb;
BEGIN
 snapshot:=convert_from(NEW.authorization_snapshot,'UTF8')::jsonb;
 now_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND revision=NEW.from_revision;
 effects:=openpc.signing_transition_effects(NEW.action_intent_id,rotation.state,NEW.to_state);
 IF effects IS NULL OR (effects->>'resumeFrom' IS NOT NULL AND effects->>'resumeFrom' IS DISTINCT FROM rotation.recovery_from_state)
 THEN RAISE EXCEPTION 'DATA-6022-SIGNING-COMMAND-MATRIX'; END IF;
 IF NEW.authorization_generation_id IS NULL THEN
  SELECT generation_id INTO NEW.authorization_generation_id FROM control.signing_authorization_generation
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id
    AND state='CONSUMED' ORDER BY result_revision DESC LIMIT 1;
 END IF;
 IF NEW.authorization_generation_id IS NULL THEN
  NEW.approval_request_id:=rotation.approval_request_id;
  NEW.approval_candidate_digest:=rotation.candidate_digest;
 ELSE
  SELECT * INTO STRICT generation FROM control.signing_authorization_generation WHERE generation_id=NEW.authorization_generation_id
   AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id;
  IF generation.state='STAGED' THEN
   IF generation.action_intent_id<>NEW.action_intent_id OR generation.from_revision<>NEW.from_revision OR generation.input_digest<>NEW.input_digest
    OR generation.target_state<>NEW.to_state OR NOT EXISTS(SELECT 1 FROM control.mutation_candidate candidate
     WHERE candidate.mutation_candidate_id=generation.candidate_id AND candidate.state='APPROVED'
      AND candidate.candidate_document->'context'=openpc.signing_governance_context(NEW.rotation_id,NEW.action_intent_id))
   THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GOVERNANCE-STALE'; END IF;
  ELSIF generation.generation_id IS DISTINCT FROM (SELECT generation_id FROM control.signing_authorization_generation
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id
    AND state='CONSUMED' ORDER BY result_revision DESC LIMIT 1)
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GENERATION-STALE'; END IF;
  SELECT a.approval_request_id,a.subject_digest INTO STRICT NEW.approval_request_id,NEW.approval_candidate_digest
   FROM control.approval_request a WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id
    AND a.subject_id=generation.candidate_id AND a.subject_digest=generation.candidate_digest
    AND a.state='APPROVED' AND a.expires_at>clock_timestamp();
 END IF;
 IF NEW.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND generation.state='STAGED' THEN
  IF NEW.original_operation_id IS DISTINCT FROM generation.original_operation_id
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-GOVERNANCE-ORIGINAL'; END IF;
 ELSIF NEW.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' THEN
  IF NEW.to_state<>'RECOVERING' OR NOT EXISTS(SELECT 1 FROM control.signing_rotation_command original
   JOIN control.signing_provider_attempt attempt ON attempt.operation_id=original.operation_id
    AND attempt.participant_id=original.participant_id AND attempt.privacy_domain_id=original.privacy_domain_id
   JOIN LATERAL (SELECT o.observation_digest FROM control.signing_rotation_observation o
    WHERE o.participant_id=attempt.participant_id AND o.privacy_domain_id=attempt.privacy_domain_id AND o.attempt_id=attempt.attempt_id
    ORDER BY o.observed_at_ns DESC,o.observation_id DESC LIMIT 1) prior ON true
   WHERE original.participant_id=NEW.participant_id AND original.privacy_domain_id=NEW.privacy_domain_id
    AND original.rotation_id=NEW.rotation_id AND original.operation_id=NEW.original_operation_id
    AND original.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' AND original.state='WRITE_AMBIGUITY'
    AND attempt.attempt_id=NEW.recovery_attempt_id AND attempt.state IN ('DISPATCHING','OBSERVED')
    AND prior.observation_digest=NEW.prior_observation_digest)
  THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-EXACT-PENDING-ATTEMPT'; END IF;
 ELSE
  IF generation.state IS DISTINCT FROM 'STAGED' AND EXISTS(SELECT 1 FROM control.signing_rotation_command denied WHERE denied.participant_id=NEW.participant_id
   AND denied.privacy_domain_id=NEW.privacy_domain_id AND denied.rotation_id=NEW.rotation_id AND denied.from_revision=NEW.from_revision
   AND denied.state='FAILED' AND denied.result_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH')
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-FRESH-APPROVAL-REQUIRED'; END IF;
  IF EXISTS(SELECT 1 FROM control.signing_rotation_authority_hold h WHERE h.participant_id=NEW.participant_id
   AND h.privacy_domain_id=NEW.privacy_domain_id AND h.rotation_id=NEW.rotation_id AND h.state='ACTIVE')
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-AUTHORITY-HOLD'; END IF;
  IF NOT openpc.signing_admission_open(NEW.participant_id,NEW.privacy_domain_id,rotation.old_signer_id,NEW.operation_id)
   OR NOT openpc.signing_admission_open(NEW.participant_id,NEW.privacy_domain_id,rotation.new_signer_id,NEW.operation_id)
  THEN RAISE EXCEPTION 'DATA-6021-SIGNING-UNRESOLVED-ADMISSION'; END IF;
 END IF;
 SELECT * INTO STRICT evidence FROM control.mutation_evidence WHERE mutation_evidence_id=NEW.authorization_evidence_id
  AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id
  AND principal_id=NEW.principal_id AND action_intent_id=NEW.action_intent_id AND candidate_digest=NEW.input_digest
  AND aggregate_type='signing-key-rotation' AND aggregate_id=NEW.rotation_id AND aggregate_version=NEW.from_revision
  AND evidence_role='AUTHORIZATION_INPUT' AND evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
  AND evidence_digest=sha256(evidence_cbor);
 IF NEW.action_intent_id NOT IN ('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1')
  OR openpc.current_action_intent_id() IS DISTINCT FROM NEW.action_intent_id
  OR openpc.current_operation_id() IS DISTINCT FROM NEW.operation_id
  OR evidence.catalog_operation_id IS DISTINCT FROM (CASE NEW.action_intent_id
   WHEN 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' THEN 'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION'
   ELSE 'OPS-OP-RECOVER-SIGNING-KEY-ROTATION' END) THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORIZATION-ACTION'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=NEW.participant_id
  AND i.privacy_domain_id=NEW.privacy_domain_id AND i.operation_id=NEW.operation_id AND i.principal_id=NEW.principal_id
  AND i.idempotency_key=NEW.idempotency_key AND i.input_digest=NEW.input_digest AND i.expected_aggregate_version=NEW.from_revision
  AND i.catalog_operation_id=evidence.catalog_operation_id AND i.action_intent_id=NEW.action_intent_id AND i.terminal_state IS NULL)
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-IDEMPOTENCY-AUTHORIZATION'; END IF;
 IF (effects->>'revoke')::boolean AND NOT EXISTS(
  SELECT 1 FROM control.qualified_receipt_inbox i JOIN control.audit_occurrence a
   ON a.participant_id=i.participant_id AND a.privacy_domain_id=i.privacy_domain_id AND a.receipt_id=i.receipt_id
  JOIN control.business_signing_grant g ON g.participant_id=a.participant_id AND g.privacy_domain_id=a.privacy_domain_id
   AND g.signer_id=a.signer_id AND g.profile_digest=a.profile_digest
  WHERE i.participant_id=NEW.participant_id AND i.privacy_domain_id=NEW.privacy_domain_id AND i.receipt_id=NEW.consumer_receipt_id
   AND i.signer_id=rotation.new_signer_id AND a.signer_id=rotation.new_signer_id
   AND a.environment_id=rotation.environment_id AND a.recorded_at_ns>=rotation.cutover_at_ns
   AND ((rotation.request->>'signerRole'='BUSINESS_EFFECT' AND i.namespace='CONTROL_BUSINESS_TRANSITION_V1' AND a.aggregate_type IN ('indexer-profile','evidence-hold','retention-policy','evidence-deletion','store-retirement','runtime-artifact-disposition','work-item','notification','notification-endpoint','workload-renewal-policy')) OR
    (rotation.request->>'signerRole'='LIFECYCLE_EVIDENCE' AND i.namespace='CONTROL_SIGNING_LIFECYCLE_V1'
      AND a.aggregate_type='signing-key-rotation' AND a.aggregate_id=NEW.rotation_id
      AND openpc.business_cbor(a.after_state_preimage)->8->>'0'='OBSERVING')))
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-REVOKE-REQUIRES-CONSUMER'; END IF;
 IF snapshot IS DISTINCT FROM jsonb_build_object('schema','pc.control.precommit-authority-snapshot.v1',
  'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'operationId',NEW.operation_id::text,
  'recordedAtNs',snapshot->'recordedAtNs','decision','ALLOW','authorities',snapshot->'authorities','dependencies',snapshot->'dependencies')
  OR jsonb_typeof(snapshot->'authorities') IS DISTINCT FROM 'array' OR jsonb_array_length(snapshot->'authorities')<>3
  OR jsonb_typeof(snapshot->'recordedAtNs') IS DISTINCT FROM 'string'
  OR NOT ((snapshot->>'recordedAtNs') ~ '^[0-9]{1,20}$') OR (snapshot->>'recordedAtNs')::numeric>now_ns
  OR snapshot->'dependencies' IS DISTINCT FROM jsonb_build_object(${keys.map((k) => `'${k}',snapshot->'dependencies'->'${k}'`).join(',')})
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORIZATION-SNAPSHOT'; END IF;
${dependencies}
 runtime_payload:=openpc.business_cbor(evidence.evidence_cbor);
 IF jsonb_typeof(runtime_payload->'8') IS DISTINCT FROM 'number' OR jsonb_typeof(runtime_payload->'9') IS DISTINCT FROM 'number' OR
    (runtime_payload->>'8')::numeric>(snapshot->>'recordedAtNs')::numeric OR
    (runtime_payload->>'9')::numeric<=now_ns THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORIZATION-EXPIRED'; END IF;
 bound:=snapshot->'authorities'->0;
 IF bound->>'principalId' IS DISTINCT FROM NEW.principal_id::text OR bound->>'actionIntentId' IS DISTINCT FROM NEW.action_intent_id
  OR bound->>'resourceId' IS DISTINCT FROM NEW.rotation_id::text OR bound->>'assignmentId' IS DISTINCT FROM evidence.bound_assignment_id::text
  OR bound->>'authorityEnvelopeId' IS DISTINCT FROM evidence.bound_authority_envelope_id::text
  OR bound->>'authorityEpoch' IS DISTINCT FROM evidence.bound_envelope_epoch::text
  OR bound->>'principalEpoch' IS DISTINCT FROM evidence.bound_principal_epoch::text
  OR bound->>'participantEpoch' IS DISTINCT FROM evidence.bound_participant_epoch::text
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-CALLER-AUTHORIZATION'; END IF;
 SELECT * INTO STRICT approval FROM control.approval_request WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND approval_request_id=NEW.approval_request_id AND state='APPROVED' AND expires_at>clock_timestamp();
 SELECT jsonb_object_agg(key,value) INTO expected FROM jsonb_each(approval.maker_authority)
  WHERE key=ANY(ARRAY['principalId','sessionId','sessionEpoch','participantEpoch','principalEpoch','assignmentId','assignmentRowVersion',
   'authorityEnvelopeId','authorityEpoch','delegationEpoch','privacyDomainId','actionIntentId','resourceId']);
 IF snapshot->'authorities'->1 IS DISTINCT FROM expected OR
  (approval.maker_authority ? 'participantId' AND approval.maker_authority->>'participantId' IS DISTINCT FROM NEW.participant_id::text)
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-MAKER-AUTHORIZATION'; END IF;
 SELECT * INTO STRICT checker FROM control.approval_decision_record WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND approval_request_id=approval.approval_request_id AND decision='APPROVE'
  AND approver_principal_id<>approval.maker_principal_id AND candidate_digest=NEW.approval_candidate_digest;
 IF snapshot->'authorities'->2 IS DISTINCT FROM jsonb_build_object('principalId',checker.approver_principal_id::text,
  'sessionId',checker.approver_session_id::text,'sessionEpoch',checker.approver_session_epoch::text,
  'participantEpoch',checker.approver_participant_epoch::text,'principalEpoch',checker.approver_principal_epoch::text,
  'assignmentId',checker.approver_assignment_id::text,'assignmentRowVersion',checker.approver_assignment_row_version::text,
  'authorityEnvelopeId',checker.approver_authority_envelope_id::text,'authorityEpoch',checker.approver_envelope_epoch::text,
  'delegationEpoch',checker.approver_delegation_epoch::text,'privacyDomainId',NEW.privacy_domain_id::text,
  'actionIntentId','ACT-POLICY_APPROVE_REQUEST-V1','resourceId',approval.approval_request_id::text)
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-CHECKER-AUTHORIZATION'; END IF;
 FOR bound IN SELECT * FROM jsonb_array_elements(snapshot->'authorities') LOOP
  IF bound->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text OR
    NOT (snapshot->'dependencies'->'participant' @> jsonb_build_array(jsonb_build_object('participant_id',NEW.participant_id::text,'state','ACTIVE','authority_epoch',bound->>'participantEpoch'))) OR
    NOT (snapshot->'dependencies'->'privacy_domain' @> jsonb_build_array(jsonb_build_object('privacy_domain_id',NEW.privacy_domain_id::text,'state','ACTIVE'))) OR
    NOT (snapshot->'dependencies'->'principal' @> jsonb_build_array(jsonb_build_object('principal_id',bound->>'principalId','state','ACTIVE','authority_epoch',bound->>'principalEpoch'))) OR
    NOT (snapshot->'dependencies'->'session' @> jsonb_build_array(jsonb_build_object('session_id',bound->>'sessionId','principal_id',bound->>'principalId','state','ACTIVE','session_epoch',bound->>'sessionEpoch'))) OR
    NOT (snapshot->'dependencies'->'assignment' @> jsonb_build_array(jsonb_build_object('assignment_id',bound->>'assignmentId','state','ACTIVE','row_version',bound->>'assignmentRowVersion'))) OR
    NOT (snapshot->'dependencies'->'authority_envelope' @> jsonb_build_array(jsonb_build_object('authority_envelope_id',bound->>'authorityEnvelopeId','state','ACTIVE','authority_epoch',bound->>'authorityEpoch')))
   THEN RAISE EXCEPTION 'DATA-6021-ROTATION-AUTHORITY-LIVE-PATH'; END IF;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_command_authorization BEFORE INSERT ON control.signing_rotation_command
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_command_authorization();
`;
