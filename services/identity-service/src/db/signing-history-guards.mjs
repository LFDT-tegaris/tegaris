/** Generated with the control schema. History records are product audit data, never process ledgers. */
export const signingHistoryGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.rotation_history_preimage(
 p_rotation control.signing_key_rotation,p_prior_state text,p_operation uuid,p_event uuid,p_receipt uuid,p_evidence uuid,
 p_attester jsonb DEFAULT NULL,p_receipt_ordinal numeric DEFAULT NULL)
RETURNS bytea LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE prior bytea; candidate jsonb; approval jsonb; attempts jsonb; selections jsonb; acknowledgements jsonb; command jsonb; retained_selections jsonb; effects jsonb;
BEGIN
 IF p_receipt IS NOT NULL AND p_attester IS NULL THEN
  SELECT jsonb_build_object('signerId',a.signer_id,'keyEpoch',a.key_epoch,'trustDigest',encode(a.signer_trust_digest,'hex'),
   'selectionVersion',a.selection_version,'admissionVersion',a.admission_version,'fenceGeneration',a.fence_generation),s.receipt_ordinal
  INTO STRICT p_attester,p_receipt_ordinal FROM control.receipt_signing_attempt a
  JOIN control.signing_rotation_attestation s ON s.attempt_id=a.attempt_id
  WHERE a.participant_id=p_rotation.participant_id AND a.privacy_domain_id=p_rotation.privacy_domain_id
   AND a.operation_id=p_operation AND a.attempt_id=p_receipt AND s.from_revision=p_rotation.revision-1;
 END IF;
 SELECT jsonb_build_object('operationId',c.operation_id,'actionIntentId',c.action_intent_id,'actionIntentDigest',encode(c.action_intent_digest,'hex'),
  'inputDigest',encode(c.input_digest,'hex'),'fromRevision',c.from_revision,'toState',c.to_state,
  'authorizationEvidenceId',c.authorization_evidence_id,'authorizationSnapshotDigest',encode(c.authorization_snapshot_digest,'hex'),
  'consumerReceiptId',c.consumer_receipt_id,'originalOperationId',c.original_operation_id,'recoveryAttemptId',c.recovery_attempt_id,
  'authorizationGenerationId',c.authorization_generation_id,'approvalRequestId',c.approval_request_id,'approvalCandidateDigest',encode(c.approval_candidate_digest,'hex'),
  'priorObservationDigest',encode(c.prior_observation_digest,'hex'),'recoveryObservationDigest',encode(c.recovery_observation_digest,'hex'))
 INTO command FROM control.signing_rotation_command c WHERE c.participant_id=p_rotation.participant_id AND c.privacy_domain_id=p_rotation.privacy_domain_id AND c.operation_id=p_operation;
 IF command IS NOT NULL THEN
  effects:=openpc.signing_transition_effects(command->>'actionIntentId',p_prior_state,p_rotation.state);
  IF effects IS NULL THEN RAISE EXCEPTION 'DATA-6022-SIGNING-HISTORY-MATRIX'; END IF;
 END IF;
 SELECT history_digest INTO prior FROM control.signing_rotation_history
 WHERE participant_id=p_rotation.participant_id AND privacy_domain_id=p_rotation.privacy_domain_id
  AND rotation_id=p_rotation.rotation_id AND revision=p_rotation.revision-1;
 SELECT jsonb_build_object('id',c.mutation_candidate_id,'digest',encode(c.candidate_digest,'hex'),
  'maker',c.maker_principal_id,'session',c.maker_session_id,'sessionEpoch',c.maker_session_epoch,
  'participantEpoch',c.maker_participant_epoch,'principalEpoch',c.maker_principal_epoch,
  'assignment',c.maker_assignment_id,'assignmentVersion',c.maker_assignment_row_version,
  'envelope',c.maker_authority_envelope_id,'authorityEpoch',c.maker_authority_epoch,'delegationEpoch',c.maker_delegation_epoch)
 INTO STRICT candidate FROM control.mutation_candidate c WHERE c.participant_id=p_rotation.participant_id
  AND c.privacy_domain_id=p_rotation.privacy_domain_id AND c.resource_id=p_rotation.rotation_id
  AND c.candidate_digest=p_rotation.candidate_digest AND c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1';
 IF p_rotation.approval_request_id IS NOT NULL THEN
  SELECT jsonb_build_object('id',a.approval_request_id,'candidateDigest',encode(a.subject_digest,'hex'),
   'maker',a.maker_principal_id,'makerAuthority',a.maker_authority,'approvedOperation',p_rotation.approved_operation_id,
   'checker',d.approver_principal_id,'decision',d.approval_decision_id,'session',d.approver_session_id,
   'sessionEpoch',d.approver_session_epoch,'participantEpoch',d.approver_participant_epoch,
   'principalEpoch',d.approver_principal_epoch,'assignment',d.approver_assignment_id,
   'assignmentVersion',d.approver_assignment_row_version,'envelope',d.approver_authority_envelope_id,
   'authorityEpoch',d.approver_envelope_epoch,'delegationEpoch',d.approver_delegation_epoch,
   'signerCredential',d.signer_credential_id,'signerEpoch',d.signer_credential_epoch)
  INTO STRICT approval FROM control.approval_request a JOIN control.approval_decision_record d
   ON d.participant_id=a.participant_id AND d.privacy_domain_id=a.privacy_domain_id AND d.approval_request_id=a.approval_request_id
  WHERE a.participant_id=p_rotation.participant_id AND a.privacy_domain_id=p_rotation.privacy_domain_id
   AND a.approval_request_id=p_rotation.approval_request_id AND d.decision='APPROVE';
 END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('attemptId',a.attempt_id,'operationId',a.operation_id,'revision',a.from_revision,
  'fromState',a.from_state,'toState',a.to_state,'slot',a.slot,'method',a.request->>'method',
  'requestDigest',encode(a.request_digest,'hex'),'observationDigest',encode(a.observation_digest,'hex'),
  'state',CASE WHEN a.operation_id=p_operation AND a.state='OBSERVED' AND effects->>'kind' IN ('ADVANCE','FAILURE')
   THEN CASE WHEN effects->>'kind'='FAILURE' THEN 'REJECTED' ELSE 'ACCEPTED' END ELSE a.state END)
  ORDER BY a.from_revision,a.slot),'[]'::jsonb) INTO attempts FROM control.signing_provider_attempt a
 WHERE a.participant_id=p_rotation.participant_id AND a.privacy_domain_id=p_rotation.privacy_domain_id AND a.rotation_id=p_rotation.rotation_id
  AND a.request->>'method'<>'SIGN_RECEIPT';
 SELECT coalesce(jsonb_agg(jsonb_build_object('profileDigest',encode(s.profile_digest,'hex'),'fingerprint',k.signer_id,
  'epoch',k.key_epoch,'selectionVersion',s.row_version+CASE WHEN s.signer_id<>k.signer_id THEN CASE WHEN s.fenced_operation_id IS NULL THEN 2 ELSE 1 END ELSE 0 END,
  'admissionVersion',s.admission_version,'fenceGeneration',s.fence_generation+CASE WHEN s.signer_id<>k.signer_id AND s.fenced_operation_id IS NULL THEN 1 ELSE 0 END,'trustDigest',encode(k.trust_digest,'hex'),
  'admissionReference',k.admission_reference,'admissionDigest',encode(k.admission_digest,'hex')) ORDER BY s.profile_digest),'[]'::jsonb)
 INTO selections FROM control.business_signing_selection s JOIN control.business_signing_key k
  ON k.participant_id=s.participant_id AND k.privacy_domain_id=s.privacy_domain_id
   AND k.signer_id=CASE WHEN coalesce((effects->>'cutover')::boolean,false) AND s.signer_id=p_rotation.old_signer_id THEN p_rotation.new_signer_id ELSE s.signer_id END
 WHERE s.participant_id=p_rotation.participant_id AND s.privacy_domain_id=p_rotation.privacy_domain_id
  AND s.environment_id=p_rotation.environment_id AND k.workload_credential_id=p_rotation.workload_credential_id;
 -- Preserve the already signed admission snapshot across this operation's own ambiguity fence.
 -- Every other selection field must still match the actual/prospective selected key exactly.
 IF p_receipt IS NOT NULL THEN
  SELECT convert_from(a.history_preimage,'UTF8')::jsonb->'selections' INTO STRICT retained_selections
   FROM control.signing_rotation_attestation a WHERE a.participant_id=p_rotation.participant_id
    AND a.privacy_domain_id=p_rotation.privacy_domain_id AND a.operation_id=p_operation AND a.attempt_id=p_receipt;
  IF jsonb_typeof(retained_selections) IS DISTINCT FROM 'array' OR
   jsonb_array_length(retained_selections)<>jsonb_array_length(selections) OR EXISTS(
    SELECT 1 FROM jsonb_array_elements(selections) WITH ORDINALITY live(value,ordinal)
    LEFT JOIN jsonb_array_elements(retained_selections) WITH ORDINALITY retained(value,ordinal) USING(ordinal)
    WHERE (live.value-'admissionVersion') IS DISTINCT FROM (retained.value-'admissionVersion') OR
     NOT coalesce(openpc.retained_signing_admission_matches(p_rotation.participant_id,p_rotation.privacy_domain_id,
      live.value->>'fingerprint',p_operation,(retained.value->>'admissionVersion')::numeric,
      (live.value->>'admissionVersion')::numeric),false))
  THEN RAISE EXCEPTION 'DATA-6021-ROTATION-HISTORY-ADMISSION'; END IF;
  selections:=retained_selections;
 END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('namespace',i.namespace,'aggregateType',i.aggregate_type,'aggregateId',i.aggregate_id,
  'sequence',i.sequence,'receiptId',i.receipt_id,'receiptDigest',encode(i.receipt_digest,'hex'),'fingerprint',i.signer_id,'keyEpoch',i.key_epoch)
  ORDER BY i.receipt_id),'[]'::jsonb) INTO acknowledgements FROM control.qualified_receipt_inbox i
  JOIN control.signing_rotation_command c ON c.participant_id=i.participant_id AND c.privacy_domain_id=i.privacy_domain_id
   AND c.consumer_receipt_id=i.receipt_id
  WHERE c.participant_id=p_rotation.participant_id AND c.privacy_domain_id=p_rotation.privacy_domain_id AND c.operation_id=p_operation;
 RETURN convert_to(jsonb_build_object('schema','pc.control.signing-rotation-history.v1','participantId',p_rotation.participant_id,
  'privacyDomainId',p_rotation.privacy_domain_id,'rotationId',p_rotation.rotation_id,'revision',p_rotation.revision,
  'priorState',p_prior_state,'state',p_rotation.state,'operationId',p_operation,'priorDigest',encode(prior,'hex'),
  'candidate',candidate,'approval',approval,'command',command,'signerRole',p_rotation.request->>'signerRole','attempts',attempts,'selections',selections,'consumerAcknowledgements',acknowledgements,
  'oldTrustDigest',encode(p_rotation.old_trust_digest,'hex'),'newFingerprint',p_rotation.new_signer_id,
  'cutoverAtNs',p_rotation.cutover_at_ns,'recoveryFromState',p_rotation.recovery_from_state,
  'recoveryFromRevision',p_rotation.recovery_from_revision,'eventId',p_event,'evidenceId',p_evidence,
  'attester',p_attester,'receiptNamespace',CASE WHEN p_receipt_ordinal IS NULL THEN NULL ELSE 'CONTROL_SIGNING_LIFECYCLE_V1' END,
  'receiptOrdinal',p_receipt_ordinal)::text,'UTF8');
END $$;
CREATE OR REPLACE FUNCTION openpc.append_rotation_history()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE previous_state text; previous_digest bytea; operation uuid; event uuid; receipt uuid; evidence uuid; preimage bytea; ordinal numeric;
BEGIN
 previous_state:=CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.state END;
 SELECT history_digest INTO previous_digest FROM control.signing_rotation_history
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND revision=NEW.revision-1;
 IF NEW.revision>1 AND previous_digest IS NULL THEN RAISE EXCEPTION 'DATA-6021-ROTATION-HISTORY-GAP'; END IF;
 IF NEW.state='REQUESTED' THEN operation:=openpc.current_operation_id();
 ELSIF NEW.state='APPROVED' AND OLD.state='REQUESTED' THEN operation:=NEW.approved_operation_id;
 ELSE
  SELECT operation_id INTO STRICT operation FROM control.signing_rotation_command
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id
   AND operation_id=openpc.current_operation_id()
   AND (from_revision=OLD.revision OR (OLD.state='RECOVERING'
    AND openpc.current_action_intent_id()='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' AND from_revision=OLD.recovery_from_revision));
 END IF;
 IF NEW.state<>'REQUESTED' AND NOT (NEW.state='APPROVED' AND OLD.state='REQUESTED') THEN
  SELECT a.event_id,a.attempt_id,a.evidence_record_id,a.receipt_ordinal INTO STRICT event,receipt,evidence,ordinal
  FROM control.signing_rotation_attestation a JOIN control.signing_provider_attempt p USING(attempt_id)
  WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id AND a.operation_id=operation
   AND a.rotation_id=NEW.rotation_id AND a.from_revision=OLD.revision AND a.to_state=NEW.state
   AND p.state IN ('OBSERVED','ACCEPTED') AND p.observation->>'outcome'='SUCCEEDED';
  IF ordinal<>1+coalesce((SELECT max(receipt_ordinal) FROM control.signing_rotation_history
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id),0)
  THEN RAISE EXCEPTION 'DATA-6021-ROTATION-RECEIPT-ORDINAL'; END IF;
 END IF;
 preimage:=openpc.rotation_history_preimage(NEW,previous_state,operation,event,receipt,evidence);
 INSERT INTO control.signing_rotation_history(participant_id,privacy_domain_id,rotation_id,revision,prior_state,state,operation_id,
  prior_digest,history_preimage,history_digest,event_id,receipt_id,evidence_id,receipt_namespace,receipt_ordinal)
 VALUES(NEW.participant_id,NEW.privacy_domain_id,NEW.rotation_id,NEW.revision,previous_state,NEW.state,operation,
  previous_digest,preimage,sha256(preimage),event,receipt,evidence,
  CASE WHEN receipt IS NULL THEN NULL ELSE 'CONTROL_SIGNING_LIFECYCLE_V1' END,ordinal);
 RETURN NULL;
END $$;
CREATE TRIGGER signing_history_append AFTER INSERT OR UPDATE ON control.signing_key_rotation
 FOR EACH ROW EXECUTE FUNCTION openpc.append_rotation_history();
CREATE OR REPLACE FUNCTION openpc.guard_rotation_history()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE rotation control.signing_key_rotation%ROWTYPE; previous control.signing_rotation_history%ROWTYPE;
BEGIN
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id
  AND revision=NEW.revision AND state=NEW.state;
 IF NEW.revision>1 THEN
  SELECT * INTO STRICT previous FROM control.signing_rotation_history WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND revision=NEW.revision-1;
  IF NEW.prior_state<>previous.state OR NEW.prior_digest<>previous.history_digest THEN RAISE EXCEPTION 'DATA-6021-ROTATION-HISTORY-CHAIN'; END IF;
 END IF;
 IF NEW.history_preimage<>openpc.rotation_history_preimage(rotation,NEW.prior_state,NEW.operation_id,NEW.event_id,NEW.receipt_id,NEW.evidence_id)
 THEN RAISE EXCEPTION 'DATA-6021-ROTATION-HISTORY-BINDING'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_history_binding BEFORE INSERT ON control.signing_rotation_history
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_rotation_history();
CREATE TRIGGER signing_history_immutable BEFORE UPDATE OR DELETE ON control.signing_rotation_history
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE OR REPLACE FUNCTION openpc.check_rotation_history_completion()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.state IN ('REQUESTED','APPROVED') AND NEW.revision<=2 THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.signing_rotation_attestation a
  JOIN control.signing_provider_attempt p USING(attempt_id)
  JOIN control.audit_occurrence r ON r.participant_id=a.participant_id AND r.privacy_domain_id=a.privacy_domain_id AND r.receipt_id=a.attempt_id
  JOIN control.evidence_record e ON e.participant_id=r.participant_id AND e.privacy_domain_id=r.privacy_domain_id AND e.receipt_id=r.receipt_id
  WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id AND a.rotation_id=NEW.rotation_id
   AND a.operation_id=NEW.operation_id AND a.attempt_id=NEW.receipt_id AND a.from_revision=NEW.revision-1 AND a.to_state=NEW.state
   AND a.history_preimage=NEW.history_preimage AND a.history_digest=NEW.history_digest AND a.receipt_ordinal=NEW.receipt_ordinal
   AND a.receipt_cbor=r.receipt_cbor AND a.event_id IS NOT DISTINCT FROM NEW.event_id AND a.evidence_record_id=NEW.evidence_id
   AND e.evidence_record_id=NEW.evidence_id AND r.before_revision=NEW.revision-1 AND r.after_revision=NEW.revision
   AND p.state='ACCEPTED' AND p.observation->>'outcome'='SUCCEEDED'
   AND p.observation->>'resultHex'=encode(r.cose_sign1,'hex'))
 THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-SIGNED-ROTATION-HISTORY'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER signing_history_complete AFTER INSERT ON control.signing_rotation_history
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_rotation_history_completion();
`;
