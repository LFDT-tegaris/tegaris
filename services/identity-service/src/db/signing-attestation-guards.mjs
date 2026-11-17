/** Lifecycle-only additions to the unchanged v1 occurrence/event acceptance path. */
export const signingAttestationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_signing_attestation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE rotation control.signing_key_rotation%ROWTYPE; command control.signing_rotation_command%ROWTYPE;
 attempt control.receipt_signing_attempt%ROWTYPE; provider control.signing_provider_attempt%ROWTYPE;
 payload jsonb; after_state jsonb; prospective control.signing_key_rotation%ROWTYPE; attester jsonb; expected bytea; expected_authorization jsonb; effects jsonb;
BEGIN
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND revision=NEW.from_revision;
 SELECT * INTO STRICT command FROM control.signing_rotation_command WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id AND operation_id=NEW.operation_id
  AND state IN ('ACCEPTED','WRITE_AMBIGUITY');
 SELECT * INTO STRICT attempt FROM control.receipt_signing_attempt WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id AND attempt_id=NEW.attempt_id
  AND reservation_kind='LIFECYCLE_DURABLE' AND schema_version=2;
 SELECT * INTO STRICT provider FROM control.signing_provider_attempt WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id AND attempt_id=NEW.attempt_id AND state='READY';
 IF command.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' AND EXISTS(
  SELECT 1 FROM control.signing_rotation_command recovery WHERE recovery.participant_id=NEW.participant_id
   AND recovery.privacy_domain_id=NEW.privacy_domain_id AND recovery.original_operation_id=NEW.operation_id
   AND recovery.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND recovery.state='ACCEPTED')
 THEN RAISE EXCEPTION 'DATA-6021-RECOVERY-IN-PROGRESS'; END IF;
 effects:=openpc.signing_transition_effects(command.action_intent_id,rotation.state,NEW.to_state);
 IF effects IS NULL OR (effects->>'resumeFrom' IS NOT NULL AND effects->>'resumeFrom' IS DISTINCT FROM rotation.recovery_from_state)
 THEN RAISE EXCEPTION 'DATA-6022-SIGNING-TRANSITION-MATRIX'; END IF;
 payload:=openpc.business_cbor(NEW.receipt_cbor);
 IF NEW.continuation_assertion_id IS NOT NULL THEN
  PERFORM openpc.check_signing_continuation_snapshot(NEW.authority_snapshot,NEW.participant_id,NEW.privacy_domain_id,
   NEW.operation_id,NEW.attempt_id,(payload->>'23')::numeric,false);
  SELECT jsonb_agg(proof ORDER BY proof->>'1') INTO expected_authorization FROM control.signing_continuation c
   JOIN control.mutation_evidence e ON e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
    AND e.operation_id=c.operation_id AND e.mutation_evidence_id=command.authorization_evidence_id
   CROSS JOIN LATERAL jsonb_array_elements(jsonb_build_array(
    jsonb_build_object('0',2,'1',c.assertion_id::text,'2',openpc.business_bytes(c.assertion_digest)),
    jsonb_build_object('0',2,'1',e.mutation_evidence_id::text,'2',openpc.business_bytes(e.evidence_digest)))) proof
   WHERE c.assertion_id=NEW.continuation_assertion_id;
  IF payload->'20' IS DISTINCT FROM expected_authorization OR
   convert_from(NEW.authority_snapshot,'UTF8')::jsonb->>'continuationAssertionId' IS DISTINCT FROM NEW.continuation_assertion_id::text
  THEN RAISE EXCEPTION 'DATA-6021-ATTESTATION-CONTINUATION'; END IF;
 END IF;
 after_state:=openpc.business_cbor(NEW.after_state_preimage);
 IF NEW.operation_id IS DISTINCT FROM openpc.current_operation_id() OR command.action_intent_id IS DISTINCT FROM openpc.current_action_intent_id()
  OR NEW.receipt_cbor<>attempt.payload_cbor OR NEW.signer_id<>attempt.signer_id OR NEW.signer_trust_digest<>attempt.signer_trust_digest
  OR NEW.selection_version<>attempt.selection_version OR
    (NEW.continuation_assertion_id IS NULL AND (convert_from(NEW.authority_snapshot,'UTF8')::jsonb->'authorities') IS DISTINCT FROM
    (convert_from(command.authorization_snapshot,'UTF8')::jsonb->'authorities'))
  OR payload->'14' IS DISTINCT FROM openpc.business_bytes(sha256(NEW.authority_snapshot))
  OR payload->'18'->'2' IS DISTINCT FROM openpc.business_bytes(sha256(NEW.before_state_preimage))
  OR payload->'19'->'2' IS DISTINCT FROM openpc.business_bytes(sha256(NEW.after_state_preimage))
  OR payload->'19'->'1' IS DISTINCT FROM to_jsonb(NEW.from_revision+1)
  OR provider.from_revision<>NEW.from_revision OR provider.from_state<>rotation.state OR provider.to_state<>NEW.to_state
  OR provider.rotation_id<>NEW.rotation_id OR provider.request->>'method' IS DISTINCT FROM 'SIGN_RECEIPT'
  OR provider.request->>'payloadHex' IS DISTINCT FROM encode(NEW.receipt_cbor,'hex')
  OR provider.request->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text OR provider.request->>'operationId' IS DISTINCT FROM NEW.operation_id::text
  OR (effects->>'eventType' IS NOT NULL) IS DISTINCT FROM (NEW.event_id IS NOT NULL)
  OR (NEW.to_state<>command.to_state AND NEW.to_state NOT IN ('FAILED','RECOVERING'))
 THEN RAISE EXCEPTION 'DATA-6021-ATTESTATION-EXACT-ATTEMPT'; END IF;
 IF EXISTS(SELECT 1 FROM control.signing_rotation_attestation a JOIN control.signing_provider_attempt p USING(attempt_id)
  WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id
   AND a.operation_id=NEW.operation_id AND p.state NOT IN ('REJECTED','SUPERSEDED'))
 THEN RAISE EXCEPTION 'DATA-6021-ATTESTATION-ALREADY-PENDING'; END IF;
 IF NEW.receipt_ordinal<>1+coalesce((SELECT max(receipt_ordinal) FROM control.signing_rotation_history
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND rotation_id=NEW.rotation_id),0)
 THEN RAISE EXCEPTION 'DATA-6021-ATTESTATION-ORDINAL'; END IF;
 prospective:=rotation;
 prospective.state:=NEW.to_state;
 prospective.revision:=NEW.from_revision+1;
 IF (effects->>'prepare')::boolean THEN
  SELECT observation->'descriptor'->>'fingerprint' INTO STRICT prospective.new_signer_id
  FROM control.signing_provider_attempt WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
   AND operation_id=NEW.operation_id AND request->>'method'='PREPARE' AND state='OBSERVED' AND observation->>'outcome'='SUCCEEDED';
 END IF;
 IF (effects->>'cutover')::boolean
 THEN prospective.cutover_at_ns:=(payload->>'23')::bigint; END IF;
 IF effects->>'kind' IN ('RECOVERY','FORWARD_RECOVERY') THEN
  IF command.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' AND command.authorization_generation_id IS NOT NULL THEN
   SELECT resume_state,resume_revision INTO STRICT prospective.recovery_from_state,prospective.recovery_from_revision
    FROM control.signing_authorization_generation WHERE generation_id=command.authorization_generation_id AND state='STAGED';
  ELSE
   prospective.recovery_from_state:=coalesce(rotation.recovery_from_state,rotation.state);
   prospective.recovery_from_revision:=coalesce(rotation.recovery_from_revision,rotation.revision);
  END IF;
 ELSE prospective.recovery_from_state:=NULL; prospective.recovery_from_revision:=NULL; END IF;
 attester:=jsonb_build_object('signerId',attempt.signer_id,'keyEpoch',attempt.key_epoch,'trustDigest',encode(attempt.signer_trust_digest,'hex'),
  'selectionVersion',attempt.selection_version,'admissionVersion',attempt.admission_version,'fenceGeneration',attempt.fence_generation);
 expected:=openpc.rotation_history_preimage(prospective,rotation.state,NEW.operation_id,NEW.event_id,NULL,NEW.evidence_record_id,attester,NEW.receipt_ordinal);
 IF expected<>NEW.history_preimage OR after_state->8->'2' IS DISTINCT FROM openpc.business_bytes(sha256(expected))
 THEN RAISE EXCEPTION 'DATA-6021-ATTESTATION-HISTORY'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_attestation_typed BEFORE INSERT ON control.signing_rotation_attestation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_attestation();
CREATE OR REPLACE FUNCTION openpc.check_signing_rotation_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE rotation control.signing_key_rotation%ROWTYPE; history control.signing_rotation_history%ROWTYPE;
 previous control.signing_rotation_history%ROWTYPE; attestation control.signing_rotation_attestation%ROWTYPE;
 before_new text; before_projection jsonb; after_projection jsonb; self_cutover boolean; effects jsonb;
BEGIN
 SELECT * INTO STRICT rotation FROM control.signing_key_rotation WHERE participant_id=receipt.participant_id
  AND privacy_domain_id=receipt.privacy_domain_id AND rotation_id=receipt.aggregate_id AND revision=receipt.after_revision;
 SELECT * INTO STRICT history FROM control.signing_rotation_history WHERE participant_id=receipt.participant_id
  AND privacy_domain_id=receipt.privacy_domain_id AND rotation_id=receipt.aggregate_id AND revision=receipt.after_revision
  AND receipt_id=receipt.receipt_id AND operation_id=receipt.operation_id;
 SELECT * INTO STRICT previous FROM control.signing_rotation_history WHERE participant_id=receipt.participant_id
  AND privacy_domain_id=receipt.privacy_domain_id AND rotation_id=receipt.aggregate_id AND revision=receipt.before_revision;
 SELECT * INTO STRICT attestation FROM control.signing_rotation_attestation WHERE participant_id=receipt.participant_id
  AND privacy_domain_id=receipt.privacy_domain_id AND rotation_id=receipt.aggregate_id AND operation_id=receipt.operation_id
  AND attempt_id=receipt.receipt_id AND from_revision=receipt.before_revision AND to_state=rotation.state;
 effects:=openpc.signing_transition_effects(receipt.action_intent_id,previous.state,rotation.state);
 IF effects IS NULL THEN RAISE EXCEPTION 'DATA-6022-SIGNING-TRANSITION-MATRIX'; END IF;
 IF attestation.receipt_cbor<>receipt.receipt_cbor OR attestation.authority_snapshot<>receipt.authority_snapshot
  OR attestation.before_state_preimage<>receipt.before_state_preimage OR attestation.after_state_preimage<>receipt.after_state_preimage
  OR attestation.history_digest<>history.history_digest OR receipt.after_revision<>receipt.before_revision+1
  OR jsonb_array_length(openpc.business_cbor(receipt.receipt_cbor)->'21')<>(CASE WHEN effects->>'eventType' IS NOT NULL THEN 1 ELSE 0 END)
  OR (effects->>'eventType' IS NOT NULL AND
    openpc.business_cbor(receipt.receipt_cbor)->'21'->0->'0' IS DISTINCT FROM openpc.business_uuid(attestation.event_id))
 THEN RAISE EXCEPTION 'DATA-6021-LIFECYCLE-RECEIPT-HISTORY'; END IF;
 before_new:=convert_from(previous.history_preimage,'UTF8')::jsonb->>'newFingerprint';
 before_projection:=jsonb_build_object('0',previous.state,'1',openpc.business_bytes(rotation.candidate_digest),
  '2',openpc.business_bytes(previous.history_digest),'3',rotation.request->>'signerRole',
  '4',openpc.business_bytes(decode(substring(rotation.old_signer_id from 8),'hex')),'5',CASE WHEN before_new IS NULL THEN 0 ELSE 1 END)
  ||CASE WHEN before_new IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('6',openpc.business_bytes(decode(substring(before_new from 8),'hex'))) END;
 after_projection:=jsonb_build_object('0',rotation.state,'1',openpc.business_bytes(rotation.candidate_digest),
  '2',openpc.business_bytes(history.history_digest),'3',rotation.request->>'signerRole',
  '4',openpc.business_bytes(decode(substring(rotation.old_signer_id from 8),'hex')),'5',CASE WHEN rotation.new_signer_id IS NULL THEN 0 ELSE 1 END)
  ||CASE WHEN rotation.new_signer_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('6',openpc.business_bytes(decode(substring(rotation.new_signer_id from 8),'hex'))) END;
 IF openpc.business_cbor(receipt.before_state_preimage)->8 IS DISTINCT FROM before_projection OR
  openpc.business_cbor(receipt.after_state_preimage)->8 IS DISTINCT FROM after_projection
 THEN RAISE EXCEPTION 'DATA-6021-LIFECYCLE-ACTUAL-STATE'; END IF;
 self_cutover:=rotation.request->>'signerRole'='LIFECYCLE_EVIDENCE' AND (effects->>'cutover')::boolean
  AND receipt.signer_id=rotation.old_signer_id AND receipt.recorded_at_ns=rotation.cutover_at_ns;
 IF NOT EXISTS(SELECT 1 FROM control.receipt_signing_attempt a
  JOIN control.business_signing_key k ON k.participant_id=a.participant_id AND k.privacy_domain_id=a.privacy_domain_id AND k.signer_id=a.signer_id
  JOIN control.business_signing_key_state ks ON ks.participant_id=a.participant_id AND ks.privacy_domain_id=a.privacy_domain_id AND ks.signer_id=a.signer_id
  JOIN control.business_signing_selection s ON s.participant_id=a.participant_id AND s.privacy_domain_id=a.privacy_domain_id
   AND s.environment_id=k.environment_id AND s.profile_digest=a.profile_digest
  JOIN control.credential c ON c.participant_id=k.participant_id AND c.credential_id=k.workload_credential_id
  JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
  WHERE a.participant_id=receipt.participant_id AND a.privacy_domain_id=receipt.privacy_domain_id AND a.attempt_id=receipt.receipt_id
   AND a.reservation_kind='LIFECYCLE_DURABLE' AND a.payload_cbor=receipt.receipt_cbor AND a.operation_id=receipt.operation_id
   AND k.trust_digest=receipt.signer_trust_snapshot_digest AND k.key_epoch=a.key_epoch AND k.environment_id=receipt.environment_id
   AND k.valid_from_ns<=receipt.recorded_at_ns AND k.valid_until_ns>receipt.recorded_at_ns
   AND c.credential_epoch=k.workload_credential_epoch AND c.state='ACTIVE' AND p.state='ACTIVE' AND p.kind='WORKLOAD'
   AND c.valid_from<=clock_timestamp() AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
   AND openpc.retained_signing_admission_matches(a.participant_id,a.privacy_domain_id,a.signer_id,a.operation_id,a.admission_version,s.admission_version)
   AND s.fenced_operation_id IS NULL AND ((NOT self_cutover AND ks.state='ACTIVE' AND s.signer_id=a.signer_id
    AND s.row_version=a.selection_version AND s.fence_generation=a.fence_generation
    AND k.valid_until_ns>floor(extract(epoch FROM clock_timestamp())*1000000)*1000)
    OR (self_cutover AND ks.state='RETIRED' AND s.signer_id=rotation.new_signer_id
     AND s.row_version=a.selection_version+2 AND s.fence_generation=a.fence_generation+1))
   FOR SHARE OF s,ks,c,p)
 THEN RAISE EXCEPTION 'DATA-6021-LIFECYCLE-SIGNER-FENCE'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_signing_rotation_event(event control.outbox_event,receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE state jsonb; expected_type text; expected_schema text; effects jsonb;
BEGIN
 state:=openpc.business_cbor(receipt.after_state_preimage)->8;
 effects:=openpc.signing_transition_effects(receipt.action_intent_id,openpc.business_cbor(receipt.before_state_preimage)->8->>'0',state->>'0');
 expected_type:=effects->>'eventType';
 expected_schema:=CASE expected_type WHEN 'io.openpc.ops.secret.revoked.v1' THEN 'SecretRevoked' WHEN 'io.openpc.ops.secret.rotated.v1' THEN 'SecretRotated' END;
 IF expected_type IS NULL OR receipt.catalog_operation_id<>'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION'
  OR event.event_type IS DISTINCT FROM expected_type
  OR event.data_schema_uri IS DISTINCT FROM 'https://schemas.openpc.local/event-payloads.schema.json#/$defs/'||expected_schema
  OR event.aggregate_type<>receipt.aggregate_type OR event.aggregate_id<>receipt.aggregate_id
  OR event.payload_digest<>sha256(event.payload_cbor) OR state->>'5'<>'1'
  OR openpc.business_cbor(event.payload_cbor) IS DISTINCT FROM jsonb_build_object('0',openpc.business_uuid(receipt.aggregate_id),
    '1',state->>'3','2',state->'4','3',state->'6')
 THEN RAISE EXCEPTION 'DATA-6021-LIFECYCLE-STATE-EVENT'; END IF;
END $$;
`;
