const actions = [
  [
    'PROTECTED_PROOFS_CREATE_RESOURCE',
    'protected-proofs',
    'CREATE',
    'HIGH',
    true,
    true,
    true,
    'PROTECTED_PROOF_RETENTION',
  ],
  [
    'PROTECTED_PROOF_ACCESS_CREATE_RESOURCE',
    'protected-proof-access',
    'CREATE',
    'HIGH',
    true,
    true,
    true,
    'PROTECTED_PROOF_ACCESS_REQUEST',
  ],
  [
    'PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE',
    'protected-proof-access',
    'EXPORT',
    'STANDARD',
    false,
    false,
    true,
    'PROTECTED_PROOF_CONSUMPTION',
  ],
  [
    'PROTECTED_PROOFS_READ_SOURCE',
    'evidence-records',
    'READ',
    'HIGH',
    false,
    false,
    false,
    'PROTECTED_PROOF_SOURCE_READ',
  ],
  [
    'PROTECTED_PROOFS_READ_RESOURCE',
    'protected-proofs',
    'READ',
    'STANDARD',
    false,
    false,
    false,
    'PROTECTED_PROOF_METADATA_READ',
  ],
  [
    'PROTECTED_PROOFS_READ_COLLECTION',
    'protected-proofs',
    'READ',
    'STANDARD',
    false,
    false,
    false,
    'PROTECTED_PROOF_METADATA_READ',
  ],
  [
    'PROTECTED_PROOF_ACCESS_READ_RESOURCE',
    'protected-proof-access',
    'READ',
    'STANDARD',
    false,
    false,
    false,
    'PROTECTED_PROOF_ACCESS_READ',
  ],
  [
    'PROTECTED_PROOF_ACCESS_READ_COLLECTION',
    'protected-proof-access',
    'READ',
    'STANDARD',
    false,
    false,
    false,
    'PROTECTED_PROOF_ACCESS_READ',
  ],
];
const tuples = actions
  .map(
    ([id, resource, operation, risk, maker, step, idem, evidence]) =>
      `('ACT-${id}-V1','${resource}','${operation}','${risk}',${maker},${step},${idem},'AUTHORIZED_ONLY','REDACTED','${evidence}')`,
  )
  .join(',\n');
export const protectedProofGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ${tuples} ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE (action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
 IN (${tuples}))<>8 THEN RAISE EXCEPTION 'PC-AUTH-0002-PROTECTED-PROOF-ACTION'; END IF;
END $$;
ALTER TABLE control.protected_proof_object FORCE ROW LEVEL SECURITY;
ALTER TABLE control.protected_proof_payload FORCE ROW LEVEL SECURITY;
ALTER TABLE control.protected_proof_access FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.protected_proof_object,control.protected_proof_payload,control.protected_proof_access
 FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT,INSERT ON control.protected_proof_object,control.protected_proof_payload,control.protected_proof_access TO openpc_control_runtime;
GRANT UPDATE ON control.protected_proof_access TO openpc_control_runtime;
GRANT SELECT ON control.protected_proof_object,control.protected_proof_access TO openpc_control_reader;
GRANT SELECT ON control.authentication_occurrence TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.protected_proof_binding(o control.protected_proof_object)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('objectRef','urn:openpc:resource:'||(o).object_id::text,
  'objectVersion',(o).object_version::text,'objectDigest',(o).object_digest,'source',(o).source)
$$;

CREATE OR REPLACE FUNCTION openpc.guard_protected_proof_object()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a record; e record; expected jsonb; payload jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.creation_operation_id<>current_setting('openpc.operation_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT occurrence.* INTO a FROM control.evidence_catalogue c JOIN control.authentication_occurrence occurrence
  ON occurrence.participant_id=c.participant_id AND occurrence.privacy_domain_id=c.privacy_domain_id
   AND occurrence.occurrence_id::text=c.record_id AND c.evidence_class='AUTHENTICATION'
   AND c.receipt_digest='sha256:'||encode(occurrence.receipt_digest,'hex')
  WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
   AND 'urn:openpc:resource:'||c.evidence_id::text=NEW.source->>'evidenceId' AND occurrence.method='WEBAUTHN_ASSERTION';
 SELECT proof.* INTO e FROM control.mutation_evidence proof JOIN control.idempotency_record i
  ON i.participant_id=proof.participant_id AND i.privacy_domain_id=proof.privacy_domain_id
   AND i.operation_id=proof.operation_id AND i.terminal_state='COMMITTED' AND i.input_digest=proof.candidate_digest
  WHERE proof.participant_id=NEW.participant_id AND proof.privacy_domain_id=NEW.privacy_domain_id
   AND proof.operation_id=a.operation_id AND proof.principal_id=a.principal_id AND proof.aggregate_id=a.session_id
   AND proof.mfa_challenge_id=a.source_id AND proof.signer_credential_id=a.credential_id
   AND proof.webauthn_assertion_binding_digest=a.proof_digest AND proof.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY';
 IF a.occurrence_id IS NULL OR e.operation_id IS NULL OR e.evidence_digest<>sha256(e.evidence_cbor)
  OR coalesce(NEW.source->>'signerKeyDigest','')!~'^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 expected:=jsonb_build_object('evidenceId',NEW.source->>'evidenceId','occurrenceId',a.occurrence_id::text,
  'operationId',a.operation_id::text,'sourceReceiptDigest','sha256:'||encode(a.receipt_digest,'hex'),
  'proofDigest','sha256:'||encode(a.proof_digest,'hex'),'assertionDigest','sha256:'||encode(e.evidence_digest,'hex'),
  'signatureDigest','sha256:'||encode(sha256(e.cose_sign1),'hex'),'signerKeyDigest',NEW.source->>'signerKeyDigest',
  'occurredAt',to_char(a.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'materialType','IDENTITY_SIGNED_AUTHORIZATION_ASSERTION','evidenceClass','AUTHENTICATION',
  'sourceFormat','IDENTITY_RUNTIME_ASSERTION_3002_2_13','occurrenceIntegrity','CONTROL_DATABASE_IMMUTABLE',
  'proofIntegrity','IDENTITY_COSE_ED25519','finality','NOT_APPLICABLE','authorityEffect','NONE');
 payload:=jsonb_build_object('version','OPENPC_PROTECTED_IDENTITY_PROOF_V1','participantId',NEW.participant_id::text,
  'privacyDomainId',NEW.privacy_domain_id::text,'source',expected,
  'assertionBase64',replace(encode(e.evidence_cbor,'base64'),chr(10),''),'coseSign1Base64',replace(encode(e.cose_sign1,'base64'),chr(10),''));
 IF NEW.source IS DISTINCT FROM expected OR NEW.object_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(payload),'UTF8')),'hex')
  OR NEW.object_version<>1 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.created_at:=clock_timestamp(); NEW.updated_at:=NEW.created_at;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_protected_proof_payload()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE used bigint;
BEGIN
 IF TG_OP='DELETE' THEN
  PERFORM openpc.record_raw_proof_payload_deletion(OLD);
  RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT EXISTS(SELECT 1 FROM control.protected_proof_object o WHERE o.object_id=NEW.object_id
  AND o.participant_id=NEW.participant_id AND o.privacy_domain_id=NEW.privacy_domain_id
  AND o.creation_operation_id=current_setting('openpc.operation_id')::uuid)
  OR current_setting('openpc.action_intent_id')<>'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1' THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('protected-proof-capacity:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0));
 SELECT coalesce(sum(octet_length(ciphertext)),0) INTO used FROM control.protected_proof_payload
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id;
 IF used+octet_length(NEW.ciphertext)>16777216 THEN RAISE EXCEPTION 'PC-OPS-9002'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_protected_proof_access()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o control.protected_proof_object; expected jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO o FROM control.protected_proof_object WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND object_id=NEW.object_id;
 IF o.object_id IS NULL OR o.retain_until<=clock_timestamp() OR NEW.expires_at>o.retain_until
  OR NEW.object_binding IS DISTINCT FROM openpc.protected_proof_binding(o)
  OR NEW.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_OP='INSERT' THEN
  IF current_setting('openpc.action_intent_id')<>'ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1'
   OR NEW.creation_operation_id<>current_setting('openpc.operation_id')::uuid OR NEW.revision<>1
   OR NEW.consumed_at IS NOT NULL OR NEW.consumption_operation_id IS NOT NULL OR NEW.consumption_request IS NOT NULL
   THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  NEW.created_at:=clock_timestamp(); NEW.updated_at:=NEW.created_at;
 ELSE
  IF current_setting('openpc.action_intent_id')<>'ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1'
   OR OLD.revision<>1 OR NEW.revision<>2 OR NEW.consumption_operation_id<>current_setting('openpc.operation_id')::uuid
   OR (to_jsonb(NEW)-ARRAY['revision','consumption_operation_id','consumed_at','updated_at','consumption_request']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['revision','consumption_operation_id','consumed_at','updated_at','consumption_request'])
   THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  expected:=jsonb_build_object('targetRef','urn:openpc:resource:'||NEW.access_id::text,'expectedRevision','1',
   'object',NEW.object_binding,'purpose',NEW.purpose,'caseReference',NEW.case_reference,
   'recipientPrincipalId',NEW.recipient_principal_id::text,'expiresAt',to_char(NEW.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  IF NEW.consumption_request-ARRAY['reason','actionIntentId','actionIntentDigest'] IS DISTINCT FROM expected
   OR NEW.consumption_request->>'actionIntentId'<>'ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1'
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.consumed_at:=clock_timestamp(); NEW.updated_at:=NEW.consumed_at;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.require_protected_proof_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE op uuid; rid uuid; action text; catalog text; aggregate text; document jsonb; expected numeric;
 e control.mutation_evidence; c control.mutation_candidate; original control.mutation_evidence;
BEGIN
 IF TG_TABLE_NAME='protected_proof_object' THEN
  op:=NEW.creation_operation_id;rid:=NEW.object_id;action:='ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1';
  catalog:='CFG-OP-RETAIN-PROTECTED-PROOF';aggregate:='protected-proof';expected:=0;
  document:=jsonb_build_object('source',NEW.source,'purpose',NEW.purpose,'caseReference',NEW.case_reference,
   'retainUntil',to_char(NEW.retain_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  IF NOT EXISTS(SELECT 1 FROM control.protected_proof_payload WHERE object_id=rid AND participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSIF TG_OP='INSERT' THEN
  op:=NEW.creation_operation_id;rid:=NEW.access_id;action:='ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1';
  catalog:='CFG-OP-REQUEST-PROTECTED-ACCESS';aggregate:='protected-proof-access';expected:=0;
  document:=jsonb_build_object('object',NEW.object_binding,'purpose',NEW.purpose,'caseReference',NEW.case_reference,
   'recipientPrincipalId',NEW.recipient_principal_id::text,'expiresAt',to_char(NEW.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 ELSE
  op:=NEW.consumption_operation_id;rid:=NEW.access_id;action:='ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1';
  catalog:='CFG-OP-CONSUME-PROTECTED-ACCESS';aggregate:='protected-proof-access';expected:=1;document:=NEW.consumption_request;
 END IF;
 SELECT proof.* INTO e FROM control.mutation_evidence proof JOIN control.idempotency_record i
  ON i.participant_id=proof.participant_id AND i.privacy_domain_id=proof.privacy_domain_id AND i.operation_id=proof.operation_id
   AND i.principal_id=proof.principal_id AND i.action_intent_id=proof.action_intent_id AND i.catalog_operation_id=proof.catalog_operation_id
   AND i.input_digest=proof.candidate_digest AND i.terminal_state='COMMITTED' AND i.expected_aggregate_version=expected
   AND i.result_payload->>'resourceRef'='urn:openpc:resource:'||rid::text
  WHERE proof.participant_id=NEW.participant_id AND proof.privacy_domain_id=NEW.privacy_domain_id
   AND proof.operation_id=op AND proof.action_intent_id=action AND proof.catalog_operation_id=catalog
   AND proof.aggregate_type=aggregate AND proof.aggregate_id=rid;
 IF e.operation_id IS NULL OR NOT EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=e.participant_id
  AND event.privacy_domain_id=e.privacy_domain_id AND event.aggregate_type=aggregate AND event.aggregate_id=rid
  AND event.event_type=CASE catalog WHEN 'CFG-OP-RETAIN-PROTECTED-PROOF' THEN 'openpc.evidence.protected.retained.v1'
   WHEN 'CFG-OP-REQUEST-PROTECTED-ACCESS' THEN 'openpc.evidence.protected.access-requested.v1' ELSE 'openpc.evidence.protected.consumed.v1' END
  AND event.payload_digest=sha256(event.payload_cbor)
  AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(e.candidate_digest,'hex')
  AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'='sha256:'||encode(e.evidence_digest,'hex'))
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF expected=0 THEN
  SELECT candidate.* INTO c FROM control.mutation_candidate candidate JOIN control.approval_request a
   ON a.participant_id=candidate.participant_id AND a.privacy_domain_id=candidate.privacy_domain_id
    AND a.subject_id=candidate.mutation_candidate_id AND a.approval_request_id=e.approval_request_id
   WHERE candidate.participant_id=e.participant_id AND candidate.privacy_domain_id=e.privacy_domain_id
    AND candidate.consumed_operation_id=op AND candidate.state='CONSUMED' AND candidate.candidate_digest=e.candidate_digest
    AND candidate.action_intent_id=action AND candidate.catalog_operation_id=catalog AND candidate.resource_id=rid
    AND candidate.maker_principal_id=e.principal_id AND candidate.expected_revision=0;
  IF c.mutation_candidate_id IS NULL OR e.checker_principal_id IS NULL OR e.checker_principal_id=e.principal_id
   OR NEW.approval_request_id IS DISTINCT FROM e.approval_request_id
   OR c.candidate_document-ARRAY['participantId','actionIntentId','actionIntentDigest','reason'] IS DISTINCT FROM document
   OR NOT EXISTS(SELECT 1 FROM control.mfa_challenge m WHERE m.participant_id=e.participant_id AND m.mfa_challenge_id=e.mfa_challenge_id
    AND m.principal_id=e.principal_id AND m.used_operation_id=op AND m.action_intent_id=action AND m.resource_digest=e.candidate_digest
    AND m.consumed_at>clock_timestamp()-interval '5 minutes') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 ELSE
  IF e.candidate_digest<>sha256(convert_to(openpc.signing_canonical_json(document),'UTF8')) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO original FROM control.mutation_evidence WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.creation_operation_id;
  IF original.operation_id IS NULL OR (original.principal_id,original.bound_participant_epoch,original.bound_principal_epoch,
    original.bound_authority_envelope_id,original.bound_envelope_epoch,original.bound_assignment_id) IS DISTINCT FROM
   (e.principal_id,e.bound_participant_epoch,e.bound_principal_epoch,e.bound_authority_envelope_id,e.bound_envelope_epoch,e.bound_assignment_id)
   THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 END IF;
 IF TG_TABLE_NAME='protected_proof_access' THEN
  IF NEW.recipient_principal_id<>e.principal_id OR NOT EXISTS(SELECT 1 FROM control.session s
   WHERE s.participant_id=NEW.participant_id AND s.session_id=NEW.sender_session_id AND s.principal_id=e.principal_id
    AND s.privacy_domain_id=NEW.privacy_domain_id AND s.state='ACTIVE' AND s.absolute_expires_at>clock_timestamp()
    AND s.idle_expires_at>clock_timestamp()) THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  IF expected=0 AND NOT EXISTS(SELECT 1 FROM control.mfa_challenge m WHERE m.participant_id=e.participant_id
   AND m.mfa_challenge_id=e.mfa_challenge_id AND m.session_id=NEW.sender_session_id) THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 END IF;
 RETURN NULL;
END $$;
${['object', 'payload', 'access']
  .map(
    (name) => `
DROP TRIGGER IF EXISTS protected_proof_${name}_guard ON control.protected_proof_${name};
CREATE TRIGGER protected_proof_${name}_guard BEFORE INSERT OR UPDATE OR DELETE ON control.protected_proof_${name}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_protected_proof_${name}();`,
  )
  .join('\n')}
${['object', 'access']
  .map(
    (name) => `
DROP TRIGGER IF EXISTS protected_proof_${name}_command ON control.protected_proof_${name};
CREATE CONSTRAINT TRIGGER protected_proof_${name}_command AFTER INSERT OR UPDATE ON control.protected_proof_${name}
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_protected_proof_command();`,
  )
  .join('\n')}
REVOKE ALL ON FUNCTION openpc.protected_proof_binding(control.protected_proof_object),openpc.guard_protected_proof_object(),
 openpc.guard_protected_proof_payload(),openpc.guard_protected_proof_access(),openpc.require_protected_proof_command() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.protected_proof_binding(control.protected_proof_object),openpc.guard_protected_proof_object(),
 openpc.guard_protected_proof_payload(),openpc.guard_protected_proof_access(),openpc.require_protected_proof_command() TO openpc_control_runtime;
`;
