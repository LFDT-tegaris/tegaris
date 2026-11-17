export const nativeValueGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1','native-value-authorization','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','NATIVE_VALUE_AUTHORIZATION'),
 ('ACT-NATIVE_VALUE_AUTHORIZATIONS_READ_RESOURCE-V1','native-value-authorization','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','NATIVE_VALUE_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1','native-value-authorization','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','NATIVE_VALUE_AUTHORIZATION'),
  ('ACT-NATIVE_VALUE_AUTHORIZATIONS_READ_RESOURCE-V1','native-value-authorization','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','NATIVE_VALUE_READ')))<>2 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-ACTION-REGISTRATION';
 END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_native_value_authorization()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE document jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 document:=convert_from(NEW.document_bytes,'UTF8')::jsonb;
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.creation_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1'
  OR jsonb_typeof(document)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(document))<>15
  OR convert_to(openpc.signing_canonical_json(document),'UTF8')<>NEW.document_bytes
  OR NEW.semantic_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(document-'semanticDigest'),'UTF8')),'hex')
  OR (document->>'authorizationId'='urn:openpc:resource:'||NEW.native_value_authorization_id::text
   AND document->>'participantId'=NEW.participant_id::text AND document->>'actorSubjectId'=NEW.actor_principal_id::text
   AND jsonb_typeof(document->'participantEpoch')='number' AND document->>'participantEpoch' ~ '^[1-9][0-9]{0,19}$'
   AND (document->>'participantEpoch')::numeric<=18446744073709551615
   AND document->>'purpose'='CONTRACT_CREATION_ENDOWMENT' AND document->'oneUse'='true'::jsonb AND document->'used'='false'::jsonb
   AND document->>'amountMode' IN ('EXACT','MAXIMUM') AND jsonb_typeof(document->'maxAmountWei')='string'
   AND document->>'maxAmountWei' ~ '^[1-9][0-9]{0,77}$'
   AND jsonb_typeof(document->'chainId')='string' AND document->>'chainId' ~ '^[1-9][0-9]{0,19}$'
   AND (document->>'chainId')::numeric<=18446744073709551615
   AND document->>'chainEnvironmentId' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
   AND document->>'genesisHash' ~ '^[0-9a-f]{64}$'
   AND document->>'policyDecisionDigest'=substring(NEW.creation_authority_digest,8)
   AND document->>'semanticDigest'=substring(NEW.semantic_digest,8)
   AND (document->>'validUntil')::timestamptz=NEW.valid_until) IS NOT TRUE THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-ISSUANCE';
 END IF;
 NEW.created_at:=date_trunc('milliseconds',clock_timestamp());
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS native_value_authorization_guard ON control.native_value_authorization;
CREATE TRIGGER native_value_authorization_guard BEFORE INSERT OR UPDATE OR DELETE ON control.native_value_authorization
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_native_value_authorization();

CREATE OR REPLACE FUNCTION openpc.require_native_value_issuance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE document jsonb:=convert_from(NEW.document_bytes,'UTF8')::jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  JOIN control.wallet_binding wallet ON wallet.participant_id=NEW.participant_id AND wallet.privacy_domain_id=NEW.privacy_domain_id
   AND wallet.wallet_binding_id=NEW.wallet_binding_id AND wallet.binding_epoch=NEW.wallet_binding_epoch
   AND wallet.subject_id=NEW.actor_principal_id AND wallet.state='ACTIVE' AND wallet.chain_id::text=document->>'chainId'
  JOIN control.participant participant ON participant.participant_id=NEW.participant_id
   AND participant.authority_epoch=(document->>'participantEpoch')::numeric
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.creation_operation_id AND evidence.aggregate_type='native-value-authorization'
   AND evidence.aggregate_id=NEW.native_value_authorization_id AND evidence.catalog_operation_id='CFG-OP-CREATE-NATIVE-VALUE-AUTHORIZATION'
   AND evidence.action_intent_id='ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1'
   AND NEW.creation_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.native_value_authorization_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND ((NEW.execution_workload_id IS NULL AND candidate.maker_principal_id=NEW.actor_principal_id)
    OR (NEW.execution_workload_id IS NOT NULL AND EXISTS(
     SELECT 1 FROM control.principal principal JOIN control.credential credential USING(participant_id,principal_id)
     WHERE principal.participant_id=NEW.participant_id AND principal.principal_id=NEW.actor_principal_id
      AND principal.kind='WORKLOAD' AND principal.state='ACTIVE' AND credential.kind='WORKLOAD_MTLS'
      AND credential.audience=NEW.execution_workload_id AND credential.state='ACTIVE'
      AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp())
     AND NOT EXISTS(SELECT 1 FROM control.principal other JOIN control.credential credential USING(participant_id,principal_id)
      WHERE other.participant_id=NEW.participant_id AND other.principal_id<>NEW.actor_principal_id
       AND other.kind='WORKLOAD' AND other.state='ACTIVE' AND credential.kind='WORKLOAD_MTLS'
       AND credential.audience=NEW.execution_workload_id AND credential.state='ACTIVE'
       AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp())))
   AND candidate.candidate_document->>'walletBindingId'='urn:openpc:resource:'||NEW.wallet_binding_id::text
   AND (candidate.candidate_document->>'executionWorkloadId') IS NOT DISTINCT FROM NEW.execution_workload_id
   AND candidate.candidate_document->>'chainId'=document->>'chainId'
   AND concat(candidate.candidate_document->>'chainId',':',candidate.candidate_document->>'networkId',':',candidate.candidate_document->>'genesisDigest')=document->>'chainEnvironmentId'
   AND candidate.candidate_document->>'genesisDigest'='sha256:'||(document->>'genesisHash')
   AND candidate.candidate_document->>'amountMode'=document->>'amountMode'
   AND candidate.candidate_document->>'maxAmountWei'=document->>'maxAmountWei'
   AND candidate.candidate_document->>'validUntil'=document->>'validUntil'
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.native_value_authorization_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.native_value_authorization_id
    AND event.aggregate_type='native-value-authorization' AND event.event_type='openpc.native-value.authorization.issued.v1')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS native_value_issuance ON control.native_value_authorization;
CREATE CONSTRAINT TRIGGER native_value_issuance AFTER INSERT ON control.native_value_authorization
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_native_value_issuance();

-- The reservation's global unique key is the one-use owner. Neither possession
-- of grant bytes nor a caller's used=false can replace this current-state fence.
-- The worker may read these scoped owners, but cannot UPDATE authority rows.
-- Keep provenance reads under its RLS; elevate only the row-lock operation.
${[
  ['wallet_binding', true],
  ['principal', false],
  ['credential', false],
]
  .map(
    ([table, privacy]) => `DROP POLICY IF EXISTS native_value_locker_scope ON control.${table};
CREATE POLICY native_value_locker_scope ON control.${table} FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)${privacy ? ' AND openpc.matches_privacy(privacy_domain_id)' : ''}
  AND openpc.current_action_intent_id()='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND pg_trigger_depth()>0)
 WITH CHECK(false);`,
  )
  .join('\n')}
CREATE OR REPLACE FUNCTION openpc.lock_native_value_authority(wallet_id uuid,actor_id uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1' OR pg_trigger_depth()=0 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY';
 END IF;
 PERFORM 1 FROM control.wallet_binding wallet
 JOIN control.participant participant USING(participant_id)
 JOIN control.principal principal ON principal.participant_id=wallet.participant_id AND principal.principal_id=actor_id
 WHERE wallet.wallet_binding_id=wallet_id AND wallet.subject_id=actor_id
  AND openpc.matches_participant(wallet.participant_id) AND openpc.matches_privacy(wallet.privacy_domain_id)
 FOR SHARE OF wallet,participant,principal;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY'; END IF;
 PERFORM 1 FROM control.credential credential WHERE openpc.matches_participant(credential.participant_id)
  AND credential.principal_id=actor_id AND credential.kind='WORKLOAD_MTLS' FOR SHARE;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_native_value_authority(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_native_value_authority(uuid,uuid) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.fence_native_value_reservation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE admitted boolean:=false; wallet_id uuid; actor_id uuid;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY';
 END IF;
 IF NEW.native_value_authorization_id IS NULL AND NEW.native_value_authorization_digest IS NULL THEN RETURN NEW; END IF;
 IF TG_OP='UPDATE' AND NEW.state='EXPIRED' THEN RETURN NEW; END IF;
 SELECT wallet_binding_id,actor_principal_id INTO STRICT wallet_id,actor_id FROM control.native_value_authorization
 WHERE native_value_authorization_id=NEW.native_value_authorization_id;
 PERFORM openpc.lock_native_value_authority(wallet_id,actor_id);
 SELECT true INTO admitted FROM control.native_value_authorization issued_grant
 JOIN control.deployment_intent preparation ON preparation.participant_id=issued_grant.participant_id
  AND preparation.privacy_domain_id=issued_grant.privacy_domain_id AND preparation.preparation_digest=NEW.prepared_record_digest
  AND preparation.intent_digest=NEW.intent_digest AND preparation.wallet_binding_id=issued_grant.wallet_binding_id
  AND coalesce(preparation.execution_principal_id,preparation.actor_principal_id)=issued_grant.actor_principal_id
  AND preparation.execution_workload_id IS NOT DISTINCT FROM issued_grant.execution_workload_id
 JOIN control.mutation_candidate submission ON submission.participant_id=issued_grant.participant_id
  AND submission.privacy_domain_id=issued_grant.privacy_domain_id AND submission.resource_id=NEW.attempt_id
  AND submission.consumed_operation_id=NEW.command_id AND submission.maker_principal_id=preparation.actor_principal_id
  AND submission.state='CONSUMED' AND submission.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
  AND submission.action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND submission.candidate_document->>'deploymentIntentId'='urn:openpc:resource:'||preparation.deployment_intent_id::text
 JOIN control.idempotency_record receipt ON receipt.participant_id=submission.participant_id
  AND receipt.privacy_domain_id=submission.privacy_domain_id AND receipt.operation_id=submission.consumed_operation_id
  AND receipt.catalog_operation_id=submission.catalog_operation_id AND receipt.input_digest=submission.candidate_digest
  AND receipt.principal_id=submission.maker_principal_id AND receipt.terminal_state='COMMITTED'
 JOIN control.mutation_evidence evidence ON evidence.participant_id=submission.participant_id
  AND evidence.privacy_domain_id=submission.privacy_domain_id AND evidence.operation_id=submission.consumed_operation_id
  AND evidence.catalog_operation_id=submission.catalog_operation_id AND evidence.candidate_digest=submission.candidate_digest
  AND evidence.aggregate_id=submission.resource_id AND evidence.aggregate_type='deployment-submission'
 CROSS JOIN LATERAL (SELECT convert_from(preparation.preparation_bytes,'UTF8')::jsonb AS prepared,
  convert_from(issued_grant.document_bytes,'UTF8')::jsonb AS document) exact
 JOIN control.wallet_binding wallet ON wallet.participant_id=issued_grant.participant_id
  AND wallet.privacy_domain_id=issued_grant.privacy_domain_id AND wallet.wallet_binding_id=issued_grant.wallet_binding_id
  AND wallet.binding_epoch=issued_grant.wallet_binding_epoch AND wallet.subject_id=issued_grant.actor_principal_id
  AND wallet.state='ACTIVE' AND wallet.chain_id::text=NEW.chain_id AND wallet.wallet_address=NEW.sender_address
 JOIN control.participant participant ON participant.participant_id=issued_grant.participant_id
  AND participant.state='ACTIVE' AND participant.authority_epoch=(exact.document->>'participantEpoch')::numeric
 JOIN control.principal principal ON principal.participant_id=issued_grant.participant_id
  AND principal.principal_id=issued_grant.actor_principal_id AND principal.state='ACTIVE'
 WHERE issued_grant.native_value_authorization_id=NEW.native_value_authorization_id
  AND issued_grant.participant_id=NEW.participant_id AND issued_grant.privacy_domain_id=NEW.privacy_domain_id
  AND issued_grant.semantic_digest=NEW.native_value_authorization_digest
  AND issued_grant.valid_until>clock_timestamp() AND issued_grant.valid_until>=NEW.expires_at
  AND 'urn:openpc:resource:'||preparation.runtime_target_id::text=NEW.target_runtime_id AND preparation.expires_at>=NEW.expires_at
  AND exact.prepared->'context'->>'nativeValueAuthorizationBytes'='0x'||encode(issued_grant.document_bytes,'hex')
  AND exact.prepared->'context'->>'participantEpoch'=exact.document->>'participantEpoch'
  AND exact.prepared->'context'->>'walletBindingEpoch'=issued_grant.wallet_binding_epoch::text
  AND exact.prepared->'context'->>'chainEnvironmentId'=exact.document->>'chainEnvironmentId'
  AND exact.prepared->'intent'->>'nativeValueAuthorizationDigest'=substring(issued_grant.semantic_digest,8)
  AND exact.prepared->'intent'->>'chainId'=NEW.chain_id AND exact.document->>'chainId'=NEW.chain_id
  AND exact.document->>'genesisHash'=substring(NEW.genesis_digest,8)
  AND exact.prepared->'intent'->>'valueWei' ~ '^[1-9][0-9]{0,77}$'
  AND (exact.prepared->'intent'->>'valueWei')::numeric<2::numeric^256
  AND ((exact.document->>'amountMode'='EXACT' AND exact.document->>'maxAmountWei'=exact.prepared->'intent'->>'valueWei')
   OR (exact.document->>'amountMode'='MAXIMUM' AND (exact.prepared->'intent'->>'valueWei')::numeric<=(exact.document->>'maxAmountWei')::numeric))
  AND (issued_grant.execution_workload_id IS NULL OR EXISTS(SELECT 1 FROM control.credential credential
   WHERE credential.participant_id=principal.participant_id AND credential.principal_id=principal.principal_id
    AND principal.kind='WORKLOAD' AND credential.kind='WORKLOAD_MTLS' AND credential.audience=issued_grant.execution_workload_id
    AND credential.state='ACTIVE' AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp()));
 IF admitted IS DISTINCT FROM true THEN RAISE EXCEPTION 'PC-AUTH-0002-NATIVE-VALUE-CUSTODY'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.fence_native_value_reservation() FROM PUBLIC;
DROP TRIGGER IF EXISTS native_value_reservation_fence ON control.deployment_address_reservation;
CREATE TRIGGER native_value_reservation_fence BEFORE INSERT OR UPDATE OF state ON control.deployment_address_reservation
 FOR EACH ROW EXECUTE FUNCTION openpc.fence_native_value_reservation();
`;
