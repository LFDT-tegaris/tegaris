import { workloadCredentialSuccessorSql } from '../../../identity-service/src/db/workload-credential-successor.mjs';

/** A completed ordinary rotation is a fact, not a new permission. The native
 * worker receives only the exact pending denial's connection binding. */
export const expiredCredentialDenialProvenanceSql = `
CREATE OR REPLACE FUNCTION openpc.expired_denial_credential_provenance(
 wanted_target uuid,certificate text,wanted_rotation uuid DEFAULT NULL)
RETURNS TABLE(binding jsonb,rotation_operation_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on SET jit=off AS $$
DECLARE pid uuid;privacy uuid;authority record;current_credential control.credential;
 original_credential control.credential;e control.runtime_expired_activation_denial;
 a control.runtime_target_disposition_admission;p control.runtime_target_disposition_admission;
 d control.runtime_target_disposition_delivery;k control.runtime_target_disposition_acknowledgement;
 w control.configuration_work;t control.runtime_target;old_target jsonb;current_target jsonb;rotations uuid[];
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'EXPIRED-CREDENTIAL-DENIAL-CONTEXT';END IF;
 pid:=openpc.current_participant_id();privacy:=openpc.current_privacy_domain_id();
 SELECT * INTO STRICT authority FROM openpc.lock_runtime_discovery_authority(wanted_target,certificate);
 SELECT * INTO STRICT current_credential FROM control.credential c WHERE c.participant_id=pid AND c.credential_id=authority.credential_id;
 SELECT * INTO STRICT e FROM control.runtime_expired_activation_denial x WHERE x.participant_id=pid
  AND x.privacy_domain_id=privacy AND x.runtime_target_id=wanted_target;
 SELECT * INTO STRICT w FROM control.configuration_work x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy
  AND x.configuration_work_id=e.configuration_work_id AND x.runtime_target_id=wanted_target;
 SELECT * INTO STRICT t FROM control.runtime_target x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy AND x.runtime_target_id=wanted_target;
 SELECT * INTO STRICT a FROM control.runtime_target_disposition_admission x WHERE x.participant_id=pid
  AND x.privacy_domain_id=privacy AND x.runtime_target_id=wanted_target AND x.revision=e.admission_revision;
 SELECT * INTO STRICT p FROM control.runtime_target_disposition_admission x WHERE x.participant_id=pid
  AND x.privacy_domain_id=privacy AND x.runtime_target_id=wanted_target AND x.revision=e.admission_revision-1;
 SELECT * INTO STRICT d FROM control.runtime_target_disposition_delivery x WHERE x.participant_id=pid
  AND x.privacy_domain_id=privacy AND x.runtime_target_id=wanted_target AND x.revision=p.revision;
 SELECT * INTO STRICT k FROM control.runtime_target_disposition_acknowledgement x WHERE x.participant_id=pid
  AND x.privacy_domain_id=privacy AND x.runtime_target_id=wanted_target AND x.delivery_digest=d.delivery_digest;
 old_target:=a.binding->'target';
 SELECT * INTO STRICT original_credential FROM control.credential c WHERE c.participant_id=pid
  AND c.credential_id=(old_target->>'credential_id')::uuid;
 current_target:=jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,'target_id',wanted_target::text,
  'credential_id',current_credential.credential_id::text,'principal_id',current_credential.principal_id::text,
  'credential_epoch',authority.credential_epoch,'principal_epoch',authority.principal_epoch,
  'certificate_digest',substring(certificate from 8));
 IF w.state IS DISTINCT FROM 'RECONCILING' OR w.reconcile_after IS DISTINCT FROM 'infinity'::timestamptz
  OR w.work_kind IS DISTINCT FROM 'RUNTIME_ACTIVATION' OR w.execution_attempt_id IS DISTINCT FROM e.execution_attempt_id
  OR w.execution_started_at IS NULL OR w.lease_owner IS NOT NULL OR w.lease_until IS NOT NULL
  OR w.result_event_id IS NOT NULL OR w.completed_at IS NOT NULL
  OR t.state IS DISTINCT FROM 'STAGING' OR t.active_generation_digest IS DISTINCT FROM w.predecessor_digest
  OR t.desired_generation_digest IS DISTINCT FROM w.generation_digest
  OR a.admission_digest IS DISTINCT FROM e.admission_digest OR a.binding->>'action' IS DISTINCT FROM 'Withdraw'
  OR a.binding->'source' IS DISTINCT FROM e.proof->'source'
  OR a.binding->'cause' IS DISTINCT FROM jsonb_build_object('kind','Activation','work_id',w.configuration_work_id::text,
   'operation_id',w.operation_id::text,'execution_attempt_id',w.execution_attempt_id::text)
  OR old_target->>'participant_id' IS DISTINCT FROM pid::text OR old_target->>'privacy_domain_id' IS DISTINCT FROM privacy::text
  OR old_target->>'target_id' IS DISTINCT FROM wanted_target::text
  OR old_target->>'principal_id' IS DISTINCT FROM current_credential.principal_id::text
  OR old_target->'principal_epoch' IS DISTINCT FROM to_jsonb(authority.principal_epoch)
  OR (old_target->>'credential_epoch')::numeric+1 IS DISTINCT FROM authority.credential_epoch::numeric
  OR original_credential.state IS DISTINCT FROM 'REVOKED'
  OR original_credential.kind IS DISTINCT FROM 'WORKLOAD_MTLS'
  OR original_credential.principal_id IS DISTINCT FROM current_credential.principal_id
  OR original_credential.audience IS DISTINCT FROM current_credential.audience
  OR current_credential.rotated_from_credential_id IS DISTINCT FROM original_credential.credential_id
  OR original_credential.credential_epoch IS DISTINCT FROM current_credential.credential_epoch
  OR old_target->>'certificate_digest' IS DISTINCT FROM encode(original_credential.secret_fingerprint,'hex')
  OR original_credential.certificate_der IS NULL OR sha256(original_credential.certificate_der) IS DISTINCT FROM original_credential.secret_fingerprint
  OR current_target=old_target OR current_target->>'certificate_digest'=old_target->>'certificate_digest'
  OR a.binding->'previous_revision' IS DISTINCT FROM to_jsonb(p.revision)
  OR a.binding->>'previous_delivery_digest' IS DISTINCT FROM substring(d.delivery_digest from 8)
  OR p.binding->'target' IS DISTINCT FROM old_target OR p.binding->>'action' IS DISTINCT FROM 'Withdraw'
  OR p.binding->'cause' IS DISTINCT FROM jsonb_build_object('kind','Activation','work_id',w.configuration_work_id::text,
   'operation_id',w.operation_id::text,'execution_attempt_id',NULL)
  OR p.binding->'source'->>'capsule_digest' IS DISTINCT FROM substring(w.predecessor_digest from 8)
  OR a.binding->'source'->>'predecessor_capsule_digest' IS DISTINCT FROM p.binding->'source'->>'capsule_digest'
  OR d.claims IS DISTINCT FROM p.binding||jsonb_build_object('committed_admission_digest',substring(p.admission_digest from 8))
  OR d.delivery_digest IS DISTINCT FROM 'sha256:'||encode(sha256(d.signed_delivery),'hex')
  OR k.claims->'target' IS DISTINCT FROM old_target OR k.claims->>'installed_state' IS DISTINCT FROM 'NewUseDenied'
  OR k.claims->'disposition_revision' IS DISTINCT FROM to_jsonb(p.revision)
  OR k.acknowledgement_digest IS DISTINCT FROM 'sha256:'||encode(sha256(k.signed_acknowledgement),'hex')
  OR EXISTS(SELECT 1 FROM control.runtime_target_disposition_delivery x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy
   AND x.runtime_target_id=wanted_target AND x.revision=e.admission_revision)
 THEN RAISE EXCEPTION 'EXPIRED-CREDENTIAL-DENIAL-ORIGINAL';END IF;
 SELECT array_agg(chosen_rotation.consumed_operation_id ORDER BY chosen_rotation.consumed_operation_id) INTO rotations
 FROM control.mutation_candidate chosen_rotation WHERE chosen_rotation.participant_id=pid AND chosen_rotation.privacy_domain_id=privacy
  AND chosen_rotation.resource_id=original_credential.credential_id AND chosen_rotation.state='CONSUMED'
  AND chosen_rotation.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'AND chosen_rotation.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  AND (wanted_rotation IS NULL OR chosen_rotation.consumed_operation_id=wanted_rotation)
  AND ${workloadCredentialSuccessorSql({
    participantId: 'pid',
    privacyDomainId: 'privacy',
    predecessorId: 'original_credential.credential_id',
    predecessorEpoch: "(old_target->>'credential_epoch')::numeric",
    successorId: 'current_credential.credential_id',
    successorEpoch: 'current_credential.credential_epoch',
    operationId: 'chosen_rotation.consumed_operation_id',
  })};
 IF cardinality(rotations) IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'EXPIRED-CREDENTIAL-DENIAL-ROTATION';END IF;
 RETURN QUERY SELECT jsonb_build_object('target',current_target,'source',a.binding->'source','credential_predecessor',old_target),rotations[1];
END $$;
ALTER FUNCTION openpc.expired_denial_credential_provenance(uuid,text,uuid) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.expired_denial_credential_provenance(uuid,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_denial_credential_provenance(uuid,text,uuid) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.expired_denial_credential_bootstrap(wanted_target uuid,certificate text)
RETURNS TABLE(binding jsonb,rotation_operation_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on SET jit=off AS $$
DECLARE e control.runtime_expired_activation_denial;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();PERFORM openpc.assert_request_context(true);
 SELECT * INTO STRICT e FROM control.runtime_expired_activation_denial x WHERE x.participant_id=openpc.current_participant_id()
  AND x.privacy_domain_id=openpc.current_privacy_domain_id() AND x.runtime_target_id=wanted_target;
 IF e.admission_revision IS DISTINCT FROM (SELECT max(a.revision)FROM control.runtime_target_disposition_admission a
   WHERE a.participant_id=e.participant_id AND a.privacy_domain_id=e.privacy_domain_id AND a.runtime_target_id=e.runtime_target_id)
  OR EXISTS(SELECT 1 FROM control.runtime_expired_denial_handover h WHERE h.configuration_work_id=e.configuration_work_id)
 THEN RAISE EXCEPTION 'EXPIRED-CREDENTIAL-DENIAL-HEAD';END IF;
 RETURN QUERY SELECT p.binding,p.rotation_operation_id FROM openpc.expired_denial_credential_provenance(wanted_target,certificate,NULL)p;
END $$;
ALTER FUNCTION openpc.expired_denial_credential_bootstrap(uuid,text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.expired_denial_credential_bootstrap(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_denial_credential_bootstrap(uuid,text) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.expired_credential_denial_state_digest(wanted_work uuid,certificate text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE e control.runtime_expired_activation_denial;p record;original text;
BEGIN
 SELECT * INTO STRICT e FROM control.runtime_expired_activation_denial x
 WHERE x.configuration_work_id=wanted_work AND x.participant_id=openpc.current_participant_id()
  AND x.privacy_domain_id=openpc.current_privacy_domain_id();
 SELECT * INTO STRICT p FROM openpc.expired_denial_credential_bootstrap(e.runtime_target_id,certificate);
 original:=openpc.expired_denial_handover_state_digest(wanted_work);
 IF original IS NULL THEN RAISE EXCEPTION 'EXPIRED-CREDENTIAL-DENIAL-STATE';END IF;
 RETURN 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
 'originalState',original,'credentialBinding',p.binding,'rotationOperationId',p.rotation_operation_id::text)),'UTF8')),'hex');
END
$$;
REVOKE ALL ON FUNCTION openpc.expired_credential_denial_state_digest(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_credential_denial_state_digest(uuid,text) TO openpc_control_worker;
`;

/** One NEW denial, preserving the spent original admission and every original
 * effect. Current TLS and the host MAC are necessary independent boundaries. */
export const expiredCredentialDenialAdmissionSql = `
CREATE OR REPLACE FUNCTION openpc.begin_expired_credential_denial_handover(proof_wire bytea,nonce bytea,mac bytea)
RETURNS TABLE(binding jsonb,admission_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on SET jit=off AS $$
DECLARE proof jsonb;secret bytea;expected bytea;different integer:=0;pid uuid;privacy uuid;target uuid;
 transition record;e control.runtime_expired_activation_denial;w control.configuration_work;t control.runtime_target;
 a control.runtime_target_disposition_admission;p control.runtime_target_disposition_admission;
 d control.runtime_target_disposition_delivery;k control.runtime_target_disposition_acknowledgement;
 h jsonb;floor jsonb;credential_transition jsonb;material jsonb;digest text;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
  OR current_setting('session_replication_role')<>'origin' OR proof_wire IS NULL
  OR octet_length(proof_wire) NOT BETWEEN 2 AND 131072 OR nonce IS NULL OR octet_length(nonce)<>32
  OR mac IS NULL OR octet_length(mac)<>32 THEN RAISE EXCEPTION 'PC-AUTH-0005';END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_target_disposition_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to('OPENPC_EXPIRED_CREDENTIAL_DENIAL_HANDOVER_V1','UTF8')||sha256(proof_wire)||nonce,secret,'sha256');
 FOR n IN 0..31 LOOP different:=different|(get_byte(expected,n)#get_byte(mac,n));END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005';END IF;
 proof:=convert_from(proof_wire,'UTF8')::jsonb;
 IF proof IS DISTINCT FROM jsonb_build_object('version',1,'transactionId',pg_current_xact_id()::text,
  'intent',proof->'intent','intentBytesHex',proof->'intentBytesHex','intentDigest',proof->'intentDigest',
  'source',proof->'source','target',proof->'target','capsuleGeneration',proof->'capsuleGeneration',
  'capsuleNotBeforeNs',proof->'capsuleNotBeforeNs','capsuleExpiresAtNs',proof->'capsuleExpiresAtNs',
  'observedAtNs',proof->'observedAtNs','receiptWireDigest',proof->'receiptWireDigest','tokenDigest',proof->'tokenDigest')
  OR proof->'intent' IS DISTINCT FROM jsonb_build_object('purpose','EXPIRED_OBSERVED_CREDENTIAL_DENIAL_HANDOVER_V1',
   'requestId',proof->'intent'->'requestId','issuedAtMs',proof->'intent'->'issuedAtMs','expiresAtMs',proof->'intent'->'expiresAtMs',
   'custody',proof->'intent'->'custody','handover',proof->'intent'->'handover','credentialTransition',proof->'intent'->'credentialTransition')
  OR coalesce(proof->'intent'->>'requestId','') !~ '^[0-9a-f-]{36}$'
  OR coalesce(proof->'intent'->>'issuedAtMs','') !~ '^[0-9]{1,16}$'
  OR coalesce(proof->'intent'->>'expiresAtMs','') !~ '^[0-9]{1,16}$'
  OR (proof->'intent'->>'issuedAtMs')::numeric>extract(epoch from clock_timestamp())*1000
  OR (proof->'intent'->>'expiresAtMs')::numeric<=extract(epoch from clock_timestamp())*1000
  OR (proof->'intent'->>'expiresAtMs')::numeric-(proof->'intent'->>'issuedAtMs')::numeric NOT BETWEEN 1 AND 120000
  OR proof->'intent'->'custody'->>'databaseRole' IS DISTINCT FROM session_user::text
  OR proof->'intent'->'custody'->>'workerRole' IS DISTINCT FROM 'openpc_control_worker'
  OR NOT pg_has_role(session_user,'openpc_control_worker','USAGE') OR pg_has_role(session_user,'openpc_control_owner','USAGE')
  OR coalesce(proof->>'intentBytesHex','') !~ '^[0-9a-f]+$'
  OR length(proof->>'intentBytesHex') NOT BETWEEN 4 AND 32768 OR length(proof->>'intentBytesHex')%2<>0
  OR convert_from(decode(proof->>'intentBytesHex','hex'),'UTF8')::jsonb IS DISTINCT FROM proof->'intent'
  OR proof->>'intentDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(decode(proof->>'intentBytesHex','hex')),'hex')
 THEN RAISE EXCEPTION 'EXPIRED-CREDENTIAL-DENIAL-PROOF';END IF;
 pid:=openpc.current_participant_id();privacy:=openpc.current_privacy_domain_id();target:=(proof->'target'->>'target_id')::uuid;
 credential_transition:=proof->'intent'->'credentialTransition';h:=proof->'intent'->'handover';floor:=h->'floor';
 SELECT * INTO STRICT transition FROM openpc.expired_denial_credential_provenance(target,
  'sha256:'||(proof->'target'->>'certificate_digest'),(credential_transition->>'rotationOperationId')::uuid);
 IF proof->'target' IS DISTINCT FROM transition.binding->'target' OR proof->'source' IS DISTINCT FROM transition.binding->'source'
  OR credential_transition IS DISTINCT FROM jsonb_build_object('predecessorTarget',transition.binding->'credential_predecessor',
   'successorCredentialId',transition.binding->'target'->>'credential_id','rotationOperationId',transition.rotation_operation_id::text)
  OR h IS DISTINCT FROM jsonb_build_object('abandonedRevision',h->'abandonedRevision','abandonedAdmissionDigest',h->'abandonedAdmissionDigest','floor',floor)
  OR floor IS DISTINCT FROM jsonb_build_object('installedRevision',floor->'installedRevision','installedDeliveryDigest',floor->'installedDeliveryDigest',
   'observedRevision',floor->'observedRevision','observedAdmissionDigest',floor->'observedAdmissionDigest','originalReceiptWireDigest',floor->'originalReceiptWireDigest')
 THEN RAISE EXCEPTION 'EXPIRED-CREDENTIAL-DENIAL-TRANSITION';END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||pid::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||pid::text||':'||privacy::text||':'||target::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007';END IF;
 SELECT * INTO STRICT e FROM control.runtime_expired_activation_denial x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy
  AND x.runtime_target_id=target AND x.configuration_work_id=(proof->'intent'->'custody'->>'workId')::uuid FOR SHARE NOWAIT;
 SELECT * INTO STRICT w FROM control.configuration_work x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy
  AND x.configuration_work_id=e.configuration_work_id AND x.runtime_target_id=target FOR UPDATE NOWAIT;
 SELECT * INTO STRICT t FROM control.runtime_target x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy AND x.runtime_target_id=target FOR UPDATE NOWAIT;
 SELECT * INTO STRICT a FROM control.runtime_target_disposition_admission x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy
  AND x.runtime_target_id=target ORDER BY x.revision DESC LIMIT 1 FOR UPDATE NOWAIT;
 SELECT * INTO STRICT p FROM control.runtime_target_disposition_admission x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy
  AND x.runtime_target_id=target AND x.revision=e.admission_revision-1 FOR SHARE NOWAIT;
 SELECT * INTO STRICT d FROM control.runtime_target_disposition_delivery x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy
  AND x.runtime_target_id=target AND x.revision=p.revision;
 SELECT * INTO STRICT k FROM control.runtime_target_disposition_acknowledgement x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy
  AND x.runtime_target_id=target AND x.delivery_digest=d.delivery_digest;
 IF a.revision IS DISTINCT FROM e.admission_revision::numeric OR a.admission_digest IS DISTINCT FROM e.admission_digest
  OR EXISTS(SELECT 1 FROM control.runtime_expired_denial_handover x WHERE x.configuration_work_id=e.configuration_work_id)
  OR h->'abandonedRevision' IS DISTINCT FROM to_jsonb(e.admission_revision)
  OR h->>'abandonedAdmissionDigest' IS DISTINCT FROM substring(e.admission_digest from 8)
  OR floor->'installedRevision' IS DISTINCT FROM to_jsonb(p.revision)
  OR floor->>'installedDeliveryDigest' IS DISTINCT FROM substring(d.delivery_digest from 8)
  OR floor->'observedRevision' IS DISTINCT FROM to_jsonb(a.revision)
  OR floor->>'observedAdmissionDigest' IS DISTINCT FROM substring(a.admission_digest from 8)
  OR floor->>'originalReceiptWireDigest' IS DISTINCT FROM e.proof->>'receiptWireDigest'
  OR proof->'intent'->'custody'->>'originalStateDigest' IS DISTINCT FROM openpc.expired_credential_denial_state_digest(w.configuration_work_id,
   'sha256:'||(proof->'target'->>'certificate_digest'))
  OR EXISTS(SELECT 1 FROM (VALUES('capsuleGeneration'),('capsuleNotBeforeNs'),('capsuleExpiresAtNs'),('observedAtNs'),('receiptWireDigest'),('tokenDigest'))n(key)
   WHERE proof->n.key IS DISTINCT FROM e.proof->n.key)
  OR (proof->>'capsuleExpiresAtNs')::numeric>extract(epoch from clock_timestamp())*1000000000
  OR EXISTS(SELECT 1 FROM (VALUES('workId'),('operationId'),('executionAttemptId'),('participantId'),('privacyDomainId'),
   ('runtimeTargetId'),('generationId'),('generationDigest'),('configurationDigest'),('xdsVersionDigest'),('capsuleDigest'),
   ('receiptDigest'),('occurrenceId'),('schemaVersion'),('claimCount'),('workerId'),('dispositionRevision'),('deliveryDigest'),('acknowledgementDigest'))n(key)
   WHERE proof->'intent'->'custody'->n.key IS DISTINCT FROM e.proof->'intent'->'custody'->n.key)
 THEN RAISE EXCEPTION 'EXPIRED-CREDENTIAL-DENIAL-ORIGINAL';END IF;
 -- Repeat the exact current credential and original custody proof after fences.
 SELECT * INTO STRICT transition FROM openpc.expired_denial_credential_provenance(target,
  'sha256:'||(proof->'target'->>'certificate_digest'),(credential_transition->>'rotationOperationId')::uuid);
 material:=jsonb_build_object('version',1,'action','Withdraw','revision',a.revision+1,
  'previous_revision',p.revision,'previous_delivery_digest',substring(d.delivery_digest from 8),
  'target',transition.binding->'target','source',a.binding->'source','cause',jsonb_build_object(
   'kind','ExpiredObservedCredentialDenialHandover','work_id',w.configuration_work_id::text,'operation_id',w.operation_id::text,
   'execution_attempt_id',w.execution_attempt_id::text,'abandoned_revision',a.revision,
   'abandoned_admission_digest',substring(a.admission_digest from 8),'original_receipt_wire_digest',proof->>'receiptWireDigest',
   'installed_revision',p.revision,'installed_delivery_digest',substring(d.delivery_digest from 8),
   'observed_revision',floor->'observedRevision','observed_admission_digest',floor->>'observedAdmissionDigest',
   'abandoned_target',transition.binding->'credential_predecessor','credential_rotation_operation_id',transition.rotation_operation_id::text));
 digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(material),'UTF8')),'hex');
 IF (proof->'intent'->>'expiresAtMs')::numeric<=extract(epoch from clock_timestamp())*1000
 THEN RAISE EXCEPTION 'EXPIRED-CREDENTIAL-DENIAL-OPERATOR-WINDOW';END IF;
 INSERT INTO control.runtime_expired_denial_handover(configuration_work_id,request_id,participant_id,privacy_domain_id,runtime_target_id,
  abandoned_revision,abandoned_admission_digest,admission_revision,admission_digest,proof,intent_bytes,intent_digest)
 VALUES(w.configuration_work_id,(proof->'intent'->>'requestId')::uuid,pid,privacy,target,e.admission_revision,e.admission_digest,
  e.admission_revision+1,digest,proof,decode(proof->>'intentBytesHex','hex'),proof->>'intentDigest');
 INSERT INTO control.runtime_target_disposition_admission(participant_id,privacy_domain_id,runtime_target_id,revision,binding,admission_digest)
 VALUES(pid,privacy,target,e.admission_revision+1,material,digest);
 RETURN QUERY SELECT material,digest;
END $$;
ALTER FUNCTION openpc.begin_expired_credential_denial_handover(bytea,bytea,bytea) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.begin_expired_credential_denial_handover(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.begin_expired_credential_denial_handover(bytea,bytea,bytea) TO openpc_control_worker;
`;

/** The pre-sign fence rechecks the actual ordinary rotation and original work.
 * A matching row is evidence only; this function never reconstructs a permit. */
export const expiredCredentialDenialIssuanceSql = `
CREATE OR REPLACE FUNCTION openpc.expired_credential_handover_issuance_matches(
 wanted_target uuid,wanted_revision bigint,wanted_digest text,wanted_worker text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE h control.runtime_expired_denial_handover;e control.runtime_expired_activation_denial;
 a control.runtime_target_disposition_admission;old control.runtime_target_disposition_admission;p record;
BEGIN
 SELECT * INTO h FROM control.runtime_expired_denial_handover x
 WHERE x.participant_id=openpc.current_participant_id() AND x.privacy_domain_id=openpc.current_privacy_domain_id()
  AND x.runtime_target_id=wanted_target AND x.admission_revision=wanted_revision AND x.admission_digest=wanted_digest;
 IF NOT FOUND OR h.proof->'intent'->>'purpose' IS DISTINCT FROM 'EXPIRED_OBSERVED_CREDENTIAL_DENIAL_HANDOVER_V1'
  OR h.proof->'intent'->'custody'->>'workerId' IS DISTINCT FROM wanted_worker
  OR (h.proof->'intent'->>'issuedAtMs')::numeric>extract(epoch from clock_timestamp())*1000
  OR (h.proof->'intent'->>'expiresAtMs')::numeric<=extract(epoch from clock_timestamp())*1000
 THEN RETURN false;END IF;
 SELECT * INTO STRICT e FROM control.runtime_expired_activation_denial x WHERE x.configuration_work_id=h.configuration_work_id
  AND x.participant_id=h.participant_id AND x.privacy_domain_id=h.privacy_domain_id AND x.runtime_target_id=h.runtime_target_id;
 SELECT * INTO STRICT old FROM control.runtime_target_disposition_admission x WHERE x.participant_id=e.participant_id
  AND x.privacy_domain_id=e.privacy_domain_id AND x.runtime_target_id=e.runtime_target_id AND x.revision=e.admission_revision;
 SELECT * INTO STRICT a FROM control.runtime_target_disposition_admission x WHERE x.participant_id=h.participant_id
  AND x.privacy_domain_id=h.privacy_domain_id AND x.runtime_target_id=h.runtime_target_id AND x.revision=h.admission_revision;
 IF h.abandoned_revision IS DISTINCT FROM e.admission_revision OR h.abandoned_admission_digest IS DISTINCT FROM e.admission_digest
  OR h.admission_revision IS DISTINCT FROM e.admission_revision+1 OR old.admission_digest IS DISTINCT FROM e.admission_digest
  OR a.admission_digest IS DISTINCT FROM h.admission_digest OR a.binding->>'action' IS DISTINCT FROM 'Withdraw'
  OR a.binding->'source' IS DISTINCT FROM old.binding->'source' OR a.binding->'target' IS DISTINCT FROM h.proof->'target'
  OR a.binding->'cause'->>'kind' IS DISTINCT FROM 'ExpiredObservedCredentialDenialHandover'
  OR a.binding->'cause'->'abandoned_target' IS DISTINCT FROM old.binding->'target'
  OR a.binding->'cause'->>'credential_rotation_operation_id' IS DISTINCT FROM h.proof->'intent'->'credentialTransition'->>'rotationOperationId'
  OR a.binding->'cause'->>'original_receipt_wire_digest' IS DISTINCT FROM e.proof->>'receiptWireDigest'
  OR a.revision IS DISTINCT FROM (SELECT max(x.revision)FROM control.runtime_target_disposition_admission x
   WHERE x.participant_id=a.participant_id AND x.privacy_domain_id=a.privacy_domain_id AND x.runtime_target_id=a.runtime_target_id)
 THEN RETURN false;END IF;
 SELECT * INTO STRICT p FROM openpc.expired_denial_credential_provenance(wanted_target,
  'sha256:'||(a.binding->'target'->>'certificate_digest'),(a.binding->'cause'->>'credential_rotation_operation_id')::uuid);
 RETURN p.binding->'target'=a.binding->'target' AND p.binding->'source'=a.binding->'source'
  AND p.binding->'credential_predecessor'=old.binding->'target';
END $$;
REVOKE ALL ON FUNCTION openpc.expired_credential_handover_issuance_matches(uuid,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_credential_handover_issuance_matches(uuid,bigint,text,text) TO openpc_control_owner,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.expired_operator_issuance_window_matches(target uuid,revision bigint,digest text,worker text)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM control.runtime_expired_activation_denial e
  WHERE e.participant_id=openpc.current_participant_id() AND e.privacy_domain_id=openpc.current_privacy_domain_id()
   AND e.runtime_target_id=$1 AND e.admission_revision=$2)
 THEN openpc.expired_denial_issuance_matches($1,$2,$3,$4)
 WHEN EXISTS(SELECT 1 FROM control.runtime_expired_denial_handover h
  WHERE h.participant_id=openpc.current_participant_id() AND h.privacy_domain_id=openpc.current_privacy_domain_id()
   AND h.runtime_target_id=$1 AND h.admission_revision=$2
   AND h.proof->'intent'->>'purpose'='EXPIRED_OBSERVED_CREDENTIAL_DENIAL_HANDOVER_V1')
 THEN openpc.expired_credential_handover_issuance_matches($1,$2,$3,$4)
 WHEN EXISTS(SELECT 1 FROM control.runtime_expired_denial_handover h
  WHERE h.participant_id=openpc.current_participant_id() AND h.privacy_domain_id=openpc.current_privacy_domain_id()
   AND h.runtime_target_id=$1 AND h.admission_revision=$2)
 THEN openpc.expired_handover_issuance_matches($1,$2,$3,$4) ELSE false END
$$;
REVOKE ALL ON FUNCTION openpc.expired_operator_issuance_window_matches(uuid,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_operator_issuance_window_matches(uuid,bigint,text,text) TO openpc_control_worker;
`;
