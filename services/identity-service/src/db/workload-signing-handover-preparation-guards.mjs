import { currentPlatformEnvelopeSql } from './current-platform-envelope.js';
import { authoritySnapshotColumns } from './authority-snapshot-columns.ts';

const actualRows = Object.entries(authoritySnapshotColumns)
  .map(([table, columns]) => {
    const projection = columns.map((column) => `'${column}',owner.${column}::text`).join(',');
    return `
 IF jsonb_typeof(snapshot->'dependencies'->'${table}') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'PC-AUTH-0005-HANDOVER-SNAPSHOT'; END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object(${projection}) ORDER BY owner.${columns[0]}),'[]'::jsonb) INTO expected
 FROM control.${table} owner WHERE owner.participant_id=NEW.participant_id AND owner.${columns[0]} IN
 (SELECT (dependency->>'${columns[0]}')::uuid FROM jsonb_array_elements(snapshot->'dependencies'->'${table}') dependency);
 IF snapshot->'dependencies'->'${table}' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-AUTH-0005-HANDOVER-SNAPSHOT-ROW'; END IF;`;
  })
  .join('\n');

/** Shared only by governed handover preparation and dispatch custody. */
export const workloadHandoverAuthorityValidationSql = `
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'INSERT' OR openpc.current_action_intent_id()<>'ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1'
  OR NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id)
  OR NEW.operation_id<>openpc.current_operation_id() OR NEW.authority_snapshot_digest<>sha256(NEW.authority_snapshot)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-HANDOVER-PREPARATION'; END IF;
 snapshot:=convert_from(NEW.authority_snapshot,'UTF8')::jsonb;
 IF snapshot->>'schema' IS DISTINCT FROM 'pc.control.precommit-authority-snapshot.v1'
  OR snapshot->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR snapshot->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR snapshot->>'operationId' IS DISTINCT FROM NEW.operation_id::text OR snapshot->>'decision' IS DISTINCT FROM 'ALLOW'
  OR jsonb_typeof(snapshot->'authorities') IS DISTINCT FROM 'array' OR jsonb_array_length(snapshot->'authorities')<>1
  OR (snapshot->>'recordedAtNs')::numeric>NEW.recorded_at_ns
  OR NEW.recorded_at_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000
 THEN RAISE EXCEPTION 'PC-AUTH-0005-HANDOVER-SNAPSHOT'; END IF;
${actualRows}
 bound:=snapshot->'authorities'->0;
 IF bound->>'principalId' IS DISTINCT FROM NEW.maker_principal_id::text
  OR bound->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR bound->>'actionIntentId' IS DISTINCT FROM openpc.current_action_intent_id() OR bound->>'resourceId' IS DISTINCT FROM '*'
  OR NOT (snapshot->'dependencies'->'participant' @> jsonb_build_array(jsonb_build_object('participant_id',NEW.participant_id::text,'state','ACTIVE','authority_epoch',bound->>'participantEpoch')))
  OR NOT (snapshot->'dependencies'->'privacy_domain' @> jsonb_build_array(jsonb_build_object('privacy_domain_id',NEW.privacy_domain_id::text,'state','ACTIVE')))
  OR NOT (snapshot->'dependencies'->'principal' @> jsonb_build_array(jsonb_build_object('principal_id',NEW.maker_principal_id::text,'state','ACTIVE','authority_epoch',bound->>'principalEpoch')))
  OR NOT (snapshot->'dependencies'->'session' @> jsonb_build_array(jsonb_build_object('session_id',bound->>'sessionId','principal_id',NEW.maker_principal_id::text,'state','ACTIVE','session_epoch',bound->>'sessionEpoch')))
  OR NOT (snapshot->'dependencies'->'assignment' @> jsonb_build_array(jsonb_build_object('assignment_id',bound->>'assignmentId','state','ACTIVE','row_version',bound->>'assignmentRowVersion')))
  OR NOT (snapshot->'dependencies'->'authority_envelope' @> jsonb_build_array(jsonb_build_object('authority_envelope_id',bound->>'authorityEnvelopeId','state','ACTIVE','authority_epoch',bound->>'authorityEpoch')))
 THEN RAISE EXCEPTION 'PC-AUTH-0005-HANDOVER-BOUND-PATH'; END IF;
 IF current_setting('transaction_isolation')<>'serializable' OR NOT EXISTS(
  WITH RECURSIVE path AS (
   SELECT a.principal_id terminal_principal_id,a.delegation_epoch,a.onward_delegation_depth remaining_depth,
    null::uuid delegation_id,array[]::uuid[] delegation_ids,array[a.principal_id] principal_ids
   FROM control.assignment a WHERE a.participant_id=NEW.participant_id AND a.assignment_id=(bound->>'assignmentId')::uuid
    AND a.state='ACTIVE' AND a.row_version::text=bound->>'assignmentRowVersion'
    AND a.authority_envelope_id=(bound->>'authorityEnvelopeId')::uuid AND a.valid_during @> clock_timestamp()
    AND openpc.current_action_intent_id()=any(a.action_intent_ids) AND NEW.privacy_domain_id::text=any(a.privacy_domain_ids)
    AND openpc.assignment_role_permits(a.participant_id,a.role_id,openpc.current_action_intent_id())
    AND openpc.assignment_group_permits(a.participant_id,a.authority_group_id,a.principal_id,a.valid_during)
    AND openpc.administration_resource_permits(a.resource_ids,'*',openpc.current_action_intent_id(),NEW.participant_id,NEW.maker_principal_id,(bound->>'sessionId')::uuid,(bound->>'authorityEnvelopeId')::uuid)
   UNION ALL
   SELECT d.delegate_principal_id,d.delegation_epoch,d.onward_delegation_depth,d.delegation_id,
    path.delegation_ids||d.delegation_id,path.principal_ids||d.delegate_principal_id
   FROM path JOIN control.delegation d ON d.participant_id=NEW.participant_id
    AND ((path.delegation_id IS NULL AND d.parent_assignment_id=(bound->>'assignmentId')::uuid) OR d.parent_delegation_id=path.delegation_id)
    AND d.grantor_principal_id=path.terminal_principal_id AND d.state='ACTIVE' AND d.valid_during @> clock_timestamp()
    AND openpc.current_action_intent_id()=any(d.action_intent_ids) AND NEW.privacy_domain_id::text=any(d.privacy_domain_ids)
    AND '*'=any(d.resource_ids) AND d.onward_delegation_depth<path.remaining_depth
   WHERE path.remaining_depth>0 AND cardinality(path.delegation_ids)<32 AND NOT d.delegation_id=any(path.delegation_ids)
  ) SELECT 1 FROM path JOIN control.authority_envelope e ON e.participant_id=NEW.participant_id
   AND e.authority_envelope_id=(bound->>'authorityEnvelopeId')::uuid AND e.state='ACTIVE' AND e.authority_epoch::text=bound->>'authorityEpoch'
   AND ${currentPlatformEnvelopeSql('e', false, true)} AND e.valid_from<=clock_timestamp() AND (e.valid_until IS NULL OR e.valid_until>clock_timestamp())
   AND openpc.current_action_intent_id()=any(e.action_intent_ids) AND NEW.privacy_domain_id::text=any(e.privacy_domain_ids)
   AND openpc.administration_resource_permits(e.resource_ids,'*',openpc.current_action_intent_id(),NEW.participant_id,NEW.maker_principal_id,(bound->>'sessionId')::uuid,e.authority_envelope_id)
   JOIN control.principal actor ON actor.participant_id=NEW.participant_id AND actor.principal_id=NEW.maker_principal_id
    AND actor.state='ACTIVE' AND actor.authority_epoch::text=bound->>'principalEpoch' AND actor.kind IN('USER','PLATFORM_OPERATOR')
   JOIN control.session session ON session.participant_id=NEW.participant_id AND session.session_id=(bound->>'sessionId')::uuid
    AND session.principal_id=NEW.maker_principal_id AND session.state='ACTIVE' AND session.session_epoch::text=bound->>'sessionEpoch'
    AND session.participant_epoch::text=bound->>'participantEpoch' AND session.authority_epoch::text=bound->>'principalEpoch'
    AND session.delegation_epoch::text=bound->>'delegationEpoch' AND session.idle_expires_at>clock_timestamp() AND session.absolute_expires_at>clock_timestamp()
   WHERE path.terminal_principal_id=NEW.maker_principal_id AND path.delegation_epoch::text=bound->>'delegationEpoch'
    AND NOT EXISTS(SELECT 1 FROM unnest(path.principal_ids) dependency(id) WHERE NOT EXISTS(
      SELECT 1 FROM control.principal principal WHERE principal.participant_id=NEW.participant_id AND principal.principal_id=dependency.id AND principal.state='ACTIVE'))
    AND NOT EXISTS(SELECT 1 FROM control.recovery_principal recovery WHERE recovery.participant_id=NEW.participant_id AND recovery.principal_id=NEW.maker_principal_id)
 ) THEN RAISE EXCEPTION 'PC-AUTH-0005-HANDOVER-LIVE-AUTHORITY'; END IF;
`;
export const workloadHandoverCurrentIssuerValidationSql = `
 IF source_document->>'schema' IS DISTINCT FROM 'pc.identity.workload-signing-handover.source.v1'
  OR source_document->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR source_document->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR NOT EXISTS(SELECT 1 FROM control.credential credential JOIN control.principal principal USING(participant_id,principal_id)
   JOIN control.participant participant USING(participant_id)
   WHERE credential.participant_id=NEW.participant_id AND credential.credential_id=(source_document->'issuer'->>'workloadCredentialId')::uuid
    AND credential.principal_id=(source_document->'issuer'->>'workloadPrincipalId')::uuid
    AND credential.state='ACTIVE' AND credential.kind='WORKLOAD_MTLS' AND principal.state='ACTIVE' AND principal.kind='WORKLOAD'
    AND participant.state='ACTIVE' AND credential.valid_from<=clock_timestamp() AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
    AND credential.credential_epoch::text=source_document->'issuer'->>'workloadCredentialEpoch'
    AND principal.authority_epoch::text=source_document->'issuer'->>'workloadPrincipalEpoch'
    AND participant.authority_epoch::text=source_document->'issuer'->>'workloadParticipantEpoch')
 THEN RAISE EXCEPTION 'PC-AUTH-0005-HANDOVER-CURRENT-ISSUER'; END IF;
`;

/** Initial preparation custody only. It confers no signer trust, approval,
 * provider dispatch permission or selector transition. Generated into new SQL. */
export const workloadSigningHandoverPreparationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_workload_signing_handover_preparation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE snapshot jsonb; expected jsonb; bound jsonb; source_document jsonb;
 owner_row control.workload_signing_handover; key_document jsonb; request_document jsonb; request_domain text;
BEGIN
${workloadHandoverAuthorityValidationSql}
 IF TG_TABLE_NAME='workload_signing_handover' THEN
  source_document:=NEW.source;
  IF NEW.request_canonical<>convert_to(openpc.signing_canonical_json(NEW.request),'UTF8')
   OR NEW.source_canonical<>convert_to(openpc.signing_canonical_json(NEW.source),'UTF8')
   OR NEW.request_digest<>sha256(convert_to('pc.identity.workload-signing-handover.request.v1','UTF8')||decode('00','hex')||NEW.request_canonical)
   OR NEW.source_digest<>sha256(convert_to('pc.identity.workload-signing-handover.source.v1','UTF8')||decode('00','hex')||NEW.source_canonical)
   OR NEW.request->>'actionIntentId' IS DISTINCT FROM openpc.current_action_intent_id()
   OR NEW.request->>'actionIntentDigest' IS DISTINCT FROM (SELECT 'sha256:'||encode(semantic_digest,'hex') FROM control.action_intent WHERE action_intent_id=openpc.current_action_intent_id())
   OR NEW.request->>'environmentId' IS DISTINCT FROM NEW.environment_id
   OR NEW.request->>'predecessorCredentialId' IS DISTINCT FROM NEW.predecessor_credential_id::text
   OR NEW.request->>'successorCredentialId' IS DISTINCT FROM NEW.successor_credential_id::text
   OR source_document->'issuer'->>'workloadCredentialId' IS DISTINCT FROM NEW.successor_credential_id::text
   OR source_document->'issuer'->>'workloadPrincipalId' IS DISTINCT FROM NEW.workload_principal_id::text
   OR source_document->'provenance'->>'predecessorCredentialId' IS DISTINCT FROM NEW.predecessor_credential_id::text
   OR source_document->'provenance'->>'successorCredentialId' IS DISTINCT FROM NEW.successor_credential_id::text
   OR source_document->'provenance'->>'credentialRotationOperationId' IS DISTINCT FROM NEW.request->>'credentialRotationOperationId'
   OR jsonb_array_length(source_document->'keys')<>jsonb_array_length(NEW.request->'replacements')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.request->'replacements') replacement
    WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(source_document->'keys') old_key
      WHERE old_key-ARRAY['oldTrustPreimageBase64','oldCredentialEpoch','oldKeyValidFromNs','oldKeyValidUntilNs']=replacement))
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-REQUEST-CUSTODY'; END IF;
 ELSE
  IF NEW.stage<>'PREPARATION' OR NEW.generation_id IS NOT NULL OR NEW.preparation_attempt_id IS NOT NULL
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-PREPARATION-STAGE'; END IF;
  SELECT * INTO STRICT owner_row FROM control.workload_signing_handover
   WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND handover_id=NEW.handover_id
    AND maker_principal_id=NEW.maker_principal_id;
  source_document:=owner_row.source;
  SELECT value INTO STRICT key_document FROM jsonb_array_elements(source_document->'keys')
   WHERE value->>'oldFingerprint'=NEW.predecessor_fingerprint;
  request_document:=NEW.attempt->'request';
  request_domain:=CASE WHEN NEW.attempt->>'purpose'='pc.cose.identity-authority-envelope.v1'
    THEN 'pc.identity.envelope-key-rotation-request.v1' ELSE 'pc.control.signing-provider-request.v1' END;
  IF NEW.binding_canonical<>convert_to(openpc.signing_canonical_json(NEW.binding),'UTF8')
   OR NEW.attempt_canonical<>convert_to(openpc.signing_canonical_json(NEW.attempt),'UTF8')
   OR NEW.binding_digest<>sha256(convert_to('pc.identity.workload-signing-handover.provider-binding.v1','UTF8')||decode('00','hex')||NEW.binding_canonical)
   OR NEW.attempt_digest<>sha256(convert_to('pc.identity.workload-signing-handover.provider-attempt.v1','UTF8')||decode('00','hex')||NEW.attempt_canonical)
   OR NEW.binding->>'participantId' IS DISTINCT FROM NEW.participant_id::text
   OR NEW.binding->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
   OR NEW.binding->>'environmentId' IS DISTINCT FROM owner_row.environment_id
   OR NEW.binding->>'handoverId' IS DISTINCT FROM NEW.handover_id::text
   OR NEW.binding->>'sourceDigest' IS DISTINCT FROM 'sha256:'||encode(owner_row.source_digest,'hex')
   OR NEW.binding->>'successorCredentialId' IS DISTINCT FROM owner_row.successor_credential_id::text
   OR NEW.binding->>'successorCredentialEpoch' IS DISTINCT FROM source_document->'issuer'->>'workloadCredentialEpoch'
   OR NEW.binding->>'participantEpoch' IS DISTINCT FROM source_document->'issuer'->>'workloadParticipantEpoch'
   OR NEW.binding->>'principalEpoch' IS DISTINCT FROM source_document->'issuer'->>'workloadPrincipalEpoch'
   OR NEW.binding->>'providerId' IS DISTINCT FROM NEW.provider_id
   OR NEW.binding->'replacement' IS DISTINCT FROM key_document-ARRAY['oldTrustPreimageBase64','oldCredentialEpoch','oldKeyValidFromNs','oldKeyValidUntilNs']
   OR NEW.attempt->>'handoverId' IS DISTINCT FROM NEW.handover_id::text
   OR NEW.attempt->>'sourceDigest' IS DISTINCT FROM 'sha256:'||encode(owner_row.source_digest,'hex')
   OR NEW.attempt->>'predecessorFingerprint' IS DISTINCT FROM NEW.predecessor_fingerprint
   OR NEW.attempt->>'providerId' IS DISTINCT FROM NEW.provider_id
   OR NEW.attempt->>'bindingDigest' IS DISTINCT FROM 'sha256:'||encode(NEW.binding_digest,'hex')
   OR NEW.attempt->>'signerRole' IS DISTINCT FROM key_document->>'signerRole'
   OR NEW.attempt->>'purpose' IS DISTINCT FROM key_document->>'purpose'
   OR NEW.attempt->>'requestDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(request_domain,'UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json(request_document),'UTF8')),'hex')
   OR request_document->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text
   OR request_document->>'operationId' IS DISTINCT FROM NEW.operation_id::text
   OR request_document->>'participantId' IS DISTINCT FROM NEW.participant_id::text
   OR request_document->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
   OR request_document->>'environmentId' IS DISTINCT FROM owner_row.environment_id
   OR request_document->>'workloadCredentialId' IS DISTINCT FROM owner_row.successor_credential_id::text
   OR request_document->>'callerWorkloadCredentialId' IS DISTINCT FROM owner_row.successor_credential_id::text
   OR request_document->>'reference' IS DISTINCT FROM key_document->>'newReference'
   OR request_document->>'secretClass' IS DISTINCT FROM 'SECRET-SIGNING-KEY'
   OR request_document->>'purpose' IS DISTINCT FROM key_document->>'purpose'
   OR (request_document->>'reference') IS DISTINCT FROM regexp_replace(request_document->>'reference','#[^#]+$','')||'#'||(request_document->>'version')
   OR (NEW.attempt->>'purpose'='pc.cose.identity-authority-envelope.v1' AND (
     request_document->>'method' IS DISTINCT FROM 'PREPARE' OR request_document->>'rotationId' IS DISTINCT FROM NEW.handover_id::text
     OR request_document->>'workloadCredentialEpoch' IS DISTINCT FROM source_document->'issuer'->>'workloadCredentialEpoch'
     OR request_document->>'issuerParticipantEpoch' IS DISTINCT FROM source_document->'issuer'->>'workloadParticipantEpoch'
     OR request_document->>'issuerPrincipalEpoch' IS DISTINCT FROM source_document->'issuer'->>'workloadPrincipalEpoch'
     OR request_document->>'governanceDigest' IS DISTINCT FROM 'sha256:'||encode(owner_row.source_digest,'hex')))
   OR (NEW.attempt->>'purpose'<>'pc.cose.identity-authority-envelope.v1' AND request_document->>'method' IS DISTINCT FROM 'INSPECT')
  THEN RAISE EXCEPTION 'DATA-6021-HANDOVER-ATTEMPT-CUSTODY'; END IF;
 END IF;
${workloadHandoverCurrentIssuerValidationSql}
 RETURN NEW;
END $$;
CREATE TRIGGER workload_handover_preparation_guard BEFORE INSERT ON control.workload_signing_handover
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_signing_handover_preparation();
CREATE TRIGGER workload_handover_attempt_guard BEFORE INSERT ON control.workload_signing_handover_attempt
 FOR EACH ROW WHEN(NEW.stage='PREPARATION') EXECUTE FUNCTION openpc.guard_workload_signing_handover_preparation();
`;
