/** Source facts and purpose admission remain independent of runtime authority.
 * The private owner observes only the separately installed exact binding. */
export const discoveryCertificateRecoveryGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.discovery_certificate_recovery_source(p_enrollment uuid,p_case uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT jsonb_build_object(
  'participantId',e.participant_id::text,'privacyDomainId',e.privacy_domain_id::text,
  'participantState',participant.state::text,'privacyState',privacy.state::text,
  'targetId',target.runtime_target_id::text,'targetParticipantId',target.participant_id::text,
  'targetPrivacyDomainId',target.privacy_domain_id::text,'targetRevision',target.revision::text,
  'requiresAuthenticatedDiscovery',target.requires_authenticated_discovery,
  'workloadPrincipalId',principal.principal_id::text,'workloadPrincipalParticipantId',principal.participant_id::text,
  'workloadPrincipalState',principal.state::text,'workloadPrincipalKind',principal.kind::text,
  'workloadPrincipalEpoch',principal.authority_epoch::text,
  'credentialId',credential.credential_id::text,'credentialParticipantId',credential.participant_id::text,
  'credentialPrincipalId',credential.principal_id::text,'credentialState',credential.state::text,
  'credentialKind',credential.kind::text,'credentialRevision',credential.row_version::text,
  'credentialEpoch',credential.credential_epoch::text,
  'certificateFingerprint','sha256:'||encode(credential.secret_fingerprint,'hex'),
  'certificateBytesDigest','sha256:'||encode(sha256(credential.certificate_der),'hex'),
  'publicKeyDigest','sha256:'||encode(credential.public_key_digest,'hex'),
  'publicKeyBytesDigest','sha256:'||encode(sha256(credential.public_key_spki_der),'hex'),
  'issuer',credential.issuer,'subject',credential.subject,'audience',credential.audience,
  'notBefore',credential.valid_from,'notAfter',credential.valid_until,'now',clock_timestamp(),
  'successorExists',exists(select 1 from control.credential successor where successor.participant_id=e.participant_id
    and successor.credential_id::text=e.document#>>'{certificateRecovery,successorCredentialId}'),
  'competingSuccessor',exists(select 1 from control.credential successor where successor.participant_id=e.participant_id
    and successor.rotated_from_credential_id=credential.credential_id)
   or exists(select 1 from control.discovery_certificate_issuance attempt where attempt.participant_id=e.participant_id
    and attempt.predecessor_credential_id=credential.credential_id and attempt.state<>'REJECTED'
    and attempt.recovery_id is distinct from p_case))
 FROM control.platform_recovery_enrollment e
 JOIN control.participant participant on participant.participant_id=e.participant_id and participant.state='ACTIVE'
 JOIN control.privacy_domain privacy on privacy.participant_id=e.participant_id and privacy.privacy_domain_id=e.privacy_domain_id and privacy.state='ACTIVE'
 JOIN control.platform_context root on root.platform_context_id=e.platform_context_id and root.owner_participant_id=e.participant_id
  and root.state='ACTIVE' and root.authority_epoch=e.root_epoch and root.row_version=e.root_revision
 JOIN control.runtime_target target on target.participant_id=e.participant_id and target.privacy_domain_id=e.privacy_domain_id
  and target.runtime_target_id::text=e.document#>>'{certificateRecovery,targetId}'
 JOIN control.principal principal on principal.participant_id=e.participant_id
  and principal.principal_id::text=e.document#>>'{certificateRecovery,workloadPrincipalId}'
 JOIN control.credential credential on credential.participant_id=e.participant_id and credential.principal_id=principal.principal_id
  and credential.credential_id::text=e.document#>>'{certificateRecovery,predecessorCredentialId}'
 WHERE e.enrollment_id=p_enrollment and e.state='ACTIVE'
  and e.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
  and e.document#>>'{certificateRecovery,purpose}'='DISCOVERY_CERTIFICATE_REPLACEMENT'
  and openpc.platform_recovery_source_root_current(e)
  and openpc.matches_participant(e.participant_id) and openpc.matches_privacy(e.privacy_domain_id)
  and e.valid_from<=clock_timestamp() and e.valid_until>clock_timestamp()
  and (e.document->>'assurance'<>'LOCAL_QA_VIRTUAL_AUTHENTICATOR' or current_setting('openpc.local_qa_runtime',true)='1')
  and (p_case is null or exists(select 1 from control.platform_recovery_case c where c.recovery_id=p_case
   and c.enrollment_id=e.enrollment_id and c.participant_id=e.participant_id and c.privacy_domain_id=e.privacy_domain_id
   and c.enrollment_revision=e.row_version and c.enrollment_digest=e.document_digest
   and c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
   and c.intent->'certificateRecovery'=e.document->'certificateRecovery'))
$$;
REVOKE ALL ON FUNCTION openpc.discovery_certificate_recovery_source(uuid,uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.discovery_certificate_recovery_current(p_enrollment uuid,p_case uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE source jsonb; binding jsonb;
BEGIN
 SELECT openpc.discovery_certificate_recovery_source(p_enrollment,p_case) INTO source;
 IF source IS NULL THEN RETURN false; END IF;
 SELECT e.document->'certificateRecovery' INTO binding FROM control.platform_recovery_enrollment e
  WHERE e.enrollment_id=p_enrollment and openpc.matches_participant(e.participant_id) and openpc.matches_privacy(e.privacy_domain_id);
 RETURN coalesce(source->>'participantState'='ACTIVE' and source->>'privacyState'='ACTIVE'
  and source->>'targetId'=binding->>'targetId' and source->>'targetRevision'=binding->>'targetRevision'
  and source->>'requiresAuthenticatedDiscovery'='true'
  and source->>'workloadPrincipalId'=binding->>'workloadPrincipalId' and source->>'workloadPrincipalState'='ACTIVE'
  and source->>'workloadPrincipalKind'='WORKLOAD' and source->>'workloadPrincipalEpoch'=binding->>'workloadPrincipalEpoch'
  and source->>'credentialId'=binding->>'predecessorCredentialId' and source->>'credentialState'='ACTIVE'
  and source->>'credentialKind'='WORKLOAD_MTLS' and source->>'credentialRevision'=binding->>'predecessorRevision'
  and source->>'credentialEpoch'=binding->>'predecessorEpoch' and (source->>'credentialEpoch')::numeric>0
  and source->>'certificateFingerprint'=binding->>'predecessorFingerprint'
  and source->>'certificateBytesDigest'=binding->>'predecessorFingerprint'
  and source->>'publicKeyDigest'=binding->>'predecessorPublicKeyDigest'
  and source->>'publicKeyBytesDigest'=binding->>'predecessorPublicKeyDigest' and source->>'issuer'=binding->>'issuer'
  and source->>'subject'='urn:openpc:participant:'||(source->>'participantId')||':workload:'||(binding->>'targetId')
  and source->>'audience'='urn:openpc:workload:'||(binding->>'targetId')
  and (source->>'notAfter')::timestamptz=(binding->>'predecessorNotAfter')::timestamptz
  and (source->>'notAfter')::timestamptz<=clock_timestamp()
  and (source->>'notBefore')::timestamptz<(source->>'notAfter')::timestamptz
  and (source->>'notBefore')::timestamptz<=clock_timestamp()
  and source->>'successorExists'='false' and source->>'competingSuccessor'='false',false);
END $$;
REVOKE ALL ON FUNCTION openpc.discovery_certificate_recovery_current(uuid,uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.lock_discovery_certificate_recovery_source(p_enrollment uuid,p_case uuid)
RETURNS TABLE(source jsonb) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE enrolled control.platform_recovery_enrollment;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO enrolled FROM control.platform_recovery_enrollment e WHERE e.enrollment_id=p_enrollment
  and openpc.matches_participant(e.participant_id) and openpc.matches_privacy(e.privacy_domain_id)
  and e.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment';
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-RECOVERY'; END IF;
 PERFORM 1 FROM control.principal p WHERE p.participant_id=enrolled.participant_id
  and p.principal_id::text=enrolled.document#>>'{certificateRecovery,workloadPrincipalId}' FOR SHARE;
 PERFORM 1 FROM control.credential c WHERE c.participant_id=enrolled.participant_id
  and c.credential_id::text=enrolled.document#>>'{certificateRecovery,predecessorCredentialId}' FOR SHARE;
 IF NOT openpc.discovery_certificate_recovery_current(p_enrollment,p_case) THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-RECOVERY'; END IF;
 RETURN QUERY SELECT openpc.discovery_certificate_recovery_source(p_enrollment,p_case);
END $$;
REVOKE ALL ON FUNCTION openpc.lock_discovery_certificate_recovery_source(uuid,uuid) FROM PUBLIC;

DROP POLICY IF EXISTS discovery_recovery_target_read ON control.runtime_target;
CREATE POLICY discovery_recovery_target_read ON control.runtime_target FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) and openpc.matches_privacy(privacy_domain_id)
  and exists(select 1 from control.platform_recovery_enrollment e where e.participant_id=runtime_target.participant_id
    and e.privacy_domain_id=runtime_target.privacy_domain_id and e.state='ACTIVE'
    and e.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
    and e.document#>>'{certificateRecovery,targetId}'=runtime_target.runtime_target_id::text
    and openpc.platform_recovery_installation_source_current(e.enrollment_id)));

-- Definer source predicates retain FORCE RLS and exact purpose/scoped reads.
DROP POLICY IF EXISTS discovery_recovery_case_source_read ON control.platform_recovery_case;
CREATE POLICY discovery_recovery_case_source_read ON control.platform_recovery_case FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) and openpc.matches_privacy(privacy_domain_id)
  and intent->>'schema'='pc.identity.discovery-certificate-recovery-intent');
DROP POLICY IF EXISTS discovery_recovery_issuance_source_read ON control.discovery_certificate_issuance;
CREATE POLICY discovery_recovery_issuance_source_read ON control.discovery_certificate_issuance FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) and openpc.matches_privacy(privacy_domain_id));
DROP POLICY IF EXISTS discovery_recovery_role_source_read ON control.authority_role;
CREATE POLICY discovery_recovery_role_source_read ON control.authority_role FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) and exists(select 1 from control.platform_recovery_enrollment e
  join control.platform_scope_replacement original on original.replacement_id=e.expired_replacement_id
   and original.participant_id=e.participant_id and original.privacy_domain_id=e.privacy_domain_id and original.state='COMMITTED'
  where e.participant_id=authority_role.participant_id and openpc.matches_privacy(e.privacy_domain_id) and e.state='ACTIVE'
   and e.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
   and openpc.platform_recovery_installation_source_current(e.enrollment_id)
   and exists(select 1 from jsonb_array_elements(original.candidate->'administrators') administrator
    where administrator->>'roleId'=authority_role.authority_role_id::text)));

CREATE OR REPLACE FUNCTION openpc.discovery_certificate_recovery_administrators_current(p_enrollment uuid,p_administrators jsonb,p_bindings jsonb)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
 SELECT coalesce(jsonb_array_length(p_administrators)=2
  and (select count(distinct a->>'principalId') from jsonb_array_elements(p_administrators) a)=2
  and NOT EXISTS(select 1 from jsonb_array_elements(p_administrators) administrator
   where NOT EXISTS(select 1 from control.platform_recovery_enrollment e
    left join control.platform_scope_replacement original on original.replacement_id=e.expired_replacement_id
     and original.participant_id=e.participant_id and original.privacy_domain_id=e.privacy_domain_id and original.state='COMMITTED'
    join lateral jsonb_array_elements(case when e.source_purpose='ROOT_EXPIRY_RECOVERY'
      then e.document#>'{source,originalAdministrators}' else original.candidate->'administrators' end) declared
     on declared->>'principalId'=administrator->>'principalId'
    join control.principal principal on principal.participant_id=e.participant_id and principal.principal_id::text=declared->>'principalId'
     and principal.state='ACTIVE' and principal.kind in ('USER','PLATFORM_OPERATOR')
    join control.authority_envelope expired on expired.participant_id=e.participant_id
     and expired.authority_envelope_id::text=declared->>'envelopeId' and expired.state='ACTIVE'
     and expired.platform_context_id=e.platform_context_id
     and expired.platform_authority_epoch=case when e.source_purpose='ROOT_EXPIRY_RECOVERY'
       then (select (ancestor.document->>'rootEpoch')::numeric from control.root_expiry_recovery_enrollment ancestor
         where ancestor.participant_id=e.participant_id and ancestor.privacy_domain_id=e.privacy_domain_id
          and ancestor.enrollment_id::text=coalesce(e.document#>>'{source,ancestorReceipts,-1,enrollmentId}',e.document#>>'{source,enrollmentId}'))
       else e.root_epoch end
     and (e.source_purpose='ROOT_EXPIRY_RECOVERY' or expired.valid_until<=clock_timestamp())
    join control.assignment assignment on assignment.participant_id=e.participant_id
     and assignment.assignment_id::text=declared->>'assignmentId' and assignment.authority_envelope_id=expired.authority_envelope_id
     and assignment.principal_id=principal.principal_id and assignment.state='ACTIVE'
     and (e.source_purpose='ROOT_EXPIRY_RECOVERY' or upper(assignment.valid_during)<=clock_timestamp())
    join control.authority_role role on role.participant_id=e.participant_id and role.authority_role_id::text=declared->>'roleId'
     and role.state='ACTIVE' and role.row_version::text=declared->>'expectedRoleRevision'
    where e.enrollment_id=p_enrollment and openpc.matches_participant(e.participant_id) and openpc.matches_privacy(e.privacy_domain_id)
     and e.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
     and openpc.platform_recovery_source_root_current(e) and openpc.platform_recovery_original_administrators_current(e)
     and administrator->>'principalId' IN (e.document#>>'{administratorPrincipalIds,0}',e.document#>>'{administratorPrincipalIds,1}')
     and administrator->>'roleId'=declared->>'roleId' and administrator->>'roleRevision'=role.row_version::text
     and administrator->>'roleDigest'=declared->>'roleDigest'
     and administrator->>'roleDigest'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
       'domain','pc.identity.envelope-role-binding.v1','participantId',e.participant_id::text,'role',jsonb_build_object(
        'roleId',role.role_id,'version',role.row_version::text,'actions',role.action_intent_ids,'origin',role.origin,
        'createdByPrincipalId',role.created_by_principal_id::text,'creatorParticipantId',role.creator_participant_id::text,
        'bootstrapMandateId',role.bootstrap_mandate_id::text,'bootstrapPlatformParticipantId',role.bootstrap_platform_participant_id::text))),'UTF8')),'hex')
     and role.action_intent_ids @> ARRAY['ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
      'ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1','ACT-OPERATIONS_READ_OPERATION-V1',
      'ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1']::text[]
     and (case when e.source_purpose='ROOT_EXPIRY_RECOVERY' then declared#>'{usable,administration,actionIntentIds}'
       else original.candidate#>'{successorScope,administration,actionIntentIds}' end) @> to_jsonb(ARRAY['ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
      'ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1','ACT-OPERATIONS_READ_OPERATION-V1',
      'ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1']::text[])
     and (e.source_purpose<>'ROOT_EXPIRY_RECOVERY' or (declared#>'{grantable,administration,actionIntentIds}') @>
       to_jsonb(ARRAY['ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
        'ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1','ACT-OPERATIONS_READ_OPERATION-V1',
        'ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1']::text[]))
     and (e.source_purpose='ROOT_EXPIRY_RECOVERY' or (
       (declared#>>'{usable,validUntilNs}')::numeric<=floor(extract(epoch from clock_timestamp())*1000000000)
       and (declared#>>'{grantable,validUntilNs}')::numeric<=floor(extract(epoch from clock_timestamp())*1000000000)))
     and administrator->'riskClasses'=(select jsonb_agg(risk.value order by risk.ordinality)
      from jsonb_array_elements(declared#>'{usable,administration,riskClasses}') with ordinality risk(value,ordinality)
      where e.source_purpose='ROOT_EXPIRY_RECOVERY' or
        (original.candidate#>'{successorScope,administration,riskClasses}') @> jsonb_build_array(risk.value))
     and jsonb_array_length(administrator->'riskClasses')>0
     and ((p_bindings is null and principal.authority_epoch::text=administrator->>'principalEpoch')
      or (jsonb_array_length(p_bindings)=2 and principal.authority_epoch=(administrator->>'principalEpoch')::numeric+1
       and exists(select 1 from jsonb_array_elements(p_bindings) binding
        where binding->>'principalId'=principal.principal_id::text and binding->>'principalEpoch'=principal.authority_epoch::text)))))
 ,false)
$$;
REVOKE ALL ON FUNCTION openpc.discovery_certificate_recovery_administrators_current(uuid,jsonb,jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.discovery_certificate_recovery_binding_current(p_intent jsonb,p_privacy uuid,p_binding jsonb,p_activated timestamptz,p_until timestamptz)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
 SELECT coalesce(EXISTS(select 1 from jsonb_array_elements(p_intent->'administrators') administrator
  join control.authority_role role on role.participant_id=openpc.current_participant_id()
   and role.authority_role_id::text=administrator->>'roleId' and role.state='ACTIVE'
   and role.row_version::text=administrator->>'roleRevision'
  where p_intent->>'schemaVersion' in ('1','2') and p_binding->>'principalId'=administrator->>'principalId'
   and (p_binding->>'principalEpoch')::numeric=(administrator->>'principalEpoch')::numeric+1
   and (p_binding#>>'{permissions,validFrom}')::timestamptz=p_activated
   and (p_binding#>>'{permissions,validUntil}')::timestamptz=p_until
   and p_binding->'permissions'=jsonb_build_object(
    'roleId',role.role_id,'validFrom',p_binding#>>'{permissions,validFrom}','validUntil',p_binding#>>'{permissions,validUntil}',
    'riskClasses',administrator->'riskClasses','privacyDomainIds',jsonb_build_array(p_privacy::text),
    'capabilityIds','[]'::jsonb,'makerCheckerRequired',true,'stepUpRequired',true,'onwardDelegationDepth',0,
    'actionIntentIds',case when p_intent->>'schemaVersion'='2' then jsonb_build_array('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1','ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1','ACT-OPERATIONS_READ_OPERATION-V1','ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1') else jsonb_build_array('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
     'ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1','ACT-OPERATIONS_READ_OPERATION-V1',
     'ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1') end,
    'resourceIds',(select jsonb_agg(resource order by resource collate "C") from (select distinct unnest(ARRAY[
     p_intent#>>'{certificateRecovery,targetId}',p_intent#>>'{certificateRecovery,workloadPrincipalId}',
     p_intent#>>'{certificateRecovery,predecessorCredentialId}',p_intent#>>'{certificateRecovery,successorCredentialId}',
     administrator->>'principalId','urn:openpc:self-session:'||(administrator->>'principalId')]) resource) resources)))
 ,false)
$$;
REVOKE ALL ON FUNCTION openpc.discovery_certificate_recovery_binding_current(jsonb,uuid,jsonb,timestamptz,timestamptz) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.guard_discovery_certificate_recovery_case()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
DECLARE source control.platform_recovery_enrollment;
BEGIN
 IF NEW.intent->>'schema'<>'pc.identity.discovery-certificate-recovery-intent' THEN RETURN NEW; END IF;
 -- Historical closure preserves the immutable case and activation bytes under
 -- the shared guard. Completion retains its current administrator checks.
 SELECT * INTO source FROM control.platform_recovery_enrollment e WHERE e.enrollment_id=NEW.enrollment_id
  and e.participant_id=NEW.participant_id and e.privacy_domain_id=NEW.privacy_domain_id;
 IF NOT FOUND or source.document->>'schema' IS DISTINCT FROM 'pc.identity.discovery-certificate-recovery-enrollment'
  or NEW.intent->>'schemaVersion' not in ('1','2')
  or (NEW.state NOT IN ('REVOKED','EXPIRED') and NEW.intent->>'schemaVersion'='2'
   and NOT openpc.discovery_certificate_resume_administrators_current(NEW.enrollment_id))
  or NEW.intent->'certificateRecovery' IS DISTINCT FROM source.document->'certificateRecovery'
  or NEW.intent-ARRAY['schema','schemaVersion','recoveryId','enrollmentId','enrollmentRevision','enrollmentDigest',
    'certificateRecovery','administrators','validFrom','validUntil','lifetimes']<>'{}'::jsonb
  or NOT (NEW.intent ?& ARRAY['certificateRecovery','administrators','lifetimes'])
  or NEW.planned_record_ids<>'[]'::jsonb THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-RECOVERY'; END IF;
 IF NEW.state IN ('DRAFT','REQUESTED','ACTIVE') and (NOT openpc.discovery_certificate_recovery_current(NEW.enrollment_id,null)
  or NOT openpc.discovery_certificate_recovery_administrators_current(NEW.enrollment_id,NEW.intent->'administrators',
   case when NEW.state='ACTIVE' then NEW.lease_bindings else null end)) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-RECOVERY'; END IF;
 IF NEW.state='ACTIVE' and (jsonb_array_length(NEW.lease_bindings)<>2
  or (select count(distinct binding->>'principalId') from jsonb_array_elements(NEW.lease_bindings) binding)<>2
  or EXISTS(select 1 from jsonb_array_elements(NEW.lease_bindings) binding where NOT
    openpc.discovery_certificate_recovery_binding_current(NEW.intent,NEW.privacy_domain_id,binding,NEW.activated_at,NEW.valid_until))) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-RECOVERY'; END IF;
 IF NEW.state='COMPLETED' and (NEW.completion_operation_id IS DISTINCT FROM openpc.current_operation_id()
  or NOT EXISTS(select 1 from control.discovery_certificate_issuance issuance where issuance.participant_id=NEW.participant_id
   and issuance.privacy_domain_id=NEW.privacy_domain_id and issuance.recovery_id=NEW.recovery_id and issuance.state='COMMITTED'
   and issuance.committed_operation_id=NEW.completion_operation_id
   and NEW.completion_result=jsonb_build_object('issuanceId',issuance.issuance_id::text,'operationId',issuance.committed_operation_id::text,
    'predecessorCredentialId',issuance.predecessor_credential_id::text,'successorCredentialId',issuance.successor_credential_id::text,
    'certificateFingerprint','sha256:'||encode(issuance.certificate_fingerprint,'hex')))) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-RECOVERY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS platform_recovery_discovery_case_guard ON control.platform_recovery_case;
CREATE TRIGGER platform_recovery_discovery_case_guard BEFORE INSERT OR UPDATE ON control.platform_recovery_case
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_certificate_recovery_case();

CREATE OR REPLACE FUNCTION openpc.guard_discovery_certificate_issuance()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
DECLARE intent jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUANCE'; END IF;
 SELECT c.intent INTO intent FROM control.platform_recovery_case c WHERE c.recovery_id=NEW.recovery_id
  and c.participant_id=NEW.participant_id and c.privacy_domain_id=NEW.privacy_domain_id;
 IF intent IS NULL or intent->>'schema'<>'pc.identity.discovery-certificate-recovery-intent'
  or NEW.request_digest<>sha256(convert_to(openpc.signing_canonical_json(NEW.request),'UTF8'))
  or NEW.predecessor_credential_id::text IS DISTINCT FROM intent#>>'{certificateRecovery,predecessorCredentialId}'
  or NEW.successor_credential_id::text IS DISTINCT FROM intent#>>'{certificateRecovery,successorCredentialId}'
  or NEW.request IS DISTINCT FROM jsonb_build_object('credentialId',NEW.successor_credential_id::text,
   'participantId',NEW.participant_id::text,'principalId',intent#>>'{certificateRecovery,workloadPrincipalId}',
   'workloadId','urn:openpc:workload:'||(intent#>>'{certificateRecovery,targetId}'),
   'publicKeySpkiDer',intent#>>'{certificateRecovery,successorPublicKeySpkiDer}')
 THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUANCE'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PREPARED' or NEW.row_version<>1 or NOT EXISTS(select 1 from control.mutation_candidate candidate
    join control.approval_request approval on approval.participant_id=candidate.participant_id
     and approval.privacy_domain_id=candidate.privacy_domain_id and approval.subject_id=candidate.mutation_candidate_id
     and approval.subject_digest=candidate.candidate_digest and approval.subject_version=candidate.expected_revision
     and approval.maker_principal_id=candidate.maker_principal_id and approval.state='APPROVED'
     and approval.expires_at>clock_timestamp() and approval.approval_request_id=NEW.approval_request_id
    join control.authority_envelope envelope on envelope.participant_id=candidate.participant_id
     and envelope.authority_envelope_id=candidate.maker_authority_envelope_id and envelope.recovery_case_id=NEW.recovery_id
     and envelope.representation='RECOVERY_V1' and openpc.platform_recovery_envelope_current(envelope.authority_envelope_id)
    where candidate.participant_id=NEW.participant_id and candidate.privacy_domain_id=NEW.privacy_domain_id
     and candidate.mutation_candidate_id=NEW.mutation_candidate_id and candidate.candidate_digest=NEW.candidate_digest
     and candidate.state='APPROVED' and candidate.expires_at>clock_timestamp()
     and candidate.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'
     and candidate.resource_id=NEW.predecessor_credential_id
     and candidate.expected_revision=(intent#>>'{certificateRecovery,predecessorRevision}')::numeric
     and candidate.candidate_document=jsonb_build_object('replacedCredentialId',NEW.predecessor_credential_id::text,
       'credentialId',NEW.successor_credential_id::text,'publicKeySpkiDer',intent#>>'{certificateRecovery,successorPublicKeySpkiDer}'))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUANCE'; END IF;
 ELSE
  IF NEW.row_version<>OLD.row_version+1 or NEW.updated_at<=OLD.updated_at
   or (to_jsonb(NEW)-ARRAY['state','row_version','updated_at','certificate_der','certificate_fingerprint','failure_code','committed_operation_id'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','row_version','updated_at','certificate_der','certificate_fingerprint','failure_code','committed_operation_id'])
   or NOT ((OLD.state='PREPARED' and NEW.state IN ('ISSUING','REJECTED'))
     or (OLD.state='ISSUING' and NEW.state IN ('OBSERVED','AMBIGUOUS','REJECTED'))
     or (OLD.state='AMBIGUOUS' and NEW.state='ISSUING' and OLD.replay_profile='IMMUTABLE_REQUEST_RESPONSE')
     or (OLD.state='OBSERVED' and NEW.state='COMMITTED'))
   or (OLD.state='OBSERVED' and (NEW.certificate_der,NEW.certificate_fingerprint) IS DISTINCT FROM (OLD.certificate_der,OLD.certificate_fingerprint))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUANCE'; END IF;
 END IF;
 IF NEW.state='COMMITTED' and (NEW.committed_operation_id IS DISTINCT FROM openpc.current_operation_id()
  or NOT EXISTS(select 1 from control.credential successor join control.credential predecessor
    on predecessor.participant_id=successor.participant_id and predecessor.credential_id=NEW.predecessor_credential_id
   where successor.participant_id=NEW.participant_id and successor.credential_id=NEW.successor_credential_id
    and successor.rotated_from_credential_id=predecessor.credential_id and predecessor.state='REVOKED'
    and successor.state='ACTIVE' and successor.kind='WORKLOAD_MTLS' and successor.certificate_der=NEW.certificate_der
    and successor.secret_fingerprint=NEW.certificate_fingerprint)) THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUANCE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS discovery_certificate_issuance_guard ON control.discovery_certificate_issuance;
CREATE TRIGGER discovery_certificate_issuance_guard BEFORE INSERT OR UPDATE OR DELETE ON control.discovery_certificate_issuance
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_certificate_issuance();

`;

export const discoveryCertificateRecoveryGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.discovery_certificate_recovery_binding_current(jsonb,uuid,jsonb,timestamptz,timestamptz) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.discovery_certificate_recovery_administrators_current(uuid,jsonb,jsonb) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.discovery_certificate_recovery_source(uuid,uuid),openpc.discovery_certificate_recovery_current(uuid,uuid),
 openpc.lock_discovery_certificate_recovery_source(uuid,uuid) TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
GRANT SELECT,INSERT,UPDATE ON control.discovery_certificate_issuance TO openpc_control_runtime,openpc_control_platform_runtime;
`;

export const discoveryPreapprovalTargetGuardsSql = `
-- Only the private source owner can inspect cross-privacy claims for the exact
-- target of an actual active, installed local Discovery case. No rows are exposed.
DROP POLICY IF EXISTS discovery_preapproval_target_claim_read ON control.discovery_certificate_issuance;
CREATE POLICY discovery_preapproval_target_claim_read ON control.discovery_certificate_issuance FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND EXISTS(
  SELECT 1 FROM control.platform_recovery_case c JOIN control.platform_recovery_enrollment e
   ON e.enrollment_id=c.enrollment_id AND e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
  WHERE c.participant_id=discovery_certificate_issuance.participant_id AND openpc.matches_privacy(c.privacy_domain_id)
   AND c.state='ACTIVE' AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
   AND e.state='ACTIVE' AND e.row_version=c.enrollment_revision AND e.document_digest=c.enrollment_digest
   AND c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
   AND e.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' AND current_setting('openpc.local_qa_runtime',true)='1'
   AND c.intent->'certificateRecovery'=e.document->'certificateRecovery'
   AND (discovery_certificate_issuance.predecessor_credential_id::text=c.intent#>>'{certificateRecovery,predecessorCredentialId}'
     OR discovery_certificate_issuance.successor_credential_id::text=c.intent#>>'{certificateRecovery,successorCredentialId}')));
DROP POLICY IF EXISTS discovery_preapproval_target_attempt_read ON control.discovery_certificate_issuer_attempt;
CREATE POLICY discovery_preapproval_target_attempt_read ON control.discovery_certificate_issuer_attempt FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND EXISTS(
  SELECT 1 FROM control.discovery_certificate_issuance i
   JOIN control.platform_recovery_case c ON c.participant_id=i.participant_id
   JOIN control.platform_recovery_enrollment e ON e.enrollment_id=c.enrollment_id AND e.participant_id=c.participant_id
    AND e.privacy_domain_id=c.privacy_domain_id
  WHERE i.participant_id=discovery_certificate_issuer_attempt.participant_id AND i.issuance_id=discovery_certificate_issuer_attempt.issuance_id
   AND openpc.matches_privacy(c.privacy_domain_id) AND c.state='ACTIVE'
   AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
   AND e.state='ACTIVE' AND e.row_version=c.enrollment_revision AND e.document_digest=c.enrollment_digest
   AND c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
   AND e.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' AND current_setting('openpc.local_qa_runtime',true)='1'
   AND c.intent->'certificateRecovery'=e.document->'certificateRecovery'
   AND (i.predecessor_credential_id::text=c.intent#>>'{certificateRecovery,predecessorCredentialId}'
     OR i.successor_credential_id::text=c.intent#>>'{certificateRecovery,successorCredentialId}')));

-- The old callable case oracle is withdrawn. Only a real candidate INSERT's
-- private trigger can cross privacy boundaries, between the invoker admission
-- trigger and its invoker final-clock/proof recheck.
DROP FUNCTION IF EXISTS openpc.assert_discovery_preapproval_target_no_claim(uuid);
-- A stored child is visible only to this trigger owner for its exact installed,
-- current, local Discovery target. This policy never recurses into candidates.
DROP POLICY IF EXISTS discovery_preapproval_stored_child_read ON control.mutation_candidate;
CREATE POLICY discovery_preapproval_stored_child_read ON control.mutation_candidate FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND catalog_operation_id='ID-OP-WORKLOAD-ROTATE' AND action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  AND resume_request->>'command'='DISCOVERY_PREAPPROVAL_CONTINUE' AND predecessor_candidate_id IS NOT NULL
  AND state='PROPOSED' AND consumed_operation_id IS NULL AND EXISTS(
   SELECT 1 FROM control.platform_recovery_case c JOIN control.platform_recovery_enrollment e
    ON e.enrollment_id=c.enrollment_id AND e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
   WHERE c.participant_id=mutation_candidate.participant_id AND c.privacy_domain_id=mutation_candidate.privacy_domain_id
    AND c.recovery_id::text=mutation_candidate.resume_request->>'recoveryId'
    AND c.state='ACTIVE' AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
    AND e.state='ACTIVE' AND e.row_version=c.enrollment_revision AND e.document_digest=c.enrollment_digest
    AND c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
    AND e.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR' AND current_setting('openpc.local_qa_runtime',true)='1'
    AND c.intent->'certificateRecovery'=e.document->'certificateRecovery'
    AND mutation_candidate.resource_id::text=c.intent#>>'{certificateRecovery,predecessorCredentialId}'
    AND mutation_candidate.candidate_document=jsonb_build_object('replacedCredentialId',mutation_candidate.resource_id::text,
      'credentialId',c.intent#>>'{certificateRecovery,successorCredentialId}',
      'publicKeySpkiDer',c.intent#>>'{certificateRecovery,successorPublicKeySpkiDer}')));
CREATE OR REPLACE FUNCTION openpc.guard_discovery_preapproval_target_claims()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on AS $$
DECLARE c control.platform_recovery_case; stored control.mutation_candidate;
BEGIN
 IF TG_TABLE_SCHEMA<>'control' OR TG_TABLE_NAME<>'mutation_candidate' OR TG_OP<>'INSERT'
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 IF NEW.resume_request->>'command' IS DISTINCT FROM 'DISCOVERY_PREAPPROVAL_CONTINUE' THEN RETURN NEW; END IF;
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id() IS DISTINCT FROM NEW.action_intent_id THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 SELECT * INTO STRICT stored FROM control.mutation_candidate WHERE mutation_candidate_id=NEW.mutation_candidate_id;
 IF to_jsonb(stored) IS DISTINCT FROM to_jsonb(NEW) THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 SELECT * INTO STRICT c FROM control.platform_recovery_case
  WHERE recovery_id::text=NEW.resume_request->>'recoveryId' AND participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
   AND state='ACTIVE' AND valid_from<=clock_timestamp() AND valid_until>clock_timestamp()
   AND intent->>'schema'='pc.identity.discovery-certificate-recovery-intent';
 IF current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR NEW.catalog_operation_id<>'ID-OP-WORKLOAD-ROTATE' OR NEW.action_intent_id<>'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  OR NEW.resource_id::text IS DISTINCT FROM c.intent#>>'{certificateRecovery,predecessorCredentialId}'
  OR NEW.candidate_document IS DISTINCT FROM jsonb_build_object('replacedCredentialId',NEW.resource_id::text,
    'credentialId',c.intent#>>'{certificateRecovery,successorCredentialId}',
    'publicKeySpkiDer',c.intent#>>'{certificateRecovery,successorPublicKeySpkiDer}')
  OR NEW.expected_revision::text IS DISTINCT FROM c.intent#>>'{certificateRecovery,predecessorRevision}'
  OR NEW.maker_principal_id::text IS DISTINCT FROM c.intent#>>'{administrators,0,principalId}'
  OR NEW.state<>'PROPOSED' OR NEW.consumed_operation_id IS NOT NULL OR NEW.predecessor_candidate_id IS NULL
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 PERFORM * FROM openpc.lock_discovery_certificate_recovery_source(c.enrollment_id,c.recovery_id);
 IF EXISTS(SELECT 1 FROM control.discovery_certificate_issuance i WHERE i.participant_id=c.participant_id
    AND (i.predecessor_credential_id::text=c.intent#>>'{certificateRecovery,predecessorCredentialId}'
     OR i.successor_credential_id::text=c.intent#>>'{certificateRecovery,successorCredentialId}'))
  OR EXISTS(SELECT 1 FROM control.discovery_certificate_issuer_attempt a JOIN control.discovery_certificate_issuance i
    ON i.participant_id=a.participant_id AND i.issuance_id=a.issuance_id WHERE i.participant_id=c.participant_id
     AND (i.predecessor_credential_id::text=c.intent#>>'{certificateRecovery,predecessorCredentialId}'
      OR i.successor_credential_id::text=c.intent#>>'{certificateRecovery,successorCredentialId}'))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 -- A clock advance may have hidden all target rows through their RLS basis.
 -- Reauthenticate the SAME case/source after the scan before any success.
 PERFORM * FROM openpc.lock_discovery_certificate_recovery_source(c.enrollment_id,c.recovery_id);
 IF NOT EXISTS(SELECT 1 FROM control.platform_recovery_case fresh WHERE fresh.recovery_id=c.recovery_id
   AND fresh.participant_id=c.participant_id AND fresh.privacy_domain_id=c.privacy_domain_id AND fresh.state='ACTIVE'
   AND fresh.enrollment_id=c.enrollment_id AND fresh.enrollment_revision=c.enrollment_revision
   AND fresh.enrollment_digest=c.enrollment_digest AND fresh.intent=c.intent
   AND fresh.valid_from<=clock_timestamp() AND fresh.valid_until>clock_timestamp())
  OR NEW.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_discovery_preapproval_target_claims() FROM PUBLIC;
DROP TRIGGER IF EXISTS zz_discovery_preapproval_claims ON control.mutation_candidate;
CREATE TRIGGER zz_discovery_preapproval_claims AFTER INSERT ON control.mutation_candidate
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_preapproval_target_claims();
DROP TRIGGER IF EXISTS zz_discovery_preapproval_claims_completed ON control.mutation_candidate;
CREATE CONSTRAINT TRIGGER zz_discovery_preapproval_claims_completed AFTER INSERT ON control.mutation_candidate
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_preapproval_target_claims();
`;

export const discoveryPreapprovalTargetGrantsSql = `GRANT EXECUTE ON FUNCTION openpc.guard_discovery_preapproval_target_claims() TO openpc_control_owner;`;
