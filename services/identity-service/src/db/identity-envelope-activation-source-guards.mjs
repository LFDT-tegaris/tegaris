import { identityEnvelopeContext } from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';
import { currentPlatformEnvelopeSql } from './current-platform-envelope.ts';

const authorityFields = identityEnvelopeContext.types.Authority.map(({ key, name, type }) => {
  const value = `p_value->>'${name}'`;
  const encoded =
    type === 'uuid'
      ? `openpc.business_uuid((${value})::uuid)`
      : type === 'H32'
        ? `openpc.business_bytes(decode(substr(${value},8),'hex'))`
        : type === 'u64' || type === 'u64p'
          ? `to_jsonb((${value})::numeric)`
          : type === 'id'
            ? `to_jsonb(${value})`
            : undefined;
  if (!encoded) throw new Error('Unsupported envelope authority wire field');
  return `'${key}',${encoded}`;
}).join(',');

/** Source-owned SQL comparisons supplement real service/native cryptography.
 * A JSON snapshot, context GUC or structurally valid COSE is never a signature
 * verification or a replacement for the current public authorization owner.
 * The transaction owner takes the complete sorted authority fence first; these
 * comparisons acquire no new per-actor lock order. */
export const identityEnvelopeActivationSourceGuardsSql = `
-- Request-cache retention is separate from business authority. A reservation
-- cannot extend an unconsumed candidate or approval into its first dispatch.
-- Historical observation never calls this current-use predicate.
CREATE OR REPLACE FUNCTION openpc.identity_envelope_activation_intent_current(
 p_participant uuid,p_privacy uuid,p_candidate uuid,p_approval uuid)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.mutation_candidate c
  JOIN control.approval_request a ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
   AND a.subject_type='CONFIGURATION_CANDIDATE' AND a.subject_id=c.mutation_candidate_id
   AND a.subject_digest=c.candidate_digest AND a.subject_version=c.expected_revision
   AND a.action_intent_id=c.action_intent_id AND a.maker_principal_id=c.maker_principal_id
  WHERE c.participant_id=p_participant AND c.privacy_domain_id=p_privacy
   AND c.mutation_candidate_id=p_candidate AND a.approval_request_id=p_approval
   AND c.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' AND c.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
   AND c.operation_class='ACTIVATE' AND c.resource_type='participant' AND c.expected_revision=3
   AND c.candidate_document=jsonb_build_object('envelopeId',c.resource_id::text)
   AND c.state='APPROVED' AND c.consumed_operation_id IS NULL AND c.expires_at>clock_timestamp()
   AND a.state='APPROVED' AND a.expires_at>clock_timestamp()
   AND NOT EXISTS(SELECT 1 FROM control.mutation_candidate successor
    WHERE successor.participant_id=c.participant_id AND successor.privacy_domain_id=c.privacy_domain_id
     AND successor.predecessor_candidate_id=c.mutation_candidate_id))
$$;
CREATE OR REPLACE FUNCTION openpc.identity_envelope_authority_wire(p_value jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object(${authorityFields})
$$;
CREATE OR REPLACE FUNCTION openpc.identity_envelope_actor_wire(p_value jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('1',openpc.identity_envelope_authority_wire(p_value->'authority'),
  '2',openpc.business_uuid((p_value->>'stepUpChallengeId')::uuid),
  '3',openpc.business_bytes(decode(substr(p_value->>'stepUpEvidenceDigest',8),'hex')),
  '4',openpc.business_uuid((p_value->>'signerCredentialId')::uuid),
  '5',(p_value->>'signerCredentialEpoch')::numeric)
$$;

CREATE OR REPLACE FUNCTION openpc.identity_envelope_activation_authority_current(
 p_participant uuid,p_privacy uuid,p_captured jsonb,p_action text,p_resource uuid,p_live_session boolean)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE b jsonb:=p_captured->'binding'; d jsonb:=p_captured->'durable';
 a control.assignment%ROWTYPE; e control.authority_envelope%ROWTYPE; r control.authority_role%ROWTYPE;
 pr control.principal%ROWTYPE; privacy control.privacy_domain%ROWTYPE; role_document jsonb; expected jsonb;
BEGIN
 IF b->>'participantId' IS DISTINCT FROM p_participant::text
  OR d#>>'{grant,privacyDomainId}' IS DISTINCT FROM p_privacy::text
  OR d#>>'{grant,actionIntentId}' IS DISTINCT FROM p_action
  OR d#>>'{grant,resourceId}' IS DISTINCT FROM p_resource::text THEN RETURN false; END IF;
 SELECT * INTO a FROM control.assignment WHERE participant_id=p_participant
  AND assignment_id=(b->>'assignmentId')::uuid;
 SELECT * INTO e FROM control.authority_envelope WHERE participant_id=p_participant
  AND authority_envelope_id=(b->>'authorityEnvelopeId')::uuid;
 SELECT * INTO r FROM control.authority_role WHERE participant_id=p_participant AND role_id=b->>'roleId';
 SELECT * INTO pr FROM control.principal WHERE participant_id=p_participant
  AND principal_id=(b->>'principalId')::uuid;
 SELECT * INTO privacy FROM control.privacy_domain WHERE participant_id=p_participant AND privacy_domain_id=p_privacy;
 IF a.assignment_id IS NULL OR e.authority_envelope_id IS NULL OR r.authority_role_id IS NULL
  OR pr.principal_id IS NULL OR privacy.privacy_domain_id IS NULL
  OR a.principal_id IS DISTINCT FROM pr.principal_id OR a.authority_envelope_id IS DISTINCT FROM e.authority_envelope_id
  OR a.role_id IS DISTINCT FROM r.role_id OR a.row_version::text IS DISTINCT FROM b->>'assignmentVersion'
  OR a.delegation_epoch::text IS DISTINCT FROM b->>'delegationEpoch' OR a.state<>'ACTIVE'
  OR NOT (a.valid_during @> clock_timestamp()) OR NOT a.maker_checker_required
  OR NOT (p_action=ANY(a.action_intent_ids)) OR NOT (p_privacy::text=ANY(a.privacy_domain_ids))
  OR NOT openpc.administration_resource_permits(a.resource_ids,p_resource::text,p_action,p_participant,pr.principal_id,(b->>'sessionId')::uuid,e.authority_envelope_id)
  OR NOT openpc.assignment_group_permits(a.participant_id,a.authority_group_id,a.principal_id,a.valid_during)
  OR e.state<>'ACTIVE' OR e.valid_from>clock_timestamp() OR (e.valid_until IS NOT NULL AND e.valid_until<=clock_timestamp())
  OR NOT ${currentPlatformEnvelopeSql('e', false, true)}
  OR e.authority_epoch::text IS DISTINCT FROM b->>'authorityEpoch' OR NOT e.maker_checker_required
  OR NOT (p_action=ANY(e.action_intent_ids)) OR NOT (p_privacy::text=ANY(e.privacy_domain_ids))
  OR NOT openpc.administration_resource_permits(e.resource_ids,p_resource::text,p_action,p_participant,pr.principal_id,(b->>'sessionId')::uuid,e.authority_envelope_id)
  OR NOT EXISTS(SELECT 1 FROM control.action_intent action WHERE action.action_intent_id=p_action
    AND action.risk_class=ANY(a.risk_classes) AND action.risk_class=ANY(e.risk_classes))
  OR NOT (e.principal_id=pr.principal_id OR (e.representation='TYPED_V1' AND e.principal_id IS NULL))
  OR r.state<>'ACTIVE' OR r.row_version::text IS DISTINCT FROM b->>'roleVersion' OR NOT (p_action=ANY(r.action_intent_ids))
  OR pr.state<>'ACTIVE' OR pr.kind<>'PLATFORM_OPERATOR' OR pr.authority_epoch::text IS DISTINCT FROM b->>'principalEpoch'
  OR privacy.state<>'ACTIVE'
  OR NOT EXISTS(SELECT 1 FROM control.participant p WHERE p.participant_id=p_participant
    AND p.state='ACTIVE' AND p.authority_epoch::text=b->>'participantEpoch')
 THEN RETURN false; END IF;
 expected:=jsonb_build_object('principalId',b->'principalId','participantEpoch',b->'participantEpoch',
  'principalEpoch',b->'principalEpoch','assignmentId',b->'assignmentId','assignmentRowVersion',b->'assignmentVersion',
  'authorityEnvelopeId',b->'authorityEnvelopeId','authorityEpoch',b->'authorityEpoch','delegationEpoch',b->'delegationEpoch',
  'privacyDomainId',p_privacy::text,'actionIntentId',p_action,'resourceId',p_resource::text);
 IF (d->'grant')-'catalogOperationId' IS DISTINCT FROM expected THEN RETURN false; END IF;
 expected:=jsonb_build_object('path',jsonb_build_object('delegationIds','[]'::jsonb,
   'principalIds',jsonb_build_array(pr.principal_id::text),'roleId',r.authority_role_id::text),
  'principals',jsonb_build_array(jsonb_build_array(pr.principal_id::text,pr.authority_epoch::text)),
  'privacy',privacy.row_version::text,'role',r.row_version::text,'delegations',NULL);
 IF d->'dependencies' IS DISTINCT FROM expected THEN RETURN false; END IF;
 role_document:=jsonb_build_object('roleId',r.role_id,'version',r.row_version::text,'actions',to_jsonb(r.action_intent_ids),
  'origin',r.origin,'createdByPrincipalId',r.created_by_principal_id::text,'creatorParticipantId',r.creator_participant_id::text,
  'bootstrapMandateId',r.bootstrap_mandate_id::text,'bootstrapPlatformParticipantId',r.bootstrap_platform_participant_id::text);
 IF b->>'roleDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
  jsonb_build_object('domain','pc.identity.envelope-role-binding.v1','participantId',p_participant::text,'role',role_document)),'UTF8')),'hex')
  OR b->>'authorityDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
  jsonb_build_object('domain','pc.identity.envelope-authority-binding.v1','binding',b-'authorityDigest',
   'authority',(d->'grant')||jsonb_build_object('sessionId',b->'sessionId','sessionEpoch',b->'sessionEpoch'),'durable',d)),'UTF8')),'hex')
 THEN RETURN false; END IF;
 IF p_live_session AND NOT EXISTS(SELECT 1 FROM control.session s WHERE s.participant_id=p_participant
  AND s.session_id=(b->>'sessionId')::uuid AND s.principal_id=pr.principal_id AND s.context_mode='PLATFORM' AND s.privacy_domain_id IS NULL
  AND s.state='ACTIVE' AND s.session_epoch::text=b->>'sessionEpoch' AND s.participant_epoch::text=b->>'participantEpoch'
  AND s.authority_epoch::text=b->>'principalEpoch' AND s.delegation_epoch::text=b->>'delegationEpoch'
  AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp())
 THEN RETURN false; END IF;
 RETURN true;
END $$;
`;

export const identityEnvelopeActivationSourceGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.identity_envelope_authority_wire(jsonb),openpc.identity_envelope_actor_wire(jsonb),
 openpc.identity_envelope_activation_intent_current(uuid,uuid,uuid,uuid),
 openpc.identity_envelope_activation_authority_current(uuid,uuid,jsonb,text,uuid,boolean)
 TO openpc_control_runtime,openpc_control_platform_runtime;
`;
