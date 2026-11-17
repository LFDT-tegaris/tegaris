import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { LiveStepUpRecord } from './live-step-up.js';
import type { MutationCandidateContext } from './mutation-candidate-store.js';
import {
  verifyIdentityRuntimeAuthorizationAssertion,
  type IdentityRuntimeAuthorizationContext,
} from '../domain/identity-runtime-authorization.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';

export interface DiscoveryReceivingProof {
  readonly mfaChallengeId: string;
  readonly verificationOperationId: string;
  readonly evidenceDigest: string;
}
export interface DiscoveryReceivingAuthenticator {
  readonly sessionToken: string;
  readonly verifier: IdentityRuntimeVerifier;
}

export interface DiscoveryReceivingProofBinding {
  readonly actionIntentId:
    'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' | 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
  readonly resourceId: string;
  readonly candidateDigest: string;
}

type DiscoveryReceivingScope = Pick<
  MutationCandidateContext,
  'participantId' | 'privacyDomainId' | 'authorization'
>;

interface NativeReceivingEvidence extends Omit<
  IdentityRuntimeAuthorizationContext,
  'sessionToken'
> {
  readonly mfaChallengeId: string;
  readonly verificationOperationId: string;
  readonly evidenceCbor: Buffer;
  readonly evidenceDigest: Buffer;
  readonly coseSign1: Buffer;
  readonly tokenDigest: Buffer;
  readonly occurredAt: Date;
}

interface ReceivingEvidence extends NativeReceivingEvidence, LiveStepUpRecord {
  readonly validUntil: Date;
}

/** Strict continuation-only verifier. Historical VERIFY bytes retain their
 * original 60-second lifetime; their vectors must match the actual receiving
 * session and authority now. Legacy credential signatures are not a substitute. */
export async function authenticateDiscoveryReceivingEvidence(
  evidence: NativeReceivingEvidence,
  receiving: DiscoveryReceivingAuthenticator,
): Promise<DiscoveryReceivingProof | undefined> {
  if (
    !createHash('sha256').update(receiving.sessionToken).digest().equals(evidence.tokenDigest) ||
    !createHash('sha256').update(evidence.evidenceCbor).digest().equals(evidence.evidenceDigest) ||
    !(await receiving.verifier.verifyCanonicalAssertion(
      evidence.evidenceCbor,
      evidence.coseSign1,
    )) ||
    !verifyIdentityRuntimeAuthorizationAssertion(
      evidence.evidenceCbor,
      { ...evidence, sessionToken: receiving.sessionToken },
      evidence.occurredAt,
    )
  )
    return undefined;
  return {
    mfaChallengeId: evidence.mfaChallengeId,
    verificationOperationId: evidence.verificationOperationId,
    evidenceDigest: `sha256:${evidence.evidenceDigest.toString('hex')}`,
  };
}

/** Caller holds the ranked authority fence and original intent lock. Select
 * every eligible chain, without DISTINCT/LIMIT hiding duplicate commitments. */
async function selectDiscoveryReceivingEvidence(
  client: PoolClient,
  context: DiscoveryReceivingScope,
  binding: DiscoveryReceivingProofBinding,
  exclusive: boolean,
  usedOperationId?: string,
  purpose: 'DISCOVERY' | 'PLATFORM_CONTINUATION' = 'DISCOVERY',
): Promise<ReceivingEvidence | undefined> {
  if (
    !['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'].includes(
      binding.actionIntentId,
    ) ||
    !/^sha256:[0-9a-f]{64}$/u.test(binding.candidateDigest) ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      binding.resourceId,
    )
  )
    return undefined;
  const a = context.authorization;
  const result = await client.query<ReceivingEvidence>(
    `select m.mfa_challenge_id::text as "mfaChallengeId",v.operation_id::text as "verificationOperationId",
      v.evidence_cbor as "evidenceCbor",v.evidence_digest as "evidenceDigest",v.cose_sign1 as "coseSign1",
      v.occurred_at as "occurredAt",s.opaque_token_digest as "tokenDigest",
      v.signer_credential_id::text as "signerCredentialId",credential.credential_epoch::text as "signerCredentialEpoch",
      credential.public_key_spki_der as "credentialPublicKey",v.webauthn_assertion_binding_digest as "assertionBindingDigest",
      least(fresh.valid_until,e.valid_until,m.expires_at,
        case when s.step_up_mfa_challenge_id is null then m.consumed_at+interval '5 minutes'
          else coalesce(openpc.session_step_up_valid_until(m.participant_id,m.session_id,m.principal_id),'-infinity'::timestamptz) end,
        s.idle_expires_at,s.absolute_expires_at,upper(assignment.valid_during),credential.valid_until) as "validUntil",
      p.participant_id::text as "participantId",principal.principal_id::text as "principalId",
      s.session_id::text as "sessionId",s.session_epoch::text as "sessionEpoch",s.issued_at as "sessionIssuedAt",
      s.idle_expires_at as "sessionIdleExpiresAt",s.absolute_expires_at as "sessionAbsoluteExpiresAt",
      p.authority_epoch::text as "participantEpoch",principal.authority_epoch::text as "principalEpoch",
      assignment.assignment_id::text as "assignmentId",assignment.row_version::text as "assignmentRowVersion",
      e.authority_envelope_id::text as "authorityEnvelopeId",e.authority_epoch::text as "authorityEpoch",
      e.delegation_epoch::text as "delegationEpoch",e.valid_until as "authorityValidUntil",
      v.action_intent_id as "actionIntentId",v.catalog_operation_id as "catalogOperationId",
      s.session_id::text as "resourceId",'sha256:'||encode(v.candidate_digest,'hex') as "candidateDigest"
    from control.participant p join control.principal principal on principal.participant_id=p.participant_id
    join control.session s on s.participant_id=p.participant_id and s.principal_id=principal.principal_id
    join control.assignment assignment on assignment.participant_id=p.participant_id and assignment.principal_id=principal.principal_id
    join control.authority_envelope e on e.participant_id=p.participant_id and e.authority_envelope_id=assignment.authority_envelope_id
    join control.platform_recovery_case fresh on fresh.participant_id=p.participant_id and fresh.recovery_id=e.recovery_case_id
    join control.mfa_challenge m on m.participant_id=p.participant_id and m.principal_id=principal.principal_id and m.session_id=s.session_id
    join control.credential credential on credential.participant_id=m.participant_id and credential.credential_id=m.signer_credential_id
      and credential.principal_id=m.principal_id and credential.kind='WEBAUTHN' and credential.state='ACTIVE'
      and credential.credential_epoch=m.signer_credential_epoch and credential.valid_from<=clock_timestamp()
      and (credential.valid_until is null or credential.valid_until>clock_timestamp())
      and sha256(credential.public_key_spki_der)=credential.public_key_digest
    join control.mutation_evidence v on v.participant_id=m.participant_id and v.mfa_challenge_id=m.mfa_challenge_id
      and v.principal_id=m.principal_id and v.privacy_domain_id=$2 and v.signer_credential_id=m.signer_credential_id
      and v.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1' and v.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
      and v.aggregate_type='webauthn-verification' and v.aggregate_id=s.session_id
      and v.bound_participant_epoch=p.authority_epoch and v.bound_principal_epoch=principal.authority_epoch
      and v.bound_authority_envelope_id=e.authority_envelope_id and v.bound_envelope_epoch=e.authority_epoch
      and v.bound_assignment_id=assignment.assignment_id and v.evidence_digest=sha256(v.evidence_cbor)
      and v.webauthn_assertion_binding_digest is not null
      and v.occurred_at>=m.consumed_at and v.occurred_at<=clock_timestamp()
    join control.idempotency_record committed on committed.participant_id=v.participant_id and committed.privacy_domain_id=v.privacy_domain_id
      and committed.principal_id=v.principal_id and committed.operation_id=v.operation_id
      and committed.action_intent_id=v.action_intent_id and committed.catalog_operation_id=v.catalog_operation_id
      and committed.input_digest=v.candidate_digest and committed.terminal_state='COMMITTED'
      and committed.webauthn_assertion_binding_digest=v.webauthn_assertion_binding_digest
    join control.outbox_event event on event.participant_id=v.participant_id and event.privacy_domain_id=v.privacy_domain_id
      and event.aggregate_type=v.aggregate_type and event.aggregate_id=v.aggregate_id
      and event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
      and event.payload_cbor=v.evidence_cbor and event.payload_digest=v.evidence_digest and event.cose_sign1=v.cose_sign1
      and event.webauthn_assertion_binding_digest=v.webauthn_assertion_binding_digest
    where p.participant_id=$1 and p.state='ACTIVE' and p.authority_epoch=$4
      and principal.principal_id=$3 and principal.state='ACTIVE' and principal.kind='PLATFORM_OPERATOR' and principal.authority_epoch=$5
      and s.session_id=$6 and s.state='ACTIVE' and s.session_epoch=$7 and s.participant_epoch=p.authority_epoch
      and s.authority_epoch=principal.authority_epoch and s.delegation_epoch=e.delegation_epoch
      and s.context_mode='PLATFORM' and s.privacy_domain_id is null
      and s.idle_expires_at>clock_timestamp() and s.absolute_expires_at>clock_timestamp()
      and assignment.assignment_id=$8 and assignment.row_version=$9 and assignment.state='ACTIVE'
      and assignment.valid_during @> clock_timestamp() and assignment.delegation_epoch=e.delegation_epoch
      and e.authority_envelope_id=$10 and e.authority_epoch=$11 and e.delegation_epoch=$12
      and e.principal_id=principal.principal_id and e.representation='RECOVERY_V1'
      and openpc.platform_recovery_envelope_current(e.authority_envelope_id)
      and fresh.privacy_domain_id=$2 and fresh.state='ACTIVE' and fresh.valid_until>clock_timestamp()
      and ${
        purpose === 'DISCOVERY'
          ? "fresh.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'"
          : `fresh.intent->>'schema'='pc.identity.platform-recovery-intent' and fresh.intent ? 'continuation'
          and openpc.platform_recovery_approval_resume_subject_visible($1,$2,$3,$10,$15::uuid)`
      }
      and m.action_intent_id=$13 and m.resource_digest=$14 and m.resource_id=$15::text
      and m.created_at>=greatest(fresh.activated_at,e.valid_from) and m.consumed_at>=greatest(fresh.activated_at,e.valid_from)
      and v.occurred_at>=greatest(fresh.activated_at,e.valid_from)
      and case when s.step_up_mfa_challenge_id is null
        then m.consumed_at>clock_timestamp()-interval '5 minutes'
        else s.step_up_mfa_challenge_id=m.mfa_challenge_id
          and openpc.session_step_up_valid_until(m.participant_id,m.session_id,m.principal_id)>clock_timestamp()
        end
      and m.consumed_at<=clock_timestamp()
      and m.expires_at>clock_timestamp() and ((m.used_at is null and m.used_operation_id is null)
        or ($16::uuid is not null and m.used_at is not null and m.used_operation_id=$16))
    ${exclusive ? 'for update of m for share of committed' : 'for share of m,committed'}`,
    [
      context.participantId,
      context.privacyDomainId,
      a.principalId,
      a.participantEpoch,
      a.principalEpoch,
      a.sessionId,
      a.sessionEpoch,
      a.assignmentId,
      a.assignmentRowVersion,
      a.authorityEnvelopeId,
      a.authorityEpoch,
      a.delegationEpoch,
      binding.actionIntentId,
      Buffer.from(binding.candidateDigest.slice(7), 'hex'),
      binding.resourceId,
      usedOperationId ?? null,
    ],
  );
  const evidence = result.rows[0];
  if (
    result.rowCount !== 1 ||
    !evidence ||
    !(evidence.validUntil instanceof Date) ||
    !Number.isFinite(evidence.validUntil.getTime())
  )
    return undefined;
  return evidence;
}

/** Preapproval retains its unused proof and shared lock semantics. */
export async function readDiscoveryReceivingProof(
  client: PoolClient,
  context: MutationCandidateContext,
  receiving: DiscoveryReceivingAuthenticator,
): Promise<DiscoveryReceivingProof | undefined> {
  if (context.actionIntentId !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1') return undefined;
  const evidence = await selectDiscoveryReceivingEvidence(
    client,
    context,
    {
      actionIntentId: context.actionIntentId,
      resourceId: context.resourceId,
      candidateDigest: context.candidateDigest,
    },
    false,
  );
  return evidence && authenticateDiscoveryReceivingEvidence(evidence, receiving);
}

/** A committed replay is resolved before calling this owner. It locks the exact
 * selected unused MFA record before crypto; the caller consumes that same record
 * inside the atomic resume transaction, rather than selecting a newer proof. */
export async function lockDiscoveryApprovalResumeProof(
  client: PoolClient,
  context: DiscoveryReceivingScope,
  receiving: DiscoveryReceivingAuthenticator,
  binding: DiscoveryReceivingProofBinding,
): Promise<
  | {
      readonly proof: DiscoveryReceivingProof;
      readonly record: LiveStepUpRecord;
      readonly validUntil: Date;
    }
  | undefined
> {
  if (binding.actionIntentId !== 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1') return undefined;
  const evidence = await selectDiscoveryReceivingEvidence(client, context, binding, true);
  if (!evidence) return undefined;
  const proof = await authenticateDiscoveryReceivingEvidence(evidence, receiving);
  return proof && { proof, record: evidence, validUntil: evidence.validUntil };
}

/** Read the original consumed native pin on committed metadata replay. No fresh
 * MFA selection, verification mutation or authenticator counter is performed. */
export async function authenticateDiscoveryApprovalResumeReplayProof(
  client: PoolClient,
  context: DiscoveryReceivingScope,
  receiving: DiscoveryReceivingAuthenticator,
  binding: DiscoveryReceivingProofBinding,
  storedProof: DiscoveryReceivingProof,
  originalOperationId: string,
): Promise<boolean> {
  if (binding.actionIntentId !== 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1') return false;
  const evidence = await selectDiscoveryReceivingEvidence(
    client,
    context,
    binding,
    false,
    originalOperationId,
  );
  if (!evidence) return false;
  const actual = await authenticateDiscoveryReceivingEvidence(evidence, receiving);
  return (
    actual?.mfaChallengeId === storedProof.mfaChallengeId &&
    actual?.verificationOperationId === storedProof.verificationOperationId &&
    actual?.evidenceDigest === storedProof.evidenceDigest
  );
}

/** A distinct source3 purpose shares the native verification oracle, never the
 * Discovery business selector. Its selected historical subject is mandatory. */
export async function lockPlatformRecoveryApprovalResumeProof(
  client: PoolClient,
  context: DiscoveryReceivingScope,
  receiving: DiscoveryReceivingAuthenticator,
  binding: DiscoveryReceivingProofBinding,
) {
  if (binding.actionIntentId !== 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1') return undefined;
  const evidence = await selectDiscoveryReceivingEvidence(
    client,
    context,
    binding,
    true,
    undefined,
    'PLATFORM_CONTINUATION',
  );
  if (!evidence) return undefined;
  const proof = await authenticateDiscoveryReceivingEvidence(evidence, receiving);
  return proof && { proof, record: evidence, validUntil: evidence.validUntil };
}

export async function authenticatePlatformRecoveryApprovalResumeReplayProof(
  client: PoolClient,
  context: DiscoveryReceivingScope,
  receiving: DiscoveryReceivingAuthenticator,
  binding: DiscoveryReceivingProofBinding,
  storedProof: DiscoveryReceivingProof,
  originalOperationId: string,
): Promise<boolean> {
  if (binding.actionIntentId !== 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1') return false;
  const evidence = await selectDiscoveryReceivingEvidence(
    client,
    context,
    binding,
    false,
    originalOperationId,
    'PLATFORM_CONTINUATION',
  );
  if (!evidence) return false;
  const actual = await authenticateDiscoveryReceivingEvidence(evidence, receiving);
  return (
    actual?.mfaChallengeId === storedProof.mfaChallengeId &&
    actual.verificationOperationId === storedProof.verificationOperationId &&
    actual.evidenceDigest === storedProof.evidenceDigest
  );
}
