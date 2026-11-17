import type { PoolClient } from 'pg';
import {
  decodeIdentityAuthContextAssertionPayload,
  identityCredentialCoseContext,
  verifyCoseSign1Es256,
} from '@openpc/security-kernel';
import {
  identityActorKeyDigest,
  identityMutationAudienceDigest,
} from '../domain/identity-runtime-authorization.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';

interface EvidenceBinding {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly principalId: string;
  readonly credentialId: string;
  readonly evidenceCbor: Buffer;
  readonly coseSign1: Buffer;
  readonly credentialPublicKey: Buffer;
}
type VerificationPurpose =
  | { readonly approvalRequestId: string }
  | {
      readonly mfaChallengeId: string;
      readonly actionIntentId: string;
      readonly candidateDigest: Buffer;
      readonly resourceId?: string;
      readonly credentialEpoch?: string;
    };

/** Verify the retained signature, not a new authorization grant. The caller must
 * fence live authority and consume the exact approval/challenge in its transaction.
 * Runtime assertions qualify only when tied to the committed WebAuthn owner record;
 * their 60-second issuance validity is checked at that verification's commit time. */
export async function verifyStoredStepUpEvidence(
  client: PoolClient,
  input: EvidenceBinding & VerificationPurpose,
  runtimeVerifier: IdentityRuntimeVerifier | undefined,
): Promise<boolean> {
  try {
    if ('mfaChallengeId' in input && input.resourceId !== undefined) {
      if (!input.credentialEpoch) return false;
      const binding = await client.query(
        `select 1 from control.mfa_challenge challenge
        join control.mutation_evidence verification using(participant_id,mfa_challenge_id)
        where challenge.participant_id=$1 and challenge.principal_id=$2 and challenge.mfa_challenge_id=$3
          and challenge.action_intent_id=$4 and challenge.resource_digest=$5 and challenge.resource_id=$6
          and challenge.consumed_at is not null and verification.privacy_domain_id=$7
          and challenge.signer_credential_id=$8 and challenge.signer_credential_epoch=$11
          and verification.principal_id=$2 and verification.signer_credential_id=$8
          and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
          and verification.evidence_cbor=$9 and verification.cose_sign1=$10`,
        [
          input.participantId,
          input.principalId,
          input.mfaChallengeId,
          input.actionIntentId,
          input.candidateDigest,
          input.resourceId,
          input.privacyDomainId,
          input.credentialId,
          input.evidenceCbor,
          input.coseSign1,
          input.credentialEpoch,
        ],
      );
      if (binding.rowCount !== 1) return false;
    }
    if (
      verifyCoseSign1Es256(
        input.credentialPublicKey,
        input.evidenceCbor,
        input.coseSign1,
        identityCredentialCoseContext,
      )
    )
      return true;
    if (
      !runtimeVerifier ||
      !(await runtimeVerifier.verifyCanonicalAssertion(input.evidenceCbor, input.coseSign1))
    )
      return false;
    const purpose =
      'approvalRequestId' in input
        ? {
            predicate: `exists(select 1 from control.approval_decision_record decision where decision.participant_id=verification.participant_id
            and decision.privacy_domain_id=verification.privacy_domain_id and decision.approval_request_id=$7
            and decision.approver_principal_id=verification.principal_id and decision.signer_credential_id=verification.signer_credential_id
            and decision.mfa_challenge_id=challenge.mfa_challenge_id and decision.decision='APPROVE'
            and decision.evidence_cbor=verification.evidence_cbor and decision.cose_sign1=verification.cose_sign1
            and challenge.action_intent_id='ACT-POLICY_APPROVE_REQUEST-V1' and challenge.resource_digest=decision.decision_digest)`,
            values: [input.approvalRequestId],
          }
        : {
            predicate:
              'challenge.mfa_challenge_id=$7 and challenge.action_intent_id=$8 and challenge.resource_digest=$9 and ($10::text is null or challenge.resource_id=$10)',
            values: [
              input.mfaChallengeId,
              input.actionIntentId,
              input.candidateDigest,
              input.resourceId ?? null,
            ],
          };
    // A committed approval is historical evidence: validate its exact decision,
    // signature, and issuance against the original verification occurrence.
    // A live mutation uses the current session's exact source deadline. Legacy
    // unpaired sessions retain the original five-minute proof window.
    const liveChallengeFreshness =
      'approvalRequestId' in input
        ? ''
        : `and exists(select 1 from control.session proof_session
             where proof_session.participant_id=challenge.participant_id
               and proof_session.principal_id=challenge.principal_id and proof_session.session_id=challenge.session_id
               and case when proof_session.step_up_mfa_challenge_id is null
                 then challenge.consumed_at>clock_timestamp()-interval '5 minutes'
                 else proof_session.step_up_mfa_challenge_id=challenge.mfa_challenge_id
                   and openpc.session_step_up_valid_until(challenge.participant_id,challenge.session_id,challenge.principal_id)>clock_timestamp()
                 end)`;
    const result = await client.query<{
      candidate_digest: Buffer;
      session_id: string;
      occurred_at: Date;
    }>(
      `select verification.candidate_digest,challenge.session_id,verification.occurred_at
       from control.mutation_evidence verification
       join control.mfa_challenge challenge on challenge.participant_id=verification.participant_id
         and challenge.mfa_challenge_id=verification.mfa_challenge_id and challenge.principal_id=verification.principal_id
         and challenge.session_id=verification.aggregate_id and challenge.consumed_at is not null
         ${liveChallengeFreshness}
       join control.idempotency_record committed on committed.participant_id=verification.participant_id
         and committed.privacy_domain_id=verification.privacy_domain_id and committed.principal_id=verification.principal_id
         and committed.operation_id=verification.operation_id and committed.catalog_operation_id=verification.catalog_operation_id
         and committed.input_digest=verification.candidate_digest and committed.terminal_state='COMMITTED'
         and committed.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
       join control.outbox_event event on event.participant_id=verification.participant_id and event.privacy_domain_id=verification.privacy_domain_id
         and event.aggregate_type=verification.aggregate_type and event.aggregate_id=verification.aggregate_id
         and event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
         and event.payload_cbor=verification.evidence_cbor and event.payload_digest=verification.evidence_digest
         and event.cose_sign1=verification.cose_sign1 and event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
       where verification.participant_id=$1 and verification.privacy_domain_id=$2 and verification.principal_id=$3
         and verification.signer_credential_id=$4 and verification.evidence_cbor=$5 and verification.cose_sign1=$6
         and verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
         and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY' and verification.aggregate_type='webauthn-verification'
         and verification.evidence_digest=sha256(verification.evidence_cbor)
         and verification.webauthn_assertion_binding_digest is not null and verification.occurred_at>=challenge.consumed_at
         and ${purpose.predicate} limit 2`,
      [
        input.participantId,
        input.privacyDomainId,
        input.principalId,
        input.credentialId,
        input.evidenceCbor,
        input.coseSign1,
        ...purpose.values,
      ],
    );
    if (result.rowCount !== 1) return false;
    const row = result.rows[0]!;
    return authenticateHistoricalRuntimeStepUpEvidence(input, row);
  } catch {
    return false;
  }
}

/** Caller must authenticate the exact durable verification/decision joins.
 * This pure boundary checks historical runtime payload binding and lifetime;
 * it neither reauthorizes a checker nor renews a consumed challenge. */
export function authenticateHistoricalRuntimeStepUpEvidence(
  input: Pick<EvidenceBinding, 'participantId' | 'principalId' | 'evidenceCbor'>,
  row: { candidate_digest: Buffer; session_id: string; occurred_at: Date },
): boolean {
  try {
    const assertion = decodeIdentityAuthContextAssertionPayload(input.evidenceCbor);
    const committedAtNs = BigInt(row.occurred_at.getTime()) * 1_000_000n;
    return (
      assertion.actorKind === 0 &&
      assertion.senderBindingKind === 1 &&
      assertion.senderCredentialBindingDigest !== undefined &&
      assertion.actorKeyDigest.equals(
        identityActorKeyDigest(input.participantId, input.principalId),
      ) &&
      assertion.audienceDigest.equals(
        identityMutationAudienceDigest({
          actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
          catalogOperationId: 'ID-OP-WEBAUTHN-VERIFY',
          resourceId: row.session_id,
          candidateDigest: `sha256:${row.candidate_digest.toString('hex')}`,
        }),
      ) &&
      assertion.issuedAtNs <= committedAtNs + 5_000_000_000n &&
      assertion.expiresAtNs > committedAtNs &&
      assertion.expiresAtNs > assertion.issuedAtNs &&
      assertion.expiresAtNs - assertion.issuedAtNs <= 60_000_000_000n
    );
  } catch {
    return false;
  }
}
