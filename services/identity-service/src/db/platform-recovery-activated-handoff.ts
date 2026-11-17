import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { decodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import {
  platformRecoveryIntent,
  type PendingExpiryPlatformRecoveryEnrollment,
} from '../contracts/platform-recovery.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import type { IdentityRuntimeAssertionVerifier } from '../domain/identity-kernel.js';
import type { PlatformRecoveryProof } from '../domain/platform-recovery-ceremony.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { readStoredPlatformRecoveryReceipt } from './platform-recovery-readback.js';

const deny = () => new PlatformRecoveryError();

/** Authenticate one schema4 closed-approval activation as historical provenance.
 * The v2 witness never revives its case, approval, signed dates or permissions. */
export async function readActivatedPlatformRecoveryPreparation(
  client: PoolClient,
  enrollment: PendingExpiryPlatformRecoveryEnrollment,
  verifier: IdentityRuntimeAssertionVerifier | undefined,
) {
  const witness = enrollment.source.pendingExpiry;
  if (!verifier || witness.schemaVersion !== 2 || enrollment.source.closedApproval) throw deny();
  const link = witness.preparation;
  const currentPredicate = 'platform_recovery_activated_expiry_source_current';
  const historical = await readStoredPlatformRecoveryReceipt(
    client,
    enrollment,
    link.enrollmentId,
    link.recoveryId,
    verifier,
  );
  const original = platformRecoveryIntent.parse(historical.receipt.intent);
  const predecessor = historical.enrollment;
  if (
    predecessor.schemaVersion !== 4 ||
    predecessor.source.pendingExpiry.schemaVersion !== 1 ||
    !predecessor.source.closedApproval ||
    canonicalAuthorizationDigest(predecessor) !== witness.predecessorEnrollmentDigest ||
    canonicalAuthorizationDigest(predecessor.source.closedApproval) !==
      witness.predecessorClosedApprovalDigest ||
    original.closedApprovalSourceDigest !== witness.predecessorClosedApprovalDigest ||
    !original.approvalContinuation ||
    canonicalAuthorizationDigest(original.approvalContinuation) !==
      canonicalAuthorizationDigest(predecessor.source.closedApproval.approval) ||
    original.preparation.supersedes?.replacementId !==
      predecessor.source.pendingExpiry.preparation.replacementId ||
    original.preparation.supersedes?.expectedRevision !== '1' ||
    original.preparation.supersedes?.successorDigest !==
      predecessor.source.pendingExpiry.preparation.successorDigest
  )
    throw deny();

  if (
    historical.receipt.state !== 'EXPIRED' ||
    historical.receipt.authority !== 'NONE' ||
    !historical.receipt.activation ||
    !historical.activationEvidenceDigest ||
    historical.receipt.activation.operationId !== link.activationOperationId ||
    `sha256:${historical.activationEvidenceDigest.toString('hex')}` !==
      link.activationReceiptDigest ||
    historical.receipt.intentDigest !== link.intentDigest ||
    original.continuation ||
    original.supersession ||
    canonicalAuthorizationDigest(original.preparation) !== link.preparationDigest ||
    original.preparation.replacementId !== link.replacementId ||
    historical.enrollment.platformContextId !== enrollment.platformContextId ||
    historical.enrollment.rootEpoch !== enrollment.rootEpoch ||
    historical.enrollment.rootRevision !== enrollment.rootRevision ||
    historical.enrollment.rootDigest !== enrollment.rootDigest ||
    canonicalAuthorizationDigest(predecessor.recoveryPrincipal) !==
      canonicalAuthorizationDigest(enrollment.recoveryPrincipal) ||
    canonicalAuthorizationDigest(predecessor.custodians) !==
      canonicalAuthorizationDigest(enrollment.custodians) ||
    historical.enrollment.administratorPrincipalIds.some(
      (id, i) => id !== enrollment.administratorPrincipalIds[i],
    )
  )
    throw deny();

  // Reconstruct the four persisted proof commitments, including the activation
  // executor proof. Their historical sessions need not remain live; none is
  // accepted as fresh custody for the new case.
  const selected = await client.query<{
    evidence: Buffer;
    proofs: (PlatformRecoveryProof & {
      assertionDigest: string;
      verified: Record<string, unknown>;
    })[];
    current: boolean;
  }>(
    `select c.activation_evidence_cbor as evidence,
      openpc.${currentPredicate}($1,$3,$4::jsonb,$5::jsonb) as current,
      (select jsonb_agg(jsonb_build_object('proofId',p.proof_id::text,'principalId',p.principal_id::text,
        'principalEpoch',p.principal_epoch::text,'credentialId',p.credential_id::text,
        'credentialEpoch',p.credential_epoch::text,'sessionId',p.session_id::text,
        'sessionEpoch',p.session_epoch::text,'phase',p.phase,'intentDigest','sha256:'||encode(p.intent_digest,'hex'),
        'verifiedAt',p.verified_at,'assertionDigest',encode(p.assertion_digest,'hex'),'verified',p.assertion_evidence->'verified') order by p.verified_at,p.proof_id)
       from control.platform_recovery_proof p join control.platform_recovery_challenge h
        on h.participant_id=p.participant_id and h.privacy_domain_id=p.privacy_domain_id
          and h.recovery_id=p.recovery_id and h.challenge_id=p.challenge_id and h.proof_id=p.proof_id
       where p.participant_id=c.participant_id and p.privacy_domain_id=c.privacy_domain_id
        and p.recovery_id=c.recovery_id and p.intent_digest=c.intent_digest
        and h.consumed_at=p.verified_at and h.principal_id=p.principal_id and h.credential_id=p.credential_id
        and h.session_id=p.session_id and h.session_epoch=p.session_epoch and h.phase=p.phase
        and h.intent_digest=p.intent_digest and p.verified_at<=c.activated_at) as proofs
     from control.platform_recovery_case c where c.participant_id=$1 and c.privacy_domain_id=$2
       and c.recovery_id=$6 and c.enrollment_id=$7`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      enrollment.enrollmentId,
      link,
      original.preparation,
      link.recoveryId,
      link.enrollmentId,
    ],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    !createHash('sha256')
      .update(row.evidence)
      .digest()
      .equals(historical.activationEvidenceDigest) ||
    row.current !== true ||
    row.proofs?.length !== 4 ||
    new Set(row.proofs.map((p) => p.proofId)).size !== 4
  )
    throw deny();
  const fields = [
    'version',
    'credentialId',
    'credentialPublicKeyDigest',
    'principalId',
    'sessionId',
    'actionIntentId',
    'resourceDigest',
    'challengeDigest',
    'rpIdHash',
    'origin',
    'authenticatorDataDigest',
    'clientDataJsonDigest',
    'signatureDigest',
    'signCount',
    'verifiedAt',
    'userVerification',
  ] as const;
  for (const p of row.proofs) {
    if (
      !p.verified ||
      fields.some((field) => typeof p.verified[field] !== 'string') ||
      createHash('sha256')
        .update(fields.map((field) => p.verified[field]).join('\u0000'))
        .digest('hex') !== p.assertionDigest ||
      p.verified.version !== 'OPENPC_VERIFIED_WEBAUTHN_ASSERTION_V1' ||
      p.verified.userVerification !== 'REQUIRED_VERIFIED' ||
      p.verified.principalId !== p.principalId ||
      p.verified.credentialId !== p.credentialId ||
      p.verified.sessionId !== p.sessionId ||
      p.verified.actionIntentId !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' ||
      p.verified.resourceDigest !== link.intentDigest ||
      Date.parse(String(p.verified.verifiedAt)) !== new Date(p.verifiedAt).getTime()
    )
      throw deny();
  }
  const proofs = row.proofs.map(({ assertionDigest: _digest, verified: _verified, ...p }) => ({
    ...p,
    verifiedAt: new Date(p.verifiedAt).toISOString(),
  }));
  const activation = row.proofs.find((p) => p.phase === 'ACTIVATE');
  const prior = proofs.filter((p) => p.phase !== 'ACTIVATE');
  // readRecoveryCeremonyProofs included this signing-time observation in the
  // original three proof preimages. Authenticate that historical representation;
  // it is never used to establish a current session or receiving grant.
  const signedPrior = prior.map((p) => ({ ...p, liveSession: true }));
  const executor = historical.enrollment.recoveryPrincipal;
  const isExecutor = (
    p: Pick<
      PlatformRecoveryProof,
      'principalId' | 'principalEpoch' | 'credentialId' | 'credentialEpoch'
    >,
  ) =>
    p.principalId === executor.principalId &&
    p.principalEpoch === executor.principalEpoch &&
    p.credentialId === executor.credentialId &&
    p.credentialEpoch === executor.credentialEpoch;
  if (
    !activation ||
    prior.length !== 3 ||
    !isExecutor(activation) ||
    prior.filter((p) => p.phase === 'REQUEST' && isExecutor(p)).length !== 1 ||
    historical.enrollment.custodians.some(
      (custodian) =>
        prior.filter(
          (p) =>
            p.phase === 'APPROVE' &&
            p.principalId === custodian.principalId &&
            p.credentialId === custodian.credentialId &&
            p.principalEpoch === custodian.principalEpoch &&
            p.credentialEpoch === custodian.credentialEpoch,
        ).length !== 1,
    )
  )
    throw deny();
  const commit = (purpose: string, value: unknown) =>
    canonicalAuthorizationDigestBytes({
      domain: `pc.identity.platform-recovery.${purpose}.v1`,
      value,
    });
  const claims = decodeIdentityAuthContextAssertionPayload(row.evidence);
  if (
    !claims.participantContextDigest.equals(
      commit('context', [
        historical.enrollment.participantId,
        historical.enrollment.privacyDomainId,
        historical.enrollment.platformContextId,
        historical.enrollment.rootEpoch,
        historical.enrollment.rootDigest,
      ]),
    ) ||
    claims.actorKind !== 0 ||
    claims.senderBindingKind !== 1 ||
    claims.senderCredentialBindingDigest?.equals(
      commit('executor', [
        historical.enrollment.recoveryPrincipal,
        activation.proofId,
        activation.assertionDigest,
      ]),
    ) !== true ||
    !claims.assuranceProfileDigest.equals(
      commit('assurance', [
        historical.enrollment.assurance,
        'independent-two-custodian-webauthn-uv',
        'fixed-recovery-purpose',
        'no-runtime-capability',
      ]),
    ) ||
    !claims.authorityVectorDigest.equals(
      commit('source', [original, prior.map((p) => p.proofId), activation.proofId]),
    ) ||
    !claims.authenticationEvidenceDigest.equals(
      commit('proofs', [...signedPrior, proofs.find((p) => p.proofId === activation.proofId)!]),
    )
  )
    throw deny();
  const preparation = structuredClone(original.preparation);
  return {
    link,
    preparation,
    plannedRecordIds: [
      preparation.replacementId,
      ...preparation.administrators.flatMap((a) => [a.envelopeId, a.assignmentId]),
    ],
  };
}
