import { readActivatedPlatformRecoveryPreparation } from './platform-recovery-activated-handoff.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { decodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import {
  platformRecoveryIntent,
  platformRecoveryContinuation,
  type PendingPlatformRecoveryEnrollment,
  type PendingExpiryPlatformRecoveryEnrollment,
  type PlatformRecoveryIntent,
  type RootExpiryPlatformRecoveryEnrollment,
} from '../contracts/platform-recovery.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import type { IdentityRuntimeAssertionVerifier } from '../domain/identity-kernel.js';
import type { PlatformRecoveryProof } from '../domain/platform-recovery-ceremony.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { readStoredPlatformRecoveryReceipt } from './platform-recovery-readback.js';
import {
  assertUneffectedEnrollmentPermissions,
  type UneffectedRootBridge,
} from '../domain/platform-recovery-uneffected.js';

const deny = () => new PlatformRecoveryError();

/** Historical custody authenticates the original business intent. Only the
 * new independently proven case can authorize its still-unconsumed suffix. */
async function readPendingPlatformRecoveryPreparation(
  client: PoolClient,
  enrollment:
    | PendingPlatformRecoveryEnrollment
    | PendingExpiryPlatformRecoveryEnrollment
    | (RootExpiryPlatformRecoveryEnrollment & {
        uneffectedPredecessor: NonNullable<
          RootExpiryPlatformRecoveryEnrollment['uneffectedPredecessor']
        >;
      }),
  verifier: IdentityRuntimeAssertionVerifier | undefined,
  rootBridge?: UneffectedRootBridge,
) {
  if (!verifier) throw deny();
  const link =
    enrollment.schemaVersion === 2
      ? enrollment.uneffectedPredecessor
      : enrollment.schemaVersion === 3
        ? enrollment.source.continuation
        : enrollment.source.pendingExpiry.preparation;
  const currentPredicate =
    enrollment.schemaVersion === 2
      ? 'platform_recovery_uneffected_source_current'
      : enrollment.schemaVersion === 3
        ? 'platform_recovery_continuation_current'
        : 'platform_recovery_pending_expiry_source_current';
  const historical = await readStoredPlatformRecoveryReceipt(
    client,
    enrollment,
    link.enrollmentId,
    link.recoveryId,
    verifier,
  );
  const original = platformRecoveryIntent.parse(historical.receipt.intent);
  const completion =
    enrollment.schemaVersion === 3 ? enrollment.source.activatedHandoff : undefined;
  if (completion && enrollment.schemaVersion === 3) {
    const predecessor = historical.enrollment;
    if (predecessor.schemaVersion !== 4) throw deny();
    const {
      continuation: _continuation,
      activatedHandoff: _handoff,
      ...currentRootSource
    } = enrollment.source;
    void _continuation;
    void _handoff;
    const predecessorRootSource = { ...predecessor.source } as Record<string, unknown>;
    delete predecessorRootSource.pendingExpiry;
    if (
      predecessor.schemaVersion !== 4 ||
      predecessor.source.pendingExpiry.schemaVersion !== 2 ||
      predecessor.source.closedApproval ||
      canonicalAuthorizationDigest(currentRootSource) !==
        canonicalAuthorizationDigest(predecessorRootSource) ||
      original.completionSourceDigest ||
      original.approvalContinuation ||
      original.closedApprovalSourceDigest ||
      original.pendingExpiry?.schemaVersion !== 2 ||
      canonicalAuthorizationDigest(predecessor) !== completion.predecessorEnrollmentDigest ||
      canonicalAuthorizationDigest(original.pendingExpiry) !==
        canonicalAuthorizationDigest(predecessor.source.pendingExpiry) ||
      canonicalAuthorizationDigest(predecessor.recoveryPrincipal) !==
        canonicalAuthorizationDigest(enrollment.recoveryPrincipal) ||
      canonicalAuthorizationDigest(predecessor.custodians) !==
        canonicalAuthorizationDigest(enrollment.custodians) ||
      original.preparation.supersedes?.replacementId !==
        predecessor.source.pendingExpiry.preparation.replacementId ||
      original.preparation.supersedes?.expectedRevision !== '1' ||
      original.preparation.supersedes?.successorDigest !==
        predecessor.source.pendingExpiry.preparation.successorDigest ||
      completion.administrators.some((item, index) => {
        const planned = original.preparation.administrators[index];
        return (
          !planned ||
          item.principalId !== planned.principalId ||
          item.envelopeId !== planned.envelopeId ||
          item.assignmentId !== planned.assignmentId
        );
      })
    )
      throw deny();
  }
  let exactRootBridge = false;
  if (enrollment.schemaVersion === 4 || (enrollment.schemaVersion === 2 && rootBridge)) {
    const bridge = await client.query<{ current: boolean }>(
      `select openpc.platform_scope_pending_root_bridge_current(r,$4::numeric,$5::numeric,$6::bytea) as current
       from control.platform_scope_replacement r where r.participant_id=$1 and r.privacy_domain_id=$2 and r.replacement_id=$3`,
      [
        enrollment.participantId,
        enrollment.privacyDomainId,
        link.replacementId,
        enrollment.rootEpoch,
        enrollment.rootRevision,
        Buffer.from(enrollment.rootDigest.slice(7), 'hex'),
      ],
    );
    exactRootBridge = bridge.rowCount === 1 && bridge.rows[0]?.current === true;
  }
  if (enrollment.schemaVersion === 2) {
    if (historical.enrollment.schemaVersion !== 2 || (rootBridge && !exactRootBridge)) throw deny();
    try {
      assertUneffectedEnrollmentPermissions(enrollment, historical.enrollment, rootBridge);
    } catch {
      throw deny();
    }
  }
  if (
    (!completion && historical.enrollment.schemaVersion !== 2) ||
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
    (!completion && original.preparation.supersedes) ||
    canonicalAuthorizationDigest(original.preparation) !== link.preparationDigest ||
    original.preparation.replacementId !== link.replacementId ||
    historical.enrollment.platformContextId !== enrollment.platformContextId ||
    (exactRootBridge &&
      (historical.enrollment.rootEpoch !== original.preparation.predecessorEpoch ||
        historical.enrollment.rootRevision !== original.preparation.expectedRootRevision ||
        historical.enrollment.rootDigest !== original.preparation.predecessorDigest)) ||
    (!exactRootBridge &&
      (historical.enrollment.rootEpoch !== enrollment.rootEpoch ||
        historical.enrollment.rootRevision !== enrollment.rootRevision ||
        historical.enrollment.rootDigest !== enrollment.rootDigest)) ||
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

export async function readUneffectedPlatformRecoveryPredecessor(
  client: PoolClient,
  enrollment: RootExpiryPlatformRecoveryEnrollment,
  verifier: IdentityRuntimeAssertionVerifier | undefined,
  rootBridge?: UneffectedRootBridge,
) {
  if (!enrollment.uneffectedPredecessor) throw deny();
  const original = await readPendingPlatformRecoveryPreparation(
    client,
    { ...enrollment, uneffectedPredecessor: enrollment.uneffectedPredecessor },
    verifier,
    rootBridge,
  );
  return { uneffectedPreparation: original.preparation };
}

export async function readPendingPlatformRecoveryContinuation(
  client: PoolClient,
  enrollment: PendingPlatformRecoveryEnrollment,
  verifier: IdentityRuntimeAssertionVerifier | undefined,
) {
  const { link, ...original } = await readPendingPlatformRecoveryPreparation(
    client,
    enrollment,
    verifier,
  );
  return {
    ...original,
    recoveryContinuation: platformRecoveryContinuation.parse(link),
    continuationPreparation: original.preparation,
  };
}

/** Distinct terminal-expiry purpose; no old signed lease or effect is renewed. */
export async function readPendingPlatformRecoveryExpiry(
  client: PoolClient,
  enrollment: PendingExpiryPlatformRecoveryEnrollment,
  verifier: IdentityRuntimeAssertionVerifier | undefined,
) {
  const original =
    enrollment.source.pendingExpiry.schemaVersion === 2
      ? await readActivatedPlatformRecoveryPreparation(client, enrollment, verifier)
      : await readPendingPlatformRecoveryPreparation(client, enrollment, verifier);
  return {
    pendingExpiry: enrollment.source.pendingExpiry,
    expiryPreparation: original.preparation,
    preparation: original.preparation,
    originalAdministrators: original.preparation.administrators,
  };
}

/** Authenticate the original SUPERSEDED -> this case's WITHDRAWING transition.
 * A pending ID alone, a different persisted case, or a body drift is insufficient. */
export async function readPendingPlatformRecoveryExpirySuccessor(
  client: PoolClient,
  enrollment: PendingExpiryPlatformRecoveryEnrollment,
  intent: PlatformRecoveryIntent,
  plannedRecordIds: readonly string[],
  pendingReplacementId: string | null,
) {
  if (!pendingReplacementId || pendingReplacementId !== intent.preparation.replacementId)
    throw deny();
  const selected = await client.query<{ current: boolean }>(
    `select exists(select 1 from control.platform_recovery_case c
      join control.platform_scope_replacement original
        on original.participant_id=c.participant_id and original.privacy_domain_id=c.privacy_domain_id
        and original.replacement_id=$4 and original.state='SUPERSEDED' and original.row_version=2
      join control.platform_scope_replacement successor
        on successor.participant_id=original.participant_id and successor.privacy_domain_id=original.privacy_domain_id
        and successor.replacement_id=original.superseded_by and successor.replacement_id=$5
        and successor.state='WITHDRAWING' and successor.row_version=1 and successor.superseded_by is null
        and successor.platform_context_id=original.platform_context_id
        and ((successor.predecessor_epoch=original.predecessor_epoch
          and successor.expected_root_revision=original.expected_root_revision and successor.predecessor_digest=original.predecessor_digest)
          or openpc.platform_scope_pending_root_bridge_current(original,successor.predecessor_epoch,successor.expected_root_revision,successor.predecessor_digest))
      where c.participant_id=$1 and c.privacy_domain_id=$2 and c.enrollment_id=$3
        and c.recovery_id=$6 and c.state='ACTIVE' and c.intent=$7::jsonb
        and c.intent_digest=$8 and c.planned_record_ids=$9::jsonb
        and successor.candidate=c.intent->'preparation' and successor.candidate_digest=$10
        and openpc.platform_recovery_pending_expiry_intent_current(c.participant_id,c.enrollment_id,c.intent)
      ) as current`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      enrollment.enrollmentId,
      enrollment.source.pendingExpiry.preparation.replacementId,
      pendingReplacementId,
      intent.recoveryId,
      JSON.stringify(intent),
      canonicalAuthorizationDigestBytes(intent),
      JSON.stringify(plannedRecordIds),
      canonicalAuthorizationDigestBytes(intent.preparation),
    ],
  );
  if (selected.rowCount !== 1 || selected.rows[0]?.current !== true) throw deny();
  return {
    replacementId: pendingReplacementId,
    recoveryId: intent.recoveryId,
    intentDigest: canonicalAuthorizationDigest(intent),
    preparationDigest: canonicalAuthorizationDigest(intent.preparation),
    plannedRecordIds: [...plannedRecordIds],
  };
}

/** No historical grant is promoted to current authority. The consuming owner
 * separately fences the selected new grant and every current actor. */
export async function hasPlatformRecoveryProposalHistory(
  client: PoolClient,
  scope: { readonly participantId: string; readonly privacyDomainId: string },
  selectedEnvelopeId: string,
  proposalId: string,
): Promise<boolean> {
  const selected = await client.query<{ admitted: boolean }>(
    'select openpc.platform_recovery_proposal_history_current($1,$2,$3,$4) as admitted',
    [scope.participantId, scope.privacyDomainId, selectedEnvelopeId, proposalId],
  );
  return selected.rowCount === 1 && selected.rows[0]?.admitted === true;
}
