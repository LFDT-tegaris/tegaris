import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { encodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import {
  platformRecoveryIntent,
  type PendingExpiryPlatformRecoveryEnrollment,
} from '../contracts/platform-recovery.js';
import type { IdentityRuntimeAssertionVerifier } from '../domain/identity-kernel.js';
import { identityActorKeyDigest } from '../domain/identity-runtime-authorization.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { readStoredPlatformRecoveryReceipt } from './platform-recovery-readback.js';

/** Authenticate a declared closed initial approval without treating either its
 * expired enrollment or its historical signatures as current authority. */
export async function readClosedPlatformApprovalSource(
  client: PoolClient,
  enrollment: PendingExpiryPlatformRecoveryEnrollment,
  verifier: IdentityRuntimeAssertionVerifier | undefined,
) {
  const source = enrollment.source.closedApproval;
  if (!source || !verifier) throw new PlatformRecoveryError();
  const original = await readStoredPlatformRecoveryReceipt(
    client,
    enrollment,
    source.enrollmentId,
    source.approval.recoveryId,
    verifier,
  );
  const previous = original.enrollment;
  const intent = platformRecoveryIntent.parse(original.receipt.intent);
  const custody = (value: PendingExpiryPlatformRecoveryEnrollment) => {
    const copy = structuredClone(value) as Partial<PendingExpiryPlatformRecoveryEnrollment>;
    delete copy.enrollmentId;
    delete copy.validFrom;
    delete copy.validUntil;
    if (copy.source) delete copy.source.closedApproval;
    return copy;
  };
  if (
    previous.schemaVersion !== 4 ||
    previous.source.closedApproval ||
    canonicalAuthorizationDigest(previous) !== source.enrollmentDigest ||
    canonicalAuthorizationDigest(custody(previous)) !==
      canonicalAuthorizationDigest(custody(enrollment)) ||
    intent.approvalContinuation ||
    intent.continuation ||
    intent.supersession ||
    original.receipt.state !== source.closure.state ||
    original.receipt.authority !== 'NONE' ||
    original.receipt.revision !== source.closure.revision ||
    original.receipt.intentDigest !== source.approval.intentDigest ||
    original.receipt.activation?.operationId !== source.approval.activationOperationId ||
    !original.activationEvidenceDigest ||
    `sha256:${original.activationEvidenceDigest.toString('hex')}` !==
      source.approval.activationReceiptDigest ||
    canonicalAuthorizationDigest(intent.preparation) !== source.approval.candidateDigest ||
    original.receipt.proofs.length !== 4 ||
    new Set(original.receipt.proofs.map((p) => p.proofId)).size !== 4 ||
    source.approval.attempt !== '1' ||
    source.enrollmentId === enrollment.enrollmentId
  )
    throw new PlatformRecoveryError();
  const selected = await client.query<{
    evidenceCbor: Buffer;
    evidenceDigest: Buffer;
    cose: Buffer;
    current: boolean;
  }>(
    `select event.payload_cbor as "evidenceCbor",event.payload_digest as "evidenceDigest",
      event.cose_sign1 as cose,
      openpc.platform_recovery_closed_approval_source_current($1,$3,null::uuid) as current
     from control.outbox_event event
     where event.participant_id=$1 and event.privacy_domain_id=$2
      and event.event_id=$4 and event.aggregate_type='platform-recovery'
      and event.aggregate_id=$5 and event.event_type='openpc.identity.platform-recovery.closed.v1'
      and event.occurred_at=$6::timestamptz`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      enrollment.enrollmentId,
      source.closure.eventId,
      source.approval.recoveryId,
      source.closure.closedAt,
    ],
  );
  const row = selected.rows[0];
  const closure = source.closure;
  const commit = (purpose: string, value: unknown) =>
    canonicalAuthorizationDigestBytes({
      domain: `pc.identity.platform-recovery.${purpose}.v1`,
      value,
    });
  const now = Date.parse(closure.closedAt);
  const payload = encodeIdentityAuthContextAssertionPayload({
    assertionId: closure.operationId,
    actorKind: 0,
    actorKeyDigest: identityActorKeyDigest(previous.participantId, closure.actorPrincipalId),
    participantContextDigest: commit('context', [
      previous.participantId,
      previous.privacyDomainId,
      previous.platformContextId,
      previous.rootEpoch,
      previous.rootDigest,
    ]),
    audienceDigest: commit('closure', {
      recoveryId: source.approval.recoveryId,
      enrollmentId: source.enrollmentId,
      operationId: closure.operationId,
      state: closure.state,
      revision: closure.revision,
      authority: 'NONE',
      actorPrincipalId: closure.actorPrincipalId,
      closedAt: closure.closedAt,
    }),
    senderBindingKind: 1,
    senderCredentialBindingDigest: commit('closure-session', closure.session),
    assuranceProfileDigest: commit('assurance', [
      previous.assurance,
      'authenticated-enrolled-actor-closure',
      'no-authority',
    ]),
    authorityVectorDigest: commit('closure-source', [
      previous,
      source.approval.recoveryId,
      (BigInt(closure.revision) - 1n).toString(),
    ]),
    authenticationEvidenceDigest: commit('closure-actor', [
      closure.actorPrincipalId,
      closure.session,
    ]),
    issuedAtNs: BigInt(now) * 1000000n,
    expiresAtNs: BigInt(now + 60000) * 1000000n,
  });
  if (
    selected.rowCount !== 1 ||
    !row ||
    !row.current ||
    !row.evidenceCbor.equals(payload) ||
    !createHash('sha256').update(payload).digest().equals(row.evidenceDigest) ||
    `sha256:${row.evidenceDigest.toString('hex')}` !== closure.evidenceDigest ||
    !(await verifier.verifyCanonicalAssertion(payload, row.cose))
  )
    throw new PlatformRecoveryError();
  return {
    approvalContinuation: source.approval,
    approvalContinuationPreparation: intent.preparation,
    preparation: intent.preparation,
    plannedRecordIds: [
      intent.preparation.replacementId,
      ...intent.preparation.administrators.flatMap((a) => [a.envelopeId, a.assignmentId]),
    ],
  };
}
