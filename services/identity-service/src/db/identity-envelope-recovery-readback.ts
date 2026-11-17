import type { PoolClient } from 'pg';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import { authenticateHistoricalIdentityEnvelopeRecoveryCustody } from '../domain/identity-envelope-recovery-custody.js';
import {
  identityEnvelopeRecoveryIntent,
  identityEnvelopeRecoveryReceiptView,
} from '../contracts/identity-envelope-recovery.js';
import { authenticateHistoricalIdentityEnvelopeRecoveryLease } from '../domain/identity-envelope-recovery-lease-history.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { readPlatformRecoverySession } from './platform-recovery-proof.js';

/** Historical intent/evidence with a current fixed human session. Expired or
 * revoked custody can be read but cannot reissue a proof or activate a lease. */
export async function readIdentityEnvelopeRecoveryReceipt(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
  localQaEnabled: boolean,
  signer?: IdentityRuntimeEvidenceSigner,
  authorityEvaluation: 'CURRENT' | 'CUSTODY_ONLY' = 'CURRENT',
) {
  if (authorityEvaluation !== 'CURRENT' && authorityEvaluation !== 'CUSTODY_ONLY')
    throw new PlatformRecoveryError();
  const result = await client.query<{
    document: unknown;
    documentDigest: Buffer;
    signature: Buffer;
    pin: unknown;
    intent: unknown;
    intentDigest: Buffer;
    state: string;
    revision: string;
    enrollmentRevision: string;
    enrollmentState: string;
    pinState: string;
    now: Date;
    bindings: unknown;
    activatedAt: Date | null;
    operationId: string | null;
    evidenceCbor: Buffer | null;
    evidenceDigest: Buffer | null;
    cose: Buffer | null;
    current: boolean;
    reviewedAt: Date | null;
  }>(
    `select e.document,e.document_digest as "documentDigest",e.signature,t.document as pin,c.intent,c.intent_digest as "intentDigest",
      c.state,c.enrollment_revision::text as "enrollmentRevision",c.row_version::text as revision,e.state as "enrollmentState",t.state as "pinState",clock_timestamp() as now,
      c.lease_bindings as bindings,c.activated_at as "activatedAt",c.activation_operation_id::text as "operationId",
      c.activation_evidence_cbor as "evidenceCbor",c.activation_evidence_digest as "evidenceDigest",c.activation_cose as cose,
      ${authorityEvaluation === 'CURRENT' ? 'openpc.identity_envelope_recovery_lease_current(c.recovery_id)' : 'false'} as current,c.reviewed_at as "reviewedAt"
     from control.platform_recovery_case c join control.identity_envelope_recovery_enrollment e
      on e.enrollment_id=c.signer_repair_enrollment_id and e.participant_id=c.participant_id and e.privacy_domain_id=c.privacy_domain_id
      and e.document_digest=c.enrollment_digest
     join control.identity_envelope_recovery_custody_trust t on t.custody_trust_id=e.custody_trust_id
      and t.participant_id=e.participant_id and t.privacy_domain_id=e.privacy_domain_id and t.document_digest=e.custody_trust_digest
     where c.participant_id=$1 and c.signer_repair_enrollment_id=$2 and c.recovery_id=$3
      and openpc.matches_privacy(c.privacy_domain_id)`,
    [actor.participantId, enrollmentId, recoveryId],
  );
  const row = result.rows[0];
  if (result.rowCount !== 1 || !row) throw new PlatformRecoveryError();
  const enrollment = authenticateHistoricalIdentityEnvelopeRecoveryCustody(row.pin, {
    document: row.document,
    signature: row.signature.toString('base64url'),
  });
  const intent = identityEnvelopeRecoveryIntent.parse(row.intent);
  if (
    enrollment.enrollmentId !== enrollmentId ||
    enrollment.participantId !== actor.participantId ||
    (enrollment.profile === 'LOCAL_QA' && !localQaEnabled) ||
    ![
      enrollment.recoveryPrincipal.principalId,
      ...enrollment.custodians.map((v) => v.principalId),
    ].includes(actor.principalId) ||
    intent.recoveryId !== recoveryId ||
    intent.enrollmentId !== enrollmentId ||
    intent.enrollmentRevision !== row.enrollmentRevision ||
    canonicalAuthorizationDigest(enrollment) !== `sha256:${row.documentDigest.toString('hex')}` ||
    intent.enrollmentDigest !== canonicalAuthorizationDigest(enrollment) ||
    canonicalAuthorizationDigest(intent) !== `sha256:${row.intentDigest.toString('hex')}`
  )
    throw new PlatformRecoveryError();
  const session = await readPlatformRecoverySession(client, actor, enrollment);
  const nowMs = new Date(row.now).getTime();
  if (!Number.isFinite(nowMs)) throw new PlatformRecoveryError();
  const proofs = await client.query<{
    principalId: string;
    phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE';
    proofId: string;
    verifiedAt: Date;
    intentDigest: Buffer;
  }>(
    `select principal_id::text as "principalId",phase,proof_id::text as "proofId",verified_at as "verifiedAt",intent_digest as "intentDigest"
     from control.platform_recovery_proof where participant_id=$1 and privacy_domain_id=$2 and recovery_id=$3 order by verified_at,proof_id`,
    [enrollment.participantId, enrollment.privacyDomainId, recoveryId],
  );
  if (
    proofs.rows.some(
      (proof) =>
        !proof.intentDigest.equals(row.intentDigest) ||
        !Number.isFinite(new Date(proof.verifiedAt).getTime()) ||
        new Date(proof.verifiedAt).getTime() > nowMs,
    )
  )
    throw new PlatformRecoveryError();
  let lease;
  if (row.activatedAt !== null) {
    lease = await authenticateHistoricalIdentityEnvelopeRecoveryLease(
      {
        enrollment,
        intent,
        bindings: row.bindings,
        activationOperationId: row.operationId,
        activatedAt: row.activatedAt,
        evidenceCbor: row.evidenceCbor,
        evidenceDigest: row.evidenceDigest,
        coseSign1: row.cose,
      },
      signer,
    );
  }

  return {
    enrollment,
    intent,
    session,
    receipt: identityEnvelopeRecoveryReceiptView.parse({
      actors: {
        executorPrincipalId: enrollment.recoveryPrincipal.principalId,
        custodianPrincipalIds: enrollment.custodians.map((custodian) => custodian.principalId),
      },
      assurance: enrollment.assurance,
      proofs: proofs.rows.map(({ principalId, phase, proofId, verifiedAt }) => ({
        principalId,
        phase,
        proofId,
        verifiedAt: new Date(verifiedAt).toISOString(),
      })),
      recoveryId,
      enrollmentId,
      revision: row.revision,
      state: row.state,
      intent,
      intentDigest: canonicalAuthorizationDigest(intent),
      authority:
        authorityEvaluation === 'CURRENT' &&
        lease &&
        row.state === 'ACTIVE' &&
        row.current === true &&
        nowMs < Date.parse(lease.validUntil)
          ? ('IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY' as const)
          : ('NONE' as const),
      ...(lease
        ? { lease, activationEvidenceDigest: `sha256:${row.evidenceDigest!.toString('hex')}` }
        : {}),
      postReviewRequired: true,
      postReviewStatus: row.reviewedAt !== null ? ('REVIEWED' as const) : ('REQUIRED' as const),
      expired: nowMs >= Date.parse(intent.validUntil),
      enrollmentState: row.enrollmentState,
      receivingTrustState: row.pinState,
    }),
  };
}
