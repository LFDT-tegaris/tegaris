import { createHash } from 'node:crypto';
import { decodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryRotationCompletionResult,
  type IdentityEnvelopeRecoveryEnrollment,
  type IdentityEnvelopeRecoveryLease,
  type IdentityEnvelopeRecoveryRotationCompletionResult,
} from '../contracts/identity-envelope-recovery.js';
import type { IdentityRuntimeAssertionVerifier } from '../domain/identity-kernel.js';
import { identityEnvelopeRecoveryEvidencePayload } from '../domain/identity-envelope-recovery-evidence.js';
import { identityActorKeyDigest } from '../domain/identity-runtime-authorization.js';

export class WorkloadSigningRepairClosureUnavailable extends Error {
  constructor() {
    super('Original signing repair closure is unavailable');
  }
}
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const tagged = (value: Buffer) => 'sha256:' + value.toString('hex');
interface ReviewBinding {
  participantId: string;
  privacyDomainId: string;
  recoveryId: string;
  enrollmentId: string;
  enrollmentDigest: string;
  reviewOperationId: string;
  leaseClosureState: 'REVOKED' | 'EXPIRED';
  closedCaseRevision: string;
  reviewedAt: string;
}
interface ClosureCaseRow {
  state: string;
  revision: string;
  enrollmentDigest: Buffer;
  intentDigest: Buffer;
  bindings: unknown;
  activatedAt: Date;
  activationOperationId: string;
  reviewedAt: Date;
  reviewOperationId: string;
}

/** Caller authenticates original custody/lease, completed rotation and consumed
 * ordinary review first, under its existing fenced transaction. The review's
 * consumed candidate supplies the original closed revision. Today's session,
 * clock or case updated_at cannot recreate closure. Original authentication
 * evidence remains an opaque signed commitment, never a new live capability. */
export async function readWorkloadSigningRepairClosure(
  client: PoolClient,
  input: {
    enrollment: IdentityEnvelopeRecoveryEnrollment;
    lease: IdentityEnvelopeRecoveryLease;
    completion: IdentityEnvelopeRecoveryRotationCompletionResult;
    review: ReviewBinding;
    closureOperationId: string;
  },
  verifier: IdentityRuntimeAssertionVerifier,
) {
  const { enrollment, lease, review } = input;
  const deny = (): never => {
    throw new WorkloadSigningRepairClosureUnavailable();
  };
  let completion: IdentityEnvelopeRecoveryRotationCompletionResult;
  try {
    completion = identityEnvelopeRecoveryRotationCompletionResult.parse(input.completion);
    z.uuidv7().parse(input.closureOperationId);
    z.uuidv7().parse(review.reviewOperationId);
    revision.parse(review.closedCaseRevision);
    if (
      review.participantId !== enrollment.participantId ||
      review.privacyDomainId !== enrollment.privacyDomainId ||
      review.recoveryId !== lease.recoveryId ||
      review.enrollmentId !== enrollment.enrollmentId ||
      review.enrollmentDigest !== canonicalAuthorizationDigest(enrollment) ||
      lease.enrollmentDigest !== review.enrollmentDigest ||
      lease.enrollmentId !== enrollment.enrollmentId ||
      completion.rotationId !== lease.rotationId ||
      completion.recoveryId !== lease.recoveryId ||
      !['REVOKED', 'EXPIRED'].includes(review.leaseClosureState) ||
      new Set([completion.operationId, input.closureOperationId, review.reviewOperationId]).size !==
        3
    )
      return deny();
  } catch {
    return deny();
  }
  await client.query('select openpc.assert_request_context(true)');
  const cases = await client.query<ClosureCaseRow>(
    `select c.state,c.row_version::text as revision,c.enrollment_digest as "enrollmentDigest",c.intent_digest as "intentDigest",
      c.lease_bindings as bindings,c.activated_at as "activatedAt",c.activation_operation_id::text as "activationOperationId",
      c.reviewed_at as "reviewedAt",c.review_operation_id::text as "reviewOperationId"
    from control.platform_recovery_case c where c.participant_id=$1 and c.privacy_domain_id=$2
      and c.recovery_id=$3 and c.signer_repair_enrollment_id=$4 and c.state in('REVOKED','EXPIRED')
      and c.activated_at is not null and c.reviewed_at is not null and c.review_operation_id=$5
      and openpc.matches_participant($1::uuid) and openpc.matches_privacy($2::uuid)
    for share of c`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      lease.recoveryId,
      enrollment.enrollmentId,
      review.reviewOperationId,
    ],
  );
  const row = cases.rows[0];
  if (cases.rowCount !== 1 || cases.rows.length !== 1 || !row) return deny();
  const events = await client.query<{
    cbor: Buffer;
    digest: Buffer;
    cose: Buffer;
    occurredAt: Date;
  }>(
    `select payload_cbor as cbor,payload_digest as digest,cose_sign1 as cose,occurred_at as "occurredAt"
    from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='platform-recovery'
      and aggregate_id=$3 and event_type='openpc.identity.envelope-recovery.closed.v1'
      and openpc.matches_participant($1::uuid) and openpc.matches_privacy($2::uuid)
    limit 2`,
    [enrollment.participantId, enrollment.privacyDomainId, lease.recoveryId],
  );
  const event = events.rows[0];
  if (events.rowCount !== 1 || events.rows.length !== 1 || !event) return deny();
  try {
    revision.parse(row.revision);
    const closedAt = event.occurredAt.toISOString();
    const reviewedAt = row.reviewedAt.toISOString();
    if (
      row.state !== review.leaseClosureState ||
      BigInt(row.revision) !== BigInt(review.closedCaseRevision) + 1n ||
      ![row.enrollmentDigest, row.intentDigest, event.digest].every(
        (bytes) => Buffer.isBuffer(bytes) && bytes.length === 32,
      ) ||
      tagged(row.enrollmentDigest) !== lease.enrollmentDigest ||
      tagged(row.intentDigest) !== lease.intentDigest ||
      canonicalAuthorizationDigest(row.bindings) !== canonicalAuthorizationDigest(lease) ||
      row.activationOperationId !== lease.activationOperationId ||
      row.activatedAt.getTime() !== Date.parse(lease.validFrom) ||
      row.reviewOperationId !== review.reviewOperationId ||
      reviewedAt !== review.reviewedAt ||
      Date.parse(closedAt) < Date.parse(completion.completedAt) ||
      Date.parse(closedAt) < Date.parse(lease.validFrom) ||
      Date.parse(closedAt) > Date.parse(reviewedAt) ||
      !event.digest.equals(createHash('sha256').update(event.cbor).digest())
    )
      return deny();
    const claims = decodeIdentityAuthContextAssertionPayload(event.cbor);
    const closers = [
      enrollment.recoveryPrincipal.principalId,
      ...enrollment.custodians.map((value) => value.principalId),
    ].filter((id) =>
      claims.actorKeyDigest.equals(identityActorKeyDigest(enrollment.participantId, id)),
    );
    if (claims.assertionId !== input.closureOperationId || closers.length !== 1) return deny();
    const value = {
      recoveryId: lease.recoveryId,
      enrollmentId: enrollment.enrollmentId,
      operationId: input.closureOperationId,
      state: review.leaseClosureState,
      revision: review.closedCaseRevision,
      authority: 'NONE' as const,
      actorPrincipalId: closers[0]!,
      closedAt,
    };
    const expected = identityEnvelopeRecoveryEvidencePayload({
      enrollment,
      operationId: input.closureOperationId,
      actorPrincipalId: closers[0]!,
      purpose: 'closure',
      value,
      authenticationDigest: tagged(claims.authenticationEvidenceDigest),
      issuedAt: closedAt,
      expiresAt: new Date(Date.parse(closedAt) + 60000).toISOString(),
    });
    if (
      !event.cbor.equals(expected) ||
      !(await verifier.verifyCanonicalAssertion(expected, event.cose))
    )
      return deny();
    return Object.freeze({ ...value, evidenceDigest: tagged(event.digest) });
  } catch {
    return deny();
  }
}
