import {
  discoveryCertificateIssuancePolicy,
  type DiscoveryCertificateIssuancePolicy,
} from './discovery-certificate-issuance-policy.js';
import { IdentityKernelError } from './identity-errors.js';
import type { WorkloadIssuerRecovery } from './workload-credential-issuer.js';

export interface DiscoveryCertificateIssuanceState {
  readonly state: 'PREPARED' | 'ISSUING' | 'AMBIGUOUS' | 'OBSERVED' | 'COMMITTED' | 'REJECTED';
  readonly issuerProfileDigest: Buffer;
  readonly replayProfile: WorkloadIssuerRecovery['replayProfile'];
  readonly attemptCount: number;
  readonly latestAttemptDeadline: Date | null;
}
export type DiscoveryCertificateIssuanceNext =
  | { readonly kind: 'CLAIM'; readonly deadline: Date }
  | {
      readonly kind:
        | 'IN_PROGRESS'
        | 'MARK_AMBIGUOUS'
        | 'RECONCILE_REQUIRED'
        | 'ATTEMPT_LIMIT'
        | 'COMMIT_OBSERVATION'
        | 'READ_COMMITTED'
        | 'REJECTED';
    };

/** Scheduling only. The owner must independently revalidate actual custody,
 * maker/checker, current source and one-use step-up before claiming any I/O.
 * Observation and committed readback never authorize another issuer request. */
export function nextDiscoveryCertificateIssuance(
  issuance: DiscoveryCertificateIssuanceState,
  issuer: WorkloadIssuerRecovery,
  configured: DiscoveryCertificateIssuancePolicy,
  now: Date,
  authorityExpiresAt: Date,
): DiscoveryCertificateIssuanceNext {
  const policy = discoveryCertificateIssuancePolicy.parse(configured);
  if (
    !['PREPARED', 'ISSUING', 'AMBIGUOUS', 'OBSERVED', 'COMMITTED', 'REJECTED'].includes(
      issuance.state,
    ) ||
    !['IMMUTABLE_REQUEST_RESPONSE', 'READBACK_REQUIRED'].includes(issuer.replayProfile) ||
    !Number.isFinite(now.getTime()) ||
    !Number.isFinite(authorityExpiresAt.getTime()) ||
    issuance.issuerProfileDigest.length !== 32 ||
    issuer.profileDigest.length !== 32 ||
    !issuance.issuerProfileDigest.equals(issuer.profileDigest) ||
    issuance.replayProfile !== issuer.replayProfile ||
    !Number.isSafeInteger(issuance.attemptCount) ||
    issuance.attemptCount < 0 ||
    (issuance.latestAttemptDeadline !== null &&
      !Number.isFinite(issuance.latestAttemptDeadline.getTime()))
  )
    throw new IdentityKernelError('PC-IDENTITY-1006');
  if (
    ['OBSERVED', 'COMMITTED'].includes(issuance.state) &&
    (issuance.attemptCount === 0 || issuance.latestAttemptDeadline === null)
  )
    throw new IdentityKernelError('PC-IDENTITY-1006');
  if (issuance.state === 'COMMITTED') return { kind: 'READ_COMMITTED' };
  if (issuance.state === 'OBSERVED') return { kind: 'COMMIT_OBSERVATION' };
  if (issuance.state === 'REJECTED') return { kind: 'REJECTED' };
  if (issuance.state === 'ISSUING') {
    if (issuance.attemptCount === 0 || issuance.latestAttemptDeadline === null)
      throw new IdentityKernelError('PC-IDENTITY-1006');
    return { kind: issuance.latestAttemptDeadline > now ? 'IN_PROGRESS' : 'MARK_AMBIGUOUS' };
  }
  if (issuance.state === 'AMBIGUOUS' && issuer.replayProfile === 'READBACK_REQUIRED')
    return { kind: 'RECONCILE_REQUIRED' };
  if (
    issuance.state === 'PREPARED' &&
    (issuance.attemptCount !== 0 || issuance.latestAttemptDeadline !== null)
  )
    throw new IdentityKernelError('PC-IDENTITY-1006');
  if (
    issuance.state === 'AMBIGUOUS' &&
    (issuance.attemptCount === 0 || issuance.latestAttemptDeadline === null)
  )
    throw new IdentityKernelError('PC-IDENTITY-1006');
  if (issuance.attemptCount >= policy.maximumAttempts) return { kind: 'ATTEMPT_LIMIT' };
  if (authorityExpiresAt <= now) throw new IdentityKernelError('PC-AUTH-0005');
  return {
    kind: 'CLAIM',
    deadline: new Date(Math.min(now.getTime() + policy.attemptMs, authorityExpiresAt.getTime())),
  };
}
