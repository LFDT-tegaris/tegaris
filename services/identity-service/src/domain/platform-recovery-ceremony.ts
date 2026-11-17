import type {
  LocalRootExpiryRecoveryEnrollment,
  LocalRootExpiryRecoveryIntent,
} from '../contracts/local-root-expiry-recovery.js';
import type {
  IdentityEnvelopeRecoveryEnrollment,
  IdentityEnvelopeRecoveryIntent,
} from '../contracts/identity-envelope-recovery.js';
import type {
  PlatformRecoveryEnrollment,
  RootExpiryPlatformRecoveryEnrollment,
  PendingPlatformRecoveryEnrollment,
  PendingExpiryPlatformRecoveryEnrollment,
  PlatformRecoveryIntent,
  PlatformRecoverySigner,
} from '../contracts/platform-recovery.js';
import type {
  DiscoveryCertificateRecoveryEnrollment,
  DiscoveryCertificateRecoveryIntent,
} from '../contracts/discovery-certificate-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { PlatformRecoveryError } from './platform-recovery-policy.js';

export type PlatformRecoveryPhase = 'REQUEST' | 'APPROVE' | 'ACTIVATE';
export type RecoveryCustodyEnrollment =
  | PlatformRecoveryEnrollment
  | RootExpiryPlatformRecoveryEnrollment
  | PendingPlatformRecoveryEnrollment
  | PendingExpiryPlatformRecoveryEnrollment
  | DiscoveryCertificateRecoveryEnrollment
  | IdentityEnvelopeRecoveryEnrollment
  | LocalRootExpiryRecoveryEnrollment;
export type RecoveryCustodyIntent =
  | PlatformRecoveryIntent
  | DiscoveryCertificateRecoveryIntent
  | IdentityEnvelopeRecoveryIntent
  | LocalRootExpiryRecoveryIntent;
export interface PlatformRecoveryProof {
  readonly proofId: string;
  readonly principalId: string;
  readonly principalEpoch: string;
  readonly credentialId: string;
  readonly credentialEpoch: string;
  readonly sessionId: string;
  readonly sessionEpoch: string;
  readonly phase: PlatformRecoveryPhase;
  readonly intentDigest: string;
  readonly verifiedAt: Date;
  /** Loaded only from the original immutable challenge; absent legacy pins stay five minutes. */
  readonly verifiedProofMaxAgeMs?: 300000 | 3000000;
}

export function platformRecoveryProofMaxAgeMs(
  proof: PlatformRecoveryProof,
  intent: RecoveryCustodyIntent,
): 300000 | 3000000 {
  const age = proof.verifiedProofMaxAgeMs ?? 300000;
  if (age === 300000) return age;
  if (
    age === 3000000 &&
    (('lifetimes' in intent && intent.lifetimes?.profile === 'LOCAL_QA_10X') ||
      ('qaDurationProfile' in intent && intent.qaDurationProfile === 'LOCAL_QA_10X'))
  )
    return age;
  throw new PlatformRecoveryError();
}

/** Fixed enrollment determines ceremony actors; no ordinary role can substitute for a custodian. */
export function platformRecoverySignerForPhase(
  enrollment: RecoveryCustodyEnrollment,
  principalId: string,
  phase: PlatformRecoveryPhase,
): PlatformRecoverySigner {
  const signer = (
    phase === 'APPROVE' ? enrollment.custodians : [enrollment.recoveryPrincipal]
  ).find((v) => v.principalId === principalId);
  if (!signer) throw new PlatformRecoveryError();
  return signer;
}

/** Operates on owner-verified stored proofs, never on caller assertions. Fresh source/credential reads remain required. */
export function assertPlatformRecoveryCeremony(
  enrollment: RecoveryCustodyEnrollment,
  intent: RecoveryCustodyIntent,
  state: string,
  proofs: readonly PlatformRecoveryProof[],
  phase: PlatformRecoveryPhase,
  principalId: string,
  now: Date,
): void {
  platformRecoverySignerForPhase(enrollment, principalId, phase);
  const fail = () => {
    throw new PlatformRecoveryError();
  };
  const nowMs = now.getTime();
  if (
    intent.schema !==
    (
      {
        'pc.identity.platform-recovery-enrollment': 'pc.identity.platform-recovery-intent',
        'pc.identity.local-root-expiry-recovery-enrollment':
          'pc.identity.local-root-expiry-recovery-intent',
        'pc.identity.discovery-certificate-recovery-enrollment':
          'pc.identity.discovery-certificate-recovery-intent',
        'pc.identity.identity-envelope-recovery-enrollment':
          'pc.identity.identity-envelope-recovery-intent',
      } as const
    )[enrollment.schema]
  )
    fail();
  if (
    intent.enrollmentId !== enrollment.enrollmentId ||
    intent.enrollmentDigest !== canonicalAuthorizationDigest(enrollment)
  )
    fail();
  if (
    !Number.isFinite(nowMs) ||
    nowMs < Date.parse(intent.validFrom) ||
    nowMs >= Date.parse(intent.validUntil)
  )
    fail();
  if ((phase === 'REQUEST' && state !== 'DRAFT') || (phase !== 'REQUEST' && state !== 'REQUESTED'))
    fail();
  const digest = canonicalAuthorizationDigest(intent);
  const seen = new Set<string>();
  for (const proof of proofs) {
    const signer = platformRecoverySignerForPhase(enrollment, proof.principalId, proof.phase);
    const key = `${proof.phase}:${proof.principalId}`;
    if (
      seen.has(key) ||
      proof.phase === 'ACTIVATE' ||
      proof.intentDigest !== digest ||
      proof.principalEpoch !== signer.principalEpoch ||
      proof.credentialId !== signer.credentialId ||
      proof.credentialEpoch !== signer.credentialEpoch ||
      !/^[1-9][0-9]*$/u.test(proof.sessionEpoch) ||
      !Number.isFinite(proof.verifiedAt.getTime()) ||
      proof.verifiedAt.getTime() > nowMs ||
      proof.verifiedAt.getTime() < Date.parse(intent.validFrom) ||
      nowMs - proof.verifiedAt.getTime() >= platformRecoveryProofMaxAgeMs(proof, intent)
    )
      fail();
    seen.add(key);
  }
  if (phase === 'REQUEST') {
    if (proofs.length !== 0) fail();
    return;
  }
  if (!seen.has(`REQUEST:${enrollment.recoveryPrincipal.principalId}`)) fail();
  if (phase === 'APPROVE') {
    if (seen.has(`APPROVE:${principalId}`)) fail();
    return;
  }
  if (
    proofs.length !== 3 ||
    enrollment.custodians.some((v) => !seen.has(`APPROVE:${v.principalId}`))
  )
    fail();
}
