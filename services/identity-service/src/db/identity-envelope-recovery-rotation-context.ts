import type {
  IdentityEnvelopeRecoveryEnrollment,
  IdentityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import type { AuthenticatedIdentityActor } from '../domain/identity-kernel.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';

/** Internal phase resolution mode. A historical subject is only a locator for
 * original records; it carries no session and cannot enter a live phase. */
export type RecoveryRotationContext =
  | Readonly<{ kind: 'CURRENT'; actor: AuthenticatedIdentityActor }>
  | Readonly<{
      kind: 'HISTORICAL';
      subject: Readonly<{ participantId: string; principalId: string }>;
    }>;

export function recoveryRotationSubject(
  context: RecoveryRotationContext,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
): Readonly<{ participantId: string; principalId: string }> {
  const subject = context.kind === 'CURRENT' ? context.actor : context.subject;
  if (
    subject.participantId !== enrollment.participantId ||
    subject.principalId !== lease.executorPrincipalId ||
    lease.enrollmentId !== enrollment.enrollmentId
  )
    throw new PlatformRecoveryError();
  return subject;
}

export function assertHistoricalRecoveryRotationStep(
  context: RecoveryRotationContext,
  step: Readonly<{ state: string; bound: boolean }> | undefined,
) {
  if (context.kind === 'HISTORICAL' && (!step?.bound || step.state !== 'COMMITTED'))
    throw new PlatformRecoveryError();
}

/** Do not infer live authority from a historical executor ID. Keep the original
 * authenticated actor, including its actual session, for every live owner. */
export function requireCurrentRecoveryRotationActor(
  context: RecoveryRotationContext,
): AuthenticatedIdentityActor {
  if (context.kind !== 'CURRENT') throw new PlatformRecoveryError();
  return context.actor;
}
