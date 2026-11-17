import { createHash } from 'node:crypto';
import { evidenceKeyId } from '../business-transition/cose.js';
import {
  verifyNotificationClaim,
  encodeNotificationClaim,
  type NotificationCompletionWorkerProfileClaims,
} from './codec.js';
export type InstalledNotificationCompletionWorkerProfile = Pick<
  NotificationCompletionWorkerProfileClaims,
  | 'environmentId'
  | 'participantId'
  | 'privacyDomainId'
  | 'profileId'
  | 'revision'
  | 'serviceId'
  | 'processRole'
  | 'subscriptionId'
  | 'principalId'
  | 'workloadCredentialId'
  | 'workloadEpoch'
  | 'workloadId'
  | 'workloadKeyDigest'
  | 'producerTrustDigest'
> & {
  readonly issuerSpki: Buffer;
  readonly signedProfileDigest: string;
};
const fail = (): never => {
  throw new Error('Notification completion worker profile rejected');
};
/** Historical crypto only, including withdrawn/expired originals. Independently
 * installed pins must come from their immutable owner, never an incoming event. */
export function verifyNotificationCompletionWorkerProfileOriginal(
  pins: InstalledNotificationCompletionWorkerProfile,
  payload: Buffer,
  cose: Buffer,
) {
  try {
    if (`sha256:${createHash('sha256').update(cose).digest('hex')}` !== pins.signedProfileDigest)
      return fail();
    const p = verifyNotificationClaim(
      'NotificationCompletionWorkerProfileV1',
      pins.issuerSpki,
      payload,
      cose,
    );
    for (const name of [
      'environmentId',
      'participantId',
      'privacyDomainId',
      'profileId',
      'revision',
      'serviceId',
      'processRole',
      'subscriptionId',
      'principalId',
      'workloadCredentialId',
      'workloadEpoch',
      'workloadId',
      'workloadKeyDigest',
      'producerTrustDigest',
    ] as const)
      if (p[name] !== pins[name]) return fail();
    if (p.issuerKeyId === p.workloadKeyDigest || evidenceKeyId(pins.issuerSpki) !== p.issuerKeyId)
      return fail();
    return Object.freeze(p);
  } catch {
    return fail();
  }
}
/** Current profile validity is necessary, never sufficient, for real peer admission. */
export function verifyInstalledNotificationCompletionWorkerProfile(
  pins: InstalledNotificationCompletionWorkerProfile,
  payload: Buffer,
  cose: Buffer,
  nowMs: number,
) {
  const p = verifyNotificationCompletionWorkerProfileOriginal(pins, payload, cose);
  if (
    !Number.isSafeInteger(nowMs) ||
    Object.is(nowMs, -0) ||
    nowMs < p.validFromMs ||
    nowMs >= p.validUntilMs
  )
    return fail();
  return p;
}
/** Delay after an actually committed failed consumer attempt. Null means the
 * finite budget is exhausted, NOT permission to quarantine/ACK/mutate WorkItems.
 * Attempt numbering is durable and starts at one; replacement profiles cannot
 * reset it. These are consumer retries, unrelated to gateway delivery retries. */
export function notificationCompletionConsumerBackoff(
  profile: NotificationCompletionWorkerProfileClaims,
  completedAttempts: number,
): number | null {
  encodeNotificationClaim('NotificationCompletionWorkerProfileV1', profile);
  if (!Number.isSafeInteger(completedAttempts) || completedAttempts < 1) return fail();
  if (completedAttempts >= profile.maximumAttempts) return null;
  return Math.min(
    profile.maximumBackoffMs,
    profile.initialBackoffMs * 2 ** Math.min(completedAttempts - 1, 52),
  );
}
