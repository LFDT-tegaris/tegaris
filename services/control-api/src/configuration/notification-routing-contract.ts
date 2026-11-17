import { z } from 'zod';
import {
  verifyNotificationClaim,
  type NotificationRoutingProfileClaims,
} from '@openpc/security-kernel';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  notificationPayloadBinding,
  notificationPayloadEncryptionProfileDigest,
  type NotificationPayloadBinding,
} from '../evidence/notification-payload-crypto.js';
import { digest } from '../evidence/segment.js';
import { sha256 } from './digest.js';

const hex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const installedTrust = z.strictObject({
  environmentId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
  participantId: notificationPayloadBinding.shape.participantId,
  privacyDomainId: notificationPayloadBinding.shape.privacyDomainId,
  signedProfileDigest: digest,
  issuerSpkiHex: hex.length(182),
});
const signedProfile = z.strictObject({
  payloadHex: hex.max(131072),
  coseHex: hex.max(133120),
});
export type NotificationRoutingInstalledTrust = z.infer<typeof installedTrust>;
export type SignedNotificationRoutingProfile = z.infer<typeof signedProfile>;
export interface InstalledNotificationRoutingProfile {
  readonly claims: Readonly<NotificationRoutingProfileClaims>;
  readonly signedProfileDigest: string;
}
export class NotificationRoutingContractError extends Error {
  constructor() {
    super('Notification routing contract invalid');
  }
}
function contract<T>(operation: () => T): T {
  try {
    return operation();
  } catch {
    throw new NotificationRoutingContractError();
  }
}

/** Independently installed trust is mandatory; never build it from the received
 * profile. This verifies historical signature/binding, not installation, current
 * revocation, endpoint/producer authorization, key access or dispatch admission. */
export function verifyInstalledNotificationRouting(
  trustValue: NotificationRoutingInstalledTrust,
  signedValue: SignedNotificationRoutingProfile,
): InstalledNotificationRoutingProfile {
  return contract(() => {
    const trust = installedTrust.parse(immutableJsonCopy(trustValue));
    const signed = signedProfile.parse(immutableJsonCopy(signedValue));
    const cose = Buffer.from(signed.coseHex, 'hex');
    const claims = verifyNotificationClaim(
      'NotificationRoutingProfileV1',
      Buffer.from(trust.issuerSpkiHex, 'hex'),
      Buffer.from(signed.payloadHex, 'hex'),
      cose,
    );
    if (
      sha256(cose) !== trust.signedProfileDigest ||
      claims.environmentId !== trust.environmentId ||
      claims.participantId !== trust.participantId ||
      claims.privacyDomainId !== trust.privacyDomainId ||
      claims.encryptionProfileDigest !== notificationPayloadEncryptionProfileDigest
    )
      throw new Error();
    return immutableJsonCopy({ claims, signedProfileDigest: trust.signedProfileDigest });
  });
}

/** Connects independently retained routing and object bindings without granting
 * authority. The durable owner must additionally resolve the exact object key
 * under claims.payloadKeyPolicyDigest and retain its original wrapped record;
 * a caller-supplied key label is not that proof. Occurrence/object/payload fields
 * remain the occurrence and Evidence owners' responsibility. */
export function assertNotificationPayloadRouting(
  route: InstalledNotificationRoutingProfile,
  bindingValue: NotificationPayloadBinding,
): void {
  contract(() => {
    const binding = notificationPayloadBinding.parse(immutableJsonCopy(bindingValue));
    const p = route.claims;
    if (
      binding.routingProfileDigest !== route.signedProfileDigest ||
      binding.environmentId !== p.environmentId ||
      binding.participantId !== p.participantId ||
      binding.privacyDomainId !== p.privacyDomainId ||
      binding.templateDigest !== p.templateDigest ||
      binding.recipientSetDigest !== p.recipientSetDigest ||
      binding.redactionProfileDigest !== p.redactionProfileDigest ||
      binding.preferenceGeneration !== p.preferenceGeneration ||
      p.encryptionProfileDigest !== notificationPayloadEncryptionProfileDigest
    )
      throw new Error();
  });
}
