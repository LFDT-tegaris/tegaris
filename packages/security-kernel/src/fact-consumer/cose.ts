import { evidenceKeyId } from '../business-transition/cose.js';
import { factConsumerProfileContext as context } from './generated.js';
import {
  decodeFactConsumerProfile,
  factConsumerProfileDigest,
  type FactConsumerProfile,
} from './profile.js';
import { consumerProtectedHeader, signConsumerCose, verifyConsumerCose } from './cose-framing.js';

export const factConsumerProtectedHeader = (spki: Buffer): Buffer =>
  consumerProtectedHeader(context, spki);
function assertIssuer(spki: Buffer, payload: Buffer): void {
  if (decodeFactConsumerProfile(payload).issuerKeyId !== evidenceKeyId(spki))
    throw new Error('Fact consumer issuer mismatch');
}
/** Installation signer primitive; no runtime trust is established by signing. */
export function signFactConsumerProfile(privateKey: Buffer, spki: Buffer, payload: Buffer): Buffer {
  assertIssuer(spki, payload);
  return signConsumerCose(context, privateKey, spki, payload);
}
export function verifyFactConsumerProfileSignature(
  spki: Buffer,
  payload: Buffer,
  cose: Buffer,
): boolean {
  try {
    assertIssuer(spki, payload);
    return verifyConsumerCose(context, spki, payload, cose);
  } catch {
    return false;
  }
}
export interface InstalledFactConsumerProfile {
  issuerSpkiDer: Buffer;
  signedProfileDigest: string;
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
  profileId: string;
  revision: string;
  consumerId: FactConsumerProfile['consumerId'];
  subscriptionId: string;
  workloadCredentialId: string;
  workloadCredentialEpoch: string;
  databaseRole: string;
}
/** Trust must come from the installer, never the profile or a public caller.
 * Pins exact signed bytes so an older still-valid profile cannot roll back the
 * installed retry policy. Live credential/revocation and effect fences remain
 * mandatory at the committing owner; this function cannot establish them. */
export function verifyInstalledFactConsumerProfile(
  installed: InstalledFactConsumerProfile,
  payload: Buffer,
  cose: Buffer,
  nowMs: number,
): Readonly<FactConsumerProfile> {
  try {
    if (
      !Number.isSafeInteger(nowMs) ||
      nowMs < 0 ||
      factConsumerProfileDigest(cose) !== installed.signedProfileDigest ||
      !verifyFactConsumerProfileSignature(installed.issuerSpkiDer, payload, cose)
    )
      throw new Error();
    const profile = decodeFactConsumerProfile(payload);
    for (const key of [
      'environmentId',
      'participantId',
      'privacyDomainId',
      'profileId',
      'revision',
      'consumerId',
      'subscriptionId',
      'workloadCredentialId',
      'workloadCredentialEpoch',
      'databaseRole',
    ] as const)
      if (profile[key] !== installed[key]) throw new Error();
    if (nowMs < profile.validFromMs || nowMs >= profile.validUntilMs) throw new Error();
    return Object.freeze(profile);
  } catch {
    throw new Error('Installed Fact consumer profile rejected');
  }
}
