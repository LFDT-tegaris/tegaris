import { createHash, X509Certificate } from 'node:crypto';

import {
  convertCertBufferToPEM,
  decodeAttestationObject,
  validateCertificatePath,
} from '@simplewebauthn/server/helpers';
import { z } from 'zod';

/** Deployment-owned trust input. Browser/caller claims never select a trust anchor. */
export const hardwareAttestationProfileSchema = z.strictObject({
  profileId: z.string().min(1).max(160),
  aaguids: z.array(z.uuid()).min(1).max(64),
  rootCertificatesPem: z.array(z.string().min(128).max(16384)).min(1).max(16),
});
export type HardwareAttestationProfile = z.infer<typeof hardwareAttestationProfileSchema>;
export interface HardwareAttestation {
  readonly profileId: string;
  readonly profileDigest: string;
  readonly aaguid: string;
  readonly attestationDigest: string;
}

/** Additional trust admission after WebAuthn has verified challenge, RP, UV and signature. */
export async function admitHardwareAttestation(
  registration: {
    readonly fmt: string;
    readonly aaguid: string;
    readonly credentialDeviceType: string;
    readonly credentialBackedUp: boolean;
    readonly attestationObject: Uint8Array;
  },
  profile: HardwareAttestationProfile,
): Promise<HardwareAttestation | undefined> {
  if (
    registration.fmt !== 'packed' ||
    registration.credentialDeviceType !== 'singleDevice' ||
    registration.credentialBackedUp ||
    !profile.aaguids.includes(registration.aaguid)
  )
    return undefined;
  try {
    const attestation = decodeAttestationObject(new Uint8Array(registration.attestationObject));
    const chain = attestation.get('attStmt').get('x5c');
    if (
      !chain ||
      chain.length === 0 ||
      chain.length > 8 ||
      profile.rootCertificatesPem.length === 0
    )
      return undefined;
    await validateCertificatePath(chain.map(convertCertBufferToPEM), profile.rootCertificatesPem);
    const roots = profile.rootCertificatesPem
      .map((pem) => new X509Certificate(pem).fingerprint256)
      .sort();
    return {
      profileId: profile.profileId,
      profileDigest: `sha256:${createHash('sha256')
        .update(
          JSON.stringify({
            profileId: profile.profileId,
            aaguids: [...profile.aaguids].sort(),
            roots,
          }),
        )
        .digest('hex')}`,
      aaguid: registration.aaguid,
      attestationDigest: `sha256:${createHash('sha256').update(registration.attestationObject).digest('hex')}`,
    };
  } catch {
    return undefined;
  }
}
