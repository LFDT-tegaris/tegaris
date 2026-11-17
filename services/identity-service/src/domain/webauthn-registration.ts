import { createHash } from 'node:crypto';

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { convertCOSEtoPKCS, isoBase64URL } from '@simplewebauthn/server/helpers';
import {
  admitHardwareAttestation,
  type HardwareAttestation,
  type HardwareAttestationProfile,
} from './hardware-attestation.js';

const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

export interface WebAuthnRegistrationOptionsInput {
  readonly challenge: string;
  readonly rpId: string;
  readonly principalId: string;
  readonly displayLabel: string;
  readonly excludedCredentialIds: readonly string[];
  readonly hardwareAttestation?: boolean;
}

export interface VerifiedWebAuthnRegistration {
  readonly externalCredentialId: string;
  readonly publicKeySpkiDer: Buffer;
  readonly publicKeyDigest: Buffer;
  readonly signCount: string;
  readonly attestationDigest: Buffer;
  readonly hardwareAttestation?: HardwareAttestation;
}

export interface WebAuthnRegistrationAdapter {
  options(input: WebAuthnRegistrationOptionsInput): Promise<unknown>;
  verify(input: {
    readonly response: unknown;
    readonly expectedChallengeDigest: Buffer;
    readonly expectedOrigin: string;
    readonly expectedRpId: string;
  }): Promise<VerifiedWebAuthnRegistration | undefined>;
}

function digest(value: string | Buffer | Uint8Array): Buffer {
  return createHash('sha256').update(value).digest();
}

export const rejectingWebAuthnRegistrationAdapter: WebAuthnRegistrationAdapter = {
  async options() {
    throw new Error('WebAuthn registration is not configured');
  },
  async verify() {
    return undefined;
  },
};

export function createWebAuthnRegistrationAdapter(
  hardwareProfile?: HardwareAttestationProfile,
): WebAuthnRegistrationAdapter {
  return {
    async options(input) {
      return generateRegistrationOptions({
        rpName: 'OpenPC',
        rpID: input.rpId,
        userID: Buffer.from(input.principalId, 'utf8'),
        userName: input.principalId,
        userDisplayName: input.displayLabel,
        challenge: input.challenge,
        timeout: 300_000,
        attestationType: input.hardwareAttestation ? 'direct' : 'none',
        excludeCredentials: input.excludedCredentialIds.map((id) => ({ id })),
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'required',
        },
        supportedAlgorithmIDs: [-7],
      });
    },
    async verify(input) {
      let verified: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
      try {
        verified = await verifyRegistrationResponse({
          response: input.response as RegistrationResponseJSON,
          expectedChallenge: (challenge) =>
            digest(isoBase64URL.toBuffer(challenge)).equals(input.expectedChallengeDigest),
          expectedOrigin: input.expectedOrigin,
          expectedRPID: input.expectedRpId,
          requireUserPresence: true,
          requireUserVerification: true,
          supportedAlgorithmIDs: [-7],
        });
      } catch {
        process.stderr.write(
          'OPENPC_WEBAUTHN_REGISTRATION_REJECT|stage=attestation-verification\n',
        );
        return undefined;
      }
      if (!verified.verified || verified.registrationInfo.rpID !== input.expectedRpId) {
        process.stderr.write('OPENPC_WEBAUTHN_REGISTRATION_REJECT|stage=rp-binding\n');
        return undefined;
      }
      try {
        const rawPublicKey = Buffer.from(
          convertCOSEtoPKCS(verified.registrationInfo.credential.publicKey),
        );
        if (rawPublicKey.length !== 65 || rawPublicKey[0] !== 0x04) return undefined;
        const publicKeySpkiDer = Buffer.concat([P256_SPKI_PREFIX, rawPublicKey]);
        const hardwareAttestation = hardwareProfile
          ? await admitHardwareAttestation(verified.registrationInfo, hardwareProfile)
          : undefined;
        return {
          externalCredentialId: verified.registrationInfo.credential.id,
          publicKeySpkiDer,
          publicKeyDigest: digest(publicKeySpkiDer),
          signCount: String(verified.registrationInfo.credential.counter),
          attestationDigest: digest(verified.registrationInfo.attestationObject),
          ...(hardwareAttestation === undefined ? {} : { hardwareAttestation }),
        };
      } catch {
        process.stderr.write('OPENPC_WEBAUTHN_REGISTRATION_REJECT|stage=public-key-conversion\n');
        return undefined;
      }
    },
  };
}

export const localWebAuthnRegistrationAdapter = createWebAuthnRegistrationAdapter();
