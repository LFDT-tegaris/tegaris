import type { PoolClient } from 'pg';
import type { VerifiedWebAuthnRegistration } from '../domain/webauthn-registration.js';
import { IdentityKernelError } from '../domain/identity-errors.js';

/** Only the verified registration result is accepted, inside its credential transaction. */
export async function saveHardwareAuthenticator(
  client: PoolClient,
  participantId: string,
  principalId: string,
  credentialId: string,
  registration: VerifiedWebAuthnRegistration,
): Promise<void> {
  const hardware = registration.hardwareAttestation;
  if (!hardware) return;
  if (hardware.attestationDigest !== `sha256:${registration.attestationDigest.toString('hex')}`) {
    throw new IdentityKernelError('PC-AUTH-0006');
  }
  await client.query(
    `insert into control.hardware_authenticator
     (credential_id,participant_id,principal_id,profile_id,profile_digest,aaguid,attestation_digest)
     values ($1,$2,$3,$4,$5,$6,$7)`,
    [
      credentialId,
      participantId,
      principalId,
      hardware.profileId,
      hardware.profileDigest,
      hardware.aaguid,
      hardware.attestationDigest,
    ],
  );
}
