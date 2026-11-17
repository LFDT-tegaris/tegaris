import { createHash } from 'node:crypto';
import { afterAll, expect, it } from 'vitest';
import {
  createHardwareAuthenticatorEmulator,
  createUnattestedTestRegistration,
} from '../../../../tests/integration/identity/hardware-authenticator.js';
import { createWebAuthnRegistrationAdapter } from './webauthn-registration.js';

const emulator = createHardwareAuthenticatorEmulator();
const other = createHardwareAuthenticatorEmulator();
afterAll(() => {
  emulator.dispose();
  other.dispose();
});
const challenge = 'recovery-hardware-registration-challenge';
const original = createUnattestedTestRegistration(
  challenge,
  'https://identity.example',
  'identity.example',
);
const input = {
  expectedChallengeDigest: createHash('sha256').update(challenge).digest(),
  expectedOrigin: 'https://identity.example',
  expectedRpId: 'identity.example',
};
const verifier = createWebAuthnRegistrationAdapter(emulator.profile);

it('qualifies only a verified packed attestation chained to the deployment trust profile', async () => {
  const response = emulator.attest(original);
  const verified = await verifier.verify({ ...input, response });
  expect(verified?.hardwareAttestation).toMatchObject({
    profileId: emulator.profile.profileId,
    aaguid: emulator.profile.aaguids[0],
  });
  expect(verified?.hardwareAttestation?.attestationDigest).toBe(
    `sha256:${verified?.attestationDigest.toString('hex')}`,
  );
  const withoutTrust = await createWebAuthnRegistrationAdapter().verify({ ...input, response });
  expect(withoutTrust?.externalCredentialId).toBe(response.id);
  expect(withoutTrust?.hardwareAttestation).toBeUndefined();
});
it('does not turn none, foreign-root, unlisted-model or backed-up authenticators into recovery assurance', async () => {
  for (const response of [
    original,
    other.attest(original),
    emulator.attest(original, '018f0000-0000-7000-8000-000000000998'),
    emulator.attest(original, undefined, 0x5d),
  ]) {
    const result = await verifier.verify({ ...input, response });
    expect(result?.externalCredentialId).toBe(response.id);
    expect(result?.hardwareAttestation).toBeUndefined();
  }
});
it('rejects a valid attestation with wrong challenge, origin, RP or modified client data', async () => {
  const response = emulator.attest(original);
  for (const invalid of [
    { ...input, expectedChallengeDigest: Buffer.alloc(32) },
    { ...input, expectedOrigin: 'https://other.example' },
    { ...input, expectedRpId: 'other.example' },
  ])
    expect(await verifier.verify({ ...invalid, response })).toBeUndefined();
  const forged = {
    ...response,
    response: {
      ...response.response,
      clientDataJSON: Buffer.from(
        JSON.stringify({
          type: 'webauthn.create',
          challenge: Buffer.from(challenge).toString('base64url'),
          origin: input.expectedOrigin,
          crossOrigin: false,
          extra: 'forged',
        }),
      ).toString('base64url'),
    },
  };
  expect(await verifier.verify({ ...input, response: forged })).toBeUndefined();
});
it('requests direct attestation only when hardware enrollment is selected', async () => {
  const options = {
    challenge,
    rpId: input.expectedRpId,
    principalId: '018f0000-0000-7000-8000-000000000111',
    displayLabel: 'Recovery executor',
    excludedCredentialIds: [],
  };
  expect(await verifier.options({ ...options, hardwareAttestation: true })).toMatchObject({
    attestation: 'direct',
  });
  expect(await verifier.options(options)).toMatchObject({ attestation: 'none' });
});
