import { createHash, generateKeyPairSync, sign } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  type LocalWebAuthnCredential,
  verifyLocalWebAuthnAssertion,
} from './local-webauthn-trust-adapter.js';
import type { IdentityTrustAdapter } from './trust-adapter.js';

const sha256 = (value: string | Buffer) => createHash('sha256').update(value).digest();
const prefixed = (value: string | Buffer) => `sha256:${sha256(value).toString('hex')}`;
const credentialId = '018f0000-0000-7000-8000-000000000916';
const principalId = '018f0000-0000-7000-8000-000000000111';
const sessionId = '018f0000-0000-7000-8000-000000000411';
const origin = 'https://openpc.local';
const challenge = 'local-webauthn-challenge-00000001';
const rpIdHash = sha256('openpc.local');
const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const publicKeySpkiDer = keys.publicKey.export({ format: 'der', type: 'spki' });
const credential: LocalWebAuthnCredential = {
  credentialId,
  publicKeyDigest: sha256(publicKeySpkiDer),
  publicKeySpkiDer,
};
const input = {
  challenge,
  rpIdHash: `sha256:${rpIdHash.toString('hex')}`,
  principalId,
  sessionId,
  actionIntentId: 'ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1',
  resourceDigest: prefixed('provider-candidate'),
  allowedOrigin: origin,
} satisfies Omit<Parameters<IdentityTrustAdapter['verifyWebAuthnAssertion']>[0], 'assertion'>;

function assertion(options?: {
  readonly challenge?: string;
  readonly flags?: number;
  readonly origin?: string;
  readonly rpIdHash?: Buffer;
  readonly tamperSignature?: boolean;
  readonly crossOrigin?: boolean;
  readonly extension?: boolean;
}): string {
  const clientDataJson = Buffer.from(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: options?.challenge ?? challenge,
      origin: options?.origin ?? origin,
      crossOrigin: options?.crossOrigin ?? false,
      ...(options?.extension ? { other_keys_can_be_added_here: 'ignored' } : {}),
    }),
  );
  const authenticatorData = Buffer.alloc(37);
  (options?.rpIdHash ?? rpIdHash).copy(authenticatorData);
  authenticatorData[32] = options?.flags ?? 0x05;
  authenticatorData.writeUInt32BE(1, 33);
  const signature = sign(
    'sha256',
    Buffer.concat([authenticatorData, sha256(clientDataJson)]),
    keys.privateKey,
  );
  if (options?.tamperSignature) {
    signature[signature.length - 1] = signature.at(-1)! ^ 1;
  }
  return JSON.stringify({
    credentialId,
    authenticatorData: authenticatorData.toString('base64url'),
    clientDataJson: clientDataJson.toString('base64url'),
    signature: signature.toString('base64url'),
  });
}

describe('local WebAuthn trust boundary', () => {
  it('accepts one exact cryptographic assertion and retains its complete binding', () => {
    const verified = verifyLocalWebAuthnAssertion(
      credential,
      { ...input, assertion: assertion() },
      new Date('2026-09-10T00:00:00.000Z'),
    );
    expect(verified).toMatchObject({
      credentialId,
      principalId,
      sessionId,
      challengeDigest: prefixed(challenge),
      rpIdHash: input.rpIdHash,
      origin,
      signCount: '1',
      verifiedAt: '2026-09-10T00:00:00.000Z',
      userVerification: 'REQUIRED_VERIFIED',
    });
  });

  it('accepts forward-compatible collected client data while retaining exact signed bytes', () => {
    expect(
      verifyLocalWebAuthnAssertion(credential, {
        ...input,
        assertion: assertion({ extension: true }),
      }),
    ).toMatchObject({ credentialId, challengeDigest: prefixed(challenge), origin });
  });

  it('rejects field-isolated credential, RP, origin, challenge, UV, signature, and shape drift', () => {
    const valid = JSON.parse(assertion()) as Record<string, unknown>;
    const cases = [
      { ...input, assertion: JSON.stringify({ ...valid, credentialId: sessionId }) },
      { ...input, rpIdHash: prefixed('wrong-rp'), assertion: assertion() },
      { ...input, allowedOrigin: 'https://other.local', assertion: assertion() },
      { ...input, challenge: `${challenge}-wrong`, assertion: assertion() },
      { ...input, assertion: assertion({ flags: 0x01 }) },
      { ...input, assertion: assertion({ tamperSignature: true }) },
      { ...input, assertion: assertion({ crossOrigin: true }) },
      { ...input, assertion: JSON.stringify({ ...valid, unexpected: true }) },
      {
        ...input,
        assertion: JSON.stringify({ ...valid, signature: `${String(valid.signature)}=` }),
      },
    ];
    for (const candidate of cases) {
      expect(verifyLocalWebAuthnAssertion(credential, candidate)).toBeUndefined();
    }
    expect(
      verifyLocalWebAuthnAssertion(
        { ...credential, publicKeyDigest: sha256('wrong-key') },
        { ...input, assertion: assertion() },
      ),
    ).toBeUndefined();
  });
});
