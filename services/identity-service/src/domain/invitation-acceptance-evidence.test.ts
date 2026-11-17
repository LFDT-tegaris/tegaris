import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { createLocalIdentityRuntimeCryptoAdapter } from './identity-runtime-crypto.js';
import {
  createInvitationProofAssertion,
  verifyInvitationProofAssertion,
  type InvitationProofEvidence,
} from './invitation-acceptance-evidence.js';
import {
  createIdentityRuntimeAuthorizationAssertion,
  verifyIdentityRuntimeAuthorizationAssertion,
  type IdentityRuntimeAuthorizationContext,
} from './identity-runtime-authorization.js';

it('binds the recipient proof and committed result without authorizing a session mutation', async () => {
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ format: 'der', type: 'spki' });
  const signer = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: keys.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const id = (last: string) => `018f0000-0000-7000-8000-000000000${last}`;
  const hash = (byte: string) => `sha256:${byte.repeat(64)}`;
  const now = new Date('2026-09-15T12:00:00Z');
  const inputs: InvitationProofEvidence = {
    operationId: id('101'),
    participantId: id('102'),
    privacyDomainId: id('103'),
    membershipId: id('104'),
    participantEpoch: '1',
    invitationId: id('105'),
    tokenVersion: '2',
    tokenDigest: hash('1'),
    issuanceAuthorityDigest: hash('2'),
    recipientDigest: hash('3'),
    oidcConfigurationDigest: hash('4'),
    transactionId: id('106'),
    stateDigest: hash('5'),
    nonceDigest: hash('6'),
    codeVerifierDigest: hash('7'),
    browserSessionDigest: hash('8'),
    codeChallenge: 'PKCE-test-challenge',
    authorizationCodeDigest: hash('9'),
    idTokenDigest: hash('a'),
    signingKeyDigest: hash('b'),
    claimsDigest: hash('c'),
    resultDigest: hash('d'),
    verifiedAt: now,
    validUntil: new Date(now.getTime() + 300_000),
  };
  const signed = await signer.signCanonicalAssertion(createInvitationProofAssertion(inputs));
  expect(
    await verifyInvitationProofAssertion(inputs, signed.evidenceCbor, signed.coseSign1, signer),
  ).toBe(true);
  for (const changed of [
    { invitationId: id('201') },
    { participantId: id('202') },
    { privacyDomainId: id('203') },
    { membershipId: id('204') },
    { tokenVersion: '3' },
    { tokenDigest: hash('e') },
    { recipientDigest: hash('e') },
    { issuanceAuthorityDigest: hash('e') },
    { transactionId: id('206') },
    { browserSessionDigest: hash('e') },
    { nonceDigest: hash('e') },
    { authorizationCodeDigest: hash('e') },
    { idTokenDigest: hash('e') },
    { signingKeyDigest: hash('e') },
    { resultDigest: hash('e') },
  ]) {
    expect(
      await verifyInvitationProofAssertion(
        { ...inputs, ...changed },
        signed.evidenceCbor,
        signed.coseSign1,
        signer,
      ),
    ).toBe(false);
  }
  const altered = Buffer.from(signed.coseSign1);
  altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
  expect(await verifyInvitationProofAssertion(inputs, signed.evidenceCbor, altered, signer)).toBe(
    false,
  );
  const authorization: IdentityRuntimeAuthorizationContext = {
    participantId: inputs.participantId,
    principalId: inputs.membershipId,
    sessionId: id('301'),
    sessionEpoch: '1',
    sessionIssuedAt: now,
    sessionIdleExpiresAt: new Date(now.getTime() + 300_000),
    sessionAbsoluteExpiresAt: new Date(now.getTime() + 600_000),
    participantEpoch: '1',
    principalEpoch: '1',
    assignmentId: id('302'),
    assignmentRowVersion: '1',
    authorityEnvelopeId: id('303'),
    authorityEpoch: '1',
    delegationEpoch: '1',
    actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
    catalogOperationId: 'ID-OP-SESSION-REFRESH',
    resourceId: id('301'),
    candidateDigest: inputs.resultDigest,
    sessionToken: 'unrelated-session-token',
  };
  expect(
    verifyIdentityRuntimeAuthorizationAssertion(signed.evidenceCbor, authorization, now),
  ).toBeUndefined();
  const sessionSigned = await signer.signCanonicalAssertion(
    createIdentityRuntimeAuthorizationAssertion(id('304'), authorization, now),
  );
  expect(
    await verifyInvitationProofAssertion(
      inputs,
      sessionSigned.evidenceCbor,
      sessionSigned.coseSign1,
      signer,
    ),
  ).toBe(false);
});
