import { createHash, createPublicKey, verify } from 'node:crypto';

import type { Pool } from 'pg';
import { z } from 'zod';

import { runScopedTransaction } from '../db/scoped-transaction.js';
import { localOperationId } from './local-operation-id.js';
import {
  createVerifiedWebAuthnAssertion,
  type IdentityTrustAdapter,
  type VerifiedWebAuthnAssertion,
} from './trust-adapter.js';

const sha256Text = /^sha256:[0-9a-f]{64}$/u;
const base64Url = /^[A-Za-z0-9_-]+$/u;
const assertionSchema = z.strictObject({
  credentialId: z.string().min(1).max(1024).regex(base64Url),
  authenticatorData: z.string().regex(base64Url),
  clientDataJson: z.string().regex(base64Url),
  signature: z.string().regex(base64Url),
});
// CollectedClientData is explicitly extensible. Validate the security-critical
// members and ignore unknown forward-compatible members from the user agent.
const clientDataSchema = z.object({
  type: z.literal('webauthn.get'),
  challenge: z.string().min(32).max(256),
  origin: z.url(),
  crossOrigin: z.literal(false).optional(),
});

export interface LocalWebAuthnCredential {
  readonly credentialId: string;
  readonly externalCredentialId?: string;
  readonly publicKeyDigest: Buffer;
  readonly publicKeySpkiDer: Buffer;
}

function sha256(value: string | Buffer): Buffer {
  return createHash('sha256').update(value).digest();
}

function decodeBase64Url(value: string): Buffer | undefined {
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length > 0 && decoded.toString('base64url') === value ? decoded : undefined;
}

/** Verify the complete local WebAuthn assertion against one database-owned credential. */
function verifyLocalWebAuthnAssertionDetailed(
  credential: LocalWebAuthnCredential,
  input: Parameters<IdentityTrustAdapter['verifyWebAuthnAssertion']>[0],
  verifiedAt = new Date(),
): { readonly verified: VerifiedWebAuthnAssertion } | { readonly reason: string } {
  try {
    const assertion = assertionSchema.safeParse(JSON.parse(input.assertion));
    if (!assertion.success) return { reason: 'assertion-shape' };
    if (
      assertion.data.credentialId !== (credential.externalCredentialId ?? credential.credentialId)
    )
      return { reason: 'credential-binding' };
    const authenticatorData = decodeBase64Url(assertion.data.authenticatorData);
    const clientDataJson = decodeBase64Url(assertion.data.clientDataJson);
    const signature = decodeBase64Url(assertion.data.signature);
    if (authenticatorData === undefined) return { reason: 'authenticator-data-encoding' };
    if (clientDataJson === undefined) return { reason: 'client-data-encoding' };
    if (signature === undefined) return { reason: 'signature-encoding' };
    const clientData =
      clientDataJson === undefined
        ? undefined
        : clientDataSchema.safeParse(JSON.parse(clientDataJson.toString('utf8')));
    if (clientData === undefined || !clientData.success) return { reason: 'client-data-shape' };
    const origin = new URL(input.allowedOrigin);
    const expectedRpIdHash = sha256(origin.hostname);
    if (origin.origin !== input.allowedOrigin) return { reason: 'allowed-origin' };
    if (!sha256Text.test(input.rpIdHash)) return { reason: 'rp-id-shape' };
    if (!expectedRpIdHash.equals(Buffer.from(input.rpIdHash.slice(7), 'hex')))
      return { reason: 'rp-id-input' };
    if (authenticatorData.length !== 37) return { reason: 'authenticator-data-length' };
    if (!authenticatorData.subarray(0, 32).equals(expectedRpIdHash))
      return { reason: 'authenticator-rp-id' };
    if ((authenticatorData[32]! & 0x05) !== 0x05) return { reason: 'authenticator-flags' };
    if (clientData.data.challenge !== input.challenge) return { reason: 'challenge-binding' };
    if (clientData.data.origin !== input.allowedOrigin) return { reason: 'client-origin' };
    if (!sha256(credential.publicKeySpkiDer).equals(credential.publicKeyDigest))
      return { reason: 'credential-key-digest' };
    if (
      !verify(
        'sha256',
        Buffer.concat([authenticatorData, sha256(clientDataJson)]),
        createPublicKey({ key: credential.publicKeySpkiDer, format: 'der', type: 'spki' }),
        signature,
      )
    )
      return { reason: 'signature-verification' };
    return {
      verified: createVerifiedWebAuthnAssertion({
        credentialId: credential.credentialId,
        credentialPublicKeyDigest: `sha256:${credential.publicKeyDigest.toString('hex')}`,
        principalId: input.principalId,
        sessionId: input.sessionId,
        actionIntentId: input.actionIntentId,
        resourceDigest: input.resourceDigest,
        challengeDigest: `sha256:${sha256(input.challenge).toString('hex')}`,
        rpIdHash: input.rpIdHash,
        origin: input.allowedOrigin,
        authenticatorDataDigest: `sha256:${sha256(authenticatorData).toString('hex')}`,
        clientDataJsonDigest: `sha256:${sha256(clientDataJson).toString('hex')}`,
        signatureDigest: `sha256:${sha256(signature).toString('hex')}`,
        signCount: String(authenticatorData.readUInt32BE(33)),
        verifiedAt: verifiedAt.toISOString(),
      }),
    };
  } catch {
    return { reason: 'unexpected-verification-error' };
  }
}

/** Verify the complete local WebAuthn assertion against one database-owned credential. */
export function verifyLocalWebAuthnAssertion(
  credential: LocalWebAuthnCredential,
  input: Parameters<IdentityTrustAdapter['verifyWebAuthnAssertion']>[0],
  verifiedAt = new Date(),
): VerifiedWebAuthnAssertion | undefined {
  const result = verifyLocalWebAuthnAssertionDetailed(credential, input, verifiedAt);
  return 'verified' in result ? result.verified : undefined;
}

/** Local-only composition adapter; OIDC remains fail-closed. */
export function createLocalWebAuthnTrustAdapter(
  pool: Pool,
  participantId: string,
): IdentityTrustAdapter {
  return {
    async exchangeAuthorizationCode() {
      return undefined;
    },
    async verifyWebAuthnAssertion(input) {
      const contextParticipantId = input.participantId ?? participantId;
      let credentialId: string;
      try {
        const assertion = assertionSchema.parse(JSON.parse(input.assertion));
        credentialId = assertion.credentialId;
      } catch {
        return undefined;
      }
      const credential = await runScopedTransaction(
        pool,
        { participantId: contextParticipantId, actionIntentId: input.actionIntentId },
        localOperationId,
        async (client) => {
          const result = await client.query<LocalWebAuthnCredential>(
            `select credential_id as "credentialId",subject as "externalCredentialId",
                    public_key_digest as "publicKeyDigest",
                    public_key_spki_der as "publicKeySpkiDer"
               from control.credential
              where participant_id=$1 and principal_id=$2
                and (subject=$3 or credential_id::text=$3)
                and kind='WEBAUTHN' and state='ACTIVE' and public_key_spki_der is not null
                and valid_from<=clock_timestamp()
                and (valid_until is null or valid_until>clock_timestamp())`,
            [contextParticipantId, input.principalId, credentialId],
          );
          return result.rowCount === 1 ? result.rows[0] : undefined;
        },
      );
      if (credential === undefined) {
        process.stderr.write('OPENPC_LOCAL_WEBAUTHN_VERIFY_FAILURE|stage=credential-resolution\n');
        return undefined;
      }
      const result = verifyLocalWebAuthnAssertionDetailed(credential, input);
      if (!('verified' in result)) {
        process.stderr.write(
          `OPENPC_LOCAL_WEBAUTHN_VERIFY_FAILURE|stage=cryptographic-assertion|reason=${result.reason}\n`,
        );
        return undefined;
      }
      return result.verified;
    },
  };
}
