import { createHash, createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { z } from 'zod';

export const signingContinuationPurpose = 'SIGNING_ROTATION_ATTEMPT_RECONCILE_V1';
export const signingContinuationAudience =
  'urn:openpc:control-api:signing-rotation-attempt-finalizer:v1';
const issuer = 'urn:openpc:identity:signing-rotation-reconciliation:v1';
const tokenType = 'openpc-signing-rotation-attempt-reconcile+jwt';
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/u);

/** This capability can finalize one recorded provider effect; it cannot authorize a provider mutation. */
export const signingContinuationContextSchema = z
  .strictObject({
    version: z.literal(1),
    purpose: z.literal(signingContinuationPurpose),
    effect: z.literal('FINALIZE_EXISTING_SIGNING_ROTATION_ATTEMPT'),
    participantId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    rotationId: z.uuidv7(),
    rotationRevision: revision,
    operationId: z.uuidv7(),
    actionIntentId: z.literal('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'),
    targetState: z.enum(['PREPARED', 'DISTRIBUTED', 'OLD_REVOKED', 'OLD_RETIRED']),
    candidateDigest: digest,
    approvalRequestId: z.uuidv7(),
    originalActorKeyDigest: digest,
    originalAuthoritySnapshotDigest: digest,
    originalMakerSnapshotDigest: digest,
    originalCheckerSnapshotDigest: digest,
    providerAttemptId: z.uuidv7(),
    providerMethod: z.enum(['PREPARE', 'DISTRIBUTE', 'REVOKE', 'RETIRE']),
    providerRequestDigest: digest,
    providerObservationDigest: digest,
    resultDisposition: z.enum([
      'APPLY_RESERVED_TARGET',
      'NO_EFFECT_RETRYABLE',
      'ENTER_FAILED_STATE',
    ]),
    workloadPrincipalId: z.uuidv7(),
    workloadCredentialId: z.uuidv7(),
    workloadCredentialEpoch: revision,
    workloadKeyDigest: digest,
    currentAuthorityStatus: z.enum(['UNCHANGED_LIVE', 'CHANGED']),
    currentAuthorityDigest: digest,
  })
  .refine(
    (context) =>
      ({
        PREPARE: 'PREPARED',
        DISTRIBUTE: 'DISTRIBUTED',
        REVOKE: 'OLD_REVOKED',
        RETIRE: 'OLD_RETIRED',
      })[context.providerMethod] === context.targetState,
  );
export type SigningContinuationContext = z.infer<typeof signingContinuationContextSchema>;
const claimsSchema = signingContinuationContextSchema
  .safeExtend({
    iss: z.literal(issuer),
    aud: z.literal(signingContinuationAudience),
    sub: z.uuidv7(),
    jti: z.uuidv7(),
    iat: z.number().int().positive(),
    exp: z.number().int().positive(),
  })
  .refine((claims) => claims.sub === claims.workloadPrincipalId && claims.exp === claims.iat + 30);

export class SigningContinuationDenied extends Error {
  constructor() {
    super('Signing continuation is unavailable');
  }
}
const hash = (value: Buffer | string) => createHash('sha256').update(value).digest();
function publicKey(bytes: Buffer): KeyObject {
  const key = createPublicKey({ key: bytes, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
    throw new SigningContinuationDenied();
  return key;
}
export interface VerifiedSigningContinuation {
  readonly assertionId: string;
  readonly context: SigningContinuationContext;
  readonly assertionDigest: Buffer;
  readonly signerKeyDigest: Buffer;
  readonly issuedAtNs: bigint;
  readonly expiresAtNs: bigint;
}
export function createSigningContinuationVerifier(trustedPublicKeys: readonly Buffer[]) {
  if (trustedPublicKeys.length === 0) throw new SigningContinuationDenied();
  const keys = trustedPublicKeys.map((der) => ({
    key: publicKey(der),
    id: 'sha256:' + hash(der).toString('hex'),
  }));
  if (new Set(keys.map((key) => key.id)).size !== keys.length)
    throw new SigningContinuationDenied();
  return async (
    assertion: string,
    expected: SigningContinuationContext,
    now: Date,
  ): Promise<VerifiedSigningContinuation> => {
    const context = signingContinuationContextSchema.parse(expected);
    if (assertion.length > 16384) throw new SigningContinuationDenied();
    for (const trusted of keys) {
      try {
        const { payload, protectedHeader } = await jwtVerify(assertion, trusted.key, {
          algorithms: ['ES256'],
          issuer,
          audience: signingContinuationAudience,
          typ: tokenType,
          currentDate: now,
          clockTolerance: 0,
          maxTokenAge: '30s',
          requiredClaims: ['iss', 'aud', 'sub', 'jti', 'iat', 'exp'],
        });
        if (
          Object.keys(protectedHeader).sort().join(',') !== 'alg,kid,typ' ||
          protectedHeader.kid !== trusted.id
        )
          throw new SigningContinuationDenied();
        const claims = claimsSchema.parse(payload);
        for (const key of Object.keys(context) as (keyof SigningContinuationContext)[])
          if (claims[key] !== context[key]) throw new SigningContinuationDenied();
        return {
          assertionId: claims.jti,
          context,
          assertionDigest: hash(assertion),
          signerKeyDigest: Buffer.from(trusted.id.slice(7), 'hex'),
          issuedAtNs: BigInt(claims.iat) * 1000000000n,
          expiresAtNs: BigInt(claims.exp) * 1000000000n,
        };
      } catch {
        /* Only pinned keys and the complete closed claims set can verify. */
      }
    }
    throw new SigningContinuationDenied();
  };
}
export function createSigningContinuationSigner(privateBytes: Buffer, publicBytes: Buffer) {
  const key = createPrivateKey({ key: privateBytes, format: 'der', type: 'pkcs8' });
  const derived = createPublicKey(key).export({ format: 'der', type: 'spki' });
  publicKey(publicBytes);
  if (!derived.equals(publicBytes)) throw new SigningContinuationDenied();
  const keyId = 'sha256:' + hash(publicBytes).toString('hex');
  return async (context: SigningContinuationContext, assertionId: string, now: Date) => {
    const iat = Math.floor(now.getTime() / 1000);
    const claims = claimsSchema.parse({
      ...signingContinuationContextSchema.parse(context),
      iss: issuer,
      aud: signingContinuationAudience,
      sub: context.workloadPrincipalId,
      jti: assertionId,
      iat,
      exp: iat + 30,
    });
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', kid: keyId, typ: tokenType })
      .sign(key);
  };
}
