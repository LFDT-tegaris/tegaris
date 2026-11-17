import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import {
  decodeHandoverAdmissionAuthorization,
  signHandoverAdmissionAuthorization,
  verifyHandoverAdmissionAuthorization,
  type HandoverAdmissionAuthorization,
} from '@openpc/security-kernel';

export interface HandoverAdmissionTrustPolicy {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly environmentId: string;
  readonly workloadPrincipalId: string;
  readonly workloadId: string;
  readonly signers: readonly {
    readonly publicKeySpkiDer: Buffer;
    readonly validFromNs: string;
    readonly validUntilNs: string;
  }[];
}
export interface VerifiedHandoverAdmissionAuthorization {
  readonly statement: HandoverAdmissionAuthorization;
  readonly signerKeyDigest: Buffer;
  readonly authorizationDigest: Buffer;
}
export interface HandoverAdmissionVerifier {
  verifyAuthorization(
    payload: Buffer,
    coseSign1: Buffer,
  ): VerifiedHandoverAdmissionAuthorization | undefined;
}
export interface LocalHandoverAdmissionSigner extends HandoverAdmissionVerifier {
  readonly mode: 'LOCAL_BOUNDED_PURE';
  signAuthorization(payload: Buffer): {
    readonly authorizationCbor: Buffer;
    readonly authorizationDigest: Buffer;
    readonly coseSign1: Buffer;
    readonly signerKeyDigest: Buffer;
  };
}
const scopeKeys = [
  'participantId',
  'privacyDomainId',
  'environmentId',
  'workloadPrincipalId',
  'workloadId',
] as const;
const hash = (bytes: Buffer) => createHash('sha256').update(bytes).digest();
const deny = (): never => {
  throw new Error('Handover admission trust is unavailable');
};
function canonicalPublicKey(input: Buffer): Buffer {
  const bytes = Buffer.from(input);
  if (
    bytes.length !== 44 ||
    !bytes.subarray(0, 12).equals(Buffer.from('302a300506032b6570032100', 'hex'))
  )
    return deny();
  const key = createPublicKey({ key: bytes, format: 'der', type: 'spki' });
  if (
    key.asymmetricKeyType !== 'ed25519' ||
    !key.export({ format: 'der', type: 'spki' }).equals(bytes)
  )
    return deny();
  return bytes;
}
function nanos(input: string): bigint {
  if (typeof input !== 'string' || !/^(0|[1-9][0-9]{0,19})$/u.test(input)) return deny();
  const value = BigInt(input);
  if (value > (1n << 64n) - 1n || value % 1000n !== 0n) return deny();
  return value;
}
function capturePolicy(policy: HandoverAdmissionTrustPolicy) {
  if (
    !policy ||
    Object.getPrototypeOf(policy) !== Object.prototype ||
    Reflect.ownKeys(policy).length !== 6
  )
    return deny();
  const descriptor = Object.getOwnPropertyDescriptor(policy, 'signers');
  if (!descriptor || !('value' in descriptor)) return deny();
  const entries: unknown = descriptor.value;
  if (
    !Array.isArray(entries) ||
    Object.getPrototypeOf(entries) !== Array.prototype ||
    entries.length < 1 ||
    entries.length > 16 ||
    Reflect.ownKeys(entries).length !== entries.length + 1
  )
    return deny();
  const scope = Object.fromEntries(
    scopeKeys.map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(policy, key);
      if (!descriptor || !('value' in descriptor) || typeof descriptor.value !== 'string')
        return deny();
      const value = descriptor.value as string;
      const valid =
        key.endsWith('Id') && key !== 'environmentId' && key !== 'workloadId'
          ? /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
          : /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$/u.test(value);
      if (!valid) return deny();
      return [key, value];
    }),
  );
  const signers = Array.from({ length: entries.length }, (_, index) => {
    const item = Object.getOwnPropertyDescriptor(entries, index);
    if (!item || !('value' in item)) return deny();
    const entry = item.value as HandoverAdmissionTrustPolicy['signers'][number];
    if (
      !entry ||
      Object.getPrototypeOf(entry) !== Object.prototype ||
      Reflect.ownKeys(entry).length !== 3
    )
      return deny();
    for (const name of ['publicKeySpkiDer', 'validFromNs', 'validUntilNs']) {
      const descriptor = Object.getOwnPropertyDescriptor(entry, name);
      if (!descriptor || !('value' in descriptor)) return deny();
    }
    const publicKey = canonicalPublicKey(entry.publicKeySpkiDer);
    const validFromNs = nanos(entry.validFromNs),
      validUntilNs = nanos(entry.validUntilNs);
    if (validFromNs >= validUntilNs) return deny();
    return { publicKey, digest: hash(publicKey), validFromNs, validUntilNs };
  });
  if (new Set(signers.map((entry) => entry.digest.toString('hex'))).size !== signers.length)
    return deny();
  return { scope, signers };
}
type CapturedPolicy = ReturnType<typeof capturePolicy>;
function scopedStatement(policy: CapturedPolicy, payload: Buffer) {
  const statement = decodeHandoverAdmissionAuthorization(payload);
  if (scopeKeys.some((key) => statement[key] !== policy.scope[key])) return deny();
  return statement;
}
function withinSigner(
  statement: HandoverAdmissionAuthorization,
  signer: CapturedPolicy['signers'][number],
) {
  return (
    BigInt(statement.admittedAtNs) >= signer.validFromNs &&
    BigInt(statement.authorizationExpiresAtNs) <= signer.validUntilNs
  );
}
function verifier(policy: CapturedPolicy): HandoverAdmissionVerifier {
  return Object.freeze({
    verifyAuthorization(payload: Buffer, coseSign1: Buffer) {
      try {
        const bytes = Buffer.from(payload),
          signature = Buffer.from(coseSign1);
        const statement = scopedStatement(policy, bytes);
        for (const signer of policy.signers) {
          if (
            withinSigner(statement, signer) &&
            verifyHandoverAdmissionAuthorization(signer.publicKey, bytes, signature)
          )
            return Object.freeze({
              statement: Object.freeze(statement),
              signerKeyDigest: Buffer.from(signer.digest),
              authorizationDigest: hash(bytes),
            });
        }
        return undefined;
      } catch {
        return undefined;
      }
    },
  });
}

/** Explicit purpose-specific scoped trust. No fallback to the ordinary Identity
 * assertion ring, predecessor trust or successor self-signature is permitted.
 * Historical verification never authorizes a current activation by itself. */
export function createHandoverAdmissionVerifier(
  policy: HandoverAdmissionTrustPolicy,
): HandoverAdmissionVerifier {
  return verifier(capturePolicy(policy));
}

/** Synchronous local primitive only. The transaction owner supplies the exact
 * fenced statement and must still commit the complete transition. External
 * signing adapters require a separately qualified durable attempt protocol. */
export function createLocalHandoverAdmissionSigner(input: {
  readonly policy: HandoverAdmissionTrustPolicy;
  readonly activePrivateKeyPkcs8Der: Buffer;
  readonly activePublicKeySpkiDer: Buffer;
}): LocalHandoverAdmissionSigner {
  const policy = capturePolicy(input.policy);
  const active = canonicalPublicKey(input.activePublicKeySpkiDer);
  const admitted = policy.signers.find((signer) => signer.publicKey.equals(active));
  if (!admitted) return deny();
  const privateKey = createPrivateKey({
    key: Buffer.from(input.activePrivateKeyPkcs8Der),
    format: 'der',
    type: 'pkcs8',
  });
  if (
    privateKey.asymmetricKeyType !== 'ed25519' ||
    !createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).equals(active)
  )
    return deny();
  return Object.freeze({
    mode: 'LOCAL_BOUNDED_PURE' as const,
    ...verifier(policy),
    signAuthorization(payload: Buffer) {
      const bytes = Buffer.from(payload),
        statement = scopedStatement(policy, bytes);
      if (!withinSigner(statement, admitted)) return deny();
      const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });
      try {
        return Object.freeze({
          authorizationCbor: bytes,
          authorizationDigest: hash(bytes),
          coseSign1: signHandoverAdmissionAuthorization(privateDer, active, bytes),
          signerKeyDigest: Buffer.from(admitted.digest),
        });
      } finally {
        privateDer.fill(0);
      }
    },
  });
}
